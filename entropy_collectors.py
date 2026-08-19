#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
扩展熵源采集模块
提供多种物理/硬件熵源：
- AudioEntropyCollector: 麦克风ADC底噪LSB
- CameraEntropyCollector: CMOS暗电流噪声
- InputEntropyCollector: 鼠标/键盘中断时间间隔
- DiskIOEntropyCollector: 磁盘IO抖动
"""

import os
import time
import struct
import hashlib
import asyncio
import logging
from typing import Optional, List, Tuple
from collections import deque

logger = logging.getLogger("chaos_rng.collectors")

# ====================================================================
# 冯·诺依曼纠偏器
# ====================================================================
class VonNeumannExtractor:
    """
    冯·诺依曼纠偏器

    原理：读取两位原始比特
      01 → 输出 0
      10 → 输出 1
      00 / 11 → 丢弃

    能完美消除直流偏置，但效率约 25%（丢弃75%数据）
    """

    def __init__(self):
        self._buffer = 0
        self._bit_count = 0
        self._output = bytearray()

    def feed_bytes(self, data: bytes) -> bytes:
        """喂入原始字节，返回纠偏后的字节"""
        for byte in data:
            for i in range(8):
                bit = (byte >> i) & 1
                self._buffer = (self._buffer << 1) | bit
                self._bit_count += 1

                if self._bit_count == 2:
                    pair = self._buffer & 0b11
                    if pair == 0b01:
                        self._append_bit(0)
                    elif pair == 0b10:
                        self._append_bit(1)
                    # 00 和 11 丢弃
                    self._bit_count = 0
                    self._buffer = 0

        result = bytes(self._output)
        self._output = bytearray()
        return result

    def _append_bit(self, bit: int):
        """累积比特到输出缓冲区"""
        if not hasattr(self, '_out_buffer'):
            self._out_buffer = 0
            self._out_bits = 0

        self._out_buffer = (self._out_buffer << 1) | bit
        self._out_bits += 1

        if self._out_bits == 8:
            self._output.append(self._out_buffer & 0xFF)
            self._out_buffer = 0
            self._out_bits = 0

    def flush(self) -> bytes:
        """刷新剩余比特（可能不满8位，丢弃）"""
        result = bytes(self._output)
        self._output = bytearray()
        self._buffer = 0
        self._bit_count = 0
        if hasattr(self, '_out_buffer'):
            self._out_buffer = 0
            self._out_bits = 0
        return result


# ====================================================================
# 1. 音频熵采集器（麦克风ADC底噪）
# ====================================================================
class AudioEntropyCollector:
    """
    音频噪声熵采集器

    原理：读取麦克风（或不插麦克风时的声卡底噪），
    取每个采样值的最低有效位（LSB），因为高位是稳定的环境偏置。
    """

    def __init__(self, pool, sample_rate: int = 44100, 
                 chunk_size: int = 1024, channels: int = 1,
                 use_von_neumann: bool = True):
        self.pool = pool
        self.sample_rate = sample_rate
        self.chunk_size = chunk_size
        self.channels = channels
        self.use_von_neumann = use_von_neumann
        self._stream = None
        self._audio = None
        self._running = False
        self._total_bits = 0

        # 尝试导入音频库
        self._backend = None
        try:
            import sounddevice as sd
            self._backend = "sounddevice"
            self._sd = sd
        except ImportError:
            try:
                import pyaudio
                self._backend = "pyaudio"
                self._pyaudio = pyaudio
            except ImportError:
                pass

    @property
    def available(self) -> bool:
        return self._backend is not None

    def _extract_lsb(self, audio_data: bytes) -> bytes:
        """从音频数据提取LSB"""
        # 假设16位采样
        lsb_bits = []
        for i in range(0, len(audio_data), 2):
            if i + 1 < len(audio_data):
                sample = struct.unpack('<h', audio_data[i:i+2])[0]
                lsb_bits.append(sample & 1)

        # 比特打包成字节
        result = bytearray()
        for i in range(0, len(lsb_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(lsb_bits):
                    byte |= (lsb_bits[i + j] << j)
            result.append(byte)

        return bytes(result)

    async def collect_once(self, duration_sec: float = 0.5) -> int:
        """采集一次音频熵，返回混入的比特数"""
        if not self.available:
            return 0

        try:
            if self._backend == "sounddevice":
                return await self._collect_sounddevice(duration_sec)
            elif self._backend == "pyaudio":
                return await self._collect_pyaudio(duration_sec)
        except Exception as e:
            logger.debug(f"音频采集失败: {e}")
        return 0

    async def _collect_sounddevice(self, duration_sec: float) -> int:
        import numpy as np

        loop = asyncio.get_event_loop()

        def _record():
            samples = int(self.sample_rate * duration_sec)
            recording = self._sd.rec(
                samples, 
                samplerate=self.sample_rate, 
                channels=self.channels,
                dtype=np.int16
            )
            self._sd.wait()
            return recording

        recording = await loop.run_in_executor(None, _record)

        # 提取LSB
        lsb_data = bytearray()
        for sample in recording.flatten():
            lsb_data.append(sample & 0xFF)

        raw = bytes(lsb_data)

        if self.use_von_neumann:
            extractor = VonNeumannExtractor()
            processed = extractor.feed_bytes(raw)
            processed += extractor.flush()
        else:
            processed = hashlib.sha256(raw).digest()

        if processed:
            self.pool.mix_bytes(processed)
            self._total_bits += len(processed) * 8

        return len(processed) * 8

    async def _collect_pyaudio(self, duration_sec: float) -> int:
        loop = asyncio.get_event_loop()

        def _record():
            p = self._pyaudio.PyAudio()
            stream = p.open(
                format=self._pyaudio.paInt16,
                channels=self.channels,
                rate=self.sample_rate,
                input=True,
                frames_per_buffer=self.chunk_size
            )

            frames = []
            num_chunks = int(self.sample_rate / self.chunk_size * duration_sec)
            for _ in range(num_chunks):
                data = stream.read(self.chunk_size, exception_on_overflow=False)
                frames.append(data)

            stream.stop_stream()
            stream.close()
            p.terminate()
            return b''.join(frames)

        raw = await loop.run_in_executor(None, _record)

        # 提取LSB
        lsb_data = bytearray()
        for i in range(0, len(raw), 2):
            if i + 1 < len(raw):
                sample = struct.unpack('<h', raw[i:i+2])[0]
                lsb_data.append(sample & 0xFF)

        raw_bits = bytes(lsb_data)

        if self.use_von_neumann:
            extractor = VonNeumannExtractor()
            processed = extractor.feed_bytes(raw_bits)
            processed += extractor.flush()
        else:
            processed = hashlib.sha256(raw_bits).digest()

        if processed:
            self.pool.mix_bytes(processed)
            self._total_bits += len(processed) * 8

        return len(processed) * 8

    async def start_daemon(self, interval_sec: float = 5.0):
        """后台持续采集"""
        self._running = True
        while self._running:
            await self.collect_once(0.3)
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits


# ====================================================================
# 2. 摄像头CMOS暗电流噪声采集器
# ====================================================================
class CameraEntropyCollector:
    """
    CMOS暗电流噪声熵采集器

    原理：盖上镜头盖（或遮挡摄像头），读取像素点的暗电流噪声。
    取RGB值的奇偶性或相邻像素差值作为熵源。
    """

    def __init__(self, pool, device_id: int = 0, 
                 use_von_neumann: bool = True):
        self.pool = pool
        self.device_id = device_id
        self.use_von_neumann = use_von_neumann
        self._cap = None
        self._running = False
        self._total_bits = 0

        # 检查 opencv 可用性
        try:
            import cv2
            self._cv2 = cv2
            self._available = True
        except ImportError:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    async def collect_once(self) -> int:
        """采集一帧暗电流噪声"""
        if not self.available:
            return 0

        loop = asyncio.get_event_loop()

        def _capture():
            cap = self._cv2.VideoCapture(self.device_id)
            if not cap.isOpened():
                cap.release()
                return None

            # 读取几帧让自动曝光稳定
            for _ in range(5):
                cap.read()

            ret, frame = cap.read()
            cap.release()

            if not ret or frame is None:
                return None

            return frame

        try:
            frame = await loop.run_in_executor(None, _capture)
            if frame is None:
                return 0

            # 方法1: 取每个像素RGB的LSB
            # 方法2: 相邻像素差值的LSB（更好）
            raw_bits = bytearray()

            h, w = frame.shape[:2]
            # 采样部分像素（避免数据量过大）
            step = max(1, min(h, w) // 64)

            for y in range(0, h - 1, step):
                for x in range(0, w - 1, step):
                    # 当前像素与右下像素差值
                    px1 = frame[y, x]
                    px2 = frame[y + 1, x + 1] if y + 1 < h and x + 1 < w else px1

                    for c in range(3):  # RGB
                        diff = int(px1[c]) - int(px2[c])
                        raw_bits.append(diff & 0xFF)

            raw = bytes(raw_bits)

            if self.use_von_neumann:
                extractor = VonNeumannExtractor()
                processed = extractor.feed_bytes(raw)
                processed += extractor.flush()
            else:
                processed = hashlib.sha256(raw).digest()

            if processed:
                self.pool.mix_bytes(processed)
                self._total_bits += len(processed) * 8

            return len(processed) * 8

        except Exception as e:
            logger.debug(f"摄像头采集失败: {e}")
            return 0

    async def start_daemon(self, interval_sec: float = 10.0):
        """后台持续采集"""
        self._running = True
        while self._running:
            await self.collect_once()
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits


# ====================================================================
# 3. 输入设备熵采集器（鼠标/键盘）
# ====================================================================
class InputEntropyCollector:
    """
    鼠标/键盘中断时间间隔熵采集器

    原理：记录两次鼠标移动/点击/键盘按键之间的纳秒级时间间隔，
    利用人机交互的不可预测性。

    注意：某些系统需要特殊权限监听全局输入。
    """

    def __init__(self, pool, use_von_neumann: bool = True):
        self.pool = pool
        self.use_von_neumann = use_von_neumann
        self._running = False
        self._last_time = None
        self._intervals = deque(maxlen=1000)
        self._total_bits = 0
        self._listener = None

        # 检查 pynput 可用性
        try:
            from pynput import mouse, keyboard
            self._mouse = mouse
            self._keyboard = keyboard
            self._available = True
        except ImportError:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def _on_mouse_move(self, x, y):
        """鼠标移动回调"""
        self._record_interval("mouse_move")

    def _on_mouse_click(self, x, y, button, pressed):
        """鼠标点击回调"""
        if pressed:
            self._record_interval("mouse_click")

    def _on_key_press(self, key):
        """键盘按下回调"""
        self._record_interval("key_press")

    def _record_interval(self, event_type: str):
        """记录时间间隔"""
        now = time.perf_counter_ns()
        if self._last_time is not None:
            interval = now - self._last_time
            self._intervals.append(interval)
        self._last_time = now

    async def collect_once(self, min_events: int = 10) -> int:
        """采集当前缓冲区中的输入熵"""
        if len(self._intervals) < min_events:
            return 0

        # 取间隔值的低字节作为熵
        raw_bits = bytearray()
        for interval in list(self._intervals):
            # 取纳秒间隔的低字节（变化最剧烈的部分）
            raw_bits.extend(struct.pack('<Q', interval & 0xFFFFFFFFFFFFFFFF))

        raw = bytes(raw_bits)

        if self.use_von_neumann:
            extractor = VonNeumannExtractor()
            processed = extractor.feed_bytes(raw)
            processed += extractor.flush()
        else:
            processed = hashlib.sha256(raw).digest()

        if processed:
            self.pool.mix_bytes(processed)
            self._total_bits += len(processed) * 8

        # 清空已处理的间隔
        self._intervals.clear()

        return len(processed) * 8

    async def start_daemon(self, interval_sec: float = 3.0):
        """启动输入监听并定期采集"""
        if not self.available:
            return

        self._running = True

        # 启动监听器（在后台线程）
        loop = asyncio.get_event_loop()

        def _start_listeners():
            mouse_listener = self._mouse.Listener(
                on_move=self._on_mouse_move,
                on_click=self._on_mouse_click
            )
            keyboard_listener = self._keyboard.Listener(
                on_press=self._on_key_press
            )
            mouse_listener.start()
            keyboard_listener.start()
            return mouse_listener, keyboard_listener

        try:
            mouse_l, key_l = await loop.run_in_executor(None, _start_listeners)

            while self._running:
                await self.collect_once(min_events=5)
                await asyncio.sleep(interval_sec)

            mouse_l.stop()
            key_l.stop()
        except Exception as e:
            logger.warning(f"输入监听启动失败（可能需要权限）: {e}")

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits

    @property
    def event_count(self) -> int:
        return len(self._intervals)


# ====================================================================
# 4. 磁盘IO抖动熵采集器
# ====================================================================
class DiskIOEntropyCollector:
    """
    磁盘IO抖动熵采集器

    原理：利用机械硬盘寻道时间的微小抖动，
    或SSD控制器响应时间的微秒级变化。

    方法：创建临时文件，进行随机读写，测量操作耗时。
    """

    def __init__(self, pool, use_von_neumann: bool = True):
        self.pool = pool
        self.use_von_neumann = use_von_neumann
        self._running = False
        self._total_bits = 0

    @property
    def available(self) -> bool:
        return True  # 总是可用（只要有磁盘）

    async def collect_once(self, iterations: int = 100) -> int:
        """采集一次磁盘IO抖动熵"""
        loop = asyncio.get_event_loop()

        def _measure():
            import tempfile
            import os

            timings = []

            with tempfile.NamedTemporaryFile(delete=False) as f:
                path = f.name
                # 写入随机数据并测量时间
                for _ in range(iterations):
                    data = os.urandom(4096)
                    t0 = time.perf_counter_ns()
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                    t1 = time.perf_counter_ns()
                    timings.append(t1 - t0)

            os.unlink(path)
            return timings

        try:
            timings = await loop.run_in_executor(None, _measure)

            # 取时间差的低字节
            raw_bits = bytearray()
            for t in timings:
                raw_bits.extend(struct.pack('<Q', t & 0xFFFFFFFFFFFFFFFF))

            raw = bytes(raw_bits)

            if self.use_von_neumann:
                extractor = VonNeumannExtractor()
                processed = extractor.feed_bytes(raw)
                processed += extractor.flush()
            else:
                processed = hashlib.sha256(raw).digest()

            if processed:
                self.pool.mix_bytes(processed)
                self._total_bits += len(processed) * 8

            return len(processed) * 8

        except Exception as e:
            logger.debug(f"磁盘IO采集失败: {e}")
            return 0

    async def start_daemon(self, interval_sec: float = 30.0):
        """后台定期采集"""
        self._running = True
        while self._running:
            await self.collect_once()
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits
