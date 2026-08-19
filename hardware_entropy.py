#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
硬件级熵采集模块

采集来源：
1. 内存读取 - 随机读取内存地址内容作为熵源
   - self 模式: 仅读取本进程内存（安全，不会被反外挂误判）
   - all 模式: 读取系统全部内存（需要root，可能被安全软件标记）
2. 硬盘实时读写量 - 磁盘IO统计的微小抖动
3. 硬件温度 - CPU/GPU/主板温度传感器的微小波动

所有数据经过加密哈希后混入熵池。
"""

import os
import sys
import time
import random
import struct
import hashlib
import asyncio
import logging
import platform
import subprocess
from typing import Optional, Dict, List, Tuple
from ctypes import cdll, c_void_p, c_size_t, create_string_buffer

logger = logging.getLogger("chaos_rng.hardware")


# ====================================================================
# 1. 内存读取熵采集器
# ====================================================================
class MemoryEntropyCollector:
    """
    内存读取熵采集器

    模式:
    - "self": 仅读取本进程内存地址空间（推荐，安全）
    - "all":  尝试读取系统全部可访问内存（需要root/admin）

    原理: 内存中未初始化区域、堆栈残留、缓存内容等具有不可预测性。
    随机选取地址读取内容，经哈希后作为熵源。
    """

    def __init__(self, pool, mode: str = "self", 
                 read_size: int = 256, iterations: int = 50,
                 use_hash_stir: bool = True):
        self.pool = pool
        self.mode = mode  # "self" or "all"
        self.read_size = min(read_size, 4096)  # 限制单次读取大小
        self.iterations = iterations
        self.use_hash_stir = use_hash_stir
        self._running = False
        self._total_bits = 0
        self._system = platform.system().lower()

        # 安全检查
        if mode == "all":
            logger.warning("⚠️ 内存采集模式为 'all'，可能需要root权限且可能被安全软件标记")

    @property
    def available(self) -> bool:
        return True  # self 模式总是可用

    async def collect_once(self) -> int:
        """执行一次内存熵采集"""
        try:
            if self.mode == "self":
                return await self._collect_self()
            elif self.mode == "all":
                return await self._collect_all()
        except Exception as e:
            logger.debug(f"内存采集失败: {e}")
        return 0

    async def _collect_self(self) -> int:
        """
        仅读取本进程内存

        安全策略：
        - 只读取 Python 对象、栈帧、模块等合法内存
        - 不读取受保护区域
        - 不会被任何反外挂/安全软件误判
        """
        loop = asyncio.get_event_loop()

        def _read():
            raw_data = bytearray()

            # 1. 读取当前栈帧信息
            import inspect
            for _ in range(self.iterations // 4):
                try:
                    frame = sys._current_frames()[os.getpid()]
                    # 读取栈帧对象的内存表示
                    frame_repr = repr(frame).encode('utf-8', errors='ignore')
                    raw_data.extend(frame_repr)

                    # 读取局部变量
                    if frame.f_locals:
                        for k, v in list(frame.f_locals.items())[:5]:
                            raw_data.extend(f"{k}:{type(v).__name__}:{id(v)}".encode())
                except:
                    pass

            # 2. 读取已加载模块的内存地址内容
            for _ in range(self.iterations // 4):
                try:
                    mod_name = random.choice(list(sys.modules.keys()))
                    mod = sys.modules[mod_name]
                    mod_addr = id(mod)
                    # 读取模块对象的 __dict__ 键值哈希
                    if hasattr(mod, '__dict__'):
                        keys = list(mod.__dict__.keys())
                        raw_data.extend(str(sorted(keys)).encode())
                    raw_data.extend(struct.pack('<Q', mod_addr))
                except:
                    pass

            # 3. 读取 gc 对象的一些地址
            try:
                import gc
                objs = gc.get_objects()
                for _ in range(min(self.iterations // 4, 20)):
                    obj = random.choice(objs)
                    raw_data.extend(struct.pack('<Q', id(obj)))
                    raw_data.extend(str(type(obj)).encode())
            except:
                pass

            # 4. 读取当前进程的内存映射信息（Linux）
            if self._system == "linux":
                try:
                    with open(f"/proc/{os.getpid()}/maps", "r") as f:
                        maps = f.read(2048)
                    raw_data.extend(maps.encode())
                except:
                    pass

            # 5. 读取一些大对象的内存内容（安全对象）
            try:
                # 创建并读取一个临时大数组的部分内容
                arr = bytearray(os.urandom(1024))
                start = random.randint(0, len(arr) - self.read_size)
                raw_data.extend(arr[start:start + self.read_size])
            except:
                pass

            return bytes(raw_data)

        raw = await loop.run_in_executor(None, _read)

        if raw:
            if self.use_hash_stir:
                hash_result = hashlib.sha256(raw).digest()
            else:
                hash_result = raw[:32]
            self.pool.mix_bytes(hash_result)
            self._total_bits += len(hash_result) * 8
            return len(hash_result) * 8
        return 0

    async def _collect_all(self) -> int:
        """
        读取系统全部可访问内存（需要高权限）

        ⚠️ 警告: 此模式可能被安全软件/反外挂系统标记为可疑行为！
        仅在受信任环境中使用。
        """
        loop = asyncio.get_event_loop()

        def _read():
            raw_data = bytearray()

            if self._system == "linux":
                # Linux: 读取 /dev/mem 或 /proc/kcore
                try:
                    # 尝试读取 /proc/kcore（内核内存镜像）
                    with open("/proc/kcore", "rb") as f:
                        for _ in range(self.iterations):
                            offset = random.randint(0, 1024 * 1024 * 1024)  # 1GB范围内
                            f.seek(offset)
                            chunk = f.read(self.read_size)
                            raw_data.extend(chunk)
                except PermissionError:
                    logger.warning("读取 /proc/kcore 需要root权限，回退到self模式")
                    return None
                except Exception:
                    pass

                # 读取 /proc/*/mem（各进程内存）
                try:
                    import glob
                    pids = [int(os.path.basename(p)) for p in glob.glob("/proc/[0-9]*") if os.path.basename(p).isdigit()]
                    for _ in range(min(self.iterations // 2, 10)):
                        pid = random.choice(pids)
                        try:
                            with open(f"/proc/{pid}/mem", "rb") as f:
                                # 读取随机偏移
                                f.seek(random.randint(0, 1024 * 1024))
                                chunk = f.read(self.read_size)
                                raw_data.extend(chunk)
                        except:
                            pass
                except:
                    pass

            elif self._system == "windows":
                # Windows: 使用 ReadProcessMemory
                try:
                    import ctypes
                    from ctypes import wintypes

                    kernel32 = ctypes.windll.kernel32

                    # 枚举进程
                    EnumProcesses = kernel32.EnumProcesses
                    EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

                    process_ids = (wintypes.DWORD * 1024)()
                    cb_needed = wintypes.DWORD()

                    if EnumProcesses(process_ids, ctypes.sizeof(process_ids), ctypes.byref(cb_needed)):
                        num_processes = cb_needed.value // ctypes.sizeof(wintypes.DWORD)

                        for _ in range(min(self.iterations // 4, 5)):
                            pid = process_ids[random.randint(0, num_processes - 1)]
                            PROCESS_VM_READ = 0x0010
                            h_process = kernel32.OpenProcess(PROCESS_VM_READ, False, pid)

                            if h_process:
                                buf = create_string_buffer(self.read_size)
                                bytes_read = ctypes.c_size_t()
                                # 随机地址
                                addr = random.randint(0x10000, 0x7FFFFFFF)
                                if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(addr), buf, self.read_size, ctypes.byref(bytes_read)):
                                    raw_data.extend(buf.raw[:bytes_read.value])
                                kernel32.CloseHandle(h_process)
                except Exception as e:
                    logger.debug(f"Windows 内存读取失败: {e}")

            elif self._system == "darwin":
                # macOS: 使用 vmmap 或 mach API
                try:
                    result = subprocess.run(
                        ["vmmap", str(os.getpid())],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        raw_data.extend(result.stdout.encode())
                except:
                    pass

            return bytes(raw_data) if raw_data else None

        raw = await loop.run_in_executor(None, _read)

        if raw is None and self.mode == "all":
            # 权限不足，回退到 self 模式
            logger.info("'all' 模式权限不足，自动回退到 'self' 模式")
            return await self._collect_self()

        if raw:
            hash_result = hashlib.sha256(raw).digest()
            self.pool.mix_bytes(hash_result)
            self._total_bits += len(hash_result) * 8
            return len(hash_result) * 8
        return 0

    async def start_daemon(self, interval_sec: float = 5.0):
        """后台持续采集"""
        self._running = True
        while self._running:
            bits = await self.collect_once()
            if bits > 0:
                logger.debug(f"内存采集 {bits} bits (mode={self.mode})")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits


# ====================================================================
# 2. 硬盘实时读写量采集器
# ====================================================================
class DiskIOStatsCollector:
    """
    硬盘实时读写量熵采集器

    采集来源：
    - 磁盘读写字节数的实时变化
    - 读写操作次数的抖动
    - 读写时间的微秒级差异
    - 各分区的IO统计差异

    依赖: psutil (磁盘IO计数器)
    """

    def __init__(self, pool, use_hash_stir: bool = True):
        self.pool = pool
        self.use_hash_stir = use_hash_stir
        self._running = False
        self._total_bits = 0
        self._last_disk_io = None
        self._system = platform.system().lower()

    @property
    def available(self) -> bool:
        try:
            import psutil
            psutil.disk_io_counters()
            return True
        except:
            return False

    async def collect_once(self) -> int:
        """采集一次磁盘IO统计"""
        try:
            import psutil
            loop = asyncio.get_event_loop()

            def _read():
                data = {}

                # 总体磁盘IO
                io = psutil.disk_io_counters(perdisk=False)
                if io:
                    data["total"] = {
                        "read_bytes": io.read_bytes,
                        "write_bytes": io.write_bytes,
                        "read_count": io.read_count,
                        "write_count": io.write_count,
                        "read_time": io.read_time,
                        "write_time": io.write_time,
                    }

                # 各磁盘IO
                perdisk = psutil.disk_io_counters(perdisk=True)
                if perdisk:
                    for disk_name, disk_io in perdisk.items():
                        data[disk_name] = {
                            "read_bytes": disk_io.read_bytes,
                            "write_bytes": disk_io.write_bytes,
                            "read_count": disk_io.read_count,
                            "write_count": disk_io.write_count,
                            "read_time": disk_io.read_time,
                            "write_time": disk_io.write_time,
                        }

                # 分区使用情况（增加抖动）
                partitions = psutil.disk_partitions(all=False)
                for part in partitions:
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        data[f"usage_{part.device}"] = {
                            "total": usage.total,
                            "used": usage.used,
                            "free": usage.free,
                            "percent": usage.percent,
                        }
                    except:
                        pass

                return data

            current_io = await loop.run_in_executor(None, _read)

            # 计算差值（抖动）
            if self._last_disk_io:
                jitter_data = {}
                for key in current_io:
                    if key in self._last_disk_io:
                        curr = current_io[key]
                        prev = self._last_disk_io[key]
                        jitter = {}
                        for subkey in curr:
                            if subkey in prev:
                                jitter[subkey] = curr[subkey] - prev[subkey]
                        jitter_data[key] = jitter

                # 混入差值
                json_str = json.dumps(jitter_data, sort_keys=True)
                hash_result = hashlib.sha256(
                    f"disk_io:{json_str}:{time.perf_counter_ns()}".encode()
                ).digest()
                self.pool.mix_bytes(hash_result)
                self._total_bits += len(hash_result) * 8
                return len(hash_result) * 8

            self._last_disk_io = current_io
            return 0

        except Exception as e:
            logger.debug(f"磁盘IO采集失败: {e}")
        return 0

    async def start_daemon(self, interval_sec: float = 3.0):
        """后台持续采集"""
        self._running = True
        while self._running:
            bits = await self.collect_once()
            if bits > 0:
                logger.debug(f"磁盘IO采集 {bits} bits")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits


# ====================================================================
# 3. 硬件温度采集器
# ====================================================================
class HardwareTemperatureCollector:
    """
    硬件温度熵采集器

    采集来源：
    - CPU 核心温度
    - GPU 温度
    - 主板/传感器温度
    - 温度值的微小幅波动（即使显示整数，底层有浮点精度）

    平台支持：
    - Linux: psutil.sensors_temperatures, /sys/class/thermal
    - Windows: WMI, OpenHardwareMonitor, wmic
    - macOS: osx-cpu-temp, powermetrics
    """

    def __init__(self, pool, use_hash_stir: bool = True):
        self.pool = pool
        self.use_hash_stir = use_hash_stir
        self._running = False
        self._total_bits = 0
        self._system = platform.system().lower()
        self._last_temps = None

    @property
    def available(self) -> bool:
        """检测温度传感器可用性"""
        if self._system == "linux":
            try:
                import psutil
                temps = psutil.sensors_temperatures()
                return bool(temps)
            except:
                return os.path.exists("/sys/class/thermal")
        elif self._system == "windows":
            try:
                import wmi
                return True
            except:
                # 尝试 wmic
                try:
                    subprocess.run(["wmic", "/?"], capture_output=True, timeout=2)
                    return True
                except:
                    return False
        elif self._system == "darwin":
            try:
                subprocess.run(["osx-cpu-temp"], capture_output=True, timeout=2)
                return True
            except:
                return os.path.exists("/usr/bin/powermetrics")
        return False

    async def collect_once(self) -> int:
        """采集一次温度数据"""
        try:
            loop = asyncio.get_event_loop()

            def _read():
                temps = {}

                if self._system == "linux":
                    temps = self._read_linux()
                elif self._system == "windows":
                    temps = self._read_windows()
                elif self._system == "darwin":
                    temps = self._read_macos()

                return temps

            current_temps = await loop.run_in_executor(None, _read)

            if not current_temps:
                return 0

            # 混入原始温度值
            json_str = json.dumps(current_temps, sort_keys=True)
            hash_result = hashlib.sha256(
                f"temp:{json_str}:{time.perf_counter_ns()}".encode()
            ).digest()
            self.pool.mix_bytes(hash_result)

            # 如果有历史数据，混入温度变化率
            if self._last_temps:
                changes = {}
                for sensor, curr_val in current_temps.items():
                    if sensor in self._last_temps:
                        changes[sensor] = curr_val - self._last_temps[sensor]

                if changes:
                    change_str = json.dumps(changes, sort_keys=True)
                    change_hash = hashlib.sha256(
                        f"temp_delta:{change_str}:{time.perf_counter_ns()}".encode()
                    ).digest()
                    self.pool.mix_bytes(change_hash)
                    self._total_bits += (len(hash_result) + len(change_hash)) * 8
                    return (len(hash_result) + len(change_hash)) * 8

            self._last_temps = current_temps
            self._total_bits += len(hash_result) * 8
            return len(hash_result) * 8

        except Exception as e:
            logger.debug(f"温度采集失败: {e}")
        return 0

    def _read_linux(self) -> Dict[str, float]:
        """Linux 温度读取"""
        temps = {}

        # 方法1: psutil
        try:
            import psutil
            sensors = psutil.sensors_temperatures()
            if sensors:
                for name, entries in sensors.items():
                    for i, entry in enumerate(entries):
                        temps[f"{name}_{i}"] = entry.current
                        if entry.high:
                            temps[f"{name}_{i}_high"] = entry.high
                        if entry.critical:
                            temps[f"{name}_{i}_crit"] = entry.critical
        except:
            pass

        # 方法2: /sys/class/thermal
        try:
            import glob
            thermal_zones = glob.glob("/sys/class/thermal/thermal_zone*/temp")
            for zone in thermal_zones:
                try:
                    zone_name = os.path.basename(os.path.dirname(zone))
                    with open(zone, "r") as f:
                        temp_milli = int(f.read().strip())
                        temps[zone_name] = temp_milli / 1000.0
                except:
                    pass
        except:
            pass

        # 方法3: /sys/class/hwmon
        try:
            import glob
            hwmon_dirs = glob.glob("/sys/class/hwmon/hwmon*")
            for hwmon in hwmon_dirs:
                try:
                    with open(os.path.join(hwmon, "name"), "r") as f:
                        name = f.read().strip()

                    temp_inputs = glob.glob(os.path.join(hwmon, "temp*_input"))
                    for temp_file in temp_inputs:
                        try:
                            with open(temp_file, "r") as f:
                                temp_milli = int(f.read().strip())
                            label_file = temp_file.replace("_input", "_label")
                            label = ""
                            if os.path.exists(label_file):
                                with open(label_file, "r") as f:
                                    label = f.read().strip()
                            temps[f"{name}_{label or os.path.basename(temp_file)}"] = temp_milli / 1000.0
                        except:
                            pass
                except:
                    pass
        except:
            pass

        return temps

    def _read_windows(self) -> Dict[str, float]:
        """Windows 温度读取"""
        temps = {}

        # 方法1: WMI
        try:
            import wmi
            w = wmi.WMI(namespace="root\wmi")
            for sensor in w.MSAcpi_ThermalZoneTemperature():
                temps[f"thermal_zone_{sensor.InstanceName}"] = (sensor.CurrentTemperature - 2732) / 10.0
        except:
            pass

        # 方法2: wmic
        try:
            result = subprocess.run(
                ["wmic", "/namespace:\\root\wmi", "PATH", "MSAcpi_ThermalZoneTemperature", "GET", "CurrentTemperature"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for i, line in enumerate(lines[1:], 1):
                    line = line.strip()
                    if line.isdigit():
                        temps[f"wmic_thermal_{i}"] = (int(line) - 2732) / 10.0
        except:
            pass

        return temps

    def _read_macos(self) -> Dict[str, float]:
        """macOS 温度读取"""
        temps = {}

        # 方法1: osx-cpu-temp
        try:
            result = subprocess.run(
                ["osx-cpu-temp"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                temp_str = result.stdout.strip().replace("°C", "").strip()
                temps["cpu"] = float(temp_str)
        except:
            pass

        # 方法2: powermetrics (需要sudo)
        try:
            result = subprocess.run(
                ["powermetrics", "--samplers", "smc", "-n", "1"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "temperature" in line.lower():
                        parts = line.split(":")
                        if len(parts) == 2:
                            try:
                                temps[f"smc_{parts[0].strip()}"] = float(parts[1].strip().split()[0])
                            except:
                                pass
        except:
            pass

        # 方法3: ioreg
        try:
            result = subprocess.run(
                ["ioreg", "-r", "-c", "AppleSmartBattery"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                temps["battery_raw"] = hashlib.sha256(result.stdout.encode()).hexdigest()[:16]
        except:
            pass

        return temps

    async def start_daemon(self, interval_sec: float = 10.0):
        """后台持续采集"""
        self._running = True
        while self._running:
            bits = await self.collect_once()
            if bits > 0:
                logger.debug(f"温度采集 {bits} bits")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits
