#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Termux 音频/摄像头熵源 — 带前台检测

每 5 秒：
  1. 检查前台
  2. 若在前台 → 录音 0.3s + 拍照
  3. 文件哈希混入池
"""

import os
import time
import shutil
import hashlib
import logging
import subprocess
import asyncio
import tempfile
from pathlib import Path

from foreground_check import ForegroundChecker

logger = logging.getLogger("chaos_rng.termux_media")


class TermuxMicCollector:
    def __init__(self, pool, duration=0.3, use_hash_stir=True,
                 foreground_checker=None):
        self.pool = pool
        self.duration = duration
        self.use_hash_stir = use_hash_stir
        self.fg = foreground_checker or ForegroundChecker()
        self._running = False
        self._total_bits = 0
        self._read_count = 0
        self._available = shutil.which("termux-microphone-record") is not None
        if self._available:
            logger.info("🎙️ Termux 麦克风熵源已就绪")
        else:
            logger.debug("termux-microphone-record 不可用")

    @property
    def available(self):
        return self._available

    @property
    def total_bits(self):
        return self._total_bits

    @property
    def read_count(self):
        return self._read_count

    async def collect_once(self):
        if not self._available:
            return 0
        if not self.fg.is_foreground():
            return 0

        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, self._record)
        except Exception:
            return 0
        if not data:
            return 0

        h = hashlib.sha256(data).digest() if self.use_hash_stir else data[:32]
        self.pool.mix_bytes(h)
        self._total_bits += len(h) * 8
        self._read_count += 1
        return len(h) * 8

    def _record(self):
        tmpdir = Path(tempfile.gettempdir())
        out = tmpdir / f"mic_{os.getpid()}_{int(time.time()*1000)}.m4a"
        try:
            subprocess.run(
                ["termux-microphone-record", "-f", str(out),
                 "-l", str(self.duration), "-e", "aac", "-b", "96000"],
                capture_output=True, timeout=self.duration + 5)
            time.sleep(0.3)
            subprocess.run(["termux-microphone-record", "-q"],
                           capture_output=True, timeout=3)
            data = out.read_bytes()
        except Exception:
            data = b""
        finally:
            try:
                out.unlink()
            except OSError:
                pass
        return data

    async def start_daemon(self, interval_sec=5.0):
        if not self._available:
            return
        self._running = True
        while self._running:
            try:
                await self.collect_once()
            except Exception as e:
                logger.debug(f"麦克风 daemon: {e}")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False
        try:
            subprocess.run(["termux-microphone-record", "-q"],
                           capture_output=True, timeout=3)
        except Exception:
            pass


class TermuxCameraCollector:
    def __init__(self, pool, camera_id=0, use_hash_stir=True,
                 foreground_checker=None):
        self.pool = pool
        self.camera_id = camera_id
        self.use_hash_stir = use_hash_stir
        self.fg = foreground_checker or ForegroundChecker()
        self._running = False
        self._total_bits = 0
        self._read_count = 0
        self._available = shutil.which("termux-camera-photo") is not None
        if self._available:
            logger.info(f"📷 Termux 摄像头熵源已就绪 (camera={camera_id})")
        else:
            logger.debug("termux-camera-photo 不可用")

    @property
    def available(self):
        return self._available

    @property
    def total_bits(self):
        return self._total_bits

    @property
    def read_count(self):
        return self._read_count

    async def collect_once(self):
        if not self._available:
            return 0
        if not self.fg.is_foreground():
            return 0

        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, self._capture)
        except Exception:
            return 0
        if not data:
            return 0

        h = hashlib.sha256(data).digest() if self.use_hash_stir else data[:32]
        self.pool.mix_bytes(h)
        self._total_bits += len(h) * 8
        self._read_count += 1
        return len(h) * 8

    def _capture(self):
        tmpdir = Path(tempfile.gettempdir())
        out = tmpdir / f"cam_{os.getpid()}_{int(time.time()*1000)}.jpg"
        try:
            subprocess.run(
                ["termux-camera-photo", "-c", str(self.camera_id), str(out)],
                capture_output=True, timeout=10)
            time.sleep(0.2)
            data = out.read_bytes()
        except Exception:
            data = b""
        finally:
            try:
                out.unlink()
            except OSError:
                pass
        return data

    async def start_daemon(self, interval_sec=5.0):
        if not self._available:
            return
        self._running = True
        while self._running:
            try:
                await self.collect_once()
            except Exception as e:
                logger.debug(f"摄像头 daemon: {e}")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False
