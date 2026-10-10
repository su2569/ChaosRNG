#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Termux 传感器熵源

仅在 Termux（Android + Termux:API）环境下可用。
通过 termux-sensor 命令读取手机的所有物理传感器（加速度计、陀螺仪、
磁力计、气压计、光线、温度、湿度、距离等），将微秒级读数抖动混入熵池。

依赖：
  pkg install termux-api
  并安装 Termux:API 应用（F-Droid / Google Play）

非 Termux 环境自动跳过，不产生任何副作用。
"""

import os
import sys
import json
import time
import shutil
import struct
import asyncio
import hashlib
import logging
import subprocess
from typing import Optional, Dict, List, Any

logger = logging.getLogger("chaos_rng.termux")


# ====================================================================
# 环境检测
# ====================================================================
def is_termux() -> bool:
    """
    检测当前环境是否为 Termux。

    多路判断，任一命中即为 True：
      1. 环境变量 PREFIX 包含 "com.termux"
      2. 环境变量 TERMUX_VERSION 存在
      3. /data/data/com.termux 目录存在
      4. termux-sensor 命令可执行
    """
    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    if os.environ.get("TERMUX_VERSION"):
        return True
    try:
        if os.path.isdir("/data/data/com.termux"):
            return True
    except Exception:
        pass
    if shutil.which("termux-sensor"):
        return True
    return False


def _have_termux_api() -> bool:
    """termux-api 命令行是否可用"""
    return shutil.which("termux-sensor") is not None


# ====================================================================
# 传感器采集器
# ====================================================================
class TermuxSensorCollector:
    """
    Termux 传感器熵采集器

    工作方式：
      1. 启动时用 termux-sensor -l 列出所有传感器
      2. 每次采集用 termux-sensor -a -n 1 一次性读所有传感器
      3. 传感器名 + float 值(IEEE754) + 时间戳 拼成字节串
      4. SHA-256 后混入熵池

    熵源本质：传感器 ADC 读数的末位抖动、系统调度延迟、
    Android 传感器 HAL 的微秒级时间戳抖动。
    """

    def __init__(self, pool, use_hash_stir: bool = True,
                 read_interval_ms: int = 500):
        self.pool = pool
        self.use_hash_stir = use_hash_stir
        self.read_interval_ms = read_interval_ms
        self._running = False
        self._total_bits = 0
        self._sensor_cache: Optional[List[str]] = None
        self._available = False
        self._last_readings: Dict[str, Any] = {}
        self._read_count = 0

        if not is_termux():
            logger.debug("非 Termux 环境，Termux 传感器熵源跳过")
            return

        if not _have_termux_api():
            logger.warning("termux-sensor 命令未找到，"
                           "请执行 `pkg install termux-api` 并安装 Termux:API 应用")
            return

        try:
            sensors = self._list_sensors()
            if sensors:
                self._available = True
                self._sensor_cache = sensors
                logger.info(f"📱 Termux 传感器: 发现 {len(sensors)} 个")
                for s in sensors[:10]:
                    logger.info(f"    - {s}")
                if len(sensors) > 10:
                    logger.info(f"    ... 还有 {len(sensors) - 10} 个")
            else:
                logger.warning("Termux 未检测到任何传感器（权限或硬件缺失）")
        except Exception as e:
            logger.warning(f"Termux 传感器初始化失败: {e}")

    # ------------------------------------------------------------------
    @property
    def available(self) -> bool:
        return self._available

    @property
    def total_bits(self) -> int:
        return self._total_bits

    @property
    def sensor_count(self) -> int:
        return len(self._sensor_cache) if self._sensor_cache else 0

    @property
    def read_count(self) -> int:
        return self._read_count

    def sensor_list(self) -> List[str]:
        return list(self._sensor_cache) if self._sensor_cache else []

    # ------------------------------------------------------------------
    # 传感器枚举 & 读取
    # ------------------------------------------------------------------
    def _list_sensors(self) -> List[str]:
        """列出所有可用传感器（termux-sensor -l）"""
        try:
            result = subprocess.run(
                ["termux-sensor", "-l"],
                capture_output=True, text=True, timeout=10
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug(f"termux-sensor -l 失败: {e}")
            return []

        if result.returncode != 0:
            logger.debug(f"termux-sensor -l 返回 {result.returncode}: "
                         f"{result.stderr.strip()}")
            return []

        raw = result.stdout.strip()
        if not raw:
            return []

        # 优先按 JSON 解析
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [str(x) for x in data]
            if isinstance(data, dict):
                # 有些实现包一层 {"sensors": [...]}
                sensors = data.get("sensors") or data.get("list") or []
                return [str(x) for x in sensors]
        except json.JSONDecodeError:
            pass

        # 回退：按行/逗号拆
        parts = []
        for line in raw.split("\n"):
            line = line.strip().strip(",").strip("[]").strip()
            if not line:
                continue
            parts.extend(p.strip().strip('"').strip("'")
                         for p in line.split(",") if p.strip())
        return [p for p in parts if p]

    def _read_all_sensors(self) -> Optional[Dict[str, Any]]:
        """
        一次性读取所有传感器（termux-sensor -a -n 1）。

        典型输出：
        {
          "accelerometer":   {"values": [x, y, z], "timestamp": 1234567890},
          "gyroscope":       {"values": [x, y, z], "timestamp": 1234567891},
          "magnetic_field":  {"values": [x, y, z], "timestamp": 1234567892},
          ...
        }
        """
        timeout_s = self.read_interval_ms / 1000.0 + 5.0
        try:
            result = subprocess.run(
                ["termux-sensor", "-a", "-n", "1"],
                capture_output=True, text=True, timeout=timeout_s
            )
        except subprocess.TimeoutExpired:
            logger.debug("termux-sensor 读取超时")
            return None
        except FileNotFoundError:
            self._available = False
            return None

        if result.returncode != 0:
            logger.debug(f"termux-sensor 返回 {result.returncode}: "
                         f"{result.stderr.strip()}")
            return None

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.debug("termux-sensor 输出非 JSON")
            return None

    # ------------------------------------------------------------------
    # 单次采集
    # ------------------------------------------------------------------
    async def collect_once(self) -> int:
        """采集一次传感器数据并混入熵池，返回混入的 bit 数"""
        if not self._available:
            return 0

        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, self._read_all_sensors)
        except Exception as e:
            logger.debug(f"Termux 传感器采集失败: {e}")
            return 0

        if not data or not isinstance(data, dict):
            return 0

        raw = bytearray()
        for sensor_name, reading in data.items():
            # 有些实现 readings 直接是 list，有些是 dict
            values = []
            ts = 0
            if isinstance(reading, dict):
                values = reading.get("values", [])
                ts = reading.get("timestamp", 0)
            elif isinstance(reading, list):
                values = reading
            else:
                continue

            # 传感器名也参与哈希（防串换）
            raw.extend(sensor_name.encode("utf-8", errors="ignore"))
            raw.append(0x00)

            # float 数组按 IEEE754 小端打包
            for v in values:
                try:
                    raw.extend(struct.pack("<f", float(v)))
                except (ValueError, TypeError):
                    continue

            # 时间戳（int64 小端）
            try:
                raw.extend(struct.pack("<q", int(ts)))
            except (ValueError, TypeError, OverflowError):
                pass

        if not raw:
            return 0

        # 加一次纳秒抖动，进一步打散
        raw.extend(struct.pack("<Q", time.perf_counter_ns()))

        if self.use_hash_stir:
            h = hashlib.sha256(bytes(raw)).digest()
        else:
            h = bytes(raw)[:32]

        self.pool.mix_bytes(h)
        self._total_bits += len(h) * 8
        self._read_count += 1
        self._last_readings = data
        return len(h) * 8

    # ------------------------------------------------------------------
    # 后台守护
    # ------------------------------------------------------------------
    async def start_daemon(self, interval_sec: float = 5.0):
        if not self._available:
            return
        self._running = True
        while self._running:
            try:
                await self.collect_once()
            except Exception as e:
                logger.debug(f"Termux daemon 异常: {e}")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False


# ====================================================================
# 手动扫描入口（供交互 shell 调用）
# ====================================================================
async def scan_all_sensors(pool, use_hash_stir: bool = True) -> int:
    """
    一次性扫描所有传感器并混池，返回混入 bit 数。
    不受 daemon 状态影响，每次调用都会真正读一遍。
    """
    if not is_termux():
        return 0
    if not _have_termux_api():
        return 0
    collector = TermuxSensorCollector(pool, use_hash_stir=use_hash_stir)
    if not collector.available:
        return 0
    return await collector.collect_once()