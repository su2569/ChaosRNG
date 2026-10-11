#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Termux 附加熵源（无麦克风/摄像头）

五大类：
  1. 网络类    — DNS 时延、TCP RTT、网络接口统计、ARP 表
  2. 内核类    — 内核熵池、负载、软中断、调度、分页、上下文切换
  3. 时钟类    — perf_counter_ns 纳秒抖动、多种时钟源对比
  4. 电池类    — termux-battery-status 电压/电流/温度
  5. 进程类    — 后台进程状态、FD、内存映射

每个类统一接口：
  available / collect_once() / start_daemon(interval) / stop() / total_bits
"""

import os
import re
import time
import math
import shutil
import struct
import socket
import hashlib
import logging
import asyncio
import subprocess
from pathlib import Path

logger = logging.getLogger("chaos_rng.termux_extra")


def _have_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def _safe_read(path: str, max_bytes: int = 8192) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except (OSError, PermissionError):
        return b""


def _safe_read_lines(path: str, prefix: bytes = None,
                     max_lines: int = 32, max_bytes: int = 8192) -> bytes:
    """读文件，只取指定前缀的行"""
    try:
        buf = bytearray()
        with open(path, "rb") as f:
            for line in f:
                if prefix is None or line.startswith(prefix):
                    buf.extend(line[:256])
                    if len(buf) > max_bytes:
                        break
                    if buf.count(b"\n") >= max_lines:
                        break
        return bytes(buf)
    except (OSError, PermissionError):
        return b""


# ====================================================================
# 基类（统一接口）
# ====================================================================
class _BaseCollector:
    name = "base"

    def __init__(self, pool, use_hash_stir=True):
        self.pool = pool
        self.use_hash_stir = use_hash_stir
        self._running = False
        self._total_bits = 0
        self._read_count = 0
        self._available = True

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
        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, self._sample)
        except Exception as e:
            logger.debug(f"{self.name} 采集失败: {e}")
            return 0
        if not data:
            return 0
        h = hashlib.sha256(data).digest() if self.use_hash_stir else data[:32]
        self.pool.mix_bytes(h)
        self._total_bits += len(h) * 8
        self._read_count += 1
        return len(h) * 8

    def _sample(self) -> bytes:
        """子类实现：返回原始字节"""
        return b""

    async def start_daemon(self, interval_sec=5.0):
        if not self._available:
            return
        self._running = True
        while self._running:
            try:
                await self.collect_once()
            except Exception as e:
                logger.debug(f"{self.name} daemon 异常: {e}")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False


# ====================================================================
# 一、网络类
# ====================================================================
class NetDNSCollector(_BaseCollector):
    """DNS 查询时延抖动"""
    name = "termux_dns"

    def __init__(self, pool, use_hash_stir=True,
                 hosts=None, samples=8):
        super().__init__(pool, use_hash_stir)
        self.hosts = hosts or [
            "one.one.one.one", "dns.google", "cloudflare.com",
            "example.com", "wikipedia.org", "github.com",
        ]
        self.samples = samples
        logger.info("🌐 DNS 时延熵源已就绪")

    def _sample(self):
        buf = bytearray()
        for host in self.hosts[:self.samples]:
            try:
                t0 = time.perf_counter_ns()
                try:
                    ip = socket.gethostbyname(host)
                except socket.gaierror:
                    ip = "0.0.0.0"
                t1 = time.perf_counter_ns()
                buf.extend(struct.pack("<q", t1 - t0))
                buf.extend(ip.encode())
            except Exception:
                pass
        return bytes(buf)


class NetRTTCollector(_BaseCollector):
    """TCP 连接 RTT 抖动"""
    name = "termux_tcp_rtt"

    def __init__(self, pool, use_hash_stir=True,
                 targets=None, timeout=2.0):
        super().__init__(pool, use_hash_stir)
        self.targets = targets or [
            ("1.1.1.1", 443),
            ("8.8.8.8", 443),
            ("1.1.1.1", 53),
            ("8.8.8.8", 53),
        ]
        self.timeout = timeout
        logger.info("🌐 TCP RTT 熵源已就绪")

    def _sample(self):
        buf = bytearray()
        for host, port in self.targets:
            try:
                t0 = time.perf_counter_ns()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                try:
                    s.connect((host, port))
                    ok = 1
                except Exception:
                    ok = 0
                t1 = time.perf_counter_ns()
                s.close()
                buf.extend(struct.pack("<qQ", t1 - t0, ok))
            except Exception:
                pass
        return bytes(buf)


class NetIfCollector(_BaseCollector):
    """网络接口收发包统计"""
    name = "termux_net_if"

    def __init__(self, pool, use_hash_stir=True):
        super().__init__(pool, use_hash_stir)
        logger.info("🌐 网络接口统计熵源已就绪")

    def _sample(self):
        buf = bytearray()
        buf.extend(_safe_read("/proc/net/dev", 4096))
        buf.extend(_safe_read("/proc/net/snmp", 4096))
        buf.extend(_safe_read("/proc/net/netstat", 4096))
        buf.extend(_safe_read("/proc/net/arp", 2048))
        buf.extend(_safe_read("/proc/net/route", 2048))
        buf.extend(_safe_read("/proc/net/tcp", 4096))
        buf.extend(_safe_read("/proc/net/udp", 4096))
        buf.extend(struct.pack("<Q", time.perf_counter_ns()))
        return bytes(buf)


# ====================================================================
# 二、内核类
# ====================================================================
class KernelEntropyCollector(_BaseCollector):
    """内核熵池估计值"""
    name = "termux_entropy_avail"

    def __init__(self, pool, use_hash_stir=True):
        super().__init__(pool, use_hash_stir)
        logger.info("🎲 内核熵池熵源已就绪")

    def _sample(self):
        buf = bytearray()
        buf.extend(_safe_read("/proc/sys/kernel/random/entropy_avail", 32))
        buf.extend(_safe_read("/proc/sys/kernel/random/poolsize", 32))
        buf.extend(_safe_read("/proc/sys/kernel/random/urandom_min_reseed_secs", 32))
        buf.extend(struct.pack("<Q", time.perf_counter_ns()))
        return bytes(buf)


class KernelStatCollector(_BaseCollector):
    """负载、软中断、调度、分页、上下文切换"""
    name = "termux_kernel_stat"

    def __init__(self, pool, use_hash_stir=True):
        super().__init__(pool, use_hash_stir)
        logger.info("⚙️ 内核统计熵源已就绪")

    def _sample(self):
        buf = bytearray()
        # 负载
        buf.extend(_safe_read("/proc/loadavg", 128))
        # 软中断
        buf.extend(_safe_read("/proc/softirqs", 4096))
        # 调度统计
        buf.extend(_safe_read("/proc/schedstat", 2048))
        # 分页
        buf.extend(_safe_read_lines("/proc/vmstat", max_lines=64))
        # 上下文切换 + 中断 + 进程数
        buf.extend(_safe_read_lines("/proc/stat",
                                    prefix=b"cpu", max_lines=16))
        buf.extend(_safe_read_lines("/proc/stat",
                                    prefix=b"intr", max_lines=4))
        buf.extend(_safe_read_lines("/proc/stat",
                                    prefix=b"ctxt", max_lines=4))
        buf.extend(_safe_read_lines("/proc/stat",
                                    prefix=b"processes", max_lines=4))
        buf.extend(_safe_read_lines("/proc/stat",
                                    prefix=b"procs_running", max_lines=4))
        # 中断（可能没权限）
        buf.extend(_safe_read("/proc/interrupts", 4096))
        # 时间戳
        buf.extend(struct.pack("<Q", time.perf_counter_ns()))
        return bytes(buf)


# ====================================================================
# 三、时钟类
# ====================================================================
class ClockJitterCollector(_BaseCollector):
    """
    CPU 时钟纳秒抖动
    最纯净的、零依赖的真随机源
    """
    name = "termux_clock"

    def __init__(self, pool, use_hash_stir=True, samples=2048):
        super().__init__(pool, use_hash_stir)
        self.samples = samples
        logger.info(f"⏱️ 时钟抖动熵源已就绪 (samples={samples})")

    def _sample(self):
        buf = bytearray()
        # 连续拉纳秒时间戳
        prev = time.perf_counter_ns()
        for _ in range(self.samples):
            now = time.perf_counter_ns()
            delta = now - prev
            buf.extend(struct.pack("<q", delta))
            prev = now

        # 采样 3 种时钟，对比偏移
        try:
            t_perf = time.perf_counter_ns()
            t_mono = time.monotonic_ns()
            t_wall = time.time_ns()
            buf.extend(struct.pack("<QQQ", t_perf, t_mono, t_wall))
        except Exception:
            pass

        # CPU 时间戳（如果可用）
        try:
            with open("/proc/uptime", "rb") as f:
                buf.extend(f.read(64))
        except Exception:
            pass

        return bytes(buf)


# ====================================================================
# 四、电池类
# ====================================================================
class BatteryCollector(_BaseCollector):
    """termux-battery-status"""
    name = "termux_battery"

    def __init__(self, pool, use_hash_stir=True):
        super().__init__(pool, use_hash_stir)
        if not _have_cmd("termux-battery-status"):
            self._available = False
            logger.debug("termux-battery-status 不可用，跳过")
            return
        logger.info("🔋 电池状态熵源已就绪")

    def _sample(self):
        try:
            r = subprocess.run(["termux-battery-status"],
                               capture_output=True, timeout=5)
            if r.returncode == 0 and r.stdout:
                return r.stdout
        except Exception:
            pass
        return b""


# ====================================================================
# 五、进程类
# ====================================================================
class ProcStateCollector(_BaseCollector):
    """后台进程、FD、内存映射"""
    name = "termux_proc_state"

    def __init__(self, pool, use_hash_stir=True, max_procs=64):
        super().__init__(pool, use_hash_stir)
        self.max_procs = max_procs
        logger.info("🔧 进程状态熵源已就绪")

    def _sample(self):
        buf = bytearray()

        # 全进程列表（PID + CPU 时间 + RSS + 状态）
        try:
            r = subprocess.run(
                ["ps", "-eo", "pid,ppid,utime,stime,rss,vsz,ni,stat"],
                capture_output=True, timeout=3,
            )
            if r.returncode == 0:
                lines = r.stdout.split(b"\n")
                buf.extend(b"\n".join(lines[:self.max_procs]))
        except Exception:
            pass

        # 自身 FD 数
        try:
            mypid = os.getpid()
            fds = os.listdir(f"/proc/{mypid}/fd")
            buf.extend(struct.pack("<H", len(fds)))
        except Exception:
            pass

        # 自身内存映射
        try:
            mypid = os.getpid()
            buf.extend(_safe_read(f"/proc/{mypid}/maps", 4096))
        except Exception:
            pass

        # 内核状态
        buf.extend(_safe_read("/proc/stat", 2048))

        return bytes(buf)


# ====================================================================
# 便捷启动器
# ====================================================================
def build_all(pool, cfg=None):
    """
    根据配置构建全部采集器

    cfg 结构（可选）:
      {
        "dns": {"enabled": True, "interval": 30, "samples": 8},
        "tcp_rtt": {"enabled": True, "interval": 30},
        "net_if": {"enabled": True, "interval": 5},
        "kernel_entropy": {"enabled": True, "interval": 5},
        "kernel_stat": {"enabled": True, "interval": 5},
        "clock": {"enabled": True, "interval": 1, "samples": 2048},
        "battery": {"enabled": True, "interval": 15},
        "proc_state": {"enabled": True, "interval": 3},
      }
    """
    cfg = cfg or {}

    def get(key, default=None):
        return cfg.get(key, default or {})

    collectors = []

    # 1. 时钟（最高优先级）
    if get("clock").get("enabled", True):
        try:
            collectors.append((ClockJitterCollector(
                pool,
                samples=get("clock").get("samples", 2048),
            ), get("clock").get("interval", 1)))
        except Exception as e:
            logger.warning(f"时钟抖动加载失败: {e}")

    # 2. 内核
    if get("kernel_entropy").get("enabled", True):
        try:
            collectors.append((KernelEntropyCollector(pool),
                               get("kernel_entropy").get("interval", 5)))
        except Exception as e:
            logger.warning(f"内核熵池加载失败: {e}")

    if get("kernel_stat").get("enabled", True):
        try:
            collectors.append((KernelStatCollector(pool),
                               get("kernel_stat").get("interval", 5)))
        except Exception as e:
            logger.warning(f"内核统计加载失败: {e}")

    # 3. 网络
    if get("dns").get("enabled", True):
        try:
            collectors.append((NetDNSCollector(
                pool,
                samples=get("dns").get("samples", 8),
            ), get("dns").get("interval", 30)))
        except Exception as e:
            logger.warning(f"DNS 时延加载失败: {e}")

    if get("tcp_rtt").get("enabled", True):
        try:
            collectors.append((NetRTTCollector(pool),
                               get("tcp_rtt").get("interval", 30)))
        except Exception as e:
            logger.warning(f"TCP RTT 加载失败: {e}")

    if get("net_if").get("enabled", True):
        try:
            collectors.append((NetIfCollector(pool),
                               get("net_if").get("interval", 5)))
        except Exception as e:
            logger.warning(f"网络接口加载失败: {e}")

    # 4. 电池
    if get("battery").get("enabled", True):
        try:
            c = BatteryCollector(pool)
            if c.available:
                collectors.append((c, get("battery").get("interval", 15)))
        except Exception as e:
            logger.warning(f"电池加载失败: {e}")

    # 5. 进程
    if get("proc_state").get("enabled", True):
        try:
            collectors.append((ProcStateCollector(pool),
                               get("proc_state").get("interval", 3)))
        except Exception as e:
            logger.warning(f"进程状态加载失败: {e}")

    return collectors
