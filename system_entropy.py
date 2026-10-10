#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
系统级熵采集模块

采集来源：
1. 系统调度事件 - 进程/线程调度、上下文切换、CPU时间片
2. 会话数据 - 登录会话、环境变量、终端信息、用户活动
3. 系统事件日志 - journalctl/syslog/Event Log/FSEvents
4. 文件系统事件 - inotify/kqueue/FSEvents 监控
5. 系统调用计数 - /proc/stat, /proc/interrupts 等

所有数据经过加密哈希后混入熵池。
"""

import os
import re
import sys
import time
import json
import hashlib
import asyncio
import logging
import platform
import subprocess
from typing import Optional, Dict, List, Tuple, Any
from collections import deque

logger = logging.getLogger("chaos_rng.system")


class SystemEntropyCollector:
    """
    系统级熵采集器

    综合采集系统调度、会话、事件日志、文件系统变化等多维度熵源。
    """

    def __init__(self, pool):
        self.pool = pool
        self._running = False
        self._total_bits = 0
        self._system = platform.system().lower()

        # 会话数据缓存
        self._session_cache = {}
        self._last_sched_data = None
        self._last_interrupts = None

        # 文件系统监控
        self._fs_watcher = None
        self._fs_events = deque(maxlen=100)

    @property
    def available(self) -> bool:
        return True  # 总是可用（至少部分功能）

    # ---------- 主采集接口 ----------
    async def collect_once(self) -> int:
        """执行一次完整的系统熵采集"""
        total_bits = 0

        # 1. 系统调度数据
        sched_bits = await self._collect_scheduling()
        total_bits += sched_bits

        # 2. 会话数据
        session_bits = await self._collect_session()
        total_bits += session_bits

        # 3. 系统事件日志
        event_bits = await self._collect_events()
        total_bits += event_bits

        # 4. 系统调用计数/中断
        irq_bits = await self._collect_interrupts()
        total_bits += irq_bits

        # 5. 文件系统事件
        fs_bits = await self._collect_fs_events()
        total_bits += fs_bits

        # 6. 运行时环境抖动
        env_bits = await self._collect_environment_jitter()
        total_bits += env_bits

        self._total_bits += total_bits
        return total_bits

    # ---------- 1. 系统调度 ----------
    async def _collect_scheduling(self) -> int:
        """采集进程调度相关数据"""
        try:
            loop = asyncio.get_event_loop()

            def _read():
                data = {}

                if self._system == "linux":
                    # /proc/stat - CPU 时间片统计
                    try:
                        with open("/proc/stat", "r") as f:
                            data["stat"] = f.read(4096)
                    except:
                        pass

                    # /proc/schedstat - 调度统计
                    try:
                        with open("/proc/schedstat", "r") as f:
                            data["schedstat"] = f.read(2048)
                    except:
                        pass

                    # /proc/loadavg
                    try:
                        with open("/proc/loadavg", "r") as f:
                            data["loadavg"] = f.read().strip()
                    except:
                        pass

                    # 上下文切换数
                    try:
                        with open("/proc/vmstat", "r") as f:
                            content = f.read()
                            for line in content.split("\n"):
                                if "ctxt" in line or "pgpgin" in line or "pgpgout" in line:
                                    data["vmstat"] = data.get("vmstat", "") + line + "\n"
                    except:
                        pass

                elif self._system == "darwin":
                    # macOS: vm_stat
                    try:
                        result = subprocess.run(
                            ["vm_stat"], capture_output=True, text=True, timeout=5
                        )
                        data["vm_stat"] = result.stdout
                    except:
                        pass

                elif self._system == "windows":
                    # Windows: WMI 查询进程信息
                    try:
                        import win32com.client
                        wmi = win32com.client.GetObject("winmgmts:")
                        processes = wmi.ExecQuery("SELECT * FROM Win32_PerfRawData_PerfOS_System")
                        proc_data = []
                        for p in processes:
                            proc_data.append(f"{p.ContextSwitchesPersec}_{p.SystemCallsPersec}_{p.ProcessorQueueLength}")
                        data["wmi_perf"] = "|".join(proc_data)
                    except:
                        pass

                return data

            raw_data = await loop.run_in_executor(None, _read)

            if raw_data:
                json_str = json.dumps(raw_data, sort_keys=True)
                hash_bytes = hashlib.sha256(f"sched:{json_str}:{time.perf_counter_ns()}".encode()).digest()
                self.pool.mix_bytes(hash_bytes)
                return len(hash_bytes) * 8
        except Exception as e:
            logger.debug(f"调度采集失败: {e}")
        return 0

    # ---------- 2. 会话数据 ----------
    async def _collect_session(self) -> int:
        """
        采集会话和环境数据。
        安全策略：
        - 不存储环境变量原文
        - 每个值独立哈希（完整64字符 + 32字节随机盐）
        - 使用 bytearray 作为中间缓冲区，处理后立即清零
        - 最小化敏感值在显式变量中的生命周期
        """
        try:
            # 生成随机盐值，防止已知明文攻击
            salt = os.urandom(32)

            # 环境变量处理：只存键名，值做独立完整哈希（不截断）
            env_hashes = {}
            for key in sorted(os.environ.keys()):
                # 读取值后立即转 bytearray，哈希后清零
                value = os.environ[key]
                value_buf = bytearray(value, 'utf-8')
                try:
                    env_hashes[key] = hashlib.sha256(salt + value_buf).hexdigest()
                finally:
                    for i in range(len(value_buf)):
                        value_buf[i] = 0
                # 显式删除引用
                value = ""

            # 盐值也清零（只保留前缀用于验证）
            salt_prefix = salt.hex()[:16]
            for i in range(len(salt)):
                salt[i] = 0

            data = {
                "time_ns": time.perf_counter_ns(),
                "time_wall": time.time_ns(),
                "pid": os.getpid(),
                "ppid": os.getppid() if hasattr(os, "getppid") else 0,
                "uid": os.getuid() if hasattr(os, "getuid") else 0,
                "gid": os.getgid() if hasattr(os, "getgid") else 0,
                "cwd": os.getcwd(),
                "env_keys": sorted(os.environ.keys()),
                "env_hashes": env_hashes,  # 完整64字符哈希，加盐
                "salt_prefix": salt_prefix,  # 只记录盐值前缀
                "python_version": sys.version,
                "platform": platform.platform(),
                "processor": platform.processor(),
                "machine": platform.machine(),
                "cpu_count": os.cpu_count(),
            }

            # 终端信息
            try:
                data["ttyname"] = os.ttyname(0) if hasattr(os, "ttyname") else "none"
            except:
                pass

            # 会话ID
            try:
                data["sid"] = os.getsid(0) if hasattr(os, "getsid") else 0
            except:
                pass

            # 登录用户
            if self._system != "windows":
                try:
                    import pwd
                    pw = pwd.getpwuid(os.getuid())
                    data["user"] = pw.pw_name
                    data["shell"] = pw.pw_shell
                except:
                    pass

            json_str = json.dumps(data, sort_keys=True, default=str)
            hash_bytes = hashlib.sha256(f"session:{json_str}".encode()).digest()
            self.pool.mix_bytes(hash_bytes)
            return len(hash_bytes) * 8
        except Exception as e:
            logger.debug(f"会话采集失败: {e}")
        return 0

    # ---------- 3. 系统事件日志 ----------
    async def _collect_events(self) -> int:
        """采集系统事件日志"""
        try:
            loop = asyncio.get_event_loop()

            def _read_logs():
                logs = []

                if self._system == "linux":
                    # journalctl (systemd)
                    try:
                        result = subprocess.run(
                            ["journalctl", "--since", "1 minute ago", "--no-pager", "-q", "-n", "20"],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            logs.append(result.stdout)
                    except:
                        pass

                    # /var/log/syslog (fallback)
                    try:
                        result = subprocess.run(
                            ["tail", "-n", "10", "/var/log/syslog"],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            logs.append(result.stdout)
                    except:
                        pass

                    # dmesg
                    try:
                        result = subprocess.run(
                            ["dmesg", "|", "tail", "-n", "5"],
                            capture_output=True, text=True, timeout=5, shell=True
                        )
                        if result.returncode == 0:
                            logs.append(result.stdout)
                    except:
                        pass

                elif self._system == "darwin":
                    # macOS log
                    try:
                        result = subprocess.run(
                            ["log", "show", "--last", "1m", "--style", "compact"],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            logs.append(result.stdout[:4096])
                    except:
                        pass

                elif self._system == "windows":
                    # Windows Event Log
                    try:
                        import win32evtlog
                        hand = win32evtlog.OpenEventLog(None, "System")
                        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                        log_data = []
                        for ev in events[:10]:
                            log_data.append(f"{ev.TimeGenerated}_{ev.EventID}_{ev.SourceName}")
                        logs.append("|".join(log_data))
                        win32evtlog.CloseEventLog(hand)
                    except:
                        pass

                return "\n".join(logs)

            log_data = await loop.run_in_executor(None, _read_logs)

            if log_data:
                hash_bytes = hashlib.sha256(f"events:{log_data}:{time.perf_counter_ns()}".encode()).digest()
                self.pool.mix_bytes(hash_bytes)
                return len(hash_bytes) * 8
        except Exception as e:
            logger.debug(f"事件采集失败: {e}")
        return 0

    # ---------- 4. 中断统计 ----------
    async def _collect_interrupts(self) -> int:
        """采集硬件中断统计"""
        try:
            if self._system != "linux":
                return 0

            loop = asyncio.get_event_loop()

            def _read():
                try:
                    with open("/proc/interrupts", "r") as f:
                        return f.read(4096)
                except:
                    return None

            data = await loop.run_in_executor(None, _read)

            if data:
                # 只取变化的部分
                if self._last_interrupts != data:
                    self._last_interrupts = data
                    hash_bytes = hashlib.sha256(f"irq:{data}:{time.perf_counter_ns()}".encode()).digest()
                    self.pool.mix_bytes(hash_bytes)
                    return len(hash_bytes) * 8
        except Exception as e:
            logger.debug(f"中断采集失败: {e}")
        return 0

    # ---------- 5. 文件系统事件 ----------
    async def _collect_fs_events(self) -> int:
        """采集文件系统变化"""
        try:
            # 使用临时文件创建/删除的时序抖动
            loop = asyncio.get_event_loop()

            def _fs_jitter():
                import tempfile
                timings = []
                for _ in range(20):
                    t0 = time.perf_counter_ns()
                    fd, path = tempfile.mkstemp()
                    os.write(fd, os.urandom(64))
                    os.fsync(fd)
                    os.close(fd)
                    t1 = time.perf_counter_ns()
                    os.unlink(path)
                    timings.append(t1 - t0)
                return timings

            timings = await loop.run_in_executor(None, _fs_jitter)

            data = json.dumps(timings)
            hash_bytes = hashlib.sha256(f"fs:{data}".encode()).digest()
            self.pool.mix_bytes(hash_bytes)
            return len(hash_bytes) * 8
        except Exception as e:
            logger.debug(f"FS事件采集失败: {e}")
        return 0

    # ---------- 6. 环境抖动 ----------
    async def _collect_environment_jitter(self) -> int:
        """采集环境变量的微秒级变化"""
        try:
            # 多次快速读取环境并比较差异
            samples = []
            for _ in range(10):
                samples.append({
                    "time": time.perf_counter_ns(),
                    "env_count": len(os.environ),
                    "cwd": os.getcwd(),
                })
                time.sleep(0.001)  # 1ms

            data = json.dumps(samples, sort_keys=True)
            hash_bytes = hashlib.sha256(f"env_jitter:{data}".encode()).digest()
            self.pool.mix_bytes(hash_bytes)
            return len(hash_bytes) * 8
        except Exception as e:
            logger.debug(f"环境抖动采集失败: {e}")
        return 0

    async def start_daemon(self, interval_sec: float = 10.0):
        """后台持续采集"""
        self._running = True
        while self._running:
            bits = await self.collect_once()
            if bits > 0:
                logger.debug(f"系统熵采集 {bits} bits")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits
