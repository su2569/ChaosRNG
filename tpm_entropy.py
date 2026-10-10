#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TPM (Trusted Platform Module) 熵采集模块

利用 TPM 芯片提供的硬件级随机数生成和平台状态寄存器(PCR)值作为熵源。

支持平台：
- Linux: /dev/tpm0, /dev/tpmrm0, tpm2-tools
- Windows: TBS (TPM Base Services) via ctypes, CNG
"""

import os
import sys
import time
import hashlib
import asyncio
import logging
import platform
import subprocess
from typing import Optional, List, Tuple

logger = logging.getLogger("chaos_rng.tpm")


class TPMEntropyCollector:
    """
    TPM 熵采集器

    采集来源：
    1. TPM RNG (getrandom) - 硬件真随机数
    2. PCR 寄存器值 - 平台启动状态的哈希链
    3. TPM 时钟/计数器 - 单调计数器的微小抖动
    """

    def __init__(self, pool, use_pcr: bool = True, use_rng: bool = True):
        self.pool = pool
        self.use_pcr = use_pcr
        self.use_rng = use_rng
        self._running = False
        self._total_bits = 0
        self._backend = None
        self._system = platform.system().lower()

        # 检测可用后端
        self._detect_backend()

    def _detect_backend(self):
        """检测 TPM 可用性"""
        if self._system == "linux":
            # 检查 /dev/tpmrm0 (resource manager, 推荐) 或 /dev/tpm0
            if os.path.exists("/dev/tpmrm0"):
                self._backend = "linux_tpmrm"
                logger.info("TPM 后端: /dev/tpmrm0")
            elif os.path.exists("/dev/tpm0"):
                self._backend = "linux_tpm0"
                logger.info("TPM 后端: /dev/tpm0")
            elif self._check_tpm2_tools():
                self._backend = "tpm2_tools"
                logger.info("TPM 后端: tpm2-tools")
        elif self._system == "windows":
            if self._check_windows_tbs():
                self._backend = "windows_tbs"
                logger.info("TPM 后端: Windows TBS")

        if not self._backend:
            logger.warning("未检测到 TPM 设备，TPM 熵源将不可用")

    def _check_tpm2_tools(self) -> bool:
        """检查 tpm2-tools 是否可用"""
        try:
            result = subprocess.run(
                ["tpm2", "getcap", "properties-fixed"],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_windows_tbs(self) -> bool:
        """检查 Windows TPM Base Services"""
        try:
            import ctypes
            # 尝试加载 TBS DLL
            tbs = ctypes.windll.LoadLibrary("Tbs.dll")
            return True
        except Exception:
            return False

    @property
    def available(self) -> bool:
        return self._backend is not None

    # ---------- 采集方法 ----------
    async def collect_once(self) -> int:
        """执行一次 TPM 熵采集"""
        total_bits = 0

        if self.use_rng:
            rng_data = await self._get_tpm_random()
            if rng_data:
                self.pool.mix_bytes(rng_data)
                total_bits += len(rng_data) * 8

        if self.use_pcr:
            pcr_data = await self._get_pcr_values()
            if pcr_data:
                self.pool.mix_bytes(pcr_data)
                total_bits += len(pcr_data) * 8

        # TPM 时钟/计数器
        clock_data = await self._get_tpm_clock()
        if clock_data:
            self.pool.mix_bytes(clock_data)
            total_bits += len(clock_data) * 8

        self._total_bits += total_bits
        return total_bits

    async def _get_tpm_random(self) -> Optional[bytes]:
        """从 TPM 获取硬件随机数"""
        try:
            if self._backend == "linux_tpmrm" or self._backend == "linux_tpm0":
                return await self._get_tpm_random_linux()
            elif self._backend == "tpm2_tools":
                return await self._get_tpm_random_tools()
            elif self._backend == "windows_tbs":
                return await self._get_tpm_random_windows()
        except Exception as e:
            logger.debug(f"TPM RNG 获取失败: {e}")
        return None

    async def _get_tpm_random_linux(self) -> Optional[bytes]:
        """Linux: 直接读取 TPM 设备获取随机数"""
        loop = asyncio.get_event_loop()

        def _read():
            device = "/dev/tpmrm0" if self._backend == "linux_tpmrm" else "/dev/tpm0"
            # TPM2_GetRandom 命令: 8001 0000 000c 0000 0144 00??
            # 请求 32 字节随机数
            cmd = bytes([
                0x80, 0x01,  # tag: SESSIONS
                0x00, 0x00, 0x00, 0x0c,  # size
                0x00, 0x00, 0x01, 0x7b,  # TPM_CC_GetRandom
                0x00, 0x20   # 32 bytes requested
            ])

            with open(device, "rb+") as f:
                f.write(cmd)
                f.flush()
                resp = f.read(64)

            # 解析响应 (简单处理：跳过头部取数据)
            if len(resp) > 14:
                return resp[14:14+32]
            return None

        return await loop.run_in_executor(None, _read)

    async def _get_tpm_random_tools(self) -> Optional[bytes]:
        """Linux: 使用 tpm2_getrandom"""
        loop = asyncio.get_event_loop()

        def _run():
            result = subprocess.run(
                ["tpm2", "getrandom", "32", "--hex"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return bytes.fromhex(result.stdout.strip())
            return None

        return await loop.run_in_executor(None, _run)

    async def _get_tpm_random_windows(self) -> Optional[bytes]:
        """Windows: 使用 TBS 或 CNG"""
        loop = asyncio.get_event_loop()

        def _read():
            import ctypes
            from ctypes import wintypes

            # 尝试使用 BCryptGenRandom with BCRYPT_RNG_USE_ENTROPY_IN_BUFFER
            bcrypt = ctypes.windll.LoadLibrary("bcrypt.dll")

            # 使用 TPM 支持的 RNG
            # 实际上 Windows CNG 会自动使用 TPM 如果可用
            buffer = ctypes.create_string_buffer(32)

            # BCryptGenRandom
            status = bcrypt.BCryptGenRandom(
                None,  # hAlgorithm
                buffer,
                32,
                0x00000002  # BCRYPT_RNG_USE_ENTROPY_IN_BUFFER
            )

            if status == 0:  # STATUS_SUCCESS
                return buffer.raw
            return None

        return await loop.run_in_executor(None, _read)

    async def _get_pcr_values(self) -> Optional[bytes]:
        """读取 TPM PCR 寄存器值"""
        try:
            if self._backend in ("linux_tpmrm", "linux_tpm0", "tpm2_tools"):
                return await self._get_pcr_linux()
            elif self._backend == "windows_tbs":
                return await self._get_pcr_windows()
        except Exception as e:
            logger.debug(f"PCR 读取失败: {e}")
        return None

    async def _get_pcr_linux(self) -> Optional[bytes]:
        """Linux: 读取 PCR 值"""
        loop = asyncio.get_event_loop()

        def _read():
            if self._backend == "tpm2_tools":
                result = subprocess.run(
                    ["tpm2", "pcrread", "sha256:0,1,2,3,4,5,6,7"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return hashlib.sha256(result.stdout.encode()).digest()
            else:
                # 直接读取 TPM 设备
                device = "/dev/tpmrm0" if self._backend == "linux_tpmrm" else "/dev/tpm0"
                # TPM2_PCR_Read 命令
                cmd = bytes([
                    0x80, 0x01,
                    0x00, 0x00, 0x00, 0x14,  # size
                    0x00, 0x00, 0x01, 0x7e,  # TPM_CC_PCR_Read
                    0x00, 0x00, 0x00, 0x01,  # count = 1
                    0x03, 0x00, 0x00, 0x0b,  # sha256
                    0x00, 0x00, 0x00, 0x00   # pcr 0
                ])
                with open(device, "rb+") as f:
                    f.write(cmd)
                    f.flush()
                    resp = f.read(128)
                if len(resp) > 32:
                    return hashlib.sha256(resp).digest()
            return None

        return await loop.run_in_executor(None, _read)

    async def _get_pcr_windows(self) -> Optional[bytes]:
        """Windows: 使用 WMI 或 TBS 读取 PCR"""
        loop = asyncio.get_event_loop()

        def _read():
            try:
                import win32com.client
                wmi = win32com.client.GetObject("winmgmts:")
                # 查询 TPM 信息
                tpm = wmi.ExecQuery("SELECT * FROM Win32_Tpm")
                data = []
                for t in tpm:
                    data.append(str(t.IsActivated_InitialValue))
                    data.append(str(t.IsEnabled_InitialValue))
                    data.append(str(t.IsOwned_InitialValue))

                if data:
                    return hashlib.sha256("|".join(data).encode()).digest()
            except Exception:
                pass
            return None

        return await loop.run_in_executor(None, _read)

    async def _get_tpm_clock(self) -> Optional[bytes]:
        """获取 TPM 时钟/计数器"""
        # 使用系统时间 + TPM 状态作为替代
        # 真实 TPM 时钟需要更复杂的命令
        try:
            data = str(time.perf_counter_ns()).encode()
            if self._backend:
                data += b":" + self._backend.encode()
            return hashlib.sha256(data).digest()
        except Exception:
            return None

    async def start_daemon(self, interval_sec: float = 60.0):
        """后台持续采集"""
        self._running = True
        while self._running:
            bits = await self.collect_once()
            if bits > 0:
                logger.debug(f"TPM 采集 {bits} bits")
            await asyncio.sleep(interval_sec)

    def stop(self):
        self._running = False

    @property
    def total_bits(self) -> int:
        return self._total_bits
