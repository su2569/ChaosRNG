#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络数据包采集模块（增强版）
- 根据系统权限和配置自动决定是否启用
- 抓到的包 payload 经 AES-256(熵池种子) 加密后 SHA256 哈希混入熵池
- 支持 scapy 和原始 socket 两种模式
- 与网络行为交替进行，避免抓到自己的流量
"""

import os
import time
import hashlib
import asyncio
import logging
import platform
from typing import Optional

logger = logging.getLogger("chaos_rng.packet")

# 尝试导入 scapy
try:
    from scapy.all import sniff, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    import socket

# AES-256 加密
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography 库未安装，将使用 HMAC-SHA256 替代 AES 加密")


class PacketCollector:
    """
    数据包采集器

    工作流程：
    1. 获取当前熵池 digest 作为 AES-256 key (32字节)
    2. 对包 payload 进行 AES-256-ECB 加密（PKCS7 padding）
    3. 对密文进行 SHA256 哈希
    4. 将哈希结果混入熵池
    """

    def __init__(
        self,
        pool,
        interface: Optional[str] = None,
        filter_expr: str = "tcp or udp",
        capture_duration: float = 15.0,
        max_payload: int = 256,
        prefer_scapy: bool = True,
        npcap_path: Optional[str] = None
    ):
        self.pool = pool
        self.interface = interface
        self.filter_expr = filter_expr
        self.capture_duration = capture_duration
        self.max_payload = max_payload
        self.prefer_scapy = prefer_scapy
        self.npcap_path = npcap_path

        self._capturing = False
        self._packets_captured = 0
        self._total_packets = 0

        # Windows: 尝试设置 Npcap/WinPcap 路径
        if platform.system().lower() == "windows":
            self._setup_windows_npcap()

        # 确定使用哪种后端
        self._backend = self._detect_backend()
        if self._backend == "none":
            logger.warning("无可用抓包后端，抓包功能将不可用")


    def _setup_windows_npcap(self):
        """Windows: 搜索并设置 Npcap/WinPcap 路径"""
        import platform
        if platform.system().lower() != "windows":
            return

        if self.npcap_path and os.path.exists(self.npcap_path):
            os.environ["SCAPY_INSTALL_ROOT"] = self.npcap_path
            logger.info(f"使用指定 Npcap 路径: {self.npcap_path}")
            return

        # 常见安装路径（按优先级排序）
        common_paths = [
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap",
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\WinPcap",
            r"C:\Windows\System32\drivers",
        ]

        # 用户虚拟存储路径
        user_profile = os.environ.get("USERPROFILE", "")
        if user_profile:
            common_paths.append(
                os.path.join(user_profile, r"AppData\Local\VirtualStore\Program Files\Npcap")
            )

        # 从注册表读取安装路径
        try:
            import winreg
            reg_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinPcap"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\WinPcap"),
            ]
            for hkey, reg_path in reg_paths:
                try:
                    key = winreg.OpenKey(hkey, reg_path)
                    install_path, _ = winreg.QueryValueEx(key, "")
                    if install_path and os.path.exists(install_path):
                        common_paths.insert(0, install_path)
                    winreg.CloseKey(key)
                except (FileNotFoundError, OSError):
                    pass
        except ImportError:
            pass

        # 搜索路径
        for path in common_paths:
            if os.path.exists(path):
                # 检查 wpcap.dll 或 npcap.sys
                for check_file in ["wpcap.dll", "npcap.sys", "Packet.dll", "NPFInstall.exe"]:
                    check_path = os.path.join(path, check_file)
                    if os.path.exists(check_path):
                        os.environ["SCAPY_INSTALL_ROOT"] = path
                        # 关键: 将 Npcap 目录添加到系统 PATH，让 scapy 能找到 DLL
                        if path not in os.environ.get("PATH", ""):
                            os.environ["PATH"] = path + os.pathsep + os.environ.get("PATH", "")
                        logger.info(f"找到 Npcap/WinPcap: {path} ({check_file})")
                        return

        logger.warning("未找到 Npcap/WinPcap，Windows 抓包可能不可用。请从 https://npcap.com/ 安装")

    def _try_import_scapy(self) -> bool:
        """尝试导入 scapy（在设置 Npcap 路径后）"""
        global SCAPY_AVAILABLE
        if SCAPY_AVAILABLE:
            return True
        try:
            import sys
            # 清除 scapy 导入缓存，强制重新加载
            for mod_name in list(sys.modules.keys()):
                if mod_name == 'scapy' or mod_name.startswith('scapy.'):
                    del sys.modules[mod_name]
            from scapy.all import sniff, Raw
            SCAPY_AVAILABLE = True
            logger.info("✅ scapy 延迟导入成功")
            return True
        except Exception as e:
            logger.warning(f"scapy 导入失败: {e}")
            logger.warning("请确保已安装: pip install scapy")
            return False

    def _detect_backend(self) -> str:
        """检测可用的抓包后端"""
        # Windows: 如果之前 scapy 导入失败，但找到了 Npcap，重新尝试
        if platform.system().lower() == "windows":
            if not SCAPY_AVAILABLE:
                self._try_import_scapy()
            if SCAPY_AVAILABLE:
                logger.info("使用 scapy 作为抓包后端")
                return "scapy"
            # Windows 不支持原始 socket 抓包 (无 AF_PACKET)
            logger.warning("Windows 上无 scapy，抓包不可用")
            return "none"

        # Linux/macOS
        if self.prefer_scapy and SCAPY_AVAILABLE:
            logger.info("使用 scapy 作为抓包后端")
            return "scapy"

        # 检查原始 socket 权限 (Linux/macOS only)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            logger.info("使用原始 socket 作为抓包后端（root）")
            return "raw_socket"

        logger.warning("无足够权限进行抓包，scapy 和原始 socket 均不可用")
        return "none"

    def _encrypt_and_hash(self, data: bytes) -> bytes:
        """
        使用当前熵池种子进行 AES-256 加密后再 SHA256 哈希
        """
        key = self.pool.digest()
        payload = data[:self.max_payload]

        if CRYPTO_AVAILABLE:
            try:
                padder = padding.PKCS7(128).padder()
                padded = padder.update(payload) + padder.finalize()

                cipher = Cipher(algorithms.AES(key), modes.ECB())
                encryptor = cipher.encryptor()
                encrypted = encryptor.update(padded) + encryptor.finalize()

                return hashlib.sha256(encrypted).digest()
            except Exception as e:
                logger.debug(f"AES 加密失败，回退到 HMAC: {e}")

        # 回退方案：HMAC-SHA256
        import hmac
        return hmac.new(key, payload, hashlib.sha256).digest()

    def _packet_handler(self, packet):
        """scapy 包处理回调"""
        try:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if len(payload) > 0:
                    hash_result = self._encrypt_and_hash(payload)
                    self.pool.mix_bytes(hash_result)
                    self._packets_captured += 1
        except Exception as e:
            logger.debug(f"包处理异常: {e}")

    async def capture_once(self) -> int:
        """执行一次抓包，返回捕获到的有效包数量"""
        if self._capturing:
            logger.warning("已有抓包任务在运行，跳过")
            return 0

        if self._backend == "none":
            logger.warning("抓包后端不可用，跳过")
            return 0

        self._capturing = True
        self._packets_captured = 0
        start_time = time.time()

        try:
            if self._backend == "scapy":
                await self._capture_scapy()
            else:
                await self._capture_raw_socket()
        except Exception as e:
            logger.error(f"抓包异常: {e}")
        finally:
            self._capturing = False
            elapsed = time.time() - start_time
            self._total_packets += self._packets_captured
            logger.info(f"抓包完成: 捕获 {self._packets_captured} 个包, 耗时 {elapsed:.1f}s")

        return self._packets_captured

    async def _capture_scapy(self):
        """使用 scapy 抓包"""
        loop = asyncio.get_event_loop()

        def _sniff():
            sniff(
                iface=self.interface,
                filter=self.filter_expr,
                prn=self._packet_handler,
                timeout=self.capture_duration,
                store=False
            )

        await loop.run_in_executor(None, _sniff)

    async def _capture_raw_socket(self):
        """使用原始 socket 抓包（备用方案，Linux/macOS only）"""
        import platform
        if platform.system().lower() == "windows":
            logger.error("Windows 不支持原始 socket 抓包，请安装 scapy + Npcap/WinPcap")
            return
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                sock.bind((self.interface, 0))
            sock.setblocking(False)

            start = time.time()
            while time.time() - start < self.capture_duration:
                try:
                    raw, addr = sock.recvfrom(65535)
                    if len(raw) > 14:
                        ip_header_len = (raw[14] & 0x0F) * 4
                        payload_start = 14 + ip_header_len
                        if len(raw) > payload_start:
                            payload = raw[payload_start:payload_start + self.max_payload]
                            hash_result = self._encrypt_and_hash(payload)
                            self.pool.mix_bytes(hash_result)
                            self._packets_captured += 1
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                except Exception:
                    pass

            sock.close()
        except PermissionError:
            logger.error("原始 socket 需要 root 权限")
        except Exception as e:
            logger.error(f"原始 socket 抓包失败: {e}")

    @property
    def is_capturing(self) -> bool:
        return self._capturing

    @property
    def total_packets(self) -> int:
        return self._total_packets

    @property
    def available(self) -> bool:
        return self._backend != "none"
