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
        prefer_scapy: bool = True
    ):
        self.pool = pool
        self.interface = interface
        self.filter_expr = filter_expr
        self.capture_duration = capture_duration
        self.max_payload = max_payload
        self.prefer_scapy = prefer_scapy

        self._capturing = False
        self._packets_captured = 0
        self._total_packets = 0

        # 确定使用哪种后端
        self._backend = self._detect_backend()
        if self._backend == "none":
            logger.warning("无可用抓包后端，抓包功能将不可用")

    def _detect_backend(self) -> str:
        """检测可用的抓包后端"""
        if self.prefer_scapy and SCAPY_AVAILABLE:
            logger.info("使用 scapy 作为抓包后端")
            return "scapy"

        # 检查原始 socket 权限
        if platform.system().lower() == "windows":
            # Windows 原始 socket 需要管理员权限
            try:
                import ctypes
                if ctypes.windll.shell32.IsUserAnAdmin():
                    logger.info("使用原始 socket 作为抓包后端（Windows Admin）")
                    return "raw_socket"
            except Exception:
                pass
        else:
            # Linux/macOS 原始 socket 需要 root
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
        """使用原始 socket 抓包（备用方案）"""
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
