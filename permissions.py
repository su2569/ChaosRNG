#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
权限管理模块
- 检测当前权限级别（Windows Admin / Linux root / macOS root）
- 自动请求提权（Windows UAC / Linux sudo）
- 功能可用性评估（根据权限决定哪些功能可以开启）
"""

import os
import sys
import ctypes
import platform
import subprocess
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger("chaos_rng.permissions")


class PermissionManager:
    """权限管理器"""

    def __init__(self):
        self.system = platform.system().lower()  # windows, linux, darwin
        self.is_admin = False
        self.is_root = False
        self.elevated = False
        self._check_privileges()

    def _check_privileges(self):
        """检测当前权限"""
        if self.system == "windows":
            try:
                self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                self.is_admin = False
            self.is_root = self.is_admin
        else:
            self.is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
            self.is_admin = self.is_root

        self.elevated = self.is_admin or self.is_root
        logger.info(f"系统: {platform.system()}, 管理员: {self.is_admin}, root: {self.is_root}")

    def request_elevation(self, script_path: Optional[str] = None, args: Optional[List[str]] = None) -> bool:
        """
        请求提权，以管理员/root重新运行当前脚本

        Windows: 使用 ShellExecute + runas 触发 UAC
        Linux: 使用 sudo 或 pkexec
        macOS: 使用 osascript 或 sudo

        返回 True 表示已尝试提权（程序将重启），False 表示无需提权或失败
        """
        if self.elevated:
            logger.info("已经是管理员/root权限，无需提权")
            return False

        if script_path is None:
            script_path = sys.argv[0]
        if args is None:
            args = sys.argv[1:]

        logger.info("正在请求管理员权限...")

        try:
            if self.system == "windows":
                return self._elevate_windows(script_path, args)
            elif self.system == "linux":
                return self._elevate_linux(script_path, args)
            elif self.system == "darwin":
                return self._elevate_macos(script_path, args)
            else:
                logger.warning(f"不支持在 {self.system} 上自动提权")
                return False
        except Exception as e:
            logger.error(f"提权失败: {e}")
            return False

    def _elevate_windows(self, script_path: str, args: List[str]) -> bool:
        """Windows UAC 提权"""
        try:
            # 构建命令行参数
            cmd = f'"{sys.executable}" "{script_path}"'
            if args:
                cmd += " " + " ".join(f'"{a}"' for a in args)

            # 添加 --elevated 标记，避免无限循环
            if "--elevated" not in args:
                cmd += " --elevated"

            logger.info(f"触发 UAC 提权: {cmd}")

            # ShellExecuteW 以 runas 启动
            ctypes.windll.shell32.ShellExecuteW(
                None,  # hwnd
                "runas",  # lpVerb
                sys.executable,  # lpFile
                f'"{script_path}" ' + " ".join(f'"{a}"' for a in args) + " --elevated",
                None,  # lpDirectory
                1  # nShowCmd (SW_SHOWNORMAL)
            )

            # 退出当前非特权进程
            logger.info("UAC 提权已触发，当前进程退出")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Windows 提权失败: {e}")
            return False

    def _elevate_linux(self, script_path: str, args: List[str]) -> bool:
        """Linux sudo 提权"""
        try:
            cmd = [sys.executable, script_path] + args
            if "--elevated" not in cmd:
                cmd.append("--elevated")

            # 尝试 pkexec（图形界面）
            if os.environ.get("DISPLAY"):
                try:
                    pkexec_cmd = ["pkexec"] + cmd
                    logger.info(f"尝试 pkexec 提权: {' '.join(pkexec_cmd)}")
                    subprocess.Popen(pkexec_cmd)
                    sys.exit(0)
                except Exception:
                    pass

            # 回退到 sudo
            sudo_cmd = ["sudo", "-E", "python3"] + cmd[1:]
            logger.info(f"尝试 sudo 提权: {' '.join(sudo_cmd)}")
            subprocess.Popen(sudo_cmd)
            sys.exit(0)

        except Exception as e:
            logger.error(f"Linux 提权失败: {e}")
            return False

    def _elevate_macos(self, script_path: str, args: List[str]) -> bool:
        """macOS 提权"""
        try:
            cmd = [sys.executable, script_path] + args
            if "--elevated" not in cmd:
                cmd.append("--elevated")

            # 尝试 osascript 弹窗提权
            script = f'do shell script "{" ".join(cmd)}" with administrator privileges'
            logger.info("尝试 osascript 提权")
            subprocess.Popen(["osascript", "-e", script])
            sys.exit(0)
        except Exception:
            # 回退 sudo
            try:
                sudo_cmd = ["sudo", "-E", "python3"] + cmd[1:]
                subprocess.Popen(sudo_cmd)
                sys.exit(0)
            except Exception as e:
                logger.error(f"macOS 提权失败: {e}")
                return False

    def evaluate_capabilities(self, user_config: Dict) -> Dict[str, bool]:
        """
        根据当前系统环境和权限，评估各功能的可用性

        返回一个字典，表示各功能是否应该启用
        """
        caps = {}

        # 1. 抓包（需要 root/admin 或特定权限）
        packet_enabled = user_config.get("packet_capture", {}).get("enabled", True)
        if packet_enabled:
            if self.elevated:
                # 检查 scapy 或原始 socket 可用性
                try:
                    import scapy.all
                    caps["packet_capture"] = True
                    logger.info("✅ 抓包功能可用 (scapy)")
                except ImportError:
                    # 原始 socket 也需要 root
                    caps["packet_capture"] = True
                    logger.info("✅ 抓包功能可用 (原始 socket)")
            else:
                caps["packet_capture"] = False
                logger.warning("⚠️ 无管理员权限，抓包功能已禁用")
        else:
            caps["packet_capture"] = False
            logger.info("抓包功能已手动禁用")

        # 2. 进程采集（不需要特殊权限，但部分信息可能受限）
        caps["process_collector"] = user_config.get("entropy", {}).get("process_enabled", True)

        # 3. 天气采集（需要网络）
        weather_enabled = user_config.get("entropy", {}).get("weather_enabled", True)
        if weather_enabled:
            try:
                import aiohttp
                caps["weather"] = True
                logger.info("✅ 天气采集可用")
            except ImportError:
                caps["weather"] = False
                logger.warning("⚠️ aiohttp 未安装，天气采集已禁用")
        else:
            caps["weather"] = False

        # 4. OneBot 客户端（需要 websockets）
        onebot_enabled = user_config.get("onebot", {}).get("enabled", True)
        if onebot_enabled:
            try:
                import websockets
                caps["onebot"] = True
                logger.info("✅ OneBot 客户端可用")
            except ImportError:
                caps["onebot"] = False
                logger.warning("⚠️ websockets 未安装，OneBot 已禁用")
        else:
            caps["onebot"] = False

        # 5. TCP 服务
        caps["tcp_server"] = user_config.get("tcp_server", {}).get("enabled", True)

        # 6. AES 加密（需要 cryptography）
        try:
            import cryptography
            caps["aes_encryption"] = True
            logger.info("✅ AES-256 加密可用")
        except ImportError:
            caps["aes_encryption"] = False
            logger.warning("⚠️ cryptography 未安装，使用 HMAC-SHA256 替代 AES")

        return caps

    def print_summary(self, caps: Dict[str, bool]):
        """打印功能可用性摘要"""
        print("\n" + "=" * 50)
        print("功能可用性评估")
        print("=" * 50)
        for name, available in caps.items():
            status = "✅ 启用" if available else "❌ 禁用"
            print(f"  {name:20s} {status}")
        print("=" * 50 + "\n")
