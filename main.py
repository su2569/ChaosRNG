#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Chaos RNG 独立程序（全熵源版）
================================
主程序仅负责：配置管理、权限控制、模块调度、TCP 服务、交互接口

熵源模块（全部可选，自动检测）：
  🔧 process     - 系统进程抖动
  🌤️ weather     - 全国省会天气
  🕸️ packet      - 网络抓包（AES-256加密后哈希）
  💬 onebot      - OneBot V11 消息
  🎙️ audio       - 麦克风ADC底噪LSB
  📷 camera      - CMOS暗电流噪声
  🖱️ input       - 鼠标/键盘中断间隔
  💾 disk_io     - 磁盘IO抖动
  🧠 memory      - 内存读取（self/all模式）
  📊 disk_stats  - 硬盘实时读写量
  🌡️ temperature - 硬件温度
  🔒 tpm         - TPM芯片熵源
  ⚙️ system      - 系统调度/会话/事件
  📰 content     - 各平台最新内容（缓冲采集）

处理流程：
  原始熵数据 → [冯·诺依曼纠偏(可选)] → HashWhirlpool搅拌 → 混入熵池

依赖：
  核心: pyyaml, psutil
  可选: aiohttp, websockets, cryptography, scapy, sounddevice/pyaudio,
        opencv-python, pynput, pywin32(windows), wmi(windows)

运行：
  sudo python main.py              # 完整功能
  python main.py --no-elevate      # 不请求提权
  python main.py --no-shell        # 无交互控制台
"""

import os
import sys
import time
import json
import random
import hashlib
import asyncio
import argparse
import logging
import platform
import subprocess
from typing import Dict, Any, Optional, List
from datetime import datetime

# ====================================================================
# 配置加载
# ====================================================================
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

DEFAULT_CONFIG = {
    "permissions": {"auto_elevate": True, "keep_original": False},
    "onebot": {
        "enabled": True, "ws_url": "ws://127.0.0.1:3001/", "access_token": "",
        "reconnect_interval": 5, "heartbeat_interval": 30, "self_id": None,
        "auto_collect": True, "auto_collect_interval": 60
    },
    "packet_capture": {
        "enabled": True, "interface": None, "filter": "tcp or udp",
        "duration": 15, "max_payload": 256, "prefer_scapy": True
    },
    "entropy_sources": {
        "process": {"enabled": True, "interval": 2},
        "weather": {"enabled": True, "interval": 600, "sample_count": 5},
        "audio": {"enabled": True, "sample_rate": 44100, "chunk_size": 1024,
                  "channels": 1, "collection_interval": 5, "use_von_neumann": True},
        "camera": {"enabled": True, "device_id": 0, "collection_interval": 10,
                   "use_von_neumann": True},
        "input": {"enabled": True, "collection_interval": 3, "use_von_neumann": True},
        "disk_io": {"enabled": True, "collection_interval": 30, "iterations": 100,
                    "use_von_neumann": True},
        "memory": {"enabled": True, "mode": "self", "read_size": 256,
                   "iterations": 50, "collection_interval": 5, "use_hash_stir": True},
        "disk_stats": {"enabled": True, "collection_interval": 3, "use_hash_stir": True},
        "temperature": {"enabled": True, "collection_interval": 10, "use_hash_stir": True},
        "tpm": {"enabled": True, "collection_interval": 60, "use_pcr": True, "use_rng": True},
        "system": {"enabled": True, "collection_interval": 10},
        "content": {
            "enabled": True, "collection_interval": 300, "buffer_size": 500,
            "mix_count": 10, "request_timeout": 15, "min_interval": 2.0,
            "platforms": {"weibo": True, "zhihu": True, "bilibili": True,
                         "github": True, "hackernews": True, "baidu": True}
        }
    },
    "entropy_processing": {"global_von_neumann": False, "hash_algorithm": "sha256"},
    "tcp_server": {"enabled": True, "host": "0.0.0.0", "port": 18888},
    "scheduler": {"network_quiet_duration": 20, "startup_delay": 3},
    "logging": {"level": "INFO", "file": None}
}


def load_config(path: str) -> dict:
    config = DEFAULT_CONFIG.copy()
    if YAML_AVAILABLE and os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                user = yaml.safe_load(f)
                if user:
                    def deep_merge(b, u):
                        for k, v in u.items():
                            if k in b and isinstance(b[k], dict) and isinstance(v, dict):
                                deep_merge(b[k], v)
                            else:
                                b[k] = v
                    deep_merge(config, user)
        except Exception as e:
            print(f"[WARN] 配置加载失败: {e}")
    return config


# ====================================================================
# 日志
# ====================================================================
def setup_logging(cfg: dict):
    level = getattr(logging, cfg.get("level", "INFO"), logging.INFO)
    handlers = [logging.StreamHandler(sys.stdout)]
    if cfg.get("file"):
        handlers.append(logging.FileHandler(cfg["file"], encoding='utf-8'))
    logging.basicConfig(
        level=level, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S", handlers=handlers
    )


# ====================================================================
# 权限处理
# ====================================================================
def handle_elevation(config: dict, args) -> bool:
    if args.no_elevate or args.elevated:
        return True
    if not config.get("permissions", {}).get("auto_elevate", True):
        return True

    system = platform.system().lower()
    is_elevated = False
    if system == "windows":
        try:
            import ctypes
            is_elevated = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            pass
    elif hasattr(os, "geteuid"):
        is_elevated = os.geteuid() == 0

    if is_elevated:
        return True

    print("[INFO] 请求管理员权限...")
    arg_str = " ".join(sys.argv[1:] + ["--elevated"])

    if system == "windows":
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{sys.argv[0]}" {arg_str}', None, 1
        )
    elif system == "linux":
        if os.environ.get("DISPLAY"):
            try:
                subprocess.Popen(["pkexec", sys.executable] + sys.argv[1:] + ["--elevated"])
                sys.exit(0)
            except:
                pass
        subprocess.Popen(["sudo", "-E", sys.executable] + sys.argv[1:] + ["--elevated"])
        sys.exit(0)
    elif system == "darwin":
        script = f'do shell script "{sys.executable} {arg_str}" with administrator privileges'
        subprocess.Popen(["osascript", "-e", script])
        sys.exit(0)
    else:
        print(f"[WARN] {system} 不支持自动提权")
        return True

    print("[INFO] 提权已触发，当前进程退出")
    sys.exit(0)


# ====================================================================
# 主控制器
# ====================================================================
class ChaosRNGController:
    def __init__(self, config: dict):
        self.config = config
        self._running = False
        self._tasks: List[asyncio.Task] = []

        from chaos_rng_core import ChaosEntropyPool, SeedGenerator
        hash_algo = config.get("entropy_processing", {}).get("hash_algorithm", "sha256")
        self.pool = ChaosEntropyPool(hash_algorithm=hash_algo)
        self.seed_gen = SeedGenerator

        self.modules = {}
        self.capabilities = {}
        self._stats = {"start_time": time.time(), "seeds_served": 0, "commands_processed": 0}

    def _init_modules(self):
        logger = logging.getLogger("chaos_rng")
        src_cfg = self.config.get("entropy_sources", {})

        # 1. 进程
        if src_cfg.get("process", {}).get("enabled", True):
            try:
                from chaos_rng_core import ProcessSnapshotCollector
                self.modules["process"] = ProcessSnapshotCollector(self.pool)
                self.capabilities["process"] = True
                logger.info("🔧 进程采集已加载")
            except Exception as e:
                logger.warning(f"进程采集失败: {e}")
                self.capabilities["process"] = False

        # 2. 天气
        if src_cfg.get("weather", {}).get("enabled", True):
            try:
                import aiohttp
                from chaos_rng_core import WeatherEntropyCollector
                wc = WeatherEntropyCollector(self.pool, sample_count=src_cfg["weather"].get("sample_count", 5))
                self.modules["weather"] = wc
                self.capabilities["weather"] = True
                logger.info("🌤️ 天气采集已加载")
            except ImportError:
                logger.warning("aiohttp 未安装，天气禁用")
                self.capabilities["weather"] = False

        # 3. 抓包
        pc_cfg = self.config.get("packet_capture", {})
        if pc_cfg.get("enabled", True):
            try:
                from packet_collector import PacketCollector
                pc = PacketCollector(
                    self.pool, interface=pc_cfg.get("interface"),
                    filter_expr=pc_cfg.get("filter", "tcp or udp"),
                    capture_duration=pc_cfg.get("duration", 15),
                    max_payload=pc_cfg.get("max_payload", 256),
                    prefer_scapy=pc_cfg.get("prefer_scapy", True)
                )
                if pc.available:
                    self.modules["packet"] = pc
                    self.capabilities["packet"] = True
                    logger.info("🕸️ 抓包已加载")
                else:
                    logger.warning("抓包不可用（权限不足）")
                    self.capabilities["packet"] = False
            except Exception as e:
                logger.warning(f"抓包加载失败: {e}")
                self.capabilities["packet"] = False
        else:
            self.capabilities["packet"] = False

        # 4. OneBot
        ob_cfg = self.config.get("onebot", {})
        if ob_cfg.get("enabled", True) and ob_cfg.get("ws_url"):
            try:
                import websockets
                from onebot_client import OneBotV11Client
                ob = OneBotV11Client(
                    self.pool, ws_url=ob_cfg["ws_url"],
                    access_token=ob_cfg.get("access_token", ""),
                    reconnect_interval=ob_cfg.get("reconnect_interval", 5),
                    heartbeat_interval=ob_cfg.get("heartbeat_interval", 30),
                    self_id=ob_cfg.get("self_id"),
                    auto_collect=ob_cfg.get("auto_collect", True),
                    auto_collect_interval=ob_cfg.get("auto_collect_interval", 60),
                    message_buffer_size=src_cfg.get("process", {}).get("message_buffer_size", 200),
                    message_sample_count=src_cfg.get("process", {}).get("message_sample_count", 10)
                )
                if ob.available:
                    self.modules["onebot"] = ob
                    self.capabilities["onebot"] = True
                    logger.info("💬 OneBot 已加载")
                else:
                    self.capabilities["onebot"] = False
            except ImportError:
                logger.warning("websockets 未安装，OneBot 禁用")
                self.capabilities["onebot"] = False
        else:
            self.capabilities["onebot"] = False

        # 5. 音频
        if src_cfg.get("audio", {}).get("enabled", True):
            try:
                from entropy_collectors import AudioEntropyCollector
                ac = AudioEntropyCollector(
                    self.pool,
                    sample_rate=src_cfg["audio"].get("sample_rate", 44100),
                    chunk_size=src_cfg["audio"].get("chunk_size", 1024),
                    channels=src_cfg["audio"].get("channels", 1),
                    use_von_neumann=src_cfg["audio"].get("use_von_neumann", True)
                )
                if ac.available:
                    self.modules["audio"] = ac
                    self.capabilities["audio"] = True
                    logger.info("🎙️ 音频熵源已加载")
                else:
                    self.capabilities["audio"] = False
            except Exception as e:
                logger.warning(f"音频加载失败: {e}")
                self.capabilities["audio"] = False
        else:
            self.capabilities["audio"] = False

        # 6. 摄像头
        if src_cfg.get("camera", {}).get("enabled", True):
            try:
                from entropy_collectors import CameraEntropyCollector
                cc = CameraEntropyCollector(
                    self.pool,
                    device_id=src_cfg["camera"].get("device_id", 0),
                    use_von_neumann=src_cfg["camera"].get("use_von_neumann", True)
                )
                if cc.available:
                    self.modules["camera"] = cc
                    self.capabilities["camera"] = True
                    logger.info("📷 摄像头熵源已加载")
                else:
                    self.capabilities["camera"] = False
            except Exception as e:
                logger.warning(f"摄像头加载失败: {e}")
                self.capabilities["camera"] = False
        else:
            self.capabilities["camera"] = False

        # 7. 输入设备
        if src_cfg.get("input", {}).get("enabled", True):
            try:
                from entropy_collectors import InputEntropyCollector
                ic = InputEntropyCollector(
                    self.pool,
                    use_von_neumann=src_cfg["input"].get("use_von_neumann", True)
                )
                if ic.available:
                    self.modules["input"] = ic
                    self.capabilities["input"] = True
                    logger.info("🖱️ 输入熵源已加载")
                else:
                    self.capabilities["input"] = False
            except Exception as e:
                logger.warning(f"输入加载失败: {e}")
                self.capabilities["input"] = False
        else:
            self.capabilities["input"] = False

        # 8. 磁盘IO抖动
        if src_cfg.get("disk_io", {}).get("enabled", True):
            try:
                from entropy_collectors import DiskIOEntropyCollector
                dc = DiskIOEntropyCollector(
                    self.pool,
                    use_von_neumann=src_cfg["disk_io"].get("use_von_neumann", True)
                )
                self.modules["disk_io"] = dc
                self.capabilities["disk_io"] = True
                logger.info("💾 磁盘IO熵源已加载")
            except Exception as e:
                logger.warning(f"磁盘IO加载失败: {e}")
                self.capabilities["disk_io"] = False
        else:
            self.capabilities["disk_io"] = False

        # 9. 内存读取
        if src_cfg.get("memory", {}).get("enabled", True):
            try:
                from hardware_entropy import MemoryEntropyCollector
                mc = MemoryEntropyCollector(
                    self.pool,
                    mode=src_cfg["memory"].get("mode", "self"),
                    read_size=src_cfg["memory"].get("read_size", 256),
                    iterations=src_cfg["memory"].get("iterations", 50),
                    use_hash_stir=src_cfg["memory"].get("use_hash_stir", True)
                )
                self.modules["memory"] = mc
                self.capabilities["memory"] = True
                logger.info(f"🧠 内存熵源已加载 (mode={mc.mode})")
            except Exception as e:
                logger.warning(f"内存加载失败: {e}")
                self.capabilities["memory"] = False
        else:
            self.capabilities["memory"] = False

        # 10. 硬盘实时读写量
        if src_cfg.get("disk_stats", {}).get("enabled", True):
            try:
                from hardware_entropy import DiskIOStatsCollector
                dsc = DiskIOStatsCollector(self.pool, use_hash_stir=True)
                if dsc.available:
                    self.modules["disk_stats"] = dsc
                    self.capabilities["disk_stats"] = True
                    logger.info("📊 磁盘统计熵源已加载")
                else:
                    self.capabilities["disk_stats"] = False
            except Exception as e:
                logger.warning(f"磁盘统计加载失败: {e}")
                self.capabilities["disk_stats"] = False
        else:
            self.capabilities["disk_stats"] = False

        # 11. 硬件温度
        if src_cfg.get("temperature", {}).get("enabled", True):
            try:
                from hardware_entropy import HardwareTemperatureCollector
                tc = HardwareTemperatureCollector(self.pool, use_hash_stir=True)
                if tc.available:
                    self.modules["temperature"] = tc
                    self.capabilities["temperature"] = True
                    logger.info("🌡️ 温度熵源已加载")
                else:
                    logger.warning("未检测到温度传感器")
                    self.capabilities["temperature"] = False
            except Exception as e:
                logger.warning(f"温度加载失败: {e}")
                self.capabilities["temperature"] = False
        else:
            self.capabilities["temperature"] = False

        # 12. TPM
        if src_cfg.get("tpm", {}).get("enabled", True):
            try:
                from tpm_entropy import TPMEntropyCollector
                tpm = TPMEntropyCollector(
                    self.pool,
                    use_pcr=src_cfg["tpm"].get("use_pcr", True),
                    use_rng=src_cfg["tpm"].get("use_rng", True)
                )
                if tpm.available:
                    self.modules["tpm"] = tpm
                    self.capabilities["tpm"] = True
                    logger.info("🔒 TPM 熵源已加载")
                else:
                    logger.warning("未检测到 TPM 设备")
                    self.capabilities["tpm"] = False
            except Exception as e:
                logger.warning(f"TPM 加载失败: {e}")
                self.capabilities["tpm"] = False
        else:
            self.capabilities["tpm"] = False

        # 13. 系统调度/会话/事件
        if src_cfg.get("system", {}).get("enabled", True):
            try:
                from system_entropy import SystemEntropyCollector
                sc = SystemEntropyCollector(self.pool)
                self.modules["system"] = sc
                self.capabilities["system"] = True
                logger.info("⚙️ 系统熵源已加载")
            except Exception as e:
                logger.warning(f"系统熵源加载失败: {e}")
                self.capabilities["system"] = False
        else:
            self.capabilities["system"] = False

        # 14. 内容熵源（各平台最新内容）
        if src_cfg.get("content", {}).get("enabled", True):
            try:
                import aiohttp
                from content_entropy import ContentEntropyCollector
                cc_cfg = src_cfg["content"]
                cc = ContentEntropyCollector(
                    self.pool,
                    platforms=cc_cfg.get("platforms"),
                    buffer_size=cc_cfg.get("buffer_size", 500),
                    collection_interval=cc_cfg.get("collection_interval", 300),
                    request_timeout=cc_cfg.get("request_timeout", 15),
                    min_interval_between_requests=cc_cfg.get("min_interval", 2.0)
                )
                if cc.available:
                    self.modules["content"] = cc
                    self.capabilities["content"] = True
                    logger.info("📰 内容熵源已加载")
                else:
                    logger.warning("aiohttp 未安装，内容熵源禁用")
                    self.capabilities["content"] = False
            except ImportError:
                logger.warning("aiohttp 未安装，内容熵源禁用")
                self.capabilities["content"] = False
            except Exception as e:
                logger.warning(f"内容熵源加载失败: {e}")
                self.capabilities["content"] = False
        else:
            self.capabilities["content"] = False

    async def start(self):
        self._running = True
        logger = logging.getLogger("chaos_rng")
        logger.info("🔥 Chaos RNG 全熵源版启动...")
        logger.info(f"   系统: {platform.system()} {platform.release()}")
        logger.info(f"   熵池: {self.pool.digest().hex()[:16]}...")

        self._init_modules()
        self._print_capabilities()

        src_cfg = self.config.get("entropy_sources", {})

        # 启动各模块任务
        if "process" in self.modules:
            interval = src_cfg["process"].get("interval", 2)
            self._tasks.append(asyncio.create_task(self._process_daemon(interval)))

        if "weather" in self.modules:
            interval = src_cfg["weather"].get("interval", 600)
            self._tasks.append(asyncio.create_task(self._weather_loop(interval)))

        if "audio" in self.modules:
            interval = src_cfg["audio"].get("collection_interval", 5)
            self._tasks.append(asyncio.create_task(self.modules["audio"].start_daemon(interval)))

        if "camera" in self.modules:
            interval = src_cfg["camera"].get("collection_interval", 10)
            self._tasks.append(asyncio.create_task(self.modules["camera"].start_daemon(interval)))

        if "input" in self.modules:
            interval = src_cfg["input"].get("collection_interval", 3)
            self._tasks.append(asyncio.create_task(self.modules["input"].start_daemon(interval)))

        if "disk_io" in self.modules:
            interval = src_cfg["disk_io"].get("collection_interval", 30)
            self._tasks.append(asyncio.create_task(self.modules["disk_io"].start_daemon(interval)))

        if "memory" in self.modules:
            interval = src_cfg["memory"].get("collection_interval", 5)
            self._tasks.append(asyncio.create_task(self.modules["memory"].start_daemon(interval)))

        if "disk_stats" in self.modules:
            interval = src_cfg["disk_stats"].get("collection_interval", 3)
            self._tasks.append(asyncio.create_task(self.modules["disk_stats"].start_daemon(interval)))

        if "temperature" in self.modules:
            interval = src_cfg["temperature"].get("collection_interval", 10)
            self._tasks.append(asyncio.create_task(self.modules["temperature"].start_daemon(interval)))

        if "tpm" in self.modules:
            interval = src_cfg["tpm"].get("collection_interval", 60)
            self._tasks.append(asyncio.create_task(self.modules["tpm"].start_daemon(interval)))

        if "system" in self.modules:
            interval = src_cfg["system"].get("collection_interval", 10)
            self._tasks.append(asyncio.create_task(self.modules["system"].start_daemon(interval)))

        if "content" in self.modules:
            # 内容采集后台 + 定期混入
            self._tasks.append(asyncio.create_task(self.modules["content"].start_daemon()))
            mix_count = src_cfg["content"].get("mix_count", 10)
            mix_interval = max(10, src_cfg["content"].get("collection_interval", 300) // 3)
            self._tasks.append(asyncio.create_task(self._content_mix_loop(mix_count, mix_interval)))

        if "onebot" in self.modules:
            self._tasks.append(asyncio.create_task(self.modules["onebot"].start()))

        # TCP
        if self.config.get("tcp_server", {}).get("enabled", True):
            tcp = self.config["tcp_server"]
            self._tasks.append(asyncio.create_task(
                self._start_tcp_server(tcp["host"], tcp["port"])
            ))

        # 交替调度（抓包）
        if "packet" in self.modules:
            self._tasks.append(asyncio.create_task(self._alternating_scheduler()))

        logger.info("🚀 所有服务已启动")

    def _print_capabilities(self):
        print("\n" + "=" * 50)
        print("Chaos RNG 功能状态")
        print("=" * 50)
        icons = {
            "process": "🔧", "weather": "🌤️", "packet": "🕸️", "onebot": "💬",
            "audio": "🎙️", "camera": "📷", "input": "🖱️", "disk_io": "💾",
            "memory": "🧠", "disk_stats": "📊", "temperature": "🌡️",
            "tpm": "🔒", "system": "⚙️", "content": "📰"
        }
        for name, ok in self.capabilities.items():
            icon = icons.get(name, "📦")
            status = "✅ 启用" if ok else "❌ 禁用"
            print(f"  {icon} {name:12s} {status}")
        print("=" * 50 + "\n")

    # ---------- 调度器 ----------
    async def _alternating_scheduler(self):
        pc = self.modules["packet"]
        sch = self.config["scheduler"]
        await asyncio.sleep(sch.get("startup_delay", 3))

        while self._running:
            logger = logging.getLogger("chaos_rng")
            logger.info(f"🕸️ 抓包阶段 ({pc.capture_duration}s)...")
            await pc.capture_once()

            logger.info(f"🌐 网络阶段 ({sch['network_quiet_duration']}s)...")
            if "weather" in self.modules:
                try:
                    await self.modules["weather"].collect()
                    logger.info("🌤️ 天气已更新")
                except Exception as e:
                    logger.debug(f"天气失败: {e}")
            await asyncio.sleep(sch["network_quiet_duration"])

    async def _weather_loop(self, interval: int):
        while self._running:
            try:
                await self.modules["weather"].collect()
                logging.getLogger("chaos_rng").info("🌤️ 天气已更新")
            except Exception as e:
                logging.getLogger("chaos_rng").debug(f"天气失败: {e}")
            await asyncio.sleep(interval)

    async def _process_daemon(self, interval: int):
        while self._running:
            try:
                self.modules["process"].scan_and_update()
            except Exception as e:
                logging.getLogger("chaos_rng").debug(f"进程异常: {e}")
            await asyncio.sleep(interval)

    async def _content_mix_loop(self, mix_count: int, interval: int):
        """定期从内容缓冲区混入熵池"""
        while self._running:
            await asyncio.sleep(interval)
            if "content" in self.modules:
                try:
                    bits = await self.modules["content"].mix_from_buffer(mix_count)
                    if bits > 0:
                        logging.getLogger("chaos_rng").debug(
                            f"📰 内容熵混入 {bits} bits (buffer={self.modules['content'].buffer_size_current})"
                        )
                except Exception as e:
                    logging.getLogger("chaos_rng").debug(f"内容混入失败: {e}")

    # ---------- TCP ----------
    async def _start_tcp_server(self, host: str, port: int):
        try:
            server = await asyncio.start_server(self._handle_client, host, port)
            logging.getLogger("chaos_rng").info(f"🌐 TCP {host}:{port}")
            async with server:
                await server.serve_forever()
        except Exception as e:
            logging.getLogger("chaos_rng").error(f"TCP失败: {e}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        self.pool.mix_event(f"pull:{addr[0]}:{addr[1]}")
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                cmd = data.decode().strip().upper()
                self._stats["commands_processed"] += 1

                if cmd == 'GET_SEED':
                    seed = self.seed_gen.generate(self.pool)
                    writer.write(len(seed).to_bytes(4, 'big'))
                    writer.write(seed)
                    await writer.drain()
                    self._stats["seeds_served"] += 1
                elif cmd == 'GET_HEX':
                    seed = self.seed_gen.generate(self.pool)
                    writer.write((seed.hex() + '\n').encode())
                    await writer.drain()
                    self._stats["seeds_served"] += 1
                elif cmd == 'PING':
                    writer.write(b'PONG\n')
                    await writer.drain()
                elif cmd == 'STATUS':
                    writer.write((json.dumps(self._get_status(), ensure_ascii=False) + '\n').encode())
                    await writer.drain()
                elif cmd == 'CAPS':
                    writer.write((json.dumps(self.capabilities, ensure_ascii=False) + '\n').encode())
                    await writer.drain()
                else:
                    writer.write(b'ERROR: GET_SEED GET_HEX PING STATUS CAPS\n')
                    await writer.drain()
        except:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    # ---------- 接口 ----------
    def get_seed(self) -> bytes:
        return self.seed_gen.generate(self.pool)

    def get_lucky(self, a: int = 1, b: int = 100) -> int:
        return random.Random(int.from_bytes(self.get_seed(), 'big')).randint(a, b)

    def _get_status(self) -> dict:
        uptime = int(time.time() - self._stats["start_time"])
        status = {
            "entropy_pool": {
                "hash_prefix": self.pool.digest().hex()[:16] + "...",
                "event_count": self.pool.event_count,
                "last_mix": datetime.fromtimestamp(self.pool.last_mix_time).isoformat(),
                "uptime_sec": uptime,
                "hash_algorithm": self.config.get("entropy_processing", {}).get("hash_algorithm", "sha256")
            },
            "capabilities": self.capabilities,
            "modules": {}
        }

        if "onebot" in self.modules:
            ob = self.modules["onebot"]
            status["modules"]["onebot"] = {"connected": ob.connected, "messages": ob.message_count, "buffer": ob.buffer_size}
        if "packet" in self.modules:
            pc = self.modules["packet"]
            status["modules"]["packet"] = {"capturing": pc.is_capturing, "total": pc.total_packets}
        if "weather" in self.modules:
            status["modules"]["weather"] = {"updates": self.modules["weather"].update_count}
        if "process" in self.modules:
            status["modules"]["process"] = {"scans": self.modules["process"].scan_count}
        if "audio" in self.modules:
            status["modules"]["audio"] = {"total_bits": self.modules["audio"].total_bits}
        if "camera" in self.modules:
            status["modules"]["camera"] = {"total_bits": self.modules["camera"].total_bits}
        if "input" in self.modules:
            ic = self.modules["input"]
            status["modules"]["input"] = {"total_bits": ic.total_bits, "events": ic.event_count}
        if "disk_io" in self.modules:
            status["modules"]["disk_io"] = {"total_bits": self.modules["disk_io"].total_bits}
        if "memory" in self.modules:
            mc = self.modules["memory"]
            status["modules"]["memory"] = {"total_bits": mc.total_bits, "mode": mc.mode}
        if "disk_stats" in self.modules:
            status["modules"]["disk_stats"] = {"total_bits": self.modules["disk_stats"].total_bits}
        if "temperature" in self.modules:
            status["modules"]["temperature"] = {"total_bits": self.modules["temperature"].total_bits}
        if "tpm" in self.modules:
            status["modules"]["tpm"] = {"total_bits": self.modules["tpm"].total_bits}
        if "system" in self.modules:
            status["modules"]["system"] = {"total_bits": self.modules["system"].total_bits}
        if "content" in self.modules:
            cc = self.modules["content"]
            status["modules"]["content"] = {
                "buffer": cc.buffer_size_current,
                "updates": cc.update_count,
                "platforms": cc.get_status()["platforms"]
            }

        status["stats"] = {"seeds_served": self._stats["seeds_served"], "commands": self._stats["commands_processed"]}
        return status

    # ---------- 停止 ----------
    async def stop(self):
        logging.getLogger("chaos_rng").info("🛑 停止中...")
        self._running = False
        for name, mod in self.modules.items():
            if hasattr(mod, 'stop'):
                try:
                    if asyncio.iscoroutinefunction(mod.stop):
                        await mod.stop()
                    else:
                        mod.stop()
                except Exception as e:
                    logging.getLogger("chaos_rng").debug(f"停止{name}失败: {e}")
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        logging.getLogger("chaos_rng").info("✅ 已停止")


# ====================================================================
# 交互式控制台
# ====================================================================
async def interactive_shell(ctrl: ChaosRNGController):
    print("\n" + "=" * 50)
    print("Chaos RNG 控制台")
    print("命令: seed, lucky, status, caps, collect, weather, content, quit")
    print("=" * 50 + "\n")

    while ctrl._running:
        try:
            cmd = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("chaos> ").strip().lower()
            )
        except EOFError:
            break
        if not cmd:
            continue

        if cmd in ("quit", "q", "exit"):
            break
        elif cmd == "seed":
            print(f"🎲 {ctrl.get_seed().hex()}")
        elif cmd == "lucky":
            print(f"🍀 {ctrl.get_lucky()} / 100")
        elif cmd == "status":
            print(json.dumps(ctrl._get_status(), indent=2, ensure_ascii=False))
        elif cmd == "caps":
            for k, v in ctrl.capabilities.items():
                print(f"  {'✅' if v else '❌'} {k}")
        elif cmd == "collect":
            if "onebot" in ctrl.modules:
                count = await ctrl.modules["onebot"].collect_and_mix(10)
                print(f"✅ 采集 {count} 条" if count else "❌ OneBot 未就绪")
            else:
                print("❌ OneBot 未启用")
        elif cmd == "weather":
            if "weather" in ctrl.modules:
                await ctrl.modules["weather"].collect()
                print("🌤️ 已更新")
            else:
                print("❌ 天气未启用")
        elif cmd == "content":
            if "content" in ctrl.modules:
                cc = ctrl.modules["content"]
                count = await cc.collect()
                bits = await cc.mix_from_buffer(10)
                print(f"📰 采集 {count} 条，混入 {bits} bits，缓冲 {cc.buffer_size_current}")
            else:
                print("❌ 内容熵源未启用")
        else:
            print("未知命令: seed, lucky, status, caps, collect, weather, content, quit")


# ====================================================================
# 入口
# ====================================================================
async def main():
    parser = argparse.ArgumentParser(description="Chaos RNG 全熵源版")
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--no-elevate", action="store_true")
    parser.add_argument("--elevated", action="store_true")
    parser.add_argument("--no-shell", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    handle_elevation(config, args)
    setup_logging(config.get("logging", {}))

    ctrl = ChaosRNGController(config)
    ctrl_task = asyncio.create_task(ctrl.start())
    await asyncio.sleep(1)

    if not args.no_shell:
        await interactive_shell(ctrl)
    else:
        try:
            while ctrl._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    await ctrl.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] 中断退出")
        sys.exit(0)
