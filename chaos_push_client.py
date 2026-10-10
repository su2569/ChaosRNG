#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chaos RNG 桥接客户端
====================

把 Python 版 ChaosRNG（本机）产生的种子，推送给 Go 版 ChaosRNG（远程）。

流程：
  1. 启动（或复用）本地 Python 版 ChaosRNG（main.py），子进程模式
  2. 从本地 ChaosRNG 的 TCP 服务 GET_SEED 拉取 32 字节种子
  3. 把种子通过 TCP PUSH_SEED 推送给远程 Go 版 ChaosRNG
  4. 本地进程崩溃 → 自动重启；远程连接断开 → 自动重连

协议说明：
  本地（GET_SEED）:
    请求   b"GET_SEED\\n"
    响应   [4B BE 长度][N 字节种子]         ← 二进制，不能按行读
  远程（PUSH_SEED）:
    请求   b"PUSH_SEED <64 hex 字符>\\n"
    响应   {"ok":true,"score":..,"reason":"..","mixed":..}\\n

用法：
  # 默认：本地起 Python RNG（127.0.0.1:18889），推给远程 Go（127.0.0.1:18888）
  python chaos_push_client.py --push-host 192.168.1.10

  # 只连本地已运行实例，不启动子进程
  python chaos_push_client.py --no-launch --push-host 192.168.1.10

  # 环境变量
  PUSH_HOST=192.168.1.10 PUSH_PORT=18888 python chaos_push_client.py

  # 显示子进程日志（调试启动失败时用）
  python chaos_push_client.py --push-host 192.168.1.10 --local-verbose

  # 限制推送次数（跑完就退出）
  python chaos_push_client.py --push-host 192.168.1.10 --count 1000

  # 用非默认本地端口（避免与远程或其它实例冲突）
  python chaos_push_client.py --local-port 18890 --push-host 192.168.1.10
"""

import os
import sys
import json
import time
import random
import shlex
import struct
import socket
import argparse
import logging
import subprocess
import threading
from typing import Optional, List

logger = logging.getLogger("chaos_bridge")


# ====================================================================
# 本地 Python 版 ChaosRNG 管理
# ====================================================================
class LocalRNG:
    """
    启动/守护本地 Python 版 ChaosRNG 子进程。

    - 若本地已在运行，直接复用，不启动新进程
    - 若未运行且 allow_launch=True，启动 main.py 子进程
    - 子进程崩溃时由调用方通过 ensure_running() 触发重启
    """

    def __init__(self, host: str, port: int,
                 allow_launch: bool,
                 main_py: str,
                 extra_args: Optional[List[str]] = None,
                 verbose: bool = False):
        self.host = host
        self.port = port
        self.allow_launch = allow_launch
        self.main_py = os.path.abspath(main_py)
        self.extra_args = list(extra_args or [])
        self.verbose = verbose

        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def connect(self, timeout: float = 2.0) -> Optional[socket.socket]:
        """尝试连接本地 RNG TCP 服务"""
        try:
            s = socket.create_connection((self.host, self.port), timeout=timeout)
            s.settimeout(timeout)
            return s
        except OSError:
            return None

    def is_alive(self) -> bool:
        """子进程是否还活着（未启动过则返回 False）"""
        return self._proc is not None and self._proc.poll() is None

    def is_reachable(self) -> bool:
        """本地 RNG 的 TCP 服务是否可连接（不管是谁启动的）"""
        s = self.connect(timeout=1.5)
        if s is None:
            return False
        try:
            s.close()
        except Exception:
            pass
        return True

    # ------------------------------------------------------------------
    def ensure_running(self, startup_timeout: float = 30.0) -> bool:
        """
        确保本地 RNG 在跑。
        - 已能连上  → True（复用）
        - 未连上且允许启动 → 启动子进程并等待就绪
        - 未连上且禁止启动 → False
        """
        # 1. 先探测
        if self.is_reachable():
            logger.info(f"复用已运行的本地 RNG {self.host}:{self.port}")
            return True

        if not self.allow_launch:
            logger.error(f"本地 RNG {self.host}:{self.port} 未运行，"
                         f"且 --no-launch 已设置")
            return False

        # 2. 启动子进程
        if not self.is_alive():
            if not self._start_subprocess():
                return False

        # 3. 等待就绪
        deadline = time.time() + startup_timeout
        while time.time() < deadline:
            if self.is_reachable():
                logger.info(f"本地 RNG 已就绪 {self.host}:{self.port}")
                return True
            # 子进程意外挂了？
            if not self.is_alive():
                rc = self._proc.returncode if self._proc else "?"
                logger.error(f"本地 RNG 子进程意外退出 (returncode={rc})")
                return False
            time.sleep(0.5)

        logger.error(f"本地 RNG 启动超时（{startup_timeout}s）")
        return False

    def _start_subprocess(self) -> bool:
        """启动 main.py 子进程"""
        if not os.path.exists(self.main_py):
            logger.error(f"未找到 main.py: {self.main_py}")
            return False

        cwd = os.path.dirname(self.main_py)

        args = [
            sys.executable, "-u", self.main_py,
            "--no-shell",
            "--no-elevate",
            "--tcp-host", self.host,
            "--tcp-port", str(self.port),
        ] + self.extra_args

        logger.info("启动本地 Python 版 ChaosRNG:")
        logger.info("  " + " ".join(shlex.quote(a) for a in args))

        try:
            if self.verbose:
                stdout = None
                stderr = None
            else:
                stdout = subprocess.DEVNULL
                stderr = subprocess.DEVNULL

            self._proc = subprocess.Popen(
                args,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
            )
            return True
        except OSError as e:
            logger.error(f"启动子进程失败: {e}")
            return False

    # ------------------------------------------------------------------
    def stop(self):
        """停止子进程（只停我们启动的，不动别人已经跑着的）"""
        with self._lock:
            if self._proc is None:
                return
            if self._proc.poll() is None:
                logger.info("正在停止本地 RNG 子进程 ...")
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("子进程未响应 SIGTERM，强制 kill")
                    try:
                        self._proc.kill()
                        self._proc.wait(timeout=3)
                    except Exception:
                        pass
                except Exception:
                    pass
            self._proc = None


# ====================================================================
# 本地种子源（持久连接，GET_SEED 二进制协议）
# ====================================================================
class SeedSource:
    """
    从本地 Python 版 ChaosRNG 拉取种子。

    维持一个持久 TCP 连接，反复发送 GET_SEED。
    连接断开时下次调用会自动重连。
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def _ensure(self) -> bool:
        if self._sock is not None:
            return True
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout)
            self._sock.settimeout(self.timeout)
            return True
        except OSError:
            self._sock = None
            return False

    def _close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def get_seed(self) -> Optional[bytes]:
        """拉一个 32 字节种子。失败返回 None（下次调用会自动重连）"""
        if not self._ensure():
            return None
        try:
            # 请求
            self._sock.sendall(b"GET_SEED\n")

            # 读 4 字节长度头
            hdr = b""
            while len(hdr) < 4:
                chunk = self._sock.recv(4 - len(hdr))
                if not chunk:
                    self._close()
                    return None
                hdr += chunk
            n = struct.unpack(">I", hdr)[0]

            # 长度合理范围
            if n <= 0 or n > 4096:
                self._close()
                return None

            # 读 N 字节种子
            body = b""
            while len(body) < n:
                chunk = self._sock.recv(n - len(body))
                if not chunk:
                    self._close()
                    return None
                body += chunk

            return body
        except OSError:
            self._close()
            return None

    def close(self):
        self._close()


# ====================================================================
# 远程推送端（持久连接，PUSH_SEED 文本协议）
# ====================================================================
class PushSink:
    """
    向远程 Go 版 ChaosRNG 推送种子。

    维持一个持久 TCP 连接，反复发送 PUSH_SEED。
    连接断开时下次调用会自动重连。
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf = bytearray()

    def _ensure(self) -> bool:
        if self._sock is not None:
            return True
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout)
            self._sock.settimeout(self.timeout)
            self._buf.clear()
            return True
        except OSError:
            self._sock = None
            return False

    def _close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            self._buf.clear()

    def push(self, seed: bytes) -> Optional[dict]:
        """
        推送一个 32 字节种子。
        成功返回服务端 JSON（dict）；失败返回 None（下次调用会自动重连）。
        """
        if not self._ensure():
            return None
        try:
            line = b"PUSH_SEED " + seed.hex().encode() + b"\n"
            self._sock.sendall(line)

            # 读一行响应（可能分多次 recv）
            while b"\n" not in self._buf:
                chunk = self._sock.recv(4096)
                if not chunk:
                    self._close()
                    return None
                self._buf.extend(chunk)

            resp_line, _, rest = bytes(self._buf).partition(b"\n")
            self._buf = bytearray(rest)

            try:
                return json.loads(resp_line)
            except json.JSONDecodeError:
                logger.debug(f"响应非 JSON: {resp_line!r}")
                return None
        except OSError:
            self._close()
            return None

    def close(self):
        self._close()


# ====================================================================
# 主循环
# ====================================================================
def run_bridge(args) -> int:
    # --- 参数整理 ---
    local_host = args.local_host
    local_port = args.local_port
    push_host = args.push_host
    push_port = args.push_port

    # 默认的 main.py 路径：与本文件同目录
    default_main = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "main.py")
    main_py = args.local_main or default_main

    logger.info("=" * 60)
    logger.info("Chaos RNG 桥接客户端")
    logger.info(f"  本地 Python RNG : {local_host}:{local_port}")
    logger.info(f"  远程 Go RNG     : {push_host}:{push_port}")
    logger.info(f"  本地 main.py    : {main_py}")
    logger.info(f"  自动启动本地 RNG: {not args.no_launch}")
    logger.info("=" * 60)

    # --- 启动/连接本地 RNG ---
    local = LocalRNG(
        host=local_host, port=local_port,
        allow_launch=not args.no_launch,
        main_py=main_py,
        extra_args=args.local_arg,
        verbose=args.local_verbose,
    )
    if not local.ensure_running():
        logger.error("无法启动或连接本地 RNG，退出")
        return 1

    source = SeedSource(local_host, local_port, timeout=args.timeout)
    sink = PushSink(push_host, push_port, timeout=args.timeout)

    # --- 速率控制 ---
    base_interval = 1.0 / max(args.rate, 0.01)
    jitter = max(0.0, min(args.jitter, 0.9))

    # --- 统计 ---
    total = 0
    accepts = 0
    rejects = 0
    window_count = 0
    last_log = time.time()
    push_fail_streak = 0
    seed_fail_streak = 0

    logger.info("开始推送循环（Ctrl-C 退出）")

    try:
        while True:
            # ---- 完成度检查 ----
            if args.count > 0 and total >= args.count:
                logger.info(f"已推送 {total} 次，退出")
                break

            # ---- 确保本地 RNG 存活 ----
            if not local.is_reachable():
                logger.warning("本地 RNG 无响应，尝试重启 ...")
                if not local.ensure_running():
                    logger.error("本地 RNG 重启失败，10s 后重试")
                    time.sleep(10)
                    continue

            # ---- 拉种子 ----
            seed = source.get_seed()
            if seed is None:
                seed_fail_streak += 1
                wait = min(1.0 * (2 ** min(seed_fail_streak, 5)), 30.0)
                logger.warning(f"拉取种子失败（连续 {seed_fail_streak} 次），"
                               f"{wait:.1f}s 后重试")
                time.sleep(wait)
                continue
            seed_fail_streak = 0

            # ---- 推种子 ----
            resp = sink.push(seed)
            if resp is None:
                push_fail_streak += 1
                wait = min(2.0 * (2 ** min(push_fail_streak, 5)), 30.0)
                logger.warning(f"推送失败（连续 {push_fail_streak} 次），"
                               f"{wait:.1f}s 后重试")
                time.sleep(wait)
                continue
            push_fail_streak = 0

            # ---- 统计 ----
            total += 1
            window_count += 1
            ok = bool(resp.get("ok"))
            if ok:
                accepts += 1
            else:
                rejects += 1

            # ---- 单条日志 ----
            if not args.quiet:
                mark = "✅" if ok else "❌"
                reason = resp.get("reason", "?")
                score = float(resp.get("score", 0.0))
                extra = ""
                if "retry_ms" in resp:
                    extra = f" retry={resp['retry_ms']}ms"
                logger.info(f"{mark} score={score:5.1f} reason={reason:12s} "
                            f"total={total} ok={accepts} ng={rejects}{extra}")

            # ---- 30 秒汇总 ----
            now = time.time()
            if now - last_log >= 30:
                elapsed = now - last_log
                rate = window_count / elapsed if elapsed > 0 else 0
                logger.info(f"[汇总] 近 {elapsed:.0f}s 速率={rate:.2f}/s "
                            f"累计={total} 接受={accepts} 拒绝={rejects} "
                            f"接受率={100.0 * accepts / max(total, 1):.1f}%")
                window_count = 0
                last_log = now

            # ---- 计算下次间隔 ----
            sleep_t = base_interval
            if jitter > 0:
                sleep_t *= (1.0 + random.uniform(-jitter, jitter))

            # 服务端限流 → 听它的话
            if not ok:
                retry_ms = int(resp.get("retry_ms", 0) or 0)
                if retry_ms > 0:
                    sleep_t = max(sleep_t, retry_ms / 1000.0 + 0.05)

            time.sleep(max(sleep_t, 0.05))

    except KeyboardInterrupt:
        logger.info("收到 Ctrl-C，正在退出 ...")
    finally:
        source.close()
        sink.close()
        local.stop()

    logger.info(f"退出统计：总推送 {total}，接受 {accepts}，拒绝 {rejects}")
    return 0


# ====================================================================
# 入口
# ====================================================================
def main():
    # 环境变量作为默认值
    env_push_host = os.environ.get("PUSH_HOST", "127.0.0.1")
    env_push_port = int(os.environ.get("PUSH_PORT", "18888"))
    env_local_port = int(os.environ.get("LOCAL_RNG_PORT", "18889"))

    parser = argparse.ArgumentParser(
        description="Chaos RNG 桥接客户端："
                    "启动本地 Python RNG，向远程 Go RNG 推送种子",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法：", 1)[-1] if "用法：" in __doc__ else ""
    )

    # ---- 本地 Python RNG ----
    g_local = parser.add_argument_group("本地 Python 版 ChaosRNG")
    g_local.add_argument("--local-host", default="127.0.0.1",
                         help="本地 RNG 监听地址（默认 127.0.0.1）")
    g_local.add_argument("--local-port", type=int, default=env_local_port,
                         help=f"本地 RNG 监听端口（默认 {env_local_port}）")
    g_local.add_argument("--local-main", default=None,
                         help="本地 main.py 路径（默认与本文件同目录）")
    g_local.add_argument("--local-arg", action="append", default=[],
                         metavar="ARG",
                         help="额外传给 main.py 的参数（可多次，"
                              "如 --local-arg=-c --local-arg=config.yaml）")
    g_local.add_argument("--local-verbose", action="store_true",
                         help="显示子进程 stdout/stderr（默认静默）")
    g_local.add_argument("--no-launch", action="store_true",
                         help="不启动本地 RNG，只连已运行的实例")

    # ---- 远程 Go RNG ----
    g_push = parser.add_argument_group("远程 Go 版 ChaosRNG")
    g_push.add_argument("--push-host", default=env_push_host,
                        help=f"远程 RNG 地址（默认 {env_push_host}，"
                             f"可用 PUSH_HOST 环境变量覆盖）")
    g_push.add_argument("--push-port", type=int, default=env_push_port,
                        help=f"远程 RNG 端口（默认 {env_push_port}，"
                             f"可用 PUSH_PORT 环境变量覆盖）")

    # ---- 速率与统计 ----
    g_rate = parser.add_argument_group("速率与运行控制")
    g_rate.add_argument("--rate", type=float, default=1.5,
                        help="平均每秒推送次数（默认 1.5）")
    g_rate.add_argument("--jitter", type=float, default=0.5,
                        help="间隔抖动比例 0~0.9（默认 0.5）")
    g_rate.add_argument("--count", type=int, default=0,
                        help="推送次数上限（0=无限，默认 0）")
    g_rate.add_argument("--timeout", type=float, default=5.0,
                        help="TCP 连接/读取超时秒数（默认 5.0）")
    g_rate.add_argument("--quiet", action="store_true",
                        help="不打印每一条推送结果")
    g_rate.add_argument("-v", "--verbose", action="store_true",
                        help="调试日志")

    args = parser.parse_args()

    # 日志
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [bridge] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # 简单参数校验
    if args.rate <= 0:
        logger.error("--rate 必须 > 0")
        return 1
    if args.jitter < 0 or args.jitter >= 1.0:
        logger.error("--jitter 必须在 [0, 1) 区间")
        return 1
    if args.count < 0:
        logger.error("--count 必须 >= 0")
        return 1

    try:
        return run_bridge(args)
    except Exception as e:
        logger.exception(f"未处理异常: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())