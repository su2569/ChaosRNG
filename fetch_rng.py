#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChaosRNG 数据拉取 — 实时进度 + 断线重连 + 可选并发

用法:
  python fetch_rng.py                              # 默认 1 MB，8 并发
  python fetch_rng.py -s 32M                       # 32 MB
  python fetch_rng.py -s 64M -w 16                 # 64 MB，16 并发
  python fetch_rng.py -s 1M -w 1                   # 单连接
  python fetch_rng.py -o mydata.bin -s 8M          # 指定输出文件
  python fetch_rng.py --host 192.168.1.168 --port 18888
"""

import os
import sys
import time
import socket
import struct
import argparse
import threading
import concurrent.futures
from pathlib import Path


def parse_size(s: str) -> int:
    """'32M' -> 33554432"""
    s = s.strip().upper()
    mult = 1
    if s.endswith("K") or s.endswith("KB"):
        mult = 1024
        s = s.rstrip("KB").rstrip("K")
    elif s.endswith("M") or s.endswith("MB"):
        mult = 1024 * 1024
        s = s.rstrip("MB").rstrip("M")
    elif s.endswith("G") or s.endswith("GB"):
        mult = 1024 * 1024 * 1024
        s = s.rstrip("GB").rstrip("G")
    return int(float(s) * mult)


def human_size(n: int) -> str:
    if n >= 1024 ** 3:
        return f"{n / 1024**3:.2f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024**2:.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def human_time(sec: float) -> str:
    if sec < 60:
        return f"{sec:.1f}s"
    if sec < 3600:
        return f"{sec / 60:.1f}min"
    return f"{sec / 3600:.1f}h"


# ====================================================================
# 单连接拉取器
# ====================================================================
class Fetcher:
    def __init__(self, host: str, port: int, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.reconnects = 0

    def _connect(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        return s

    def _fetch_one_seed(self, sock: socket.socket) -> bytes:
        """请求一个 32 字节种子"""
        sock.sendall(b"GET_SEED\n")
        hdr = b""
        while len(hdr) < 4:
            ch = sock.recv(4 - len(hdr))
            if not ch:
                raise IOError("连接中断（header）")
            hdr += ch
        n = struct.unpack(">I", hdr)[0]
        if n <= 0 or n > 65536:
            raise IOError(f"长度异常: {n}")
        body = b""
        while len(body) < n:
            ch = sock.recv(n - len(body))
            if not ch:
                raise IOError("连接中断（body）")
            body += ch
        return body

    def fetch(self, target_bytes: int, on_progress=None,
              stop_event: threading.Event = None) -> bytes:
        """拉取指定字节数，返回 bytes"""
        buf = bytearray()
        sock = self._connect()
        try:
            while len(buf) < target_bytes:
                if stop_event is not None and stop_event.is_set():
                    break
                try:
                    seed = self._fetch_one_seed(sock)
                    buf.extend(seed)
                except (OSError, IOError):
                    # 断线重连
                    try:
                        sock.close()
                    except Exception:
                        pass
                    self.reconnects += 1
                    if on_progress:
                        on_progress(len(buf), target_bytes, self.reconnects)
                    # 重试连接
                    for _ in range(5):
                        if stop_event is not None and stop_event.is_set():
                            break
                        try:
                            time.sleep(0.5)
                            sock = self._connect()
                            break
                        except Exception:
                            continue
                    else:
                        raise IOError("重连失败")
                if on_progress:
                    on_progress(len(buf), target_bytes, self.reconnects)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return bytes(buf[:target_bytes])


# ====================================================================
# 并发拉取 + 实时进度
# ====================================================================
class ProgressPrinter:
    """带 \r 覆盖式刷新的进度打印机"""

    def __init__(self, target_total: int, workers: int):
        self.target = target_total
        self.workers = workers
        self.lock = threading.Lock()
        self.done = 0
        self.t0 = time.time()
        self.last_print = 0.0
        self.reconnects = 0

    def add(self, n: int):
        with self.lock:
            self.done += n

    def add_reconnect(self):
        with self.lock:
            self.reconnects += 1

    def _render(self):
        now = time.time()
        if now - self.last_print < 0.15 and self.done < self.target:
            return
        self.last_print = now
        el = now - self.t0
        done = self.done

        pct = 100.0 * done / self.target
        rate = done / el if el > 0 else 0
        remain_bytes = max(0, self.target - done)
        eta = remain_bytes / rate if rate > 0 else 0

        # 进度条
        bar_width = 30
        filled = int(bar_width * done / self.target)
        bar = "█" * filled + "░" * (bar_width - filled)

        # ANSI 颜色
        GREEN = "\033[92m"
        CYAN = "\033[96m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"
        CLEAR = "\033[K"

        line = (
            f"\r  {GREEN}{bar}{RESET} "
            f"{CYAN}{pct:5.1f}%{RESET} "
            f"{human_size(done):>10s} / {human_size(self.target):<10s} "
            f"{YELLOW}{human_size(rate)}/s{RESET} "
            f"ETA {human_time(eta):>7s} "
            f"[{self.workers}w]"
        )
        if self.reconnects > 0:
            line += f" 🔄{self.reconnects}"
        line += CLEAR
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        el = time.time() - self.t0
        rate = self.done / el if el > 0 else 0
        sys.stdout.write("\n")
        sys.stdout.write(
            f"  ✅ 完成 {human_size(self.done)} 耗时 {human_time(el)} "
            f"平均 {human_size(rate)}/s"
        )
        if self.reconnects > 0:
            sys.stdout.write(f"  (重连 {self.reconnects} 次)")
        sys.stdout.write("\n")
        sys.stdout.flush()


def fetch_concurrent(host: str, port: int, target_bytes: int,
                     workers: int, timeout: float = 15.0) -> bytes:
    """并发拉取，实时显示进度"""
    print(f"  目标: {human_size(target_bytes)}")
    print(f"  并发: {workers} 连接")
    print(f"  端点: {host}:{port}")
    print()

    # 先测单次延迟
    print("  → 测连通性 ...")
    t0 = time.time()
    try:
        probe = Fetcher(host, port, timeout)
        s = probe._connect()
        seed = probe._fetch_one_seed(s)
        s.close()
        latency = (time.time() - t0) * 1000
        print(f"  ✅ 连接成功，单次 GET_SEED 耗时 {latency:.1f} ms")
        if latency > 500:
            print(f"  ⚠️ 延迟偏高（{latency:.0f}ms），拉取会较慢")
    except Exception as e:
        print(f"  ❌ 连接失败: {e}")
        sys.exit(1)
    print()

    # 分片
    chunk_size = target_bytes // workers
    remainder = target_bytes - chunk_size * workers

    # 进度打印机
    prog = ProgressPrinter(target_bytes, workers)
    stop_event = threading.Event()

    def worker(idx: int, size: int) -> bytes:
        f = Fetcher(host, port, timeout)
        last_n = 0

        def on_progress(n, total, reconnects):
            nonlocal last_n
            prog.add(n - last_n)
            last_n = n

        try:
            return f.fetch(size, on_progress=on_progress,
                           stop_event=stop_event)
        except Exception as e:
            print(f"\n  ⚠️ worker {idx} 异常: {e}")
            stop_event.set()
            return b""

    # 后台线程定时刷新（避免主线程等 IO 不刷新）
    def refresher():
        while not stop_event.is_set():
            prog._render()
            if prog.done >= prog.target:
                break
            time.sleep(0.1)

    refresh_thread = threading.Thread(target=refresher, daemon=True)
    refresh_thread.start()

    # 并发拉
    chunks = [None] * workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for i in range(workers):
            sz = chunk_size + (remainder if i == 0 else 0)
            futures[pool.submit(worker, i, sz)] = i
        for fut in concurrent.futures.as_completed(futures):
            idx = futures[fut]
            try:
                chunks[idx] = fut.result()
            except Exception as e:
                print(f"\n  ❌ worker {idx} 最终失败: {e}")
                chunks[idx] = b""

    stop_event.set()
    prog._render()
    prog.finish()

    # 检查
    total = sum(len(c) for c in chunks)
    if total < target_bytes:
        print(f"  ⚠️ 只拉到 {human_size(total)}，"
              f"比目标少 {human_size(target_bytes - total)}")

    return b"".join(chunks)[:target_bytes]


# ====================================================================
# 主流程
# ====================================================================
def main():
    ap = argparse.ArgumentParser(
        description="ChaosRNG 数据拉取 — 实时进度显示")
    ap.add_argument("-s", "--size", default="1M",
                    help="目标大小（如 1M / 512K / 8M），默认 1M")
    ap.add_argument("-w", "--workers", type=int, default=8,
                    help="并发连接数（默认 8，1=单连接）")
    ap.add_argument("-o", "--output", default="rng_data.bin",
                    help="输出文件（默认 rng_data.bin）")
    ap.add_argument("--host", default="192.168.1.168")
    ap.add_argument("--port", type=int, default=18888)
    ap.add_argument("--timeout", type=float, default=15.0,
                    help="单次读写超时（秒）")
    args = ap.parse_args()

    target = parse_size(args.size)

    print("╔" + "═" * 60 + "╗")
    print("║  ChaosRNG 数据拉取                                  ║")
    print("╠" + "═" * 60 + "╣")
    print(f"║  端点: {args.host}:{args.port:<44} ║")
    print(f"║  大小: {human_size(target):<48} ║")
    print(f"║  并发: {args.workers:<48} ║")
    print(f"║  输出: {args.output:<48} ║")
    print("╚" + "═" * 60 + "╝")
    print()

    t0 = time.time()
    try:
        data = fetch_concurrent(
            args.host, args.port, target, args.workers, args.timeout)
    except KeyboardInterrupt:
        print("\n  ⚠️ 用户中断")
        sys.exit(130)

    el = time.time() - t0
    Path(args.output).write_bytes(data)

    print()
    print(f"  💾 已保存: {args.output}")
    print(f"  📦 大小: {human_size(len(data))}")
    print(f"  ⏱️  总耗时: {human_time(el)}")
    print(f"  🚀 平均: {human_size(len(data) / el)}/s")


if __name__ == "__main__":
    main()
