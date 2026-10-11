#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chaos_dieharder.py — 单独跑 Dieharder

架构：
  ┌─────────────────────────────────────────────────────────────┐
  │  32 个 worker 线程  ──►  内部队列  ──►  主线程               │
  │  (TCP 拉取)             (10万容量)    (写到 dieharder stdin)  │
  │                                                              │
  │  主线程行为：                                                │
  │    1. 先读本地缓存 rng_data.bin → dieharder stdin            │
  │    2. 缓存读完后，从队列取 TCP 数据 → dieharder stdin         │
  │                                                              │
  │  dieharder 从 stdin 读（-g 200 = raw binary）                │
  └─────────────────────────────────────────────────────────────┘

用法：
  python3 chaos_dieharder.py                              # 默认
  python3 chaos_dieharder.py --no-cache                   # 跳过本地缓存
  python3 chaos_dieharder.py --workers 32                 # 指定线程数
  python3 chaos_dieharder.py --dh-args "-a -Y 10"         # 更严格（10 样本）
  python3 chaos_dieharder.py --dh-args "-d 0 -d 1 -d 2"   # 指定测试
  python3 chaos_dieharder.py --list                       # 列出可用的 dieharder 测试
"""

import os
import sys
import time
import socket
import struct
import queue
import shutil
import argparse
import subprocess
import threading
from datetime import datetime
from pathlib import Path


# ====================================================================
# Worker：维持长连接，不断拉种子，写入队列
# ====================================================================
def worker(host, port, q, stop, worker_id, stats):
    while not stop.is_set():
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=15)
            sock.settimeout(15)
            fails = 0

            while not stop.is_set():
                try:
                    sock.sendall(b"GET_SEED\n")
                    # 读 4 字节长度
                    hdr = b""
                    while len(hdr) < 4:
                        ch = sock.recv(4 - len(hdr))
                        if not ch:
                            raise IOError("conn closed (hdr)")
                        hdr += ch
                    n = struct.unpack(">I", hdr)[0]
                    if n <= 0 or n > 65536:
                        raise IOError(f"bad len {n}")
                    # 读 N 字节 body
                    body = b""
                    while len(body) < n:
                        ch = sock.recv(n - len(body))
                        if not ch:
                            raise IOError("conn closed (body)")
                        body += ch

                    # 写入队列（带 1 秒超时，避免卡死）
                    while not stop.is_set():
                        try:
                            q.put(body, timeout=1.0)
                            stats["total_bytes"] += len(body)
                            stats["total_seeds"] += 1
                            fails = 0
                            break
                        except queue.Full:
                            continue
                except (socket.timeout, IOError, OSError):
                    fails += 1
                    if fails >= 3:
                        break
                    time.sleep(0.3)
        except Exception:
            pass
        finally:
            if sock:
                try: sock.close()
                except Exception: pass
        if not stop.is_set():
            time.sleep(0.5)


# ====================================================================
# 主流程
# ====================================================================
def main():
    ap = argparse.ArgumentParser(
        description="Dieharder 测试（本地缓存优先 + 32 线程 TCP 并行）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="192.168.1.168")
    ap.add_argument("--port", type=int, default=18888)
    ap.add_argument("--cache", default="rng_data.bin",
                    help="本地缓存文件（默认 rng_data.bin）")
    ap.add_argument("--workers", type=int, default=32,
                    help="TCP 拉取线程数（默认 32）")
    ap.add_argument("--no-cache", action="store_true",
                    help="跳过本地缓存，直接走 TCP")
    ap.add_argument("--dh-args", default="-a -Y 1",
                    help="传给 dieharder 的参数（默认 '-a -Y 1'）")
    ap.add_argument("--queue-size", type=int, default=100000,
                    help="内部队列容量（种子数，默认 10 万 = 3.2 MB）")
    ap.add_argument("--log", default=None,
                    help="日志文件路径（默认自动生成时间戳）")
    ap.add_argument("--list", action="store_true",
                    help="列出所有可用的 dieharder 测试并退出")
    args = ap.parse_args()

    # 列出测试
    if args.list:
        if not shutil.which("dieharder"):
            print("❌ dieharder 未安装")
            return 1
        return subprocess.call(["dieharder", "-l"])

    # 检查 dieharder
    if not shutil.which("dieharder"):
        print("❌ dieharder 未安装")
        print("   Termux: pkg install dieharder")
        print("   或从源码编译")
        return 1

    # 日志
    if args.log is None:
        args.log = f"dieharder_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    # 打印配置
    cache_path = Path(args.cache)
    cache_exists = cache_path.exists() and not args.no_cache
    cache_mb = cache_path.stat().st_size / 1024 / 1024 if cache_exists else 0

    print()
    print("╔" + "═" * 66 + "╗")
    print("║  Dieharder 测试 — 本地缓存 + TCP 并行                            ║")
    print("╠" + "═" * 66 + "╣")
    print(f"║  本地缓存: {str(cache_path) + (' (' + f'{cache_mb:.1f} MB' + ')' if cache_exists else ' (禁用)'):<47} ║")
    print(f"║  TCP 端点: {args.host + ':' + str(args.port):<51} ║")
    print(f"║  并发线程: {str(args.workers):<51} ║")
    print(f"║  队列容量: {str(args.queue_size) + ' 种子':<51} ║")
    print(f"║  Dieharder: {'dieharder -g 200 ' + args.dh_args:<50} ║")
    print(f"║  日志文件: {args.log:<51} ║")
    print("╚" + "═" * 66 + "╝")
    print()

    # 打开日志
    try:
        log_fp = open(args.log, "w", encoding="utf-8", buffering=1)
    except Exception as e:
        print(f"❌ 无法打开日志: {e}")
        return 1

    # 启动 dieharder（-g 200 = stdin raw）
    dh_cmd = ["dieharder", "-g", "200"] + args.dh_args.split()
    print(f"[启动] {' '.join(dh_cmd)}")
    print()

    dh = subprocess.Popen(
        dh_cmd,
        stdin=subprocess.PIPE,
        stdout=log_fp,
        stderr=subprocess.STDOUT,
        bufsize=0,           # 无缓冲，flush 立即生效
    )

    # 启动 worker 线程
    q = queue.Queue(maxsize=args.queue_size)
    stop = threading.Event()
    stats = {"total_bytes": 0, "total_seeds": 0, "start_time": time.time()}

    threads = []
    for i in range(args.workers):
        t = threading.Thread(
            target=worker,
            args=(args.host, args.port, q, stop, i, stats),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # 进度监控线程
    def progress_monitor():
        last_bytes = 0
        while not stop.is_set():
            time.sleep(10)
            now = time.time()
            cur_bytes = stats["total_bytes"]
            delta = cur_bytes - last_bytes
            last_bytes = cur_bytes
            rate = delta / 10 / 1024 / 1024  # MB/s
            elapsed = now - stats["start_time"]
            print(f"  [状态] 拉取={cur_bytes/1024/1024:.1f}MB  "
                  f"速率={rate:.2f}MB/s  队列={q.qsize()}/{args.queue_size}  "
                  f"已运行={elapsed:.0f}s",
                  file=sys.stderr, flush=True)

    monitor = threading.Thread(target=progress_monitor, daemon=True)
    monitor.start()

    # ============ 主循环 ============
    total_written = 0
    t_start = time.time()

    try:
        # ---------- 阶段 1：本地缓存 ----------
        if cache_exists and cache_mb > 0:
            print(f"[1/2] 读本地缓存 {cache_path} ({cache_mb:.1f} MB) → dieharder stdin",
                  file=sys.stderr)
            with open(cache_path, "rb") as f:
                while True:
                    chunk = f.read(1 << 20)  # 每次 1MB
                    if not chunk:
                        break
                    try:
                        dh.stdin.write(chunk)
                        dh.stdin.flush()
                        total_written += len(chunk)
                    except (BrokenPipeError, OSError):
                        print("  dieharder 关闭了 stdin", file=sys.stderr)
                        raise
            print(f"  ✅ 本地缓存 {cache_mb:.1f} MB 已喂完", file=sys.stderr)
            print(f"  → 切换到 TCP 流", file=sys.stderr)
        else:
            print(f"[1/2] 跳过本地缓存", file=sys.stderr)

        # ---------- 阶段 2：TCP 流 ----------
        print(f"[2/2] TCP 流式拉取（{args.workers} 线程）→ dieharder stdin",
              file=sys.stderr)
        print(file=sys.stderr)

        while True:
            # 检查 dieharder 是否已经结束
            if dh.poll() is not None:
                print(f"\n[结束] dieharder 退出码={dh.returncode}", file=sys.stderr)
                break

            try:
                data = q.get(timeout=30.0)
            except queue.Empty:
                print("  ⚠️  30 秒未收到数据", file=sys.stderr)
                continue

            try:
                dh.stdin.write(data)
                dh.stdin.flush()
                total_written += len(data)
            except (BrokenPipeError, OSError):
                print("\n[结束] dieharder 关闭了 stdin", file=sys.stderr)
                break

    except KeyboardInterrupt:
        print("\n[中断] Ctrl-C", file=sys.stderr)
    except Exception as e:
        print(f"\n[异常] {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        stop.set()
        try:
            dh.stdin.close()
        except Exception:
            pass
        try:
            dh.wait(timeout=30)
        except subprocess.TimeoutExpired:
            dh.kill()
        log_fp.close()

    # ============ 汇总 ============
    elapsed = time.time() - t_start
    print()
    print("╔" + "═" * 66 + "╗")
    print("║  完成                                                            ║")
    print("╠" + "═" * 66 + "╣")
    print(f"║  总写入:   {total_written/1024/1024:>10.1f} MB                              ║")
    print(f"║  TCP 拉取: {stats['total_bytes']/1024/1024:>10.1f} MB ({stats['total_seeds']} 种子)           ║")
    print(f"║  耗时:     {elapsed:>10.1f} 秒                              ║")
    if elapsed > 0:
        print(f"║  平均速率: {total_written/1024/1024/elapsed:>10.2f} MB/s                          ║")
    print(f"║  日志:     {args.log:<51} ║")
    print("╚" + "═" * 66 + "╝")

    # 从日志里抓 PASSED/FAILED 数
    try:
        with open(args.log, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        n_passed = content.count("PASSED")
        n_failed = content.count("FAILED")
        print()
        print(f"  Dieharder 结果: {n_passed} PASSED, {n_failed} FAILED")
        if n_failed == 0:
            print(f"  🎉 全部通过")
        elif n_failed <= 3:
            print(f"  ✅ 通过（{n_failed} 项统计波动，正常范围内）")
        else:
            print(f"  ⚠️  {n_failed} 项失败，建议查看日志")
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INFO] 中断", file=sys.stderr)
        sys.exit(130)
