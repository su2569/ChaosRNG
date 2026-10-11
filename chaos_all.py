#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChaosRNG 一键全套检测 — 从快到慢
=================================

修复点：
1. 不再依赖退出码（单项偶发失败不算失败）
2. 解析实际通过数/失败数，按统计学阈值判定
3. 每阶段日志保存到 ~/ChaosRNG/logs/
4. NIST nistrng 多版本兼容
5. 汇总显示详细通过率
"""

import os
import re
import sys
import time
import signal
import subprocess
from pathlib import Path
from datetime import datetime

HOME = Path.home()
RNG = HOME / "ChaosRNG"
DATA = RNG / "rng_data.bin"
LOGS = RNG / "logs"
HOST = os.environ.get("RNG_HOST", "192.168.1.168")
PORT = int(os.environ.get("RNG_PORT", "18888"))

LOGS.mkdir(exist_ok=True)


NIST_CODE = r'''
import sys
import numpy as np
from nistrng import (
    pack_sequence,
    check_eligibility_all_battery,
    run_all_battery,
    SP800_22R1A_BATTERY,
)

data = open("rng_data.bin", "rb").read()
bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))[:1000000]
seq = pack_sequence(bits)
elig = check_eligibility_all_battery(seq, SP800_22R1A_BATTERY)

try:
    results = run_all_battery(seq, elig, False)
except TypeError:
    results = run_all_battery(seq, elig)

print(f"比特数: {len(bits)}, 适用测试: {len(elig)}")
print()
print(f"{'检验':<45} {'p 值':<14} {'结果'}")
print("-" * 72)

passed = 0
failed = 0
for r in results:
    if isinstance(r, tuple):
        name, pv = r[0], r[1]
    else:
        name = getattr(r, "name", str(r))
        pv = getattr(r, "score", getattr(r, "p_value", 0.0))
    pv = float(pv)
    ok = pv >= 0.01
    if ok:
        passed += 1
        mark = "✅ 通过"
    else:
        failed += 1
        mark = "❌ 失败"
    print(f"{str(name):<45} {pv:<14.6f} {mark}")

print("-" * 72)
print(f"NIST SP 800-22: {passed}/{passed+failed} 通过")
'''


def human_time(sec):
    if sec < 60:   return f"{sec:.1f}s"
    if sec < 3600: return f"{sec/60:.1f}min"
    return f"{sec/3600:.2f}h"


# ==================== 解析器 ====================
def parse_gmt(out):
    """从 GM/T 输出解析 (通过, 失败)"""
    p = f = 0
    for line in out.split("\n"):
        if "✅ 通过" in line:
            p += 1
        elif "❌ 失败" in line:
            f += 1
    return (p, f) if (p + f) > 0 else None


def parse_nist(out):
    m = re.search(r"NIST SP 800-22:\s*(\d+)/(\d+)\s*通过", out)
    if m:
        p, t = int(m.group(1)), int(m.group(2))
        return (p, t - p)
    return None


def parse_testu01(out):
    """返回 (通过标记, 失败项数)"""
    if "All tests were passed" in out:
        return (True, 0)
    fails = out.count("FAILED")
    return (False, fails)


def parse_dieharder(out):
    fails = len(re.findall(r"\bFAILED\b", out))
    passes = len(re.findall(r"\bPASSED\b", out))
    return (passes, fails)


# ==================== 判定逻辑 ====================
def judge(name, parsed, rc):
    """根据解析结果返回 (status, detail)"""
    if rc == -1:
        return "⏸", "中断"
    if rc == -2:
        return "⚠️", "命令不存在"
    if rc == -3:
        return "❌", "异常"

    lname = name.lower()

    if "gm/t" in lname or "gmt" in lname:
        if parsed:
            p, f = parsed
            total = p + f
            if f == 0:
                return "✅", f"{p}/{total} 全过"
            if f <= 1:
                return "✅", f"{p}/{total}（{f} 项统计波动）"
            return "⚠️", f"{p}/{total}"
        return ("✅" if rc == 0 else "⚠️"), f"rc={rc}"

    if "nist" in lname:
        if parsed:
            p, f = parsed
            total = p + f
            if f == 0:
                return "✅", f"{p}/{total} 全过"
            if f <= 1:
                return "✅", f"{p}/{total}（{f} 项统计波动）"
            return "⚠️", f"{p}/{total}"
        return "⚠️", "无法解析"

    if "testu01" in lname:
        if parsed:
            all_pass, fails = parsed
            if all_pass:
                return "✅", "All passed"
            if fails <= 1:
                return "✅", f"{fails} FAILED（可容忍）"
            return "⚠️", f"{fails} FAILED"
        return "⚠️", "无法判定"

    if "dieharder" in lname:
        if parsed:
            p, f = parsed
            if f == 0:
                return "✅", f"{p} 通过 0 失败"
            if f <= 3:
                return "✅", f"{p} 通过 {f} 失败"
            return "⚠️", f"{p} 通过 {f} 失败"
        return "⚠️", "无法判定"

    return ("✅" if rc == 0 else "❌"), f"rc={rc}"


# ==================== 阶段执行 ====================
def run_step(name, cmd, est, parse_fn):
    print()
    print("╔" + "═" * 66 + "╗")
    print(f"║  {name:<62}  ║")
    if est:
        print(f"║  预计: {est:<58} ║")
    print("╚" + "═" * 66 + "╝")
    print()

    # 日志路径
    safe = re.sub(r'[^a-zA-Z0-9]+', '_', name.lower()).strip('_')
    ts = datetime.now().strftime("%H%M%S")
    log_path = LOGS / f"{ts}_{safe}.log"

    t0 = time.time()
    lines = []

    try:
        proc = subprocess.Popen(
            cmd, cwd=str(RNG),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except FileNotFoundError as e:
        print(f"  ❌ 命令不存在: {cmd[0]}")
        return {"name": name, "elapsed": 0.0, "exit_code": -2,
                "error": str(e), "parsed": None}

    try:
        for line in proc.stdout:
            sys.stdout.write("  " + line)
            sys.stdout.flush()
            lines.append(line)
        proc.wait(timeout=86400)
    except KeyboardInterrupt:
        print("\n  ⚠️  Ctrl-C，终止当前测试 ...")
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise
    except Exception as e:
        print(f"\n  ❌ 异常: {e}")
        return {"name": name, "elapsed": time.time() - t0, "exit_code": -3,
                "error": str(e), "parsed": None}

    el = time.time() - t0
    out_text = "".join(lines)

    # 保存日志
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"# {name}\n")
            f.write(f"# cmd: {' '.join(cmd)}\n")
            f.write(f"# elapsed: {human_time(el)}\n")
            f.write(f"# exit_code: {proc.returncode}\n")
            f.write("# " + "─" * 60 + "\n")
            f.write(out_text)
    except Exception as e:
        print(f"  ⚠️  日志保存失败: {e}")

    print()
    print(f"  ⏱  耗时 {human_time(el)}   退出码 {proc.returncode}")
    print(f"  📄 日志: {log_path}")

    parsed = None
    if parse_fn:
        try:
            parsed = parse_fn(out_text)
        except Exception as e:
            print(f"  ⚠️  解析异常: {e}")

    return {"name": name, "elapsed": el, "exit_code": proc.returncode,
            "log": str(log_path), "parsed": parsed}


# ==================== 主流程 ====================
def main():
    if not DATA.exists():
        print(f"❌ 数据不存在: {DATA}")
        print(f"   先跑: python3 fetch_rng.py -s 64M")
        return 1

    size_mb = DATA.stat().st_size / 1024 / 1024
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print()
    print("╔" + "═" * 66 + "╗")
    print("║  ChaosRNG 一键全套检测                                            ║")
    print("╠" + "═" * 66 + "╣")
    print(f"║  数据:     {DATA.name} ({size_mb:.1f} MB)")
    print(f"║  端点:     {HOST}:{PORT}")
    print(f"║  时间:     {now}")
    print(f"║  日志目录: {LOGS}")
    print("╚" + "═" * 66 + "╝")

    steps = [
        ("GM/T 0005-2021",
         [sys.executable, "chaos_nist.py",
          "--suite", "gmt", "--bits", "1048576",
          "--host", HOST, "--port", str(PORT)],
         "1~3 min", parse_gmt),

        ("NIST SP 800-22",
         [sys.executable, "-c", NIST_CODE],
         "2~5 min", parse_nist),

        ("TestU01 SmallCrush",
         ["./testu01_driver", HOST, str(PORT), "1"],
         "3~10 min", parse_testu01),

        ("Dieharder -a -Y 1",
         ["dieharder", "-f", str(DATA), "-g", "201", "-a", "-Y", "1"],
         "20~40 min", parse_dieharder),
    ]

    if "--full" in sys.argv:
        steps.append((
            "TestU01 Crush",
            ["./testu01_driver", HOST, str(PORT), "2"],
            "1~2 h", parse_testu01,
        ))

    total_t0 = time.time()
    results = []

    for name, cmd, est, parse_fn in steps:
        try:
            res = run_step(name, cmd, est, parse_fn)
            results.append(res)
        except KeyboardInterrupt:
            results.append({"name": name, "elapsed": time.time() - total_t0,
                            "exit_code": -1, "parsed": None})
            break
        except Exception as e:
            print(f"\n  ❌ 未处理异常: {e}")
            results.append({"name": name, "elapsed": 0.0, "exit_code": -3,
                            "error": str(e), "parsed": None})

    total_el = time.time() - total_t0

    # ============ 汇总 ============
    print()
    print("╔" + "═" * 78 + "╗")
    print("║  汇总" + " " * 71 + "║")
    print("╠" + "═" * 78 + "╣")

    summary_rows = []
    for r in results:
        name = r["name"]
        el = r["elapsed"]
        parsed = r.get("parsed")
        rc = r.get("exit_code", 0)
        status, detail = judge(name, parsed, rc)
        summary_rows.append((status, name, el, detail))

    for status, name, el, detail in summary_rows:
        line = f"║  {status} {name:<28} {human_time(el):>10}  {detail:<24} ║"
        print(line)

    print("╠" + "═" * 78 + "╣")
    print(f"║  总耗时:   {human_time(total_el):<62} ║")
    print(f"║  日志目录: {str(LOGS):<60} ║")
    print("╚" + "═" * 78 + "╝")
    print()

    # 返回码判定
    has_hard_error = False
    for r in results:
        rc = r.get("exit_code", 0)
        if rc in (-1, -2, -3):
            has_hard_error = True
            break
        # dieharder 超过 3 项失败
        if "dieharder" in r["name"].lower() and r.get("parsed"):
            _, f = r["parsed"]
            if f > 3:
                has_hard_error = True
                break

    return 1 if has_hard_error else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INFO] 已中断")
        sys.exit(130)
