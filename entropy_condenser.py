#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
熵浓缩器压缩率测试
====================

用多种有损压缩方案测量 RNG 数据的"有效熵密度"。

方法：
  1. JPEG 有损压缩（不同 quality）
  2. WebP 有损压缩
  3. 下采样（降分辨率）
  4. 调色板量化（降色深）
  5. PCA 降维 + 无损压缩

输出：
  - 每种方案的压缩率
  - 有效熵密度（bit/字节）
  - 与 /dev/urandom 对照
"""

import os
import sys
import time
import subprocess
from pathlib import Path
import numpy as np
from PIL import Image


# ====================================================================
# 工具
# ====================================================================
def human_size(n):
    if n >= 1024**3: return f"{n/1024**3:.2f} GB"
    if n >= 1024**2: return f"{n/1024**2:.2f} MB"
    if n >= 1024:    return f"{n/1024:.1f} KB"
    return f"{n} B"


def test_results_table(results, orig_size):
    print()
    print("╔" + "═" * 72 + "╗")
    print("║  熵浓缩器 — 压缩率与有效熵密度                                    ║")
    print("╠" + "═" * 72 + "╣")
    print(f"║  原始大小: {human_size(orig_size):<55} ║")
    print("╠" + "═" * 72 + "╣")
    print(f"║  {'方法':<10} {'参数':<12} {'压缩后':<12} {'压缩率':<10} "
          f"{'有效熵':<12} {'耗时':<6} ║")
    print("╠" + "═" * 72 + "╣")

    for method, param, size, elapsed in results:
        ratio = size / orig_size * 100
        # 有效熵 = 8 bit × 压缩率
        entropy = 8 * size / orig_size
        print(f"║  {method:<10} {param:<12} {human_size(size):<12} "
              f"{ratio:>7.2f}%   {entropy:>6.3f} bit/B  {elapsed:>4.1f}s ║")

    print("╚" + "═" * 72 + "╝")


# ====================================================================
# 1. JPEG 有损压缩
# ====================================================================
def test_jpeg(img, results, orig_size, tmp="temp_entropy"):
    print("\n[JPEG 有损压缩]")
    for q in [95, 80, 60, 40, 20, 10, 5, 1]:
        path = f"{tmp}_q{q}.jpg"
        t0 = time.time()
        img.save(path, "JPEG", quality=q, optimize=True, subsampling=0)
        el = time.time() - t0
        size = Path(path).stat().st_size
        print(f"  Q={q:>3}  {human_size(size):>10}  {size/orig_size*100:.2f}%  "
              f"熵={8*size/orig_size:.3f} bit/B  {el:.2f}s")
        results.append(("JPEG", f"Q={q}", size, el))
        os.remove(path)


# ====================================================================
# 2. WebP 有损压缩
# ====================================================================
def test_webp(img, results, orig_size, tmp="temp_entropy"):
    print("\n[WebP 有损压缩]")
    for q in [90, 70, 50, 30, 15, 5]:
        path = f"{tmp}_webp_q{q}.webp"
        t0 = time.time()
        try:
            img.save(path, "WEBP", quality=q, method=4)
            el = time.time() - t0
            size = Path(path).stat().st_size
            print(f"  Q={q:>3}  {human_size(size):>10}  {size/orig_size*100:.2f}%  "
                  f"熵={8*size/orig_size:.3f} bit/B  {el:.2f}s")
            results.append(("WebP", f"Q={q}", size, el))
            os.remove(path)
        except Exception as e:
            print(f"  Q={q}: WebP 不支持 ({e})")


# ====================================================================
# 3. 下采样（降分辨率）
# ====================================================================
def test_downsample(img, results, orig_size, tmp="temp_entropy"):
    print("\n[降分辨率 + PNG 无损]")
    side = img.size[0]
    for scale in [2, 4, 8, 16, 32]:
        new_side = side // scale
        if new_side < 64:
            continue
        path = f"{tmp}_scale{scale}.png"
        t0 = time.time()
        small = img.resize((new_side, new_side), Image.LANCZOS)
        small.save(path, "PNG", compress_level=1)
        el = time.time() - t0
        size = Path(path).stat().st_size
        print(f"  1/{scale:<3}  {human_size(size):>10}  {size/orig_size*100:.2f}%  "
              f"熵={8*size/orig_size:.3f} bit/B  {el:.2f}s")
        results.append(("DownSmp", f"1/{scale}", size, el))
        os.remove(path)


# ====================================================================
# 4. 调色板量化（降色深）
# ====================================================================
def test_palette(img, results, orig_size, tmp="temp_entropy"):
    print("\n[调色板量化 + PNG 无损]")
    # 先把大图缩到 2048 减小计算量
    small = img.resize((2048, 2048), Image.NEAREST)
    for n_colors in [128, 64, 32, 16, 8, 4, 2]:
        path = f"{tmp}_pal{n_colors}.png"
        t0 = time.time()
        quant = small.quantize(colors=n_colors, method=Image.MEDIANCUT)
        quant.save(path, "PNG", compress_level=1)
        el = time.time() - t0
        size = Path(path).stat().st_size
        ratio_to_small = size / (2048 * 2048)
        ratio_effective = ratio_to_small * (2048 * 2048) / orig_size
        print(f"  {n_colors:>4}色  {human_size(size):>10}  "
              f"相对原图 {ratio_effective*100:.2f}%  "
              f"log2({n_colors})={np.log2(n_colors):.1f} bit/B  {el:.2f}s")
        results.append(("Palette", f"{n_colors}色", size, el))
        os.remove(path)


# ====================================================================
# 5. 统计法：连续字节相关性
# ====================================================================
def test_statistical(data):
    print("\n[统计信息密度]")
    n = len(data)

    # 每字节频率的熵
    freq = np.bincount(data, minlength=256)
    p = freq / n
    p = p[p > 0]
    H_byte = -np.sum(p * np.log2(p))

    # 一阶马尔可夫熵：H(X_i | X_{i-1})
    # 统计转移矩阵
    a = data[:-1].astype(np.int64)
    b = data[1:].astype(np.int64)
    idx = a * 256 + b
    counts = np.bincount(idx, minlength=256*256).reshape(256, 256)
    row_sum = counts.sum(axis=1, keepdims=True)
    row_sum[row_sum == 0] = 1
    cond_prob = counts / row_sum
    cond_prob = cond_prob[cond_prob > 0]
    # 平均条件熵
    row_weights = counts.sum(axis=1) / counts.sum()
    H_cond = 0.0
    for i in range(256):
        if row_sum[i, 0] == 0:
            continue
        row = counts[i] / row_sum[i, 0]
        row = row[row > 0]
        H_cond += row_weights[i] * (-np.sum(row * np.log2(row)))

    print(f"  零阶熵 H(X):        {H_byte:.6f} bit/B  (理论最大 8.0)")
    print(f"  一阶条件熵 H(X_i|X_{{i-1}}): {H_cond:.6f} bit/B  (越小越可压缩)")
    print(f"  冗余度:             {(8 - H_cond):.6f} bit/B ({(8-H_cond)/8*100:.4f}%)")


# ====================================================================
# 主流程
# ====================================================================
def main():
    data_path = sys.argv[1] if len(sys.argv) > 1 else "rng_data.bin"

    print(f"读取: {data_path}")
    data = np.fromfile(data_path, dtype=np.uint8)
    orig_size = len(data)
    print(f"  大小: {human_size(orig_size)}")

    # 重塑为正方形
    side = int(np.sqrt(len(data)))
    if side * side != len(data):
        side = side
    img = Image.fromarray(data[:side*side].reshape(side, side), mode="L")
    print(f"  图像: {side}×{side} 灰度")

    results = []

    # 各方案
    test_jpeg(img, results, orig_size)
    test_webp(img, results, orig_size)
    test_downsample(img, results, orig_size)
    test_palette(img, results, orig_size)

    # 汇总表
    test_results_table(results, orig_size)

    # 统计法
    test_statistical(data)

    # 分析
    print()
    print("╔" + "═" * 72 + "╗")
    print("║  结论                                                            ║")
    print("╠" + "═" * 72 + "╣")

    # 最佳有损压缩
    best = min(results, key=lambda x: x[2])
    best_ratio = best[2] / orig_size * 100

    print(f"║  最佳有损压缩: {best[0]} {best[1]:<20} "
          f"{best_ratio:>6.2f}%{'':<26} ║")
    print(f"║  对应有效熵:   {8*best_ratio/100:.3f} bit/B"
          f"{'':<44} ║")
    print("║" + " " * 70 + "║")

    if best_ratio > 50:
        verdict = "❌ 数据极端随机，即使有损压缩也无法显著减小"
    elif best_ratio > 20:
        verdict = "⚠️ 有损压缩有一定效果，需进一步分析"
    else:
        verdict = "❌ 数据存在可压缩结构，RNG 有问题"

    print(f"║  {verdict:<64} ║")
    print("╚" + "═" * 72 + "╝")


if __name__ == "__main__":
    main()
