#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从灰度图提取横/竖/斜线 → 过滤短串 → 哈希 → 输出 TXT

用法:
    python3 extract_hash.py <图片路径> [最小像素数]
    python3 extract_hash.py rng_8192x8192.png
    python3 extract_hash.py rng_8192x8192.png 5
"""

import sys
import hashlib
import numpy as np
from PIL import Image
from pathlib import Path


def extract_lines(img):
    """提取横、竖、两个方向的斜线"""
    H, W = img.shape
    horizontal = [img[i, :] for i in range(H)]
    vertical = [img[:, j] for j in range(W)]

    # ↘
    diagonal_1 = []
    for j in range(W):
        diagonal_1.append(np.diagonal(img, offset=j))
    for i in range(1, H):
        diagonal_1.append(np.diagonal(img, offset=-i))

    # ↙
    img_flip = np.fliplr(img)
    diagonal_2 = []
    for j in range(W):
        diagonal_2.append(np.diagonal(img_flip, offset=j))
    for i in range(1, H):
        diagonal_2.append(np.diagonal(img_flip, offset=-i))

    return horizontal, vertical, diagonal_1, diagonal_2


def process(img, min_chars=5, algo="sha256", verbose=True):
    H, W = img.shape

    if verbose:
        print(f"图像: {H}×{W} = {H*W:,} 像素")
        print(f"最少像素: {min_chars}")
        print(f"哈希: {algo}")
        print()

    h_lines, v_lines, d1_lines, d2_lines = extract_lines(img)

    all_lines = []
    for name, lines in [("横线", h_lines), ("竖线", v_lines),
                        ("斜线↘", d1_lines), ("斜线↙", d2_lines)]:
        before = len(lines)
        kept = [l for l in lines if len(l) >= min_chars]
        if verbose:
            print(f"  {name}: {before} 条 → 保留 {len(kept)} 条")
        all_lines.extend(kept)

    if verbose:
        print(f"\n总保留: {len(all_lines)} 条")

    # 逐条哈希
    if verbose:
        print(f"逐条哈希 ({algo}) ...")
    line_hashes = []
    for line in all_lines:
        b = np.asarray(line, dtype=np.uint8).tobytes()
        h = hashlib.new(algo)
        h.update(b)
        line_hashes.append(h.digest())

    # 最终种子
    final_h = hashlib.new(algo)
    for h in line_hashes:
        final_h.update(h)
    final_seed = final_h.digest()

    if verbose:
        print(f"  完成 {len(line_hashes)} 条哈希")

    return {
        "line_count": len(all_lines),
        "line_hashes": line_hashes,
        "final_seed": final_seed,
    }


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "rng_8192x8192.png"
    min_chars = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    if not Path(path).exists():
        print(f"❌ 文件不存在: {path}")
        sys.exit(1)

    print("=" * 66)
    print("  提取 + 过滤 + 哈希 → TXT")
    print("=" * 66)
    print()

    print(f"加载 {path} ...")
    img = np.array(Image.open(path).convert("L"))
    print()

    r = process(img, min_chars=min_chars)

    print()
    print("=" * 66)
    print("  保存")
    print("=" * 66)

    # ---------- 1. 逐条哈希 → TXT ----------
    txt_hashes = Path("line_hashes.txt")
    with open(txt_hashes, "w", encoding="utf-8") as f:
        f.write(f"# 源文件: {path}\n")
        f.write(f"# 线数: {r['line_count']}\n")
        f.write(f"# 哈希算法: SHA-256\n")
        f.write(f"# 格式: <序号> <哈希hex>\n")
        f.write(f"# {'='*60}\n")
        for i, h in enumerate(r["line_hashes"], 1):
            f.write(f"{i:>6d}  {h.hex()}\n")
    size1 = txt_hashes.stat().st_size
    print(f"  ✅ {txt_hashes}  ({size1:,} 字节, {size1/1024/1024:.2f} MB)")
    print(f"     共 {r['line_count']} 行哈希")

    # ---------- 2. 最终种子 → TXT ----------
    txt_seed = Path("final_seed.txt")
    with open(txt_seed, "w", encoding="utf-8") as f:
        f.write(f"# 源文件: {path}\n")
        f.write(f"# 线数: {r['line_count']}\n")
        f.write(f"# 哈希算法: SHA-256\n")
        f.write(f"# {'='*60}\n")
        f.write(f"\n[最终种子 hex]\n")
        f.write(r["final_seed"].hex() + "\n")
        f.write(f"\n[最终种子 base64]\n")
        import base64
        f.write(base64.b64encode(r["final_seed"]).decode() + "\n")
        f.write(f"\n[最终种子 每行 8 hex 格式]\n")
        hx = r["final_seed"].hex()
        for i in range(0, 64, 8):
            f.write(hx[i:i+8] + " ")
            if (i // 8 + 1) % 4 == 0:
                f.write("\n")
    size2 = txt_seed.stat().st_size
    print(f"  ✅ {txt_seed}  ({size2} 字节)")
    print(f"     最终种子: {r['final_seed'].hex()}")


if __name__ == "__main__":
    main()
