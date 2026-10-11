#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 RNG 数据渲染成多种可视化图片

输出:
  1. gray.png        — 灰度图 (字节→像素)
  2. bitplane_0~7.png — 8 个位平面
  3. rgb.png         — RGB 合成
  4. corr_heatmap.png — 连续字节相关热力图
  5. fft.png         — FFT 频谱
"""

import sys
import numpy as np
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("❌ 需要 Pillow：pip install Pillow")
    print("   Termux: pkg install python-pillow")
    sys.exit(1)


def load_bytes(path: str, max_bytes: int = None) -> np.ndarray:
    data = np.fromfile(path, dtype=np.uint8)
    if max_bytes and len(data) > max_bytes:
        data = data[:max_bytes]
    return data


# ====================================================================
# 1. 灰度图
# ====================================================================
def render_gray(data: np.ndarray, out: str):
    """字节 → 灰度像素，64MB → 8192×8192"""
    n = len(data)
    side = int(np.floor(np.sqrt(n)))
    if side * side > n:
        side -= 1
    img = data[:side * side].reshape(side, side)

    # 缩放到可显示尺寸（保持长宽比）
    target = 1024
    if side > target:
        # 简单下采样（平均池化）
        factor = side // target
        img = img[:factor * target, :factor * target]
        img = img.reshape(target, factor, target, factor).mean(axis=(1, 3)).astype(np.uint8)

    Image.fromarray(img, mode="L").save(out)
    print(f"  ✅ {out}: {img.shape}")


# ====================================================================
# 2. 位平面
# ====================================================================
def render_bitplanes(data: np.ndarray, outdir: str, size: int = 1024):
    """把字节的每个 bit 展开成独立平面"""
    n_used = min(len(data), size * size)
    arr = data[:n_used]

    for bit in range(8):
        bits = (arr >> bit) & 1
        img = (bits * 255).astype(np.uint8)
        # 补齐到 size × size
        if len(img) < size * size:
            img = np.pad(img, (0, size * size - len(img)), constant_values=0)
        img = img.reshape(size, size)
        out = f"{outdir}/bitplane_{bit}.png"
        Image.fromarray(img, mode="L").save(out)
        ones = int(bits.sum())
        print(f"  ✅ {out}: 1 占比 {ones/len(bits):.4f} (期望 0.5)")


# ====================================================================
# 3. RGB 合成
# ====================================================================
def render_rgb(data: np.ndarray, out: str, size: int = 1024):
    """每 3 字节 → R, G, B"""
    n_used = min(len(data), size * size * 3)
    arr = data[:n_used - (n_used % 3)]
    img = arr.reshape(-1, 3)
    if len(img) < size * size:
        pad = size * size - len(img)
        img = np.vstack([img, np.zeros((pad, 3), dtype=np.uint8)])
    else:
        img = img[:size * size]
    img = img.reshape(size, size, 3)
    Image.fromarray(img, mode="RGB").save(out)
    print(f"  ✅ {out}: RGB 各通道均值 "
          f"R={img[:,:,0].mean():.2f} G={img[:,:,1].mean():.2f} B={img[:,:,2].mean():.2f}  (期望 127.5)")


# ====================================================================
# 4. 连续字节相关热力图
# ====================================================================
def render_corr_heatmap(data: np.ndarray, out: str):
    """统计 (byte[i], byte[i+1]) 二维分布"""
    a = data[:-1].astype(np.int64)
    b = data[1:].astype(np.int64)
    hist = np.zeros((256, 256), dtype=np.int64)
    # 用 bincount 加速
    idx = a * 256 + b
    counts = np.bincount(idx, minlength=256 * 256)
    hist = counts.reshape(256, 256)

    # 归一化到 0~255 显示
    mx = hist.max()
    if mx > 0:
        img = (hist.astype(np.float32) / mx * 255).astype(np.uint8)
    else:
        img = hist.astype(np.uint8)

    # 放大到 512×512
    img_big = np.kron(img, np.ones((2, 2), dtype=np.uint8))
    Image.fromarray(img_big, mode="L").save(out)

    # 统计
    mean = hist.mean()
    std = hist.std()
    print(f"  ✅ {out}: 256×256，均值 {mean:.1f} 标准差 {std:.1f}")
    print(f"     最大格 {hist.max()} 最小格 {hist.min()}  期望 {len(a)/65536:.1f}")


# ====================================================================
# 5. FFT 频谱
# ====================================================================
def render_fft(data: np.ndarray, out: str, size: int = 512):
    """2D FFT 频谱"""
    n_used = min(len(data), size * size)
    img = data[:n_used].astype(np.float32)
    if len(img) < size * size:
        img = np.pad(img, (0, size * size - len(img)))
    img = img.reshape(size, size)

    # 2D FFT
    f = np.fft.fft2(img - img.mean())
    f_shift = np.fft.fftshift(f)
    mag = np.log1p(np.abs(f_shift))

    # 归一化
    mag = (mag - mag.min()) / (mag.max() - mag.min() + 1e-9) * 255
    img_out = mag.astype(np.uint8)
    Image.fromarray(img_out, mode="L").save(out)
    print(f"  ✅ {out}: 中心应亮，其余均匀（有十字/旁瓣说明周期）")


# ====================================================================
# 主流程
# ====================================================================
def main():
    data_path = sys.argv[1] if len(sys.argv) > 1 else "rng_data.bin"
    outdir = sys.argv[2] if len(sys.argv) > 2 else "viz"

    Path(outdir).mkdir(parents=True, exist_ok=True)

    print(f"读取 {data_path} ...")
    data = load_bytes(data_path)
    print(f"  大小: {len(data)} 字节 = {len(data)/1024/1024:.1f} MB")
    print()

    print("渲染中...")
    render_gray(data, f"{outdir}/gray.png")
    render_bitplanes(data, outdir, size=1024)
    render_rgb(data, f"{outdir}/rgb.png", size=1024)
    render_corr_heatmap(data, f"{outdir}/corr_heatmap.png")
    render_fft(data, f"{outdir}/fft.png", size=512)

    print()
    print(f"全部完成，输出目录: {outdir}/")
    print("  gray.png       — 灰度图")
    print("  bitplane_0~7.png — 8 个位平面")
    print("  rgb.png        — RGB 合成")
    print("  corr_heatmap.png — 连续字节相关")
    print("  fft.png        — 频谱")


if __name__ == "__main__":
    main()
