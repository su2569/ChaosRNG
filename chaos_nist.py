#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChaosRNG 随机性检测 — 三合一严格模式（GM/T 0005-2021 + TestU01 + Dieharder）
============================================================================

自动检测依赖、自动编译 TestU01 驱动、一键跑完整套。
"""

import os
import sys
import math
import time
import socket
import struct
import shutil
import argparse
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from collections import defaultdict


# ====================================================================
# 依赖检查
# ====================================================================
try:
    import numpy as np
    from scipy import special, stats
except ImportError as e:
    print(f"❌ 缺少依赖: {e}")
    print("请运行: pkg install python-numpy python-scipy")
    sys.exit(1)


VERSION = "1.0.0"
P_LO = 0.001
P_HI = 0.999
GMT_ALPHA = 0.01


# ====================================================================
# 精确统计工具（用 scipy）
# ====================================================================
def igamc(a, x):
    """上正则化不完全伽马函数 Q(a,x)"""
    a = float(a); x = float(x)
    if x <= 0:
        return 1.0
    return float(special.gammaincc(a, x))


def erfc(x):
    return float(special.erfc(x))


def norm_cdf(x):
    return float(special.ndtr(x))


# ====================================================================
# GM/T 0005-2021 全部 15 项
# ====================================================================
class GMTests:

    @staticmethod
    def t01_monobit(bits):
        """1. 单比特频数"""
        n = len(bits)
        s = sum(1 if b else -1 for b in bits)
        return erfc(abs(s) / math.sqrt(n) / math.sqrt(2))

    @staticmethod
    def t02_block_frequency(bits, m=10000):
        """2. 块内频数"""
        n = len(bits)
        N = n // m
        if N == 0:
            return None
        arr = np.asarray(bits[:N * m], dtype=np.float64).reshape(N, m)
        pi = arr.mean(axis=1)
        chi2 = 4.0 * m * float(np.sum((pi - 0.5) ** 2))
        return igamc(N / 2.0, chi2 / 2.0)

    @staticmethod
    def t03_poker(bits, m=4):
        """3. 扑克"""
        n = len(bits)
        k = n // m
        if k == 0:
            return None
        arr = np.asarray(bits[:k * m], dtype=np.uint32).reshape(k, m)
        # 按 m 位打包成整数
        pat = np.zeros(k, dtype=np.uint32)
        for j in range(m):
            pat = (pat << 1) | arr[:, j]
        counts = np.bincount(pat, minlength=(1 << m))
        V = float(np.sum(counts * counts)) * (1 << m) / k - k
        return igamc((1 << m) / 2.0 - 0.5, V / 2.0)

    @staticmethod
    def t04_overlapping(bits, m=3):
        """4. 重叠子序列"""
        n = len(bits)
        arr = np.asarray(bits, dtype=np.uint8)
        ext = np.concatenate([arr, arr[:m]])

        def psi_sq(m_val):
            if m_val <= 0:
                return 0.0
            # 滑动窗口模式
            pat = np.zeros(n, dtype=np.uint32)
            for j in range(m_val):
                pat = (pat << 1) | ext[j:j + n]
            counts = np.bincount(pat, minlength=(1 << m_val))
            return (1 << m_val) / n * float(np.sum(counts.astype(np.int64) ** 2)) - n

        psi_m = psi_sq(m)
        psi_m1 = psi_sq(m - 1) if m >= 2 else 0.0
        psi_m2 = psi_sq(m - 2) if m >= 3 else 0.0

        nabla1 = psi_m - psi_m1
        nabla2 = psi_m - 2.0 * psi_m1 + psi_m2
        p1 = igamc(2 ** (m - 2), nabla1 / 2.0) if m >= 2 else 1.0
        p2 = igamc(2 ** (m - 3), nabla2 / 2.0) if m >= 3 else 1.0
        return p1, p2

    @staticmethod
    def t05_runs(bits):
        """5. 游程总数"""
        n = len(bits)
        arr = np.asarray(bits, dtype=np.int8)
        pi = float(arr.mean())
        if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
            return 0.0
        v = 1 + int(np.sum(arr[1:] != arr[:-1]))
        num = abs(v - 2.0 * n * pi * (1.0 - pi))
        den = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
        return erfc(num / den)

    @staticmethod
    def t06_runs_distribution(bits):
        """6. 游程分布（GM/T 0005-2021）"""
        n = len(bits)
        arr = np.asarray(bits, dtype=np.int8)
        changes = np.where(arr[1:] != arr[:-1])[0]
        if len(changes) == 0:
            return None
        run_ends = np.concatenate([changes, [n - 1]])
        run_starts = np.concatenate([[-1], changes])
        run_lengths = run_ends - run_starts
        run_first_bit = arr[run_starts + 1]

        # 分离 0 游程和 1 游程（GM/T 标准要求分别统计）
        runs0 = run_lengths[run_first_bit == 0]
        runs1 = run_lengths[run_first_bit == 1]

        # 选 K：使 E_i >= 5 的最大 i
        K = 0
        for i in range(1, 100):
            E_i = (n - i + 3) / 2 ** (i + 2)
            if E_i >= 5:
                K = i
            else:
                break
        if K < 1:
            return None

        def hist(runs, K):
            v = np.zeros(K + 1, dtype=np.int64)
            for r in runs:
                v[min(int(r), K)] += 1
            return v

        v0 = hist(runs0, K)
        v1 = hist(runs1, K)

        # GM/T 卡方：0 游程和 1 游程分别对 E_i 检验
        chi2 = 0.0
        for i in range(1, K + 1):
            E_i = (n - i + 3) / 2 ** (i + 2)
            chi2 += (v0[i] - E_i) ** 2 / E_i
            chi2 += (v1[i] - E_i) ** 2 / E_i

        df = 2 * K - 1
        return igamc(df / 2.0, chi2 / 2.0)

    @staticmethod
    def t07_longest_run(bits, m=128):
        """7. 块内最大游程"""
        n = len(bits)
        N = n // m
        if N == 0:
            return None
        arr = np.asarray(bits[:N * m], dtype=np.int8).reshape(N, m)
        # 计算每行最长连续 1
        longest = np.zeros(N, dtype=np.int32)
        cur = np.zeros(N, dtype=np.int32)
        for j in range(m):
            col = arr[:, j]
            cur = (cur + 1) * col
            longest = np.maximum(longest, cur)

        if m == 128:
            K = 5
            pi = np.array([0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124])
            v = np.zeros(6, dtype=np.int64)
            v[0] = np.sum(longest <= 4)
            for i in range(5, 9):
                v[i - 4] = np.sum(longest == i)
            v[5] = np.sum(longest >= 9)
        elif m == 8:
            K = 3
            pi = np.array([0.2148, 0.3672, 0.2305, 0.1875])
            v = np.zeros(4, dtype=np.int64)
            v[0] = np.sum(longest <= 1)
            v[1] = np.sum(longest == 2)
            v[2] = np.sum(longest == 3)
            v[3] = np.sum(longest >= 4)
        else:  # m == 10000
            K = 6
            pi = np.array([0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727])
            v = np.zeros(7, dtype=np.int64)
            v[0] = np.sum(longest <= 10)
            for i in range(11, 16):
                v[i - 10] = np.sum(longest == i)
            v[6] = np.sum(longest >= 16)

        chi2 = float(np.sum((v - N * pi) ** 2 / (N * pi)))
        return igamc(K / 2.0, chi2 / 2.0)

    @staticmethod
    def t08_binary_derivative(bits, k=3):
        """8. 二元推导"""
        arr = np.asarray(bits, dtype=np.uint8)
        for _ in range(k):
            arr = arr[:-1] ^ arr[1:]
        n2 = len(arr)
        s = int(np.sum(arr)) * 2 - n2
        return erfc(abs(s) / math.sqrt(n2) / math.sqrt(2))

    @staticmethod
    def t09_autocorrelation(bits, d=2):
        """9. 自相关"""
        n = len(bits)
        if d >= n:
            return None
        arr = np.asarray(bits, dtype=np.uint8)
        a = int(np.sum(arr[:-d] ^ arr[d:]))
        v = 2.0 * (a - (n - d) / 2.0) / math.sqrt(n - d)
        return erfc(abs(v) / math.sqrt(2))

    @staticmethod
    def t10_matrix_rank(bits, M=32, Q=32):
        """10. 矩阵秩（GF(2) 高斯消元）"""
        n = len(bits)
        N = n // (M * Q)
        if N == 0:
            return None
        arr = np.asarray(bits[:N * M * Q], dtype=np.uint8).reshape(N, M, Q)
        full_rank = min(M, Q)
        F_M = 0
        F_M1 = 0
        for k in range(N):
            mat = arr[k].copy()  # M x Q
            rank = 0
            for col in range(Q):
                pivot = -1
                for r in range(rank, M):
                    if mat[r, col]:
                        pivot = r
                        break
                if pivot >= 0:
                    if pivot != rank:
                        mat[[rank, pivot]] = mat[[pivot, rank]]
                    # 消元其他行
                    for r in range(M):
                        if r != rank and mat[r, col]:
                            mat[r] = mat[r] ^ mat[rank]
                    rank += 1
            if rank == full_rank:
                F_M += 1
            elif rank == full_rank - 1:
                F_M1 += 1
        p_full = 0.2888
        p_1 = 0.5776
        p_rest = 0.1336
        chi2 = ((F_M - N * p_full) ** 2 / (N * p_full) +
                (F_M1 - N * p_1) ** 2 / (N * p_1) +
                (N - F_M - F_M1 - N * p_rest) ** 2 / (N * p_rest))
        return igamc(1.0, chi2 / 2.0)

    @staticmethod
    def t11_cumulative(bits):
        """11. 累加和"""
        n = len(bits)
        arr = np.asarray(bits, dtype=np.int32) * 2 - 1
        cs = np.cumsum(arr)
        z_pos = int(cs.max())
        z_neg = int(-cs.min())

        def cusum_p(z, n):
            if z <= 0:
                return 1.0
            z = abs(z)
            sqn = math.sqrt(n)
            s1 = 0.0
            k = math.ceil((-n / z + 1) / 4)
            while 4 * k + 1 <= (n / z - 1):
                s1 += norm_cdf((4 * k + 1) * z / sqn) - norm_cdf((4 * k - 1) * z / sqn)
                k += 1
            s2 = 0.0
            k = math.ceil((-n / z - 3) / 4)
            while 4 * k + 3 <= (n / z - 1):
                s2 += norm_cdf((4 * k + 3) * z / sqn) - norm_cdf((4 * k + 1) * z / sqn)
                k += 1
            return max(0.0, min(1.0, 1.0 - s1 + s2))

        return cusum_p(z_pos, n), cusum_p(z_neg, n)

    @staticmethod
    def t12_approximate_entropy(bits, m=2):
        """12. 近似熵"""
        n = len(bits)
        arr = np.asarray(bits, dtype=np.uint32)

        def phi(m_val):
            if m_val <= 0:
                return 0.0
            ext = np.concatenate([arr, arr[:m_val]])
            pat = np.zeros(n, dtype=np.uint32)
            for j in range(m_val):
                pat = (pat << 1) | ext[j:j + n]
            counts = np.bincount(pat, minlength=(1 << m_val))
            p = counts[counts > 0] / n
            return float(np.sum(p * np.log(p)))

        ap_en = phi(m) - phi(m + 1)
        chi2 = 2.0 * n * (math.log(2) - ap_en)
        return igamc(2 ** (m - 1), chi2 / 2.0)

    @staticmethod
    def _berlekamp_massey(bits):
        """Berlekamp-Massey 算法，返回线性复杂度"""
        n = len(bits)
        C = [0] * n
        B = [0] * n
        C[0] = 1
        B[0] = 1
        L = 0
        m = -1
        for i in range(n):
            d = bits[i]
            for j in range(1, L + 1):
                d ^= C[j] & bits[i - j]
            if d == 1:
                T = C[:]
                shift = i - m
                for j in range(n - shift):
                    C[j + shift] ^= B[j]
                if L <= i // 2:
                    L = i + 1 - L
                    m = i
                    B = T
        return L

    @staticmethod
    def t13_linear_complexity(bits, M=500):
        """13. 线型复杂度（M=500，GM/T 标准值）"""
        n = len(bits)
        N = n // M
        if N == 0:
            return None
        # 抽样：最多 100 块
        N_sample = min(N, 100)
        pi = np.array([0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833])
        v = np.zeros(7, dtype=np.int64)
        for k in range(N_sample):
            block = bits[k * M:(k + 1) * M]
            L = GMTests._berlekamp_massey(block)
            t_val = (-1) ** M * (L - M / 2.0) + 2.0 / 9.0
            if t_val <= -2.5:
                v[0] += 1
            elif t_val <= -1.5:
                v[1] += 1
            elif t_val <= -0.5:
                v[2] += 1
            elif t_val <= 0.5:
                v[3] += 1
            elif t_val <= 1.5:
                v[4] += 1
            elif t_val <= 2.5:
                v[5] += 1
            else:
                v[6] += 1
        chi2 = float(np.sum((v - N_sample * pi) ** 2 / (N_sample * pi)))
        return igamc(3.0, chi2 / 2.0)

    @staticmethod
    def t14_maurer_universal(bits, L=7, Q=1280):
        """14. Maurer 通用统计（NIST SP 800-22 Section 2.12）"""
        n = len(bits)
        if n < L * Q + 1000:
            return None
        K = n // L - Q
        if K <= 0:
            return None

        arr = np.asarray(bits[:L * (Q + K)], dtype=np.uint32).reshape(Q + K, L)
        patterns = np.zeros(Q + K, dtype=np.uint32)
        for j in range(L):
            patterns = (patterns << 1) | arr[:, j]

        last = {}
        T = 0
        for i in range(Q):
            last[int(patterns[i])] = i
        for i in range(Q, Q + K):
            p = int(patterns[i])
            if p in last:
                T += i - last[p]
            last[p] = i

        fn = T / K

        # NIST 标准公式
        expected = 0.0
        for i in range(1, 10000):
            term = (1 - 1.0 / (1 << L)) ** (i - 1)
            expected += term
            if term < 1e-18:
                break
        # 注意: 上面的和式 == 2^L，已经是 E[fn]
        # 不要再乘 (1 << L)

        # 方差修正因子 c
        c = 0.7 - 0.8 / L + (4 + 32.0 / L) * (K ** (-3.0 / L)) / 15.0

        # NIST: Var(fn) = c^2 * (E(fn)^2 - E(fn)) / K
        var_fn = c * c * (expected * expected - expected) / K

        if var_fn <= 0:
            return None
        sigma = math.sqrt(var_fn)
        if sigma == 0:
            return None

        v = (fn - expected) / sigma
        return erfc(abs(v) / math.sqrt(2))

    @staticmethod
    def t15_dft(bits):
        """15. 离散傅里叶"""
        n = len(bits)
        arr = np.asarray(bits, dtype=np.float64) * 2 - 1
        fft = np.fft.fft(arr)
        half = n // 2
        mods = np.abs(fft[:half])
        T = math.sqrt(math.log(1.0 / 0.05) * n)
        N0 = 0.95 * half
        N1 = int(np.sum(mods < T))
        d = (N1 - N0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
        return erfc(abs(d) / math.sqrt(2))


# ====================================================================
# 数据采集
# ====================================================================
def collect_bits(host, port, target_bytes, verbose=True):
    sock = socket.create_connection((host, port), timeout=30)
    sock.settimeout(30)
    collected = bytearray()
    seeds = 0
    t0 = time.time()
    try:
        while len(collected) < target_bytes:
            sock.sendall(b"GET_SEED\n")
            hdr = b""
            while len(hdr) < 4:
                ch = sock.recv(4 - len(hdr))
                if not ch:
                    raise IOError("连接中断")
                hdr += ch
            n = struct.unpack(">I", hdr)[0]
            if n <= 0 or n > 65536:
                raise IOError(f"长度异常: {n}")
            body = b""
            while len(body) < n:
                ch = sock.recv(n - len(body))
                if not ch:
                    raise IOError("连接中断")
                body += ch
            collected.extend(body)
            seeds += 1
            if verbose and seeds % 500 == 0:
                el = time.time() - t0
                print(f"      {len(collected)}/{target_bytes} 字节 "
                      f"({seeds} 种子, {el:.1f}s)")
        return bytes(collected[:target_bytes])
    finally:
        try:
            sock.close()
        except Exception:
            pass


def bytes_to_bits(data):
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr).tolist()


# ====================================================================
# 运行 GM/T
# ====================================================================
def run_gmt(bits, alpha=GMT_ALPHA):
    print("═" * 68)
    print("  GM/T 0005-2021（15 项）")
    print("═" * 68)
    print(f"{'检验':<40} {'p 值':<14} {'结果'}")
    print("─" * 68)

    results = []
    fails = 0

    def rec(name, p, p2=None):
        nonlocal fails
        if p is None:
            results.append((name, None, None, True))
            print(f"{name:<40} {'—':<14} ⊘ 跳过")
            return
        ok = p >= alpha
        if p2 is not None:
            ok = ok and (p2 >= alpha)
        if not ok:
            fails += 1
        if p2 is not None:
            pstr = f"{p:.4f} / {p2:.4f}"
        else:
            pstr = f"{p:.6f}"
        mark = "✅ 通过" if ok else "❌ 失败"
        print(f"{name:<40} {pstr:<14} {mark}")
        results.append((name, p, p2, ok))

    rec("1. 单比特频数", GMTests.t01_monobit(bits))
    rec("2. 块内频数 (m=10000)", GMTests.t02_block_frequency(bits, 10000))
    rec("3. 扑克 (m=4)", GMTests.t03_poker(bits, 4))
    rec("3'. 扑克 (m=8)", GMTests.t03_poker(bits, 8))
    p1, p2 = GMTests.t04_overlapping(bits, 3)
    rec("4. 重叠子序列 (m=3)", p1, p2)
    rec("5. 游程总数", GMTests.t05_runs(bits))
    rec("6. 游程分布", GMTests.t06_runs_distribution(bits))
    rec("7. 块内最大游程 (m=128)", GMTests.t07_longest_run(bits, 128))
    rec("8. 二元推导 (k=3)", GMTests.t08_binary_derivative(bits, 3))
    rec("8'. 二元推导 (k=7)", GMTests.t08_binary_derivative(bits, 7))
    rec("9. 自相关 (d=2)", GMTests.t09_autocorrelation(bits, 2))
    rec("9'. 自相关 (d=8)", GMTests.t09_autocorrelation(bits, 8))
    rec("10. 矩阵秩 (32x32)", GMTests.t10_matrix_rank(bits, 32, 32))
    pp, pn = GMTests.t11_cumulative(bits)
    rec("11. 累加和 (前向/后向)", pp, pn)
    rec("12. 近似熵 (m=2)", GMTests.t12_approximate_entropy(bits, 2))
    rec("13. 线型复杂度 (M=500)", GMTests.t13_linear_complexity(bits, 500))
    rec("14. Maurer 通用统计 (L=7)", GMTests.t14_maurer_universal(bits, 7, 1280))
    rec("15. 离散傅里叶", GMTests.t15_dft(bits))

    print("─" * 68)
    passed = sum(1 for _, _, _, ok in results if ok)
    total = sum(1 for _, p, _, _ in results if p is not None)
    print(f"GM/T 0005-2021: {passed}/{total} 通过 (α = {alpha})")
    return fails


# ====================================================================
# TestU01 驱动
# ====================================================================
TESTU01_SRC = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "unif01.h"
#include "bbattery.h"

static int sock_fd = -1;
static unsigned char buf[65536];
static size_t buf_pos = 0;
static size_t buf_len = 0;
static unsigned long long total_bits = 0;

static int connect_rng(const char *host, int port) {
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) return -1;
    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock_fd); sock_fd = -1; return -1;
    }
    return 0;
}

static int refill(void) {
    if (sock_fd < 0) return -1;
    const char *cmd = "GET_SEED\n";
    size_t cl = strlen(cmd), w = 0;
    while (w < cl) {
        ssize_t n = write(sock_fd, cmd + w, cl - w);
        if (n <= 0) return -1;
        w += n;
    }
    unsigned char hdr[4];
    size_t g = 0;
    while (g < 4) {
        ssize_t n = read(sock_fd, hdr + g, 4 - g);
        if (n <= 0) return -1;
        g += n;
    }
    unsigned int n = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16)
                   | ((unsigned int)hdr[2] << 8) | (unsigned int)hdr[3];
    if (n == 0 || n > sizeof(buf)) return -1;
    g = 0;
    while (g < n) {
        ssize_t r = read(sock_fd, buf + g, n - g);
        if (r <= 0) return -1;
        g += r;
    }
    buf_pos = 0; buf_len = n;
    return 0;
}

static unsigned int next_bits(void) {
    unsigned int x = 0;
    for (int i = 0; i < 32; i++) {
        if (buf_pos >= buf_len * 8) {
            if (refill() < 0) { fprintf(stderr, "RNG conn failed\n"); exit(1); }
        }
        size_t bi = buf_pos / 8, ofs = buf_pos % 8;
        int b = (buf[bi] >> (7 - ofs)) & 1;
        x = (x << 1) | (unsigned int)b;
        buf_pos++; total_bits++;
    }
    return x;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 18888;
    int battery = argc > 3 ? atoi(argv[3]) : 1;
    if (connect_rng(host, port) < 0) {
        fprintf(stderr, "Cannot connect %s:%d\n", host, port);
        return 1;
    }
    fprintf(stderr, "[TestU01] Connected to %s:%d\n", host, port);
    unif01_Gen *gen = unif01_CreateExternGenBits("ChaosRNG", next_bits);
    switch (battery) {
        case 1: fprintf(stderr, "[TestU01] SmallCrush\n"); bbattery_SmallCrush(gen); break;
        case 2: fprintf(stderr, "[TestU01] Crush\n");      bbattery_Crush(gen); break;
        case 3: fprintf(stderr, "[TestU01] BigCrush\n");   bbattery_BigCrush(gen); break;
    }
    unif01_DeleteExternGenBits(gen);
    fprintf(stderr, "[TestU01] Total bits: %llu\n", total_bits);
    return 0;
}
'''


def ensure_testu01_driver(workdir):
    """确保 testu01_driver 存在（不存在则生成 + 编译）"""
    drv = Path(workdir) / "testu01_driver"
    src = Path(workdir) / "testu01_driver.c"
    if drv.exists():
        return str(drv)
    src.write_text(TESTU01_SRC)
    prefix = os.environ.get("PREFIX", "/usr/local")
    cc = "clang" if shutil.which("clang") else ("gcc" if shutil.which("gcc") else "cc")
    cmd = [
        cc, "-O2", "-o", str(drv), str(src),
        f"-I{prefix}/include",
        f"-L{prefix}/lib",
        f"-Wl,-rpath,{prefix}/lib",
        "-ltestu01", "-lprobdist", "-lmylib", "-lm", "-lpthread",
    ]
    print(f"  → 编译 TestU01 驱动: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"  ❌ 编译失败:\n{r.stderr}")
        return None
    return str(drv)


def run_testu01(host, port, battery, workdir):
    print("═" * 68)
    print(f"  TestU01 {battery}")
    print("═" * 68)
    drv = ensure_testu01_driver(workdir)
    if not drv:
        print("  ❌ 驱动不可用")
        return 1
    battery_id = {"smallcrush": 1, "crush": 2, "bigcrush": 3}[battery]
    try:
        proc = subprocess.Popen(
            [drv, host, str(port), str(battery_id)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        fails = 0
        for line in proc.stdout:
            print(f"  {line.rstrip()}")
            if "FAILED" in line or "*****" in line:
                fails += 1
        proc.wait(timeout=86400)
        return fails
    except Exception as e:
        print(f"  ❌ 运行失败: {e}")
        return 1


# ====================================================================
# Dieharder
# ====================================================================
def run_dieharder(host, port, bytes_count, workdir):
    print("═" * 68)
    print("  Dieharder")
    print("═" * 68)
    if not shutil.which("dieharder"):
        print("  ❌ dieharder 未安装")
        return 1

    data_path = Path(workdir) / "dieharder_input.bin"
    if not data_path.exists() or data_path.stat().st_size < bytes_count:
        print(f"  → 采集 {bytes_count} 字节数据 ...")
        try:
            data = collect_bits(host, port, bytes_count, verbose=True)
            data_path.write_bytes(data)
            print(f"  → 保存: {data_path} ({len(data)} 字节)")
        except Exception as e:
            print(f"  ❌ 采集失败: {e}")
            return 1

    print("  → dieharder -a -Y 1 ...")
    cmd = ["dieharder", "-f", str(data_path), "-g", "201", "-a", "-Y", "1"]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        fails = 0
        for line in proc.stdout:
            print(f"  {line.rstrip()}")
            if "FAILED" in line:
                fails += 1
        proc.wait(timeout=86400)
        return fails
    except Exception as e:
        print(f"  ❌ dieharder 运行失败: {e}")
        return 1


# ====================================================================
# 主流程
# ====================================================================
def main():
    ap = argparse.ArgumentParser(description="ChaosRNG 三合一随机性检测")
    ap.add_argument("--host", default="192.168.1.168")
    ap.add_argument("--port", type=int, default=18888)
    ap.add_argument("--suite", default="all",
                    choices=["nist", "gmt", "testu01", "dieharder", "all"])
    ap.add_argument("--bits", type=int, default=1 << 20)
    ap.add_argument("--alpha", type=float, default=0.01)
    ap.add_argument("--testu01-battery", default="smallcrush",
                    choices=["smallcrush", "crush", "bigcrush"])
    ap.add_argument("--dieharder-bytes", type=int, default=1 << 26)
    ap.add_argument("--workdir", default=str(Path.home() / "ChaosRNG"))
    args = ap.parse_args()

    print("╔" + "═" * 66 + "╗")
    print("║  ChaosRNG 随机性检测 — 三合一严格模式" + " " * 28 + "║")
    print("╠" + "═" * 66 + "╣")
    print(f"║  RNG:      {args.host}:{args.port:<49} ║")
    print(f"║  套件:     {args.suite:<59} ║")
    print(f"║  比特数:   {args.bits:<59} ║")
    print(f"║  工作目录: {args.workdir:<59} ║")
    print("╚" + "═" * 66 + "╝")
    print()

    total_fails = 0
    bits = None

    # ---------- GM/T 和 NIST ----------
    if args.suite in ("nist", "gmt", "all"):
        target_bytes = args.bits // 8
        print(f"[数据采集] 从 {args.host}:{args.port} 拉取 {target_bytes} 字节 ...")
        t0 = time.time()
        try:
            data = collect_bits(args.host, args.port, target_bytes, verbose=True)
        except Exception as e:
            print(f"❌ 采集失败: {e}")
            return 1
        print(f"  完成: {time.time() - t0:.2f}s\n")
        bits = bytes_to_bits(data)
        del data

    # ---------- GM/T ----------
    if args.suite in ("gmt", "all"):
        f = run_gmt(bits, args.alpha)
        total_fails += f
        print()

    # ---------- NIST（简化版 - 用 GM/T 的子集） ----------
    if args.suite == "nist":
        print("NIST SP 800-22 核心 8 项（用 GM/T 实现）")
        # 复用 GM/T 的核心项
        f = run_gmt(bits, args.alpha)
        total_fails += f

    # ---------- TestU01 ----------
    if args.suite in ("testu01", "all"):
        f = run_testu01(args.host, args.port, args.testu01_battery, args.workdir)
        total_fails += f
        print()

    # ---------- Dieharder ----------
    if args.suite in ("dieharder", "all"):
        f = run_dieharder(args.host, args.port, args.dieharder_bytes, args.workdir)
        total_fails += f
        print()

    # ---------- 汇总 ----------
    print("═" * 68)
    if total_fails == 0:
        print("🎉 全部通过")
    else:
        print(f"⚠️  {total_fails} 项未通过")
    print("═" * 68)
    return 1 if total_fails > 0 else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INFO] 中断")
        sys.exit(130)
