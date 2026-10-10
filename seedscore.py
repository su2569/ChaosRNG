#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
种子质量评分 + 令牌桶限流 + Hamming 去重

对应 Go 版 seedscore.go：
  - 评分 5 个维度：Monobit / Shannon 熵 / Runs / 唯一字节 / XOR 差分熵
  - 每连接 + 全局双重限流
  - 与最近 64 个已接受种子比对 Hamming 距离
"""

import time
import math
import threading
from typing import Tuple, Optional


PUSH_SEED_BYTES  = 32
PUSH_SEED_HEX_LEN = 64
PUSH_SCORE_MIN   = 65.0
PUSH_RATE_PER_SEC = 2.0
PUSH_RATE_BURST   = 4
PUSH_RECENT_CAP   = 64
PUSH_MIN_HAMMING  = 40


# ----------------------------------------------------------------------
# 评分器
# ----------------------------------------------------------------------
class SeedScore:
    """维护最近接受的种子，用于 Hamming 去重"""

    def __init__(self):
        self._lock = threading.Lock()
        self._recent = [None] * PUSH_RECENT_CAP   # 每项 bytes(32)
        self._recent_idx = 0
        self._recent_len = 0

    @staticmethod
    def _popcount(x: int) -> int:
        return bin(x).count("1")

    def score(self, seed: bytes) -> Tuple[float, bool]:
        """返回 (总分 0~100, hamming 通过与否)"""
        if len(seed) != PUSH_SEED_BYTES:
            return 0.0, False

        # 1. Monobit
        ones = sum(self._popcount(b) for b in seed)
        dev = abs(ones - 128)
        monobit_score = max(0.0, 100.0 - dev * (100.0 / 32.0))

        # 2. Shannon 熵
        freq = [0] * 256
        for b in seed:
            freq[b] += 1
        H = 0.0
        for c in freq:
            if c == 0:
                continue
            p = c / PUSH_SEED_BYTES
            H -= p * math.log2(p)
        shannon_score = min(100.0, H / 5.0 * 100.0)

        # 3. Runs
        runs = 1
        prev = (seed[0] >> 7) & 1
        for b in seed:
            for k in range(7, -1, -1):
                bit = (b >> k) & 1
                if bit != prev:
                    runs += 1
                    prev = bit
        runs_dev = abs(runs - 128)
        runs_score = max(0.0, 100.0 - runs_dev * (100.0 / 64.0))

        # 4. 唯一字节
        uniq = sum(1 for c in freq if c > 0)
        uniq_score = min(100.0, uniq / 28.0 * 100.0)

        # 5. XOR 差分熵（专门抓递增/周期序列）
        diff = [seed[i] ^ seed[i + 1] for i in range(PUSH_SEED_BYTES - 1)]
        dfreq = [0] * 256
        for b in diff:
            dfreq[b] += 1
        DH = 0.0
        for c in dfreq:
            if c == 0:
                continue
            p = c / len(diff)
            DH -= p * math.log2(p)
        diff_score = min(100.0, DH / 4.9 * 100.0)

        total = (0.35 * monobit_score + 0.25 * shannon_score +
                 0.15 * runs_score + 0.10 * uniq_score + 0.15 * diff_score)

        return total, self._check_hamming(seed)

    def _check_hamming(self, seed: bytes) -> bool:
        with self._lock:
            for i in range(self._recent_len):
                idx = (self._recent_idx - 1 - i + PUSH_RECENT_CAP) % PUSH_RECENT_CAP
                if self._hamming(seed, self._recent[idx]) < PUSH_MIN_HAMMING:
                    return False
            return True

    def record(self, seed: bytes) -> None:
        if len(seed) != PUSH_SEED_BYTES:
            return
        with self._lock:
            self._recent[self._recent_idx] = bytes(seed)
            self._recent_idx = (self._recent_idx + 1) % PUSH_RECENT_CAP
            if self._recent_len < PUSH_RECENT_CAP:
                self._recent_len += 1

    @staticmethod
    def _hamming(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# ----------------------------------------------------------------------
# 令牌桶限流
# ----------------------------------------------------------------------
class PushLimiter:
    """令牌桶限流器（每连接一份 + 全局一份）"""

    def __init__(self, per_sec: float, burst: int):
        self._lock = threading.Lock()
        self._tokens = float(burst)
        self._capacity = float(burst)
        self._rate = per_sec
        self._last = time.monotonic()

    def allow(self) -> Tuple[bool, int]:
        """返回 (是否允许, 失败时建议等待毫秒)"""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens += elapsed * self._rate
            if self._tokens > self._capacity:
                self._tokens = self._capacity
            if self._tokens >= 1:
                self._tokens -= 1
                return True, 0
            need = (1 - self._tokens) / self._rate
            return False, int(need * 1000) + 1


# ----------------------------------------------------------------------
# PUSH_SEED 处理
# ----------------------------------------------------------------------
# 全局共享
GLOBAL_PUSH_LIMITER = PushLimiter(PUSH_RATE_PER_SEC, PUSH_RATE_BURST)
GLOBAL_SEED_SCORE = SeedScore()


def push_hex_seed(pool, per_conn: Optional[PushLimiter], hex_str: str) -> dict:
    """
    处理一条 `PUSH_SEED <hex>` 请求。
    顺序：格式 → 评分 → 阈值 → 去重 → 全局限流 → 每连接限流 → 混池。
    便宜检查在前，避免无效请求消耗限流配额。
    """
    # 1. 格式校验
    if len(hex_str) != PUSH_SEED_HEX_LEN:
        return {"ok": False, "score": 0.0, "reason": "bad_length", "mixed": False}
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return {"ok": False, "score": 0.0, "reason": "bad_hex", "mixed": False}
    if len(raw) != PUSH_SEED_BYTES:
        return {"ok": False, "score": 0.0, "reason": "bad_hex", "mixed": False}

    # 2. 评分
    score, pass_hamming = GLOBAL_SEED_SCORE.score(raw)
    if score < PUSH_SCORE_MIN:
        return {"ok": False, "score": score, "reason": "low_entropy", "mixed": False}
    if not pass_hamming:
        return {"ok": False, "score": score, "reason": "too_similar", "mixed": False}

    # 3. 全局限流（先查全局）
    ok, retry = GLOBAL_PUSH_LIMITER.allow()
    if not ok:
        return {"ok": False, "score": score, "reason": "rate_global",
                "retry_ms": retry, "mixed": False}

    # 4. 每连接限流
    if per_conn is not None:
        ok, retry = per_conn.allow()
        if not ok:
            return {"ok": False, "score": score, "reason": "rate_conn",
                    "retry_ms": retry, "mixed": False}

    # 5. 通过：记录 + 混池
    GLOBAL_SEED_SCORE.record(raw)
    pool.mix_bytes(raw)
    return {"ok": True, "score": score, "reason": "accepted", "mixed": True}