#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
混沌随机数核心模块（独立版）
提供：
- ChaosEntropyPool: SHA-256 累积熵池
- ProcessSnapshotCollector: 系统进程抖动采集
- WeatherEntropyCollector: 全国省会温度采集
- SeedGenerator: 最终种子合成（支持多种哈希算法）
- HashWhirlpool: 哈希搅拌器（支持 SHA-256 / SHA3-256 / BLAKE2b）
"""

import os
import time
import hashlib
import asyncio
import aiohttp
import psutil
from typing import Dict, Tuple, List, Optional

# ====================================================================
# 防御性时间戳工具
# ====================================================================
def _get_safe_timestamp_bytes() -> bytes:
    try:
        ns = time.perf_counter_ns()
        if ns > 10_000_000:
            return ns.to_bytes(16, 'big')
        wall_ns = time.time_ns()
        if wall_ns > 1_577_836_800_000_000_000:
            return wall_ns.to_bytes(16, 'big')
        return os.urandom(16)
    except:
        return os.urandom(16)

# ====================================================================
# 哈希搅拌器
# ====================================================================
class HashWhirlpool:
    """
    哈希搅拌器 - 将任意原始熵数据通过密码学哈希函数搅拌

    工业标准做法：不管原始数据多杂乱，全部塞进哈希函数。
    只要原始数据里有哪怕1比特真熵，输出就是近乎完美的随机数。

    支持算法: sha256, sha3_256, blake2b
    """

    ALGORITHMS = {
        "sha256": hashlib.sha256,
        "sha3_256": hashlib.sha3_256,
        "blake2b": lambda: hashlib.blake2b(digest_size=32),
    }

    def __init__(self, algorithm: str = "sha256"):
        self.algorithm = algorithm
        self._hasher_class = self.ALGORITHMS.get(algorithm, hashlib.sha256)
        self._total_stirred = 0

    def stir(self, data: bytes) -> bytes:
        """搅拌数据，返回固定长度的哈希值"""
        hasher = self._hasher_class()
        hasher.update(data)
        hasher.update(_get_safe_timestamp_bytes())
        self._total_stirred += len(data)
        return hasher.digest()

    def stir_multiple(self, *data_chunks: bytes) -> bytes:
        """搅拌多个数据块"""
        hasher = self._hasher_class()
        for chunk in data_chunks:
            hasher.update(chunk)
        hasher.update(_get_safe_timestamp_bytes())
        self._total_stirred += sum(len(c) for c in data_chunks)
        return hasher.digest()

    @property
    def total_stirred(self) -> int:
        return self._total_stirred


# ====================================================================
# 1. 熵池
# ====================================================================
class ChaosEntropyPool:
    def __init__(self, hash_algorithm: str = "sha256"):
        self._event_count = 0
        self._last_mix_time = time.time()
        self._start_time = time.time()
        self._hasher = hashlib.sha256()
        self._whirlpool = HashWhirlpool(hash_algorithm)
        self._mix(str(time.perf_counter_ns()))

    def _mix(self, data: str) -> None:
        self._hasher.update(data.encode('utf-8'))
        self._hasher.update(_get_safe_timestamp_bytes())
        self._event_count += 1
        self._last_mix_time = time.time()

    def mix_event(self, event_str: str) -> None:
        self._mix(event_str)

    def mix_bytes(self, data: bytes) -> None:
        """直接混入原始字节（经过哈希搅拌）"""
        # 先用哈希搅拌处理原始熵，再混入主池
        stirred = self._whirlpool.stir(data)
        self._hasher.update(stirred)
        self._hasher.update(_get_safe_timestamp_bytes())
        self._event_count += 1
        self._last_mix_time = time.time()

    def mix_raw(self, data: bytes) -> None:
        """直接混入原始字节（不经过额外哈希，用于内部使用）"""
        self._hasher.update(data)
        self._hasher.update(_get_safe_timestamp_bytes())
        self._event_count += 1
        self._last_mix_time = time.time()

    def digest(self) -> bytes:
        return self._hasher.digest()

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def last_mix_time(self) -> float:
        return self._last_mix_time

    @property
    def start_time(self) -> float:
        return self._start_time

    @property
    def whirlpool(self) -> HashWhirlpool:
        return self._whirlpool

# ====================================================================
# 2. 进程快照采集器（物理熵）
# ====================================================================
class ProcessSnapshotCollector:
    def __init__(self, pool: ChaosEntropyPool):
        self.pool = pool
        self.last_snapshot: Dict[int, Tuple[str, float, float, int]] = {}
        self.is_first_run = True
        self._scan_count = 0

    def _collect_current(self) -> Dict[int, Tuple[str, float, float, int]]:
        snapshot = {}
        for proc in psutil.process_iter(['pid', 'name', 'cpu_times', 'io_counters']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or 'unknown'
                ct = info['cpu_times']
                cpu_user = ct.user if ct else 0.0
                cpu_sys = ct.system if ct else 0.0
                io = info['io_counters']
                io_read = io.read_bytes if io else 0
                snapshot[pid] = (name, cpu_user, cpu_sys, io_read)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return snapshot

    def scan_and_update(self) -> None:
        current = self._collect_current()
        if self.is_first_run:
            self.last_snapshot = current
            self.is_first_run = False
            self._scan_count += 1
            return

        old = self.last_snapshot
        old_pids = set(old.keys())
        new_pids = set(current.keys())

        died = old_pids - new_pids
        born = new_pids - old_pids
        if died:
            self.pool.mix_event(f"die:{','.join(map(str, died))}")
        if born:
            self.pool.mix_event(f"born:{','.join(map(str, born))}")

        for pid, (name, u1, s1, io1) in current.items():
            if pid in old:
                _, u0, s0, io0 = old[pid]
                delta_cpu = (u1 - u0) + (s1 - s0)
                delta_io = io1 - io0
                if delta_cpu > 0.001 or delta_io > 4096:
                    evt = f"proc:{name}|{pid}|c:{delta_cpu:.6f}|i:{delta_io}"
                    self.pool.mix_event(evt)

        self.last_snapshot = current
        self._scan_count += 1

    @property
    def scan_count(self) -> int:
        return self._scan_count

# ====================================================================
# 3. 天气熵采集器
# ====================================================================
PROVINCE_CAPITALS = {
    "北京": "beijing", "上海": "shanghai", "天津": "tianjin", "重庆": "chongqing",
    "河北": "shijiazhuang", "山西": "taiyuan", "辽宁": "shenyang", "吉林": "changchun",
    "黑龙江": "haerbin", "江苏": "nanjing", "浙江": "hangzhou", "安徽": "hefei",
    "福建": "fuzhou", "江西": "nanchang", "山东": "jinan", "河南": "zhengzhou",
    "湖北": "wuhan", "湖南": "changsha", "广东": "guangzhou", "海南": "haikou",
    "四川": "chengdu", "贵州": "guiyang", "云南": "kunming", "陕西": "xian",
    "甘肃": "lanzhou", "青海": "xining", "台湾": "taipei", "内蒙古": "huhehaote",
    "广西": "nanning", "西藏": "lasa", "宁夏": "yinchuan", "新疆": "wulumuqi",
    "香港": "hongkong", "澳门": "macau"
}

class WeatherEntropyCollector:
    def __init__(self, pool: ChaosEntropyPool, sample_count: Optional[int] = None):
        self.pool = pool
        self.sample_count = sample_count
        self._session: Optional[aiohttp.ClientSession] = None
        self._running = False
        self._update_count = 0

    async def _fetch_temperature(self, city: str) -> Optional[int]:
        url = f"https://wttr.in/{city}?format=%t"
        try:
            async with self._session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    return None
                text = await resp.text()
                digits = ''.join(filter(lambda c: c.isdigit() or c == '-', text))
                if digits:
                    return int(digits)
                return None
        except:
            return None

    async def collect(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession()

        provinces = list(PROVINCE_CAPITALS.keys())
        if self.sample_count is not None and self.sample_count < len(provinces):
            import random
            selected = random.sample(provinces, self.sample_count)
        else:
            selected = provinces

        tasks = [self._fetch_temperature(PROVINCE_CAPITALS[p]) for p in selected]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_pairs = []
        for p, temp in zip(selected, results):
            if isinstance(temp, int):
                valid_pairs.append(f"{p}{temp}")

        if valid_pairs:
            seed_str = "".join(valid_pairs)
            self.pool.mix_event(f"weather:{seed_str}")
            self._update_count += 1

    async def start(self, interval: int = 600):
        self._running = True
        while self._running:
            try:
                await self.collect()
            except Exception as e:
                pass
            await asyncio.sleep(interval)

    def stop(self):
        self._running = False
        if self._session:
            asyncio.create_task(self._session.close())

    @property
    def update_count(self) -> int:
        return self._update_count

# ====================================================================
# 4. 种子合成器
# ====================================================================
class SeedGenerator:
    @staticmethod
    def generate(pool: ChaosEntropyPool) -> bytes:
        sys_entropy = os.urandom(32)
        pool_hash = pool.digest()
        try:
            safe_ts = _get_safe_timestamp_bytes()
            time_hash = hashlib.sha256(safe_ts).digest()
        except:
            time_hash = os.urandom(32)
        return bytes(a ^ b ^ c for a, b, c in zip(sys_entropy, pool_hash, time_hash))
