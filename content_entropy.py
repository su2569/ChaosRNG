#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
内容熵采集模块

从各大平台读取最新内容（热搜、热榜、趋势等），哈希后作为熵源混入池。

支持平台：
- 微博热搜
- 知乎热榜
- B站热门
- GitHub Trending
- Hacker News
- Reddit (可选)
- 百度热搜
- 抖音热点 (可选)

设计原则：
- 异步采集，避免阻塞
- 内容缓冲（不直接请求最新，而是从缓冲区取）
- 请求间隔控制（防止被反扒）
- 失败自动降级
- 所有内容经 SHA-256 哈希后混入（保护隐私，不存储原始内容）
"""

import re
import json
import time
import hashlib
import asyncio
import logging
from typing import Optional, Dict, List, Any
from datetime import datetime

logger = logging.getLogger("chaos_rng.content")


class ContentEntropyCollector:
    """
    内容熵采集器

    工作流程：
    1. 后台定期从各平台采集最新内容
    2. 内容存入环形缓冲区（不存原始文本，只存哈希值）
    3. 采集时从缓冲区随机抽取内容哈希混入熵池
    4. 缓冲区保证即使某个平台暂时不可用，仍有历史内容可用
    """

    def __init__(
        self,
        pool,
        platforms: Optional[Dict[str, bool]] = None,
        buffer_size: int = 500,
        collection_interval: int = 300,
        request_timeout: int = 15,
        min_interval_between_requests: float = 2.0
    ):
        self.pool = pool
        self.buffer_size = buffer_size
        self.collection_interval = collection_interval
        self.request_timeout = request_timeout
        self.min_interval = min_interval_between_requests

        # 平台开关
        default_platforms = {
            "weibo": True,
            "zhihu": True,
            "bilibili": True,
            "github": True,
            "hackernews": True,
            "baidu": True,
        }
        self.platforms = {**default_platforms, **(platforms or {})}

        # 缓冲区: 存储 (平台, 内容哈希, 时间戳)
        self._buffer: List[Dict[str, Any]] = []
        self._buffer_lock = asyncio.Lock()

        # aiohttp session
        self._session = None
        self._running = False
        self._last_request_time = 0
        self._update_count = 0
        self._failed_platforms: Dict[str, int] = {}  # 失败计数

    @property
    def available(self) -> bool:
        try:
            import aiohttp
            return True
        except ImportError:
            return False

    async def _get_session(self):
        """获取或创建 aiohttp session"""
        if self._session is None or self._session.closed:
            import aiohttp
            self._session = aiohttp.ClientSession(
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    )
                }
            )
        return self._session

    async def _safe_request(self, url: str, **kwargs) -> Optional[str]:
        """安全请求，带速率限制"""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)

        try:
            session = await self._get_session()
            async with session.get(url, timeout=self.request_timeout, **kwargs) as resp:
                self._last_request_time = time.time()
                if resp.status == 200:
                    return await resp.text()
                else:
                    logger.debug(f"请求 {url[:60]}... 返回 {resp.status}")
                    return None
        except asyncio.TimeoutError:
            logger.debug(f"请求超时: {url[:60]}...")
            return None
        except Exception as e:
            logger.debug(f"请求失败: {url[:60]}... - {e}")
            return None

    # ---------- 各平台采集器 ----------
    async def _fetch_weibo(self) -> List[str]:
        """微博热搜"""
        try:
            # 微博热搜API
            url = "https://weibo.com/ajax/side/hotSearch"
            text = await self._safe_request(url)
            if not text:
                return []

            data = json.loads(text)
            items = []
            if "data" in data and "realtime" in data["data"]:
                for item in data["data"]["realtime"][:20]:
                    word = item.get("word", "")
                    if word:
                        items.append(f"weibo:{word}")
            return items
        except Exception as e:
            logger.debug(f"微博采集失败: {e}")
            return []

    async def _fetch_zhihu(self) -> List[str]:
        """知乎热榜"""
        try:
            url = "https://www.zhihu.com/api/v3/feed/topstory/hot-lists/total"
            text = await self._safe_request(url)
            if not text:
                return []

            data = json.loads(text)
            items = []
            if "data" in data:
                for item in data["data"][:20]:
                    title = item.get("target", {}).get("title", "")
                    if title:
                        items.append(f"zhihu:{title}")
            return items
        except Exception as e:
            logger.debug(f"知乎采集失败: {e}")
            return []

    async def _fetch_bilibili(self) -> List[str]:
        """B站热门"""
        try:
            url = "https://api.bilibili.com/x/web-interface/ranking/v2"
            params = {"rid": 0, "type": "all"}
            session = await self._get_session()

            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)

            async with session.get(url, params=params, timeout=self.request_timeout) as resp:
                self._last_request_time = time.time()
                if resp.status != 200:
                    return []
                data = await resp.json()

            items = []
            if data.get("data", {}).get("list"):
                for item in data["data"]["list"][:20]:
                    title = item.get("title", "")
                    if title:
                        items.append(f"bilibili:{title}")
            return items
        except Exception as e:
            logger.debug(f"B站采集失败: {e}")
            return []

    async def _fetch_github(self) -> List[str]:
        """GitHub Trending"""
        try:
            url = "https://github.com/trending"
            text = await self._safe_request(url)
            if not text:
                return []

            # 简单正则提取仓库名
            pattern = r'<h2[^>]*>\s*<a[^>]*href="(/[^/]+/[^"]+)"'
            matches = re.findall(pattern, text)

            items = []
            for match in matches[:15]:
                repo = match.strip("/")
                items.append(f"github:{repo}")
            return items
        except Exception as e:
            logger.debug(f"GitHub采集失败: {e}")
            return []

    async def _fetch_hackernews(self) -> List[str]:
        """Hacker News 热门"""
        try:
            # 先获取热门故事ID
            top_url = "https://hacker-news.firebaseio.com/v0/topstories.json"
            text = await self._safe_request(top_url)
            if not text:
                return []

            story_ids = json.loads(text)[:15]
            items = []

            for sid in story_ids:
                story_url = f"https://hacker-news.firebaseio.com/v0/item/{sid}.json"
                story_text = await self._safe_request(story_url)
                if story_text:
                    try:
                        story = json.loads(story_text)
                        title = story.get("title", "")
                        if title:
                            items.append(f"hackernews:{title}")
                    except:
                        pass
                # 小延迟避免请求过快
                await asyncio.sleep(0.3)

            return items
        except Exception as e:
            logger.debug(f"HackerNews采集失败: {e}")
            return []

    async def _fetch_baidu(self) -> List[str]:
        """百度热搜"""
        try:
            url = "https://top.baidu.com/board"
            text = await self._safe_request(url)
            if not text:
                return []

            # 尝试从页面提取
            pattern = r'"word":"([^"]+)"'
            matches = re.findall(pattern, text)

            items = []
            for match in matches[:20]:
                items.append(f"baidu:{match}")
            return items
        except Exception as e:
            logger.debug(f"百度采集失败: {e}")
            return []

    # ---------- 核心方法 ----------
    async def _collect_platform(self, name: str) -> int:
        """采集单个平台的内容"""
        if not self.platforms.get(name, False):
            return 0

        # 检查失败计数（连续失败5次则跳过）
        if self._failed_platforms.get(name, 0) >= 5:
            logger.debug(f"平台 {name} 连续失败过多，跳过")
            return 0

        fetchers = {
            "weibo": self._fetch_weibo,
            "zhihu": self._fetch_zhihu,
            "bilibili": self._fetch_bilibili,
            "github": self._fetch_github,
            "hackernews": self._fetch_hackernews,
            "baidu": self._fetch_baidu,
        }

        fetcher = fetchers.get(name)
        if not fetcher:
            return 0

        try:
            items = await fetcher()
            if items:
                # 哈希后存入缓冲区
                async with self._buffer_lock:
                    for item in items:
                        item_hash = hashlib.sha256(item.encode('utf-8')).hexdigest()
                        self._buffer.append({
                            "platform": name,
                            "hash": item_hash,
                            "time": time.time(),
                            "raw_len": len(item)
                        })

                    # 限制缓冲区大小
                    if len(self._buffer) > self.buffer_size:
                        self._buffer = self._buffer[-self.buffer_size:]

                # 重置失败计数
                self._failed_platforms[name] = 0
                logger.info(f"📰 {name}: 采集 {len(items)} 条内容")
                return len(items)
            else:
                self._failed_platforms[name] = self._failed_platforms.get(name, 0) + 1
                return 0
        except Exception as e:
            self._failed_platforms[name] = self._failed_platforms.get(name, 0) + 1
            logger.debug(f"平台 {name} 采集异常: {e}")
            return 0

    async def collect(self) -> int:
        """采集所有启用的平台"""
        tasks = []
        for name in self.platforms:
            if self.platforms.get(name, False):
                tasks.append(self._collect_platform(name))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        total = sum(r for r in results if isinstance(r, int))

        if total > 0:
            self._update_count += 1

        return total

    async def mix_from_buffer(self, count: int = 10) -> int:
        """从缓冲区随机抽取内容混入熵池"""
        async with self._buffer_lock:
            if not self._buffer:
                return 0

            import random
            sample_size = min(count, len(self._buffer))
            selected = random.sample(self._buffer, sample_size)

        # 混入熵池
        combined = ""
        for item in selected:
            combined += item["hash"]

        hash_result = hashlib.sha256(
            f"content:{combined}:{time.perf_counter_ns()}".encode()
        ).digest()
        self.pool.mix_bytes(hash_result)

        return len(hash_result) * 8

    async def start_daemon(self):
        """后台持续采集"""
        self._running = True

        # 首次采集
        await self.collect()

        while self._running:
            await asyncio.sleep(self.collection_interval)
            if not self._running:
                break
            try:
                await self.collect()
            except Exception as e:
                logger.debug(f"内容采集循环异常: {e}")

    def stop(self):
        self._running = False
        if self._session and not self._session.closed:
            asyncio.create_task(self._session.close())

    @property
    def buffer_size_current(self) -> int:
        return len(self._buffer)

    @property
    def update_count(self) -> int:
        return self._update_count

    def get_status(self) -> Dict[str, Any]:
        """获取状态信息"""
        platform_status = {}
        for name, enabled in self.platforms.items():
            fails = self._failed_platforms.get(name, 0)
            status = "✅" if enabled and fails < 5 else "❌"
            platform_status[name] = {
                "enabled": enabled,
                "fails": fails,
                "status": status
            }

        return {
            "buffer_size": self.buffer_size_current,
            "buffer_max": self.buffer_size,
            "update_count": self._update_count,
            "platforms": platform_status
        }
