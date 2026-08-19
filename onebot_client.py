#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OneBot V11 WebSocket 客户端（增强版）
- 正向 WS 连接到 OneBot 实现
- 接收消息事件，加密哈希后混入熵池
- 支持心跳、自动重连、可开关
"""

import json
import time
import hashlib
import asyncio
import logging
from typing import Optional, Dict, Any


def _secure_hash(data: str) -> str:
    """
    计算字符串的 SHA-256 哈希，使用 bytearray 作为中间缓冲区以便清零。
    注意：Python str 不可变，原始字符串仍可能残留于内存直到 GC，
    但此函数最小化了敏感数据的显式引用生命周期。
    """
    buf = bytearray(data, 'utf-8')
    try:
        return hashlib.sha256(buf).hexdigest()
    finally:
        # 清零中间缓冲区
        for i in range(len(buf)):
            buf[i] = 0


def _secure_mix(pool, prefix: str, sensitive: str, suffix: str) -> None:
    """
    将 prefix + sensitive + suffix 哈希后混入熵池，然后清零 sensitive 部分。
    """
    prefix_b = bytearray(prefix, 'utf-8')
    sensitive_b = bytearray(sensitive, 'utf-8')
    suffix_b = bytearray(suffix, 'utf-8')
    try:
        combined = prefix_b + sensitive_b + suffix_b
        pool.mix_bytes(hashlib.sha256(combined).digest())
    finally:
        for b in (sensitive_b, combined):
            for i in range(len(b)):
                b[i] = 0

logger = logging.getLogger("chaos_rng.onebot")

# 尝试导入 websockets
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


class OneBotV11Client:
    """OneBot V11 正向 WebSocket 客户端"""

    def __init__(
        self,
        pool,
        ws_url: str = "ws://127.0.0.1:3001/",
        access_token: str = "",
        reconnect_interval: float = 5.0,
        heartbeat_interval: float = 30.0,
        self_id: Optional[int] = None,
        auto_collect: bool = True,
        auto_collect_interval: int = 60,
        message_buffer_size: int = 200,
        message_sample_count: int = 10
    ):
        self.pool = pool
        self.ws_url = ws_url
        self.access_token = access_token
        self.reconnect_interval = reconnect_interval
        self.heartbeat_interval = heartbeat_interval
        self.self_id = self_id
        self.auto_collect = auto_collect
        self.auto_collect_interval = auto_collect_interval
        self.message_sample_count = message_sample_count

        self.ws = None
        self._running = False
        self._connected = False
        self._heartbeat_task = None
        self._receive_task = None
        self._auto_collect_task = None
        self._message_count = 0

        # 消息缓冲区
        self._message_buffer = []
        self._buffer_lock = asyncio.Lock()
        self._buffer_maxlen = message_buffer_size

        # 检查 websockets 可用性
        if not WEBSOCKETS_AVAILABLE:
            logger.error("websockets 库未安装，OneBot 功能不可用")

    @property
    def available(self) -> bool:
        return WEBSOCKETS_AVAILABLE

    async def start(self):
        """启动客户端，自动重连（最多5次）"""
        if not WEBSOCKETS_AVAILABLE:
            logger.error("websockets 库未安装，无法启动 OneBot 客户端")
            return

        self._running = True
        retry_count = 0
        max_retries = 5

        # 启动自动采集任务
        if self.auto_collect:
            self._auto_collect_task = asyncio.create_task(self._auto_collect_loop())

        while self._running and retry_count < max_retries:
            try:
                await self._connect()
                retry_count = 0  # 连接成功后重置计数
                if self._receive_task:
                    await self._receive_task
            except Exception as e:
                retry_count += 1
                logger.error(f"OneBot 连接异常 ({retry_count}/{max_retries}): {e}")

            if self._running and retry_count < max_retries:
                logger.info(f"{self.reconnect_interval}秒后重连...")
                await asyncio.sleep(self.reconnect_interval)

        if retry_count >= max_retries:
            logger.error(f"OneBot 重连次数已达上限 ({max_retries})，停止重连")
            self._running = False

    async def _connect(self):
        """建立 WebSocket 连接"""
        headers = {}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        logger.info(f"正在连接 OneBot: {self.ws_url}")
        self.ws = await websockets.connect(self.ws_url, additional_headers=headers)
        self._connected = True
        logger.info("OneBot WebSocket 连接成功")

        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._receive_task = asyncio.create_task(self._receive_loop())

    async def _heartbeat_loop(self):
        """心跳循环"""
        while self._running and self._connected:
            try:
                if self.ws and self.ws.close_code is None:
                    heartbeat = {
                        "post_type": "meta_event",
                        "meta_event_type": "heartbeat",
                        "time": int(time.time()),
                        "self_id": self.self_id or 0,
                        "status": {"online": True, "good": True},
                        "interval": int(self.heartbeat_interval * 1000)
                    }
                    await self.ws.send(json.dumps(heartbeat))
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.debug(f"心跳异常: {e}")
                break

    async def _receive_loop(self):
        """接收消息循环"""
        while self._running and self._connected:
            try:
                if self.ws and self.ws.close_code is None:
                    message = await self.ws.recv()
                    await self._handle_message(message)
            except websockets.exceptions.ConnectionClosed:
                logger.info("OneBot 连接已关闭")
                break
            except Exception as e:
                logger.error(f"接收消息异常: {e}")
                break

        self._connected = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()

    async def _handle_message(self, raw_message: str):
        """处理收到的 OneBot 消息"""
        try:
            data = json.loads(raw_message)
        except json.JSONDecodeError:
            return

        post_type = data.get("post_type")

        if post_type == "message":
            await self._handle_message_event(data)
        elif post_type == "meta_event":
            pass
        elif post_type == "notice":
            self._mix_event_data(data, "notice")
        elif post_type == "request":
            self._mix_event_data(data, "request")

    async def _handle_message_event(self, data: Dict[str, Any]):
        """
        处理消息事件，提取内容混入熵池。
        安全策略：
        - 缓冲区只存 msg_hash，不存 raw_msg
        - 使用 bytearray 处理敏感数据，处理后立即清零
        - 尽量缩短 raw_msg 在显式变量中的生命周期
        """
        message_type = data.get("message_type", "unknown")
        user_id = str(data.get("user_id", "unknown"))
        group_id = str(data.get("group_id", "private"))
        raw_msg = data.get("raw_message", "")
        message_id = data.get("message_id", 0)

        if not raw_msg:
            return

        # 避免处理自己发送的消息
        if self.self_id and str(data.get("self_id")) == str(self.self_id):
            return

        # 计算消息哈希（使用安全函数，中间缓冲区可清零）
        msg_hash = _secure_hash(raw_msg)

        # 将哈希加入缓冲区（绝不存原文）
        async with self._buffer_lock:
            self._message_buffer.append({
                "msg_hash": msg_hash,
                "group": group_id,
                "user": user_id,
                "time": time.time()
            })
            if len(self._message_buffer) > self._buffer_maxlen:
                self._message_buffer.pop(0)

        # 混入熵池（敏感部分使用 bytearray，处理后清零）
        _secure_mix(
            self.pool,
            prefix=f"{user_id}:{group_id}:",
            sensitive=raw_msg,
            suffix=f":{message_id}:{time.time()}"
        )

        # 显式删除引用，缩短生命周期
        raw_msg = ""
        data["raw_message"] = ""

        self._message_count += 1
        logger.debug(f"收到消息 [{message_type}] 来自 {user_id}")

    def _mix_event_data(self, data: Dict[str, Any], event_type: str):
        """将事件数据混入熵池"""
        try:
            json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
            hash_bytes = hashlib.sha256(f"{event_type}:{json_str}".encode()).digest()
            self.pool.mix_bytes(hash_bytes)
        except Exception:
            pass

    async def send_private_msg(self, user_id: int, message: str) -> Optional[Dict]:
        """发送私聊消息"""
        return await self._call_api("send_private_msg", {
            "user_id": user_id,
            "message": message
        })

    async def send_group_msg(self, group_id: int, message: str) -> Optional[Dict]:
        """发送群消息"""
        return await self._call_api("send_group_msg", {
            "group_id": group_id,
            "message": message
        })

    async def _call_api(self, action: str, params: Dict[str, Any]) -> Optional[Dict]:
        """调用 OneBot API"""
        if not self._connected or not self.ws:
            logger.warning(f"OneBot 未连接，无法调用 {action}")
            return None

        payload = {
            "action": action,
            "params": params,
            "echo": f"{action}_{int(time.time() * 1000)}"
        }

        try:
            await self.ws.send(json.dumps(payload))
            return {"status": "sent"}
        except Exception as e:
            logger.error(f"API 调用失败: {e}")
            return None

    async def sample_messages(self, n: int = 10) -> list:
        """从缓冲区随机采样 n 条消息哈希"""
        async with self._buffer_lock:
            if not self._message_buffer:
                return []

            seen = set()
            unique = []
            for item in self._message_buffer:
                key = (item["group"], item["msg_hash"])
                if key not in seen:
                    seen.add(key)
                    unique.append(item["msg_hash"])

            if len(unique) <= n:
                return unique

            import random
            return random.sample(unique, n)

    async def collect_and_mix(self, sample_count: int = 10) -> int:
        """自采集：采样消息并混入熵池"""
        messages = await self.sample_messages(sample_count)
        if not messages:
            return 0

        SECRET_KEY = "ChaosRNG_OneBot_Secret_2024"
        combined = SECRET_KEY + "".join(messages)
        hash_bytes = hashlib.sha256(combined.encode('utf-8')).digest()
        self.pool.mix_event(f"onebot_collect:{hash_bytes.hex()}")

        return len(messages)

    async def _auto_collect_loop(self):
        """自动采集循环"""
        while self._running:
            await asyncio.sleep(self.auto_collect_interval)
            if self._connected:
                try:
                    count = await self.collect_and_mix(self.message_sample_count)
                    if count > 0:
                        logger.info(f"📝 自动采集 {count} 条 OneBot 消息混入熵池")
                except Exception as e:
                    logger.debug(f"自动采集失败: {e}")

    async def stop(self):
        """停止客户端"""
        self._running = False
        self._connected = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._receive_task:
            self._receive_task.cancel()
        if self._auto_collect_task:
            self._auto_collect_task.cancel()
        if self.ws:
            await self.ws.close()
        logger.info("OneBot 客户端已停止")

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def message_count(self) -> int:
        return self._message_count

    @property
    def buffer_size(self) -> int:
        return len(self._message_buffer)
