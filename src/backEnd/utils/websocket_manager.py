"""
WebSocket 连接管理器

管理所有 WebSocket 连接，支持广播消息和定时刷新通知。
"""

import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any
from fastapi import WebSocket
from datetime import datetime

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    WebSocket 连接管理器
    
    负责：
    - 管理所有活跃的 WebSocket 连接
    - 广播消息给所有连接的客户端
    - 定时发送刷新通知
    - 新任务创建时发送刷新通知
    """
    
    def __init__(self):
        # 活跃的 WebSocket 连接集合
        self._active_connections: Set[WebSocket] = set()
        # 刷新间隔（分钟），默认5分钟
        self._refresh_interval: int = 5
        # 定时任务
        self._refresh_task: Optional[asyncio.Task] = None
        # 是否正在运行
        self._is_running: bool = False
        # 锁，保护连接集合的线程安全
        self._lock = asyncio.Lock()
    
    @property
    def refresh_interval(self) -> int:
        """获取当前刷新间隔（分钟）"""
        return self._refresh_interval
    
    @property
    def connection_count(self) -> int:
        """获取当前连接数"""
        return len(self._active_connections)
    
    async def connect(self, websocket: WebSocket) -> None:
        """
        接受新的 WebSocket 连接
        
        Args:
            websocket: WebSocket 连接对象
        """
        await websocket.accept()
        async with self._lock:
            self._active_connections.add(websocket)
        logger.info(f"WebSocket 连接已建立，当前连接数: {self.connection_count}")
        
        # 发送欢迎消息和当前配置
        await self._send_welcome_message(websocket)
    
    async def disconnect(self, websocket: WebSocket) -> None:
        """
        断开 WebSocket 连接
        
        Args:
            websocket: WebSocket 连接对象
        """
        async with self._lock:
            self._active_connections.discard(websocket)
        logger.info(f"WebSocket 连接已断开，当前连接数: {self.connection_count}")
    
    async def _send_welcome_message(self, websocket: WebSocket) -> None:
        """发送欢迎消息"""
        try:
            await websocket.send_json({
                "type": "connected",
                "message": "WebSocket 连接成功",
                "data": {
                    "refreshInterval": self._refresh_interval,
                    "timestamp": datetime.now().isoformat()
                }
            })
        except Exception as e:
            logger.error(f"发送欢迎消息失败: {e}")
    
    async def broadcast(self, message: Dict[str, Any]) -> None:
        """
        广播消息给所有连接的客户端
        
        Args:
            message: 要广播的消息（字典格式）
        """
        if not self._active_connections:
            return
        
        # 复制连接集合，避免迭代时修改
        async with self._lock:
            connections = list(self._active_connections)
        
        disconnected = []
        for websocket in connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.warning(f"发送消息失败，连接可能已断开: {e}")
                disconnected.append(websocket)
        
        # 清理已断开的连接
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    self._active_connections.discard(ws)
            logger.info(f"清理了 {len(disconnected)} 个已断开的连接")
    
    async def broadcast_refresh(self) -> None:
        """广播刷新通知"""
        await self.broadcast({
            "type": "refresh",
            "message": "请刷新数据",
            "data": {
                "reason": "scheduled",
                "timestamp": datetime.now().isoformat()
            }
        })
        logger.info(f"已广播定时刷新通知，当前连接数: {self.connection_count}")
    
    def update_refresh_interval(self, interval: int) -> None:
        """
        更新刷新间隔
        
        Args:
            interval: 新的刷新间隔（分钟），范围 1-60
        """
        # 限制范围
        interval = max(1, min(60, interval))
        if interval != self._refresh_interval:
            old_interval = self._refresh_interval
            self._refresh_interval = interval
            logger.info(f"刷新间隔已更新: {old_interval}分钟 -> {interval}分钟")
            
            # 如果定时任务正在运行，重启它以应用新间隔
            if self._is_running and self._refresh_task:
                self._restart_refresh_task()
    
    def _restart_refresh_task(self) -> None:
        """重启定时刷新任务"""
        if self._refresh_task:
            self._refresh_task.cancel()
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        logger.info("定时刷新任务已重启")
    
    async def _refresh_loop(self) -> None:
        """定时刷新循环"""
        print(f"[WebSocket] 定时刷新循环已启动，间隔: {self._refresh_interval} 分钟")
        logger.info(f"定时刷新循环已启动，间隔: {self._refresh_interval} 分钟")
        while self._is_running:
            try:
                # 等待指定的刷新间隔（转换为秒）
                wait_seconds = self._refresh_interval * 60
                print(f"[WebSocket] 下一次刷新将在 {self._refresh_interval} 分钟后 ({wait_seconds}秒)")
                logger.info(f"下一次刷新将在 {self._refresh_interval} 分钟后 ({wait_seconds}秒)")
                await asyncio.sleep(wait_seconds)
                
                # 只有有连接时才广播
                if self._active_connections:
                    print(f"[WebSocket] 定时刷新触发，准备广播到 {self.connection_count} 个连接")
                    logger.info(f"定时刷新触发，准备广播到 {self.connection_count} 个连接")
                    await self.broadcast_refresh()
                else:
                    print("[WebSocket] 定时刷新触发，但没有活跃连接，跳过广播")
                    logger.info("定时刷新触发，但没有活跃连接，跳过广播")
            except asyncio.CancelledError:
                print("[WebSocket] 定时刷新任务被取消")
                logger.info("定时刷新任务被取消")
                break
            except Exception as e:
                print(f"[WebSocket] 定时刷新循环出错: {e}")
                logger.error(f"定时刷新循环出错: {e}")
                await asyncio.sleep(5)  # 出错后短暂等待再重试
    
    def start(self, initial_interval: int = None) -> None:
        """启动 WebSocket 管理器（包括定时刷新任务）
        
        Args:
            initial_interval: 初始刷新间隔（分钟），为None时使用默认值
        """
        if not self._is_running:
            if initial_interval is not None:
                self._refresh_interval = max(1, min(60, initial_interval))
            self._is_running = True
            self._refresh_task = asyncio.create_task(self._refresh_loop())
            print(f"[WebSocket] WebSocket 管理器已启动，刷新间隔: {self._refresh_interval}分钟")
            logger.info(f"WebSocket 管理器已启动，刷新间隔: {self._refresh_interval}分钟")
    
    async def stop(self) -> None:
        """停止 WebSocket 管理器"""
        self._is_running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        
        # 关闭所有连接
        async with self._lock:
            for websocket in list(self._active_connections):
                try:
                    await websocket.close()
                except Exception:
                    pass
            self._active_connections.clear()
        
        logger.info("WebSocket 管理器已停止")
    
    async def handle_message(self, websocket: WebSocket, data: Dict[str, Any]) -> None:
        """
        处理来自客户端的消息
        
        Args:
            websocket: WebSocket 连接
            data: 接收到的消息数据
        """
        msg_type = data.get("type", "")
        
        if msg_type == "ping":
            # 心跳响应
            await websocket.send_json({
                "type": "pong",
                "timestamp": datetime.now().isoformat()
            })
        elif msg_type == "setRefreshInterval":
            # 客户端请求更新刷新间隔
            interval = data.get("interval", 5)
            self.update_refresh_interval(interval)
            # 广播新的配置给所有客户端
            await self.broadcast({
                "type": "configUpdate",
                "message": "刷新间隔已更新",
                "data": {
                    "refreshInterval": self._refresh_interval
                }
            })
        else:
            logger.debug(f"收到未知消息类型: {msg_type}")

    async def notify_task_created(self, task_id: str = None) -> None:
        """
        通知新任务已创建，触发前端刷新
        
        Args:
            task_id: 新创建的任务ID（可选）
        """
        await self.broadcast({
            "type": "refresh",
            "message": "新任务已创建，请刷新数据",
            "data": {
                "reason": "task_created",
                "taskId": task_id,
                "timestamp": datetime.now().isoformat()
            }
        })
        logger.info(f"已广播新任务创建通知: {task_id}")


# 全局单例
ws_manager = WebSocketManager()
