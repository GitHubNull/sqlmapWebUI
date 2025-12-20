import threading
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

from model.SessionHeader import SessionHeader, SessionHeaderCreate, ReplaceStrategy
from model.DataStore import DataStore

# 使用标准库的logging模块
import logging
logger = logging.getLogger(__name__)


class SessionHeaderManager:
    """会话性请求头管理器 - 内存存储临时会话请求头"""
    
    def __init__(self):
        # {client_ip: {header_name: SessionHeader}}
        self._session_headers: Dict[str, Dict[str, SessionHeader]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._id_counter = 1  # ID计数器
        logger.debug("SessionHeaderManager initialized")
        
    def _get_db(self):
        """获取请求头数据库连接"""
        return DataStore.header_db
    
    def _generate_id(self) -> int:
        """生成唯一ID"""
        self._id_counter += 1
        return self._id_counter

    def set_session_header(self, client_ip: str, header_create: SessionHeaderCreate) -> bool:
        """设置会话性请求头"""
        try:
            with self._lock:
                expires_at = datetime.now() + timedelta(seconds=header_create.ttl)
                current_time = datetime.now()
                
                # 检查是否已存在，如果存在则复用ID
                existing_header = None
                if client_ip in self._session_headers and header_create.header_name in self._session_headers[client_ip]:
                    existing_header = self._session_headers[client_ip][header_create.header_name]
                
                header_id = existing_header.id if existing_header and existing_header.id else self._generate_id()
                
                # 处理scope字段
                scope = header_create.scope
                
                session_header = SessionHeader(
                    id=header_id,
                    header_name=header_create.header_name,
                    header_value=header_create.header_value,
                    replace_strategy=header_create.replace_strategy,
                    priority=header_create.priority,
                    is_active=header_create.is_active,
                    expires_at=expires_at,
                    created_at=existing_header.created_at if existing_header else current_time,
                    updated_at=current_time if existing_header else None,
                    source_ip=client_ip,
                    scope=scope
                )
                
                # 如果客户端IP不存在，创建新的字典
                if client_ip not in self._session_headers:
                    self._session_headers[client_ip] = {}
                
                # 设置或更新请求头
                self._session_headers[client_ip][header_create.header_name] = session_header
                
                # 序列化scope配置
                scope_config_json = None
                if scope is not None:
                    scope_config_json = json.dumps(scope.to_dict(), ensure_ascii=False)
                
                # 持久化到数据库
                try:
                    db = self._get_db()
                    if db is not None:
                        # 尝试更新现有记录
                        cursor = db.only_execute("""
                            UPDATE session_headers 
                            SET header_value = ?, replace_strategy = ?, priority = ?, is_active = ?,
                                expires_at = ?, updated_at = ?, scope_config = ?
                            WHERE client_ip = ? AND header_name = ?
                        """, (
                            header_create.header_value,
                            header_create.replace_strategy.value,
                            header_create.priority,
                            1 if header_create.is_active else 0,
                            expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                            current_time.strftime('%Y-%m-%d %H:%M:%S'),
                            scope_config_json,
                            client_ip,
                            header_create.header_name
                        ))
                        
                        # 如果没有更新任何记录，则插入新记录
                        if cursor.rowcount == 0:
                            insert_cursor = db.only_execute("""
                                INSERT INTO session_headers 
                                (client_ip, header_name, header_value, replace_strategy, priority, is_active, 
                                 expires_at, created_at, scope_config)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                client_ip,
                                header_create.header_name,
                                header_create.header_value,
                                header_create.replace_strategy.value,
                                header_create.priority,
                                1 if header_create.is_active else 0,
                                expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                                current_time.strftime('%Y-%m-%d %H:%M:%S'),
                                scope_config_json
                            ))
                            # 获取数据库生成的真实ID并更新内存对象
                            if insert_cursor and insert_cursor.lastrowid:
                                session_header.id = insert_cursor.lastrowid
                                self._session_headers[client_ip][header_create.header_name] = session_header
                        else:
                            # 更新时也需要获取数据库中的ID
                            id_cursor = db.only_execute("""
                                SELECT id FROM session_headers WHERE client_ip = ? AND header_name = ?
                            """, (client_ip, header_create.header_name))
                            if id_cursor:
                                row = id_cursor.fetchone()
                                if row:
                                    session_header.id = row[0]
                                    self._session_headers[client_ip][header_create.header_name] = session_header
                        logger.debug(f"Persisted session header to database for {client_ip}: {header_create.header_name}")
                except Exception as db_error:
                    logger.error(f"Failed to persist session header to database: {db_error}")
                
                logger.debug(f"Set session header for {client_ip}: {header_create.header_name}")
                return True
        except Exception as e:
            logger.error(f"Failed to set session header: {e}")
            return False

    def set_session_headers_batch(self, client_ip: str, headers: List[SessionHeaderCreate]) -> int:
        """批量设置会话性请求头"""
        success_count = 0
        for header_create in headers:
            if self.set_session_header(client_ip, header_create):
                success_count += 1
        
        logger.debug(f"Set {success_count}/{len(headers)} session headers for {client_ip}")
        return success_count

    def get_session_headers(self, client_ip: str, active_only: bool = True) -> Dict[str, SessionHeader]:
        """获取指定客户端的会话性请求头"""
        try:
            with self._lock:
                if client_ip not in self._session_headers:
                    return {}
                
                headers = self._session_headers[client_ip]
                if not active_only:
                    return headers.copy()
                
                # 只返回未过期的请求头
                active_headers = {}
                for header_name, session_header in headers.items():
                    if not session_header.is_expired():
                        active_headers[header_name] = session_header
                
                return active_headers
        except Exception as e:
            logger.error(f"Failed to get session headers for {client_ip}: {e}")
            return {}

    def get_all_session_headers(self, client_ip: str) -> List[SessionHeader]:
        """获取指定客户端的所有会话性请求头（包括已过期的）"""
        try:
            with self._lock:
                if client_ip not in self._session_headers:
                    return []
                
                return list(self._session_headers[client_ip].values())
        except Exception as e:
            logger.error(f"Failed to get all session headers for {client_ip}: {e}")
            return []

    def remove_session_header(self, client_ip: str, header_name: str) -> bool:
        """删除指定的会话性请求头"""
        try:
            with self._lock:
                if client_ip in self._session_headers and header_name in self._session_headers[client_ip]:
                    del self._session_headers[client_ip][header_name]
                    logger.debug(f"Removed session header {header_name} for {client_ip}")
                    
                    # 如果该客户端没有任何请求头了，删除客户端条目
                    if not self._session_headers[client_ip]:
                        del self._session_headers[client_ip]
                    
                    # 同时从数据库中删除
                    try:
                        db = self._get_db()
                        if db is not None:
                            db.only_execute("""
                                DELETE FROM session_headers 
                                WHERE client_ip = ? AND header_name = ?
                            """, (client_ip, header_name))
                            logger.debug(f"Removed session header from database for {client_ip}: {header_name}")
                    except Exception as db_error:
                        logger.error(f"Failed to remove session header from database: {db_error}")
                    
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to remove session header {header_name} for {client_ip}: {e}")
            return False

    def clear_session_headers(self, client_ip: str) -> bool:
        """清除指定客户端的所有会话性请求头"""
        try:
            with self._lock:
                if client_ip in self._session_headers:
                    del self._session_headers[client_ip]
                    logger.debug(f"Cleared all session headers for {client_ip}")
                    
                    # 同时从数据库中清除
                    try:
                        db = self._get_db()
                        if db is not None:
                            db.only_execute("""
                                DELETE FROM session_headers 
                                WHERE client_ip = ?
                            """, (client_ip,))
                            logger.debug(f"Cleared all session headers from database for {client_ip}")
                    except Exception as db_error:
                        logger.error(f"Failed to clear session headers from database: {db_error}")
                    
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to clear session headers for {client_ip}: {e}")
            return False

    def cleanup_expired_headers(self) -> int:
        """清理所有已过期的会话性请求头"""
        removed_count = 0
        try:
            with self._lock:
                clients_to_remove = []
                
                for client_ip, headers in self._session_headers.items():
                    headers_to_remove = []
                    
                    for header_name, session_header in headers.items():
                        if session_header.is_expired():
                            headers_to_remove.append(header_name)
                    
                    # 删除过期的请求头
                    for header_name in headers_to_remove:
                        del headers[header_name]
                        removed_count += 1
                    
                    # 如果客户端没有任何请求头了，标记为删除
                    if not headers:
                        clients_to_remove.append(client_ip)
                
                # 删除没有请求头的客户端
                for client_ip in clients_to_remove:
                    del self._session_headers[client_ip]
                
                if removed_count > 0:
                    logger.debug(f"Cleaned up {removed_count} expired session headers from memory")
                
                # 同时从数据库中清理过期的请求头
                try:
                    db = self._get_db()
                    if db is not None:
                        # 获取当前时间
                        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        cursor = db.only_execute("""
                            DELETE FROM session_headers 
                            WHERE expires_at < ?
                        """, (current_time,))
                        db_removed_count = cursor.rowcount
                        if db_removed_count > 0:
                            logger.debug(f"Cleaned up {db_removed_count} expired session headers from database")
                except Exception as db_error:
                    logger.error(f"Failed to cleanup expired headers from database: {db_error}")
                
                return removed_count
        except Exception as e:
            logger.error(f"Failed to cleanup expired headers: {e}")
            return 0

    def get_client_count(self) -> int:
        """获取有会话性请求头的客户端数量"""
        with self._lock:
            return len(self._session_headers)

    def get_total_headers_count(self) -> int:
        """获取所有会话性请求头的总数量"""
        total_count = 0
        with self._lock:
            for headers in self._session_headers.values():
                total_count += len(headers)
        return total_count

    def get_active_headers_count(self) -> int:
        """获取所有活跃(未过期)会话性请求头的数量"""
        active_count = 0
        with self._lock:
            for headers in self._session_headers.values():
                for session_header in headers.values():
                    if not session_header.is_expired():
                        active_count += 1
        return active_count