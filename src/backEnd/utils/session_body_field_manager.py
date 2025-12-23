"""
SessionBodyFieldManager - 会话Body字段管理器

管理会话Body字段规则的生命周期，包括创建、读取、更新、删除、过期清理等。
"""

import threading
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

from model.SessionBodyField import (
    SessionBodyField, 
    SessionBodyFieldCreate, 
    SessionBodyFieldUpdate,
    MatchStrategy,
    ReplaceStrategy
)
from model.DataStore import DataStore

# 使用标准库的logging模块
import logging
logger = logging.getLogger(__name__)


class SessionBodyFieldManager:
    """会话Body字段管理器 - 内存存储临时会话Body字段"""
    
    def __init__(self):
        # {client_ip: {field_name: SessionBodyField}}
        self._session_body_fields: Dict[str, Dict[str, SessionBodyField]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._id_counter = 1  # ID计数器
        logger.debug("SessionBodyFieldManager initialized")
        
    def _get_db(self):
        """获取请求头数据库连接"""
        return DataStore.header_db
    
    def _generate_id(self) -> int:
        """生成唯一ID"""
        self._id_counter += 1
        return self._id_counter

    def set_session_body_field(self, client_ip: str, field_create: SessionBodyFieldCreate) -> bool:
        """设置会话Body字段"""
        try:
            with self._lock:
                expires_at = datetime.now() + timedelta(seconds=field_create.ttl)
                current_time = datetime.now()
                
                # 检查是否已存在，如果存在则复用ID
                existing_field = None
                if client_ip in self._session_body_fields and field_create.field_name in self._session_body_fields[client_ip]:
                    existing_field = self._session_body_fields[client_ip][field_create.field_name]
                
                field_id = existing_field.id if existing_field and existing_field.id else self._generate_id()
                
                # 处理scope字段
                scope = field_create.scope
                
                session_field = SessionBodyField(
                    id=field_id,
                    field_name=field_create.field_name,
                    field_value=field_create.field_value,
                    match_strategy=field_create.match_strategy,
                    match_pattern=field_create.match_pattern,
                    replace_strategy=field_create.replace_strategy,
                    content_types=field_create.content_types,
                    priority=field_create.priority,
                    is_active=field_create.is_active,
                    expires_at=expires_at,
                    created_at=existing_field.created_at if existing_field else current_time,
                    updated_at=current_time if existing_field else None,
                    source_ip=client_ip,
                    scope=scope
                )
                
                # 如果客户端IP不存在，创建新的字典
                if client_ip not in self._session_body_fields:
                    self._session_body_fields[client_ip] = {}
                
                # 设置或更新字段
                self._session_body_fields[client_ip][field_create.field_name] = session_field
                
                # 序列化scope配置和content_types
                scope_config_json = None
                if scope is not None:
                    scope_config_json = json.dumps(scope.to_dict(), ensure_ascii=False)
                
                content_types_json = None
                if field_create.content_types:
                    content_types_json = json.dumps(field_create.content_types, ensure_ascii=False)
                
                # 持久化到数据库
                try:
                    db = self._get_db()
                    if db is not None:
                        # 尝试更新现有记录
                        cursor = db.only_execute("""
                            UPDATE session_body_fields 
                            SET field_value = ?, match_strategy = ?, match_pattern = ?, 
                                replace_strategy = ?, content_types = ?, priority = ?, 
                                is_active = ?, expires_at = ?, updated_at = ?, scope_config = ?
                            WHERE client_ip = ? AND field_name = ?
                        """, (
                            field_create.field_value,
                            field_create.match_strategy.value,
                            field_create.match_pattern,
                            field_create.replace_strategy.value,
                            content_types_json,
                            field_create.priority,
                            1 if field_create.is_active else 0,
                            expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                            current_time.strftime('%Y-%m-%d %H:%M:%S'),
                            scope_config_json,
                            client_ip,
                            field_create.field_name
                        ))
                        
                        # 如果没有更新任何记录，则插入新记录
                        if cursor.rowcount == 0:
                            insert_cursor = db.only_execute("""
                                INSERT INTO session_body_fields 
                                (client_ip, field_name, field_value, match_strategy, match_pattern,
                                 replace_strategy, content_types, priority, is_active, 
                                 expires_at, created_at, scope_config)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                client_ip,
                                field_create.field_name,
                                field_create.field_value,
                                field_create.match_strategy.value,
                                field_create.match_pattern,
                                field_create.replace_strategy.value,
                                content_types_json,
                                field_create.priority,
                                1 if field_create.is_active else 0,
                                expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                                current_time.strftime('%Y-%m-%d %H:%M:%S'),
                                scope_config_json
                            ))
                            # 获取数据库生成的真实ID并更新内存对象
                            if insert_cursor and insert_cursor.lastrowid:
                                session_field.id = insert_cursor.lastrowid
                                self._session_body_fields[client_ip][field_create.field_name] = session_field
                        else:
                            # 更新时也需要获取数据库中的ID
                            id_cursor = db.only_execute("""
                                SELECT id FROM session_body_fields WHERE client_ip = ? AND field_name = ?
                            """, (client_ip, field_create.field_name))
                            if id_cursor:
                                row = id_cursor.fetchone()
                                if row:
                                    session_field.id = row[0]
                                    self._session_body_fields[client_ip][field_create.field_name] = session_field
                        logger.debug(f"Persisted session body field to database for {client_ip}: {field_create.field_name}")
                except Exception as db_error:
                    logger.error(f"Failed to persist session body field to database: {db_error}")
                
                logger.debug(f"Set session body field for {client_ip}: {field_create.field_name}")
                return True
        except Exception as e:
            logger.error(f"Failed to set session body field: {e}")
            return False

    def set_session_body_fields_batch(self, client_ip: str, fields: List[SessionBodyFieldCreate]) -> int:
        """批量设置会话Body字段"""
        success_count = 0
        for field_create in fields:
            if self.set_session_body_field(client_ip, field_create):
                success_count += 1
        
        logger.debug(f"Set {success_count}/{len(fields)} session body fields for {client_ip}")
        return success_count

    def get_session_body_fields(self, client_ip: str, active_only: bool = True) -> Dict[str, SessionBodyField]:
        """获取指定客户端的会话Body字段"""
        try:
            with self._lock:
                if client_ip not in self._session_body_fields:
                    return {}
                
                fields = self._session_body_fields[client_ip]
                if not active_only:
                    return fields.copy()
                
                # 只返回未过期且启用的字段
                active_fields = {}
                for field_name, session_field in fields.items():
                    if not session_field.is_expired() and session_field.is_active:
                        active_fields[field_name] = session_field
                
                return active_fields
        except Exception as e:
            logger.error(f"Failed to get session body fields for {client_ip}: {e}")
            return {}

    def get_all_session_body_fields(self, client_ip: str) -> List[SessionBodyField]:
        """获取指定客户端的所有会话Body字段（包括已过期的）"""
        try:
            with self._lock:
                if client_ip not in self._session_body_fields:
                    return []
                
                return list(self._session_body_fields[client_ip].values())
        except Exception as e:
            logger.error(f"Failed to get all session body fields for {client_ip}: {e}")
            return []

    def remove_session_body_field(self, client_ip: str, field_name: str) -> bool:
        """删除指定的会话Body字段"""
        try:
            with self._lock:
                if client_ip in self._session_body_fields and field_name in self._session_body_fields[client_ip]:
                    del self._session_body_fields[client_ip][field_name]
                    logger.debug(f"Removed session body field {field_name} for {client_ip}")
                    
                    # 如果该客户端没有任何字段了，删除客户端条目
                    if not self._session_body_fields[client_ip]:
                        del self._session_body_fields[client_ip]
                    
                    # 同时从数据库中删除
                    try:
                        db = self._get_db()
                        if db is not None:
                            db.only_execute("""
                                DELETE FROM session_body_fields 
                                WHERE client_ip = ? AND field_name = ?
                            """, (client_ip, field_name))
                            logger.debug(f"Removed session body field from database for {client_ip}: {field_name}")
                    except Exception as db_error:
                        logger.error(f"Failed to remove session body field from database: {db_error}")
                    
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to remove session body field {field_name} for {client_ip}: {e}")
            return False

    def clear_session_body_fields(self, client_ip: str) -> bool:
        """清除指定客户端的所有会话Body字段"""
        try:
            with self._lock:
                if client_ip in self._session_body_fields:
                    del self._session_body_fields[client_ip]
                    logger.debug(f"Cleared all session body fields for {client_ip}")
                    
                    # 同时从数据库中清除
                    try:
                        db = self._get_db()
                        if db is not None:
                            db.only_execute("""
                                DELETE FROM session_body_fields 
                                WHERE client_ip = ?
                            """, (client_ip,))
                            logger.debug(f"Cleared all session body fields from database for {client_ip}")
                    except Exception as db_error:
                        logger.error(f"Failed to clear session body fields from database: {db_error}")
                    
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to clear session body fields for {client_ip}: {e}")
            return False

    def update_session_body_field(self, client_ip: str, field_name: str, field_update: SessionBodyFieldUpdate) -> bool:
        """更新会话Body字段"""
        try:
            # 创建一个新的SessionBodyFieldCreate对象用于更新
            field_create = SessionBodyFieldCreate(
                field_name=field_update.field_name,
                field_value=field_update.field_value,
                match_strategy=field_update.match_strategy,
                match_pattern=field_update.match_pattern,
                replace_strategy=field_update.replace_strategy,
                content_types=field_update.content_types,
                priority=field_update.priority,
                is_active=field_update.is_active,
                ttl=field_update.ttl,
                scope=field_update.scope
            )
            return self.set_session_body_field(client_ip, field_create)
        except Exception as e:
            logger.error(f"Failed to update session body field {field_name} for {client_ip}: {e}")
            return False

    def cleanup_expired_fields(self) -> int:
        """清理所有已过期的会话Body字段"""
        removed_count = 0
        try:
            with self._lock:
                clients_to_remove = []
                
                for client_ip, fields in self._session_body_fields.items():
                    fields_to_remove = []
                    
                    for field_name, session_field in fields.items():
                        if session_field.is_expired():
                            fields_to_remove.append(field_name)
                    
                    # 删除过期的字段
                    for field_name in fields_to_remove:
                        del fields[field_name]
                        removed_count += 1
                    
                    # 如果客户端没有任何字段了，标记为删除
                    if not fields:
                        clients_to_remove.append(client_ip)
                
                # 删除没有字段的客户端
                for client_ip in clients_to_remove:
                    del self._session_body_fields[client_ip]
                
                if removed_count > 0:
                    logger.debug(f"Cleaned up {removed_count} expired session body fields from memory")
                
                # 同时从数据库中清理过期的字段
                try:
                    db = self._get_db()
                    if db is not None:
                        # 获取当前时间
                        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        cursor = db.only_execute("""
                            DELETE FROM session_body_fields 
                            WHERE expires_at < ?
                        """, (current_time,))
                        db_removed_count = cursor.rowcount
                        if db_removed_count > 0:
                            logger.debug(f"Cleaned up {db_removed_count} expired session body fields from database")
                except Exception as db_error:
                    logger.error(f"Failed to cleanup expired fields from database: {db_error}")
                
                return removed_count
        except Exception as e:
            logger.error(f"Failed to cleanup expired fields: {e}")
            return 0

    def get_client_count(self) -> int:
        """获取有会话Body字段的客户端数量"""
        with self._lock:
            return len(self._session_body_fields)

    def get_total_fields_count(self) -> int:
        """获取所有会话Body字段的总数量"""
        total_count = 0
        with self._lock:
            for fields in self._session_body_fields.values():
                total_count += len(fields)
        return total_count

    def get_active_fields_count(self) -> int:
        """获取所有活跃(未过期且启用)会话Body字段的数量"""
        active_count = 0
        with self._lock:
            for fields in self._session_body_fields.values():
                for session_field in fields.values():
                    if not session_field.is_expired() and session_field.is_active:
                        active_count += 1
        return active_count
