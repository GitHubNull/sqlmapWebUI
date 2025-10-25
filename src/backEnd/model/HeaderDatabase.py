import sqlite3
import threading
import time
import os

from third_lib.sqlmap.lib.core.data import logger
from third_lib.sqlmap.lib.core.common import getSafeExString
from model.Database import Database


class HeaderDatabase(Database):
    """独立的请求头管理数据库"""
    
    def __init__(self, database_path=None):
        # 如果没有指定数据库路径，则使用程序所在目录下的headers.db文件
        if database_path is None:
            # 获取当前脚本所在目录
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # 确保是src目录的上一级目录
            project_dir = os.path.dirname(current_dir)
            database_path = os.path.join(project_dir, "headers.db")
        
        super().__init__(database_path)
        self.database_path = database_path
        
    def init(self):
        """初始化请求头管理数据库表"""
        # 创建持久化请求头规则表
        self.execute("""
            CREATE TABLE IF NOT EXISTS persistent_header_rules(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                header_name TEXT NOT NULL,
                header_value TEXT NOT NULL,
                replace_strategy TEXT NOT NULL DEFAULT 'REPLACE',
                match_condition TEXT,
                priority INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # 创建会话性请求头表
        self.execute("""
            CREATE TABLE IF NOT EXISTS session_headers(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT NOT NULL,
                header_name TEXT NOT NULL,
                header_value TEXT NOT NULL,
                priority INTEGER DEFAULT 0,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(client_ip, header_name)
            )
        """)
        
        # 创建索引以提高查询性能
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_active ON persistent_header_rules(is_active)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_priority ON persistent_header_rules(priority)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_name ON persistent_header_rules(header_name)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_session_headers_client_ip ON session_headers(client_ip)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_session_headers_expires ON session_headers(expires_at)")
        
        logger.info(f"Header database initialized at {self.database_path}")