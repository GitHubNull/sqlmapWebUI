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
                scope_config TEXT DEFAULT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # 检查并添加scope_config列（如果表已存在但没有该列）
        self._add_column_if_not_exists(
            'persistent_header_rules', 
            'scope_config', 
            'TEXT DEFAULT NULL'
        )
        
        # 创建会话性请求头表
        self.execute("""
            CREATE TABLE IF NOT EXISTS session_headers(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT NOT NULL,
                header_name TEXT NOT NULL,
                header_value TEXT NOT NULL,
                priority INTEGER DEFAULT 0,
                scope_config TEXT DEFAULT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(client_ip, header_name)
            )
        """)
        
        # 检查并添加scope_config列（如果表已存在但没有该列）
        self._add_column_if_not_exists(
            'session_headers', 
            'scope_config', 
            'TEXT DEFAULT NULL'
        )
        
        # 创建索引以提高查询性能
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_active ON persistent_header_rules(is_active)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_priority ON persistent_header_rules(priority)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_name ON persistent_header_rules(header_name)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_session_headers_client_ip ON session_headers(client_ip)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_session_headers_expires ON session_headers(expires_at)")
        
        logger.info(f"Header database initialized at {self.database_path}")
    
    def _add_column_if_not_exists(self, table_name: str, column_name: str, column_definition: str):
        """
        检查并添加列（如果不存在）
        
        参数:
            table_name: 表名
            column_name: 列名
            column_definition: 列定义（包含类型和默认值）
        """
        try:
            # 查询表结构
            result = self.only_execute(f"PRAGMA table_info({table_name})")
            if result:
                columns = [row[1] for row in result.fetchall()]
            else:
                columns = []
            
            # 如果列不存在，添加它
            if column_name not in columns:
                logger.info(f"添加列 {column_name} 到表 {table_name}")
                self.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
                logger.info(f"列 {column_name} 添加成功")
        except Exception as e:
            logger.warning(f"添加列 {column_name} 失败: {getSafeExString(e)}")