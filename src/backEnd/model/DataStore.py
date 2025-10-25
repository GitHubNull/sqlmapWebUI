import threading
from collections import OrderedDict
from typing import Optional
from model.Database import Database
from model.HeaderDatabase import HeaderDatabase


# Global data storage
class DataStore(object):
    admin_token: str = ""
    current_db: Optional[Database] = None
    header_db: Optional[HeaderDatabase] = None
    tasks_lock = threading.Lock()
    tasks = OrderedDict()
    username: str = ""
    password: str = ""
    first_checkin_monitor: bool = True
    max_tasks_count: int = 3
    max_tasks_count_lock = threading.Lock()
    
    # 会话性请求头管理器（单例模式）
    session_header_manager = None
    session_header_manager_lock = threading.Lock()
    
    @classmethod
    def get_session_header_manager(cls):
        """获取会话性请求头管理器单例"""
        if cls.session_header_manager is None:
            with cls.session_header_manager_lock:
                if cls.session_header_manager is None:
                    from utils.session_header_manager import SessionHeaderManager
                    cls.session_header_manager = SessionHeaderManager()
        return cls.session_header_manager
