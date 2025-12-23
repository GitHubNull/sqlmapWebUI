import threading
from collections import OrderedDict
from typing import Optional, TYPE_CHECKING
from model.Database import Database
from model.HeaderDatabase import HeaderDatabase

if TYPE_CHECKING:
    from model.ScanPresetDatabase import ScanPresetDatabase


# Global data storage
class DataStore(object):
    admin_token: str = ""
    current_db: Optional[Database] = None
    header_db: Optional[HeaderDatabase] = None
    scan_preset_db: Optional["ScanPresetDatabase"] = None
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
    
    # 会话Body字段管理器（单例模式）
    _session_body_field_manager: Optional['SessionBodyFieldManager'] = None
    _session_body_field_manager_lock = threading.Lock()
    
    @classmethod
    def get_session_header_manager(cls):
        """获取会话性请求头管理器单例"""
        if cls.session_header_manager is None:
            with cls.session_header_manager_lock:
                if cls.session_header_manager is None:
                    from utils.session_header_manager import SessionHeaderManager
                    cls.session_header_manager = SessionHeaderManager()
        return cls.session_header_manager
    
    @classmethod
    def get_session_body_field_manager(cls) -> Optional['SessionBodyFieldManager']:
        """获取会话Body字段管理器单例"""
        if cls._session_body_field_manager is None:
            with cls._session_body_field_manager_lock:
                if cls._session_body_field_manager is None:
                    from utils.session_body_field_manager import SessionBodyFieldManager
                    cls._session_body_field_manager = SessionBodyFieldManager()
        return cls._session_body_field_manager
