import sqlite3
import threading
import time

from third_lib.sqlmap.lib.core.data import logger
from third_lib.sqlmap.lib.core.common import getSafeExString


# API objects
class Database(object):
    filepath = None

    def __init__(self, database=None):
        self.database = self.filepath if database is None else database
        self.connection = None
        self.cursor = None

    def connect(self, who="server"):
        self.connection = sqlite3.connect(
            self.database, timeout=3, isolation_level=None, check_same_thread=False)
        self.cursor = self.connection.cursor()
        self.lock = threading.Lock()
        logger.debug("REST-JSON API %s connected to IPC database" % who)

    def disconnect(self):
        if self.cursor:
            self.cursor.close()

        if self.connection:
            self.connection.close()

    def commit(self):
        self.connection.commit()

    def execute(self, statement, arguments=None):
        with self.lock:
            while True:
                try:
                    if arguments:
                        self.cursor.execute(statement, arguments)
                    else:
                        self.cursor.execute(statement)
                except sqlite3.OperationalError as ex:
                    if "locked" not in getSafeExString(ex):
                        raise
                    else:
                        time.sleep(1)
                else:
                    break

        if statement.lstrip().upper().startswith("SELECT"):
            return self.cursor.fetchall()

    def only_execute(self, statement, arguments=None):
        with self.lock:
            while True:
                try:
                    if arguments:
                        self.cursor.execute(statement, arguments)
                    else:
                        self.cursor.execute(statement)
                except sqlite3.OperationalError as ex:
                    if "locked" not in getSafeExString(ex):
                        raise
                    else:
                        time.sleep(1)
                else:
                    break

        return self.cursor

    def init(self):
        self.execute(
            "CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, datetime TEXT, level TEXT, message TEXT)")
        self.execute(
            "CREATE TABLE data(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, status INTEGER, content_type INTEGER, value TEXT)")
        self.execute(
            "CREATE TABLE errors(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, error TEXT)")
        
        # 创建持久化请求头规则表
        self.execute("""
            CREATE TABLE IF NOT EXISTS persistent_header_rules(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
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
        
        # 创建索引以提高查询性能
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_active ON persistent_header_rules(is_active)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_priority ON persistent_header_rules(priority)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_header_rules_name ON persistent_header_rules(header_name)")