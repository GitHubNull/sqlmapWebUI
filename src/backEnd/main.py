# import pdb
import sys
import tempfile
import os


def disable_windows_quick_edit():
    """
    禁用 Windows 控制台的 Quick Edit Mode。
    Quick Edit Mode 会导致点击控制台窗口时进程输出被暂停，
    必须按 Enter 才能恢复，这会导致后端服务卡住。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # STD_INPUT_HANDLE = -10
        handle = kernel32.GetStdHandle(-10)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # ENABLE_QUICK_EDIT_MODE = 0x0040
            # ENABLE_EXTENDED_FLAGS = 0x0080 (必须设置才能修改 Quick Edit)
            mode.value &= ~0x0040  # 禁用 Quick Edit
            mode.value |= 0x0080   # 启用 Extended Flags
            kernel32.SetConsoleMode(handle, mode)
            print("[INFO] Windows Quick Edit Mode 已禁用，控制台点击不会再暂停进程")
    except Exception as e:
        print(f"[WARNING] 无法禁用 Quick Edit Mode: {e}")


# 在服务启动前禁用 Windows Quick Edit Mode
disable_windows_quick_edit()

# 配置 Python 模块导入路径 - 必须在所有项目模块导入之前完成
current_dir = os.path.dirname(os.path.abspath(__file__))
sqlmap_path = os.path.join(current_dir, "third_lib", "sqlmap")

# 将路径添加到 sys.path 最前面,确保优先级最高
if sqlmap_path not in sys.path:
    sys.path.insert(0, sqlmap_path)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# 现在才能安全地导入项目模块
from app import app
from utils.task_monitor import monitor

sys.dont_write_bytecode = True

__import__("third_lib.sqlmap.lib.utils.versioncheck")  # this has to be the first non-standard import
import logging
# import os
import warnings

warnings.filterwarnings(action="ignore", category=UserWarning)
warnings.filterwarnings(action="ignore", category=DeprecationWarning)

try:
    from optparse import OptionGroup
    from optparse import OptionParser as ArgumentParser

    ArgumentParser.add_argument = ArgumentParser.add_option

    def _add_argument(self, *args, **kwargs):
        return self.add_option(*args, **kwargs)

    OptionGroup.add_argument = _add_argument

except ImportError:
    from argparse import ArgumentParser

finally:
    def get_actions(instance):
        for attr in ("option_list", "_group_actions", "_actions"):
            if hasattr(instance, attr):
                return getattr(instance, attr)

    def get_groups(parser):
        return getattr(parser, "option_groups", None) or getattr(parser, "_action_groups")

    def get_all_options(parser):
        retVal = set()

        for option in get_actions(parser):
            if hasattr(option, "option_strings"):
                retVal.update(option.option_strings)
            else:
                retVal.update(option._long_opts)
                retVal.update(option._short_opts)

        for group in get_groups(parser):
            for option in get_actions(group):
                if hasattr(option, "option_strings"):
                    retVal.update(option.option_strings)
                else:
                    retVal.update(option._long_opts)
                    retVal.update(option._short_opts)

        return retVal

# from third_lib.sqlmap.lib.core.convert import getUnicode
# from third_lib.sqlmap.lib.core.common import setPaths
# from third_lib.sqlmap.lib.core.convert import encodeHex
# from third_lib.sqlmap.lib.core.data import logger
# from third_lib.sqlmap.lib.core.patch import dirtyPatches
# from third_lib.sqlmap.lib.core.patch import resolveCrossReferences
# from third_lib.sqlmap.lib.core.settings import UNICODE_ENCODING
# from third_lib.sqlmap.lib.core.enums import MKSTEMP_PREFIX

from third_lib.sqlmap.lib.core.convert import getUnicode
from third_lib.sqlmap.lib.core.common import setPaths
from third_lib.sqlmap.lib.core.convert import encodeHex
from third_lib.sqlmap.lib.core.data import logger
from third_lib.sqlmap.lib.core.patch import dirtyPatches
from third_lib.sqlmap.lib.core.patch import resolveCrossReferences
from third_lib.sqlmap.lib.core.settings import UNICODE_ENCODING
from third_lib.sqlmap.lib.core.enums import MKSTEMP_PREFIX

try:
    from third_lib.sqlmap.sqlmap import modulePath
except ImportError:
    def modulePath():
        return getUnicode(os.path.dirname(os.path.realpath(__file__)), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

from model.Database import Database
from model.DataStore import DataStore
from model.HeaderDatabase import HeaderDatabase
from model.ScanPresetDatabase import get_scan_preset_db
# from model.DataStore import data_store

FORMATTER = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(module)s] [%(filename)s] [Line: %(lineno)d] %(message)s", "%Y-%m-%d %H:%M:%S")
for handler in logger.handlers:
    handler.setFormatter(FORMATTER)

import uvicorn
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.schedulers.background import BackgroundScheduler

# 确保 DataStore.admin_token 是 str 类型
def generate_admin_token():
    token = encodeHex(os.urandom(16), binary=False)
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token

def main(username, password):
    logger.info("Starting sqlmap API server...")
    try:
        # pdb.set_trace()
        dirtyPatches()
        resolveCrossReferences()

        # Set default logging level to debug
        logger.setLevel(logging.DEBUG)

        # Initialize paths
        setPaths(modulePath())

        global_admin_token = generate_admin_token()
        global_username = username
        global_password = password

        # 创建 sqlite_dbs 目录（所有数据库文件统一存放）
        sqlite_dbs_dir = os.path.join(current_dir, "sqlite_dbs")
        os.makedirs(sqlite_dbs_dir, exist_ok=True)
        logger.info(f"[*] SQLite database directory: {sqlite_dbs_dir}")

        # Initialize IPC database (固定存储到 sqlite_dbs 目录)
        Database.filepath = os.path.join(sqlite_dbs_dir, f"{MKSTEMP_PREFIX.IPC}ipc.db")
        DataStore.current_db = Database()
        logger.info(f"id(DataStore.current_db): {id(DataStore.current_db)}")
        DataStore.current_db.connect()
        DataStore.current_db.init()
        logger.info("[*] IPC database initialized")
        
        # Initialize Header database (存储到 sqlite_dbs 目录)
        header_db_path = os.path.join(sqlite_dbs_dir, "headers.db")
        DataStore.header_db = HeaderDatabase(database_path=header_db_path)
        DataStore.header_db.connect()
        DataStore.header_db.init()
        logger.info("[*] Header database initialized")
        
        # Initialize Scan Preset database (存储到 sqlite_dbs 目录)
        scan_preset_db_path = os.path.join(sqlite_dbs_dir, "scan_presets.db")
        DataStore.scan_preset_db = get_scan_preset_db(database_path=scan_preset_db_path)
        logger.info("[*] Scan preset database initialized")

        scheduler = BackgroundScheduler()
        scheduler.add_job(monitor, 'interval', seconds=3)  # 每10秒执行一次
        scheduler.start()
        logger.info("[*] Scheduler started")

        uvicorn.run(app=app, host="127.0.0.1", port=8775, reload=False, log_config='./uvicorn_config.json')
    except Exception as e:
        import traceback
        print(f"\n[ERROR] 服务启动失败: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    username = "admin"
    password = "admin"
    main(username=username, password=password)