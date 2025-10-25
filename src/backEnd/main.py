# import pdb
import sys
import tempfile
import os

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

        _, Database.filepath = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.IPC, text=False)
        os.close(_)

        # Initialize IPC database
        # pdb.set_trace()
        DataStore.current_db = Database()
        logger.info(f"id(DataStore.current_db): {id(DataStore.current_db)}")
        DataStore.current_db.connect()
        DataStore.current_db.init()
        logger.info("[*] IPC database initialized")

        scheduler = BackgroundScheduler()
        scheduler.add_job(monitor, 'interval', seconds=3)  # 每10秒执行一次
        scheduler.start()
        logger.info("[*] Scheduler started")

        uvicorn.run(app=app, host="127.0.0.1", port=8775, reload=False, log_config='./uvicorn_config.json')
    except Exception as e:
        print(e)

if __name__ == "__main__":
    username = "admin"
    password = "admin"
    main(username=username, password=password)