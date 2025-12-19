import tempfile
import os
import sys
from datetime import datetime

from third_lib.sqlmap.lib.core.datatype import AttribDict
from third_lib.sqlmap.lib.core.optiondict import optDict
from third_lib.sqlmap.lib.core.common import unArrayizeValue
from third_lib.sqlmap.lib.core.defaults import _defaults
from third_lib.sqlmap.lib.core.enums import MKSTEMP_PREFIX
from third_lib.sqlmap.lib.core.common import saveConfig
from third_lib.sqlmap.lib.core.subprocessng import Popen
from third_lib.sqlmap.lib.core.settings import IS_WIN
from third_lib.sqlmap.lib.core.data import logger

from model.TaskStatus import TaskStatus
from model.Database import Database


class Task(object):
    def __init__(self, taskid, remote_addr, scanUrl, host, headers, body):
        self.status = TaskStatus.New
        self.create_datetime = datetime.now()  # 任务创建时间 (New状态)
        self.start_datetime = None  # 任务开始执行时间 (Running状态)
        self.taskid = taskid
        self.scanUrl = scanUrl
        self.host = host
        self.headers = headers
        self.body = body
        self.remote_addr = remote_addr
        self.process = None
        self.output_directory = None
        self.options = None
        self._original_options = None
        self._header_rules_applied = False  # 标记是否已应用请求头规则
        self.initialize_options(taskid)
        
        logger.debug(f"[{self.taskid}] Task initialized with {len(self.headers) if self.headers else 0} headers")
        
        # 在任务创建时就处理请求头，确保请求头规则立即生效
        self.apply_header_rules()
        
        logger.debug(f"[{self.taskid}] Task initialization completed")

    def initialize_options(self, taskid):
        datatype = {"boolean": False, "string": None, "integer": None, "float": None}
        self.options = AttribDict()

        for _ in optDict:
            for name, type_ in optDict[_].items():
                type_ = unArrayizeValue(type_)
                self.options[name] = _defaults.get(name, datatype[type_])  # type: ignore

        # Let sqlmap engine knows it is getting called by the API,
        # the task ID and the file path of the IPC database
        self.options.api = True
        self.options.taskid = taskid
        self.options.database = Database.filepath

        # Enforce batch mode and disable coloring and ETA
        self.options.batch = True
        self.options.disableColoring = True
        self.options.eta = False

        self._original_options = AttribDict(self.options)

    def set_option(self, option, value):
        self.options[option] = value  # type: ignore

    def get_option(self, option):
        return self.options[option]  # type: ignore

    def get_options(self):
        return self.options

    def reset_options(self):
        self.options = AttribDict(self._original_options)

    def apply_header_rules(self):
        """在SQLMap扫描启动前应用请求头规则"""
        # 检查是否已经应用过请求头规则，避免重复处理
        if self._header_rules_applied:
            logger.debug(f"[{self.taskid}] Header rules already applied, skipping")
            return
            
        try:
            logger.debug(f"[{self.taskid}] Starting header rules application")
            if not self.headers:
                logger.debug(f"[{self.taskid}] No headers to process")
                self._header_rules_applied = True
                return
            
            # 动态导入避免循环引用
            from service.headerRuleService import HeaderRuleService
            from utils.header_processor import HeaderProcessor
            from model.DataStore import DataStore
            
            logger.debug(f"[{self.taskid}] Importing header service and processor")
            
            logger.debug(f"[{self.taskid}] Applying header rules to {len(self.headers)} headers")
            
            # 获取服务实例
            header_service = HeaderRuleService()
            
            logger.debug(f"[{self.taskid}] Getting active persistent rules")
            # 获取持久化规则
            persistent_rules = header_service.get_active_persistent_rules_for_processing()
            logger.debug(f"[{self.taskid}] Got {len(persistent_rules)} persistent rules")
            
            # 获取会话性请求头
            session_manager = DataStore.get_session_header_manager()
            logger.debug(f"[{self.taskid}] Getting session headers for {self.remote_addr}")
            session_headers = session_manager.get_session_headers(self.remote_addr, active_only=True)
            logger.debug(f"[{self.taskid}] Got {len(session_headers)} session headers")
            
            # 处理请求头
            logger.debug(f"[{self.taskid}] Processing headers with {len(self.headers)} original headers")
            processed_headers, applied_rules = HeaderProcessor.process_headers(
                self.headers, persistent_rules, session_headers
            )
            logger.debug(f"[{self.taskid}] Processed headers: {len(processed_headers)}, Applied rules: {len(applied_rules)}")
            
            # 更新请求头
            if processed_headers != self.headers:
                self.headers = processed_headers
                # 将处理后的请求头设置到SQLMap配置中
                # SQLMap期望headers是一个换行符分隔的字符串
                self.options.headers = "\n".join(processed_headers)
                logger.info(f"[{self.taskid}] Applied {len(applied_rules)} header rules: {', '.join(applied_rules)}")
                logger.debug(f"[{self.taskid}] Set headers option for SQLMap: {self.options.headers}")
            else:
                logger.debug(f"[{self.taskid}] No header changes applied")
                
            # 标记请求头规则已应用
            self._header_rules_applied = True
                
        except Exception as e:
            logger.error(f"[{self.taskid}] Failed to apply header rules: {e}")
            # 如果应用规则失败，保持原始请求头不变

    def engine_start(self):
        logger.debug(f"[{self.taskid}] Starting engine with headers: {self.headers}")
        # 在SQLMap真正启动前应用请求头规则
        self.apply_header_rules()
        
        logger.debug(f"[{self.taskid}] Headers option for SQLMap: {getattr(self.options, 'headers', 'Not set')}")
        
        handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG,
                                              text=True)
        os.close(handle)
        saveConfig(self.options, configFile)
        
        logger.debug(f"[{self.taskid}] SQLMap config saved to {configFile}")

        if os.path.exists("third_lib/sqlmap/sqlmap.py"):
            self.process = Popen([sys.executable or "python", "third_lib/sqlmap/sqlmap.py",
                                  "--api",
                                  "-c", configFile], shell=False,
                                 close_fds=not IS_WIN)
        elif os.path.exists(os.path.join(os.getcwd(), "sqlmap.py")):
            self.process = Popen([sys.executable or "python", "sqlmap.py",
                                  "--api", "-c", configFile], shell=False,
                                 cwd=os.getcwd(),
                                 close_fds=not IS_WIN)
        elif os.path.exists(os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "sqlmap.py")):
            self.process = Popen([sys.executable or "python", "sqlmap.py",
                                  "--api", "-c", configFile], shell=False,
                                 cwd=os.path.join(
                                 os.path.abspath(os.path.dirname(sys.argv[0]))), close_fds=not IS_WIN)
        else:
            self.process = Popen(["sqlmap", "--api", "-c", configFile],
                                 shell=False, close_fds=not IS_WIN)

    def engine_stop(self):
        if self.process:
            self.process.terminate()
            return self.process.wait()
        else:
            return None

    def engine_process(self):
        return self.process

    def engine_kill(self):
        if self.process:
            try:
                self.process.kill()
                return self.process.wait()
            except Exception as e:
                logger.debug(e)
                return None
        return None

    def engine_get_id(self):
        if self.process:
            return self.process.pid
        else:
            return None

    def engine_get_returncode(self):
        if self.process:
            self.process.poll()
            return self.process.returncode
        else:
            return None

    def engine_has_terminated(self):
        return isinstance(self.engine_get_returncode(), int)
