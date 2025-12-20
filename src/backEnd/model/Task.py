import tempfile
import os
import sys
import random
from datetime import datetime
from urllib.parse import urlparse

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


# 默认临时文件目录（后端服务启动目录下的temp目录）
_DEFAULT_TEMP_DIR = os.path.join(os.getcwd(), "temp", "http_requests")
_custom_temp_dir = None  # 用户自定义的临时文件目录


def get_http_request_temp_dir():
    """获取HTTP请求临时文件目录"""
    global _custom_temp_dir
    if _custom_temp_dir:
        return _custom_temp_dir
    return _DEFAULT_TEMP_DIR


def set_http_request_temp_dir(path: str):
    """设置HTTP请求临时文件目录"""
    global _custom_temp_dir
    if path and path.strip():
        _custom_temp_dir = path.strip()
    else:
        _custom_temp_dir = None


def get_default_http_request_temp_dir():
    """获取默认的HTTP请求临时文件目录"""
    return _DEFAULT_TEMP_DIR


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
        self._request_file_path = None  # HTTP原始报文文件路径
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

    def _generate_request_file_name(self):
        """生成HTTP请求文件名: 日期时间 + 随机6位数字"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = random.randint(100000, 999999)
        return f"request_{timestamp}_{random_suffix}.txt"

    def _build_raw_http_request(self):
        """
        根据headers和body构建HTTP原始报文
        格式:
        POST /path HTTP/1.1
        Host: example.com
        Header1: Value1
        ...
        
        body_content
        """
        # 解析URL获取请求路径
        parsed_url = urlparse(self.scanUrl)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += "?" + parsed_url.query
        
        # 确定请求方法 (如果有body则为POST，否则为GET)
        method = "POST" if self.body else "GET"
        
        # 构建请求行
        request_line = f"{method} {path} HTTP/1.1"
        
        # 构建headers部分
        headers_list = []
        if self.headers:
            for header in self.headers:
                if header and ":" in header:
                    headers_list.append(header)
        
        # 确保Host头存在
        has_host = any(h.lower().startswith("host:") for h in headers_list)
        if not has_host and self.host:
            headers_list.insert(0, f"Host: {self.host}")
        elif not has_host:
            # 从URL提取host
            host = parsed_url.netloc or parsed_url.hostname
            if host:
                headers_list.insert(0, f"Host: {host}")
        
        # 组装完整报文
        raw_request = request_line + "\n"
        raw_request += "\n".join(headers_list)
        
        # 如果有body，添加空行和body
        if self.body:
            raw_request += "\n\n" + self.body
        else:
            raw_request += "\n\n"
        
        return raw_request

    def _create_request_file(self):
        """
        创建HTTP原始报文临时文件
        返回文件路径
        """
        # 获取临时文件目录
        temp_dir = get_http_request_temp_dir()
        
        # 确保目录存在
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir, exist_ok=True)
            logger.debug(f"[{self.taskid}] Created temp directory: {temp_dir}")
        
        # 生成文件名和完整路径
        file_name = self._generate_request_file_name()
        file_path = os.path.join(temp_dir, file_name)
        
        # 构建原始HTTP报文
        raw_request = self._build_raw_http_request()
        
        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(raw_request)
        
        logger.info(f"[{self.taskid}] Created HTTP request file: {file_path}")
        logger.debug(f"[{self.taskid}] HTTP request content:\n{raw_request}")
        
        return file_path

    def engine_start(self):
        logger.debug(f"[{self.taskid}] Starting engine with headers: {self.headers}")
        # 在SQLMap真正启动前应用请求头规则
        self.apply_header_rules()
        
        logger.debug(f"[{self.taskid}] Headers option for SQLMap: {getattr(self.options, 'headers', 'Not set')}")
        
        # 创建HTTP原始报文文件
        self._request_file_path = self._create_request_file()
        
        # 设置requestFile选项（使用-r参数）
        self.options.requestFile = self._request_file_path
        
        handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG,
                                              text=True)
        os.close(handle)
        saveConfig(self.options, configFile)
        
        logger.debug(f"[{self.taskid}] SQLMap config saved to {configFile}")
        logger.info(f"[{self.taskid}] Using request file mode (-r): {self._request_file_path}")

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
