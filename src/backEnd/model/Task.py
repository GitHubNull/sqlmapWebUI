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
    def __init__(self, taskid, remote_addr, scanUrl, host, method, headers, body):
        self.status = TaskStatus.New
        self.create_datetime = datetime.now()  # 任务创建时间 (New状态)
        self.start_datetime = None  # 任务开始执行时间 (Running状态)
        self.taskid = taskid
        self.scanUrl = scanUrl
        self.host = host
        self.method = method
        self.headers = headers
        self.body = body
        self.remote_addr = remote_addr
        self.process = None
        self.output_directory = None
        self.options = None
        self._original_options = None
        self._user_set_options = set()  # 跟踪用户显式设置的参数
        self._header_rules_applied = False  # 标记是否已应用请求头规则
        self._body_field_rules_applied = False  # 标记是否已应用Body字段规则
        self._request_file_path = None  # HTTP原始报文文件路径
        self.initialize_options(taskid)
        
        logger.debug(f"[{self.taskid}] Task initialized with {len(self.headers) if self.headers else 0} headers")
        
        # 注意：不在这里调用 apply_header_rules()
        # 因为此时 randomAgent 等参数还未设置
        # apply_header_rules() 会在 engine_start() 中被调用
        
        logger.debug(f"[{self.taskid}] Task initialization completed")

    
    def __str__(self):
        return f"Task(taskid={self.taskid}, status={self.status}, create_datetime={self.create_datetime}, start_datetime={self.start_datetime}, scanUrl={self.scanUrl}, host={self.host}, method={self.method}, headers={self.headers}, body={self.body}, remote_addr={self.remote_addr}, process={self.process}, output_directory={self.output_directory}, options={self.options}, _original_options={self._original_options}, _user_set_options={self._user_set_options}, _header_rules_applied={self._header_rules_applied}, _body_field_rules_applied={self._body_field_rules_applied}, _request_file_path={self._request_file_path})"

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
        self._user_set_options.add(option)  # 记录用户显式设置的参数

    def get_option(self, option):
        return self.options[option]  # type: ignore

    def get_options(self):
        return self.options

    def get_user_set_options(self):
        """获取用户显式设置的参数名集合"""
        return self._user_set_options

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
                self.headers, persistent_rules, session_headers, self.scanUrl
            )
            logger.debug(f"[{self.taskid}] Processed headers: {len(processed_headers)}, Applied rules: {len(applied_rules)}")
            
            # 更新请求头
            if processed_headers != self.headers:
                self.headers = processed_headers
                
            # 如果启用了randomAgent，从headers中移除User-Agent
            # 这样SQLMap的_setHTTPUserAgent()会添加随机UA
            logger.debug(f"[{self.taskid}] Checking randomAgent: {self.options.randomAgent}")
            if self.options.randomAgent:
                original_count = len(self.headers)
                self.headers = [h for h in self.headers 
                               if not h.lower().startswith("user-agent:")]
                if len(self.headers) < original_count:
                    logger.info(f"[{self.taskid}] Removed User-Agent from headers due to randomAgent=True")
                else:
                    logger.debug(f"[{self.taskid}] No User-Agent header found to remove")
            
            # 将请求头设置到SQLMap配置中
            # SQLMap期望headers是一个换行符分隔的字符串
            self.options.headers = "\n".join(self.headers)
            
            if applied_rules:
                logger.info(f"[{self.taskid}] Applied {len(applied_rules)} header rules: {', '.join(applied_rules)}")
            logger.debug(f"[{self.taskid}] Set headers option for SQLMap: {self.options.headers}")
                
            # 标记请求头规则已应用
            self._header_rules_applied = True
                
        except Exception as e:
            logger.error(f"[{self.taskid}] Failed to apply header rules: {e}")
            # 如果应用规则失败，保持原始请求头不变

    def apply_body_field_rules(self):
        """在SQLMap扫描启动前应用Body字段规则"""
        # 检查是否已经应用过Body字段规则，避免重复处理
        if self._body_field_rules_applied:
            logger.debug(f"[{self.taskid}] Body field rules already applied, skipping")
            return
            
        try:
            logger.debug(f"[{self.taskid}] Starting body field rules application")
            
            # 检查是否有Body内容
            if not self.body:
                logger.debug(f"[{self.taskid}] No body to process")
                self._body_field_rules_applied = True
                return
            
            # 动态导入避免循环引用
            from utils.body_field_processor import BodyFieldProcessor
            from model.DataStore import DataStore
            
            logger.debug(f"[{self.taskid}] Importing body field processor")
            
            # 获取会话Body字段管理器
            body_field_manager = DataStore.get_session_body_field_manager()
            if not body_field_manager:
                logger.debug(f"[{self.taskid}] Body field manager not available")
                self._body_field_rules_applied = True
                return
            
            # 获取会话Body字段
            logger.debug(f"[{self.taskid}] Getting body fields for {self.remote_addr}")
            session_fields = body_field_manager.get_session_body_fields(self.remote_addr, active_only=True)
            logger.debug(f"[{self.taskid}] Got {len(session_fields)} session body fields")
            
            if not session_fields:
                logger.debug(f"[{self.taskid}] No active body fields to apply")
                self._body_field_rules_applied = True
                return
            
            # 从headers中提取Content-Type
            content_type = None
            if self.headers:
                for header in self.headers:
                    if header and ":" in header:
                        name, value = header.split(":", 1)
                        if name.strip().lower() == "content-type":
                            content_type = value.strip()
                            break
            
            logger.debug(f"[{self.taskid}] Content-Type: {content_type}")
            logger.debug(f"[{self.taskid}] Processing body with {len(session_fields)} fields")
            
            # 处理Body
            processed_body, applied_rules = BodyFieldProcessor.process_body(
                self.body, content_type, session_fields, self.scanUrl
            )
            
            logger.debug(f"[{self.taskid}] Processed body, Applied rules: {len(applied_rules)}")
            
            # 更新Body
            if processed_body != self.body:
                self.body = processed_body
                logger.info(f"[{self.taskid}] Applied {len(applied_rules)} body field rules: {', '.join(applied_rules)}")
                logger.debug(f"[{self.taskid}] Updated body content")
            else:
                logger.debug(f"[{self.taskid}] No body changes applied")
            
            # 标记Body字段规则已应用
            self._body_field_rules_applied = True
            
        except Exception as e:
            logger.error(f"[{self.taskid}] Failed to apply body field rules: {e}")
            # 如果应用规则失败，保持原始Body不变

    def _generate_request_file_name(self):
        """生成HTTP请求文件名: 日期时间 + 随机6位数字"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = random.randint(100000, 999999)
        return f"request_{timestamp}_{random_suffix}.txt"

    def _build_raw_http_request(self):
        """
        根据headers和body构建HTTP原始报文
        格式（使用标准HTTP换行符 \\r\\n）:
        POST /path HTTP/1.1\\r\\n
        Host: example.com\\r\\n
        Header1: Value1\\r\\n
        \\r\\n
        body_content
        
        注意：
        - 移除 Content-Length 头，让 sqlmap 根据实际 body 长度自动计算
        - body 中的换行符统一规范化为 \\n（避免 \\r\\n 被重复转换）
        - 使用 \\r\\n 作为 HTTP 标准行分隔符
        """
        # 解析URL获取请求路径
        parsed_url = urlparse(self.scanUrl)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += "?" + parsed_url.query
        
        # 使用存储的method，如果不存在则根据body推断
        method = self.method if self.method else ("POST" if self.body else "GET")
        
        # 构建请求行
        request_line = f"{method} {path} HTTP/1.1"
        
        # 构建headers部分（移除 Content-Length，让 sqlmap 自动计算）
        headers_list = []
        if self.headers:
            for header in self.headers:
                if header and ":" in header:
                    # 跳过 Content-Length，由 sqlmap 根据实际 body 重新计算
                    if header.lower().startswith("content-length:"):
                        logger.debug(f"[{self.taskid}] Removing Content-Length header, sqlmap will recalculate")
                        continue
                    # 如果启用了randomAgent，跳过原始User-Agent头
                    # 让SQLMap的_setHTTPUserAgent()添加随机UA
                    if self.options.randomAgent and header.lower().startswith("user-agent:"):
                        logger.debug(f"[{self.taskid}] Skipping original User-Agent header due to randomAgent=True")
                        continue
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
        
        # 规范化 body 中的换行符：统一为 \n，避免混合换行符导致字节数不一致
        body = self.body
        if body:
            body = body.replace("\r\n", "\n").replace("\r", "\n")
        
        # 使用 \r\n 作为 HTTP 标准行分隔符组装报文
        CRLF = "\r\n"
        raw_request = request_line + CRLF
        raw_request += CRLF.join(headers_list)
        
        # 如果有body，添加空行和body
        if body:
            raw_request += CRLF + CRLF + body
        else:
            raw_request += CRLF + CRLF
        
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
        
        # 使用二进制模式写入，避免 Windows 文本模式自动将 \n 转换为 \r\n
        # 导致 body 字节数与 Content-Length 不匹配（XML 等多行 body 的截断根因）
        with open(file_path, 'wb') as f:
            f.write(raw_request.encode('utf-8'))
        
        logger.info(f"[{self.taskid}] Created HTTP request file: {file_path}")
        logger.debug(f"[{self.taskid}] HTTP request content:\n{raw_request}")
        
        return file_path

    def engine_start(self):
        logger.debug(f"[{self.taskid}] Starting engine with headers: {self.headers}")
        # 在SQLMap真正启动前应用请求头规则
        self.apply_header_rules()
        
        # 在SQLMap真正启动前应用Body字段规则
        self.apply_body_field_rules()
        
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
