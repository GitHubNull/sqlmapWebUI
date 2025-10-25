import re
import json
from typing import List, Dict, Optional
from ..model.HeaderBatch import ParsedHeaderItem, ParseResult, FormatHint

# 使用标准库的logging模块
import logging
logger = logging.getLogger(__name__)


class HeaderParser:
    """请求头解析器 - 支持多种格式的请求头数据解析"""

    @staticmethod
    def validate_header_name(header_name: str) -> bool:
        """验证请求头名称是否合法"""
        if not header_name:
            return False
        
        # HTTP请求头名称只能包含字母、数字、连字符和下划线
        # RFC 7230 规定请求头名称为token格式
        pattern = r'^[a-zA-Z0-9\-_]+$'
        return bool(re.match(pattern, header_name))

    @staticmethod
    def clean_header_value(value: str) -> str:
        """清理请求头值"""
        if not value:
            return ""
        
        # 移除首尾空白字符
        cleaned = value.strip()
        
        # 移除可能的引号包围
        if len(cleaned) >= 2:
            if (cleaned.startswith('"') and cleaned.endswith('"')) or \
               (cleaned.startswith("'") and cleaned.endswith("'")):
                cleaned = cleaned[1:-1]
        
        return cleaned

    @classmethod
    def parse_http_format(cls, text: str) -> List[ParsedHeaderItem]:
        """
        解析HTTP格式的请求头
        
        支持格式:
        Accept: application/json
        Authorization: Bearer token123
        X-Custom-Header: value
        """
        headers = []
        lines = text.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # 跳过空行和注释行
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # 跳过HTTP状态行和请求行
            if line.startswith(('HTTP/', 'GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                continue
            
            # 查找冒号分隔符
            if ':' in line:
                name, value = line.split(':', 1)
                name = name.strip()
                value = cls.clean_header_value(value)
                
                if cls.validate_header_name(name) and value:
                    headers.append(ParsedHeaderItem(
                        header_name=name,
                        header_value=value,
                        priority=0,
                        source_line=line_num
                    ))
                    logger.debug(f"Parsed HTTP header: {name} = {value}")
        
        return headers

    @classmethod
    def parse_key_value_format(cls, text: str) -> List[ParsedHeaderItem]:
        """
        解析键值对格式的请求头
        
        支持格式:
        Accept=application/json
        Authorization=Bearer token123
        X-Custom-Header=value
        """
        headers = []
        lines = text.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # 跳过空行和注释行
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # 查找等号分隔符
            if '=' in line:
                name, value = line.split('=', 1)
                name = name.strip()
                value = cls.clean_header_value(value)
                
                if cls.validate_header_name(name) and value:
                    headers.append(ParsedHeaderItem(
                        header_name=name,
                        header_value=value,
                        priority=0,
                        source_line=line_num
                    ))
                    logger.debug(f"Parsed key-value header: {name} = {value}")
        
        return headers

    @classmethod
    def parse_json_format(cls, text: str) -> List[ParsedHeaderItem]:
        """
        解析JSON格式的请求头
        
        支持格式:
        {
            "Accept": "application/json",
            "Authorization": "Bearer token123",
            "X-Custom-Header": "value"
        }
        """
        headers = []
        
        try:
            data = json.loads(text.strip())
            
            if isinstance(data, dict):
                for line_num, (name, value) in enumerate(data.items(), 1):
                    name = str(name).strip()
                    value = cls.clean_header_value(str(value))
                    
                    if cls.validate_header_name(name) and value:
                        headers.append(ParsedHeaderItem(
                            header_name=name,
                            header_value=value,
                            priority=0,
                            source_line=line_num
                        ))
                        logger.debug(f"Parsed JSON header: {name} = {value}")
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON format: {e}")
        
        return headers

    @classmethod
    def parse_curl_format(cls, text: str) -> List[ParsedHeaderItem]:
        """
        解析cURL命令中的请求头
        
        支持格式:
        curl -H "Accept: application/json" -H "Authorization: Bearer token"
        curl --header "Content-Type: application/json" --header "X-API-Key: abc123"
        """
        headers = []
        
        # 使用正则表达式提取 -H 或 --header 参数
        # 支持单引号、双引号和无引号
        patterns = [
            r'-H\s+["\']([^"\']+)["\']',           # -H "header"
            r'-H\s+([^\s]+)',                      # -H header
            r'--header\s+["\']([^"\']+)["\']',     # --header "header"
            r'--header\s+([^\s]+)'                 # --header header
        ]
        
        line_num = 1
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                header_str = match
                if ':' in header_str:
                    name, value = header_str.split(':', 1)
                    name = name.strip()
                    value = cls.clean_header_value(value)
                    
                    if cls.validate_header_name(name) and value:
                        headers.append(ParsedHeaderItem(
                            header_name=name,
                            header_value=value,
                            priority=0,
                            source_line=line_num
                        ))
                        logger.debug(f"Parsed cURL header: {name} = {value}")
                        line_num += 1
        
        return headers

    @classmethod
    def auto_detect_format(cls, text: str) -> FormatHint:
        """自动检测文本格式"""
        text_stripped = text.strip()
        
        # 检查是否为JSON格式
        if text_stripped.startswith('{') and text_stripped.endswith('}'):
            try:
                json.loads(text_stripped)
                return FormatHint.JSON
            except json.JSONDecodeError:
                pass
        
        # 检查是否为cURL命令
        if 'curl' in text_stripped.lower() and ('-H' in text or '--header' in text):
            return FormatHint.CURL
        
        # 检查是否包含等号（键值对格式）
        lines = text_stripped.split('\n')
        equal_count = sum(1 for line in lines if '=' in line and ':' not in line)
        colon_count = sum(1 for line in lines if ':' in line)
        
        if equal_count > colon_count:
            return FormatHint.KEY_VALUE
        else:
            return FormatHint.HTTP

    @classmethod
    def parse_raw_text(cls, text: str, format_hint: FormatHint = FormatHint.AUTO, 
                      default_priority: int = 0) -> ParseResult:
        """
        解析原始文本中的请求头
        
        Args:
            text: 原始文本
            format_hint: 格式提示
            default_priority: 默认优先级
            
        Returns:
            ParseResult: 解析结果
        """
        if not text or not text.strip():
            return ParseResult(
                success=False,
                errors=["输入文本为空"]
            )
        
        # 自动检测格式
        if format_hint == FormatHint.AUTO:
            format_hint = cls.auto_detect_format(text)
            logger.info(f"Auto-detected format: {format_hint}")
        
        headers = []
        errors = []
        warnings = []
        
        try:
            # 根据格式提示选择解析方法
            if format_hint == FormatHint.HTTP:
                headers = cls.parse_http_format(text)
            elif format_hint == FormatHint.KEY_VALUE:
                headers = cls.parse_key_value_format(text)
            elif format_hint == FormatHint.JSON:
                headers = cls.parse_json_format(text)
            elif format_hint == FormatHint.CURL:
                headers = cls.parse_curl_format(text)
            else:
                # 默认尝试HTTP格式
                headers = cls.parse_http_format(text)
            
            # 应用默认优先级
            for header in headers:
                header.priority = default_priority
            
            # 检查重复的请求头
            seen_headers = set()
            for header in headers:
                if header.header_name.lower() in seen_headers:
                    warnings.append(f"重复的请求头: {header.header_name}")
                else:
                    seen_headers.add(header.header_name.lower())
            
            # 检查是否解析出任何请求头
            if not headers:
                errors.append(f"未能从文本中解析出有效的请求头 (格式: {format_hint})")
            
            success = len(headers) > 0 and len(errors) == 0
            
            result = ParseResult(
                success=success,
                parsed_headers=headers,
                total_count=len(headers),
                errors=errors,
                warnings=warnings
            )
            
            logger.info(f"Parsing completed: {len(headers)} headers parsed, "
                       f"{len(errors)} errors, {len(warnings)} warnings")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse headers: {e}")
            return ParseResult(
                success=False,
                errors=[f"解析失败: {str(e)}"]
            )

    @classmethod
    def validate_parsed_headers(cls, headers: List[ParsedHeaderItem]) -> Dict[str, List[str]]:
        """
        验证解析后的请求头
        
        Returns:
            Dict with 'errors' and 'warnings' keys
        """
        errors = []
        warnings = []
        
        if not headers:
            errors.append("请求头列表为空")
            return {"errors": errors, "warnings": warnings}
        
        # 检查请求头数量限制
        if len(headers) > 100:
            errors.append(f"请求头数量超过限制 (当前: {len(headers)}, 最大: 100)")
        
        # 验证每个请求头
        seen_names = {}
        for i, header in enumerate(headers):
            # 验证请求头名称
            if not cls.validate_header_name(header.header_name):
                errors.append(f"第{i+1}个请求头名称不合法: {header.header_name}")
            
            # 检查重复
            lower_name = header.header_name.lower()
            if lower_name in seen_names:
                warnings.append(f"重复的请求头: {header.header_name} (行 {header.source_line} 和 {seen_names[lower_name]})")
            else:
                seen_names[lower_name] = header.source_line
            
            # 检查值长度
            if len(header.header_value) > 2000:
                errors.append(f"第{i+1}个请求头值过长: {header.header_name}")
        
        return {"errors": errors, "warnings": warnings}