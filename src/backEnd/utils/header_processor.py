import re
from typing import List, Dict, Optional, Tuple
from model.PersistentHeaderRule import PersistentHeaderRule, ReplaceStrategy
from model.SessionHeader import SessionHeader

# 使用标准库的logging模块
import logging
logger = logging.getLogger(__name__)


class HeaderProcessor:
    """请求头处理器 - 负责应用持久化规则和会话性请求头"""

    @staticmethod
    def normalize_headers(headers: List[str]) -> Dict[str, str]:
        """
        将请求头列表转换为字典格式
        输入: ["Content-Type: application/json", "Authorization: Bearer token"]
        输出: {"Content-Type": "application/json", "Authorization": "Bearer token"}
        """
        header_dict = {}
        if not headers:
            return header_dict
        
        for header_line in headers:
            if not header_line or ':' not in header_line:
                continue
            
            # 分割请求头名称和值，只分割第一个冒号
            name, value = header_line.split(':', 1)
            header_dict[name.strip()] = value.strip()
        
        return header_dict

    @staticmethod
    def format_headers_for_sqlmap(headers: Dict[str, str]) -> List[str]:
        """
        将字典格式的请求头转换回SQLMap所需的列表格式
        输入: {"Content-Type": "application/json", "Authorization": "Bearer token"}
        输出: ["Content-Type: application/json", "Authorization: Bearer token"]
        """
        header_list = []
        for name, value in headers.items():
            header_list.append(f"{name}: {value}")
        return header_list

    @staticmethod
    def validate_header_name(header_name: str) -> bool:
        """验证请求头名称是否合法"""
        if not header_name:
            return False
        
        # HTTP请求头名称只能包含字母、数字、连字符和下划线
        pattern = r'^[a-zA-Z0-9\-_]+$'
        return bool(re.match(pattern, header_name))

    @staticmethod
    def apply_replace_strategy(existing_value: str, new_value: str, strategy: ReplaceStrategy) -> str:
        """根据替换策略应用新值"""
        if strategy == ReplaceStrategy.REPLACE:
            return new_value
        elif strategy == ReplaceStrategy.APPEND:
            return f"{existing_value}, {new_value}" if existing_value else new_value
        elif strategy == ReplaceStrategy.PREPEND:
            return f"{new_value}, {existing_value}" if existing_value else new_value
        elif strategy == ReplaceStrategy.CONDITIONAL:
            # 条件性替换：如果原值为空或包含特定模式则替换
            return new_value if not existing_value or existing_value.lower() in ['none', 'null', ''] else existing_value
        elif strategy == ReplaceStrategy.UPSERT:
            # UPSERT策略：如果存在则替换，如果不存在则新增（与REPLACE策略行为相同）
            return new_value
        else:
            return new_value

    @staticmethod
    def match_condition(header_value: str, condition: Optional[str]) -> bool:
        """检查请求头值是否匹配指定条件"""
        if not condition:
            return True
        
        try:
            # 简单的正则表达式匹配
            return bool(re.search(condition, header_value, re.IGNORECASE))
        except re.error:
            logger.warning(f"Invalid regex condition: {condition}")
            return True

    @classmethod
    def apply_persistent_rules(cls, headers_dict: Dict[str, str], rules: List[PersistentHeaderRule]) -> Tuple[Dict[str, str], List[str]]:
        """应用持久化规则到请求头字典
        返回: (处理后的请求头字典, 实际应用的规则名称列表)"""
        if not rules:
            return headers_dict, []
        
        # 按优先级排序规则（优先级高的先执行）
        sorted_rules = sorted(rules, key=lambda x: x.priority, reverse=True)
        
        processed_headers = headers_dict.copy()
        applied_rules = []
        
        for rule in sorted_rules:
            if not rule.is_active:
                continue
            
            # 验证请求头名称
            if not cls.validate_header_name(rule.header_name):
                logger.warning(f"Invalid header name in rule {rule.name}: {rule.header_name}")
                continue
            
            existing_value = processed_headers.get(rule.header_name, "")
            
            # 检查匹配条件
            if not cls.match_condition(existing_value, rule.match_condition):
                continue
            
            # 应用替换策略
            new_value = cls.apply_replace_strategy(
                existing_value, 
                rule.header_value, 
                rule.replace_strategy
            )
            
            # 总是应用规则，无论值是否改变（满足用户需求：不论如何都添加到请求头里面）
            # 对于UPSERT策略，这里的行为是：如果请求头已存在则替换(new_value)，如果不存在则新增(new_value)
            processed_headers[rule.header_name] = new_value
            applied_rules.append(rule.name)
            
            logger.debug(f"Applied persistent rule '{rule.name}': {rule.header_name} = {new_value}")
        
        if applied_rules:
            logger.info(f"Applied {len(applied_rules)} persistent header rules: {', '.join(applied_rules)}")
        
        return processed_headers, applied_rules

    @classmethod
    def apply_session_headers(cls, headers_dict: Dict[str, str], session_headers: Dict[str, SessionHeader]) -> Tuple[Dict[str, str], List[str]]:
        """应用会话性请求头到请求头字典
        返回: (处理后的请求头字典, 实际应用的会话头名称列表)"""
        if not session_headers:
            return headers_dict, []
        
        # 过滤掉已过期的会话性请求头
        active_session_headers = {
            name: header for name, header in session_headers.items() 
            if not header.is_expired()
        }
        
        if not active_session_headers:
            return headers_dict
        
        # 按优先级排序会话性请求头（优先级高的后执行，以便覆盖优先级低的）
        sorted_session_headers = sorted(
            active_session_headers.items(),
            key=lambda x: x[1].priority
        )
        
        processed_headers = headers_dict.copy()
        applied_headers = []
        
        for header_name, session_header in sorted_session_headers:
            # 验证请求头名称
            if not cls.validate_header_name(header_name):
                logger.warning(f"Invalid session header name: {header_name}")
                continue
            
            # 总是应用会话性请求头，无论值是否改变
            # 这里的行为相当于UPSERT策略：如果请求头已存在则替换，如果不存在则新增
            processed_headers[header_name] = session_header.header_value
            applied_headers.append(header_name)
            
            logger.debug(f"Applied session header: {header_name} = {session_header.header_value}")
        
        if applied_headers:
            logger.info(f"Applied {len(applied_headers)} session headers: {', '.join(applied_headers)}")
        
        return processed_headers, applied_headers

    @classmethod
    def process_headers(cls, original_headers: List[str], persistent_rules: List[PersistentHeaderRule], 
                       session_headers: Dict[str, SessionHeader]) -> Tuple[List[str], List[str]]:
        """
        处理请求头，应用持久化规则和会话性请求头
        返回: (处理后的请求头列表, 应用的规则描述列表)
        """
        try:
            logger.debug(f"Processing headers: {len(original_headers)} original headers, {len(persistent_rules)} rules, {len(session_headers)} session headers")
            
            # 1. 将原始请求头转换为字典格式
            headers_dict = cls.normalize_headers(original_headers)
            logger.debug(f"Original headers: {headers_dict}")
            
            # 2. 应用持久化规则
            headers_dict, applied_persistent_rules = cls.apply_persistent_rules(headers_dict, persistent_rules)
            
            # 3. 应用会话性请求头
            headers_dict, applied_session_headers = cls.apply_session_headers(headers_dict, session_headers)
            
            # 4. 转换回SQLMap所需的格式
            processed_headers = cls.format_headers_for_sqlmap(headers_dict)
            
            # 5. 生成应用规则的描述
            applied_rules_desc = []
            applied_rules_desc.extend([f"Persistent: {rule_name}" for rule_name in applied_persistent_rules])
            applied_rules_desc.extend([f"Session: {header_name}" for header_name in applied_session_headers])
            
            logger.info(f"Header processing completed. Original: {len(original_headers)}, Processed: {len(processed_headers)}")
            logger.debug(f"Processed headers: {processed_headers}")
            logger.debug(f"Applied rules: {applied_rules_desc}")
            
            return processed_headers, applied_rules_desc
            
        except Exception as e:
            logger.error(f"Failed to process headers: {e}")
            # 如果处理失败，返回原始请求头
            return original_headers, [f"Error: {str(e)}"]

    @classmethod
    def preview_header_processing(cls, original_headers: List[str], persistent_rules: List[PersistentHeaderRule], 
                                 session_headers: Dict[str, SessionHeader]) -> Dict:
        """
        预览请求头处理结果，不实际应用
        返回详细的处理信息用于调试和预览
        """
        try:
            processed_headers, applied_rules = cls.process_headers(original_headers, persistent_rules, session_headers)
            
            return {
                "original_headers": original_headers,
                "processed_headers": processed_headers,
                "applied_rules": applied_rules,
                "changes_count": len(applied_rules),
                "success": True
            }
        except Exception as e:
            return {
                "original_headers": original_headers,
                "processed_headers": original_headers,
                "applied_rules": [],
                "changes_count": 0,
                "success": False,
                "error": str(e)
            }