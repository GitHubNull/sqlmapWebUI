"""
BodyFieldProcessor - Body字段处理器

根据Content-Type解析Body，应用匹配和替换规则，生成处理后的Body。
支持JSON、XML、URL编码三种格式。
"""

import re
import json
import urllib.parse
from typing import List, Dict, Optional, Tuple, Any

try:
    from jsonpath_ng import parse as jsonpath_parse
    JSONPATH_AVAILABLE = True
except ImportError:
    JSONPATH_AVAILABLE = False

try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

from model.SessionBodyField import SessionBodyField, MatchStrategy, ReplaceStrategy
from utils.scope_matcher import ScopeMatcher

import logging
logger = logging.getLogger(__name__)


class BodyFieldProcessor:
    """Body字段处理器 - 负责应用Body字段替换规则"""

    @staticmethod
    def detect_content_type(content_type: Optional[str]) -> str:
        """
        检测Content-Type并返回简化类型
        
        返回: 'json', 'xml', 'urlencoded', 'unknown'
        """
        if not content_type:
            return 'unknown'
        
        content_type_lower = content_type.lower()
        if 'application/json' in content_type_lower:
            return 'json'
        elif 'application/xml' in content_type_lower or 'text/xml' in content_type_lower:
            return 'xml'
        elif 'application/x-www-form-urlencoded' in content_type_lower:
            return 'urlencoded'
        else:
            return 'unknown'

    @classmethod
    def parse_json_body(cls, body_str: str) -> Optional[dict]:
        """解析JSON格式Body"""
        try:
            return json.loads(body_str)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON body: {e}")
            return None

    @classmethod
    def parse_xml_body(cls, body_str: str):
        """解析XML格式Body"""
        if not LXML_AVAILABLE:
            logger.error("lxml library not available for XML parsing")
            return None
        
        try:
            return etree.fromstring(body_str.encode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to parse XML body: {e}")
            return None

    @classmethod
    def parse_urlencoded_body(cls, body_str: str) -> Optional[dict]:
        """解析URL编码格式Body"""
        try:
            return dict(urllib.parse.parse_qsl(body_str))
        except Exception as e:
            logger.error(f"Failed to parse urlencoded body: {e}")
            return None

    @classmethod
    def serialize_json_body(cls, json_obj: dict) -> str:
        """序列化JSON对象为字符串"""
        return json.dumps(json_obj, ensure_ascii=False)

    @classmethod
    def serialize_xml_body(cls, xml_tree) -> str:
        """序列化XML树为字符串"""
        if not LXML_AVAILABLE:
            return ""
        return etree.tostring(xml_tree, encoding='unicode')

    @classmethod
    def serialize_urlencoded_body(cls, params: dict) -> str:
        """序列化字典为URL编码字符串"""
        return urllib.parse.urlencode(params)

    @classmethod
    def match_field_jsonpath(cls, json_obj: dict, field_name: str, pattern: str) -> Optional[Any]:
        """使用JSONPath匹配字段"""
        if not JSONPATH_AVAILABLE:
            logger.warning("jsonpath-ng not available, falling back to keyword match")
            return cls.match_field_keyword(json_obj, field_name)
        
        try:
            jsonpath_expr = jsonpath_parse(pattern)
            matches = jsonpath_expr.find(json_obj)
            if matches:
                return matches[0]
            return None
        except Exception as e:
            logger.error(f"JSONPath matching failed: {e}")
            return None

    @classmethod
    def match_field_xpath(cls, xml_tree, field_name: str, pattern: str) -> Optional[Any]:
        """使用XPath匹配字段"""
        if not LXML_AVAILABLE:
            logger.error("lxml not available for XPath matching")
            return None
        
        try:
            result = xml_tree.xpath(pattern)
            if result:
                if isinstance(result, list) and len(result) > 0:
                    return result[0]
                return result
            return None
        except Exception as e:
            logger.error(f"XPath matching failed: {e}")
            return None

    @classmethod
    def match_field_keyword(cls, body: Any, field_name: str) -> Optional[Any]:
        """使用关键字匹配字段（直接访问字典key）"""
        if isinstance(body, dict):
            return body.get(field_name)
        return None

    @classmethod
    def match_field_regex(cls, body_str: str, field_name: str, pattern: str) -> Optional[str]:
        """使用正则表达式匹配字段"""
        try:
            match = re.search(pattern, body_str)
            if match:
                return match.group(1) if match.groups() else match.group(0)
            return None
        except Exception as e:
            logger.error(f"Regex matching failed: {e}")
            return None

    @classmethod
    def apply_replace_strategy(cls, existing_value: Any, new_value: str, strategy: ReplaceStrategy) -> Any:
        """根据替换策略应用新值"""
        if strategy == ReplaceStrategy.REPLACE or strategy == ReplaceStrategy.UPSERT:
            return new_value
        elif strategy == ReplaceStrategy.APPEND:
            if existing_value:
                return f"{existing_value}{new_value}"
            return new_value
        elif strategy == ReplaceStrategy.PREPEND:
            if existing_value:
                return f"{new_value}{existing_value}"
            return new_value
        elif strategy == ReplaceStrategy.CONDITIONAL:
            if not existing_value or str(existing_value).lower() in ['none', 'null', '']:
                return new_value
            return existing_value
        else:
            return new_value

    @classmethod
    def apply_rules_to_json(cls, json_obj: dict, fields: List[SessionBodyField], target_url: Optional[str]) -> Tuple[dict, List[str]]:
        """对JSON对象应用规则"""
        # 过滤适用的规则
        applicable_fields = []
        for field in fields:
            if field.content_types and 'application/json' not in field.content_types:
                continue
            if not field.is_active:
                continue
            applicable_fields.append(field)
        
        if not applicable_fields:
            return json_obj, []
        
        # 按优先级排序
        applicable_fields.sort(key=lambda x: x.priority, reverse=True)
        
        # 应用规则
        modified_obj = json_obj.copy()
        applied_rules = []
        
        for field in applicable_fields:
            # 作用域匹配
            if field.scope and target_url:
                if not ScopeMatcher.match_scope(field.scope, target_url):
                    logger.debug(f"Field '{field.field_name}' scope not matched, skipping")
                    continue
            
            try:
                # 根据匹配策略定位字段
                if field.match_strategy == MatchStrategy.JSONPATH and field.match_pattern:
                    if JSONPATH_AVAILABLE:
                        # 使用JSONPath更新值
                        jsonpath_expr = jsonpath_parse(field.match_pattern)
                        matches = jsonpath_expr.find(modified_obj)
                        if matches:
                            for match in matches:
                                existing_value = match.value
                                new_value = cls.apply_replace_strategy(
                                    existing_value, field.field_value, field.replace_strategy
                                )
                                match.full_path.update(modified_obj, new_value)
                            applied_rules.append(f"BodyField: {field.field_name}")
                
                elif field.match_strategy == MatchStrategy.KEYWORD:
                    # 直接访问字典key
                    if field.field_name in modified_obj:
                        existing_value = modified_obj[field.field_name]
                        new_value = cls.apply_replace_strategy(
                            existing_value, field.field_value, field.replace_strategy
                        )
                        modified_obj[field.field_name] = new_value
                        applied_rules.append(f"BodyField: {field.field_name}")
                
            except Exception as e:
                logger.error(f"Failed to apply field rule '{field.field_name}': {e}")
        
        return modified_obj, applied_rules

    @classmethod
    def apply_rules_to_xml(cls, xml_tree, fields: List[SessionBodyField], target_url: Optional[str]) -> Tuple[Any, List[str]]:
        """对XML树应用规则"""
        if not LXML_AVAILABLE:
            logger.error("lxml not available for XML processing")
            return xml_tree, []
        
        # 过滤适用的规则
        applicable_fields = []
        for field in fields:
            if field.content_types and not any(ct in field.content_types for ct in ['application/xml', 'text/xml']):
                continue
            if not field.is_active:
                continue
            applicable_fields.append(field)
        
        if not applicable_fields:
            return xml_tree, []
        
        # 按优先级排序
        applicable_fields.sort(key=lambda x: x.priority, reverse=True)
        
        # 应用规则
        applied_rules = []
        
        for field in applicable_fields:
            # 作用域匹配
            if field.scope and target_url:
                if not ScopeMatcher.match_scope(field.scope, target_url):
                    continue
            
            try:
                if field.match_strategy == MatchStrategy.XPATH and field.match_pattern:
                    elements = xml_tree.xpath(field.match_pattern)
                    for element in elements:
                        if hasattr(element, 'text'):
                            existing_value = element.text
                            new_value = cls.apply_replace_strategy(
                                existing_value, field.field_value, field.replace_strategy
                            )
                            element.text = new_value
                        applied_rules.append(f"BodyField: {field.field_name}")
            
            except Exception as e:
                logger.error(f"Failed to apply XML field rule '{field.field_name}': {e}")
        
        return xml_tree, applied_rules

    @classmethod
    def apply_rules_to_urlencoded(cls, params: dict, fields: List[SessionBodyField], target_url: Optional[str]) -> Tuple[dict, List[str]]:
        """对URL编码参数应用规则"""
        # 过滤适用的规则
        applicable_fields = []
        for field in fields:
            if field.content_types and 'application/x-www-form-urlencoded' not in field.content_types:
                continue
            if not field.is_active:
                continue
            applicable_fields.append(field)
        
        if not applicable_fields:
            return params, []
        
        # 按优先级排序
        applicable_fields.sort(key=lambda x: x.priority, reverse=True)
        
        # 应用规则
        modified_params = params.copy()
        applied_rules = []
        
        for field in applicable_fields:
            # 作用域匹配
            if field.scope and target_url:
                if not ScopeMatcher.match_scope(field.scope, target_url):
                    continue
            
            try:
                if field.match_strategy == MatchStrategy.KEYWORD:
                    if field.field_name in modified_params:
                        existing_value = modified_params[field.field_name]
                        new_value = cls.apply_replace_strategy(
                            existing_value, field.field_value, field.replace_strategy
                        )
                        modified_params[field.field_name] = new_value
                        applied_rules.append(f"BodyField: {field.field_name}")
                
                elif field.match_strategy == MatchStrategy.REGEX and field.match_pattern:
                    # 对整个参数字符串应用正则
                    body_str = urllib.parse.urlencode(modified_params)
                    match = re.search(field.match_pattern, body_str)
                    if match:
                        # 简单替换
                        new_body_str = body_str.replace(match.group(0), field.field_value)
                        modified_params = dict(urllib.parse.parse_qsl(new_body_str))
                        applied_rules.append(f"BodyField: {field.field_name}")
            
            except Exception as e:
                logger.error(f"Failed to apply urlencoded field rule '{field.field_name}': {e}")
        
        return modified_params, applied_rules

    @classmethod
    def process_body(cls, original_body: str, content_type: Optional[str], 
                     fields: Dict[str, SessionBodyField], target_url: Optional[str] = None) -> Tuple[str, List[str]]:
        """
        处理Body并应用规则
        
        参数:
            original_body: 原始Body字符串
            content_type: Content-Type
            fields: 会话Body字段字典
            target_url: 目标URL（用于作用域匹配）
        
        返回: (处理后的Body字符串, 应用的规则列表)
        """
        try:
            # 检测Content-Type
            body_type = cls.detect_content_type(content_type)
            logger.debug(f"Detected body type: {body_type}")
            
            # 过滤未过期且启用的字段
            active_fields = {name: field for name, field in fields.items() 
                            if not field.is_expired() and field.is_active}
            
            if not active_fields:
                logger.debug("No active body fields to apply")
                return original_body, []
            
            logger.debug(f"Processing {len(active_fields)} active body fields")
            
            # 根据类型解析和处理
            if body_type == 'json':
                json_obj = cls.parse_json_body(original_body)
                if json_obj is not None:
                    modified_obj, applied = cls.apply_rules_to_json(
                        json_obj, list(active_fields.values()), target_url
                    )
                    processed_body = cls.serialize_json_body(modified_obj)
                    logger.info(f"Applied {len(applied)} rules to JSON body")
                    return processed_body, applied
            
            elif body_type == 'xml':
                if not LXML_AVAILABLE:
                    logger.warning("lxml not available, skipping XML processing")
                    return original_body, []
                
                xml_tree = cls.parse_xml_body(original_body)
                if xml_tree is not None:
                    modified_tree, applied = cls.apply_rules_to_xml(
                        xml_tree, list(active_fields.values()), target_url
                    )
                    processed_body = cls.serialize_xml_body(modified_tree)
                    logger.info(f"Applied {len(applied)} rules to XML body")
                    return processed_body, applied
            
            elif body_type == 'urlencoded':
                params = cls.parse_urlencoded_body(original_body)
                if params is not None:
                    modified_params, applied = cls.apply_rules_to_urlencoded(
                        params, list(active_fields.values()), target_url
                    )
                    processed_body = cls.serialize_urlencoded_body(modified_params)
                    logger.info(f"Applied {len(applied)} rules to urlencoded body")
                    return processed_body, applied
            
            # 不支持的类型或解析失败，返回原始body
            logger.debug(f"Body type '{body_type}' not supported or parsing failed")
            return original_body, []
            
        except Exception as e:
            logger.error(f"Failed to process body: {e}")
            # 失败时返回原始body，不中断任务
            return original_body, [f"Error: {str(e)}"]
