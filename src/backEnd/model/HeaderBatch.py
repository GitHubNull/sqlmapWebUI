from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from model.PersistentHeaderRule import ReplaceStrategy


class FormatHint(str, Enum):
    """解析格式提示"""
    AUTO = "auto"           # 自动检测
    HTTP = "http"           # HTTP报文格式
    KEY_VALUE = "keyvalue"  # 键值对格式
    JSON = "json"           # JSON格式
    CURL = "curl"           # cURL命令格式


class TargetType(str, Enum):
    """目标类型"""
    PERSISTENT = "persistent"  # 持久化规则
    SESSION = "session"       # 会话头


class HeaderBatchParseRequest(BaseModel):
    """批量解析请求头的请求模型"""
    raw_text: str = Field(..., min_length=1, max_length=50000, description="原始文本数据")
    format_hint: FormatHint = Field(default=FormatHint.AUTO, description="格式提示")
    default_priority: int = Field(default=0, ge=0, le=100, description="默认优先级")
    default_ttl: int = Field(default=3600, ge=60, le=86400, description="默认TTL")


class ParsedHeaderItem(BaseModel):
    """解析后的请求头项"""
    header_name: str = Field(..., min_length=1, max_length=200, description="请求头名称")
    header_value: str = Field(..., min_length=1, max_length=2000, description="请求头值")
    priority: int = Field(default=0, ge=0, le=100, description="优先级")
    source_line: int = Field(..., ge=1, description="源文本行号")


class ParseResult(BaseModel):
    """解析结果模型"""
    success: bool = Field(..., description="解析是否成功")
    parsed_headers: List[ParsedHeaderItem] = Field(default=[], description="解析出的请求头列表")
    total_count: int = Field(default=0, description="总数量")
    errors: List[str] = Field(default=[], description="错误信息列表")
    warnings: List[str] = Field(default=[], description="警告信息列表")


class PersistentRuleConfig(BaseModel):
    """持久化规则配置"""
    name_prefix: str = Field(default="批量导入_", max_length=50, description="规则名称前缀")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
    default_priority: int = Field(default=0, ge=0, le=100, description="默认优先级")
    is_active: bool = Field(default=True, description="是否启用")


class SessionConfig(BaseModel):
    """会话配置"""
    default_ttl: int = Field(default=3600, ge=60, le=86400, description="默认TTL")
    default_priority: int = Field(default=0, ge=0, le=100, description="默认优先级")


class HeaderBatchCreateRequest(BaseModel):
    """批量创建请求头的请求模型"""
    raw_text: str = Field(..., min_length=1, max_length=50000, description="原始文本数据")
    target_type: TargetType = Field(..., description="目标类型")
    format_hint: FormatHint = Field(default=FormatHint.AUTO, description="格式提示")
    rule_config: Optional[PersistentRuleConfig] = Field(None, description="持久化规则配置")
    session_config: Optional[SessionConfig] = Field(None, description="会话配置")


class HeaderBatchResult(BaseModel):
    """批量操作结果模型"""
    success: bool = Field(..., description="操作是否成功")
    total_count: int = Field(default=0, description="总处理数量")
    success_count: int = Field(default=0, description="成功数量")
    failed_count: int = Field(default=0, description="失败数量")
    created_items: List[dict] = Field(default=[], description="成功创建的项目")
    failed_items: List[dict] = Field(default=[], description="失败的项目")
    warnings: List[str] = Field(default=[], description="警告信息")


class ParsedHeaderBatchCreateRequest(BaseModel):
    """基于解析结果的批量创建请求模型"""
    headers: List[ParsedHeaderItem] = Field(..., min_items=1, max_items=100, description="请求头列表")
    target_type: TargetType = Field(..., description="目标类型")
    rule_config: Optional[PersistentRuleConfig] = Field(None, description="持久化规则配置")
    session_config: Optional[SessionConfig] = Field(None, description="会话配置")