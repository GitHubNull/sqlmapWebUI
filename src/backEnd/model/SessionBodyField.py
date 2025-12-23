"""
SessionBodyField数据模型

定义会话Body字段的数据结构，用于管理HTTP请求Body中会话字段的动态替换。
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from pydantic import BaseModel, Field
from enum import Enum
import json

from model.HeaderScope import HeaderScope


class MatchStrategy(str, Enum):
    """Body字段匹配策略枚举"""
    KEYWORD = "KEYWORD"      # 关键字匹配
    REGEX = "REGEX"          # 正则表达式匹配
    JSONPATH = "JSONPATH"    # JSONPath表达式(用于JSON格式)
    XPATH = "XPATH"          # XPath表达式(用于XML格式)


class ReplaceStrategy(str, Enum):
    """字段替换策略枚举"""
    REPLACE = "REPLACE"      # 完全替换现有值
    APPEND = "APPEND"        # 追加到现有值后面
    PREPEND = "PREPEND"      # 前置到现有值前面
    CONDITIONAL = "CONDITIONAL"  # 条件性替换
    UPSERT = "UPSERT"        # 如果存在则替换，如果不存在则新增


class SessionBodyField(BaseModel):
    """会话Body字段模型(内存存储)"""
    id: Optional[int] = Field(None, description="唯一标识")
    field_name: str = Field(..., min_length=1, max_length=200, description="字段名称")
    field_value: str = Field(..., min_length=1, max_length=5000, description="字段值")
    match_strategy: MatchStrategy = Field(default=MatchStrategy.KEYWORD, description="匹配策略")
    match_pattern: Optional[str] = Field(None, max_length=1000, description="匹配模式(JSONPath/XPath/正则)")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
    content_types: Optional[List[str]] = Field(default=None, description="适用的Content-Type列表")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    is_active: bool = Field(default=True, description="是否启用")
    expires_at: datetime = Field(..., description="过期时间")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    updated_at: Optional[datetime] = Field(default=None, description="更新时间")
    source_ip: Optional[str] = Field(None, description="来源IP")
    scope: Optional[HeaderScope] = Field(default=None, description="作用域配置(可选，不填写时默认全局生效)")

    def is_expired(self) -> bool:
        """检查是否已过期"""
        return datetime.now() > self.expires_at

    def to_dict(self) -> dict:
        """转换为字典格式"""
        result = {
            "id": self.id,
            "field_name": self.field_name,
            "field_value": self.field_value,
            "match_strategy": self.match_strategy.value if isinstance(self.match_strategy, MatchStrategy) else self.match_strategy,
            "match_pattern": self.match_pattern,
            "replace_strategy": self.replace_strategy.value if isinstance(self.replace_strategy, ReplaceStrategy) else self.replace_strategy,
            "content_types": self.content_types,
            "priority": self.priority,
            "is_active": self.is_active,
            "expires_at": self.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None,
            "source_ip": self.source_ip
        }
        if self.scope is not None:
            result["scope"] = self.scope.to_dict()
        else:
            result["scope"] = None
        return result

    class Config:
        json_encoders = {
            datetime: lambda v: v.strftime('%Y-%m-%d %H:%M:%S') if v else None
        }


class SessionBodyFieldCreate(BaseModel):
    """创建会话Body字段的请求模型"""
    field_name: str = Field(..., min_length=1, max_length=200, description="字段名称")
    field_value: str = Field(..., min_length=1, max_length=5000, description="字段值")
    match_strategy: MatchStrategy = Field(default=MatchStrategy.KEYWORD, description="匹配策略")
    match_pattern: Optional[str] = Field(None, max_length=1000, description="匹配模式(JSONPath/XPath/正则)")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
    content_types: Optional[List[str]] = Field(default=None, description="适用的Content-Type列表")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    is_active: bool = Field(default=True, description="是否启用")
    ttl: int = Field(default=3600, ge=60, le=86400, description="生存时间(秒, 60-86400)")
    scope: Optional[HeaderScope] = Field(default=None, description="作用域配置(可选，不填写时默认全局生效)")


class SessionBodyFieldUpdate(BaseModel):
    """更新会话Body字段的请求模型"""
    field_name: str = Field(..., min_length=1, max_length=200, description="字段名称")
    field_value: str = Field(..., min_length=1, max_length=5000, description="字段值")
    match_strategy: MatchStrategy = Field(default=MatchStrategy.KEYWORD, description="匹配策略")
    match_pattern: Optional[str] = Field(None, max_length=1000, description="匹配模式(JSONPath/XPath/正则)")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
    content_types: Optional[List[str]] = Field(default=None, description="适用的Content-Type列表")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    is_active: bool = Field(default=True, description="是否启用")
    ttl: int = Field(default=3600, ge=60, le=86400, description="生存时间(秒, 60-86400)")
    scope: Optional[HeaderScope] = Field(default=None, description="作用域配置(可选，不填写时默认全局生效)")


class SessionBodyFieldBatchCreate(BaseModel):
    """批量创建会话Body字段的请求模型"""
    fields: List[SessionBodyFieldCreate] = Field(..., description="Body字段列表")


class SessionBodyFieldResponse(BaseModel):
    """会话Body字段响应模型"""
    id: Optional[int] = None
    field_name: str
    field_value: str
    match_strategy: str = "KEYWORD"
    match_pattern: Optional[str] = None
    replace_strategy: str = "REPLACE"
    content_types: Optional[List[str]] = None
    priority: int
    is_active: bool = True
    expires_at: str
    created_at: str
    updated_at: Optional[str] = None
    scope: Optional[dict] = None


class SessionBodyFieldListResponse(BaseModel):
    """会话Body字段列表响应模型"""
    client_ip: str
    fields: List[SessionBodyFieldResponse]
    total_count: int
