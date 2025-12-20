from datetime import datetime, timedelta
from typing import Optional, Dict, List
from pydantic import BaseModel, Field
from enum import Enum
import json

from model.HeaderScope import HeaderScope


class ReplaceStrategy(str, Enum):
    """请求头替换策略枚举"""
    REPLACE = "REPLACE"      # 完全替换现有值
    APPEND = "APPEND"        # 追加到现有值后面
    PREPEND = "PREPEND"      # 前置到现有值前面
    CONDITIONAL = "CONDITIONAL"  # 条件性替换
    UPSERT = "UPSERT"        # 如果存在则替换，如果不存在则新增


class SessionHeader(BaseModel):
    """会话性请求头模型(内存存储)"""
    id: Optional[int] = Field(None, description="唯一标识")
    header_name: str = Field(..., min_length=1, max_length=200, description="请求头名称")
    header_value: str = Field(..., min_length=1, max_length=2000, description="请求头值")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
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
            "header_name": self.header_name,
            "header_value": self.header_value,
            "replace_strategy": self.replace_strategy.value if isinstance(self.replace_strategy, ReplaceStrategy) else self.replace_strategy,
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


class SessionHeaderCreate(BaseModel):
    """创建会话性请求头的请求模型"""
    header_name: str = Field(..., min_length=1, max_length=200, description="请求头名称")
    header_value: str = Field(..., min_length=1, max_length=2000, description="请求头值")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    is_active: bool = Field(default=True, description="是否启用")
    ttl: int = Field(default=3600, ge=60, le=86400, description="生存时间(秒, 60-86400)")
    scope: Optional[HeaderScope] = Field(default=None, description="作用域配置(可选，不填写时默认全局生效)")


class SessionHeaderBatchCreate(BaseModel):
    """批量创建会话性请求头的请求模型"""
    headers: List[SessionHeaderCreate] = Field(..., description="请求头列表")


class SessionHeaderResponse(BaseModel):
    """会话性请求头响应模型"""
    id: Optional[int] = None  # 唯一标识
    header_name: str
    header_value: str
    replace_strategy: str = "REPLACE"  # 替换策略
    priority: int
    is_active: bool = True  # 是否启用
    expires_at: str
    created_at: str
    updated_at: Optional[str] = None  # 更新时间
    scope: Optional[dict] = None  # 返回字典格式的scope


class SessionHeaderListResponse(BaseModel):
    """会话性请求头列表响应模型"""
    client_ip: str
    headers: List[SessionHeaderResponse]
    total_count: int