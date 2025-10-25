from datetime import datetime, timedelta
from typing import Optional, Dict, List
from pydantic import BaseModel, Field


class SessionHeader(BaseModel):
    """会话性请求头模型(内存存储)"""
    header_name: str = Field(..., min_length=1, max_length=200, description="请求头名称")
    header_value: str = Field(..., min_length=1, max_length=2000, description="请求头值")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    expires_at: datetime = Field(..., description="过期时间")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    source_ip: Optional[str] = Field(None, description="来源IP")

    def is_expired(self) -> bool:
        """检查是否已过期"""
        return datetime.now() > self.expires_at

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "header_name": self.header_name,
            "header_value": self.header_value,
            "priority": self.priority,
            "expires_at": self.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "source_ip": self.source_ip
        }

    class Config:
        json_encoders = {
            datetime: lambda v: v.strftime('%Y-%m-%d %H:%M:%S') if v else None
        }


class SessionHeaderCreate(BaseModel):
    """创建会话性请求头的请求模型"""
    header_name: str = Field(..., min_length=1, max_length=200, description="请求头名称")
    header_value: str = Field(..., min_length=1, max_length=2000, description="请求头值")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    ttl: int = Field(default=3600, ge=60, le=86400, description="生存时间(秒, 60-86400)")


class SessionHeaderBatchCreate(BaseModel):
    """批量创建会话性请求头的请求模型"""
    headers: List[SessionHeaderCreate] = Field(..., min_items=1, max_items=20, description="请求头列表")


class SessionHeaderResponse(BaseModel):
    """会话性请求头响应模型"""
    header_name: str
    header_value: str
    priority: int
    expires_at: str
    created_at: str


class SessionHeaderListResponse(BaseModel):
    """会话性请求头列表响应模型"""
    client_ip: str
    headers: List[SessionHeaderResponse]
    total_count: int