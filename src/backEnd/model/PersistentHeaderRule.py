from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import json

from model.HeaderScope import HeaderScope


class ReplaceStrategy(str, Enum):
    """请求头替换策略枚举"""
    REPLACE = "REPLACE"      # 完全替换现有值
    APPEND = "APPEND"        # 追加到现有值后面
    PREPEND = "PREPEND"      # 前置到现有值前面
    CONDITIONAL = "CONDITIONAL"  # 条件性替换
    UPSERT = "UPSERT"        # 如果存在则替换，如果不存在则新增


class PersistentHeaderRule(BaseModel):
    """持久化请求头规则数据模型"""
    id: Optional[int] = None
    name: str = Field(..., min_length=1, max_length=100, description="规则名称")
    header_name: str = Field(..., min_length=1, max_length=200, description="请求头名称")
    header_value: str = Field(..., min_length=1, max_length=1000, description="请求头值")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
    match_condition: Optional[str] = Field(default=None, max_length=500, description="匹配条件(可选)")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    is_active: bool = Field(default=True, description="是否启用")
    scope: Optional[HeaderScope] = Field(default=None, description="作用域配置(可选，不填写时默认全局生效)")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def get_scope_config_json(self) -> Optional[str]:
        """将scope对象序列化为JSON字符串，用于数据库存储"""
        if self.scope is None:
            return None
        return json.dumps(self.scope.to_dict(), ensure_ascii=False)
    
    @classmethod
    def from_db_row(cls, row: dict) -> 'PersistentHeaderRule':
        """从数据库行创建对象，处理scope_config的反序列化"""
        # 复制数据避免修改原始数据
        data = dict(row)
        
        # 处理scope_config字段
        scope_config_json = data.pop('scope_config', None)
        if scope_config_json:
            try:
                scope_data = json.loads(scope_config_json)
                data['scope'] = HeaderScope.from_dict(scope_data)
            except (json.JSONDecodeError, Exception) as e:
                # 解析失败，记录警告，scope设为None（全局生效）
                import logging
                logging.warning(f"解析scope_config失败: {e}, 将scope设为None（全局生效）")
                data['scope'] = None
        else:
            data['scope'] = None
        
        return cls(**data)

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.strftime('%Y-%m-%d %H:%M:%S') if v else None
        }


class PersistentHeaderRuleCreate(BaseModel):
    """创建持久化请求头规则的请求模型"""
    name: str = Field(..., min_length=1, max_length=100, description="规则名称")
    header_name: str = Field(..., min_length=1, max_length=200, description="请求头名称")
    header_value: str = Field(..., min_length=1, max_length=1000, description="请求头值")
    replace_strategy: ReplaceStrategy = Field(default=ReplaceStrategy.REPLACE, description="替换策略")
    match_condition: Optional[str] = Field(default=None, max_length=500, description="匹配条件(可选)")
    priority: int = Field(default=0, ge=0, le=100, description="优先级(0-100)")
    is_active: bool = Field(default=True, description="是否启用")
    scope: Optional[HeaderScope] = Field(default=None, description="作用域配置(可选，不填写时默认全局生效)")


class PersistentHeaderRuleUpdate(BaseModel):
    """更新持久化请求头规则的请求模型"""
    name: Optional[str] = Field(None, min_length=1, max_length=100, description="规则名称")
    header_name: Optional[str] = Field(None, min_length=1, max_length=200, description="请求头名称")
    header_value: Optional[str] = Field(None, min_length=1, max_length=1000, description="请求头值")
    replace_strategy: Optional[ReplaceStrategy] = Field(None, description="替换策略")
    match_condition: Optional[str] = Field(None, max_length=500, description="匹配条件")
    priority: Optional[int] = Field(None, ge=0, le=100, description="优先级")
    is_active: Optional[bool] = Field(None, description="是否启用")
    scope: Optional[HeaderScope] = Field(None, description="作用域配置(可选)")


class PersistentHeaderRuleResponse(BaseModel):
    """持久化请求头规则响应模型"""
    id: int
    name: str
    header_name: str
    header_value: str
    replace_strategy: str
    match_condition: Optional[str]
    priority: int
    is_active: bool
    scope: Optional[dict] = None  # 返回字典格式的scope
    created_at: str
    updated_at: str