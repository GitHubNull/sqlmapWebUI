"""
HeaderScope数据模型

定义作用域的数据结构，支持多维度匹配（协议、主机名、IP、端口、路径）。
作用域为可选配置，整个scope字段可以不填写。
scope字段为空（null或未提供）时，表示全局生效，对所有扫描任务生效。
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator
import re


class HeaderScope(BaseModel):
    """
    请求头作用域配置模型
    
    属性:
        protocol_pattern: 协议匹配模式，如 "http", "https", "http,https"。为空时默认所有协议生效
        host_pattern: 主机名匹配模式，支持通配符，如 "example.com", "*.example.com"
        ip_pattern: IP地址匹配模式，支持通配符，如 "192.168.1.100", "192.168.*"
        port_pattern: 端口匹配模式，如 "8080", "80,443,8080"
        path_pattern: 路径匹配模式，支持通配符，如 "/api/*", "/admin/.*"
        use_regex: 是否使用正则表达式匹配，默认为False（使用关键字匹配）
    
    匹配逻辑:
        - scope字段为空（null或未提供）时，表示全局生效，对所有扫描任务生效
        - 当scope字段存在时，所有非空字段必须同时匹配（AND逻辑）
        - scope内部空字段表示不限制该维度
        - scope内部所有字段都为空，等同于scope为null，表示全局生效
        - protocol_pattern为空时，默认所有协议（http/https）都生效
    """
    
    protocol_pattern: Optional[str] = Field(
        None,
        description="协议匹配模式（http/https），为空时默认所有协议生效"
    )
    host_pattern: Optional[str] = Field(
        None,
        description="主机名匹配模式，支持通配符*"
    )
    ip_pattern: Optional[str] = Field(
        None,
        description="IP地址匹配模式，支持通配符*"
    )
    port_pattern: Optional[str] = Field(
        None,
        description="端口匹配模式，支持逗号分隔多个端口"
    )
    path_pattern: Optional[str] = Field(
        None,
        description="路径匹配模式，支持通配符*"
    )
    use_regex: bool = Field(
        False,
        description="是否使用正则表达式匹配"
    )
    
    @field_validator('protocol_pattern')
    @classmethod
    def validate_protocol(cls, v: Optional[str]) -> Optional[str]:
        """验证协议模式"""
        if v is None or v.strip() == "":
            return None
        
        # 如果不使用正则，验证协议值
        if not v:
            return v
            
        # 支持逗号分隔的多个协议
        protocols = [p.strip().lower() for p in v.split(',')]
        valid_protocols = {'http', 'https'}
        
        # 检查是否可能是正则表达式（包含特殊字符）
        regex_chars = set('[]()|^$.*+?{}\\')
        if any(char in v for char in regex_chars):
            # 可能是正则表达式，不验证
            return v
        
        # 验证非正则模式的协议
        for proto in protocols:
            if proto and proto not in valid_protocols:
                raise ValueError(f"协议必须是http或https，当前值: {proto}")
        
        return v
    
    @field_validator('port_pattern')
    @classmethod
    def validate_port(cls, v: Optional[str]) -> Optional[str]:
        """验证端口模式"""
        if v is None or v.strip() == "":
            return None
        
        # 如果包含正则表达式字符，跳过验证
        regex_chars = set('[]()|^$.*+?{}\\')
        if any(char in v for char in regex_chars):
            return v
        
        # 支持逗号分隔的多个端口
        ports = [p.strip() for p in v.split(',')]
        for port in ports:
            if port:
                try:
                    port_num = int(port)
                    if not (1 <= port_num <= 65535):
                        raise ValueError(f"端口号必须在1-65535之间，当前值: {port_num}")
                except ValueError as e:
                    if "invalid literal" in str(e):
                        # 可能是通配符或其他模式
                        continue
                    raise
        
        return v
    
    @field_validator('host_pattern', 'ip_pattern', 'path_pattern')
    @classmethod
    def validate_pattern_length(cls, v: Optional[str]) -> Optional[str]:
        """验证模式字符串长度"""
        if v is None or v.strip() == "":
            return None
        
        max_length = 1000 if 'path' in cls.model_fields else 500
        if len(v) > max_length:
            raise ValueError(f"模式字符串长度不能超过{max_length}字符")
        
        return v
    
    def is_empty(self) -> bool:
        """
        判断作用域是否为空（所有字段都为None或空字符串）
        
        返回:
            True表示作用域为空，等同于全局生效
        """
        return all([
            not self.protocol_pattern or self.protocol_pattern.strip() == "",
            not self.host_pattern or self.host_pattern.strip() == "",
            not self.ip_pattern or self.ip_pattern.strip() == "",
            not self.port_pattern or self.port_pattern.strip() == "",
            not self.path_pattern or self.path_pattern.strip() == ""
        ])
    
    def to_dict(self) -> dict:
        """
        转换为字典格式
        
        返回:
            包含所有非None字段的字典
        """
        return {
            k: v for k, v in {
                "protocol_pattern": self.protocol_pattern,
                "host_pattern": self.host_pattern,
                "ip_pattern": self.ip_pattern,
                "port_pattern": self.port_pattern,
                "path_pattern": self.path_pattern,
                "use_regex": self.use_regex
            }.items() if v is not None
        }
    
    @classmethod
    def from_dict(cls, data: Optional[dict]) -> Optional['HeaderScope']:
        """
        从字典创建HeaderScope对象
        
        参数:
            data: 字典数据，可以为None
        
        返回:
            HeaderScope对象，如果data为None则返回None
        """
        if data is None:
            return None
        
        return cls(**data)
    
    class Config:
        json_schema_extra = {
            "example": {
                "protocol_pattern": "https",
                "host_pattern": "*.example.com",
                "port_pattern": "443",
                "path_pattern": "/api/*",
                "use_regex": False
            }
        }
