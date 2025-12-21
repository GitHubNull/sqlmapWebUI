"""
扫描配置预设模型
用于存储常用配置、默认配置、历史配置
配置字段与sqlmap的optiondict.py保持一致
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class PresetType(str, Enum):
    """预设类型"""
    DEFAULT = "default"      # 默认配置
    PRESET = "preset"        # 常用配置
    HISTORY = "history"      # 历史配置


class ScanOptions(BaseModel):
    """
    扫描选项模型
    字段名与sqlmap的optiondict.py保持一致
    """
    # ==================== Detection 检测选项 ====================
    level: int = Field(default=1, ge=1, le=5, description="检测级别 (1-5)")
    risk: int = Field(default=1, ge=1, le=3, description="风险级别 (1-3)")
    string: Optional[str] = Field(default=None, description="页面匹配字符串")
    notString: Optional[str] = Field(default=None, description="页面不匹配字符串")
    regexp: Optional[str] = Field(default=None, description="正则匹配")
    code: Optional[int] = Field(default=None, description="HTTP响应码")
    smart: bool = Field(default=False, description="智能检测")
    textOnly: bool = Field(default=False, description="仅文本比较")
    titles: bool = Field(default=False, description="基于标题比较")
    
    # ==================== Injection 注入选项 ====================
    testParameter: Optional[str] = Field(default=None, description="指定测试参数 (-p)")
    skip: Optional[str] = Field(default=None, description="跳过参数")
    skipStatic: bool = Field(default=False, description="跳过静态参数")
    paramExclude: Optional[str] = Field(default=None, description="排除参数")
    dbms: Optional[str] = Field(default=None, description="数据库类型")
    os: Optional[str] = Field(default=None, description="操作系统")
    prefix: Optional[str] = Field(default=None, description="注入前缀")
    suffix: Optional[str] = Field(default=None, description="注入后缀")
    tamper: Optional[str] = Field(default=None, description="篡改脚本")
    
    # ==================== Techniques 技术选项 ====================
    technique: str = Field(default="BEUSTQ", description="注入技术 (BEUSTQ)")
    timeSec: int = Field(default=5, ge=1, le=60, description="时间盲注延迟(秒)")
    
    # ==================== Request 请求选项 ====================
    timeout: int = Field(default=30, ge=1, description="请求超时(秒)")
    retries: int = Field(default=3, ge=0, description="重试次数")
    delay: float = Field(default=0, ge=0, description="请求延迟(秒)")
    randomAgent: bool = Field(default=False, description="随机User-Agent")
    proxy: Optional[str] = Field(default=None, description="代理")
    tor: bool = Field(default=False, description="使用Tor")
    
    # ==================== Optimization 优化选项 ====================
    optimize: bool = Field(default=False, description="使用所有优化选项")
    predictOutput: bool = Field(default=False, description="预测输出")
    keepAlive: bool = Field(default=False, description="保持连接")
    nullConnection: bool = Field(default=False, description="空连接")
    threads: int = Field(default=1, ge=1, le=10, description="线程数")
    
    # ==================== Enumeration 枚举选项 ====================
    getBanner: bool = Field(default=False, description="获取Banner")
    getCurrentUser: bool = Field(default=False, description="获取当前用户")
    getCurrentDb: bool = Field(default=False, description="获取当前数据库")
    getHostname: bool = Field(default=False, description="获取主机名")
    isDba: bool = Field(default=False, description="是否DBA")
    getUsers: bool = Field(default=False, description="获取所有用户")
    getPasswordHashes: bool = Field(default=False, description="获取密码哈希")
    getPrivileges: bool = Field(default=False, description="获取权限")
    getRoles: bool = Field(default=False, description="获取角色")
    getDbs: bool = Field(default=False, description="获取所有数据库")
    getTables: bool = Field(default=False, description="获取所有表")
    getColumns: bool = Field(default=False, description="获取所有列")
    dumpTable: bool = Field(default=False, description="导出表")
    dumpAll: bool = Field(default=False, description="导出所有")
    db: Optional[str] = Field(default=None, description="指定数据库")
    tbl: Optional[str] = Field(default=None, description="指定表")
    col: Optional[str] = Field(default=None, description="指定列")
    
    # ==================== General 通用选项 ====================
    batch: bool = Field(default=True, description="非交互模式")
    forms: bool = Field(default=False, description="解析表单")
    crawlDepth: int = Field(default=0, ge=0, description="爬取深度(0=禁用)")
    flushSession: bool = Field(default=False, description="刷新会话")
    freshQueries: bool = Field(default=False, description="刷新查询")
    verbose: int = Field(default=1, ge=0, le=6, description="详细级别 (0-6)")
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，只包含非默认值"""
        result = {}
        default_model = ScanOptions()
        for field_name, field_value in self:
            default_value = getattr(default_model, field_name)
            if field_value != default_value and field_value is not None:
                result[field_name] = field_value
        return result
    
    def to_full_dict(self) -> Dict[str, Any]:
        """转换为完整字典"""
        return self.model_dump()


class ScanPreset(BaseModel):
    """扫描配置预设"""
    id: Optional[int] = Field(default=None, description="预设ID")
    name: str = Field(..., min_length=1, max_length=100, description="预设名称")
    description: Optional[str] = Field(default=None, max_length=500, description="预设描述")
    preset_type: PresetType = Field(default=PresetType.PRESET, description="预设类型")
    options: ScanOptions = Field(default_factory=ScanOptions, description="扫描选项")
    parameter_string: Optional[str] = Field(default=None, description="命令行参数字符串(与BurpSuite兼容)")
    is_active: bool = Field(default=True, description="是否启用")
    created_at: Optional[datetime] = Field(default=None, description="创建时间")
    updated_at: Optional[datetime] = Field(default=None, description="更新时间")
    last_used_at: Optional[datetime] = Field(default=None, description="最后使用时间")
    use_count: int = Field(default=0, ge=0, description="使用次数")
    
    model_config = {
        "use_enum_values": True,
        "json_encoders": {
            datetime: lambda v: v.isoformat() if v else None
        }
    }
    
    def model_dump(self, **kwargs):
        """Override model_dump to convert datetime to string"""
        data = super().model_dump(**kwargs)
        # Convert datetime fields to ISO format strings
        for field in ['created_at', 'updated_at', 'last_used_at']:
            if field in data and data[field] is not None:
                if isinstance(data[field], datetime):
                    data[field] = data[field].isoformat()
        return data


class ScanPresetCreate(BaseModel):
    """创建扫描配置预设请求"""
    name: str = Field(..., min_length=1, max_length=100, description="预设名称")
    description: Optional[str] = Field(default=None, max_length=500, description="预设描述")
    preset_type: PresetType = Field(default=PresetType.PRESET, description="预设类型")
    options: Dict[str, Any] = Field(default_factory=dict, description="扫描选项")
    parameter_string: Optional[str] = Field(default=None, description="命令行参数字符串")
    
    class Config:
        use_enum_values = True


class ScanPresetUpdate(BaseModel):
    """更新扫描配置预设请求"""
    name: Optional[str] = Field(default=None, min_length=1, max_length=100, description="预设名称")
    description: Optional[str] = Field(default=None, max_length=500, description="预设描述")
    options: Optional[Dict[str, Any]] = Field(default=None, description="扫描选项")
    parameter_string: Optional[str] = Field(default=None, description="命令行参数字符串")
    is_active: Optional[bool] = Field(default=None, description="是否启用")
    
    class Config:
        use_enum_values = True


class ScanPresetListResponse(BaseModel):
    """扫描配置预设列表响应"""
    presets: List[ScanPreset] = Field(default_factory=list, description="预设列表")
    total: int = Field(default=0, description="总数")
    default_preset: Optional[ScanPreset] = Field(default=None, description="默认配置")


# ==================== 预定义配置 ====================

def create_default_preset() -> ScanPreset:
    """创建默认配置"""
    return ScanPreset(
        id=0,
        name="默认配置",
        description="系统默认扫描配置",
        preset_type=PresetType.DEFAULT,
        options=ScanOptions(),
        is_active=True,
        created_at=datetime.now(),
        updated_at=datetime.now()
    )


def create_quick_scan_preset() -> ScanPreset:
    """创建快速扫描配置"""
    return ScanPreset(
        name="快速扫描",
        description="快速扫描 - 仅基础检测",
        preset_type=PresetType.PRESET,
        options=ScanOptions(
            level=1,
            risk=1,
            technique="B",
            batch=True
        )
    )


def create_deep_scan_preset() -> ScanPreset:
    """创建深度扫描配置"""
    return ScanPreset(
        name="深度扫描",
        description="深度扫描 - 全面检测",
        preset_type=PresetType.PRESET,
        options=ScanOptions(
            level=5,
            risk=3,
            technique="BEUSTQ",
            batch=True,
            threads=3
        )
    )


def create_safe_scan_preset() -> ScanPreset:
    """创建安全扫描配置"""
    return ScanPreset(
        name="安全扫描",
        description="安全扫描 - 低风险检测",
        preset_type=PresetType.PRESET,
        options=ScanOptions(
            level=3,
            risk=1,
            technique="BEU",
            batch=True,
            delay=1
        )
    )
