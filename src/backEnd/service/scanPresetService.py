"""
扫描配置预设服务
提供扫描配置预设的业务逻辑
"""
import logging
from typing import List, Optional, Dict, Any

from model.ScanPreset import (
    ScanPreset, ScanPresetCreate, ScanPresetUpdate,
    ScanOptions, PresetType, ScanPresetListResponse
)
from model.ScanPresetDatabase import get_scan_preset_db

logger = logging.getLogger(__name__)


class ScanPresetService:
    """扫描配置预设服务"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        self._db = None
    
    @property
    def db(self):
        if self._db is None:
            self._db = get_scan_preset_db()
        return self._db
    
    def get_all_presets(self, include_inactive: bool = False) -> ScanPresetListResponse:
        """获取所有预设配置"""
        presets = self.db.get_all_presets(include_inactive)
        default_preset = self.db.get_default_preset()
        
        return ScanPresetListResponse(
            presets=presets,
            total=len(presets),
            default_preset=default_preset
        )
    
    def get_presets_by_type(self, preset_type: PresetType) -> List[ScanPreset]:
        """根据类型获取预设配置"""
        return self.db.get_presets_by_type(preset_type)
    
    def get_preset_configs(self) -> List[ScanPreset]:
        """获取常用配置列表"""
        return self.db.get_presets_by_type(PresetType.PRESET)
    
    def get_history_configs(self, limit: int = 20) -> List[ScanPreset]:
        """获取历史配置列表"""
        return self.db.get_history_presets(limit)
    
    def get_default_preset(self) -> Optional[ScanPreset]:
        """获取默认配置"""
        return self.db.get_default_preset()
    
    def get_preset_by_id(self, preset_id: int) -> Optional[ScanPreset]:
        """根据ID获取预设配置"""
        return self.db.get_preset_by_id(preset_id)
    
    def create_preset(self, data: ScanPresetCreate) -> Optional[ScanPreset]:
        """创建新的预设配置"""
        # 验证名称不能为空
        if not data.name or not data.name.strip():
            logger.warning("Preset name cannot be empty")
            return None
        
        # 检查名称是否已存在
        existing = self.db.get_preset_by_name(data.name)
        if existing:
            logger.warning(f"Preset with name '{data.name}' already exists")
            return None
        
        return self.db.create_preset(data)
    
    def update_preset(self, preset_id: int, data: ScanPresetUpdate) -> Optional[ScanPreset]:
        """更新预设配置"""
        # 检查预设是否存在
        existing = self.db.get_preset_by_id(preset_id)
        if not existing:
            logger.warning(f"Preset with id {preset_id} not found")
            return None
        
        # 不允许修改默认配置的类型
        if existing.preset_type == PresetType.DEFAULT:
            # 只允许修改选项，不允许修改名称
            if data.name is not None and data.name != existing.name:
                logger.warning("Cannot change default preset name")
                data.name = None
        
        # 如果修改名称，检查新名称是否已存在
        if data.name and data.name != existing.name:
            name_exists = self.db.get_preset_by_name(data.name)
            if name_exists:
                logger.warning(f"Preset with name '{data.name}' already exists")
                return None
        
        return self.db.update_preset(preset_id, data)
    
    def delete_preset(self, preset_id: int) -> bool:
        """删除预设配置"""
        # 检查预设是否存在
        existing = self.db.get_preset_by_id(preset_id)
        if not existing:
            logger.warning(f"Preset with id {preset_id} not found")
            return False
        
        # 不允许删除默认配置
        if existing.preset_type == PresetType.DEFAULT:
            logger.warning("Cannot delete default preset")
            return False
        
        return self.db.delete_preset(preset_id)
    
    def update_default_preset(self, options: Dict[str, Any]) -> Optional[ScanPreset]:
        """更新默认配置的选项"""
        default_preset = self.db.get_default_preset()
        if not default_preset:
            logger.warning("Default preset not found")
            return None
        
        return self.db.update_preset(default_preset.id, ScanPresetUpdate(options=options))
    
    def record_preset_usage(self, preset_id: int):
        """记录预设使用"""
        self.db.record_preset_usage(preset_id)
    
    def add_to_history(self, name: str, options: Dict[str, Any]) -> Optional[ScanPreset]:
        """添加配置到历史记录"""
        return self.db.add_to_history(name, options)
    
    def get_all_config_options(self) -> Dict[str, Any]:
        """
        获取所有可选配置（用于下拉菜单）
        返回格式与BurpSuite插件类似：
        - 默认配置
        - 常用配置列表
        - 历史配置列表
        """
        default_preset = self.get_default_preset()
        preset_configs = self.get_preset_configs()
        history_configs = self.get_history_configs()
        
        return {
            "default": default_preset,
            "presets": preset_configs,
            "history": history_configs
        }
    
    def apply_preset_to_options(self, preset_id: int, base_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        将预设配置应用到基础选项上
        返回合并后的选项字典
        """
        preset = self.get_preset_by_id(preset_id)
        if not preset:
            return base_options or {}
        
        # 记录使用
        self.record_preset_usage(preset_id)
        
        # 获取预设选项
        preset_options = preset.options.to_dict()
        
        # 如果有基础选项，合并
        if base_options:
            result = {**base_options}
            result.update(preset_options)
            return result
        
        return preset_options


# 全局服务实例
scanPresetService = ScanPresetService()
