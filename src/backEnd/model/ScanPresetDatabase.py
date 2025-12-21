"""
扫描配置预设数据库
管理扫描配置预设的持久化存储
"""
import os
import json
from datetime import datetime
from typing import List, Optional

from third_lib.sqlmap.lib.core.data import logger
from third_lib.sqlmap.lib.core.common import getSafeExString
from model.Database import Database
from model.ScanPreset import (
    ScanPreset, ScanPresetCreate, ScanPresetUpdate, 
    ScanOptions, PresetType,
    create_default_preset, create_quick_scan_preset,
    create_deep_scan_preset, create_safe_scan_preset
)


# 定义标准的列顺序（用于SELECT查询，确保列顺序一致）
_PRESET_COLUMNS = "id, name, description, preset_type, options, parameter_string, is_active, created_at, updated_at, last_used_at, use_count"


class ScanPresetDatabase(Database):
    """扫描配置预设数据库"""
    
    _instance = None
    
    def __new__(cls, database_path=None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, database_path=None):
        if self._initialized:
            return
            
        # 如果没有指定数据库路径，使用默认路径
        if database_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_dir = os.path.dirname(current_dir)
            database_path = os.path.join(project_dir, "scan_presets.db")
        
        super().__init__(database_path)
        self.database_path = database_path
        
        # 连接数据库并初始化锁
        self.connect(who="scan-preset")
        
        self._initialized = True
        
    def init(self):
        """初始化数据库表"""
        # 创建扫描配置预设表
        self.execute("""
            CREATE TABLE IF NOT EXISTS scan_presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                preset_type TEXT NOT NULL DEFAULT 'preset',
                options TEXT NOT NULL DEFAULT '{}',
                parameter_string TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                use_count INTEGER DEFAULT 0
            )
        """)
        
        # 表迁移：添加 parameter_string 列（如果不存在）
        self._migrate_add_parameter_string_column()
        
        # 创建索引
        self.execute("CREATE INDEX IF NOT EXISTS idx_scan_presets_type ON scan_presets(preset_type)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_scan_presets_active ON scan_presets(is_active)")
        self.execute("CREATE INDEX IF NOT EXISTS idx_scan_presets_name ON scan_presets(name)")
        
        # 初始化默认配置
        self._init_default_presets()
        
        logger.info(f"Scan preset database initialized at {self.database_path}")
    
    def _migrate_add_parameter_string_column(self):
        """表迁移：添加 parameter_string 列"""
        try:
            # 检查列是否存在
            cursor = self.only_execute("PRAGMA table_info(scan_presets)")
            if cursor:
                columns = [row[1] for row in cursor.fetchall()]
                if 'parameter_string' not in columns:
                    self.execute("ALTER TABLE scan_presets ADD COLUMN parameter_string TEXT")
                    logger.info("Added parameter_string column to scan_presets table")
        except Exception as e:
            logger.warning(f"Migration check for parameter_string column: {getSafeExString(e)}")
    
    def _init_default_presets(self):
        """初始化默认预设配置"""
        try:
            # 检查是否已有默认配置
            cursor = self.only_execute(
                "SELECT COUNT(*) FROM scan_presets WHERE preset_type = ?",
                (PresetType.DEFAULT.value,)
            )
            if cursor:
                count = cursor.fetchone()[0]
                if count > 0:
                    return  # 已有默认配置，跳过初始化
            
            # 创建默认配置
            default_presets = [
                create_default_preset(),
                create_quick_scan_preset(),
                create_deep_scan_preset(),
                create_safe_scan_preset()
            ]
            
            for preset in default_presets:
                self._insert_preset(preset)
                
            logger.info("Default scan presets initialized")
            
        except Exception as e:
            logger.warning(f"Failed to init default presets: {getSafeExString(e)}")
    
    def _insert_preset(self, preset: ScanPreset) -> Optional[int]:
        """插入预设配置"""
        try:
            now = datetime.now().isoformat()
            options_json = json.dumps(preset.options.to_full_dict())
            
            self.execute("""
                INSERT INTO scan_presets (name, description, preset_type, options, parameter_string, is_active, created_at, updated_at, use_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                preset.name,
                preset.description,
                preset.preset_type if isinstance(preset.preset_type, str) else preset.preset_type.value,
                options_json,
                preset.parameter_string,
                1 if preset.is_active else 0,
                now,
                now,
                preset.use_count
            ))
            
            # execute() 对于 INSERT 语句返回 None，直接使用 self.cursor.lastrowid
            return self.cursor.lastrowid
            
        except Exception as e:
            logger.error(f"Failed to insert preset: {getSafeExString(e)}")
            return None
    
    def create_preset(self, data: ScanPresetCreate) -> Optional[ScanPreset]:
        """创建新的预设配置"""
        try:
            # 验证选项
            options = ScanOptions(**data.options) if data.options else ScanOptions()
            
            preset = ScanPreset(
                name=data.name,
                description=data.description,
                preset_type=data.preset_type,
                options=options,
                parameter_string=data.parameter_string,
                is_active=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            preset_id = self._insert_preset(preset)
            if preset_id:
                preset.id = preset_id
                return preset
            return None
            
        except Exception as e:
            logger.error(f"Failed to create preset: {getSafeExString(e)}")
            return None
    
    def get_preset_by_id(self, preset_id: int) -> Optional[ScanPreset]:
        """根据ID获取预设配置"""
        try:
            cursor = self.only_execute(
                f"SELECT {_PRESET_COLUMNS} FROM scan_presets WHERE id = ?",
                (preset_id,)
            )
            if cursor:
                row = cursor.fetchone()
                if row:
                    return self._row_to_preset(row)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get preset by id: {getSafeExString(e)}")
            return None
    
    def get_preset_by_name(self, name: str) -> Optional[ScanPreset]:
        """根据名称获取预设配置"""
        try:
            cursor = self.only_execute(
                f"SELECT {_PRESET_COLUMNS} FROM scan_presets WHERE name = ?",
                (name,)
            )
            if cursor:
                row = cursor.fetchone()
                if row:
                    return self._row_to_preset(row)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get preset by name: {getSafeExString(e)}")
            return None
    
    def get_all_presets(self, include_inactive: bool = False) -> List[ScanPreset]:
        """获取所有预设配置"""
        try:
            if include_inactive:
                cursor = self.only_execute(
                    f"SELECT {_PRESET_COLUMNS} FROM scan_presets ORDER BY preset_type, use_count DESC, name"
                )
            else:
                cursor = self.only_execute(
                    f"SELECT {_PRESET_COLUMNS} FROM scan_presets WHERE is_active = 1 ORDER BY preset_type, use_count DESC, name"
                )
            
            presets = []
            if cursor:
                for row in cursor.fetchall():
                    preset = self._row_to_preset(row)
                    if preset:
                        presets.append(preset)
            return presets
            
        except Exception as e:
            logger.error(f"Failed to get all presets: {getSafeExString(e)}")
            return []
    
    def get_presets_by_type(self, preset_type: PresetType, include_inactive: bool = False) -> List[ScanPreset]:
        """根据类型获取预设配置"""
        try:
            type_value = preset_type.value if isinstance(preset_type, PresetType) else preset_type
            
            if include_inactive:
                cursor = self.only_execute(
                    f"SELECT {_PRESET_COLUMNS} FROM scan_presets WHERE preset_type = ? ORDER BY use_count DESC, name",
                    (type_value,)
                )
            else:
                cursor = self.only_execute(
                    f"SELECT {_PRESET_COLUMNS} FROM scan_presets WHERE preset_type = ? AND is_active = 1 ORDER BY use_count DESC, name",
                    (type_value,)
                )
            
            presets = []
            if cursor:
                for row in cursor.fetchall():
                    preset = self._row_to_preset(row)
                    if preset:
                        presets.append(preset)
            return presets
            
        except Exception as e:
            logger.error(f"Failed to get presets by type: {getSafeExString(e)}")
            return []
    
    def get_default_preset(self) -> Optional[ScanPreset]:
        """获取默认配置"""
        presets = self.get_presets_by_type(PresetType.DEFAULT)
        return presets[0] if presets else None
    
    def get_history_presets(self, limit: int = 20) -> List[ScanPreset]:
        """获取历史配置"""
        try:
            cursor = self.only_execute(
                f"""SELECT {_PRESET_COLUMNS} FROM scan_presets 
                   WHERE preset_type = ? AND is_active = 1 
                   ORDER BY last_used_at DESC 
                   LIMIT ?""",
                (PresetType.HISTORY.value, limit)
            )
            
            presets = []
            if cursor:
                for row in cursor.fetchall():
                    preset = self._row_to_preset(row)
                    if preset:
                        presets.append(preset)
            return presets
            
        except Exception as e:
            logger.error(f"Failed to get history presets: {getSafeExString(e)}")
            return []
    
    def update_preset(self, preset_id: int, data: ScanPresetUpdate) -> Optional[ScanPreset]:
        """更新预设配置"""
        try:
            # 获取现有配置
            existing = self.get_preset_by_id(preset_id)
            if not existing:
                return None
            
            # 构建更新字段
            updates = []
            params = []
            
            if data.name is not None:
                updates.append("name = ?")
                params.append(data.name)
                
            if data.description is not None:
                updates.append("description = ?")
                params.append(data.description)
                
            if data.options is not None:
                options = ScanOptions(**data.options)
                updates.append("options = ?")
                params.append(json.dumps(options.to_full_dict()))
            
            if data.parameter_string is not None:
                updates.append("parameter_string = ?")
                params.append(data.parameter_string)
                
            if data.is_active is not None:
                updates.append("is_active = ?")
                params.append(1 if data.is_active else 0)
            
            if not updates:
                return existing
            
            # 更新时间
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            
            params.append(preset_id)
            
            self.execute(
                f"UPDATE scan_presets SET {', '.join(updates)} WHERE id = ?",
                tuple(params)
            )
            
            return self.get_preset_by_id(preset_id)
            
        except Exception as e:
            logger.error(f"Failed to update preset: {getSafeExString(e)}")
            return None
    
    def delete_preset(self, preset_id: int) -> bool:
        """删除预设配置"""
        try:
            # 不允许删除默认配置
            preset = self.get_preset_by_id(preset_id)
            if preset and preset.preset_type == PresetType.DEFAULT:
                logger.warning("Cannot delete default preset")
                return False
            
            self.execute("DELETE FROM scan_presets WHERE id = ?", (preset_id,))
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete preset: {getSafeExString(e)}")
            return False
    
    def record_preset_usage(self, preset_id: int):
        """记录预设使用"""
        try:
            now = datetime.now().isoformat()
            self.execute(
                "UPDATE scan_presets SET use_count = use_count + 1, last_used_at = ? WHERE id = ?",
                (now, preset_id)
            )
        except Exception as e:
            logger.error(f"Failed to record preset usage: {getSafeExString(e)}")
    
    def add_to_history(self, name: str, options: dict, max_history: int = 20) -> Optional[ScanPreset]:
        """添加到历史记录"""
        try:
            # 检查是否已存在相同名称的历史记录
            existing = self.get_preset_by_name(name)
            if existing and existing.preset_type == PresetType.HISTORY:
                # 更新现有记录
                return self.update_preset(existing.id, ScanPresetUpdate(
                    options=options
                ))
            
            # 创建新历史记录
            preset = self.create_preset(ScanPresetCreate(
                name=name,
                description=f"历史配置 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                preset_type=PresetType.HISTORY,
                options=options
            ))
            
            if preset:
                # 记录使用
                self.record_preset_usage(preset.id)
                
                # 清理超出限制的历史记录
                self._cleanup_old_history(max_history)
            
            return preset
            
        except Exception as e:
            logger.error(f"Failed to add to history: {getSafeExString(e)}")
            return None
    
    def _cleanup_old_history(self, max_history: int):
        """清理旧的历史记录"""
        try:
            # 获取需要保留的历史记录ID
            cursor = self.only_execute(
                """SELECT id FROM scan_presets 
                   WHERE preset_type = ? 
                   ORDER BY last_used_at DESC 
                   LIMIT ?""",
                (PresetType.HISTORY.value, max_history)
            )
            
            if cursor:
                keep_ids = [row[0] for row in cursor.fetchall()]
                if keep_ids:
                    placeholders = ','.join('?' * len(keep_ids))
                    self.execute(
                        f"DELETE FROM scan_presets WHERE preset_type = ? AND id NOT IN ({placeholders})",
                        (PresetType.HISTORY.value, *keep_ids)
                    )
                    
        except Exception as e:
            logger.error(f"Failed to cleanup old history: {getSafeExString(e)}")
    
    def _row_to_preset(self, row) -> Optional[ScanPreset]:
        """将数据库行转换为预设对象
        
        列顺序(由_PRESET_COLUMNS定义): 
        id(0), name(1), description(2), preset_type(3), options(4), 
        parameter_string(5), is_active(6), created_at(7), updated_at(8), 
        last_used_at(9), use_count(10)
        """
        try:
            options_dict = json.loads(row[4]) if row[4] else {}
            options = ScanOptions(**options_dict)
            
            # 安全获取 parameter_string（确保是字符串类型）
            param_str = row[5] if len(row) > 5 else None
            if param_str is not None and not isinstance(param_str, str):
                param_str = None  # 类型不对时设为None
            
            # 安全获取 is_active
            is_active = True
            if len(row) > 6:
                is_active = bool(row[6]) if isinstance(row[6], (int, bool)) else True
            
            # 安全获取时间字段
            created_at = None
            if len(row) > 7 and row[7] and isinstance(row[7], str):
                try:
                    created_at = datetime.fromisoformat(row[7])
                except ValueError:
                    pass
            
            updated_at = None
            if len(row) > 8 and row[8] and isinstance(row[8], str):
                try:
                    updated_at = datetime.fromisoformat(row[8])
                except ValueError:
                    pass
            
            last_used_at = None
            if len(row) > 9 and row[9] and isinstance(row[9], str):
                try:
                    last_used_at = datetime.fromisoformat(row[9])
                except ValueError:
                    pass
            
            # 安全获取 use_count
            use_count = 0
            if len(row) > 10 and row[10] is not None:
                if isinstance(row[10], int):
                    use_count = row[10]
                elif isinstance(row[10], str) and row[10].isdigit():
                    use_count = int(row[10])
            
            return ScanPreset(
                id=row[0],
                name=row[1],
                description=row[2],
                preset_type=row[3],
                options=options,
                parameter_string=param_str,
                is_active=is_active,
                created_at=created_at,
                updated_at=updated_at,
                last_used_at=last_used_at,
                use_count=use_count
            )
        except Exception as e:
            logger.error(f"Failed to convert row to preset: {getSafeExString(e)}")
            return None


# 全局单例
_scan_preset_db: Optional[ScanPresetDatabase] = None


def get_scan_preset_db() -> ScanPresetDatabase:
    """获取扫描配置预设数据库实例"""
    global _scan_preset_db
    if _scan_preset_db is None:
        _scan_preset_db = ScanPresetDatabase()
        _scan_preset_db.init()
    return _scan_preset_db
