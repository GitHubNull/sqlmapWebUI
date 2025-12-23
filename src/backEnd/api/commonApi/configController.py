# 系统配置管理控制器
import os
import json
import logging
from typing import Optional
from pathlib import Path

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from model.BaseResponseMsg import BaseResponseMsg
from model.Task import (
    get_http_request_temp_dir,
    set_http_request_temp_dir,
    get_default_http_request_temp_dir
)
from utils.auth import get_current_user
from utils.websocket_manager import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/config")

# 配置文件路径
CONFIG_FILE = Path(__file__).parent.parent.parent / "data" / "system_config.json"

# 默认配置
DEFAULT_CONFIG = {
    "refreshInterval": 5  # 默认5分钟
}


def _ensure_config_dir():
    """确保配置目录存在"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)


def _load_system_config() -> dict:
    """加载系统配置"""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # 合并默认配置
                return {**DEFAULT_CONFIG, **config}
    except Exception as e:
        logger.error(f"加载系统配置失败: {e}")
    return DEFAULT_CONFIG.copy()


def _save_system_config(config: dict):
    """保存系统配置"""
    try:
        _ensure_config_dir()
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        logger.info(f"系统配置已保存: {config}")
    except Exception as e:
        logger.error(f"保存系统配置失败: {e}")
        raise


def get_refresh_interval() -> int:
    """获取刷新间隔（分钟）"""
    config = _load_system_config()
    return config.get("refreshInterval", DEFAULT_CONFIG["refreshInterval"])


def set_refresh_interval(interval: int):
    """设置刷新间隔（分钟）"""
    # 限制范围 1-60 分钟
    interval = max(1, min(60, interval))
    config = _load_system_config()
    config["refreshInterval"] = interval
    _save_system_config(config)
    # 更新 WebSocket 管理器的刷新间隔
    ws_manager.update_refresh_interval(interval)
    return interval


class TempDirConfigRequest(BaseModel):
    """临时文件目录配置请求"""
    tempDir: Optional[str] = None  # 为空或null时恢复默认值


class TempDirConfigResponse(BaseModel):
    """临时文件目录配置响应"""
    currentTempDir: str
    defaultTempDir: str
    isCustom: bool


@router.get('/temp-dir')
async def get_temp_dir_config(current_user: dict = Depends(get_current_user)):
    """
    获取HTTP请求临时文件目录配置
    """
    try:
        current_dir = get_http_request_temp_dir()
        default_dir = get_default_http_request_temp_dir()
        is_custom = current_dir != default_dir
        
        data = {
            "currentTempDir": current_dir,
            "defaultTempDir": default_dir,
            "isCustom": is_custom
        }
        
        logger.debug(f"Get temp dir config: {data}")
        return BaseResponseMsg(
            data=data,
            msg="success",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"Failed to get temp dir config: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"Failed to get config: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.post('/temp-dir')
async def set_temp_dir_config(
    request: TempDirConfigRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    设置HTTP请求临时文件目录
    - 如果tempDir为空或null，则恢复默认值
    - 如果目录不存在，会自动创建
    """
    try:
        temp_dir = request.tempDir
        
        # 如果提供了路径，验证并创建目录
        if temp_dir and temp_dir.strip():
            temp_dir = temp_dir.strip()
            
            # 尝试创建目录（如果不存在）
            if not os.path.exists(temp_dir):
                try:
                    os.makedirs(temp_dir, exist_ok=True)
                    logger.info(f"Created temp directory: {temp_dir}")
                except OSError as e:
                    logger.error(f"Failed to create temp directory: {e}")
                    return BaseResponseMsg(
                        data=None,
                        msg=f"Failed to create directory: {str(e)}",
                        success=False,
                        code=status.HTTP_400_BAD_REQUEST
                    )
            
            # 验证目录是否可写
            if not os.access(temp_dir, os.W_OK):
                return BaseResponseMsg(
                    data=None,
                    msg=f"Directory is not writable: {temp_dir}",
                    success=False,
                    code=status.HTTP_400_BAD_REQUEST
                )
        
        # 设置临时目录
        set_http_request_temp_dir(temp_dir)
        
        # 返回更新后的配置
        current_dir = get_http_request_temp_dir()
        default_dir = get_default_http_request_temp_dir()
        is_custom = current_dir != default_dir
        
        data = {
            "currentTempDir": current_dir,
            "defaultTempDir": default_dir,
            "isCustom": is_custom
        }
        
        action = "reset to default" if not temp_dir else f"set to {temp_dir}"
        logger.info(f"Temp dir config {action}")
        
        return BaseResponseMsg(
            data=data,
            msg=f"Temp directory {action}",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"Failed to set temp dir config: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"Failed to set config: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.post('/temp-dir/reset')
async def reset_temp_dir_config(current_user: dict = Depends(get_current_user)):
    """
    重置HTTP请求临时文件目录为默认值
    """
    try:
        set_http_request_temp_dir(None)
        
        current_dir = get_http_request_temp_dir()
        default_dir = get_default_http_request_temp_dir()
        
        data = {
            "currentTempDir": current_dir,
            "defaultTempDir": default_dir,
            "isCustom": False
        }
        
        logger.info("Temp dir config reset to default")
        
        return BaseResponseMsg(
            data=data,
            msg="Temp directory reset to default",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"Failed to reset temp dir config: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"Failed to reset config: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class RefreshIntervalRequest(BaseModel):
    """刷新间隔配置请求"""
    interval: int  # 刷新间隔（分钟）


@router.get('/refresh-interval')
async def get_refresh_interval_config(current_user: dict = Depends(get_current_user)):
    """
    获取数据刷新间隔配置
    """
    try:
        interval = get_refresh_interval()
        
        return BaseResponseMsg(
            data={
                "refreshInterval": interval,
                "minInterval": 1,
                "maxInterval": 60
            },
            msg="success",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"获取刷新间隔配置失败: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"Failed to get refresh interval: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.post('/refresh-interval')
async def set_refresh_interval_config(
    request: RefreshIntervalRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    设置数据刷新间隔
    - interval: 刷新间隔（分钟），范围 1-60
    """
    try:
        new_interval = set_refresh_interval(request.interval)
        
        logger.info(f"刷新间隔已设置为 {new_interval} 分钟")
        
        return BaseResponseMsg(
            data={
                "refreshInterval": new_interval,
                "minInterval": 1,
                "maxInterval": 60
            },
            msg=f"刷新间隔已设置为 {new_interval} 分钟",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"设置刷新间隔失败: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"Failed to set refresh interval: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
