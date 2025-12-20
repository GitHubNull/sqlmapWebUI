# 系统配置管理控制器
import os
import logging
from typing import Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from model.BaseResponseMsg import BaseResponseMsg
from model.Task import (
    get_http_request_temp_dir,
    set_http_request_temp_dir,
    get_default_http_request_temp_dir
)
from utils.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/config")


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
