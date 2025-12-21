"""
扫描配置预设API
提供Web端扫描配置预设的管理接口
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request, Depends
from fastapi import status as http_status

from model.BaseResponseMsg import BaseResponseMsg
from model.ScanPreset import (
    ScanPreset, ScanPresetCreate, ScanPresetUpdate, PresetType
)
from service.scanPresetService import scanPresetService
from utils.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan-preset")


@router.get("/list", summary="获取所有预设配置列表")
async def get_all_presets(
    include_inactive: bool = Query(False, description="是否包含未激活的配置"),
    current_user: dict = Depends(get_current_user)
):
    """获取所有预设配置，包括默认配置、常用配置和历史配置"""
    try:
        result = scanPresetService.get_all_presets(include_inactive)
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="获取成功",
            data={
                "presets": [p.model_dump() for p in result.presets],
                "total": result.total,
                "default_preset": result.default_preset.model_dump() if result.default_preset else None
            }
        )
    except Exception as e:
        logger.error(f"Failed to get presets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config-options", summary="获取配置选项（用于下拉菜单）")
async def get_config_options(
    current_user: dict = Depends(get_current_user)
):
    """
    获取所有可选配置，用于下拉菜单
    返回：默认配置、常用配置列表、历史配置列表
    """
    try:
        result = scanPresetService.get_all_config_options()
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="获取成功",
            data={
                "default": result["default"].model_dump() if result["default"] else None,
                "presets": [p.model_dump() for p in result["presets"]],
                "history": [p.model_dump() for p in result["history"]]
            }
        )
    except Exception as e:
        logger.error(f"Failed to get config options: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/default", summary="获取默认配置")
async def get_default_preset(
    current_user: dict = Depends(get_current_user)
):
    """获取默认扫描配置"""
    try:
        preset = scanPresetService.get_default_preset()
        if not preset:
            return BaseResponseMsg(
                success=False,
                code=http_status.HTTP_404_NOT_FOUND,
                msg="默认配置不存在",
                data=None
            )
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="获取成功",
            data=preset.model_dump()
        )
    except Exception as e:
        logger.error(f"Failed to get default preset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/default", summary="更新默认配置")
async def update_default_preset(
    options: dict,
    current_user: dict = Depends(get_current_user)
):
    """更新默认扫描配置的选项"""
    try:
        preset = scanPresetService.update_default_preset(options)
        if not preset:
            return BaseResponseMsg(
                success=False,
                code=http_status.HTTP_404_NOT_FOUND,
                msg="更新失败",
                data=None
            )
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="更新成功",
            data=preset.model_dump()
        )
    except Exception as e:
        logger.error(f"Failed to update default preset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/presets", summary="获取常用配置列表")
async def get_preset_configs(
    current_user: dict = Depends(get_current_user)
):
    """获取常用配置列表"""
    try:
        presets = scanPresetService.get_preset_configs()
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="获取成功",
            data={
                "presets": [p.model_dump() for p in presets],
                "total": len(presets)
            }
        )
    except Exception as e:
        logger.error(f"Failed to get preset configs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history", summary="获取历史配置列表")
async def get_history_configs(
    limit: int = Query(20, ge=1, le=100, description="返回数量限制"),
    current_user: dict = Depends(get_current_user)
):
    """获取历史配置列表"""
    try:
        presets = scanPresetService.get_history_configs(limit)
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="获取成功",
            data={
                "presets": [p.model_dump() for p in presets],
                "total": len(presets)
            }
        )
    except Exception as e:
        logger.error(f"Failed to get history configs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{preset_id}", summary="获取指定预设配置")
async def get_preset_by_id(
    preset_id: int,
    current_user: dict = Depends(get_current_user)
):
    """根据ID获取预设配置"""
    try:
        preset = scanPresetService.get_preset_by_id(preset_id)
        if not preset:
            return BaseResponseMsg(
                success=False,
                code=http_status.HTTP_404_NOT_FOUND,
                msg="配置不存在",
                data=None
            )
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="获取成功",
            data=preset.model_dump()
        )
    except Exception as e:
        logger.error(f"Failed to get preset by id: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("", summary="创建新的预设配置")
async def create_preset(
    data: ScanPresetCreate,
    current_user: dict = Depends(get_current_user)
):
    """创建新的预设配置"""
    try:
        preset = scanPresetService.create_preset(data)
        if not preset:
            return BaseResponseMsg(
                success=False,
                code=http_status.HTTP_400_BAD_REQUEST,
                msg="创建失败，配置名称可能已存在",
                data=None
            )
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_201_CREATED,
            msg="创建成功",
            data=preset.model_dump()
        )
    except Exception as e:
        logger.error(f"Failed to create preset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{preset_id}", summary="更新预设配置")
async def update_preset(
    preset_id: int,
    data: ScanPresetUpdate,
    current_user: dict = Depends(get_current_user)
):
    """更新指定的预设配置"""
    try:
        preset = scanPresetService.update_preset(preset_id, data)
        if not preset:
            return BaseResponseMsg(
                success=False,
                code=http_status.HTTP_404_NOT_FOUND,
                msg="更新失败，配置不存在或名称冲突",
                data=None
            )
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="更新成功",
            data=preset.model_dump()
        )
    except Exception as e:
        logger.error(f"Failed to update preset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{preset_id}", summary="删除预设配置")
async def delete_preset(
    preset_id: int,
    current_user: dict = Depends(get_current_user)
):
    """删除指定的预设配置"""
    try:
        success = scanPresetService.delete_preset(preset_id)
        if not success:
            return BaseResponseMsg(
                success=False,
                code=http_status.HTTP_400_BAD_REQUEST,
                msg="删除失败，配置不存在或为默认配置",
                data=None
            )
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="删除成功",
            data=None
        )
    except Exception as e:
        logger.error(f"Failed to delete preset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/history", summary="添加到历史记录")
async def add_to_history(
    request: Request,
    name: str = Query(..., description="配置名称"),
    current_user: dict = Depends(get_current_user)
):
    """将配置添加到历史记录"""
    try:
        body = await request.json()
        options = body.get("options", {})
        
        preset = scanPresetService.add_to_history(name, options)
        if not preset:
            return BaseResponseMsg(
                success=False,
                code=http_status.HTTP_400_BAD_REQUEST,
                msg="添加失败",
                data=None
            )
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_201_CREATED,
            msg="添加成功",
            data=preset.model_dump()
        )
    except Exception as e:
        logger.error(f"Failed to add to history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{preset_id}/apply", summary="应用预设配置")
async def apply_preset(
    preset_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """应用预设配置到选项，返回合并后的选项"""
    try:
        body = await request.json()
        base_options = body.get("base_options", {})
        
        result = scanPresetService.apply_preset_to_options(preset_id, base_options)
        
        # 记录使用
        scanPresetService.record_preset_usage(preset_id)
        
        return BaseResponseMsg(
            success=True,
            code=http_status.HTTP_200_OK,
            msg="应用成功",
            data={"options": result}
        )
    except Exception as e:
        logger.error(f"Failed to apply preset: {e}")
        raise HTTPException(status_code=500, detail=str(e))
