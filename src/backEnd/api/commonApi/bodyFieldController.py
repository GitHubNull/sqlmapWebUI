"""
Body Field Controller - 会话Body字段管理API

提供会话Body字段的CRUD接口和预览功能。
"""

from fastapi import APIRouter, Request, status
from typing import List

from model.BaseResponseMsg import BaseResponseMsg
from model.SessionBodyField import (
    SessionBodyFieldBatchCreate,
    SessionBodyFieldUpdate,
    SessionBodyFieldListResponse,
    SessionBodyFieldResponse
)
from model.DataStore import DataStore

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.post('/session-body-fields')
async def set_session_body_fields(
    batch_create: SessionBodyFieldBatchCreate,
    request: Request
) -> BaseResponseMsg:
    """批量设置会话Body字段"""
    try:
        client_ip = request.client.host
        manager = DataStore.get_session_body_field_manager()
        
        if manager is None:
            return BaseResponseMsg(
                data=None,
                msg="Body字段管理器不可用",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        count = manager.set_session_body_fields_batch(
            client_ip, 
            batch_create.fields
        )
        
        logger.info(f"Set {count} session body fields for {client_ip}")
        
        return BaseResponseMsg(
            data={"count": count, "client_ip": client_ip},
            msg=f"成功设置{count}个会话Body字段",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"Failed to set session body fields: {e}")
        return BaseResponseMsg(
            data=None, 
            msg=str(e), 
            success=False, 
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.get('/session-body-fields')
async def get_session_body_fields(request: Request) -> BaseResponseMsg:
    """获取会话Body字段列表"""
    try:
        client_ip = request.client.host
        manager = DataStore.get_session_body_field_manager()
        
        if manager is None:
            return BaseResponseMsg(
                data=None,
                msg="Body字段管理器不可用",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # 获取所有字段（包括过期的）
        all_fields = manager.get_all_session_body_fields(client_ip)
        
        # 转换为响应格式
        field_responses = []
        for field in all_fields:
            field_dict = field.to_dict()
            field_responses.append(SessionBodyFieldResponse(**field_dict))
        
        response_data = SessionBodyFieldListResponse(
            client_ip=client_ip,
            fields=field_responses,
            total_count=len(field_responses)
        )
        
        return BaseResponseMsg(
            data=response_data.dict(),
            msg="获取会话Body字段成功",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"Failed to get session body fields: {e}")
        return BaseResponseMsg(
            data=None, 
            msg=str(e), 
            success=False, 
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.put('/session-body-fields/{field_name}')
async def update_session_body_field(
    field_name: str,
    field_update: SessionBodyFieldUpdate,
    request: Request
) -> BaseResponseMsg:
    """更新单个会话Body字段"""
    try:
        client_ip = request.client.host
        manager = DataStore.get_session_body_field_manager()
        
        if manager is None:
            return BaseResponseMsg(
                data=None,
                msg="Body字段管理器不可用",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        success = manager.update_session_body_field(client_ip, field_name, field_update)
        
        if success:
            return BaseResponseMsg(
                data={"client_ip": client_ip, "field_name": field_name},
                msg="会话Body字段更新成功",
                success=True,
                code=status.HTTP_200_OK
            )
        else:
            return BaseResponseMsg(
                data=None,
                msg="会话Body字段更新失败",
                success=False,
                code=status.HTTP_404_NOT_FOUND
            )
    except Exception as e:
        logger.error(f"Failed to update session body field: {e}")
        return BaseResponseMsg(
            data=None, 
            msg=str(e), 
            success=False, 
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.delete('/session-body-fields/{field_name}')
async def delete_session_body_field(
    field_name: str,
    request: Request
) -> BaseResponseMsg:
    """删除单个会话Body字段"""
    try:
        client_ip = request.client.host
        manager = DataStore.get_session_body_field_manager()
        
        if manager is None:
            return BaseResponseMsg(
                data=None,
                msg="Body字段管理器不可用",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        removed = manager.remove_session_body_field(client_ip, field_name)
        
        if removed:
            return BaseResponseMsg(
                data={"client_ip": client_ip, "field_name": field_name},
                msg="会话Body字段删除成功",
                success=True,
                code=status.HTTP_200_OK
            )
        else:
            return BaseResponseMsg(
                data=None,
                msg="没有找到指定的会话Body字段",
                success=False,
                code=status.HTTP_404_NOT_FOUND
            )
    except Exception as e:
        logger.error(f"Failed to delete session body field: {e}")
        return BaseResponseMsg(
            data=None, 
            msg=str(e), 
            success=False, 
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.delete('/session-body-fields')
async def clear_session_body_fields(request: Request) -> BaseResponseMsg:
    """清除所有会话Body字段"""
    try:
        client_ip = request.client.host
        manager = DataStore.get_session_body_field_manager()
        
        if manager is None:
            return BaseResponseMsg(
                data=None,
                msg="Body字段管理器不可用",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        cleared = manager.clear_session_body_fields(client_ip)
        
        if cleared:
            return BaseResponseMsg(
                data={"client_ip": client_ip},
                msg="会话Body字段清除成功",
                success=True,
                code=status.HTTP_200_OK
            )
        else:
            return BaseResponseMsg(
                data={"client_ip": client_ip},
                msg="没有找到需要清除的会话Body字段",
                success=True,
                code=status.HTTP_200_OK
            )
    except Exception as e:
        logger.error(f"Failed to clear session body fields: {e}")
        return BaseResponseMsg(
            data=None, 
            msg=str(e), 
            success=False, 
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.post('/body-processing/preview')
async def preview_body_processing(
    request: Request,
    preview_request: dict
) -> BaseResponseMsg:
    """预览Body处理结果"""
    try:
        from utils.body_field_processor import BodyFieldProcessor
        
        # 提取参数
        body = preview_request.get('body', '')
        content_type = preview_request.get('content_type')
        target_url = preview_request.get('target_url')
        
        if not body:
            return BaseResponseMsg(
                data=None,
                msg="Body内容不能为空",
                success=False,
                code=status.HTTP_400_BAD_REQUEST
            )
        
        client_ip = request.client.host
        manager = DataStore.get_session_body_field_manager()
        
        if manager is None:
            return BaseResponseMsg(
                data=None,
                msg="Body字段管理器不可用",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # 获取活跃的会话Body字段
        session_fields = manager.get_session_body_fields(client_ip, active_only=True)
        
        # 处理Body
        processed_body, applied_rules = BodyFieldProcessor.process_body(
            body,
            content_type,
            session_fields,
            target_url
        )
        
        preview_result = {
            "original_body": body,
            "processed_body": processed_body,
            "applied_rules": applied_rules,
            "changes_count": len(applied_rules)
        }
        
        return BaseResponseMsg(
            data=preview_result,
            msg="Body处理预览成功",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"Failed to preview body processing: {e}")
        return BaseResponseMsg(
            data=None, 
            msg=str(e), 
            success=False, 
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
