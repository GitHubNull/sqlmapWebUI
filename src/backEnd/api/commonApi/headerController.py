# 使用标准库的logging模块
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Query, Request
from fastapi import status
from pydantic import BaseModel, Field

from model.BaseResponseMsg import BaseResponseMsg
from model.DataStore import DataStore
from model.HeaderBatch import HeaderBatchCreateRequest, ParsedHeaderBatchCreateRequest, HeaderBatchParseRequest
from model.PersistentHeaderRule import PersistentHeaderRuleCreate, PersistentHeaderRuleUpdate
from model.SessionHeader import SessionHeaderBatchCreate
from service.headerRuleService import HeaderRuleService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/commonApi/header")

# ===========================================
# 请求头管理 API 接口
# ===========================================

# 实例化请求头服务

# 实例化请求头服务
headerRuleService = HeaderRuleService()


# 健康检查接口
@router.get('/headers/ping')
async def ping_headers_service():
    """检查Chrome请求头管理服务健康状态（本地单机模式）"""
    try:
        capabilities = [
            "persistent_rules",
            "session_headers",
            "batch_operations",
            "header_preview",
            "stats"
        ]

        response_data = {
            "service": "chrome_headers",
            "status": "healthy",
            "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            "version": "1.0.0",
            "capabilities": capabilities
        }

        return BaseResponseMsg(
            data=response_data,
            msg="Chrome请求头管理服务正常运行（本地模式）",
            success=True,
            code=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f"Chrome headers service ping failed: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"Chrome请求头管理服务异常（本地模式）: {str(e)}",
            success=False,
            code=status.HTTP_503_SERVICE_UNAVAILABLE
        )


# 持久化请求头规则管理
@router.post('/persistent-header-rules')
async def create_persistent_header_rule(
        rule_data: PersistentHeaderRuleCreate
):
    """创建持久化请求头规则"""
    try:
        res = await headerRuleService.create_persistent_rule(rule_data)
        return res
    except Exception as e:
        logger.error(f"Failed to create persistent header rule: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.get('/persistent-header-rules')
async def get_persistent_header_rules(
        active_only: bool = Query(default=True, description="只获取活跃规则")
):
    """获取持久化请求头规则列表"""
    try:
        res = await headerRuleService.get_persistent_rules(active_only=active_only)
        return res
    except Exception as e:
        logger.error(f"Failed to get persistent header rules: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.get('/persistent-header-rules/{rule_id}')
async def get_persistent_header_rule_by_id(
        rule_id: int
):
    """根据ID获取持久化请求头规则"""
    try:
        res = await headerRuleService.get_persistent_rule_by_id(rule_id)
        return res
    except Exception as e:
        logger.error(f"Failed to get persistent header rule {rule_id}: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.put('/persistent-header-rules/{rule_id}')
async def update_persistent_header_rule(
        rule_id: int,
        update_data: PersistentHeaderRuleUpdate
):
    """更新持久化请求头规则"""
    try:
        res = await headerRuleService.update_persistent_rule(rule_id, update_data)
        return res
    except Exception as e:
        logger.error(f"Failed to update persistent header rule {rule_id}: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.delete('/persistent-header-rules/{rule_id}')
async def delete_persistent_header_rule(
        rule_id: int
):
    """删除持久化请求头规则"""
    try:
        res = await headerRuleService.delete_persistent_rule(rule_id)
        return res
    except Exception as e:
        logger.error(f"Failed to delete persistent header rule {rule_id}: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


# 会话性请求头管理
@router.post('/session-headers')
async def set_session_headers(
        headers_data: SessionHeaderBatchCreate,
        request: Request
):
    """设置会话性请求头"""
    try:
        client_ip = request.client.host
        session_manager = DataStore.get_session_header_manager()

        success_count = session_manager.set_session_headers_batch(client_ip, headers_data.headers)

        response_data = {
            "client_ip": client_ip,
            "headers_count": success_count,
            "total_headers": len(headers_data.headers)
        }

        if success_count == len(headers_data.headers):
            return BaseResponseMsg(
                data=response_data,
                msg="会话性请求头设置成功",
                success=True,
                code=status.HTTP_200_OK
            )
        else:
            return BaseResponseMsg(
                data=response_data,
                msg=f"部分会话性请求头设置成功 ({success_count}/{len(headers_data.headers)})",
                success=True,
                code=status.HTTP_206_PARTIAL_CONTENT
            )

    except Exception as e:
        logger.error(f"Failed to set session headers: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.get('/session-headers')
async def get_session_headers(
        request: Request
):
    """获取会话性请求头"""
    try:
        client_ip = request.client.host
        session_manager = DataStore.get_session_header_manager()

        session_headers = session_manager.get_session_headers(client_ip, active_only=True)

        headers_list = []
        for header_name, session_header in session_headers.items():
            headers_list.append({
                "header_name": header_name,
                "header_value": session_header.header_value,
                "priority": session_header.priority,
                "expires_at": session_header.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                "created_at": session_header.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })

        response_data = {
            "client_ip": client_ip,
            "headers": headers_list,
            "total_count": len(headers_list)
        }

        return BaseResponseMsg(
            data=response_data,
            msg="查询成功",
            success=True,
            code=status.HTTP_200_OK
        )

    except Exception as e:
        logger.error(f"Failed to get session headers: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.delete('/session-headers')
async def clear_session_headers(
        request: Request
):
    """清除会话性请求头"""
    try:
        client_ip = request.client.host
        session_manager = DataStore.get_session_header_manager()

        cleared = session_manager.clear_session_headers(client_ip)

        if cleared:
            return BaseResponseMsg(
                data={"client_ip": client_ip},
                msg="会话性请求头清除成功",
                success=True,
                code=status.HTTP_200_OK
            )
        else:
            return BaseResponseMsg(
                data={"client_ip": client_ip},
                msg="没有找到需要清除的会话性请求头",
                success=True,
                code=status.HTTP_200_OK
            )

    except Exception as e:
        logger.error(f"Failed to clear session headers: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.delete('/session-headers/{header_name}')
async def delete_session_header(
        header_name: str,
        request: Request
):
    """删除单个会话性请求头"""
    try:
        client_ip = request.client.host
        session_manager = DataStore.get_session_header_manager()

        removed = session_manager.remove_session_header(client_ip, header_name)

        if removed:
            return BaseResponseMsg(
                data={"client_ip": client_ip, "header_name": header_name},
                msg="会话性请求头删除成功",
                success=True,
                code=status.HTTP_200_OK
            )
        else:
            return BaseResponseMsg(
                data=None,
                msg="没有找到指定的会话性请求头",
                success=False,
                code=status.HTTP_404_NOT_FOUND
            )

    except Exception as e:
        logger.error(f"Failed to delete session header: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


class SessionHeaderUpdateRequest(BaseModel):
    header_value: str = Field(..., description="新的请求头值")
    priority: Optional[int] = Field(None, description="优先级")
    ttl: Optional[int] = Field(None, description="生存时间(秒)")


@router.put('/session-headers/{header_name}')
async def update_session_header(
        header_name: str,
        update_data: SessionHeaderUpdateRequest,
        request: Request
):
    """更新单个会话性请求头"""
    try:
        client_ip = request.client.host
        session_manager = DataStore.get_session_header_manager()
        
        # 检查请求头是否存在
        existing_headers = session_manager.get_session_headers(client_ip, active_only=False)
        if header_name not in existing_headers:
            return BaseResponseMsg(
                data=None,
                msg="没有找到指定的会话性请求头",
                success=False,
                code=status.HTTP_404_NOT_FOUND
            )
        
        existing = existing_headers[header_name]
        
        # 使用set_session_header更新（它会覆盖现有记录）
        from model.SessionHeader import SessionHeaderCreate
        updated_header = SessionHeaderCreate(
            header_name=header_name,
            header_value=update_data.header_value,
            priority=update_data.priority if update_data.priority is not None else existing.priority,
            ttl=update_data.ttl if update_data.ttl is not None else 3600
        )
        
        success = session_manager.set_session_header(client_ip, updated_header)
        
        if success:
            return BaseResponseMsg(
                data={"client_ip": client_ip, "header_name": header_name},
                msg="会话性请求头更新成功",
                success=True,
                code=status.HTTP_200_OK
            )
        else:
            return BaseResponseMsg(
                data=None,
                msg="更新失败",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    except Exception as e:
        logger.error(f"Failed to update session header: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


# 请求头处理预览
class HeaderPreviewRequest(BaseModel):
    headers: List[str] = Field(..., description="原始请求头列表")
    target_url: Optional[str] = Field(None, description="目标URL，用于作用域匹配（可选）")


@router.post('/header-processing/preview')
async def preview_header_processing(
        preview_request: HeaderPreviewRequest,
        request: Request
):
    """
    预览请求头处理结果
    
    支持作用域匹配：
    - 如果提供target_url，则只应用作用域匹配的规则
    - 如果不提供target_url，则应用所有活跃规则
    """
    try:
        client_ip = request.client.host
        res = await headerRuleService.preview_header_processing(
            preview_request.headers, 
            client_ip, 
            preview_request.target_url
        )
        return res
    except Exception as e:
        logger.error(f"Failed to preview header processing: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


# 系统统计接口
@router.get('/header-management/stats')
async def get_header_management_stats():
    """获取请求头管理统计信息"""
    try:
        # 获取持久化规则统计
        persistent_rules_res = await headerRuleService.get_persistent_rules(active_only=False)
        persistent_rules_count = len(persistent_rules_res.data.get('rules', [])) if persistent_rules_res.success else 0
        active_persistent_rules_count = len([r for r in persistent_rules_res.data.get('rules', []) if
                                             r.get('is_active', False)]) if persistent_rules_res.success else 0

        # 获取会话性请求头统计
        session_manager = DataStore.get_session_header_manager()
        session_stats = {
            "client_count": session_manager.get_client_count(),
            "total_headers_count": session_manager.get_total_headers_count(),
            "active_headers_count": session_manager.get_active_headers_count()
        }

        response_data = {
            "persistent_rules": {
                "total_count": persistent_rules_count,
                "active_count": active_persistent_rules_count
            },
            "session_headers": session_stats
        }

        return BaseResponseMsg(
            data=response_data,
            msg="统计信息获取成功",
            success=True,
            code=status.HTTP_200_OK
        )

    except Exception as e:
        logger.error(f"Failed to get header management stats: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


# ===========================================
# 批量添加接口
# ===========================================

@router.post('/headers/parse')
async def parse_headers_batch(
        request: HeaderBatchParseRequest
):
    """批量解析请求头"""
    try:
        res = await headerRuleService.parse_headers_batch(request)
        return res
    except Exception as e:
        logger.error(f"Failed to parse headers batch: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.post('/persistent-header-rules/batch')
async def create_persistent_header_rules_batch(
        request: ParsedHeaderBatchCreateRequest
):
    """批量创建持久化请求头规则"""
    try:
        res = await headerRuleService.create_persistent_rules_batch(request)
        return res
    except Exception as e:
        logger.error(f"Failed to create persistent header rules batch: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.post('/session-headers/batch')
async def create_session_headers_batch(
        request: ParsedHeaderBatchCreateRequest,
        request_context: Request
):
    """批量创建会话性请求头"""
    try:
        client_ip = request_context.client.host
        res = await headerRuleService.create_session_headers_batch(request, client_ip)
        return res
    except Exception as e:
        logger.error(f"Failed to create session headers batch: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.post('/headers/batch-create')
async def create_headers_batch(
        request: HeaderBatchCreateRequest,
        request_context: Request
):
    """一体化批量创建请求头（解析+创建）"""
    try:
        client_ip = request_context.client.host
        res = await headerRuleService.create_headers_batch(request, client_ip)
        return res
    except Exception as e:
        logger.error(f"Failed to create headers batch: {e}")
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)