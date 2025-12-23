# Web端扫描任务提交接口
# 与BurpSuite插件端共用相同的业务逻辑，但日志来源区分
import logging

from fastapi import HTTPException
from fastapi import APIRouter, Depends, Request
from fastapi import status

from model.BaseResponseMsg import BaseResponseMsg
from model.requestModel.TaskRequest import TaskAddRequest
from service.taskService import taskService
from utils.auth import get_current_user
from utils.websocket_manager import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/web/admin")


@router.post('/task/add')
async def add_task_from_web(
    taskAddRequest: TaskAddRequest, 
    request: Request, 
    current_user: dict = Depends(get_current_user)
):
    """
    Web端添加扫描任务
    
    与BurpSuite插件端使用相同的业务逻辑和参数格式，
    但通过独立接口区分日志来源，便于维护和调试。
    
    Args:
        taskAddRequest: 任务请求参数（与BurpSuite端一致）
            - scanUrl: 扫描地址
            - host: 扫描域名
            - headers: 请求头列表
            - body: 请求体
            - options: 扫描参数配置
    
    Returns:
        BaseResponseMsg: 包含任务ID的响应
    """
    try:
        if request.client:
            task_dict = taskAddRequest.model_dump()
            
            # 验证options参数
            if 'options' not in task_dict or task_dict['options'] is None:
                logger.warning("[Web] Task add failed: options is required")
                return BaseResponseMsg(
                    success=False, 
                    msg="options is required", 
                    code=status.HTTP_400_BAD_REQUEST, 
                    data=None
                )
            
            remote_ip = request.client.host
            
            # 日志标记来源为Web端
            logger.info(f"[Web] New scan task from {remote_ip}")
            logger.info(f"[Web] Target URL: {taskAddRequest.scanUrl}")
            logger.info(f"[Web] Host: {taskAddRequest.host}")
            logger.debug(f"[Web] Options: {taskAddRequest.options}")
            
            # 复用相同的业务逻辑
            res = await taskService.star_task(
                remote_addr=remote_ip, 
                scanUrl=taskAddRequest.scanUrl, 
                host=taskAddRequest.host, 
                headers=taskAddRequest.headers, 
                body=taskAddRequest.body, 
                options=taskAddRequest.options
            )
            
            if res.success:
                logger.info(f"[Web] Task created successfully: {res.data}")
                # 通知前端刷新数据
                task_id = res.data.get('taskid') if isinstance(res.data, dict) else None
                await ws_manager.notify_task_created(task_id)
            else:
                logger.warning(f"[Web] Task creation failed: {res.msg}")
            
            return res
        else:
            logger.warning("[Web] Task add failed: request.client is None")
            return BaseResponseMsg(
                success=False, 
                msg="Unable to determine client address", 
                code=status.HTTP_400_BAD_REQUEST, 
                data=None
            )
    except Exception as e:
        logger.error(f"[Web] Task add error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scan task: {str(e)}")
