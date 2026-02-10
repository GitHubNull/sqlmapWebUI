# 使用标准库的logging模块
import logging
from datetime import datetime

from fastapi import HTTPException
from fastapi import APIRouter, Depends, Request, Query
from fastapi import status

from model.BaseResponseMsg import BaseResponseMsg
from model.requestModel.TaskRequest import TaskAddRequest
from service.taskService import taskService
from utils.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/burpsuite/admin")

@router.post('/task/add')
async def add_task(taskAddRequest: TaskAddRequest, request: Request, current_user: dict = Depends(get_current_user)):
    try:
        if request.client:
            # pdb.set_trace()
            task_dict = taskAddRequest.model_dump()
            if 'options' not in task_dict or task_dict['options'] is None:
                return BaseResponseMsg(success=False, msg="options is required", code=status.HTTP_400_BAD_REQUEST, data=None)
            logger.info(f"request.client: {request.client}")
            remote_ip = request.client.host
            # pdb.set_trace()
            res = await taskService.star_task(remote_addr=remote_ip, scanUrl=taskAddRequest.scanUrl, host=taskAddRequest.host, method=taskAddRequest.method, headers=taskAddRequest.headers, body=taskAddRequest.body, options=taskAddRequest.options)
            return res
        else:
            remote_ip = None
            logger.warning("request.client is None")
            return BaseResponseMsg(success=False, msg="options is required", code=status.HTTP_400_BAD_REQUEST, data=None)
    except Exception as e:
        logger.error(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Error accessing request.client")