# 使用标准库的logging模块
import logging
import sys

from fastapi import APIRouter, Depends, Query

sys.path.append("..。")
from model.BaseResponseMsg import BaseResponseMsg
from model.requestModel.TaskRequest import TaskDeleteRequest, TaskFindByHeaderKeyWordRequest, \
    TaskLogQueryRequest, TaskFindByBodyKeyWordRequest, TaskFindByUrlPathRequest, TaskStopRequest
from service.taskService import taskService
from utils.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chrome/admin")


@router.delete('/task/delete')
async def delete_task(taskDeleteRequest: TaskDeleteRequest = Depends(), current_user: dict = Depends(get_current_user)):
    res = await taskService.delete_task(taskDeleteRequest.taskid)
    return res


@router.put('/task/kill')
async def kill_task(taskDeleteRequest: TaskDeleteRequest, current_user: dict = Depends(get_current_user)):
    res = await taskService.kill_task(taskDeleteRequest.taskid)
    return res


@router.get('/task/list')
async def list_task(current_user: dict = Depends(get_current_user)):
    res = await taskService.list_task()
    return res


@router.put('/task/startBlocked')
async def start_start_with_taskid(taskDeleteRequest: TaskDeleteRequest, current_user: dict = Depends(get_current_user)):
    res = await taskService.start_task_with_taskid(taskDeleteRequest.taskid)
    return res


@router.put('/task/stop')
async def stop_task(taskStopRequest: TaskStopRequest, current_user: dict = Depends(get_current_user)):
    res = await taskService.stop_task(taskStopRequest.taskid)
    return res


@router.patch('/task/flush')
async def stop_flush(current_user: dict = Depends(get_current_user)):
    res = await taskService.flush_task()
    return res


@router.post('/task/findByUrlPath')
async def find_task_by_urlPath(taskFindByUrlPathRequest: TaskFindByUrlPathRequest, current_user: dict = Depends(get_current_user)):
    res = await taskService.find_task_by_urlPath(taskFindByUrlPathRequest.urlPath)
    return res


@router.post('/task/findByBodyKeyWord')
async def find_task_by_bodyKeyWord(taskFindByBodyKeyWordRequest: TaskFindByBodyKeyWordRequest, current_user: dict = Depends(get_current_user)):
    res = await taskService.find_task_by_bodyKeyWord(taskFindByBodyKeyWordRequest.bodyKeyWord)
    return res


@router.post('/task/findByHeaderKeyWord')
async def find_task_by_headerKeyWord(taskFindByHeaderKeyWordRequest: TaskFindByHeaderKeyWordRequest, current_user: dict = Depends(get_current_user)):
    res = await taskService.find_task_by_header_keyword(taskFindByHeaderKeyWordRequest.headerKeyWord)
    return res


@router.get('/task/logs/getLogsByTaskId')
async def get_logs_by_taskid(taskLogQueryRequest: TaskLogQueryRequest = Depends(), current_user: dict = Depends(get_current_user)):
    res = await taskService.find_task_log_by_taskid(taskid=taskLogQueryRequest.taskId)
    return res

@router.get("/task/getPayloadDetailByTaskId")
async def get_payload_detail_by_task_id(taskId: str = Query(..., min_length=16, max_length=16), current_user: dict = Depends(get_current_user)):
    try:
        res = await taskService.get_payload_detail_by_task_id(taskId)
        return res
    except Exception as e:
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.get("/task/getTaskHttpRequestInfoByTaskId")
async def get_task_http_request_info(taskId: str = Query(..., min_length=16, max_length=16), current_user: dict = Depends(get_current_user)):
    try:
        res = await taskService.get_task_http_request_info(taskId)
        return res
    except Exception as e:
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.get("/task/getTasksByKeyWord")
async def get_task_by_keyword(keyword: str = Query(..., min_length=1, max_length=32), current_user: dict = Depends(get_current_user)):
    try:
        res = await taskService.find_task_by_KeyWord(keyword)
        return res
    except Exception as e:
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.get("/task/getTaskScanOptionsByTaskId")
async def get_task_scan_options_by_taskId(taskId: str = Query(..., min_length=16, max_length=16), current_user: dict = Depends(get_current_user)):
    try:
        res = await taskService.get_task_scan_options(taskId)
        return res
    except Exception as e:
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)


@router.get("/task/getTaskErrorsByTaskId")
async def get_task_errors_by_taskId(taskId: str = Query(..., min_length=16, max_length=16), current_user: dict = Depends(get_current_user)):
    try:
        res = await taskService.get_task_errors_by_taskId(taskId)
        return res
    except Exception as e:
        return BaseResponseMsg(data=None, msg=str(e), success=False, code=500)