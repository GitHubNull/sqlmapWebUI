import pdb
import os
import sys
import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import status

from fastapi.exceptions import HTTPException

sys.path.append("..")
from model.DataStore import DataStore
# from config import data_store
from model.Task import Task
from model.TaskStatus import TaskStatus
from model.requestModel.TaskRequest import TaskAddRequest
from model.BaseResponseMsg import BaseResponseMsg

from third_lib.sqlmap.lib.core.settings import RESTAPI_UNSUPPORTED_OPTIONS
from third_lib.sqlmap.lib.core.convert import encodeHex
from third_lib.sqlmap.lib.core.data import logger
from utils.content_type_helper import get_content_type_by_number


def validate_options(options):
    if not isinstance(options, dict):
        logger.error("Invalid options format: expected list or tuple")
        return BaseResponseMsg(data=None, msg="Invalid options format", success=False, code=status.HTTP_400_BAD_REQUEST)

    try:
        unsupported_options_set = set(RESTAPI_UNSUPPORTED_OPTIONS)
        for key in options:
            if key in unsupported_options_set:
                logger.warning(f"Unsupported option '{key}' provided to scan_start()")
                return BaseResponseMsg(data=None, msg=f"Unsupported option {key}", success=False, code=status.HTTP_400_BAD_REQUEST)
    except TypeError:
        logger.error("Options is not iterable")
        return BaseResponseMsg(data=None, msg="Options is not iterable", success=False, code=status.HTTP_400_BAD_REQUEST)

    if not options:
        logger.info("No options provided")
        # 根据业务需求决定是否需要返回特定响应
        return BaseResponseMsg(data=None, msg="No options provided", success=True, code=status.HTTP_200_OK)

    return None  # 如果所有选项都支持，则继续后续逻辑


class TaskService(object):
    """
    TaskService
    
    注意：由于 DataStore.tasks_lock 是同步锁，在异步函数中使用会阻塞事件循环。
    对于简短的操作（如任务创建），我们使用线程池来执行同步代码。
    """
    # 线程池用于执行同步锁操作
    _executor = ThreadPoolExecutor(max_workers=4)
    
    def __init__(self):
        pass

    def _create_task_sync(self, remote_addr: str, scanUrl: str, host, headers: list, body: str, options: dict, taskid: str):
        """同步创建任务（在线程池中执行）"""
        with DataStore.tasks_lock:
            DataStore.tasks[taskid] = Task(taskid, remote_addr, scanUrl, host, headers, body)
            for option in options:
                logger.debug(f"option: {option}, value: {options[option]}")
                DataStore.tasks[taskid].set_option(option, options[option])
            DataStore.tasks[taskid].status = TaskStatus.Runnable
            return DataStore.tasks[taskid].engine_get_id()

    async def star_task(self, remote_addr: str, scanUrl: str, host, headers: list, body: str, options: dict):
        option_check_res = validate_options(options)
        if option_check_res is not None:
            return option_check_res

        taskid = encodeHex(os.urandom(8), binary=False)
        try:
            # 使用线程池执行同步锁操作，避免阻塞事件循环
            loop = asyncio.get_event_loop()
            engine_id = await loop.run_in_executor(
                self._executor,
                self._create_task_sync,
                remote_addr, scanUrl, host, headers, body, options, taskid
            )
            return BaseResponseMsg(
                data={"engineid": engine_id, "taskid": taskid},
                msg="success",
                success=True,
                code=status.HTTP_200_OK
            )
        except Exception as e:
            # 异常处理也使用线程池执行同步锁操作
            def _handle_error():
                with DataStore.tasks_lock:
                    if taskid in DataStore.tasks:
                        DataStore.tasks[taskid].status = TaskStatus.Terminated
            loop.run_in_executor(self._executor, _handle_error)
            logger.error("[%s] Failed to start scan: %s" % (taskid, e))
            raise HTTPException(status_code=500, detail=str(e))

    def _delete_task_sync(self, taskid):
        """同步删除任务（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                return (False, "Non-existing task ID", 400)
            task_status = DataStore.tasks[taskid].status
            if task_status == TaskStatus.Running:
                DataStore.tasks[taskid].engine_kill()
            DataStore.tasks.pop(taskid)
            return (True, f"{taskid} Deleted task", 200)

    async def delete_task(self, taskid):
        loop = asyncio.get_event_loop()
        success, msg, code = await loop.run_in_executor(
            self._executor, self._delete_task_sync, taskid
        )
        if not success:
            logger.warning(f"{taskid} Non-existing task ID provided to task_delete()")
        else:
            logger.info(f"{taskid} Deleted task")
        return BaseResponseMsg(data=None, msg=msg, success=success, code=code)

    def _list_task_sync(self):
        """同步获取任务列表（在线程池中执行）"""
        tasks = []
        index = 0
        with DataStore.tasks_lock:
            if DataStore.current_db is None:
                return (None, "Database connection is not initialized", False, status.HTTP_500_INTERNAL_SERVER_ERROR)

            for taskid in DataStore.tasks:
                task = DataStore.tasks[taskid]
                
                # 查询错误数
                errors_query = "SELECT COUNT(*) FROM errors WHERE taskid = ?"
                cursor = DataStore.current_db.only_execute(errors_query, (taskid,))
                errors_count = cursor.fetchone()[0] if cursor else 0
                
                # 查询日志数
                logs_query = "SELECT COUNT(*) FROM logs WHERE taskid = ?"
                cursor = DataStore.current_db.only_execute(logs_query, (taskid,))
                logs_count = cursor.fetchone()[0] if cursor else 0
                
                # 查询数据数
                data_query = "SELECT COUNT(*) FROM data WHERE taskid = ?"
                cursor = DataStore.current_db.only_execute(data_query, (taskid,))
                data_count = cursor.fetchone()[0] if cursor else 0

                index += 1
                task_src_status = task.status

                if task_src_status in [TaskStatus.New, TaskStatus.Runnable, TaskStatus.Blocked]:
                    tmp_task_status = task_src_status.value
                else:
                    tmp_task_status = TaskStatus.Terminated.value if task.engine_has_terminated() else TaskStatus.Running.value

                resul_task_item = {
                    "index": index,
                    "create_datetime": None if task.create_datetime is None else task.create_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                    "start_datetime": None if task.start_datetime is None else task.start_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                    "task_id": taskid,
                    "scanUrl": task.scanUrl,
                    "host": task.host,
                    "remote_addr": task.remote_addr,
                    "errors": errors_count,
                    "logs": logs_count,
                    "status": tmp_task_status,
                    "injected": data_count > 0
                }
                tasks.append(resul_task_item)

        return ({"tasks": tasks, "tasks_num": len(tasks)}, "success", True, status.HTTP_200_OK)

    async def list_task(self):
        try:
            loop = asyncio.get_event_loop()
            data, msg, success, code = await loop.run_in_executor(
                self._executor, self._list_task_sync
            )
            if not success:
                logger.error(msg)
            return BaseResponseMsg(data=data, msg=msg, success=success, code=code)
        except Exception as e:
            logger.error(f"Error: {e}")
            return BaseResponseMsg(data=None, msg="error", success=False, code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _kill_task_sync(self, taskid):
        """同步终止任务（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                return (False, "Non-existing task ID", status.HTTP_404_NOT_FOUND)
            tmp_task_status = DataStore.tasks[taskid].status
            if tmp_task_status == TaskStatus.Running:
                DataStore.tasks[taskid].engine_kill()
            DataStore.tasks[taskid].status = TaskStatus.Terminated
            return (True, f"task {taskid} was Killed", status.HTTP_200_OK)

    async def kill_task(self, taskid):
        loop = asyncio.get_event_loop()
        success, msg, code = await loop.run_in_executor(
            self._executor, self._kill_task_sync, taskid
        )
        if not success:
            logger.warning(f"{taskid} Non-existing task ID provided to task_delete()")
        else:
            logger.info(f"[{taskid}] Killed task")
        return BaseResponseMsg(data=None, msg=msg, success=success, code=code)

    def _stop_task_sync(self, taskid):
        """同步停止任务（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                return (False, f"task {taskid} was not running", "not_found")
            if DataStore.tasks[taskid].status == TaskStatus.Running:
                DataStore.tasks[taskid].engine_stop()
                DataStore.tasks[taskid].status = TaskStatus.Blocked
                return (True, f"task {taskid} was stopped", "stopped")
            elif DataStore.tasks[taskid].status in [TaskStatus.New, TaskStatus.Runnable]:
                DataStore.tasks[taskid].status = TaskStatus.Blocked
                return (True, f"task {taskid} was stopped", "stopped")
            elif DataStore.tasks[taskid].status == TaskStatus.Blocked:
                return (False, f"task {taskid} had blocked", "blocked")
            else:
                return (False, f"task {taskid} had terminaled", "terminated")

    async def stop_task(self, taskid):
        loop = asyncio.get_event_loop()
        success, msg, state = await loop.run_in_executor(
            self._executor, self._stop_task_sync, taskid
        )
        if state == "not_found":
            logger.warning(f"[{taskid}] Invalid task ID provided to scan_stop()")
        elif state == "stopped":
            logger.debug(f"[{taskid}] Stopped scan")
        elif state == "blocked":
            logger.warning(f"[{taskid}] task had blocked")
        else:
            logger.warning(f"[{taskid}] task had terminaled!")
        return BaseResponseMsg(data=None, success=success, msg=msg, code=status.HTTP_200_OK)

    def _start_task_sync(self, taskid):
        """同步启动任务（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                return (None, f"Task {taskid} does not exist", "not_found")
            if DataStore.tasks[taskid].status == TaskStatus.Blocked:
                DataStore.tasks[taskid].status = TaskStatus.Runnable
                return (True, f"Task status set to {TaskStatus.Runnable}", "started")
            else:
                current_status = DataStore.tasks[taskid].status
                return (False, f"Task status is {current_status}", "invalid_state")

    async def start_task_with_taskid(self, taskid):
        loop = asyncio.get_event_loop()
        success, msg, state = await loop.run_in_executor(
            self._executor, self._start_task_sync, taskid
        )
        if state == "not_found":
            raise Exception(msg)
        elif state == "started":
            logger.debug(f"{taskid} Task status changed to Runnable")
        else:
            logger.debug(f"{taskid} {msg}")
        return BaseResponseMsg(data=None, success=success if success is not None else False, msg=msg, code=status.HTTP_200_OK)

    def _flush_task_sync(self):
        """同步清空任务（在线程池中执行）"""
        with DataStore.tasks_lock:
            for key in list(DataStore.tasks):
                task = DataStore.tasks[key]
                if task.status == TaskStatus.Running:
                    task.engine_kill()
                del DataStore.tasks[key]

    async def flush_task(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._flush_task_sync)
        logger.debug("Flushed task pool")
        return BaseResponseMsg(data=None, msg="Flushed task pool", success=True, code=status.HTTP_200_OK)

    def _find_task_by_urlPath_sync(self, urlPath: str):
        """同步按URL查找任务（在线程池中执行）"""
        res = []
        with DataStore.tasks_lock:
            for key in list(DataStore.tasks):
                task = DataStore.tasks[key]
                if urlPath in task.scanUrl:
                    res.append(task)
        return res

    async def find_task_by_urlPath(self, urlPath: str):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, self._find_task_by_urlPath_sync, urlPath
        )

    def _find_task_by_taskid_sync(self, taskid: str):
        """同步按ID查找任务（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskid in DataStore.tasks:
                task = DataStore.tasks[taskid]
                return {"task": task}
            return None

    async def find_task_by_taskid(self, taskid: str):
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self._executor, self._find_task_by_taskid_sync, taskid
        )
        if result is None:
            return None
        return BaseResponseMsg(data=result, msg="Find task by taskid", success=True, code=status.HTTP_200_OK)

    def _find_task_by_bodyKeyWord_sync(self, requestBodyKeyWord: str):
        """同步按Body关键字查找任务（在线程池中执行）"""
        res = []
        with DataStore.tasks_lock:
            for taskid in DataStore.tasks:
                task = DataStore.tasks[taskid]
                if task.body and requestBodyKeyWord in task.body:
                    res.append(task)
        return res

    async def find_task_by_bodyKeyWord(self, requestBodyKeyWord: str):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, self._find_task_by_bodyKeyWord_sync, requestBodyKeyWord
        )

    def _build_task_list_from_results_sync(self, all_res):
        """同步构建任务列表（在线程池中执行）"""
        if not all_res:
            return None
        
        with DataStore.tasks_lock:
            if DataStore.current_db is None:
                return None
                
            taskId_set = set()
            task_list = []
            index = 0
            
            for task in all_res:
                if task.taskid not in taskId_set:
                    taskId_set.add(task.taskid)
                    taskid = task.taskid

                    # 查询错误数
                    errors_query = "SELECT COUNT(*) FROM errors WHERE taskid = ?"
                    cursor = DataStore.current_db.only_execute(errors_query, (taskid,))
                    errors_count = cursor.fetchone()[0] if cursor else 0

                    # 查询日志数
                    logs_query = "SELECT COUNT(*) FROM logs WHERE taskid = ?"
                    cursor = DataStore.current_db.only_execute(logs_query, (taskid,))
                    logs_count = cursor.fetchone()[0] if cursor else 0

                    # 查询数据数
                    data_query = "SELECT COUNT(*) FROM data WHERE taskid = ?"
                    cursor = DataStore.current_db.only_execute(data_query, (taskid,))
                    data_count = cursor.fetchone()[0] if cursor else 0

                    index += 1
                    task_src_status = task.status

                    if task_src_status in [TaskStatus.New, TaskStatus.Runnable, TaskStatus.Blocked]:
                        tmp_status = task_src_status.value
                    else:
                        tmp_status = TaskStatus.Terminated.value if task.engine_has_terminated() else TaskStatus.Running.value

                    resul_task_item = {
                        "index": index,
                        "start_datetime": None if task.start_datetime is None else task.start_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                        "task_id": taskid,
                        "scanUrl": task.scanUrl,
                        "errors": errors_count,
                        "logs": logs_count,
                        "status": tmp_status,
                        "injected": data_count > 0
                    }
                    task_list.append(resul_task_item)

        return {"tasks": task_list, "tasks_num": len(task_list)}

    async def find_task_by_KeyWord(self, keyword: str):
        all_res = []

        try:
            urlPath_res = await self.find_task_by_urlPath(keyword)
            if urlPath_res is not None and len(urlPath_res) > 0:
                all_res.extend(urlPath_res)
        except Exception as e:
            logger.error(str(e))

        try:
            host_res = await self.find_task_by_requestHost(keyword)
            if host_res is not None and len(host_res) > 0:
                all_res.extend(host_res)
        except Exception as e:
            logger.error(str(e))

        try:
            header_keyWord_res = await self.find_task_by_header_keyword(keyword)
            if header_keyWord_res is not None and len(header_keyWord_res) > 0:
                all_res.extend(header_keyWord_res)
        except Exception as e:
            logger.error(str(e))

        try:
            body_keyWord_res = await self.find_task_by_bodyKeyWord(keyword)
            if body_keyWord_res is not None and len(body_keyWord_res) > 0:
                all_res.extend(body_keyWord_res)
        except Exception as e:
            logger.error(str(e))

        if not all_res:
            return BaseResponseMsg(data=None, msg="No results found", success=True, code=200)

        # 在线程池中执行数据库查询和结果构建
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(
            self._executor, self._build_task_list_from_results_sync, all_res
        )
        
        if data is None:
            return BaseResponseMsg(data=None, msg="No results found", success=True, code=200)

        return BaseResponseMsg(data=data, success=True, msg="success", code=status.HTTP_200_OK)

    def _find_task_by_header_keyword_sync(self, headerKeyWord: str):
        """同步按Header关键字查找任务（在线程池中执行）"""
        res = []
        with DataStore.tasks_lock:
            for task in DataStore.tasks.values():
                if task.headers is not None:
                    for i in range(1, len(task.headers)):
                        header = task.headers[i]
                        if headerKeyWord in header:
                            res.append(task)
        return res

    async def find_task_by_header_keyword(self, headerKeyWord: str):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, self._find_task_by_header_keyword_sync, headerKeyWord
        )

    def _find_task_by_requestHost_sync(self, requestHost: str):
        """同步按Host查找任务（在线程池中执行）"""
        res = []
        with DataStore.tasks_lock:
            for task in DataStore.tasks.values():
                if task.host == requestHost:
                    res.append(task)
        return res

    async def find_task_by_requestHost(self, requestHost: str):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, self._find_task_by_requestHost_sync, requestHost
        )

    def _find_task_log_sync(self, taskid: str):
        """同步查询任务日志（在线程池中执行）"""
        json_log_messages = []
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                return (None, False, f"task {taskid} does not exist", status.HTTP_404_NOT_FOUND)
            if DataStore.current_db is None:
                return (None, False, "Database connection is not initialized", status.HTTP_500_INTERNAL_SERVER_ERROR)
            try:
                cursor = DataStore.current_db.execute(
                    "SELECT datetime, level, message FROM logs WHERE taskid = ? ORDER BY id ASC", (taskid,)
                )
                if cursor is not None:
                    for datetime_, level, message in cursor:
                        json_log_messages.append({"datetime": datetime_, "level": level, "message": message})
            except Exception as e:
                return (None, False, f"Error fetching logs: {e}", status.HTTP_500_INTERNAL_SERVER_ERROR)
        return (json_log_messages, True, "success", status.HTTP_200_OK)

    async def find_task_log_by_taskid(self, taskid: str):
        loop = asyncio.get_event_loop()
        data, success, msg, code = await loop.run_in_executor(
            self._executor, self._find_task_log_sync, taskid
        )
        if not success:
            logger.error(msg) if code == status.HTTP_500_INTERNAL_SERVER_ERROR else None
        return BaseResponseMsg(data=data, success=success, msg=msg, code=code)

    def _get_payload_detail_sync(self, taskId: str):
        """同步查询任务payload（在线程池中执行）"""
        payloads = []
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return (None, False, "Task not found", status.HTTP_404_NOT_FOUND)
            if DataStore.current_db is None:
                return (None, False, "Database not found", status.HTTP_500_INTERNAL_SERVER_ERROR)
            result_cursor = DataStore.current_db.only_execute(
                "SELECT status, content_type, value FROM data WHERE taskid = ? ORDER BY id", (taskId,)
            )
            if result_cursor is None:
                return (None, False, "data not found", status.HTTP_404_NOT_FOUND)
            index = 0
            for tmp_status, content_type, value in result_cursor:
                index += 1
                payloads.append({
                    "index": index,
                    "status": tmp_status,
                    "content_type": get_content_type_by_number(content_type),
                    "value": value
                })
        return (payloads, True, "success", status.HTTP_200_OK)

    async def get_payload_detail_by_task_id(self, taskId: str):
        loop = asyncio.get_event_loop()
        data, success, msg, code = await loop.run_in_executor(
            self._executor, self._get_payload_detail_sync, taskId
        )
        return BaseResponseMsg(data=data, msg=msg, success=success, code=code)

    def _get_task_http_request_info_sync(self, taskId):
        """同步获取HTTP请求信息（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return (None, False, "taskId not found", status.HTTP_404_NOT_FOUND)
            task = DataStore.tasks[taskId]
            http_info = {
                "url": task.scanUrl,
                "headers": task.headers,
                "body": task.body,
            }
            return (http_info, True, "success", status.HTTP_200_OK)

    async def get_task_http_request_info(self, taskId):
        loop = asyncio.get_event_loop()
        data, success, msg, code = await loop.run_in_executor(
            self._executor, self._get_task_http_request_info_sync, taskId
        )
        return BaseResponseMsg(data=data, msg=msg, success=success, code=code)

    def _get_task_scan_options_sync(self, taskId: str):
        """同步获取扫描选项（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return (None, False, "task not found", status.HTTP_404_NOT_FOUND)
            task = DataStore.tasks[taskId]
            task_options = task.get_options()
            res_options = []
            for option in task_options:
                option_value = task_options[option]
                if option_value is not None:
                    if isinstance(option_value, list) and len(option_value) > 0:
                        res_options.append({"option": option, "value": option_value})
                    elif isinstance(option_value, bool) and option_value is True:
                        res_options.append({"option": option, "value": option_value})
                    elif isinstance(option_value, str) and len(option_value) > 0:
                        res_options.append({"option": option, "value": option_value})
                    elif isinstance(option_value, int) and option_value > 0:
                        res_options.append({"option": option, "value": option_value})
            data = {
                "taskid": taskId,
                "options": res_options,
                "options_cnt": len(res_options),
            }
            return (data, True, "success", status.HTTP_200_OK)

    async def get_task_scan_options(self, taskId: str):
        loop = asyncio.get_event_loop()
        data, success, msg, code = await loop.run_in_executor(
            self._executor, self._get_task_scan_options_sync, taskId
        )
        return BaseResponseMsg(data=data, msg=msg, success=success, code=code)

    def _get_task_errors_sync(self, taskId: str):
        """同步获取任务错误（在线程池中执行）"""
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return (None, False, "taskId not found", status.HTTP_404_NOT_FOUND)
            if DataStore.current_db is None:
                return (None, False, "db not found", status.HTTP_404_NOT_FOUND)
            errors_query = "SELECT id, error FROM errors WHERE taskid = ? order by id ASC"
            cursor = DataStore.current_db.only_execute(errors_query, (taskId,))
            if cursor is None:
                return (None, False, "cursor is None", status.HTTP_404_NOT_FOUND)
            task_errors = []
            index = 0
            for id, error in cursor:
                index += 1
                task_errors.append({"index": index, "id": id, "error": error})
            data = {
                "taskId": taskId,
                "errors": task_errors,
                "errors_cnt": len(task_errors)
            }
            return (data, True, "success", status.HTTP_200_OK)

    async def get_task_errors_by_taskId(self, taskId: str):
        loop = asyncio.get_event_loop()
        data, success, msg, code = await loop.run_in_executor(
            self._executor, self._get_task_errors_sync, taskId
        )
        return BaseResponseMsg(data=data, msg=msg, success=success, code=code)


taskService = TaskService()
