import pdb
import os
import sys

from fastapi import status

from fastapi.exceptions import HTTPException

sys.path.append("..")
from model.DataStore import DataStore
# from config import data_store
from model.Task import Task
from model.TaskStatus import TaskStatus
from model.requestModel.TaskRequest import TaskAddRequest
from model.BaseResponseMsg import BaseResponseMsg

from ..third_lib.sqlmap.lib.core.settings import RESTAPI_UNSUPPORTED_OPTIONS
from ..third_lib.sqlmap.lib.core.convert import encodeHex
from ..third_lib.sqlmap.lib.core.data import logger
from ..utils.content_type_helper import get_content_type_by_number


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
    """
    # def __init__(self, DataStore.current_db, DataStore.tasks_lock, tasks):
    def __init__(self):
        pass
        # DataStore.current_db = DataStore.current_db
        # DataStore.tasks_lock = DataStore.tasks_lock
        # DataStore.tasks = tasks
        # self.dataStore = dataStore

    async def star_task(self, remote_addr: str, scanUrl: str, host, headers: list, body: str, options: dict):
        option_check_res = validate_options(options)
        if option_check_res is not None:
            return option_check_res
        # # 检查是否有不支持的参数
        # for key, value in options:
        #     if key in RESTAPI_UNSUPPORTED_OPTIONS:
        #         logger.warning(f"Unsupported option '{key}' provided to scan_start()")
        #         return BaseResponseMsg(data=None, msg=f"Unsupported option {key}", success=False, code=status.HTTP_400_BAD_REQUEST)

        taskid = encodeHex(os.urandom(8), binary=False)
        try:
            with DataStore.tasks_lock:
                DataStore.tasks[taskid] = Task(taskid, remote_addr, scanUrl, host, headers, body)

                # pdb.set_trace()
                for option in options:
                    logger.debug(f"option: {option}, value: {options[option]}")
                    DataStore.tasks[taskid].set_option(option, options[option])

                # pdb.set_trace()
                # Launch sqlmap engine in a separate process
                DataStore.tasks[taskid].status = TaskStatus.Runnable

            # return {"engineid": DataStore.tasks[taskid].engine_get_id(), "taskid": taskid}
                return BaseResponseMsg(data={"engineid": DataStore.tasks[taskid].engine_get_id(), "taskid": taskid}, msg="success", success=True, code=status.HTTP_200_OK)
        except Exception as e:
            DataStore.tasks[taskid].status = TaskStatus.Terminated
            logger.error("[%s] Failed to start scan: %s" % (taskid, e))
            raise HTTPException(status_code=500, detail=str(e))

    async def delete_task(self, taskid):
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                logger.warning(f"{taskid} Non-existing task ID provided to task_delete()")
                return BaseResponseMsg(None, msg="Non-existing task ID", success=False, code=400)
            else:
                status = DataStore.tasks[taskid].status
                if status == TaskStatus.Running:
                    DataStore.tasks[taskid].engine_kill()
                DataStore.tasks.pop(taskid)
                logger.info(f"{taskid} Deleted task")
                return BaseResponseMsg(data=None, msg=f"{taskid} Deleted task", success=True, code=200)

    async def list_task(self):
        tasks = []
        index = 0
        try:
            with DataStore.tasks_lock:
                # pdb.set_trace()
                logger.info(f"id(DataStore.current_db): {id(DataStore.current_db)}")
                if DataStore.current_db is None:
                    logger.error("Database connection is not initialized")
                    # return {"success": False, "message": "Database connection is not initialized"}
                    return BaseResponseMsg(data=None, msg="Database connection is not initialized", success=False, code=status.HTTP_500_INTERNAL_SERVER_ERROR)

                for taskid in DataStore.tasks:
                    task = DataStore.tasks[taskid]
                    errors_query = "SELECT COUNT(*) FROM errors WHERE taskid = ?"
                    cursor = DataStore.current_db.only_execute(
                        errors_query, (taskid,))

                    # pdb.set_trace()
                    if cursor is None:
                        errors_count = 0  # 或者根据需求处理其他逻辑
                    else:
                        errors_count = cursor.fetchone()[0]
                        # errors_count = cursor.fetchone()[0] if cursor.fetchone() is not None else 0
                    # pdb.set_trace()
                    # 获取logs表中特定task_id对应的行数
                    logs_query = "SELECT COUNT(*) FROM logs WHERE taskid = ?"
                    cursor = DataStore.current_db.only_execute(
                        logs_query, (taskid,))
                    if cursor is None:
                        logs_count = 0
                    else:
                        # logs_count = cursor.fetchone()[0] if cursor.fetchone() is not None else 0
                        logs_count = cursor.fetchone()[0]

                    data_query = "SELECT COUNT(*) FROM data WHERE taskid = ?"
                    cursor = DataStore.current_db.only_execute(
                        data_query, (taskid,))
                    if cursor is None:
                        data_count = 0
                    else:
                        data_count = cursor.fetchone()[0]
                        # data_count = cursor.fetchone()[0] if cursor.fetchone() is not None else 0

                    index += 1
                    task_src_status = task.status

                    tmp_task_status = None
                    if task_src_status in [TaskStatus.New, TaskStatus.Runnable, TaskStatus.Blocked]:
                        tmp_task_status = task_src_status.value
                    else:
                        tmp_task_status = TaskStatus.Terminated.value if task.engine_has_terminated(
                        ) is True else TaskStatus.Running.value

                    # pdb.set_trace()
                    resul_task_item = {
                        "index": index,
                        "start_datetime": None if task.start_datetime is None else task.start_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                        "task_id": taskid,
                        "scanUrl": task.scanUrl,
                        "errors": errors_count,  # errors_count
                        "logs": logs_count,
                        "status": tmp_task_status,
                        "injected": data_count > 0
                    }
                    tasks.append(resul_task_item)

            data = {
                "tasks": tasks,
                "tasks_num": len(tasks)
            }
            return BaseResponseMsg(data=data, msg="success", success=True, code=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error: {e}")
            return BaseResponseMsg(data=None, msg="error", success=False, code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def kill_task(self, taskid):
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                logger.warning(f"{taskid} Non-existing task ID provided to task_delete()")
                return BaseResponseMsg(data=None, msg="Non-existing task ID", success=False, code=status.HTTP_404_NOT_FOUND)
            else:
                tmp_task_status = DataStore.tasks[taskid].status
                if tmp_task_status == TaskStatus.Running:
                    DataStore.tasks[taskid].engine_kill()

                DataStore.tasks[taskid].status = TaskStatus.Terminated
                logger.info(f"[{taskid}] Deleted task")
                # return {"success": True, "message": f"task {taskid} was Killed"}
                return BaseResponseMsg(data=None, msg=f"task {taskid} was Killed", success=True, code=status.HTTP_200_OK)

    async def stop_task(self, taskid):
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                logger.warning(f"[{taskid}] Invalid task ID provided to scan_stop()")
                return BaseResponseMsg(data=None, success=False, msg=f"task {taskid} was not running", code=status.HTTP_200_OK)
            if DataStore.tasks[taskid].status == TaskStatus.Running:
                DataStore.tasks[taskid].engine_stop()
                DataStore.tasks[taskid].status = TaskStatus.Blocked
                logger.debug(f"[{taskid}] Stopped scan")
                return BaseResponseMsg(data=None, success=True, msg=f"task {taskid} was stopped", code=status.HTTP_200_OK)
            elif DataStore.tasks[taskid].status in [TaskStatus.New, TaskStatus.Runnable]:
                DataStore.tasks[taskid].status = TaskStatus.Blocked
                logger.debug(f"[{taskid}] Stopped scan")
                return BaseResponseMsg(data=None, success=True, msg=f"task {taskid} was stopped", code=status.HTTP_200_OK)
            elif DataStore.tasks[taskid].status == TaskStatus.Blocked:
                logger.warning(f"[{taskid}] task had blocked")
                return BaseResponseMsg(data=None, success=False, msg=f"task {taskid} had blocked", code=status.HTTP_200_OK)
            else:
                logger.warning(f"[{taskid}] task had terminaled!")
                return BaseResponseMsg(data=None, success=False, msg=f"task {taskid} had terminaled", code=status.HTTP_200_OK)

    async def start_task_with_taskid(self, taskid):
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                raise Exception(f"Task {taskid} does not exist")

            if DataStore.tasks[taskid].status == TaskStatus.Blocked:
                DataStore.tasks[taskid].status = TaskStatus.Runnable
                logger.debug(f"{taskid} Task status changed to Runnable")
                return BaseResponseMsg(data=None, success=True, msg=f"Task status set to {TaskStatus.Runnable}", code=status.HTTP_200_OK)
            else:
                logger.debug(f"{taskid} Task status is {DataStore.tasks[taskid].status}")
                return BaseResponseMsg(data=None, success=False, msg=f"Task status is {DataStore.tasks[taskid].status}", code=status.HTTP_200_OK)

    async def flush_task(self):
        with DataStore.tasks_lock:
            for key in list(DataStore.tasks):
                task = DataStore.tasks[key]
                if task.status == TaskStatus.Running:
                    task.engine_kill()
                del DataStore.tasks[key]

        logger.debug("Flushed task pool")
        return BaseResponseMsg(data=None, msg="Flushed task pool", success=True, code=status.HTTP_200_OK)

    async def find_task_by_urlPath(self, urlPath: str):
        res = []
        with DataStore.tasks_lock:
            for key in list(DataStore.tasks):
                task = DataStore.tasks[key]
                if urlPath in task.scanUrl:
                    res.append(task)

        return res

    async def find_task_by_taskid(self, taskid: str):
        task = None
        with DataStore.tasks_lock:
            if taskid in DataStore.tasks:
                task = DataStore.tasks[taskid]
            else:
                return None
        data = {
            "task": task
        }
        return BaseResponseMsg(data=data, msg="Find task by taskid", success=True, code=status.HTTP_200_OK)

    async def find_task_by_bodyKeyWord(self, requestBodyKeyWord: str):
        res = []
        with DataStore.tasks_lock:
            for taskid in DataStore.tasks:
                task = DataStore.tasks[taskid]
                if requestBodyKeyWord in task.body:
                    res.append(task)
        return res

    async def find_task_by_KeyWord(self, keyword: str):
        all_res = []

        try:
            urlPath_res = await self.find_task_by_urlPath(keyword)
            if urlPath_res is not None and 0 < len(urlPath_res):
                all_res.extend(urlPath_res)
        except Exception as e:
            logger.error(str(e))

        try:
            host_res = await self.find_task_by_requestHost(keyword)
            if host_res is not None and 0 < len(host_res):
                all_res.extend(host_res)
        except Exception as e:
            logger.error(str(e))

        try:
            header_keyWord_res = await self.find_task_by_header_keyword(keyword)
            if header_keyWord_res is not None and 0 < len(header_keyWord_res):
                all_res.extend(header_keyWord_res)
        except Exception as e:
            logger.error(str(e))

        try:
            body_keyWord_res = await self.find_task_by_bodyKeyWord(keyword)
            if body_keyWord_res is not None and 0 < len(body_keyWord_res):
                all_res.extend(body_keyWord_res)
        except Exception as e:
            logger.error(str(e))

        if all_res is None:
            return BaseResponseMsg(data=None, msg="No results found", success=True, code=200)

        taskId_set = set()
        task_list = []
        index = 0
        for task in all_res:
            if task.taskid not in taskId_set:
                taskId_set.add(task.taskid)
                taskid = task.taskid

                errors_query = "SELECT COUNT(*) FROM errors WHERE taskid = ?"
                cursor = DataStore.current_db.only_execute(  # type: ignore
                    errors_query, (taskid,))

                # pdb.set_trace()
                if cursor is None:
                    errors_count = 0  # 或者根据需求处理其他逻辑
                else:
                    errors_count = cursor.fetchone()[0]
                    # errors_count = cursor.fetchone()[0] if cursor.fetchone() is not None else 0
                # pdb.set_trace()
                # 获取logs表中特定task_id对应的行数
                logs_query = "SELECT COUNT(*) FROM logs WHERE taskid = ?"
                cursor = DataStore.current_db.only_execute(  # type: ignore
                    logs_query, (taskid,))
                if cursor is None:
                    logs_count = 0
                else:
                    # logs_count = cursor.fetchone()[0] if cursor.fetchone() is not None else 0
                    logs_count = cursor.fetchone()[0]

                data_query = "SELECT COUNT(*) FROM data WHERE taskid = ?"
                cursor = DataStore.current_db.only_execute(  # type: ignore
                    data_query, (taskid,))
                if cursor is None:
                    data_count = 0
                else:
                    data_count = cursor.fetchone()[0]
                    # data_count = cursor.fetchone()[0] if cursor.fetchone() is not None else 0

                index += 1
                task_src_status = task.status

                tmp_status = None
                if task_src_status in [TaskStatus.New, TaskStatus.Runnable, TaskStatus.Blocked]:
                    tmp_status = task_src_status.value
                else:
                    tmp_status = TaskStatus.Terminated.value if task.engine_has_terminated(
                    ) is True else TaskStatus.Running.value

                # pdb.set_trace()
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

        data = {
            "tasks": task_list,
            "tasks_num": len(task_list)
        }

        return BaseResponseMsg(data=data, success=True, msg="success", code=status.HTTP_200_OK)

    async def find_task_by_header_keyword(self, headerKeyWord: str):
        res = []
        with DataStore.tasks_lock:
            for task in DataStore.tasks.values():
                # pdb.set_trace()
                if task.headers is not None:
                    for i in range(1, len(task.headers)):
                        header = task.headers[i]
                        if headerKeyWord in header:
                            res.append(task)

        return res

    async def find_task_by_requestHost(self, requestHost: str):
        res = []
        with DataStore.tasks_lock:
            for task in DataStore.tasks.values():
                if task.host == requestHost:
                    res.append(task)

        return res

    async def find_task_log_by_taskid(self, taskid: str):
        json_log_messages = list()
        with DataStore.tasks_lock:
            if taskid not in DataStore.tasks:
                return BaseResponseMsg(data=None, success=False, msg=f"task {taskid} does not exist", code=status.HTTP_404_NOT_FOUND)

            if DataStore.current_db is None:
                logger.error("Database connection is not initialized")
                return BaseResponseMsg(data=None, msg="Database connection is not initialized", success=False, code=status.HTTP_500_INTERNAL_SERVER_ERROR)

            try:
                cursor = DataStore.current_db.execute("SELECT datetime, level, message FROM logs WHERE taskid = ? ORDER BY id ASC", (taskid,))
                if cursor is not None:
                    for detatime_, level, message in cursor:
                        json_log_messages.append({"datetime": detatime_, "level": level, "message": message})
                else:
                    logger.warning(f"No logs found for task {taskid}")
            except Exception as e:
                logger.error(f"Error fetching logs for task {taskid}: {e}")
                return BaseResponseMsg(data=None, msg="Error fetching logs", success=False, code=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return BaseResponseMsg(data=json_log_messages, msg="success", success=True, code=status.HTTP_200_OK)

    async def get_payload_detail_by_task_id(self, taskId: str):
        paylaods = []
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return BaseResponseMsg(data=None, msg="Task not found", success=False, code=status.HTTP_404_NOT_FOUND)
            if DataStore.current_db is None:
                return BaseResponseMsg(data=None, msg="Database not found", success=False, code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            result_cursor = DataStore.current_db.only_execute("SELECT status, content_type, value FROM data WHERE taskid = ? ORDER BY id", (taskId,))

            if result_cursor is None:
                return BaseResponseMsg(data=None, msg="data not fuond", success=False, code=status.HTTP_404_NOT_FOUND)

            index = 0
            for tmp_task_status, content_type, value in result_cursor:
                index += 1
                paylaods.append({
                    "index": index,
                    "status": tmp_task_status,
                    "content_type": get_content_type_by_number(content_type),
                    "value": value
                })

            # logger.info(f"[+] taskId: {taskId}, payloads: {paylaods}")
            return BaseResponseMsg(data=paylaods, msg="success", success=True, code=status.HTTP_200_OK)

    async def get_task_http_request_info(self, taskId):
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return BaseResponseMsg(data=None, msg="taskId not found", success=False, code=status.HTTP_404_NOT_FOUND)
            else:
                task = DataStore.tasks[taskId]
                http_info = {
                    "url": task.scanUrl,
                    "headers": task.headers,
                    "body": task.body,
                }
                return BaseResponseMsg(data=http_info, msg="success", success=True, code=status.HTTP_200_OK)

    async def get_task_scan_options(self, taskId: str):
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return BaseResponseMsg(data=None, msg="task not found", success=False, code=status.HTTP_404_NOT_FOUND)

            task = DataStore.tasks[taskId]
            task_options = task.get_options()
            # logger.info(f"task_options: {task_options}")
            res_options = []
            for option in task_options:
                option_value = task_options[option]
                # logger.info(f"option: {option}, option_value: {option_value}")
                if option_value is not None:
                    if isinstance(option_value, list) and 0 < len(option_value):
                        res_options.append({"option": option, "value": option_value})
                    elif isinstance(option_value, bool) and option_value is True:
                        res_options.append({"option": option, "value": option_value})
                    elif isinstance(option_value, str) and 0 < len(option_value):
                        res_options.append({"option": option, "value": option_value})
                    elif isinstance(option_value, int) and option_value > 0:
                        res_options.append({"option": option, "value": option_value})

            data = {
                "taskid": taskId,
                "options": res_options,
                "options_cnt": len(res_options),
            }
            return BaseResponseMsg(data=data, msg="success", success=True, code=status.HTTP_200_OK)

    async def get_task_errors_by_taskId(self, taskId: str):
        with DataStore.tasks_lock:
            if taskId not in DataStore.tasks:
                return BaseResponseMsg(msg="taskId not found", success=False, code=status.HTTP_404_NOT_FOUND)

            if DataStore.current_db is None:
                return BaseResponseMsg(msg="db not found", success=False, code=status.HTTP_404_NOT_FOUND)

            errors_query = "SELECT id, error FROM errors WHERE taskid = ? order by id ASC"
            cursor = DataStore.current_db.only_execute(
                errors_query, (taskId,))

            if cursor is None:
                return BaseResponseMsg(data=None, msg="cursor is None", success=False, code=status.HTTP_404_NOT_FOUND)

            task_errors = list()
            index = 0
            for id, error in cursor:
                index += 1
                task_errors.append({"index": index, "id": id, "error": error})

            test_errors = [
                {
                    "index": 1,
                    "id": 0,
                    "error": "Network connection timed out"
                },
                {
                    "index": 2,
                    "id": 1,
                    "error": "File not found"
                },
                {
                    "index": 3,
                    "id": 2,
                    "error": "Unexpected server error"
                }
            ]

            data = {
                "taskId": taskId,
                "errors": task_errors,
                "errors_cnt": len(task_errors)
            }

            return BaseResponseMsg(data=data, msg="success", success=True, code=status.HTTP_200_OK)


taskService = TaskService()
