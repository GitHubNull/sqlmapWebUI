from datetime import datetime, timedelta
import os
from model.TaskStatus import TaskStatus
from third_lib.sqlmap.lib.core.data import logger

import psutil

from model.DataStore import DataStore


def get_max_tasks_count():
    """
    计算当前计算机逻辑核心数和 CPU 占用率从而决定最大任务数。
    :return: 最大任务数 (int)
    """
    # logger.debug("Calculating max tasks count...")
    # 获取逻辑核心数
    logical_cores = os.cpu_count() or 1

    # 获取当前 CPU 平均占用率（过去 1 秒的平均值）
    cpu_usage = psutil.cpu_percent(interval=1)

    # 根据 CPU 使用率动态调整最大任务数
    # 如果 CPU 使用率较高，则减少最大任务数
    # 如果 CPU 使用率较低，则允许更多任务
    if cpu_usage < 20:
        max_tasks = logical_cores * 2  # CPU 使用率低，允许更多任务
    elif cpu_usage < 50:
        max_tasks = logical_cores  # CPU 使用率中等，使用逻辑核心数
    else:
        max_tasks = max(1, logical_cores // 2)  # CPU 使用率高，减少任务数

    return max_tasks


def monitor(max_tasks_count=None):
    # logger.info("monitor...")
    # logger.debug(f"monitor -> id(DataStore.tasks): {id(DataStore.tasks)}")
    # logger.debug(f"monitor -> id(DataStore.current_db): {id(DataStore.current_db)}")
    local_max_tasks_count = 0
    local_max_tasks_count = 0
    # 获取逻辑CPU核心数量
    logical_cores = os.cpu_count() or 1
    with DataStore.max_tasks_count_lock:
        if DataStore.first_checkin_monitor:
            if max_tasks_count is not None and max_tasks_count > 0 and max_tasks_count <= (logical_cores - 1):
                local_max_tasks_count = max_tasks_count
            else:
                local_max_tasks_count = DataStore.max_tasks_count
        else:
            local_max_tasks_count = get_max_tasks_count()
        # Ensure local_max_tasks_count is always an integer
        local_max_tasks_count = int(local_max_tasks_count)

        DataStore.max_tasks_count = local_max_tasks_count
    with DataStore.tasks_lock:
        runnable_list = []
        running_task_cnt = 0

        for taskid in DataStore.tasks:
            task = DataStore.tasks[taskid]
            task_orin_status = task.status

            if task_orin_status in [TaskStatus.New, TaskStatus.Runnable]:
                if task_orin_status == TaskStatus.Runnable:
                    runnable_list.append(task)
                continue
            else:
                tmp_task_status = TaskStatus.Terminated if task.engine_has_terminated() is True else TaskStatus.Running
                if tmp_task_status == TaskStatus.Running:
                    running_task_cnt += 1
                else:
                    task.status = TaskStatus.Terminated

        if running_task_cnt < local_max_tasks_count:
            for task in runnable_list:
                if running_task_cnt >= local_max_tasks_count:
                    break
                if task.start_datetime is not None:
                    if datetime.now() - task.start_datetime >= timedelta(seconds=1):
                        running_task_cnt += 1
                        # logger.debug(f"monitor -> task_id: {task.options.taskid} task.start_datetime: {task.start_datetime}")
                        task.engine_start()
                        task.status = TaskStatus.Running
                    else:
                        # logger.debug(f"monitor -> task_id: {task.options.taskid} task.start_datetime: {task.start_datetime}")
                        continue
                else:
                    running_task_cnt += 1
                    # logger.debug(f"monitor -> task_id: {task.options.taskid} task.start_datetime: {task.start_datetime}")
                    task.start_datetime = datetime.now()
                    task.engine_start()
                    task.status = TaskStatus.Running
