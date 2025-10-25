/**
 * 任务相关API
 */
import { request } from './request'
import type { Task } from '@/types/task'

/**
 * 获取任务列表
 */
export function getTaskList(): Promise<Task[]> {
  return request.get('/chrome/admin/task/list')
}

/**
 * 添加任务
 */
export function addTask(taskData: Partial<Task>): Promise<{ engineid: number; taskid: string }> {
  return request.post('/chrome/admin/task/add', taskData)
}

/**
 * 删除任务
 */
export function deleteTask(taskId: string): Promise<void> {
  return request.delete(`/chrome/admin/task/delete`, {
    params: { taskId },
  })
}

/**
 * 停止任务
 */
export function stopTask(taskId: string): Promise<void> {
  return request.put(`/chrome/admin/task/stop`, null, {
    params: { taskId },
  })
}

/**
 * 根据URL查找任务
 */
export function findTaskByUrl(urlPath: string): Promise<Task[]> {
  return request.post('/chrome/admin/task/findByUrlPath', { urlPath })
}

/**
 * 获取任务日志
 */
export function getTaskLogs(taskId: string): Promise<string[]> {
  return request.get('/chrome/admin/task/logs/getLogsByTaskId', {
    params: { taskId },
  })
}
