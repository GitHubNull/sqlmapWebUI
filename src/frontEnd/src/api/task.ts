/**
 * 任务相关API
 */
import { request } from './request'
import type { Task } from '@/types/task'
import { generateMockTasks, delay, MockDataMode } from '@/utils/mockData'

// ==================== Mock数据配置 ====================
// 开关：是否使用Mock数据（用于测试大量数据显示）
const USE_MOCK_DATA = true

// Mock数据配置
const MOCK_CONFIG = {
  count: 200,                      // 数据数量
  mode: MockDataMode.LONG_URL,        // 数据模式：NORMAL | LONG_URL | LONG_HOST | MIXED
  delay: 800,                      // 模拟网络延迟（毫秒）
}

/**
 * 可选的数据模式：
 * - MockDataMode.NORMAL: 普通长度的URL和主机名
 * - MockDataMode.LONG_URL: 超长URL（多级路径 + 大量查询参数）
 * - MockDataMode.LONG_HOST: 超长主机名（多级子域名）
 * - MockDataMode.MIXED: 混合模式（50%普通 + 25%超长主机 + 25%超长URL）
 */

/**
 * 获取任务列表
 */
export async function getTaskList(): Promise<Task[]> {
  if (USE_MOCK_DATA) {
    // 使用Mock数据进行测试
    console.log(`🔄 使用Mock数据模式`)
    console.log(`📊 配置: ${MOCK_CONFIG.count}条数据, 模式=${MOCK_CONFIG.mode}`)
    await delay(MOCK_CONFIG.delay) // 模拟网络延迟
    return generateMockTasks(MOCK_CONFIG.count, MOCK_CONFIG.mode)
  }
  
  // 真实API调用
  const result = await request.get<{ tasks: Task[]; tasks_num: number }>('/chrome/admin/task/list')
  return result.tasks || []
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

/**
 * 批量删除任务
 */
export async function batchDeleteTasks(taskIds: string[]): Promise<void> {
  // 逐个删除，因为后端没有批量删除接口
  for (const taskId of taskIds) {
    await deleteTask(taskId)
  }
}

/**
 * 清空所有任务
 */
export function flushTasks(): Promise<void> {
  return request.post('/chrome/admin/task/flush')
}

/**
 * 获取扫描配置
 */
export function getScanOptions(taskId: string): Promise<any> {
  return request.get('/chrome/admin/task/getScanOptionsByTaskId', {
    params: { taskId },
  })
}

/**
 * 获取HTTP请求信息
 */
export function getHttpRequestInfo(taskId: string): Promise<any> {
  return request.get('/chrome/admin/task/getHttpRequestInfo', {
    params: { taskId },
  })
}

/**
 * 获取载荷详情
 */
export function getPayloadDetail(taskId: string): Promise<any> {
  return request.get('/chrome/admin/task/getPayloadDetailByTaskId', {
    params: { taskId },
  })
}

/**
 * 获取错误记录
 */
export function getErrors(taskId: string): Promise<any[]> {
  return request.get('/chrome/admin/task/getErrorsByTaskId', {
    params: { taskId },
  })
}
