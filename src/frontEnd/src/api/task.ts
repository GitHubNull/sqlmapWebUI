/**
 * 任务相关API
 */
import { request } from './request'
import type { Task } from '@/types/task'
import { generateMockTasks, delay, MockDataMode } from '@/utils/mockData'

// ==================== Mock数据配置 ====================
// 开关：是否使用Mock数据（用于测试大量数据显示）
const USE_MOCK_DATA = false

// 开关：扫描结果页面使用Mock数据（用于测试边界情况）
const USE_PAYLOAD_MOCK = false

// Mock数据场景选择
enum PayloadMockScene {
  NORMAL = 'normal',                    // 正常数据：单个注入点
  MULTI_INJECTION = 'multi_injection',  // 多个注入点
  MULTI_TECHNIQUES = 'multi_techniques', // 多种注入技术
  NO_INJECTION = 'no_injection',        // 无注入点
  EMPTY_DATA = 'empty_data',            // 空数据
  PARTIAL_DATA = 'partial_data',        // 部分字段缺失
  INVALID_JSON = 'invalid_json',        // 无效JSON
  OTHER_DATA = 'other_data',            // 其他扫描数据（DBMS信息等）
  FULL_DATA = 'full_data',              // 完整数据（注入+数据库信息）
}

// 当前测试场景
const PAYLOAD_MOCK_SCENE: PayloadMockScene = PayloadMockScene.MULTI_INJECTION

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
 * 后端任务数据接口（字段名与前端不同）
 */
interface BackendTask {
  index: number
  task_id: string
  scanUrl: string
  host: string
  create_datetime: string | null  // 任务创建时间 (New状态)
  start_datetime: string | null   // 任务开始执行时间 (Running状态)
  remote_addr: string
  errors: number
  logs: number
  status: string | number  // 后端可能返回字符串或数字
  injected: boolean
}

/**
 * 后端状态字符串到前端枚举的映射
 */
import { TaskStatus } from '@/types/task'

function mapBackendStatus(status: string | number): TaskStatus {
  // 如果已经是数字，直接返回
  if (typeof status === 'number') {
    return status as TaskStatus
  }
  
  // 字符串状态映射
  const statusMap: Record<string, TaskStatus> = {
    'New': TaskStatus.PENDING,
    'Pending': TaskStatus.PENDING,
    'Running': TaskStatus.RUNNING,
    'Runnable': TaskStatus.RUNNING,
    'Blocked': TaskStatus.RUNNING,
    'Terminated': TaskStatus.TERMINATED,
    'Success': TaskStatus.SUCCESS,
    'Completed': TaskStatus.SUCCESS,
    'Failed': TaskStatus.FAILED,
    'Error': TaskStatus.FAILED,
    'Stopped': TaskStatus.STOPPED,
  }
  
  // 大小写不敏感匹配
  const normalizedStatus = Object.keys(statusMap).find(
    key => key.toLowerCase() === status.toLowerCase()
  )
  
  if (normalizedStatus && statusMap[normalizedStatus] !== undefined) {
    return statusMap[normalizedStatus] as TaskStatus
  }
  
  // 默认返回 PENDING
  console.warn(`Unknown task status: ${status}, defaulting to PENDING`)
  return TaskStatus.PENDING
}

/**
 * 后端任务数据转换为前端格式
 */
function transformBackendTask(backendTask: BackendTask): Task {
  return {
    engineid: backendTask.index,
    taskid: backendTask.task_id,
    scanUrl: backendTask.scanUrl,
    host: backendTask.host,
    status: mapBackendStatus(backendTask.status),  // 转换状态
    createTime: backendTask.create_datetime || '',   // 创建时间
    startTime: backendTask.start_datetime || undefined,  // 开始执行时间
    remote_addr: backendTask.remote_addr,
    errors: backendTask.errors,
    logs: backendTask.logs,
    injected: backendTask.injected,
  }
}

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
  const result = await request.get<{ tasks: BackendTask[]; tasks_num: number }>('/web/admin/task/list')
  // 转换后端字段名为前端字段名
  return (result.tasks || []).map(transformBackendTask)
}

/**
 * 添加任务
 */
export function addTask(taskData: Partial<Task>): Promise<{ engineid: number; taskid: string }> {
  return request.post('/web/admin/task/add', taskData)
}

/**
 * 删除任务
 */
export function deleteTask(taskId: string): Promise<void> {
  return request.delete(`/web/admin/task/delete`, {
    params: { taskid: taskId },
  })
}

/**
 * 停止任务
 */
export function stopTask(taskId: string): Promise<void> {
  return request.put(`/web/admin/task/stop`, { taskid: taskId })
}

/**
 * 根据URL查找任务
 */
export function findTaskByUrl(urlPath: string): Promise<Task[]> {
  return request.post('/web/admin/task/findByUrlPath', { urlPath })
}

/**
 * 后端日志条目接口
 */
interface BackendLogEntry {
  datetime: string
  level: string
  message: string
}

/**
 * 后端错误条目接口
 */
interface BackendErrorEntry {
  index: number
  id: number
  error: string
}

/**
 * 后端错误响应接口
 */
interface BackendErrorsResponse {
  taskId: string
  errors: BackendErrorEntry[]
  errors_cnt: number
}

/**
 * 后端载荷条目接口
 */
interface BackendPayloadEntry {
  index: number
  status: string
  content_type: string  // 后端使用下划线命名
  value: string
}

/**
 * 前端载荷条目接口
 */
export interface PayloadEntry {
  index: number
  status: string
  contentType: string  // 前端使用驼峰命名
  value: string
}

/**
 * 前端错误条目接口
 */
export interface ErrorEntry {
  index: number
  id: number
  error: string
}

/**
 * 获取任务日志
 */
export async function getTaskLogs(taskId: string): Promise<string[]> {
  if (USE_MOCK_DATA) {
    // 生成大量mock日志数据以测试滚动效果
    const mockLogs = [
      `[2025-12-19T10:15:23.456Z] [INFO] 正在启动SQLMap扫描引擎...`,
      `[2025-12-19T10:15:23.789Z] [INFO] 检测到目标URL: http://example.com/test?id=1`,
      `[2025-12-19T10:15:23.890Z] [DEBUG] 加载SQLMap模块: sqlmap/agent.py`,
      `[2025-12-19T10:15:24.012Z] [DEBUG] 使用检测级别: 1`,
      `[2025-12-19T10:15:24.123Z] [DEBUG] 使用风险级别: 1`,
      `[2025-12-19T10:15:24.234Z] [DEBUG] 线程数设置为: 5`,
      `[2025-12-19T10:15:24.345Z] [DEBUG] 数据库类型推测为: MySQL >= 5.0`,
      `[2025-12-19T10:15:24.456Z] [DEBUG] 目标网站技术栈: Apache 2.4, PHP 7.4`,
      `[2025-12-19T10:15:24.567Z] [INFO] 测试GET参数 'id'`,
      `[2025-12-19T10:15:24.678Z] [INFO] 测试布尔盲注 (AND boolean-based blind - WHERE or HAVING clause)`,
      `[2025-12-19T10:15:24.789Z] [INFO] 测试时间盲注 (AND time-based blind - WHERE or HAVING clause)`,
      `[2025-12-19T10:15:24.890Z] [INFO] 测试UNION查询 (UNION query (information_schema) - WHERE or HAVING clause)`,
      `[2025-12-19T10:15:24.991Z] [DEBUG] 发送测试载荷: 1 AND 1=1`,
      `[2025-12-19T10:15:25.092Z] [DEBUG] 发送测试载荷: 1 AND 1=2`,
      `[2025-12-19T10:15:25.193Z] [DEBUG] 比较响应内容长度: 原始(1523) vs 测试1(1523) vs 测试2(1523)`,
      `[2025-12-19T10:15:25.294Z] [DEBUG] 响应内容完全相同，布尔盲注测试失败`,
      `[2025-12-19T10:15:25.395Z] [DEBUG] 尝试时间盲注: 1 AND SLEEP(5)`,
      `[2025-12-19T10:15:30.496Z] [DEBUG] 延迟响应时间: 5.12秒，检测到SLEEP延迟`,
      `[2025-12-19T10:15:30.597Z] [WARNING] 目标URL 'http://example.com/test?id=1' 看起来可能不存在SQL注入`,
      `[2025-12-19T10:15:30.698Z] [WARNING] 检测到WAF/IPS/IDS保护: Cloudflare`,
      `[2025-12-19T10:15:30.799Z] [INFO] 尝试绕过WAF检测...`,
      `[2025-12-19T10:15:30.900Z] [DEBUG] 使用随机User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`,
      `[2025-12-19T10:15:31.001Z] [DEBUG] 随机化头部顺序以避免检测`,
      `[2025-12-19T10:15:31.102Z] [INFO] 重新测试GET参数 'id'`,
      `[2025-12-19T10:15:31.203Z] [INFO] 测试错误基础注入 (MySQL >= 5.0 error-based - WHERE or HAVING clause)`,
      `[2025-12-19T10:15:31.304Z] [DEBUG] 发送错误注入载荷: 1 AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)`,
      `[2025-12-19T10:15:31.405Z] [DEBUG] 响应状态码: 200 (正常)`,
      `[2025-12-19T10:15:31.506Z] [DEBUG] 响应内容中没有检测到数据库错误信息`,
      `[2025-12-19T10:15:31.607Z] [DEBUG] 错误基础注入测试失败`,
      `[2025-12-19T10:15:31.708Z] [INFO] 测试堆叠查询 (MySQL > 5.0 stacked queries)`,
      `[2025-12-19T10:15:31.809Z] [DEBUG] 尝试堆叠查询: 1; SELECT SLEEP(5)--`,
      `[2025-12-19T10:15:36.910Z] [DEBUG] 响应时间: 0.03秒，未检测到延迟`,
      `[2025-12-19T10:15:37.011Z] [DEBUG] 堆叠查询测试失败`,
      `[2025-12-19T10:15:37.112Z] [INFO] 测试UNION查询 (UNION query - WHERE or HAVING clause)`,
      `[2025-12-19T10:15:37.213Z] [DEBUG] 确定列数: 尝试 ORDER BY 1,2,3...`,
      `[2025-12-19T10:15:37.314Z] [DEBUG] ORDER BY 1: 正常响应`,
      `[2025-12-19T10:15:37.415Z] [DEBUG] ORDER BY 2: 正常响应`,
      `[2025-12-19T10:15:37.516Z] [DEBUG] ORDER BY 3: 正常响应`,
      `[2025-12-19T10:15:37.617Z] [DEBUG] ORDER BY 4: 正常响应`,
      `[2025-12-19T10:15:37.718Z] [DEBUG] ORDER BY 5: 正常响应`,
      `[2025-12-19T10:15:37.819Z] [DEBUG] ORDER BY 6: 正常响应`,
      `[2025-12-19T10:15:37.920Z] [DEBUG] ORDER BY 7: 正常响应`,
      `[2025-12-19T10:15:38.021Z] [DEBUG] ORDER BY 8: 正常响应`,
      `[2025-12-19T10:15:38.122Z] [DEBUG] ORDER BY 9: 正常响应`,
      `[2025-12-19T10:15:38.223Z] [DEBUG] ORDER BY 10: 正常响应`,
      `[2025-12-19T10:15:38.324Z] [DEBUG] ORDER BY 11: 正常响应`,
      `[2025-12-19T10:15:38.425Z] [DEBUG] ORDER BY 12: 正常响应`,
      `[2025-12-19T10:15:38.526Z] [DEBUG] ORDER BY 13: 正常响应`,
      `[2025-12-19T10:15:38.627Z] [DEBUG] ORDER BY 14: 正常响应`,
      `[2025-12-19T10:15:38.728Z] [DEBUG] ORDER BY 15: 正常响应`,
      `[2025-12-19T10:15:38.829Z] [DEBUG] ORDER BY 16: 正常响应`,
      `[2025-12-19T10:15:38.930Z] [DEBUG] ORDER BY 17: 正常响应`,
      `[2025-12-19T10:15:39.031Z] [DEBUG] ORDER BY 18: 正常响应`,
      `[2025-12-19T10:15:39.132Z] [DEBUG] ORDER BY 19: 正常响应`,
      `[2025-12-19T10:15:39.233Z] [DEBUG] ORDER BY 20: 正常响应`,
      `[2025-12-19T10:15:39.334Z] [DEBUG] ORDER BY 21: 正常响应`,
      `[2025-12-19T10:15:39.435Z] [DEBUG] ORDER BY 22: 正常响应`,
      `[2025-12-19T10:15:39.536Z] [DEBUG] ORDER BY 23: 正常响应`,
      `[2025-12-19T10:15:39.637Z] [DEBUG] ORDER BY 24: 正常响应`,
      `[2025-12-19T10:15:39.738Z] [DEBUG] ORDER BY 25: 正常响应`,
      `[2025-12-19T10:15:39.839Z] [DEBUG] ORDER BY 26: 正常响应`,
      `[2025-12-19T10:15:39.940Z] [DEBUG] ORDER BY 27: 正常响应`,
      `[2025-12-19T10:15:40.041Z] [DEBUG] ORDER BY 28: 正常响应`,
      `[2025-12-19T10:15:40.142Z] [DEBUG] ORDER BY 29: 正常响应`,
      `[2025-12-19T10:15:40.243Z] [DEBUG] ORDER BY 30: 正常响应`,
      `[2025-12-19T10:15:40.344Z] [DEBUG] ORDER BY 31: 正常响应`,
      `[2025-12-19T10:15:40.445Z] [DEBUG] ORDER BY 32: 正常响应`,
      `[2025-12-19T10:15:40.546Z] [DEBUG] ORDER BY 33: 正常响应`,
      `[2025-12-19T10:15:40.647Z] [DEBUG] ORDER BY 34: 正常响应`,
      `[2025-12-19T10:15:40.748Z] [DEBUG] ORDER BY 35: 正常响应`,
      `[2025-12-19T10:15:40.849Z] [DEBUG] ORDER BY 36: 正常响应`,
      `[2025-12-19T10:15:40.950Z] [DEBUG] ORDER BY 37: 正常响应`,
      `[2025-12-19T10:15:41.051Z] [DEBUG] ORDER BY 38: 正常响应`,
      `[2025-12-19T10:15:41.152Z] [DEBUG] ORDER BY 39: 正常响应`,
      `[2025-12-19T10:15:41.253Z] [DEBUG] ORDER BY 40: 正常响应`,
      `[2025-12-19T10:15:41.354Z] [DEBUG] ORDER BY 41: 正常响应`,
      `[2025-12-19T10:15:41.455Z] [DEBUG] ORDER BY 42: 正常响应`,
      `[2025-12-19T10:15:41.556Z] [DEBUG] ORDER BY 43: 正常响应`,
      `[2025-12-19T10:15:41.657Z] [DEBUG] ORDER BY 44: 正常响应`,
      `[2025-12-19T10:15:41.758Z] [DEBUG] ORDER BY 45: 正常响应`,
      `[2025-12-19T10:15:41.859Z] [DEBUG] ORDER BY 46: 正常响应`,
      `[2025-12-19T10:15:41.960Z] [DEBUG] ORDER BY 47: 正常响应`,
      `[2025-12-19T10:15:42.061Z] [DEBUG] ORDER BY 48: 正常响应`,
      `[2025-12-19T10:15:42.162Z] [DEBUG] ORDER BY 49: 正常响应`,
      `[2025-12-19T10:15:42.263Z] [DEBUG] ORDER BY 50: 正常响应`,
      `[2025-12-19T10:15:42.364Z] [DEBUG] ORDER BY 51: 正常响应`,
      `[2025-12-19T10:15:42.465Z] [DEBUG] ORDER BY 52: 正常响应`,
      `[2025-12-19T10:15:42.566Z] [DEBUG] ORDER BY 53: 正常响应`,
      `[2025-12-19T10:15:42.667Z] [DEBUG] ORDER BY 54: 正常响应`,
      `[2025-12-19T10:15:42.768Z] [DEBUG] ORDER BY 55: 正常响应`,
      `[2025-12-19T10:15:42.869Z] [DEBUG] ORDER BY 56: 正常响应`,
      `[2025-12-19T10:15:42.970Z] [DEBUG] ORDER BY 57: 正常响应`,
      `[2025-12-19T10:15:43.071Z] [DEBUG] ORDER BY 58: 正常响应`,
      `[2025-12-19T10:15:43.172Z] [DEBUG] ORDER BY 59: 正常响应`,
      `[2025-12-19T10:15:43.273Z] [DEBUG] ORDER BY 60: 正常响应`,
      `[2025-12-19T10:15:43.374Z] [DEBUG] ORDER BY 61: 正常响应`,
      `[2025-12-19T10:15:43.475Z] [DEBUG] ORDER BY 62: 正常响应`,
      `[2025-12-19T10:15:43.576Z] [DEBUG] ORDER BY 63: 正常响应`,
      `[2025-12-19T10:15:43.677Z] [DEBUG] ORDER BY 64: 正常响应`,
      `[2025-12-19T10:15:43.778Z] [DEBUG] ORDER BY 65: 正常响应`,
      `[2025-12-19T10:15:43.879Z] [DEBUG] ORDER BY 66: 正常响应`,
      `[2025-12-19T10:15:43.980Z] [DEBUG] ORDER BY 67: 正常响应`,
      `[2025-12-19T10:15:44.081Z] [DEBUG] ORDER BY 68: 正常响应`,
      `[2025-12-19T10:15:44.182Z] [DEBUG] ORDER BY 69: 正常响应`,
      `[2025-12-19T10:15:44.283Z] [DEBUG] ORDER BY 70: 正常响应`,
      `[2025-12-19T10:15:44.384Z] [DEBUG] ORDER BY 71: 正常响应`,
      `[2025-12-19T10:15:44.485Z] [DEBUG] ORDER BY 72: 正常响应`,
      `[2025-12-19T10:15:44.586Z] [DEBUG] ORDER BY 73: 正常响应`,
      `[2025-12-19T10:15:44.687Z] [DEBUG] ORDER BY 74: 正常响应`,
      `[2025-12-19T10:15:44.788Z] [DEBUG] ORDER BY 75: 正常响应`,
      `[2025-12-19T10:15:44.889Z] [DEBUG] ORDER BY 76: 正常响应`,
      `[2025-12-19T10:15:44.990Z] [DEBUG] ORDER BY 77: 正常响应`,
      `[2025-12-19T10:15:45.091Z] [DEBUG] ORDER BY 78: 正常响应`,
      `[2025-12-19T10:15:45.192Z] [DEBUG] ORDER BY 79: 正常响应`,
      `[2025-12-19T10:15:45.293Z] [DEBUG] ORDER BY 80: 正常响应`,
      `[2025-12-19T10:15:45.394Z] [DEBUG] ORDER BY 81: 正常响应`,
      `[2025-12-19T10:15:45.495Z] [DEBUG] ORDER BY 82: 正常响应`,
      `[2025-12-19T10:15:45.596Z] [DEBUG] ORDER BY 83: 正常响应`,
      `[2025-12-19T10:15:45.697Z] [DEBUG] ORDER BY 84: 正常响应`,
      `[2025-12-19T10:15:45.798Z] [DEBUG] ORDER BY 85: 正常响应`,
      `[2025-12-19T10:15:45.899Z] [DEBUG] ORDER BY 86: 正常响应`,
      `[2025-12-19T10:15:46.000Z] [DEBUG] ORDER BY 87: 正常响应`,
      `[2025-12-19T10:15:46.101Z] [DEBUG] ORDER BY 88: 正常响应`,
      `[2025-12-19T10:15:46.202Z] [DEBUG] ORDER BY 89: 正常响应`,
      `[2025-12-19T10:15:46.303Z] [DEBUG] ORDER BY 90: 正常响应`,
      `[2025-12-19T10:15:46.404Z] [DEBUG] ORDER BY 91: 正常响应`,
      `[2025-12-19T10:15:46.505Z] [DEBUG] ORDER BY 92: 正常响应`,
      `[2025-12-19T10:15:46.606Z] [DEBUG] ORDER BY 93: 正常响应`,
      `[2025-12-19T10:15:46.707Z] [DEBUG] ORDER BY 94: 正常响应`,
      `[2025-12-19T10:15:46.808Z] [DEBUG] ORDER BY 95: 正常响应`,
      `[2025-12-19T10:15:46.909Z] [DEBUG] ORDER BY 96: 正常响应`,
      `[2025-12-19T10:15:47.010Z] [DEBUG] ORDER BY 97: 正常响应`,
      `[2025-12-19T10:15:47.111Z] [DEBUG] ORDER BY 98: 正常响应`,
      `[2025-12-19T10:15:47.212Z] [DEBUG] ORDER BY 99: 正常响应`,
      `[2025-12-19T10:15:47.313Z] [DEBUG] ORDER BY 100: 正常响应`,
      `[2025-12-19T10:15:47.414Z] [DEBUG] 确定该页面有100个字段，可能存在UNION查询注入`,
      `[2025-12-19T10:15:47.515Z] [INFO] 开始枚举数据库信息...`,
      `[2025-12-19T10:15:47.616Z] [INFO] 完成扫描，未发现SQL注入漏洞`
    ]
    return Promise.resolve(mockLogs)
  }

  // 真实API调用，后端返回对象数组，需要转换为字符串数组
  const response = await request.get<BackendLogEntry[]>('/web/admin/task/logs/getLogsByTaskId', {
    params: { taskId },
  })
  
  // 转换对象数组为字符串数组
  if (Array.isArray(response)) {
    return response.map((entry: BackendLogEntry) => 
      `[${entry.datetime}] [${entry.level}] ${entry.message}`
    )
  }
  return []
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
 * 批量停止任务
 */
export async function batchStopTasks(taskIds: string[]): Promise<void> {
  // 逐个停止，因为后端没有批量停止接口
  for (const taskId of taskIds) {
    await stopTask(taskId)
  }
}

/**
 * 清空所有任务
 */
export function flushTasks(): Promise<void> {
  return request.patch('/web/admin/task/flush')
}

/**
 * 获取扫描配置
 */
export function getScanOptions(taskId: string): Promise<any> {
  return request.get('/web/admin/task/getTaskScanOptionsByTaskId', {
    params: { taskId },
  })
}

/**
 * 获取HTTP请求信息
 */
export async function getHttpRequestInfo(taskId: string): Promise<any> {
  if (USE_MOCK_DATA) {
    // 生成超过100行的mock HTTP请求信息
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
    const method = methods[Math.floor(Math.random() * methods.length)]

    // 生成大量请求头（确保超过100行）
    const headers = [
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept: application/json, text/plain, */*',
      'Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,ja;q=0.6',
      'Accept-Encoding: gzip, deflate, br',
      'Content-Type: application/json; charset=UTF-8',
      'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      'X-Request-ID: ' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15),
      'X-Correlation-ID: ' + Math.random().toString(36).substring(2, 15),
      'X-Trace-ID: trace-' + Date.now() + '-' + Math.random().toString(36).substring(2, 10),
      'X-Span-ID: span-' + Math.random().toString(36).substring(2, 15),
      'X-B3-TraceId: ' + Math.random().toString(16).substring(2, 34),
      'X-B3-SpanId: ' + Math.random().toString(16).substring(2, 18),
      'X-B3-ParentSpanId: ' + Math.random().toString(16).substring(2, 18),
      'X-B3-Sampled: 1',
      'Connection: keep-alive',
      'Cache-Control: no-cache, no-store, must-revalidate',
      'Pragma: no-cache',
      'Expires: 0',
      'Origin: https://example.com',
      'Referer: https://example.com/dashboard/tasks/list?page=1&limit=20',
      'Sec-Ch-Ua: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
      'Sec-Ch-Ua-Mobile: ?0',
      'Sec-Ch-Ua-Platform: "Windows"',
      'Sec-Fetch-Dest: empty',
      'Sec-Fetch-Mode: cors',
      'Sec-Fetch-Site: same-origin',
      'X-Forwarded-For: 192.168.1.100, 10.0.0.1, 172.16.0.1',
      'X-Forwarded-Host: example.com',
      'X-Forwarded-Proto: https',
      'X-Real-IP: 192.168.1.100',
      'X-Original-URL: /api/v2/users/profile',
      'X-Rewrite-URL: /internal/api/users/profile',
      'X-Custom-Header-1: value-' + Math.random().toString(36).substring(2, 20),
      'X-Custom-Header-2: value-' + Math.random().toString(36).substring(2, 20),
      'X-Custom-Header-3: value-' + Math.random().toString(36).substring(2, 20),
      'X-Custom-Header-4: value-' + Math.random().toString(36).substring(2, 20),
      'X-Custom-Header-5: value-' + Math.random().toString(36).substring(2, 20),
      'X-API-Key: api_key_' + Math.random().toString(36).substring(2, 30),
      'X-API-Secret: secret_' + Math.random().toString(36).substring(2, 40),
      'X-Client-ID: client_' + Math.random().toString(36).substring(2, 15),
      'X-Client-Version: 2.5.0-beta.3',
      'X-App-Version: 1.0.0',
      'X-Device-ID: device_' + Math.random().toString(36).substring(2, 20),
      'X-Device-Type: desktop',
      'X-Platform: web',
      'X-OS: Windows 10',
      'X-Browser: Chrome 120',
      'X-Screen-Resolution: 1920x1080',
      'X-Timezone: Asia/Shanghai',
      'X-Locale: zh-CN',
      'X-Currency: CNY',
      'X-Session-ID: sess_' + Math.random().toString(36).substring(2, 30),
      'X-User-ID: user_' + Math.floor(Math.random() * 100000),
      'X-Tenant-ID: tenant_' + Math.floor(Math.random() * 1000),
      'X-Organization-ID: org_' + Math.floor(Math.random() * 500),
      'X-Workspace-ID: ws_' + Math.floor(Math.random() * 100),
      'X-Project-ID: proj_' + Math.floor(Math.random() * 200),
      'X-Environment: production',
      'X-Region: cn-east-1',
      'X-Datacenter: dc-shanghai-01',
      'X-Cluster: cluster-main',
      'X-Node: node-' + Math.floor(Math.random() * 10),
      'X-Pod: pod-' + Math.random().toString(36).substring(2, 10),
      'X-Container: container-app',
      'X-Service-Name: user-service',
      'X-Service-Version: v2.3.1',
      'X-Feature-Flags: feature1=true,feature2=false,feature3=true',
      'X-AB-Test-Group: experiment-group-b',
      'X-Rate-Limit-Remaining: 4999',
      'X-Rate-Limit-Reset: ' + (Date.now() + 3600000),
      'X-Request-Start-Time: ' + Date.now(),
      'X-Response-Time: 0',
      'DNT: 1',
      'X-CSRF-Token: csrf_' + Math.random().toString(36).substring(2, 40),
      'X-XSRF-Token: xsrf_' + Math.random().toString(36).substring(2, 40),
      'X-Content-Type-Options: nosniff',
      'X-Frame-Options: DENY',
      'X-XSS-Protection: 1; mode=block',
      'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      'Referrer-Policy: strict-origin-when-cross-origin',
      'Permissions-Policy: geolocation=(), microphone=(), camera=()',
      'X-Permitted-Cross-Domain-Policies: none',
      'X-Download-Options: noopen',
      'X-DNS-Prefetch-Control: off',
      'Expect-CT: max-age=86400, enforce',
      'X-Debug-Mode: false',
      'X-Log-Level: INFO',
      'X-Compression: gzip',
      'X-Signature: sig_' + Math.random().toString(36).substring(2, 64),
      'X-Timestamp: ' + new Date().toISOString(),
      'X-Nonce: nonce_' + Math.random().toString(36).substring(2, 20),
      'X-Version: 1.0.0',
      'X-Build-Number: 12345',
      'X-Git-Commit: ' + Math.random().toString(16).substring(2, 42),
      'X-Build-Time: 2025-12-19T10:00:00Z',
      'X-Deployment-ID: deploy_' + Math.random().toString(36).substring(2, 15),
    ]

    // 生成大型JSON body
    const body = JSON.stringify({
      user: {
        id: Math.floor(Math.random() * 100000),
        username: 'testuser_' + Math.random().toString(36).substring(2, 10),
        email: 'test_' + Math.random().toString(36).substring(2, 8) + '@example.com',
        profile: {
          firstName: 'John',
          lastName: 'Doe',
          avatar: 'https://cdn.example.com/avatars/user_' + Math.floor(Math.random() * 1000) + '.jpg',
          bio: 'This is a test user profile with some description text.',
          location: {
            city: 'Shanghai',
            country: 'China',
            timezone: 'Asia/Shanghai',
            coordinates: { lat: 31.2304, lng: 121.4737 }
          },
          preferences: {
            theme: 'dark',
            language: 'zh-CN',
            notifications: { email: true, push: true, sms: false }
          }
        },
        permissions: ['read', 'write', 'delete', 'admin'],
        roles: ['user', 'editor', 'moderator'],
        metadata: {
          createdAt: '2024-01-15T08:30:00Z',
          updatedAt: '2025-12-19T10:15:00Z',
          lastLoginAt: '2025-12-19T09:00:00Z',
          loginCount: 1523
        }
      },
      action: 'update',
      timestamp: new Date().toISOString(),
      requestId: Math.random().toString(36).substring(2, 20)
    }, null, 2)

    return Promise.resolve({
      method,
      url: 'http://example.com/api/v2/users/profile/update?source=web&version=2.0',
      headers,
      body
    })
  }

  // 真实API调用，后端已经返回method字段
  const response = await request.get<{
    url: string
    method: string
    headers: string[]
    body: string
  }>('/web/admin/task/getTaskHttpRequestInfoByTaskId', {
    params: { taskId },
  })
  
  // 优先使用后端返回的method，如果不存在再从headers[0]解析（兼容性考虑）
  let method = response.method || 'GET'
  if (!response.method && response.headers && response.headers.length > 0 && response.headers[0]) {
    const requestLine = response.headers[0]
    const match = requestLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s/i)
    if (match && match[1]) {
      method = match[1].toUpperCase()
    }
  }
  
  return {
    method,
    url: response.url,
    headers: response.headers || [],
    body: response.body || ''
  }
}

/**
 * 获取载荷详情
 */
export async function getPayloadDetail(taskId: string): Promise<PayloadEntry[]> {
  if (USE_MOCK_DATA || USE_PAYLOAD_MOCK) {
    // 根据场景生成不同的mock数据
    return Promise.resolve(generatePayloadMockData(PAYLOAD_MOCK_SCENE))
  }

  // 真实API调用，后端使用content_type，需要转换为contentType
  const response = await request.get<BackendPayloadEntry[]>('/web/admin/task/getPayloadDetailByTaskId', {
    params: { taskId },
  })
  
  // 转换字段名
  if (Array.isArray(response)) {
    return response.map((entry: BackendPayloadEntry): PayloadEntry => ({
      index: entry.index,
      status: entry.status,
      contentType: entry.content_type,  // 字段名映射
      value: entry.value
    }))
  }
  return []
}

/**
 * 生成扫描结果Mock数据
 */
function generatePayloadMockData(scene: PayloadMockScene): PayloadEntry[] {
  switch (scene) {
    case PayloadMockScene.NORMAL:
      // 场景1: 正常单个注入点
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: JSON.stringify({
            url: 'http://127.0.0.1:9527/api/user/profile',
            query: 'id=1',
            data: null
          })
        },
        {
          index: 2,
          status: '1',
          contentType: 'TECHNIQUES',
          value: JSON.stringify([{
            place: 'GET',
            parameter: 'id',
            ptype: 1,
            prefix: '',
            suffix: '',
            dbms: 'MySQL',
            dbms_version: ['>= 5.0'],
            data: {
              '1': {
                title: 'AND boolean-based blind - WHERE or HAVING clause',
                payload: 'id=1 AND 1234=1234',
                vector: 'AND [INFERENCE]',
                trueCode: 200,
                falseCode: 404
              }
            }
          }])
        }
      ]

    case PayloadMockScene.MULTI_INJECTION:
      // 场景2: 多个注入点（GET + POST）
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: JSON.stringify({
            url: 'http://127.0.0.1:9527/api/user/search',
            query: 'name=test&page=1',
            data: 'keyword=admin&limit=10'
          })
        },
        {
          index: 2,
          status: '1',
          contentType: 'TECHNIQUES',
          value: JSON.stringify([
            {
              place: 'GET',
              parameter: 'name',
              ptype: 1,
              dbms: 'MySQL',
              dbms_version: ['>= 5.5'],
              data: {
                '1': {
                  title: 'AND boolean-based blind',
                  payload: "name=test' AND 1=1-- -",
                  vector: 'AND [INFERENCE]',
                  trueCode: 200,
                  falseCode: 500
                }
              }
            },
            {
              place: 'POST',
              parameter: 'keyword',
              ptype: 1,
              dbms: 'MySQL',
              dbms_version: ['>= 5.5'],
              data: {
                '5': {
                  title: 'MySQL >= 5.0.12 time-based blind',
                  payload: "keyword=admin' AND SLEEP(5)-- -",
                  vector: 'AND [RANDNUM]=IF([INFERENCE],SLEEP([SLEEPTIME]),[RANDNUM])'
                }
              }
            },
            {
              place: 'GET',
              parameter: 'page',
              ptype: 2,
              dbms: 'MySQL',
              data: {
                '3': {
                  title: 'MySQL UNION query (NULL)',
                  payload: 'page=1 UNION ALL SELECT NULL,CONCAT(0x716b6a7671,0x7a6847),NULL--',
                  vector: '[QUERY] UNION ALL SELECT [COLSTART][PAYLOADF][COLSTOP]'
                }
              }
            }
          ])
        }
      ]

    case PayloadMockScene.MULTI_TECHNIQUES:
      // 场景3: 单个参数多种注入技术
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: JSON.stringify({
            url: 'http://example.com/api/products',
            query: 'id=1'
          })
        },
        {
          index: 2,
          status: '1',
          contentType: 'TECHNIQUES',
          value: JSON.stringify([{
            place: 'GET',
            parameter: 'id',
            ptype: 1,
            prefix: "'",
            suffix: '-- -',
            dbms: 'MySQL',
            dbms_version: ['>= 5.0.12', '< 8.0'],
            os: 'Linux',
            data: {
              '1': {
                title: 'AND boolean-based blind - WHERE or HAVING clause',
                payload: "id=1' AND 5678=5678-- -",
                vector: 'AND [INFERENCE]',
                trueCode: 200,
                falseCode: 404
              },
              '2': {
                title: 'MySQL >= 5.0 error-based - extractvalue',
                payload: "id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
                vector: 'AND EXTRACTVALUE([RANDNUM],CONCAT(0x7e,[QUERY]))'
              },
              '3': {
                title: 'MySQL UNION query (NULL) - 3 columns',
                payload: "id=1' UNION ALL SELECT NULL,CONCAT(0x71,VERSION()),NULL-- -",
                vector: '[QUERY] UNION ALL SELECT [COLSTART][PAYLOAD][COLSTOP]'
              },
              '5': {
                title: 'MySQL >= 5.0.12 time-based blind',
                payload: "id=1' AND SLEEP(5)-- -",
                vector: 'AND [RANDNUM]=IF([INFERENCE],SLEEP([SLEEPTIME]),[RANDNUM])'
              }
            }
          }])
        }
      ]

    case PayloadMockScene.NO_INJECTION:
      // 场景4: 无注入点（仅TARGET）
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: JSON.stringify({
            url: 'http://secure-site.com/api/users',
            query: 'id=123'
          })
        },
        {
          index: 2,
          status: '0',
          contentType: 'TECHNIQUES',
          value: '[]'  // 空数组
        }
      ]

    case PayloadMockScene.EMPTY_DATA:
      // 场景5: 空数据
      return []

    case PayloadMockScene.PARTIAL_DATA:
      // 场景6: 部分字段缺失
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: JSON.stringify({
            url: 'http://test.com/api'  // 缺少query和data
          })
        },
        {
          index: 2,
          status: '1',
          contentType: 'TECHNIQUES',
          value: JSON.stringify([{
            // 缺少place和dbms
            parameter: 'unknown_param',
            data: {
              '1': {
                title: 'Some injection technique',
                payload: 'test payload'
                // 缺少vector, trueCode, falseCode
              }
            }
          }])
        }
      ]

    case PayloadMockScene.INVALID_JSON:
      // 场景7: 无效JSON
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: 'invalid json {{{'
        },
        {
          index: 2,
          status: '1',
          contentType: 'TECHNIQUES',
          value: 'not a valid json array'
        }
      ]

    case PayloadMockScene.OTHER_DATA:
      // 场景8: 其他扫描数据（无注入但有数据库信息）
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: JSON.stringify({
            url: 'http://target.com/api/data',
            query: 'id=1'
          })
        },
        {
          index: 2,
          status: '1',
          contentType: 'DBMS_FINGERPRINT',
          value: 'MySQL >= 5.6'
        },
        {
          index: 3,
          status: '1',
          contentType: 'BANNER',
          value: '5.7.32-0ubuntu0.18.04.1'
        },
        {
          index: 4,
          status: '1',
          contentType: 'CURRENT_USER',
          value: 'root@localhost'
        },
        {
          index: 5,
          status: '1',
          contentType: 'CURRENT_DB',
          value: 'test_database'
        },
        {
          index: 6,
          status: '1',
          contentType: 'HOSTNAME',
          value: 'db-server-01'
        },
        {
          index: 7,
          status: '1',
          contentType: 'DBS',
          value: JSON.stringify(['information_schema', 'mysql', 'test_database', 'production_db'])
        },
        {
          index: 8,
          status: '1',
          contentType: 'TABLES',
          value: JSON.stringify(['users', 'orders', 'products', 'sessions', 'logs'])
        }
      ]

    case PayloadMockScene.FULL_DATA:
    default:
      // 场景9: 完整数据（注入点+数据库信息）
      return [
        {
          index: 1,
          status: '1',
          contentType: 'TARGET',
          value: JSON.stringify({
            url: 'http://vulnerable-app.com/api/users/profile',
            query: 'userId=1&action=view',
            data: null
          })
        },
        {
          index: 2,
          status: '1',
          contentType: 'TECHNIQUES',
          value: JSON.stringify([
            {
              place: 'GET',
              parameter: 'userId',
              ptype: 1,
              prefix: "'",
              suffix: '-- -',
              dbms: 'MySQL',
              dbms_version: ['>= 5.6', '< 8.0'],
              os: 'Linux Ubuntu',
              data: {
                '1': {
                  title: 'AND boolean-based blind - WHERE or HAVING clause',
                  payload: "userId=1' AND 9999=9999-- -",
                  vector: 'AND [INFERENCE]',
                  trueCode: 200,
                  falseCode: 404
                },
                '5': {
                  title: 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)',
                  payload: "userId=1' AND SLEEP(5)-- -",
                  vector: 'AND [RANDNUM]=IF([INFERENCE],SLEEP([SLEEPTIME]),[RANDNUM])'
                }
              }
            },
            {
              place: 'GET',
              parameter: 'action',
              ptype: 1,
              dbms: 'MySQL',
              data: {
                '3': {
                  title: 'MySQL UNION query (NULL) - 5 columns',
                  payload: "action=view' UNION ALL SELECT NULL,NULL,CONCAT(0x71,VERSION()),NULL,NULL-- -",
                  vector: '[QUERY] UNION ALL SELECT [COLSTART][PAYLOAD][COLSTOP]'
                }
              }
            }
          ])
        },
        {
          index: 3,
          status: '1',
          contentType: 'DBMS_FINGERPRINT',
          value: 'MySQL >= 5.6 and < 8.0'
        },
        {
          index: 4,
          status: '1',
          contentType: 'BANNER',
          value: '5.7.42-log'
        },
        {
          index: 5,
          status: '1',
          contentType: 'CURRENT_USER',
          value: 'webapp@%'
        },
        {
          index: 6,
          status: '1',
          contentType: 'CURRENT_DB',
          value: 'vulnerable_app'
        },
        {
          index: 7,
          status: '1',
          contentType: 'IS_DBA',
          value: 'False'
        },
        {
          index: 8,
          status: '1',
          contentType: 'DBS',
          value: JSON.stringify(['information_schema', 'mysql', 'performance_schema', 'vulnerable_app'])
        },
        {
          index: 9,
          status: '1',
          contentType: 'TABLES',
          value: JSON.stringify(['users', 'user_sessions', 'products', 'orders', 'payments', 'admin_logs'])
        },
        {
          index: 10,
          status: '1',
          contentType: 'COLUMNS',
          value: JSON.stringify({
            'users': ['id', 'username', 'password', 'email', 'created_at', 'role'],
            'admin_logs': ['id', 'action', 'user_id', 'ip', 'timestamp']
          })
        }
      ]
  }
}

/**
 * 获取错误记录
 */
export async function getErrors(taskId: string): Promise<ErrorEntry[]> {
  if (USE_MOCK_DATA) {
    // 生成一些模拟错误用于测试
    const mockErrors: ErrorEntry[] = [
      { index: 1, id: 1, error: '[2025-12-19 10:15:30] Connection timeout while testing parameter "id"' },
      { index: 2, id: 2, error: '[2025-12-19 10:15:35] Failed to parse response: invalid JSON format' },
      { index: 3, id: 3, error: '[2025-12-19 10:15:40] WAF detected: Cloudflare blocking requests' },
      { index: 4, id: 4, error: '[2025-12-19 10:15:45] Database error: MySQL syntax error near ORDER BY' },
      { index: 5, id: 5, error: '[2025-12-19 10:15:50] Network unreachable: target host not responding' },
    ]
    // 随机决定是否返回错误（50%概率）
    return Math.random() > 0.5 ? mockErrors : []
  }

  // 真实API调用，后端返回 {taskId, errors: [...], errors_cnt}
  const response = await request.get<BackendErrorsResponse>('/web/admin/task/getTaskErrorsByTaskId', {
    params: { taskId },
  })
  
  // 提取errors数组
  if (response && Array.isArray(response.errors)) {
    return response.errors
  }
  return []
}
