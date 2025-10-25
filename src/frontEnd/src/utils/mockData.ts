/**
 * Mock数据生成器 - 用于测试大数据量显示
 */
import type { Task } from '@/types/task'
import { TaskStatus } from '@/types/task'

/**
 * 生成随机任务数据
 */
export function generateMockTask(index: number): Task {
  const statuses = [
    TaskStatus.PENDING,
    TaskStatus.RUNNING,
    TaskStatus.SUCCESS,
    TaskStatus.FAILED,
    TaskStatus.STOPPED,
  ]
  
  const domains = [
    'example.com',
    'test-site.org',
    'demo-app.net',
    'api.service.io',
    'backend.platform.com',
    'app.cloud-service.cn',
    'web.security-test.com',
    'portal.enterprise.net',
  ]
  
  const paths = [
    '/api/users',
    '/api/products',
    '/api/orders',
    '/login',
    '/admin/dashboard',
    '/search',
    '/profile',
    '/settings',
    '/checkout',
    '/api/v1/data',
    '/api/v2/auth',
    '/user/info',
  ]
  
  const randomDomain = domains[Math.floor(Math.random() * domains.length)]!
  const randomPath = paths[Math.floor(Math.random() * paths.length)]!
  const randomStatus = statuses[Math.floor(Math.random() * statuses.length)]!
  
  // 生成随机日期（最近30天内）
  const now = new Date()
  const daysAgo = Math.floor(Math.random() * 30)
  const createTime = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000)
  
  return {
    engineid: 1000 + index,
    taskid: `task-${String(index).padStart(6, '0')}-${Math.random().toString(36).substring(2, 9)}`,
    scanUrl: `https://${randomDomain}${randomPath}?id=${Math.floor(Math.random() * 1000)}`,
    host: randomDomain,
    status: randomStatus,
    createTime: createTime.toISOString(),
    headers: [
      'User-Agent: Mozilla/5.0',
      'Accept: application/json',
      `Authorization: Bearer token-${index}`,
    ],
    body: JSON.stringify({ test: `data-${index}` }),
    options: {
      level: Math.floor(Math.random() * 5) + 1,
      risk: Math.floor(Math.random() * 3) + 1,
      threads: Math.floor(Math.random() * 10) + 1,
    },
    updateTime: createTime.toISOString(),
  }
}

/**
 * 生成指定数量的Mock任务数据
 */
export function generateMockTasks(count: number = 200): Task[] {
  const tasks: Task[] = []
  for (let i = 0; i < count; i++) {
    tasks.push(generateMockTask(i))
  }
  return tasks
}

/**
 * 延迟执行（模拟网络请求）
 */
export function delay(ms: number = 500): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
