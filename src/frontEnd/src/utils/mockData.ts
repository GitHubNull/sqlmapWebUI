/**
 * Mock数据生成器 - 用于测试大数据量显示
 * 使用 Mock.js 生成更真实的随机数据
 */
import Mock from 'mockjs'
import type { Task } from '@/types/task'
import { TaskStatus } from '@/types/task'

/**
 * 数据生成模式
 */
export enum MockDataMode {
  /** 普通模式 - 正常长度的URL和主机名 */
  NORMAL = 'normal',
  /** 超长URL模式 - 测试URL超长情况 */
  LONG_URL = 'long_url',
  /** 超长主机名模式 - 测试主机名超长情况 */
  LONG_HOST = 'long_host',
  /** 混合模式 - 包含各种情况 */
  MIXED = 'mixed',
}

/**
 * 生成超长主机名（多级子域名）
 */
function generateLongHost(): string {
  const subdomains = [
    'api', 'backend', 'frontend', 'admin', 'user', 'data', 'service',
    'production', 'staging', 'development', 'test', 'secure', 'cdn',
    'static', 'media', 'assets', 'images', 'files', 'docs', 'portal',
  ]
  
  // 生成5-8级子域名
  const levels = Mock.Random.integer(5, 8)
  const parts: string[] = []
  
  for (let i = 0; i < levels; i++) {
    const subdomain = Mock.Random.pick(subdomains)
    const suffix = Mock.Random.string('lower', 3, 8)
    parts.push(`${subdomain}-${suffix}`)
  }
  
  // 添加主域名
  const mainDomain = Mock.Random.domain()
  parts.push(mainDomain)
  
  return parts.join('.')
}

/**
 * 生成超长URL（多级路径 + 大量查询参数）
 */
function generateLongUrl(host: string): string {
  // 生成多级路径（5-10级）
  const pathLevels = Mock.Random.integer(5, 10)
  const pathParts: string[] = []
  
  for (let i = 0; i < pathLevels; i++) {
    pathParts.push(Mock.Random.word(5, 15))
  }
  
  const path = '/' + pathParts.join('/')
  
  // 生成大量查询参数（15-25个）
  const paramCount = Mock.Random.integer(15, 25)
  const params: string[] = []
  
  for (let i = 0; i < paramCount; i++) {
    const key = Mock.Random.word(5, 12)
    const value = Mock.Random.string('lower', 10, 30)
    params.push(`${key}=${value}`)
  }
  
  return `https://${host}${path}?${params.join('&')}`
}

/**
 * 生成普通URL
 */
function generateNormalUrl(host: string): string {
  const paths = [
    '/api/users', '/api/products', '/api/orders', '/login',
    '/admin/dashboard', '/search', '/profile', '/settings',
  ]
  
  const path = Mock.Random.pick(paths)
  const id = Mock.Random.integer(1, 10000)
  
  return `https://${host}${path}?id=${id}`
}

/**
 * 生成随机任务数据
 * @param index 任务索引
 * @param mode 数据生成模式
 */
export function generateMockTask(index: number, mode: MockDataMode = MockDataMode.NORMAL): Task {
  // 增加已完成任务的比例，确保有足够的数据显示注入状态
  const statuses = [
    TaskStatus.SUCCESS,    // 60%
    TaskStatus.SUCCESS,
    TaskStatus.SUCCESS,
    TaskStatus.PENDING,    // 10%
    TaskStatus.RUNNING,    // 10%
    TaskStatus.FAILED,     // 10%
    TaskStatus.STOPPED,    // 10%
  ]
  
  const randomStatus = Mock.Random.pick(statuses)
  
  // 根据状态生成注入状态
  let injected: boolean | undefined
  
  if (randomStatus === TaskStatus.SUCCESS) {
    // 已完成的任务：60%存在注入，40%不存在注入
    injected = Mock.Random.float(0, 1) < 0.6
  } else if (randomStatus === TaskStatus.FAILED) {
    // 失败的任务：全部未知
    injected = undefined
  } else if (randomStatus === TaskStatus.RUNNING || randomStatus === TaskStatus.PENDING) {
    // 运行中或等待中：全部未知
    injected = undefined
  } else {
    // 停止的任务：50%未知，30%存在注入，20%不存在注入
    const rand = Mock.Random.float(0, 1)
    if (rand < 0.5) {
      injected = undefined
    } else if (rand < 0.8) {
      injected = true
    } else {
      injected = false
    }
  }
  
  // 根据模式生成不同的主机名和URL
  let host: string
  let scanUrl: string
  
  switch (mode) {
    case MockDataMode.LONG_HOST:
      // 超长主机名模式
      host = generateLongHost()
      scanUrl = generateNormalUrl(host)
      break
      
    case MockDataMode.LONG_URL:
      // 超长URL模式
      host = Mock.Random.domain()
      scanUrl = generateLongUrl(host)
      break
      
    case MockDataMode.MIXED:
      // 混合模式：随机选择
      const mixedMode = Mock.Random.pick([
        MockDataMode.NORMAL,
        MockDataMode.LONG_HOST,
        MockDataMode.LONG_URL,
      ])
      return generateMockTask(index, mixedMode)
      
    case MockDataMode.NORMAL:
    default:
      // 普通模式
      host = Mock.Random.domain()
      scanUrl = generateNormalUrl(host)
      break
  }
  
  // 生成随机日期（最近30天内）
  const now = new Date()
  const daysAgo = Mock.Random.integer(0, 30)
  const randomDate = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000)
  // 添加随机的小时、分钟、秒
  randomDate.setHours(Mock.Random.integer(0, 23))
  randomDate.setMinutes(Mock.Random.integer(0, 59))
  randomDate.setSeconds(Mock.Random.integer(0, 59))
  const createTime = randomDate.toISOString()
  
  return {
    engineid: 1000 + index,
    taskid: Mock.mock('@guid'),
    scanUrl,
    host,
    status: randomStatus,
    createTime,
    headers: [
      Mock.Random.string('upper', 10, 20) + ': ' + Mock.Random.sentence(3, 5),
      'Accept: application/json',
      `Authorization: Bearer ${Mock.mock('@string("lower", 32)')}`,
    ],
    body: JSON.stringify({
      test: Mock.Random.word(5, 10),
      value: Mock.Random.integer(1, 1000),
    }),
    options: {
      level: Mock.Random.integer(1, 5),
      risk: Mock.Random.integer(1, 3),
      threads: Mock.Random.integer(1, 10),
    },
    updateTime: createTime,
    injected,  // 添加注入状态
  }
}

/**
 * 生成指定数量的Mock任务数据
 * @param count 数据数量
 * @param mode 数据生成模式
 */
export function generateMockTasks(
  count: number = 200,
  mode: MockDataMode = MockDataMode.MIXED
): Task[] {
  const tasks: Task[] = []
  
  console.log(`🎲 Mock数据生成模式: ${mode}`)
  console.log(`📊 生成数量: ${count} 条`)
  
  // 混合模式：按比例分配不同类型的数据
  if (mode === MockDataMode.MIXED) {
    const normalCount = Math.floor(count * 0.5)      // 50% 普通数据
    const longHostCount = Math.floor(count * 0.25)   // 25% 超长主机名
    const longUrlCount = count - normalCount - longHostCount  // 25% 超长URL
    
    console.log(`  - 普通数据: ${normalCount} 条`)
    console.log(`  - 超长主机名: ${longHostCount} 条`)
    console.log(`  - 超长URL: ${longUrlCount} 条`)
    
    // 生成普通数据
    for (let i = 0; i < normalCount; i++) {
      tasks.push(generateMockTask(i, MockDataMode.NORMAL))
    }
    
    // 生成超长主机名数据
    for (let i = normalCount; i < normalCount + longHostCount; i++) {
      tasks.push(generateMockTask(i, MockDataMode.LONG_HOST))
    }
    
    // 生成超长URL数据
    for (let i = normalCount + longHostCount; i < count; i++) {
      tasks.push(generateMockTask(i, MockDataMode.LONG_URL))
    }
  } else {
    // 单一模式：全部使用指定模式
    for (let i = 0; i < count; i++) {
      tasks.push(generateMockTask(i, mode))
    }
  }
  
  console.log(`✅ Mock数据生成完成！`)
  
  // 统计注入状态分布
  const injectedCount = tasks.filter(t => t.injected === true).length
  const notInjectedCount = tasks.filter(t => t.injected === false).length
  const unknownCount = tasks.filter(t => t.injected === undefined).length
  
  console.log(`📈 注入状态统计：`)
  console.log(`  - 存在注入: ${injectedCount} 条 (${(injectedCount / count * 100).toFixed(1)}%)`)
  console.log(`  - 不存在注入: ${notInjectedCount} 条 (${(notInjectedCount / count * 100).toFixed(1)}%)`)
  console.log(`  - 未知状态: ${unknownCount} 条 (${(unknownCount / count * 100).toFixed(1)}%)`)
  
  // 统计任务状态分布
  const statusCounts = tasks.reduce((acc, task) => {
    acc[task.status] = (acc[task.status] || 0) + 1
    return acc
  }, {} as Record<number, number>)
  
  console.log(`📊 任务状态统计：`)
  console.log(`  - 已完成(SUCCESS): ${statusCounts[TaskStatus.SUCCESS] || 0} 条`)
  console.log(`  - 运行中(RUNNING): ${statusCounts[TaskStatus.RUNNING] || 0} 条`)
  console.log(`  - 等待中(PENDING): ${statusCounts[TaskStatus.PENDING] || 0} 条`)
  console.log(`  - 失败(FAILED): ${statusCounts[TaskStatus.FAILED] || 0} 条`)
  console.log(`  - 已停止(STOPPED): ${statusCounts[TaskStatus.STOPPED] || 0} 条`)
  
  return tasks
}

/**
 * 延迟执行（模拟网络请求）
 */
export function delay(ms: number = 500): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
