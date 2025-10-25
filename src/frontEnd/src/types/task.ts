// 任务状态枚举
export enum TaskStatus {
  PENDING = 0,
  RUNNING = 1,
  SUCCESS = 2,
  FAILED = 3,
  STOPPED = 4,
}

// 任务配置选项
export interface TaskOptions {
  level?: number // 检测级别(1-5)
  risk?: number // 风险级别(1-3)
  technique?: string // 注入技术
  dbms?: string // 指定数据库类型
  threads?: number // 线程数
  [key: string]: any // 其他选项
}

// 任务接口
export interface Task {
  engineid: number // 任务引擎ID
  taskid: string // 任务唯一标识符
  scanUrl: string // 扫描目标URL
  host: string // 目标主机
  status: TaskStatus // 任务状态
  createTime: string // 创建时间(ISO格式)
  headers?: string[] // 请求头数组
  body?: string // 请求体
  options?: TaskOptions // 任务配置选项
  updateTime?: string // 更新时间
}

// 任务筛选条件
export interface TaskFilters {
  status?: TaskStatus
  host?: string
  startDate?: string
  endDate?: string
}
