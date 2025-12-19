// 任务状态枚举
export enum TaskStatus {
  PENDING = 0,
  RUNNING = 1,
  SUCCESS = 2,
  FAILED = 3,
  STOPPED = 4,
  TERMINATED = 5,
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
  createTime: string // 创建时间 (New状态开始时)
  startTime?: string // 开始执行时间 (Running状态开始时)
  headers?: string[] // 请求头数组
  body?: string // 请求体
  options?: TaskOptions // 任务配置选项
  updateTime?: string // 更新时间
  remote_addr?: string // 来源IP
  injected?: boolean // 是否可注入
  errors?: number // 错误数量
  logs?: number // 日志数量
}

// 任务筛选条件
export interface TaskFilters {
  urlKeyword?: string // URL关键字
  messageKeyword?: string // 报文关键字
  status?: TaskStatus // 状态过滤
  startDate?: string // 创建时间-开始
  endDate?: string // 创建时间-结束
  execStartDate?: string // 执行时间-开始
  execEndDate?: string // 执行时间-结束
  injectableStatus?: 'injectable' | 'not_injectable' | 'unknown' // 注入状态过滤
}

// 任务统计数据
export interface TaskStats {
  total: number // 总任务数
  running: number // 运行中任务数
  pending: number // 等待中任务数
  success: number // 已完成任务数
  failed: number // 失败任务数
  stopped: number // 已停止任务数
  terminated: number // 已终止任务数
  injectable: number // 可注入任务数
  nonInjectable: number // 不可注入任务数
  unknown: number // 未知注入状态任务数
}

// 载荷详情模型
export interface PayloadDetail {
  index: number
  status: string
  contentType: string
  value: string
}

// 日志条目模型
export interface LogEntry {
  datetime: string
  level: 'INFO' | 'DEBUG' | 'WARN' | 'ERROR'
  message: string
}

// 错误条目模型
export interface ErrorEntry {
  datetime: string
  type: string
  message: string
  stackTrace?: string
}

// HTTP请求信息
export interface HttpRequestInfo {
  method: string
  url: string
  headers: string[]
  body: string
}

// 扫描结果
export interface ScanResult {
  injectable: boolean
  parameters: string[]
  injectionType: string[]
  dbms: string
  version: string
  payloads: PayloadDetail[]
}

// 任务详情数据模型
export interface TaskDetail {
  basic: Task // 基础信息
  scanOptions: TaskOptions // 扫描配置
  httpRequest: HttpRequestInfo // HTTP请求
  scanResult: ScanResult // 扫描结果
  logs: LogEntry[] // 日志
  errors: ErrorEntry[] // 错误
}

// 排序配置
export interface SortConfig {
  field: string
  order: 'asc' | 'desc' | null
}
