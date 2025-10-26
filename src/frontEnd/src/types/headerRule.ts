/**
 * Header作用域配置
 */
export interface HeaderScope {
  protocol_pattern?: string // 协议匹配模式（http/https）
  host_pattern?: string // 主机名匹配模式
  ip_pattern?: string // IP地址匹配模式
  port_pattern?: string // 端口匹配模式
  path_pattern?: string // 路径匹配模式
  use_regex?: boolean // 是否使用正则表达式
}

/**
 * 替换策略枚举
 */
export enum ReplaceStrategy {
  REPLACE = 'REPLACE', // 完全替换
  APPEND = 'APPEND', // 追加
  PREPEND = 'PREPEND', // 前置
  CONDITIONAL = 'CONDITIONAL', // 条件性替换
  UPSERT = 'UPSERT' // 存在则替换，不存在则新增
}

/**
 * 持久化请求头规则
 */
export interface PersistentHeaderRule {
  id: number // 规则ID
  name: string // 规则名称
  header_name: string // 请求头名称
  header_value: string // 请求头值
  replace_strategy: ReplaceStrategy // 替换策略
  match_condition?: string // 匹配条件(可选)
  priority: number // 优先级(0-100)
  is_active: boolean // 是否启用
  scope?: HeaderScope | null // 作用域配置(可选，不填写时默认全局生效)
  created_at?: string // 创建时间
  updated_at?: string // 更新时间
}

/**
 * 创建持久化规则请求
 */
export interface PersistentHeaderRuleCreate {
  name: string
  header_name: string
  header_value: string
  replace_strategy?: ReplaceStrategy
  match_condition?: string
  priority?: number
  is_active?: boolean
  scope?: HeaderScope | null
}

/**
 * 更新持久化规则请求
 */
export interface PersistentHeaderRuleUpdate {
  name?: string
  header_name?: string
  header_value?: string
  replace_strategy?: ReplaceStrategy
  match_condition?: string
  priority?: number
  is_active?: boolean
  scope?: HeaderScope | null
}

/**
 * 会话请求头
 */
export interface SessionHeader {
  header_name: string
  header_value: string
  priority?: number
  ttl?: number // 生存时间(秒)
  scope?: HeaderScope | null // 作用域配置(可选)
}

/**
 * 会话请求头批量创建
 */
export interface SessionHeaderBatchCreate {
  headers: SessionHeader[]
}

/**
 * 预览请求头处理请求
 */
export interface HeaderPreviewRequest {
  headers: string[] // 原始请求头列表
  target_url?: string // 目标URL，用于作用域匹配（可选）
}

/**
 * 批量导入规则数据
 */
export interface HeaderBatchImport {
  rules: PersistentHeaderRuleCreate[]
}
