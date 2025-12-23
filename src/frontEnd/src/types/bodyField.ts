/**
 * HTTP Body 会话字段类型定义
 */
import type { HeaderScope } from './headerRule'

/**
 * 匹配策略枚举
 */
export enum MatchStrategy {
  KEYWORD = 'KEYWORD',      // 关键字匹配
  REGEX = 'REGEX',          // 正则表达式匹配
  JSONPATH = 'JSONPATH',    // JSONPath表达式匹配
  XPATH = 'XPATH'           // XPath表达式匹配
}

/**
 * 替换策略枚举 (复用 headerRule.ts 中的定义)
 */
export enum BodyReplaceStrategy {
  REPLACE = 'REPLACE',           // 完全替换
  APPEND = 'APPEND',             // 追加
  PREPEND = 'PREPEND',           // 前置
  CONDITIONAL = 'CONDITIONAL',   // 条件性替换
  UPSERT = 'UPSERT'              // 存在则替换，不存在则新增
}

/**
 * 会话Body字段
 */
export interface SessionBodyField {
  id?: number                           // 唯一标识
  field_name: string                    // 字段名称(如"token", "sessionId")
  field_value: string                   // 字段值(新的会话值)
  match_strategy: MatchStrategy         // 匹配策略
  match_pattern?: string                // 匹配模式(用于定位字段)
  replace_strategy: BodyReplaceStrategy // 替换策略
  content_types?: string[]              // 适用的Content-Type列表
  priority?: number                     // 优先级(0-100)
  is_active?: boolean                   // 是否启用
  ttl?: number                          // 生存时间(秒)
  scope?: HeaderScope | null            // 作用域配置
  expires_at?: string                   // 过期时间
  created_at?: string                   // 创建时间
  updated_at?: string                   // 更新时间
  source_ip?: string                    // 来源IP
}

/**
 * 创建会话Body字段请求
 */
export interface SessionBodyFieldCreate {
  field_name: string                    // 字段名称
  field_value: string                   // 字段值
  match_strategy?: MatchStrategy        // 匹配策略，默认KEYWORD
  match_pattern?: string                // 匹配模式
  replace_strategy?: BodyReplaceStrategy // 替换策略，默认REPLACE
  content_types?: string[]              // 适用Content-Type
  priority?: number                     // 优先级
  is_active?: boolean                   // 是否启用
  ttl?: number                          // 生存时间
  scope?: HeaderScope | null            // 作用域配置
}

/**
 * 更新会话Body字段请求
 */
export interface SessionBodyFieldUpdate {
  field_value?: string
  match_strategy?: MatchStrategy
  match_pattern?: string
  replace_strategy?: BodyReplaceStrategy
  content_types?: string[]
  priority?: number
  is_active?: boolean
  ttl?: number
  scope?: HeaderScope | null
}

/**
 * 批量创建会话Body字段请求
 */
export interface SessionBodyFieldBatchCreate {
  fields: SessionBodyFieldCreate[]
}

/**
 * Body处理预览请求
 */
export interface BodyPreviewRequest {
  body: string                          // 原始Body内容
  content_type: string                  // Content-Type
  target_url?: string                   // 目标URL，用于作用域匹配
}

/**
 * Body处理预览响应
 */
export interface BodyPreviewResponse {
  original_body: string                 // 原始Body
  processed_body: string                // 处理后Body
  applied_rules: string[]               // 应用的规则列表
  changes_count: number                 // 变更数量
}

/**
 * 会话Body字段列表响应
 */
export interface SessionBodyFieldListResponse {
  client_ip: string
  fields: SessionBodyField[]
  total_count: number
}

/**
 * 匹配策略选项(用于下拉菜单)
 */
export const matchStrategyOptions = [
  { label: '关键字匹配', value: MatchStrategy.KEYWORD, description: '简单字段名匹配，如 token' },
  { label: '正则表达式', value: MatchStrategy.REGEX, description: '复杂模式匹配' },
  { label: 'JSONPath', value: MatchStrategy.JSONPATH, description: 'JSON格式Body，如 $.auth.token' },
  { label: 'XPath', value: MatchStrategy.XPATH, description: 'XML格式Body，如 //auth/token/text()' }
]

/**
 * 替换策略选项(用于下拉菜单)
 */
export const bodyReplaceStrategyOptions = [
  { label: '替换', value: BodyReplaceStrategy.REPLACE, description: '完全替换匹配到的值' },
  { label: '追加', value: BodyReplaceStrategy.APPEND, description: '在现有值后追加' },
  { label: '前置', value: BodyReplaceStrategy.PREPEND, description: '在现有值前添加' },
  { label: '条件替换', value: BodyReplaceStrategy.CONDITIONAL, description: '仅当值存在时替换' },
  { label: '插入或更新', value: BodyReplaceStrategy.UPSERT, description: '存在则替换，不存在则新增' }
]

/**
 * Content-Type选项(用于多选)
 */
export const contentTypeOptions = [
  { label: 'JSON', value: 'application/json' },
  { label: 'XML', value: 'application/xml' },
  { label: 'Text XML', value: 'text/xml' },
  { label: 'URL编码表单', value: 'application/x-www-form-urlencoded' }
]
