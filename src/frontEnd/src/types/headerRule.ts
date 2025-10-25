// 持久化请求头规则
export interface PersistentHeaderRule {
  id: number // 规则ID
  headerName: string // 请求头名称
  matchCondition: string // 匹配条件(正则表达式)
  replacementValue: string // 替换值
  priority: number // 优先级
  enabled: boolean // 是否启用
  createTime?: string // 创建时间
  updateTime?: string // 更新时间
}

// 会话头规则
export interface SessionHeaderRule {
  sessionId: string // 会话ID
  headers: Record<string, string> // 请求头键值对
  expiresAt?: number // 过期时间戳
}

// 批量导入规则数据
export interface HeaderBatchImport {
  rules: Omit<PersistentHeaderRule, 'id'>[] // 批量规则数据
}
