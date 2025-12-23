/**
 * HTTP Body 会话字段相关 API
 */
import { request } from './request'
import type {
  SessionBodyFieldCreate,
  SessionBodyFieldUpdate,
  SessionBodyFieldBatchCreate,
  BodyPreviewRequest,
  BodyPreviewResponse,
  SessionBodyFieldListResponse
} from '@/types/bodyField'
import { MatchStrategy, BodyReplaceStrategy } from '@/types/bodyField'

// ==================== 会话Body字段 API ====================

/**
 * 获取会话Body字段列表
 */
export async function getSessionBodyFields(activeOnly: boolean = true) {
  const data = await request.get('/commonApi/body-field/session-body-fields', {
    params: { active_only: activeOnly }
  }) as SessionBodyFieldListResponse
  return {
    success: true,
    data: data,
    message: '加载成功'
  }
}

/**
 * 批量设置会话Body字段
 */
export async function setSessionBodyFields(batchCreate: SessionBodyFieldBatchCreate) {
  const data = await request.post('/commonApi/body-field/session-body-fields', batchCreate)
  return {
    success: true,
    data: data,
    message: '设置成功'
  }
}

/**
 * 更新单个会话Body字段
 */
export async function updateSessionBodyField(fieldName: string, fieldUpdate: SessionBodyFieldUpdate) {
  const data = await request.put(
    `/commonApi/body-field/session-body-fields/${encodeURIComponent(fieldName)}`,
    fieldUpdate
  )
  return {
    success: true,
    data: data,
    message: '更新成功'
  }
}

/**
 * 删除单个会话Body字段
 */
export async function deleteSessionBodyField(fieldName: string) {
  await request.delete(`/commonApi/body-field/session-body-fields/${encodeURIComponent(fieldName)}`)
  return {
    success: true,
    data: null,
    message: '删除成功'
  }
}

/**
 * 清除所有会话Body字段
 */
export async function clearSessionBodyFields() {
  const data = await request.delete('/commonApi/body-field/session-body-fields')
  return {
    success: true,
    data: data,
    message: '清除成功'
  }
}

/**
 * 预览Body处理结果
 */
export async function previewBodyProcessing(previewData: BodyPreviewRequest) {
  const data = await request.post('/commonApi/body-field/body-processing/preview', previewData) as BodyPreviewResponse
  return {
    success: true,
    data: data,
    message: '预览成功'
  }
}

// ==================== 工具函数 ====================

/**
 * 创建默认的会话Body字段
 */
export function createDefaultSessionBodyField(): SessionBodyFieldCreate {
  return {
    field_name: '',
    field_value: '',
    match_strategy: MatchStrategy.KEYWORD,
    match_pattern: '',
    replace_strategy: BodyReplaceStrategy.REPLACE,
    content_types: ['application/json'],
    priority: 50,
    is_active: true,
    ttl: 3600,
    scope: null
  }
}

/**
 * 验证会话Body字段
 */
export function validateSessionBodyField(field: SessionBodyFieldCreate): string | null {
  if (!field.field_name || field.field_name.trim() === '') {
    return '字段名称不能为空'
  }
  if (field.field_name.length > 200) {
    return '字段名称不能超过200字符'
  }
  if (!field.field_value || field.field_value.trim() === '') {
    return '字段值不能为空'
  }
  if (field.field_value.length > 5000) {
    return '字段值不能超过5000字符'
  }
  if (field.priority !== undefined && (field.priority < 0 || field.priority > 100)) {
    return '优先级必须在0-100之间'
  }
  if (field.ttl !== undefined && (field.ttl < 60 || field.ttl > 86400)) {
    return '生存时间必须在60-86400秒之间'
  }
  // 验证匹配模式
  if (field.match_strategy === MatchStrategy.JSONPATH && field.match_pattern) {
    if (!field.match_pattern.startsWith('$')) {
      return 'JSONPath表达式应以$开头'
    }
  }
  if (field.match_strategy === MatchStrategy.XPATH && field.match_pattern) {
    if (!field.match_pattern.startsWith('/') && !field.match_pattern.startsWith('.')) {
      return 'XPath表达式格式不正确'
    }
  }
  return null
}

/**
 * 获取匹配策略的显示文本
 */
export function getMatchStrategyLabel(strategy: MatchStrategy): string {
  const labels: Record<MatchStrategy, string> = {
    [MatchStrategy.KEYWORD]: '关键字',
    [MatchStrategy.REGEX]: '正则表达式',
    [MatchStrategy.JSONPATH]: 'JSONPath',
    [MatchStrategy.XPATH]: 'XPath'
  }
  return labels[strategy] || strategy
}

/**
 * 获取替换策略的显示文本
 */
export function getReplaceStrategyLabel(strategy: BodyReplaceStrategy): string {
  const labels: Record<BodyReplaceStrategy, string> = {
    [BodyReplaceStrategy.REPLACE]: '替换',
    [BodyReplaceStrategy.APPEND]: '追加',
    [BodyReplaceStrategy.PREPEND]: '前置',
    [BodyReplaceStrategy.CONDITIONAL]: '条件替换',
    [BodyReplaceStrategy.UPSERT]: '插入/更新'
  }
  return labels[strategy] || strategy
}

/**
 * 截断文本显示
 */
export function truncateText(text: string, maxLength: number = 30): string {
  if (!text) return ''
  return text.length > maxLength ? text.substring(0, maxLength) + '...' : text
}

/**
 * 格式化过期时间
 */
export function formatExpiresAt(expiresAt: string | undefined): string {
  if (!expiresAt) return '-'
  try {
    const date = new Date(expiresAt)
    const now = new Date()
    const diffMs = date.getTime() - now.getTime()
    
    if (diffMs < 0) {
      return '已过期'
    }
    
    const diffMinutes = Math.floor(diffMs / 60000)
    if (diffMinutes < 60) {
      return `${diffMinutes}分钟后过期`
    }
    
    const diffHours = Math.floor(diffMinutes / 60)
    if (diffHours < 24) {
      return `${diffHours}小时后过期`
    }
    
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    })
  } catch {
    return expiresAt
  }
}
