/**
 * 请求头规则相关API
 */
import { request } from './request'
import type {
  PersistentHeaderRule,
  PersistentHeaderRuleCreate,
  PersistentHeaderRuleUpdate,
  SessionHeader,
  SessionHeaderBatchCreate,
  HeaderPreviewRequest,
} from '@/types/headerRule'

// ==================== 持久化规则API ====================

/**
 * 获取持久化规则列表
 */
export function getPersistentRules(activeOnly: boolean = true) {
  return request.get('/commonApi/header/persistent-header-rules', {
    params: { active_only: activeOnly },
  })
}

/**
 * 根据ID获取持久化规则
 */
export function getPersistentRuleById(ruleId: number) {
  return request.get(`/commonApi/header/persistent-header-rules/${ruleId}`)
}

/**
 * 创建持久化规则
 */
export function createPersistentRule(rule: PersistentHeaderRuleCreate) {
  return request.post('/commonApi/header/persistent-header-rules', rule)
}

/**
 * 更新持久化规则
 */
export function updatePersistentRule(ruleId: number, rule: PersistentHeaderRuleUpdate) {
  return request.put(`/commonApi/header/persistent-header-rules/${ruleId}`, rule)
}

/**
 * 删除持久化规则
 */
export function deletePersistentRule(ruleId: number) {
  return request.delete(`/commonApi/header/persistent-header-rules/${ruleId}`)
}

// ==================== 会话性请求头API ====================

/**
 * 设置会话性请求头
 */
export function setSessionHeaders(headers: SessionHeaderBatchCreate) {
  return request.post('/commonApi/header/session-headers', headers)
}

/**
 * 获取会话性请求头
 */
export function getSessionHeaders() {
  return request.get('/commonApi/header/session-headers')
}

/**
 * 清除会话性请求头
 */
export function clearSessionHeaders() {
  return request.delete('/commonApi/header/session-headers')
}

// ==================== 预览功能API ====================

/**
 * 预览请求头处理结果
 */
export function previewHeaderProcessing(data: HeaderPreviewRequest) {
  return request.post('/commonApi/header/header-processing/preview', data)
}

// ==================== 统计信息API ====================

/**
 * 获取请求头管理统计信息
 */
export function getHeaderManagementStats() {
  return request.get('/commonApi/header/header-management/stats')
}
