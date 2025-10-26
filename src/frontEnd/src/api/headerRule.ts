/**
 * 请求头规则相关API
 */
import { request } from './request'
import type {
  PersistentHeaderRuleCreate,
  PersistentHeaderRuleUpdate,
  SessionHeaderBatchCreate,
  HeaderPreviewRequest,
  PersistentHeaderRule,
} from '@/types/headerRule'
import { ReplaceStrategy } from '@/types/headerRule'
import {
  generateMockHeaderRules,
  generateMockSessionHeaders,
  generateMockHeaderRule,
  delay,
} from '@/utils/mockData'

// 是否使用Mock数据
const USE_MOCK_DATA = true

// Mock数据存储
let mockHeaderRules: PersistentHeaderRule[] = []
let mockSessionHeaders: any[] = []
let mockRuleIdCounter = 1000

// 初始化Mock数据
if (USE_MOCK_DATA) {
  mockHeaderRules = generateMockHeaderRules(20)
  mockSessionHeaders = generateMockSessionHeaders(10)
  mockRuleIdCounter = Math.max(...mockHeaderRules.map(r => r.id)) + 1
}

// ==================== 持久化规则API ====================

/**
 * 获取持久化规则列表
 */
export async function getPersistentRules(activeOnly: boolean = true) {
  if (USE_MOCK_DATA) {
    await delay(300)
    const filteredRules = activeOnly
      ? mockHeaderRules.filter(r => r.is_active)
      : mockHeaderRules
    return {
      success: true,
      data: {
        rules: filteredRules,
        total: filteredRules.length,
      },
      message: 'Mock数据加载成功',
    }
  }
  return request.get('/commonApi/header/persistent-header-rules', {
    params: { active_only: activeOnly },
  })
}

/**
 * 根据ID获取持久化规则
 */
export async function getPersistentRuleById(ruleId: number) {
  if (USE_MOCK_DATA) {
    await delay(200)
    const rule = mockHeaderRules.find(r => r.id === ruleId)
    if (rule) {
      return {
        success: true,
        data: rule,
        message: '获取成功',
      }
    }
    return {
      success: false,
      data: null,
      message: '规则不存在',
    }
  }
  return request.get(`/commonApi/header/persistent-header-rules/${ruleId}`)
}

/**
 * 创建持久化规则
 */
export async function createPersistentRule(rule: PersistentHeaderRuleCreate) {
  if (USE_MOCK_DATA) {
    await delay(400)
    const newRule: PersistentHeaderRule = {
      id: mockRuleIdCounter++,
      name: rule.name,
      header_name: rule.header_name,
      header_value: rule.header_value,
      replace_strategy: rule.replace_strategy || ReplaceStrategy.REPLACE,
      priority: rule.priority ?? 50,
      is_active: rule.is_active ?? true,
      scope: rule.scope ?? null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }
    mockHeaderRules.unshift(newRule)
    return {
      success: true,
      data: newRule,
      message: '创建成功',
    }
  }
  return request.post('/commonApi/header/persistent-header-rules', rule)
}

/**
 * 更新持久化规则
 */
export async function updatePersistentRule(ruleId: number, rule: PersistentHeaderRuleUpdate) {
  if (USE_MOCK_DATA) {
    await delay(400)
    const index = mockHeaderRules.findIndex(r => r.id === ruleId)
    if (index !== -1) {
      const existingRule = mockHeaderRules[index]!
      const updatedRule: PersistentHeaderRule = {
        id: existingRule.id,
        name: rule.name ?? existingRule.name,
        header_name: rule.header_name ?? existingRule.header_name,
        header_value: rule.header_value ?? existingRule.header_value,
        replace_strategy: rule.replace_strategy ?? existingRule.replace_strategy,
        priority: rule.priority ?? existingRule.priority,
        is_active: rule.is_active ?? existingRule.is_active,
        scope: rule.scope !== undefined ? rule.scope : existingRule.scope,
        created_at: existingRule.created_at,
        updated_at: new Date().toISOString(),
      }
      mockHeaderRules[index] = updatedRule
      return {
        success: true,
        data: updatedRule,
        message: '更新成功',
      }
    }
    return {
      success: false,
      data: null,
      message: '规则不存在',
    }
  }
  return request.put(`/commonApi/header/persistent-header-rules/${ruleId}`, rule)
}

/**
 * 删除持久化规则
 */
export async function deletePersistentRule(ruleId: number) {
  if (USE_MOCK_DATA) {
    await delay(300)
    const index = mockHeaderRules.findIndex(r => r.id === ruleId)
    if (index !== -1) {
      mockHeaderRules.splice(index, 1)
      return {
        success: true,
        data: null,
        message: '删除成功',
      }
    }
    return {
      success: false,
      data: null,
      message: '规则不存在',
    }
  }
  return request.delete(`/commonApi/header/persistent-header-rules/${ruleId}`)
}

// ==================== 会话性请求头API ====================

/**
 * 设置会话性请求头
 */
export async function setSessionHeaders(headers: SessionHeaderBatchCreate) {
  if (USE_MOCK_DATA) {
    await delay(400)
    // 添加新的session headers
    const now = new Date()
    const newHeaders = headers.headers.map(h => ({
      header_name: h.header_name,
      header_value: h.header_value,
      priority: h.priority ?? 50,
      ttl: h.ttl ?? 3600,
      scope: h.scope ?? null,
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + (h.ttl ?? 3600) * 1000).toISOString(),
    }))
    mockSessionHeaders.unshift(...newHeaders)
    return {
      success: true,
      data: { count: newHeaders.length },
      message: `成功添加 ${newHeaders.length} 个Session Header`,
    }
  }
  return request.post('/commonApi/header/session-headers', headers)
}

/**
 * 获取会话性请求头
 */
export async function getSessionHeaders() {
  if (USE_MOCK_DATA) {
    await delay(300)
    // 过滤掉已过期的headers（可选）
    // const now = new Date()
    // const validHeaders = mockSessionHeaders.filter(h => new Date(h.expires_at) > now)
    return {
      success: true,
      data: {
        headers: mockSessionHeaders,
        total: mockSessionHeaders.length,
      },
      message: 'Mock数据加载成功',
    }
  }
  return request.get('/commonApi/header/session-headers')
}

/**
 * 清除会话性请求头
 */
export async function clearSessionHeaders() {
  if (USE_MOCK_DATA) {
    await delay(300)
    const count = mockSessionHeaders.length
    mockSessionHeaders = []
    return {
      success: true,
      data: { count },
      message: `成功清除 ${count} 个Session Header`,
    }
  }
  return request.delete('/commonApi/header/session-headers')
}

// ==================== 预览功能API ====================

/**
 * 预览请求头处理结果
 */
export async function previewHeaderProcessing(data: HeaderPreviewRequest) {
  if (USE_MOCK_DATA) {
    await delay(500)
    // 简单模拟：合并原始请求头和mock规则
    const processedHeaders = [...data.headers]
    const activeRules = mockHeaderRules.filter(r => r.is_active)
    activeRules.forEach(rule => {
      processedHeaders.push(`${rule.header_name}: ${rule.header_value}`)
    })
    return {
      success: true,
      data: {
        original_headers: data.headers,
        processed_headers: processedHeaders,
        applied_rules: activeRules.map(r => r.id),
      },
      message: '预览成功',
    }
  }
  return request.post('/commonApi/header/header-processing/preview', data)
}

// ==================== 统计信息API ====================

/**
 * 获取请求头管理统计信息
 */
export async function getHeaderManagementStats() {
  if (USE_MOCK_DATA) {
    await delay(200)
    const activeRules = mockHeaderRules.filter(r => r.is_active).length
    const inactiveRules = mockHeaderRules.length - activeRules
    const now = new Date()
    const validSessionHeaders = mockSessionHeaders.filter(h => new Date(h.expires_at) > now).length
    const expiredSessionHeaders = mockSessionHeaders.length - validSessionHeaders

    return {
      success: true,
      data: {
        persistent_rules: {
          total: mockHeaderRules.length,
          active: activeRules,
          inactive: inactiveRules,
        },
        session_headers: {
          total: mockSessionHeaders.length,
          valid: validSessionHeaders,
          expired: expiredSessionHeaders,
        },
      },
      message: '统计信息获取成功',
    }
  }
  return request.get('/commonApi/header/header-management/stats')
}
