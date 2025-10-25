/**
 * 请求头规则相关API
 */
import { request } from './request'
import type { PersistentHeaderRule, HeaderBatchImport } from '@/types/headerRule'

/**
 * 获取持久化规则列表
 */
export function getPersistentRules(): Promise<PersistentHeaderRule[]> {
  return request.get('/chrome/admin/rule/list')
}

/**
 * 添加持久化规则
 */
export function addPersistentRule(rule: Omit<PersistentHeaderRule, 'id'>): Promise<PersistentHeaderRule> {
  return request.post('/chrome/admin/rule/add', rule)
}

/**
 * 更新持久化规则
 */
export function updatePersistentRule(rule: PersistentHeaderRule): Promise<void> {
  return request.put('/chrome/admin/rule/update', rule)
}

/**
 * 删除持久化规则
 */
export function deletePersistentRule(ruleId: number): Promise<void> {
  return request.delete('/chrome/admin/rule/delete', {
    params: { ruleId },
  })
}

/**
 * 批量导入规则
 */
export function batchImportRules(data: HeaderBatchImport): Promise<void> {
  return request.post('/chrome/admin/rule/batch/import', data)
}
