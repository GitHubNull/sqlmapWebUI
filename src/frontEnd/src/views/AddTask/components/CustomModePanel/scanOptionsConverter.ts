/**
 * ScanOptions 与 selectedParams 双向转换器
 * 用于 CustomModePanel 引导式 UI 的数据转换
 */

import { DEFAULT_SCAN_OPTIONS, type ScanOptions } from '@/types/scanPreset'
import { getParamDefinition, PARAM_DEFINITIONS } from '@/utils/paramDefinitions'

/**
 * 判断值是否为空（null/undefined/空字符串）
 */
function isEmptyValue(value: any): boolean {
  return value === null || value === undefined || value === ''
}

/**
 * 判断两个值是否相等
 */
function isEqual(a: any, b: any): boolean {
  if (a === b) return true
  if (typeof a !== typeof b) return false
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => v === b[i])
  }
  return false
}

/**
 * 获取已知参数的 key 集合
 */
const knownParamKeys = new Set(PARAM_DEFINITIONS.map(p => p.key))

/**
 * 将 ScanOptions 转换为 selectedParams
 * 过滤掉空值、false 和等于默认值的参数
 * 只保留用户明确修改过的非默认参数
 * 
 * @param options ScanOptions 对象
 * @returns selectedParams 对象（仅包含非默认值参数）
 */
export function scanOptionsToSelectedParams(options: ScanOptions): Record<string, any> {
  const result: Record<string, any> = {}
  
  if (!options) return result
  
  for (const [key, value] of Object.entries(options)) {
    // 跳过空值
    if (isEmptyValue(value)) continue
    
    // 跳过布尔值 false
    if (value === false) continue
    
    // 跳过 batch（始终隐含为 true，不需要显示）
    if (key === 'batch') continue
    
    // 获取默认值，跳过等于默认值的参数
    const defaultValue = DEFAULT_SCAN_OPTIONS[key as keyof ScanOptions]
    if (isEqual(value, defaultValue)) continue
    
    result[key] = value
  }
  
  return result
}

/**
 * 将 selectedParams 转换为 ScanOptions
 * 基于默认值，填充选中的参数
 * 
 * @param params selectedParams 对象
 * @returns 完整的 ScanOptions 对象
 */
export function selectedParamsToScanOptions(params: Record<string, any>): ScanOptions {
  // 克隆默认选项作为基础
  const result: ScanOptions = { ...DEFAULT_SCAN_OPTIONS }
  
  if (!params) return result
  
  for (const [key, value] of Object.entries(params)) {
    // 跳过空值
    if (isEmptyValue(value)) continue
    
    // 获取参数定义，进行类型转换
    const paramDef = getParamDefinition(key)
    
    if (paramDef) {
      // 根据参数类型进行转换
      switch (paramDef.type) {
        case 'boolean':
          result[key] = Boolean(value)
          break
        case 'integer':
          result[key] = parseInt(String(value), 10)
          break
        case 'float':
          result[key] = parseFloat(String(value))
          break
        default:
          result[key] = value
      }
    } else {
      // 未知参数，直接赋值
      result[key] = value
    }
  }
  
  // 确保 batch 始终为 true（业务要求）
  result.batch = true
  
  return result
}

/**
 * 合并参数到 ScanOptions
 * 保留基础 options 中的值，用 params 中的值覆盖
 * 
 * @param base 基础 ScanOptions
 * @param params 要合并的参数
 * @returns 合并后的 ScanOptions
 */
export function mergeIntoScanOptions(
  base: ScanOptions, 
  params: Record<string, any>
): ScanOptions {
  const result: ScanOptions = { ...base }
  
  for (const [key, value] of Object.entries(params)) {
    if (!isEmptyValue(value)) {
      result[key] = value
    }
  }
  
  return result
}

/**
 * 检查 ScanOptions 是否与默认值相同
 */
export function isDefaultOptions(options: ScanOptions): boolean {
  const selectedParams = scanOptionsToSelectedParams(options)
  // 只有 batch 参数时视为默认
  const keys = Object.keys(selectedParams)
  return keys.length === 0 || (keys.length === 1 && keys[0] === 'batch')
}

/**
 * 获取 ScanOptions 中非默认值的参数数量
 */
export function getNonDefaultParamCount(options: ScanOptions): number {
  const selectedParams = scanOptionsToSelectedParams(options)
  // 排除 batch 参数
  return Object.keys(selectedParams).filter(k => k !== 'batch').length
}
