/**
 * SQLMap 参数定义模块入口文件
 * 统一导出所有参数定义和工具函数
 */

// 导出类型定义
export * from './types'

// 导出分类定义
export * from './categories'

// 导出安全相关
export * from './security'

// 导入各分类参数
import { TARGET_PARAMS } from './params/target'
import { REQUEST_PARAMS } from './params/request'
import { OPTIMIZATION_PARAMS } from './params/optimization'
import { INJECTION_PARAMS } from './params/injection'
import { DETECTION_PARAMS } from './params/detection'
import { TECHNIQUES_PARAMS } from './params/techniques'
import { FINGERPRINT_PARAMS } from './params/fingerprint'
import { ENUMERATION_PARAMS } from './params/enumeration'
import { BRUTE_FORCE_PARAMS } from './params/bruteForce'
import { UDF_PARAMS } from './params/udf'
import { FILE_SYSTEM_PARAMS } from './params/fileSystem'
import { OS_TAKEOVER_PARAMS } from './params/osTakeover'
import { WINDOWS_REGISTRY_PARAMS } from './params/windowsRegistry'
import { GENERAL_PARAMS } from './params/general'
import { MISCELLANEOUS_PARAMS } from './params/miscellaneous'

import type { ParamDefinition, ParamCategoryKey } from './types'

// 汇总所有参数定义
export const PARAM_DEFINITIONS: ParamDefinition[] = [
  ...TARGET_PARAMS,
  ...REQUEST_PARAMS,
  ...OPTIMIZATION_PARAMS,
  ...INJECTION_PARAMS,
  ...DETECTION_PARAMS,
  ...TECHNIQUES_PARAMS,
  ...FINGERPRINT_PARAMS,
  ...ENUMERATION_PARAMS,
  ...BRUTE_FORCE_PARAMS,
  ...UDF_PARAMS,
  ...FILE_SYSTEM_PARAMS,
  ...OS_TAKEOVER_PARAMS,
  ...WINDOWS_REGISTRY_PARAMS,
  ...GENERAL_PARAMS,
  ...MISCELLANEOUS_PARAMS
]

// 按分类分组的参数
export const PARAMS_BY_CATEGORY: Record<ParamCategoryKey, ParamDefinition[]> = {
  target: TARGET_PARAMS,
  request: REQUEST_PARAMS,
  optimization: OPTIMIZATION_PARAMS,
  injection: INJECTION_PARAMS,
  detection: DETECTION_PARAMS,
  techniques: TECHNIQUES_PARAMS,
  fingerprint: FINGERPRINT_PARAMS,
  enumeration: ENUMERATION_PARAMS,
  bruteForce: BRUTE_FORCE_PARAMS,
  udf: UDF_PARAMS,
  fileSystem: FILE_SYSTEM_PARAMS,
  osTakeover: OS_TAKEOVER_PARAMS,
  windowsRegistry: WINDOWS_REGISTRY_PARAMS,
  general: GENERAL_PARAMS,
  miscellaneous: MISCELLANEOUS_PARAMS
}

// 缓存: key -> ParamDefinition
let _paramByKeyCache: Map<string, ParamDefinition> | null = null
// 缓存: cliName -> ParamDefinition
let _paramByCliNameCache: Map<string, ParamDefinition> | null = null
// 缓存: key -> cliName
let _keyToCliNameCache: Map<string, string> | null = null

/**
 * 根据 key 获取参数定义
 */
export function getParamDefinition(key: string): ParamDefinition | undefined {
  if (!_paramByKeyCache) {
    _paramByKeyCache = new Map()
    for (const param of PARAM_DEFINITIONS) {
      _paramByKeyCache.set(param.key, param)
    }
  }
  return _paramByKeyCache.get(key)
}

/**
 * 根据 CLI 名称获取参数定义
 */
export function getParamByCliName(cliName: string): ParamDefinition | undefined {
  if (!_paramByCliNameCache) {
    _paramByCliNameCache = new Map()
    for (const param of PARAM_DEFINITIONS) {
      _paramByCliNameCache.set(param.cliName, param)
    }
  }
  return _paramByCliNameCache.get(cliName)
}

/**
 * 获取 key -> cliName 映射表
 */
export function getParamKeyToCliNameMap(): Map<string, string> {
  if (!_keyToCliNameCache) {
    _keyToCliNameCache = new Map()
    for (const param of PARAM_DEFINITIONS) {
      _keyToCliNameCache.set(param.key, param.cliName)
    }
  }
  return _keyToCliNameCache
}

/**
 * 驼峰转连字符（后备方案）
 */
export function camelToKebab(str: string): string {
  return str.replace(/([A-Z])/g, '-$1').toLowerCase().replace(/^-/, '')
}

/**
 * 格式化命令行参数值
 */
function formatCliValue(value: any): string {
  if (Array.isArray(value)) {
    return value.join(',')
  }
  const str = String(value)
  if (/[\s,;|&"']/.test(str)) {
    return `"${str.replace(/"/g, '\\"')}"`
  }
  return str
}

/**
 * 转换单个参数为命令行格式
 */
export function convertOptionToCliArg(key: string, value: any): string | null {
  if (value === false || value === null || value === undefined || value === '') {
    return null
  }

  const param = getParamDefinition(key)
  const cliName = param?.cliName || '--' + camelToKebab(key)

  if (value === true) {
    return cliName
  }

  const formatted = formatCliValue(value)
  // 短选项（如 -v, -D 等）用空格分隔值
  if (/^-[a-zA-Z]$/.test(cliName)) {
    return `${cliName} ${formatted}`
  }
  return `${cliName}=${formatted}`
}

/**
 * 获取指定分类的参数列表
 */
export function getParamsByCategory(category: ParamCategoryKey): ParamDefinition[] {
  return PARAMS_BY_CATEGORY[category] || []
}

/**
 * 获取非禁用的参数列表
 */
export function getEnabledParams(): ParamDefinition[] {
  return PARAM_DEFINITIONS.filter(p => !p.disabled)
}

/**
 * 获取高级参数列表
 */
export function getAdvancedParams(): ParamDefinition[] {
  return PARAM_DEFINITIONS.filter(p => p.advanced)
}

/**
 * 获取基础参数列表（非高级）
 */
export function getBasicParams(): ParamDefinition[] {
  return PARAM_DEFINITIONS.filter(p => !p.advanced && !p.disabled)
}

/**
 * 统计各分类参数数量
 */
export function getParamCountByCategory(): Record<ParamCategoryKey, number> {
  const counts = {} as Record<ParamCategoryKey, number>
  for (const [key, params] of Object.entries(PARAMS_BY_CATEGORY)) {
    counts[key as ParamCategoryKey] = params.length
  }
  return counts
}
