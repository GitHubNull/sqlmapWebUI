/**
 * 扫描参数解析器
 * 使用 mri 实现 parameter_string ↔ ScanOptions 双向转换
 * 与 BurpSuite 端的 ScanConfigParser.java 逻辑保持一致
 * 
 * mri 是一个轻量级、浏览器兼容的命令行解析库
 * 比 minimist 快 5 倍，比 yargs-parser 快 40 倍
 */
import mri from 'mri'
import type { ScanOptions } from '@/types/scanPreset'
import { DEFAULT_SCAN_OPTIONS } from '@/types/scanPreset'

// ==================== 参数元数据定义 ====================

interface ParamMeta {
  name: string           // 规范名称 (camelCase)
  longOpt: string        // 长选项名 (--xxx)
  shortOpt?: string      // 短选项名 (-x)
  type: 'boolean' | 'number' | 'string'
  defaultValue: any
  minValue?: number
  maxValue?: number
  validValues?: string[]
  description: string
}

/**
 * 参数元数据映射表
 * 与 BurpSuite ScanConfigParser.java 保持一致
 */
const PARAM_META: ParamMeta[] = [
  // Detection 检测选项
  { name: 'level', longOpt: 'level', type: 'number', defaultValue: 1, minValue: 1, maxValue: 5, description: '检测级别 (1-5)' },
  { name: 'risk', longOpt: 'risk', type: 'number', defaultValue: 1, minValue: 1, maxValue: 3, description: '风险级别 (1-3)' },
  { name: 'string', longOpt: 'string', type: 'string', defaultValue: '', description: '页面匹配字符串' },
  { name: 'notString', longOpt: 'not-string', type: 'string', defaultValue: '', description: '页面不匹配字符串' },
  { name: 'regexp', longOpt: 'regexp', type: 'string', defaultValue: '', description: '正则匹配' },
  { name: 'code', longOpt: 'code', type: 'number', defaultValue: 0, minValue: 100, maxValue: 599, description: 'HTTP响应码' },
  { name: 'smart', longOpt: 'smart', type: 'boolean', defaultValue: false, description: '智能检测' },
  { name: 'textOnly', longOpt: 'text-only', type: 'boolean', defaultValue: false, description: '仅文本比较' },
  { name: 'titles', longOpt: 'titles', type: 'boolean', defaultValue: false, description: '基于标题比较' },
  
  // Injection 注入选项
  { name: 'testParameter', longOpt: 'test-parameter', shortOpt: 'p', type: 'string', defaultValue: '', description: '指定测试参数' },
  { name: 'skip', longOpt: 'skip', type: 'string', defaultValue: '', description: '跳过参数' },
  { name: 'skipStatic', longOpt: 'skip-static', type: 'boolean', defaultValue: false, description: '跳过静态参数' },
  { name: 'paramExclude', longOpt: 'param-exclude', type: 'string', defaultValue: '', description: '排除参数' },
  { name: 'dbms', longOpt: 'dbms', type: 'string', defaultValue: '', description: '数据库类型' },
  { name: 'os', longOpt: 'os', type: 'string', defaultValue: '', validValues: ['linux', 'windows'], description: '操作系统' },
  { name: 'prefix', longOpt: 'prefix', type: 'string', defaultValue: '', description: '注入前缀' },
  { name: 'suffix', longOpt: 'suffix', type: 'string', defaultValue: '', description: '注入后缀' },
  { name: 'tamper', longOpt: 'tamper', type: 'string', defaultValue: '', description: '篡改脚本' },
  
  // Techniques 技术选项
  { name: 'technique', longOpt: 'technique', type: 'string', defaultValue: 'BEUSTQ', description: '注入技术 (BEUSTQ)' },
  { name: 'timeSec', longOpt: 'time-sec', type: 'number', defaultValue: 5, minValue: 1, maxValue: 60, description: '时间盲注延迟(秒)' },
  
  // Request 请求选项
  { name: 'timeout', longOpt: 'timeout', type: 'number', defaultValue: 30, minValue: 1, maxValue: 300, description: '超时(秒)' },
  { name: 'retries', longOpt: 'retries', type: 'number', defaultValue: 3, minValue: 0, maxValue: 10, description: '重试次数' },
  { name: 'delay', longOpt: 'delay', type: 'number', defaultValue: 0, minValue: 0, maxValue: 60, description: '请求延迟(秒)' },
  { name: 'randomAgent', longOpt: 'random-agent', type: 'boolean', defaultValue: false, description: '随机UA' },
  { name: 'proxy', longOpt: 'proxy', type: 'string', defaultValue: '', description: '代理地址' },
  { name: 'tor', longOpt: 'tor', type: 'boolean', defaultValue: false, description: '使用Tor' },
  { name: 'forceSSL', longOpt: 'force-ssl', type: 'boolean', defaultValue: false, description: '强制SSL' },
  
  // Optimization 优化选项
  { name: 'optimize', longOpt: 'optimize', shortOpt: 'o', type: 'boolean', defaultValue: false, description: '优化模式' },
  { name: 'keepAlive', longOpt: 'keep-alive', type: 'boolean', defaultValue: false, description: '保持连接' },
  { name: 'nullConnection', longOpt: 'null-connection', type: 'boolean', defaultValue: false, description: '空连接' },
  { name: 'threads', longOpt: 'threads', type: 'number', defaultValue: 1, minValue: 1, maxValue: 10, description: '线程数' },
  
  // Enumeration 枚举选项
  { name: 'getBanner', longOpt: 'banner', type: 'boolean', defaultValue: false, description: '获取Banner' },
  { name: 'getCurrentUser', longOpt: 'current-user', type: 'boolean', defaultValue: false, description: '获取当前用户' },
  { name: 'getCurrentDb', longOpt: 'current-db', type: 'boolean', defaultValue: false, description: '获取当前数据库' },
  { name: 'isDba', longOpt: 'is-dba', type: 'boolean', defaultValue: false, description: '是否DBA' },
  { name: 'getUsers', longOpt: 'users', type: 'boolean', defaultValue: false, description: '获取用户列表' },
  { name: 'getDbs', longOpt: 'dbs', type: 'boolean', defaultValue: false, description: '获取数据库列表' },
  { name: 'getTables', longOpt: 'tables', type: 'boolean', defaultValue: false, description: '获取表列表' },
  { name: 'getColumns', longOpt: 'columns', type: 'boolean', defaultValue: false, description: '获取列列表' },
  { name: 'dumpTable', longOpt: 'dump', type: 'boolean', defaultValue: false, description: '导出表数据' },
  { name: 'dumpAll', longOpt: 'dump-all', type: 'boolean', defaultValue: false, description: '导出所有数据' },
  { name: 'db', longOpt: 'db', shortOpt: 'D', type: 'string', defaultValue: '', description: '目标数据库' },
  { name: 'tbl', longOpt: 'tbl', shortOpt: 'T', type: 'string', defaultValue: '', description: '目标表' },
  { name: 'col', longOpt: 'col', shortOpt: 'C', type: 'string', defaultValue: '', description: '目标列' },
  
  // General 通用选项
  { name: 'batch', longOpt: 'batch', type: 'boolean', defaultValue: true, description: '非交互模式' },
  { name: 'forms', longOpt: 'forms', type: 'boolean', defaultValue: false, description: '解析表单' },
  { name: 'crawlDepth', longOpt: 'crawl', type: 'number', defaultValue: 0, minValue: 0, maxValue: 10, description: '爬取深度' },
  { name: 'flushSession', longOpt: 'flush-session', type: 'boolean', defaultValue: false, description: '刷新会话' },
  { name: 'freshQueries', longOpt: 'fresh-queries', type: 'boolean', defaultValue: false, description: '新鲜查询' },
  { name: 'verbose', longOpt: 'verbose', shortOpt: 'v', type: 'number', defaultValue: 1, minValue: 0, maxValue: 6, description: '详细程度 (0-6)' },
]

// 创建映射
const NAME_MAP = new Map<string, ParamMeta>()
PARAM_META.forEach(meta => NAME_MAP.set(meta.name, meta))

// 创建长选项到参数名的映射（支持 kebab-case 到 camelCase）
const LONG_OPT_MAP = new Map<string, ParamMeta>()
PARAM_META.forEach(meta => {
  LONG_OPT_MAP.set(meta.longOpt, meta)
  // 同时添加 camelCase 版本
  const camelCase = kebabToCamel(meta.longOpt)
  if (camelCase !== meta.longOpt) {
    LONG_OPT_MAP.set(camelCase, meta)
  }
})

// 创建短选项映射
const SHORT_OPT_MAP = new Map<string, ParamMeta>()
PARAM_META.forEach(meta => {
  if (meta.shortOpt) {
    SHORT_OPT_MAP.set(meta.shortOpt, meta)
  }
})

// ==================== mri 配置构建 ====================

/**
 * 构建 mri 选项配置
 */
function buildMriOptions(): mri.Options {
  const alias: Record<string, string | string[]> = {}
  const boolean: string[] = []
  const string: string[] = []
  const defaults: Record<string, any> = {}
  
  for (const meta of PARAM_META) {
    // 设置别名（短选项和 camelCase 名称）
    const aliases: string[] = []
    if (meta.shortOpt) {
      aliases.push(meta.shortOpt)
    }
    // 添加 camelCase 别名（如果与 longOpt 不同）
    const camelName = kebabToCamel(meta.longOpt)
    if (camelName !== meta.longOpt) {
      aliases.push(camelName)
    }
    if (aliases.length > 0) {
      alias[meta.longOpt] = aliases
    }
    
    // 设置类型
    if (meta.type === 'boolean') {
      boolean.push(meta.longOpt)
    } else if (meta.type === 'string') {
      string.push(meta.longOpt)
    }
    // 注意：mri 没有专门的 number 类型，数字会自动转换
    
    // 设置默认值
    defaults[meta.longOpt] = meta.defaultValue
  }
  
  return { alias, boolean, string, default: defaults }
}

const MRI_OPTIONS = buildMriOptions()

// ==================== 解析结果类型 ====================

export interface ParseResult {
  options: ScanOptions
  errors: string[]
  warnings: string[]
  parsedParams: string[]  // 已解析的参数名列表
}

// ==================== 工具函数 ====================

/**
 * 将 kebab-case 转换为 camelCase
 */
function kebabToCamel(str: string): string {
  return str.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())
}

/**
 * 将参数字符串分割为数组（处理引号）
 */
function splitArgs(paramString: string): string[] {
  const args: string[] = []
  let current = ''
  let inQuote = false
  let quoteChar = ''
  
  for (let i = 0; i < paramString.length; i++) {
    const char = paramString[i]
    
    if (!inQuote && (char === '"' || char === "'")) {
      inQuote = true
      quoteChar = char
    } else if (inQuote && char === quoteChar) {
      inQuote = false
      quoteChar = ''
    } else if (!inQuote && char === ' ') {
      if (current.trim()) {
        args.push(current.trim())
      }
      current = ''
    } else {
      current += char
    }
  }
  
  if (current.trim()) {
    args.push(current.trim())
  }
  
  return args
}

// ==================== 解析函数 ====================

/**
 * 解析参数字符串为 ScanOptions
 * @param paramString 命令行参数字符串，如 "--level=5 --risk=3 --dbms=mysql"
 * @returns 解析结果
 */
export function parseParameterString(paramString: string): ParseResult {
  const result: ParseResult = {
    options: { ...DEFAULT_SCAN_OPTIONS },
    errors: [],
    warnings: [],
    parsedParams: []
  }
  
  if (!paramString || paramString.trim() === '') {
    return result
  }
  
  try {
    // 分割参数字符串为数组
    const args = splitArgs(paramString)
    
    // 使用 mri 解析
    const parsed = mri(args, MRI_OPTIONS)
    
    // 处理解析结果
    for (const meta of PARAM_META) {
      // mri 会使用 longOpt 作为键名
      let value = parsed[meta.longOpt]
      
      // 也检查 camelCase 版本
      if (value === undefined) {
        const camelKey = kebabToCamel(meta.longOpt)
        value = parsed[camelKey]
      }
      
      // 也检查 name（规范名）
      if (value === undefined) {
        value = parsed[meta.name]
      }
      
      // 跳过未设置的参数（使用默认值）
      if (value === undefined || value === meta.defaultValue) {
        continue
      }
      
      result.parsedParams.push(meta.name)
      
      // 验证并设置值
      if (meta.type === 'number') {
        let numValue = Number(value)
        if (isNaN(numValue)) {
          result.errors.push(`参数 '${meta.name}' 值 '${value}' 不是有效数字`)
          continue
        }
        // 范围验证
        if (meta.minValue !== undefined && numValue < meta.minValue) {
          result.warnings.push(`参数 '${meta.name}' 值 ${numValue} 小于最小值 ${meta.minValue}，已自动调整`)
          numValue = meta.minValue
        }
        if (meta.maxValue !== undefined && numValue > meta.maxValue) {
          result.warnings.push(`参数 '${meta.name}' 值 ${numValue} 大于最大值 ${meta.maxValue}，已自动调整`)
          numValue = meta.maxValue
        }
        ;(result.options as any)[meta.name] = numValue
      } else if (meta.type === 'boolean') {
        ;(result.options as any)[meta.name] = Boolean(value)
      } else {
        // 字符串类型 - 验证有效值
        const strValue = String(value)
        if (meta.validValues && meta.validValues.length > 0 && strValue !== '') {
          const lowerValue = strValue.toLowerCase()
          const valid = meta.validValues.some(v => v.toLowerCase() === lowerValue)
          if (!valid) {
            result.warnings.push(`参数 '${meta.name}' 值 '${strValue}' 不在有效值列表中: ${meta.validValues.join(', ')}`)
          }
        }
        ;(result.options as any)[meta.name] = strValue
      }
    }
    
    // 检查未识别的参数
    const knownKeys = new Set<string>()
    knownKeys.add('_')  // mri 的位置参数
    for (const meta of PARAM_META) {
      knownKeys.add(meta.longOpt)
      knownKeys.add(meta.name)
      knownKeys.add(kebabToCamel(meta.longOpt))
      if (meta.shortOpt) {
        knownKeys.add(meta.shortOpt)
      }
    }
    
    for (const key of Object.keys(parsed)) {
      if (!knownKeys.has(key)) {
        result.warnings.push(`未识别的参数: ${key}`)
      }
    }
    
  } catch (e: any) {
    result.errors.push(`解析异常: ${e.message}`)
  }
  
  return result
}

/**
 * 将 ScanOptions 转换为命令行参数字符串
 * @param options 扫描选项
 * @param includeDefaults 是否包含默认值参数
 * @returns 命令行参数字符串
 */
export function toParameterString(options: ScanOptions, includeDefaults = false): string {
  const parts: string[] = []
  
  if (!options || typeof options !== 'object') {
    return ''
  }
  
  for (const meta of PARAM_META) {
    const rawValue = options[meta.name as keyof ScanOptions]
    
    // 跳过未定义的值
    if (rawValue === undefined || rawValue === null) continue
    
    // 类型转换：确保数字类型正确处理
    let value: any = rawValue
    if (meta.type === 'number') {
      value = Number(rawValue)
      if (isNaN(value)) continue
    } else if (meta.type === 'boolean') {
      value = rawValue === true || rawValue === 'true' || rawValue === 1
    }
    
    // 如果不包含默认值，跳过等于默认值的参数
    if (!includeDefaults && isDefaultValue(meta, value)) continue
    
    if (meta.type === 'boolean') {
      if (value === true) {
        parts.push(`--${meta.longOpt}`)
      }
    } else if (meta.type === 'string') {
      if (value !== '' && value !== meta.defaultValue) {
        // 如果包含空格或特殊字符，加引号
        const strValue = String(value)
        if (strValue.includes(' ') || strValue.includes('"') || strValue.includes("'")) {
          parts.push(`--${meta.longOpt}="${strValue.replace(/"/g, '\\"')}"`)
        } else {
          parts.push(`--${meta.longOpt}=${strValue}`)
        }
      }
    } else {
      // number
      if (value !== meta.defaultValue) {
        parts.push(`--${meta.longOpt}=${value}`)
      }
    }
  }
  
  return parts.join(' ')
}

/**
 * 快速解析，返回 ScanOptions，忽略错误
 */
export function parseOrDefault(paramString: string): ScanOptions {
  const result = parseParameterString(paramString)
  return result.options
}

/**
 * 获取参数元数据列表
 */
export function getParamMetaList(): ParamMeta[] {
  return [...PARAM_META]
}

/**
 * 根据参数名获取元数据
 */
export function getParamMeta(name: string): ParamMeta | undefined {
  return NAME_MAP.get(name)
}

// ==================== 内部辅助函数 ====================

/**
 * 检查是否为默认值
 */
function isDefaultValue(meta: ParamMeta, value: any): boolean {
  if (meta.type === 'boolean') {
    return value === meta.defaultValue
  } else if (meta.type === 'string') {
    return value === meta.defaultValue || value === ''
  } else {
    return value === meta.defaultValue
  }
}

// ==================== 导出常量 ====================

export { PARAM_META }
export type { ParamMeta }
