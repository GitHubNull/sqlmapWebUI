/**
 * SQLMap 参数定义类型
 */

// 参数分类键名
export type ParamCategoryKey =
  | 'target'
  | 'request'
  | 'optimization'
  | 'injection'
  | 'detection'
  | 'techniques'
  | 'fingerprint'
  | 'enumeration'
  | 'bruteForce'
  | 'udf'
  | 'fileSystem'
  | 'osTakeover'
  | 'windowsRegistry'
  | 'general'
  | 'miscellaneous'

// 参数输入类型
export type ParamInputType = 'boolean' | 'integer' | 'float' | 'string' | 'select' | 'textarea'

// 安全等级
export type SecurityLevel = 'normal' | 'warning' | 'danger'

// 参数定义接口
export interface ParamDefinition {
  key: string                    // 内部键名 (camelCase)
  cliName: string                // CLI 参数名 (--xxx 或 -x)
  name: string                   // 显示名称
  description: string            // 中文描述
  category: ParamCategoryKey     // 所属分类

  // 类型相关
  type: ParamInputType
  defaultValue?: any

  // 值约束
  min?: number                   // 最小值 (数字类型)
  max?: number                   // 最大值 (数字类型)
  options?: string[]             // 选项列表 (select 类型)
  placeholder?: string           // 输入占位符

  // 安全警告
  securityLevel?: SecurityLevel  // 安全等级
  securityWarning?: string       // 安全警告文本

  // 显示控制
  advanced?: boolean             // 是否为高级选项
  disabled?: boolean             // 是否禁用（如 RESTAPI 不支持）
  disabledReason?: string        // 禁用原因
}

// 参数分类接口
export interface ParamCategory {
  key: ParamCategoryKey
  label: string                  // 中英文标签
  icon: string                   // PrimeVue 图标
  description: string            // 分类描述
  order: number                  // 排序
}

// 参数验证结果
export interface ParamValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
}

// 常用选项定义
export const DBMS_OPTIONS = [
  '', 'MySQL', 'Oracle', 'PostgreSQL', 'Microsoft SQL Server', 'SQLite',
  'Microsoft Access', 'Firebird', 'Sybase', 'SAP MaxDB', 'IBM DB2',
  'HSQLDB', 'H2', 'Informix', 'MonetDB', 'Apache Derby', 'Vertica',
  'Mckoi', 'Presto', 'Altibase', 'MimerSQL', 'CrateDB', 'Greenplum',
  'Drizzle', 'Apache Ignite', 'Cubrid', 'InterSystems Cache', 'IRIS',
  'eXtremeDB', 'FrontBase', 'Raima Database Manager', 'Virtuoso'
]

export const OS_OPTIONS = ['', 'Linux', 'Windows']

export const METHOD_OPTIONS = ['', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']

export const AUTH_TYPE_OPTIONS = ['', 'Basic', 'Digest', 'Bearer', 'NTLM', 'PKI']

export const PROXY_TYPE_OPTIONS = ['', 'HTTP', 'SOCKS4', 'SOCKS5']

export const DUMP_FORMAT_OPTIONS = ['', 'CSV', 'HTML', 'SQLITE']

export const TECHNIQUE_OPTIONS = [
  { value: 'B', label: 'B (布尔盲注)' },
  { value: 'E', label: 'E (报错注入)' },
  { value: 'U', label: 'U (联合查询)' },
  { value: 'S', label: 'S (堆叠查询)' },
  { value: 'T', label: 'T (时间盲注)' },
  { value: 'Q', label: 'Q (内联查询)' }
]
