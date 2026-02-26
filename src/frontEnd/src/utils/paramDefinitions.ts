/**
 * SQLMap 参数定义
 * 用于引导式参数编辑器
 */

export interface ParamDefinition {
  key: string           // 内部键名
  name: string          // 显示名称
  cliName: string       // 命令行参数名
  description: string   // 描述
  category: string      // 分类
  type: 'boolean' | 'integer' | 'float' | 'string' | 'select'
  defaultValue?: any    // 默认值
  min?: number          // 最小值(数字类型)
  max?: number          // 最大值(数字类型)
  options?: string[]    // 选项列表(select类型)
}

export interface ParamCategory {
  key: string
  label: string
}

// 参数分类
export const PARAM_CATEGORIES: ParamCategory[] = [
  { key: 'detection', label: 'Detection 检测' },
  { key: 'injection', label: 'Injection 注入' },
  { key: 'techniques', label: 'Techniques 技术' },
  { key: 'request', label: 'Request 请求' },
  { key: 'optimization', label: 'Optimization 优化' },
  { key: 'enumeration', label: 'Enumeration 枚举' },
  { key: 'general', label: 'General 通用' }
]

// DBMS选项
export const DBMS_OPTIONS = [
  '', 'MySQL', 'Oracle', 'PostgreSQL', 'Microsoft SQL Server', 'SQLite',
  'Microsoft Access', 'Firebird', 'Sybase', 'SAP MaxDB', 'IBM DB2',
  'HSQLDB', 'H2', 'Informix', 'MonetDB', 'Apache Derby'
]

// HTTP方法选项
export const METHOD_OPTIONS = ['', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

// OS选项
export const OS_OPTIONS = ['', 'Linux', 'Windows']

// 参数定义列表
export const PARAM_DEFINITIONS: ParamDefinition[] = [
  // Detection 检测
  { key: 'level', name: 'level', cliName: '--level', description: '检测级别 (1-5)', category: 'detection', type: 'integer', defaultValue: 1, min: 1, max: 5 },
  { key: 'risk', name: 'risk', cliName: '--risk', description: '风险级别 (1-3)', category: 'detection', type: 'integer', defaultValue: 1, min: 1, max: 3 },
  { key: 'string', name: 'string', cliName: '--string', description: '页面包含此字符串时为True', category: 'detection', type: 'string' },
  { key: 'notString', name: 'not-string', cliName: '--not-string', description: '页面包含此字符串时为False', category: 'detection', type: 'string' },
  { key: 'regexp', name: 'regexp', cliName: '--regexp', description: '页面匹配此正则时为True', category: 'detection', type: 'string' },
  { key: 'code', name: 'code', cliName: '--code', description: '页面返回此状态码时为True', category: 'detection', type: 'integer', min: 100, max: 599 },
  { key: 'smart', name: 'smart', cliName: '--smart', description: '智能启发式检测', category: 'detection', type: 'boolean' },
  { key: 'textOnly', name: 'text-only', cliName: '--text-only', description: '仅基于文本内容比较', category: 'detection', type: 'boolean' },
  { key: 'titles', name: 'titles', cliName: '--titles', description: '仅基于标题比较', category: 'detection', type: 'boolean' },
  
  // Injection 注入
  { key: 'testParameter', name: 'test parameter', cliName: '-p', description: '测试指定参数', category: 'injection', type: 'string' },
  { key: 'skip', name: 'skip', cliName: '--skip', description: '跳过指定参数', category: 'injection', type: 'string' },
  { key: 'skipStatic', name: 'skip-static', cliName: '--skip-static', description: '跳过静态参数', category: 'injection', type: 'boolean' },
  { key: 'paramExclude', name: 'param-exclude', cliName: '--param-exclude', description: '排除参数的正则', category: 'injection', type: 'string' },
  { key: 'dbms', name: 'dbms', cliName: '--dbms', description: '指定数据库类型', category: 'injection', type: 'select', options: DBMS_OPTIONS },
  { key: 'os', name: 'os', cliName: '--os', description: '指定操作系统', category: 'injection', type: 'select', options: OS_OPTIONS },
  { key: 'prefix', name: 'prefix', cliName: '--prefix', description: '注入payload前缀', category: 'injection', type: 'string' },
  { key: 'suffix', name: 'suffix', cliName: '--suffix', description: '注入payload后缀', category: 'injection', type: 'string' },
  { key: 'tamper', name: 'tamper', cliName: '--tamper', description: 'Tamper脚本', category: 'injection', type: 'string' },
  
  // Techniques 技术
  { key: 'technique', name: 'technique', cliName: '--technique', description: '注入技术 (BEUSTQ)', category: 'techniques', type: 'string', defaultValue: 'BEUSTQ' },
  { key: 'timeSec', name: 'time-sec', cliName: '--time-sec', description: '时间盲注延迟秒数', category: 'techniques', type: 'integer', defaultValue: 5, min: 1, max: 30 },
  
  // Request 请求
  { key: 'method', name: 'method', cliName: '--method', description: 'HTTP方法', category: 'request', type: 'select', options: METHOD_OPTIONS },
  { key: 'data', name: 'data', cliName: '--data', description: 'POST数据', category: 'request', type: 'string' },
  { key: 'cookie', name: 'cookie', cliName: '--cookie', description: 'Cookie值', category: 'request', type: 'string' },
  { key: 'agent', name: 'user-agent', cliName: '--user-agent', description: 'User-Agent', category: 'request', type: 'string' },
  { key: 'referer', name: 'referer', cliName: '--referer', description: 'Referer', category: 'request', type: 'string' },
  { key: 'headers', name: 'headers', cliName: '--headers', description: '额外Headers', category: 'request', type: 'string' },
  { key: 'proxy', name: 'proxy', cliName: '--proxy', description: 'HTTP代理', category: 'request', type: 'string' },
  { key: 'proxyCred', name: 'proxy-cred', cliName: '--proxy-cred', description: '代理认证', category: 'request', type: 'string' },
  { key: 'delay', name: 'delay', cliName: '--delay', description: '请求延迟(秒)', category: 'request', type: 'float', min: 0, max: 60 },
  { key: 'timeout', name: 'timeout', cliName: '--timeout', description: '超时时间(秒)', category: 'request', type: 'integer', defaultValue: 30, min: 1, max: 300 },
  { key: 'retries', name: 'retries', cliName: '--retries', description: '重试次数', category: 'request', type: 'integer', defaultValue: 3, min: 0, max: 10 },
  { key: 'randomAgent', name: 'random-agent', cliName: '--random-agent', description: '随机User-Agent', category: 'request', type: 'boolean' },
  { key: 'tor', name: 'tor', cliName: '--tor', description: '使用Tor网络', category: 'request', type: 'boolean' },
  { key: 'forceSSL', name: 'force-ssl', cliName: '--force-ssl', description: '强制使用SSL', category: 'request', type: 'boolean' },
  { key: 'skipUrlEncode', name: 'skip-urlencode', cliName: '--skip-urlencode', description: '跳过URL编码', category: 'request', type: 'boolean' },
  
  // Optimization 优化
  { key: 'optimize', name: 'optimize', cliName: '-o', description: '启用所有优化', category: 'optimization', type: 'boolean' },
  { key: 'keepAlive', name: 'keep-alive', cliName: '--keep-alive', description: '保持连接', category: 'optimization', type: 'boolean' },
  { key: 'nullConnection', name: 'null-connection', cliName: '--null-connection', description: '使用空连接', category: 'optimization', type: 'boolean' },
  { key: 'threads', name: 'threads', cliName: '--threads', description: '并发线程数', category: 'optimization', type: 'integer', defaultValue: 1, min: 1, max: 10 },
  
  // Enumeration 枚举
  { key: 'getAll', name: 'all', cliName: '--all', description: '枚举所有信息', category: 'enumeration', type: 'boolean' },
  { key: 'getBanner', name: 'banner', cliName: '--banner', description: '获取DBMS Banner', category: 'enumeration', type: 'boolean' },
  { key: 'getCurrentUser', name: 'current-user', cliName: '--current-user', description: '获取当前用户', category: 'enumeration', type: 'boolean' },
  { key: 'getCurrentDb', name: 'current-db', cliName: '--current-db', description: '获取当前数据库', category: 'enumeration', type: 'boolean' },
  { key: 'getHostname', name: 'hostname', cliName: '--hostname', description: '获取主机名', category: 'enumeration', type: 'boolean' },
  { key: 'isDba', name: 'is-dba', cliName: '--is-dba', description: '检测是否为DBA', category: 'enumeration', type: 'boolean' },
  { key: 'getUsers', name: 'users', cliName: '--users', description: '枚举用户', category: 'enumeration', type: 'boolean' },
  { key: 'getPasswordHashes', name: 'passwords', cliName: '--passwords', description: '获取密码哈希', category: 'enumeration', type: 'boolean' },
  { key: 'getPrivileges', name: 'privileges', cliName: '--privileges', description: '获取权限', category: 'enumeration', type: 'boolean' },
  { key: 'getRoles', name: 'roles', cliName: '--roles', description: '获取角色', category: 'enumeration', type: 'boolean' },
  { key: 'getDbs', name: 'dbs', cliName: '--dbs', description: '枚举数据库', category: 'enumeration', type: 'boolean' },
  { key: 'getTables', name: 'tables', cliName: '--tables', description: '枚举表', category: 'enumeration', type: 'boolean' },
  { key: 'getColumns', name: 'columns', cliName: '--columns', description: '枚举列', category: 'enumeration', type: 'boolean' },
  { key: 'getSchema', name: 'schema', cliName: '--schema', description: '获取Schema', category: 'enumeration', type: 'boolean' },
  { key: 'getCount', name: 'count', cliName: '--count', description: '获取记录数', category: 'enumeration', type: 'boolean' },
  { key: 'getComments', name: 'comments', cliName: '--comments', description: '获取注释', category: 'enumeration', type: 'boolean' },
  { key: 'getStatements', name: 'statements', cliName: '--statements', description: '获取SQL语句', category: 'enumeration', type: 'boolean' },
  { key: 'dumpTable', name: 'dump', cliName: '--dump', description: '导出数据', category: 'enumeration', type: 'boolean' },
  { key: 'dumpAll', name: 'dump-all', cliName: '--dump-all', description: '导出所有数据', category: 'enumeration', type: 'boolean' },
  { key: 'dumpWhere', name: 'where', cliName: '--where', description: 'dump条件', category: 'enumeration', type: 'string' },
  { key: 'limitStart', name: 'start', cliName: '--start', description: '起始行', category: 'enumeration', type: 'integer', min: 0 },
  { key: 'limitStop', name: 'stop', cliName: '--stop', description: '结束行', category: 'enumeration', type: 'integer', min: 0 },
  { key: 'firstChar', name: 'first', cliName: '--first', description: '起始字符位', category: 'enumeration', type: 'integer', min: 0 },
  { key: 'lastChar', name: 'last', cliName: '--last', description: '结束字符位', category: 'enumeration', type: 'integer', min: 0 },
  { key: 'db', name: 'database', cliName: '-D', description: '指定数据库', category: 'enumeration', type: 'string' },
  { key: 'tbl', name: 'table', cliName: '-T', description: '指定表', category: 'enumeration', type: 'string' },
  { key: 'col', name: 'column', cliName: '-C', description: '指定列', category: 'enumeration', type: 'string' },
  { key: 'extensiveFp', name: 'fingerprint', cliName: '--fingerprint', description: '深度指纹识别', category: 'enumeration', type: 'boolean' },

  // Techniques 扩展
  { key: 'uCols', name: 'union-cols', cliName: '--union-cols', description: 'UNION列数范围', category: 'techniques', type: 'string' },
  { key: 'uChar', name: 'union-char', cliName: '--union-char', description: 'UNION填充字符', category: 'techniques', type: 'string' },
  { key: 'uFrom', name: 'union-from', cliName: '--union-from', description: 'UNION FROM表', category: 'techniques', type: 'string' },
  { key: 'uValues', name: 'union-values', cliName: '--union-values', description: 'UNION填充值', category: 'techniques', type: 'string' },

  // General 通用
  { key: 'requestFile', name: 'request file', cliName: '-r', description: 'HTTP请求文件', category: 'general', type: 'string' },
  { key: 'sessionFile', name: 'session file', cliName: '-s', description: '会话文件', category: 'general', type: 'string' },
  { key: 'trafficFile', name: 'traffic file', cliName: '-t', description: '流量日志文件', category: 'general', type: 'string' },
  { key: 'batch', name: 'batch', cliName: '--batch', description: '批处理模式(不提问)', category: 'general', type: 'boolean', defaultValue: true },
  { key: 'forms', name: 'forms', cliName: '--forms', description: '解析并测试表单', category: 'general', type: 'boolean' },
  { key: 'crawlDepth', name: 'crawl', cliName: '--crawl', description: '爬取深度', category: 'general', type: 'integer', min: 0, max: 10 },
  { key: 'flushSession', name: 'flush-session', cliName: '--flush-session', description: '刷新会话文件', category: 'general', type: 'boolean' },
  { key: 'freshQueries', name: 'fresh-queries', cliName: '--fresh-queries', description: '忽略会话缓存', category: 'general', type: 'boolean' },
  { key: 'verbose', name: 'verbose', cliName: '-v', description: '详细级别 (0-6)', category: 'general', type: 'integer', defaultValue: 1, min: 0, max: 6 },
  { key: 'answers', name: 'answers', cliName: '--answers', description: '预定义答案', category: 'general', type: 'string' },
  { key: 'rParam', name: 'randomize', cliName: '--randomize', description: '随机化参数值', category: 'general', type: 'string' },
  { key: 'evalCode', name: 'eval', cliName: '--eval', description: '执行Python代码', category: 'general', type: 'string' },
  { key: 'shLib', name: 'shared-lib', cliName: '--shared-lib', description: '共享库路径', category: 'general', type: 'string' },
  { key: 'regVal', name: 'reg-value', cliName: '--reg-value', description: '注册表值', category: 'general', type: 'string' },
]

// 根据key获取参数定义
export function getParamDefinition(key: string): ParamDefinition | undefined {
  return PARAM_DEFINITIONS.find(p => p.key === key)
}

// 根据CLI名称获取参数定义
export function getParamByCliName(cliName: string): ParamDefinition | undefined {
  return PARAM_DEFINITIONS.find(p => p.cliName === cliName)
}

// 驼峰转连字符（后备方案，用于映射表中未定义的参数）
export function camelToKebab(str: string): string {
  return str.replace(/([A-Z])/g, '-$1').toLowerCase().replace(/^-/, '')
}

// 创建 key→cliName 映射表（缓存用，避免每次遍历数组）
let _paramKeyToCliNameMap: Map<string, string> | null = null
export function getParamKeyToCliNameMap(): Map<string, string> {
  if (!_paramKeyToCliNameMap) {
    _paramKeyToCliNameMap = new Map<string, string>()
    for (const param of PARAM_DEFINITIONS) {
      _paramKeyToCliNameMap.set(param.key, param.cliName)
    }
  }
  return _paramKeyToCliNameMap
}

// 转换单个参数为命令行格式
export function convertOptionToCliArg(key: string, value: any): string | null {
  if (value === false || value === null || value === undefined || value === '') {
    return null
  }

  const map = getParamKeyToCliNameMap()
  // 优先使用映射表中的 cliName
  let cliName = map.get(key)
  if (!cliName) {
    // 后备: 驼峰转连字符
    cliName = '--' + camelToKebab(key)
  }

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

// 格式化命令行参数值
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
