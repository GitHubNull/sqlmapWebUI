/**
 * 扫描配置预设类型定义
 */

// 预设类型
export type PresetType = 'default' | 'preset' | 'history'

// 扫描选项
export interface ScanOptions {
  // Detection 检测选项
  level?: number          // 检测级别 (1-5)
  risk?: number           // 风险级别 (1-3)
  string?: string         // 页面匹配字符串
  notString?: string      // 页面不匹配字符串
  regexp?: string         // 正则匹配
  code?: number           // HTTP响应码
  smart?: boolean         // 智能检测
  textOnly?: boolean      // 仅文本比较
  titles?: boolean        // 基于标题比较
  
  // Injection 注入选项
  testParameter?: string  // 指定测试参数 (-p)
  skip?: string           // 跳过参数
  skipStatic?: boolean    // 跳过静态参数
  paramExclude?: string   // 排除参数
  dbms?: string           // 数据库类型
  os?: string             // 操作系统
  prefix?: string         // 注入前缀
  suffix?: string         // 注入后缀
  tamper?: string         // 篡改脚本
  
  // Techniques 技术选项
  technique?: string      // 注入技术 (BEUSTQ)
  timeSec?: number        // 时间盲注延迟(秒)
  
  // Request 请求选项
  timeout?: number        // 请求超时(秒)
  retries?: number        // 重试次数
  delay?: number          // 请求延迟(秒)
  randomAgent?: boolean   // 随机User-Agent
  proxy?: string          // 代理
  tor?: boolean           // 使用Tor
  
  // Optimization 优化选项
  optimize?: boolean      // 使用所有优化选项
  predictOutput?: boolean // 预测输出
  keepAlive?: boolean     // 保持连接
  nullConnection?: boolean // 空连接
  threads?: number        // 线程数
  
  // Enumeration 枚举选项
  getBanner?: boolean     // 获取Banner
  getCurrentUser?: boolean // 获取当前用户
  getCurrentDb?: boolean  // 获取当前数据库
  getHostname?: boolean   // 获取主机名
  isDba?: boolean         // 是否DBA
  getUsers?: boolean      // 获取所有用户
  getPasswordHashes?: boolean // 获取密码哈希
  getPrivileges?: boolean // 获取权限
  getRoles?: boolean      // 获取角色
  getDbs?: boolean        // 获取所有数据库
  getTables?: boolean     // 获取所有表
  getColumns?: boolean    // 获取所有列
  dumpTable?: boolean     // 导出表
  dumpAll?: boolean       // 导出所有
  db?: string             // 指定数据库
  tbl?: string            // 指定表
  col?: string            // 指定列
  
  // General 通用选项
  batch?: boolean         // 非交互模式
  forms?: boolean         // 解析表单
  crawlDepth?: number     // 爬取深度(0=禁用)
  flushSession?: boolean  // 刷新会话
  freshQueries?: boolean  // 刷新查询
  verbose?: number        // 详细级别 (0-6)
  
  // 其他选项
  [key: string]: any
}

// 扫描配置预设
export interface ScanPreset {
  id?: number
  name: string
  description?: string
  preset_type: PresetType
  options: ScanOptions
  parameter_string?: string  // 命令行参数字符串(与BurpSuite兼容)
  is_active: boolean
  created_at?: string
  updated_at?: string
  last_used_at?: string
  use_count: number
}

// 创建预设请求
export interface ScanPresetCreate {
  name: string
  description?: string
  preset_type?: PresetType
  options?: ScanOptions
  parameter_string?: string  // 命令行参数字符串
}

// 更新预设请求
export interface ScanPresetUpdate {
  name?: string
  description?: string
  options?: ScanOptions
  parameter_string?: string  // 命令行参数字符串
  is_active?: boolean
}

// 预设列表响应
export interface ScanPresetListResponse {
  presets: ScanPreset[]
  total: number
  default_preset?: ScanPreset
}

// 配置选项响应（用于下拉菜单）
export interface ConfigOptionsResponse {
  default: ScanPreset | null
  presets: ScanPreset[]
  history: ScanPreset[]
}

// 预设显示选项（用于下拉菜单）
export interface PresetOption {
  label: string
  value: number | 'default' | 'separator'
  preset?: ScanPreset
  type: PresetType | 'separator'
  disabled?: boolean
}

// 默认扫描选项
export const DEFAULT_SCAN_OPTIONS: ScanOptions = {
  level: 1,
  risk: 1,
  technique: 'BEUSTQ',
  timeSec: 5,
  timeout: 30,
  retries: 3,
  delay: 0,
  threads: 1,
  batch: true,
  verbose: 1
}

// 常用DBMS选项
export const DBMS_OPTIONS = [
  { label: '自动检测', value: '' },
  { label: 'MySQL', value: 'MySQL' },
  { label: 'PostgreSQL', value: 'PostgreSQL' },
  { label: 'Microsoft SQL Server', value: 'Microsoft SQL Server' },
  { label: 'Oracle', value: 'Oracle' },
  { label: 'SQLite', value: 'SQLite' },
  { label: 'MariaDB', value: 'MariaDB' },
  { label: 'IBM DB2', value: 'IBM DB2' },
  { label: 'SAP MaxDB', value: 'SAP MaxDB' },
  { label: 'Firebird', value: 'Firebird' },
  { label: 'Sybase', value: 'Sybase' },
  { label: 'H2', value: 'H2' },
  { label: 'HSQLDB', value: 'HSQLDB' },
  { label: 'Informix', value: 'Informix' },
  { label: 'Apache Derby', value: 'Apache Derby' }
]

// 注入技术选项
export const TECHNIQUE_OPTIONS = [
  { label: 'BEUSTQ (全部)', value: 'BEUSTQ' },
  { label: 'B (布尔盲注)', value: 'B' },
  { label: 'E (报错注入)', value: 'E' },
  { label: 'U (联合查询)', value: 'U' },
  { label: 'S (堆叠查询)', value: 'S' },
  { label: 'T (时间盲注)', value: 'T' },
  { label: 'Q (内联查询)', value: 'Q' },
  { label: 'BEU (常用)', value: 'BEU' },
  { label: 'BT (盲注)', value: 'BT' }
]

// Level选项
export const LEVEL_OPTIONS = [
  { label: '1 (快速)', value: 1 },
  { label: '2 (默认)', value: 2 },
  { label: '3 (中等)', value: 3 },
  { label: '4 (完整)', value: 4 },
  { label: '5 (最深入)', value: 5 }
]

// Risk选项
export const RISK_OPTIONS = [
  { label: '1 (安全)', value: 1 },
  { label: '2 (中等)', value: 2 },
  { label: '3 (高风险)', value: 3 }
]
