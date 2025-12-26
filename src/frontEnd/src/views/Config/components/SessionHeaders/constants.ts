/**
 * Session Headers 模块常量定义
 */
import { ReplaceStrategy } from '@/types/headerRule'

// 过滤选项 - 状态
export const STATUS_OPTIONS = [
  { label: '有效', value: 'valid' },
  { label: '已过期', value: 'expired' },
] as const

// 过滤选项 - 优先级
export const PRIORITY_OPTIONS = [
  { label: '高 (80-100)', value: 'high' },
  { label: '中 (50-79)', value: 'medium' },
  { label: '低 (0-49)', value: 'low' },
] as const

// 替换策略选项
export const REPLACE_STRATEGY_OPTIONS = [
  { label: '完全替换', value: ReplaceStrategy.REPLACE },
  { label: '追加', value: ReplaceStrategy.APPEND },
  { label: '前置', value: ReplaceStrategy.PREPEND },
  { label: '条件性替换', value: ReplaceStrategy.CONDITIONAL },
  { label: '存在则替换，不存在则新增', value: ReplaceStrategy.UPSERT },
] as const

// JSON导入占位符
export const JSON_PLACEHOLDER = `[
  {
    "header_name": "Authorization",
    "header_value": "Bearer your-token-here",
    "replace_strategy": "REPLACE",
    "priority": 80,
    "ttl": 3600
  },
  {
    "header_name": "Cookie",
    "header_value": "session_id=abc123",
    "replace_strategy": "UPSERT"
  }
]`

// 文本导入模板
export const TEXT_TEMPLATE = `# Session Headers 文本导入模板
# 格式: Header名称|||Header值|||替换策略|||优先级|||TTL(秒)
# 替换策略可选值: REPLACE, APPEND, PREPEND, UPSERT
# 优先级: 0-100，默认50
# TTL: 生存时间(秒)，默认3600
# 以 # 开头的行为注释，会被忽略

Authorization|||Bearer eyJhbGciOiJIUzI1NiJ9.your-token-here|||REPLACE|||80|||3600
Cookie|||session_id=abc123; user_token=xyz789|||UPSERT|||50|||7200
X-Custom-Header|||custom-value|||APPEND|||60|||1800
X-API-Key|||your-api-key-here
Content-Type|||application/json`

// JSON导入模板数据
export const JSON_TEMPLATE_DATA = [
  {
    header_name: "Authorization",
    header_value: "Bearer eyJhbGciOiJIUzI1NiJ9.your-token-here",
    replace_strategy: "REPLACE",
    priority: 80,
    ttl: 3600,
    is_active: true
  },
  {
    header_name: "Cookie",
    header_value: "session_id=abc123; user_token=xyz789",
    replace_strategy: "UPSERT",
    priority: 50,
    ttl: 7200
  },
  {
    header_name: "X-Custom-Header",
    header_value: "custom-value",
    replace_strategy: "APPEND",
    priority: 60
  },
  {
    header_name: "X-API-Key",
    header_value: "your-api-key-here"
  }
]

// 默认配置值
export const DEFAULT_PRIORITY = 50
export const DEFAULT_TTL = 3600
export const DEFAULT_PAGE_SIZE = 10

// 分隔符
export const FIELD_SEPARATOR = '|||'
