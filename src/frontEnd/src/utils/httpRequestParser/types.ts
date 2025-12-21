/**
 * HTTP请求解析器 - 类型定义模块
 * 
 * 定义所有解析器共用的接口和类型
 */

/**
 * 解析后的HTTP请求结构
 */
export interface ParsedHttpRequest {
  /** HTTP方法 */
  method: string
  /** 完整URL */
  url: string
  /** 主机名（包含端口） */
  host: string
  /** 请求路径（包含查询字符串和hash） */
  path: string
  /** HTTP头部 */
  headers: Record<string, string>
  /** 请求体 */
  body: string
  /** 协议（http或https） */
  protocol: string
}

/**
 * 解析结果
 */
export interface ParseResult {
  /** 是否解析成功 */
  success: boolean
  /** 解析后的请求数据 */
  data?: ParsedHttpRequest
  /** 转换后的原始HTTP报文 */
  rawHttp?: string
  /** 错误信息 */
  error?: string
  /** 检测到的格式类型 */
  format?: RequestFormat
}

/**
 * 请求格式类型
 */
export type RequestFormat = 
  | 'curl_cmd'      // Windows CMD cURL格式
  | 'curl_bash'     // Linux/Mac Bash cURL格式  
  | 'powershell'    // PowerShell Invoke-WebRequest格式
  | 'fetch_js'      // 浏览器fetch API格式
  | 'fetch_nodejs'  // Node.js fetch格式
  | 'raw_http'      // 原始HTTP报文格式
  | 'unknown'       // 未知格式

/**
 * 格式显示名称映射
 */
export const FORMAT_DISPLAY_NAMES: Record<RequestFormat, string> = {
  'curl_cmd': 'cURL (Windows CMD)',
  'curl_bash': 'cURL (Bash)',
  'powershell': 'PowerShell',
  'fetch_js': 'fetch (JavaScript)',
  'fetch_nodejs': 'fetch (Node.js)',
  'raw_http': '原始 HTTP 报文',
  'unknown': '未知格式'
}

/**
 * 解析器函数类型
 */
export type ParserFunction = (input: string) => ParsedHttpRequest | null
