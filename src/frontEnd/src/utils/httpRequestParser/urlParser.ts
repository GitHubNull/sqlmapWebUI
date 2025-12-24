/**
 * HTTP请求解析器 - URL解析工具模块
 * 
 * 提供URL解析相关的工具函数
 */

export interface UrlParseResult {
  /** 主机名（不含端口） */
  host: string
  /** 请求路径 */
  path: string
  /** 协议 */
  protocol: string
}

/**
 * 解析URL，提取host、path等信息
 * 
 * @param urlStr - 完整URL字符串
 * @returns 解析结果，包含host、path、protocol
 * 
 * @example
 * parseUrl('https://example.com:8080/api/users?id=1')
 * // => { host: 'example.com', path: '/api/users?id=1', protocol: 'https' }
 */
export function parseUrl(urlStr: string): UrlParseResult {
  // 默认返回值
  const defaultResult: UrlParseResult = { host: '', path: '/', protocol: 'http' }
  
  if (!urlStr || typeof urlStr !== 'string') {
    return defaultResult
  }
  
  try {
    // 优先使用原生URL API
    const url = new URL(urlStr)
    const path = url.pathname + url.search + url.hash
    
    return {
      host: url.hostname,  // 使用 hostname 而不是 host，不包含端口
      path: path || '/',
      protocol: url.protocol.replace(':', '')
    }
  } catch {
    // URL API解析失败，尝试手动提取
    return parseUrlManually(urlStr) || defaultResult
  }
}

/**
 * 手动解析URL（当原生URL API失败时的备选方案）
 */
function parseUrlManually(urlStr: string): UrlParseResult | null {
  const match = urlStr.match(/^(https?):\/\/([^\/:]+)(?::\d+)?(\/.*)?$/)
  
  if (!match) {
    return null
  }
  
  return {
    protocol: match[1] || 'http',
    host: match[2] || '',  // 只取主机名，不含端口
    path: match[3] || '/'
  }
}

/**
 * 从URL中提取协议
 */
export function extractProtocol(urlStr: string): string {
  const match = urlStr.match(/^(https?):\/\//)
  return match && match[1] ? match[1] : 'http'
}

/**
 * 验证URL格式是否有效
 */
export function isValidUrl(urlStr: string): boolean {
  try {
    new URL(urlStr)
    return true
  } catch {
    return /^https?:\/\/[^\s]+$/.test(urlStr)
  }
}

/**
 * 构建完整URL
 */
export function buildUrl(protocol: string, host: string, path: string): string {
  const normalizedProtocol = protocol.replace(/:$/, '')
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  return `${normalizedProtocol}://${host}${normalizedPath}`
}
