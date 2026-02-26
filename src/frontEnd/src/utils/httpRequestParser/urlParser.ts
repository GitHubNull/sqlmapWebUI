/**
 * HTTP请求解析器 - URL解析工具模块
 * 
 * 提供URL解析相关的工具函数
 */

export interface UrlParseResult {
  /** 主机名（不含端口） */
  host: string
  /** 主机名（含端口，如存在非默认端口） */
  hostWithPort: string
  /** 端口号 */
  port: string
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
  const defaultResult: UrlParseResult = { host: '', hostWithPort: '', port: '', path: '/', protocol: 'http' }
  
  if (!urlStr || typeof urlStr !== 'string') {
    return defaultResult
  }
  
  try {
    // 优先使用原生URL API
    const url = new URL(urlStr)
    const path = url.pathname + url.search + url.hash
    
    // 判断是否为默认端口
    const isDefaultPort = (url.protocol === 'http:' && url.port === '80') ||
                          (url.protocol === 'https:' && url.port === '443')
    
    return {
      host: url.hostname,
      hostWithPort: isDefaultPort ? url.hostname : (url.host || url.hostname),
      port: url.port || (url.protocol === 'https:' ? '443' : '80'),
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
  const match = urlStr.match(/^(https?):\/\/([^\/:]+)(?::(\d+))?(\/.*)?$/)
  
  if (!match) {
    return null
  }
  
  const protocol = match[1] || 'http'
  const hostname = match[2] || ''
  const port = match[3]
  const path = match[4] || '/'
  
  // 判断是否为默认端口
  const isDefaultPort = (protocol === 'http' && port === '80') ||
                        (protocol === 'https' && port === '443')
  
  const hostWithPort = port && !isDefaultPort ? `${hostname}:${port}` : hostname
  
  return {
    protocol,
    host: hostname,
    hostWithPort,
    port: port || (protocol === 'https' ? '443' : '80'),
    path
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
