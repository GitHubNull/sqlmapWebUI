/**
 * HTTP请求解析器 - HTTP格式化模块
 * 
 * 提供将解析结果转换为各种格式的功能
 */

import type { ParsedHttpRequest, RequestFormat } from '../types'
import { FORMAT_DISPLAY_NAMES } from '../types'
import { parseRawHttp } from '../parsers/rawHttpParser'

/**
 * 将解析后的请求转换为原始HTTP报文格式
 * 
 * @param request - 解析后的HTTP请求对象
 * @returns 格式化的HTTP报文字符串
 * 
 * @example
 * toRawHttpRequest({
 *   method: 'POST',
 *   url: 'https://example.com/api',
 *   host: 'example.com',
 *   path: '/api',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: '{"name":"test"}',
 *   protocol: 'https'
 * })
 * // => 'POST /api HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"name":"test"}'
 */
export function toRawHttpRequest(request: ParsedHttpRequest): string {
  const lines: string[] = []
  
  // 请求行
  lines.push(`${request.method} ${request.path} HTTP/1.1`)
  
  // 确保Host头存在
  const headers = { ...request.headers }
  if (!headers['Host'] && !headers['host']) {
    headers['Host'] = request.host
  }
  
  // Headers
  for (const [name, value] of Object.entries(headers)) {
    lines.push(`${name}: ${value}`)
  }
  
  // 空行分隔
  lines.push('')
  
  // Body
  if (request.body) {
    lines.push(request.body)
  }
  
  return lines.join('\n')
}

/**
 * 获取格式的显示名称
 * 
 * @param format - 请求格式类型
 * @returns 格式的中文显示名称
 */
export function getFormatDisplayName(format: RequestFormat): string {
  return FORMAT_DISPLAY_NAMES[format] || '未知格式'
}

/**
 * 从原始HTTP报文中提取请求信息用于提交
 * 
 * 将HTTP报文转换为与后端API兼容的格式
 * 
 * @param rawHttp - 原始HTTP报文字符串
 * @returns 提取的请求信息，失败返回null
 */
export function extractRequestFromRawHttp(rawHttp: string): {
  url: string
  host: string
  headers: string[]
  body: string
  method: string
} | null {
  const parsed = parseRawHttp(rawHttp)
  if (!parsed) {
    return null
  }
  
  // 转换headers为数组格式（与后端API兼容）
  const headersArray: string[] = []
  for (const [name, value] of Object.entries(parsed.headers)) {
    headersArray.push(`${name}: ${value}`)
  }
  
  return {
    url: parsed.url,
    host: parsed.host,
    headers: headersArray,
    body: parsed.body,
    method: parsed.method
  }
}

/**
 * 格式化Headers对象为字符串数组
 */
export function formatHeadersToArray(headers: Record<string, string>): string[] {
  return Object.entries(headers).map(([name, value]) => `${name}: ${value}`)
}

/**
 * 将字符串数组格式的Headers转换为对象
 */
export function parseHeadersFromArray(headersArray: string[]): Record<string, string> {
  const headers: Record<string, string> = {}
  
  for (const header of headersArray) {
    const colonIndex = header.indexOf(':')
    if (colonIndex > 0) {
      const name = header.substring(0, colonIndex).trim()
      const value = header.substring(colonIndex + 1).trim()
      if (name) {
        headers[name] = value
      }
    }
  }
  
  return headers
}
