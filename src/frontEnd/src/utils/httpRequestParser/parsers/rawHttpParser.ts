/**
 * HTTP请求解析器 - 原始HTTP报文解析模块
 * 
 * 支持解析标准HTTP/1.1请求报文格式
 */

import type { ParsedHttpRequest } from '../types'

/**
 * HTTP请求方法列表
 */
const HTTP_METHODS = [
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 
  'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'
]

/**
 * 验证HTTP方法是否有效
 */
function isValidMethod(method: string): boolean {
  return HTTP_METHODS.includes(method.toUpperCase())
}

/**
 * 解析请求行
 * 格式: METHOD PATH HTTP/VERSION
 */
function parseRequestLine(line: string): { method: string; path: string } | null {
  const match = line.trim().match(/^(\w+)\s+(\S+)\s+HTTP\/[\d.]+$/i)
  
  if (!match || !match[1] || !match[2]) {
    return null
  }
  
  const method = match[1].toUpperCase()
  if (!isValidMethod(method)) {
    return null
  }
  
  return {
    method,
    path: match[2]
  }
}

/**
 * 解析HTTP头部
 * 格式: Name: Value
 */
function parseHeaders(lines: string[], startIndex: number): {
  headers: Record<string, string>
  bodyStartIndex: number
} {
  const headers: Record<string, string> = {}
  let bodyStartIndex = -1
  
  for (let i = startIndex; i < lines.length; i++) {
    const line = lines[i]
    
    // 空行表示头部结束，body开始
    if (!line || line.trim() === '') {
      bodyStartIndex = i + 1
      break
    }
    
    // 解析 Header: Value 格式
    const colonIndex = line.indexOf(':')
    if (colonIndex > 0) {
      const name = line.substring(0, colonIndex).trim()
      const value = line.substring(colonIndex + 1).trim()
      
      if (name) {
        headers[name] = value
      }
    }
  }
  
  return { headers, bodyStartIndex }
}

/**
 * 从headers中提取Host
 */
function extractHost(headers: Record<string, string>): string {
  return headers['Host'] || headers['host'] || ''
}

/**
 * 解析原始HTTP报文格式
 * 
 * @param input - 原始HTTP报文字符串
 * @returns 解析后的HTTP请求，失败返回null
 * 
 * @example
 * parseRawHttp(`GET /api/users?id=1 HTTP/1.1
 * Host: example.com
 * Content-Type: application/json
 * 
 * {"name": "test"}`)
 */
export function parseRawHttp(input: string): ParsedHttpRequest | null {
  try {
    if (!input || typeof input !== 'string') {
      return null
    }
    
    // 按行分割（支持 \r\n 和 \n）
    const lines = input.split(/\r?\n/)
    
    if (lines.length === 0 || !lines[0]) {
      return null
    }
    
    // 解析请求行
    const requestLine = parseRequestLine(lines[0])
    if (!requestLine) {
      return null
    }
    
    const { method, path } = requestLine
    
    // 解析Headers
    const { headers, bodyStartIndex } = parseHeaders(lines, 1)
    
    // 提取Body
    let body = ''
    if (bodyStartIndex > 0 && bodyStartIndex < lines.length) {
      body = lines.slice(bodyStartIndex).join('\n')
    }
    
    // 从Host header提取host
    const host = extractHost(headers)
    
    // 协议默认http（无法从原始报文中确定）
    const protocol = 'http'
    
    // 构建URL
    const url = host ? `${protocol}://${host}${path}` : path
    
    return {
      method,
      url,
      host,
      path,
      headers,
      body,
      protocol
    }
  } catch (e) {
    console.error('Parse raw HTTP error:', e)
    return null
  }
}

/**
 * 验证输入是否为有效的原始HTTP报文格式
 */
export function isValidRawHttp(input: string): boolean {
  if (!input || typeof input !== 'string') {
    return false
  }
  
  const firstLine = input.split(/\r?\n/)[0]
  if (!firstLine) {
    return false
  }
  
  return /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/[\d.]+$/i.test(firstLine.trim())
}
