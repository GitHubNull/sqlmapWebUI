/**
 * HTTP请求解析器 - Fetch格式解析模块
 * 
 * 支持解析浏览器fetch API和Node.js fetch格式
 */

import { parseUrl } from '../urlParser'
import type { ParsedHttpRequest } from '../types'

/**
 * 从fetch调用中提取URL
 */
function extractUrl(input: string): string {
  const urlMatch = input.match(/fetch\s*\(\s*['"]([^'"]+)['"]/i)
  return urlMatch && urlMatch[1] ? urlMatch[1] : ''
}

/**
 * 从fetch options对象中提取method
 */
function extractMethod(optionsStr: string): string {
  const methodMatch = optionsStr.match(/['"]?method['"]?\s*:\s*['"](\w+)['"]/i)
  return methodMatch && methodMatch[1] ? methodMatch[1].toUpperCase() : 'GET'
}

/**
 * 从fetch options对象中提取headers
 */
function extractHeaders(optionsStr: string): Record<string, string> {
  const headers: Record<string, string> = {}
  
  const headersMatch = optionsStr.match(/['"]?headers['"]?\s*:\s*(\{[^}]+\})/i)
  if (!headersMatch || !headersMatch[1]) {
    return headers
  }
  
  const headersStr = headersMatch[1]
  
  // 解析 "key": "value" 格式
  const headerPairs = headersStr.match(/['"]([^'"]+)['"]\s*:\s*['"]([^'"]+)['"]/g)
  if (headerPairs) {
    for (const pair of headerPairs) {
      const pairMatch = pair.match(/['"]([^'"]+)['"]\s*:\s*['"]([^'"]+)['"]/)
      if (pairMatch && pairMatch[1] && pairMatch[2]) {
        headers[pairMatch[1]] = pairMatch[2]
      }
    }
  }
  
  return headers
}

/**
 * 从fetch options对象中提取body
 */
function extractBody(optionsStr: string): string {
  // 尝试匹配直接字符串body
  const stringBodyMatch = optionsStr.match(/['"]?body['"]?\s*:\s*['"]([^'"]+)['"]/i)
  if (stringBodyMatch && stringBodyMatch[1]) {
    return stringBodyMatch[1]
  }
  
  // 尝试匹配JSON.stringify格式
  const jsonBodyMatch = optionsStr.match(/['"]?body['"]?\s*:\s*JSON\.stringify\s*\(([^)]+)\)/i)
  if (jsonBodyMatch && jsonBodyMatch[1]) {
    let body = jsonBodyMatch[1]
    // 简单清理：将单引号转换为双引号
    body = body.replace(/'/g, '"')
    return body
  }
  
  return ''
}

/**
 * 从fetch调用中提取options对象
 */
function extractOptions(input: string): string | null {
  const optionsMatch = input.match(/fetch\s*\([^,]+,\s*(\{[\s\S]*?\})\s*\)/)
  return optionsMatch && optionsMatch[1] ? optionsMatch[1] : null
}

/**
 * 解析 fetch (JavaScript) 格式
 * 
 * 支持浏览器fetch API格式
 * 
 * @param input - fetch调用代码字符串
 * @returns 解析后的HTTP请求，失败返回null
 * 
 * @example
 * parseFetch(`fetch('https://api.example.com/users', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: JSON.stringify({ name: 'test' })
 * })`)
 */
export function parseFetch(input: string): ParsedHttpRequest | null {
  try {
    // 提取URL
    const url = extractUrl(input)
    if (!url) {
      return null
    }
    
    // 默认值
    let method = 'GET'
    let headers: Record<string, string> = {}
    let body = ''
    
    // 尝试提取第二个参数（options对象）
    const optionsStr = extractOptions(input)
    if (optionsStr) {
      method = extractMethod(optionsStr)
      headers = extractHeaders(optionsStr)
      body = extractBody(optionsStr)
    }
    
    const { host, path, protocol } = parseUrl(url)
    
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
    console.error('Parse fetch error:', e)
    return null
  }
}

/**
 * 解析 fetch (Node.js) 格式
 * 
 * 与浏览器fetch格式相同，仅用于区分来源
 * 
 * @param input - Node.js fetch调用代码字符串
 * @returns 解析后的HTTP请求，失败返回null
 */
export function parseFetchNodejs(input: string): ParsedHttpRequest | null {
  // Node.js fetch 格式与浏览器相同
  return parseFetch(input)
}
