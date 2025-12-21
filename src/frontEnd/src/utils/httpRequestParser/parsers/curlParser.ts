/**
 * HTTP请求解析器 - cURL格式解析模块
 * 
 * 支持解析 cURL (bash) 和 cURL (cmd/Windows) 两种格式
 */

import { parse as parseCurlLib } from '@scrape-do/curl-parser'
import { parseUrl } from '../urlParser'
import type { ParsedHttpRequest } from '../types'

/**
 * 从 cURL 命令中提取 body 内容
 * 支持 -d, --data, --data-raw, --data-binary, --data-urlencode 等参数
 */
function extractBody(input: string): string {
  // 匹配各种 data 参数格式
  // 优先匹配双引号包围的内容（需要处理内部引号）
  const patterns = [
    /(?:-d|--data|--data-raw|--data-binary|--data-urlencode)\s+"((?:[^"\\]|\\.)*)"/,
    /(?:-d|--data|--data-raw|--data-binary|--data-urlencode)\s+'([^']*)'/,
  ]
  
  for (const pattern of patterns) {
    const match = input.match(pattern)
    if (match && match[1]) {
      let body: string = match[1]
      // 处理转义字符: \" => " (bash 双引号内的转义引号)
      body = body.replace(/\\"/g, '"')
      // 处理其他常见转义: \\\\ => \\
      body = body.replace(/\\\\/g, '\\')
      return body
    }
  }
    
  // 如果上面的模式都不匹配，尝试更宽松的匹配
  // 匹配从 data 参数开始到下一个参数或结尾
  const looseMatch = input.match(/(?:-d|--data|--data-raw)\s+"([\s\S]*?)"(?:\s+-|\s*$)/)
  if (looseMatch && looseMatch[1]) {
    let body: string = looseMatch[1]
    body = body.replace(/\\"/g, '"')
    body = body.replace(/\\\\/g, '\\')
    return body
  }
  
  return ''
}

/**
 * 使用 @scrape-do/curl-parser 库解析 cURL 命令
 * 
 * 注意：库在解析包含引号的 body 时有 bug，需要自己重新提取 body
 */
function parseCurlWithLib(normalizedInput: string): ParsedHttpRequest | null {
  try {
    const result = parseCurlLib(normalizedInput)
    
    if (!result || !result.url) {
      return null
    }
    
    // 转换 headers 数组为对象格式
    const headers: Record<string, string> = {}
    if (result.headers && Array.isArray(result.headers)) {
      for (const h of result.headers) {
        if (h.key && h.value !== undefined) {
          headers[h.key] = h.value
        }
      }
    }
    
    const method = (result.method || 'GET').toUpperCase()
    
    // 库在解析包含引号的 body 时有 bug，需要自己重新提取
    const body = extractBody(normalizedInput)
    
    const { host, path, protocol } = parseUrl(result.url)
    
    return {
      method,
      url: result.url,
      host,
      path,
      headers,
      body,
      protocol
    }
  } catch (e) {
    console.error('Parse cURL with library error:', e)
    return null
  }
}

/**
 * 解析 cURL (bash) 格式
 * 
 * @param input - cURL bash格式命令字符串
 * @returns 解析后的HTTP请求，失败返回null
 * 
 * @example
 * parseCurlBash("curl -X POST 'https://api.example.com/users' \\
 *   -H 'Content-Type: application/json' \\
 *   -d '{\"name\": \"test\"}'")
 */
export function parseCurlBash(input: string): ParsedHttpRequest | null {
  try {
    // 处理 bash 续行符 \ + 换行
    const normalized = input.replace(/\\\s*\n\s*/g, ' ').trim()
    return parseCurlWithLib(normalized)
  } catch (e) {
    console.error('Parse cURL bash error:', e)
    return null
  }
}

/**
 * 解析 cURL (cmd) 格式 - Windows命令行
 * 
 * Windows CMD 特殊字符处理:
 * - ^" 表示双引号
 * - ^ 后跟换行是续行符
 * - ^\^" 表示嵌套的转义引号 (在header值中的引号)
 * - ^{ ^} ^, 等表示转义的特殊字符
 * 
 * @param input - cURL Windows CMD格式命令字符串
 * @returns 解析后的HTTP请求，失败返回null
 */
export function parseCurlCmd(input: string): ParsedHttpRequest | null {
  try {
    // Step 1: 处理Windows续行符 ^ + 换行
    let normalized = input.replace(/\^\s*\r?\n\s*/g, ' ').trim()
    
    // Step 2: 处理嵌套的转义引号 ^\^" => 占位符
    // 在Windows CMD中, ^\^" 表示内嵌的引号（JSON值中的引号）
    // 使用占位符保护这些引号，确保 extractBody 能正确匹配
    const NESTED_QUOTE_PLACEHOLDER = '\x00Q\x00'
    normalized = normalized.replace(/\^\\\^"/g, NESTED_QUOTE_PLACEHOLDER)
    
    // Step 3: 处理 ^" => 普通双引号
    normalized = normalized.replace(/\^"/g, '"')
    
    // Step 4: 处理其他转义字符 ^X => X
    // Windows CMD 中 ^ 用于转义特殊字符如 { } , : 等
    normalized = normalized.replace(/\^([{},:;\[\]\\<>|&!])/g, '$1')
    
    // Step 5: 处理剩余的 ^^ => ^ (转义的脱字符本身)
    normalized = normalized.replace(/\^\^/g, '^')
    
    // 使用库解析标准化后的 cURL 命令
    const result = parseCurlWithLib(normalized)
    
    if (result) {
      // Step 6: 恢复占位符为实际的引号字符
      const restorePlaceholder = (str: string) => 
        str.replace(new RegExp(NESTED_QUOTE_PLACEHOLDER, 'g'), '"')
      
      if (result.body) {
        result.body = restorePlaceholder(result.body)
      }
      
      // 也需要恢复 headers 中的占位符（如 sec-ch-ua 等）
      for (const key of Object.keys(result.headers)) {
        const headerValue = result.headers[key]
        if (headerValue) {
          result.headers[key] = restorePlaceholder(headerValue)
        }
      }
      
      // 如果有 body 但方法是 GET，自动改为 POST
      if (result.body && result.method === 'GET') {
        result.method = 'POST'
      }
    }
    
    return result
  } catch (e) {
    console.error('Parse cURL cmd error:', e)
    return null
  }
}
