/**
 * HTTP请求解析器 - PowerShell格式解析模块
 * 
 * 支持解析 PowerShell 的 Invoke-WebRequest 和 Invoke-RestMethod 命令
 */

import { parseUrl } from '../urlParser'
import type { ParsedHttpRequest } from '../types'

/**
 * PowerShell转义字符处理
 * 
 * PowerShell 特殊字符:
 * - ` (反引号) 是转义字符
 * - `" 表示转义的双引号
 * - `n 表示换行符
 * - `r 表示回车符
 * - `t 表示制表符
 * - `` 表示反引号本身
 * - ` + 换行 是续行符
 * - @{ } 是哈希表语法
 */

/**
 * 处理PowerShell转义字符
 */
function unescapePowerShell(value: string): string {
  return value
    .replace(/`"/g, '"')   // `" => "
    .replace(/`n/g, '\n')  // `n => newline
    .replace(/`r/g, '\r')  // `r => carriage return
    .replace(/`t/g, '\t')  // `t => tab
    .replace(/``/g, '`')   // `` => `
}

/**
 * 从PowerShell命令中提取URL
 */
function extractUrl(normalized: string): string {
  const urlPatterns = [
    // -Uri "url" 格式（各种参数顺序）
    /(?:Invoke-WebRequest|Invoke-RestMethod|iwr)\s+(?:-[^U]\w+\s+[^-]+\s+)*-Uri\s+"([^"]+)"/i,
    /(?:Invoke-WebRequest|Invoke-RestMethod|iwr)\s+(?:-[^U]\w+\s+[^-]+\s+)*-Uri\s+'([^']+)'/i,
    /(?:Invoke-WebRequest|Invoke-RestMethod|iwr)\s+(?:-UseBasicParsing\s+)?-Uri\s+"([^"]+)"/i,
    // 直接跟URL的格式
    /(?:Invoke-WebRequest|Invoke-RestMethod|iwr)\s+"(https?:\/\/[^"]+)"/i,
    /(?:Invoke-WebRequest|Invoke-RestMethod|iwr)\s+'(https?:\/\/[^']+)'/i
  ]
  
  for (const pattern of urlPatterns) {
    const match = normalized.match(pattern)
    if (match && match[1]) {
      return match[1]
    }
  }
  
  return ''
}

/**
 * 从PowerShell命令中提取HTTP方法
 */
function extractMethod(normalized: string): { method: string; hasExplicitMethod: boolean } {
  const methodMatch = normalized.match(/-Method\s+['"]?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]?/i)
  
  if (methodMatch && methodMatch[1]) {
    const methodValue: string = methodMatch[1]
    return {
      method: methodValue.toUpperCase(),
      hasExplicitMethod: true
    }
  }
  
  return {
    method: 'GET',
    hasExplicitMethod: false
  }
}

/**
 * 从PowerShell命令中提取ContentType
 */
function extractContentType(normalized: string): string {
  const contentTypeMatch = normalized.match(/-ContentType\s+['"]([^'"]+)['"]/i)
  return contentTypeMatch && contentTypeMatch[1] ? contentTypeMatch[1] : ''
}

/**
 * 从PowerShell命令中提取Headers
 * 
 * PowerShell使用 @{ } 语法定义哈希表
 */
function extractHeaders(normalized: string): Record<string, string> {
  const headers: Record<string, string> = {}
  
  // 匹配 @{ 到 } 之间的内容，包括换行
  const headersMatch = normalized.match(/-Headers\s+@\{([\s\S]*?)\}(?=\s+-|\s*$)/i)
  
  if (!headersMatch || !headersMatch[1]) {
    return headers
  }
  
  const headerBlock = headersMatch[1]
  
  // 解析双引号格式: "Name"="Value"
  // PowerShell 中 `" 表示转义的双引号
  const doubleQuoteRegex = /['"]([^'"]+)['"]\s*=\s*"((?:[^"`]|`")*)"/g
  let match
  
  while ((match = doubleQuoteRegex.exec(headerBlock)) !== null) {
    if (match[1] && match[2] !== undefined) {
      headers[match[1]] = unescapePowerShell(match[2])
    }
  }
  
  // 解析单引号格式: 'Name'='Value'
  const singleQuoteRegex = /['"]([^'"]+)['"]\s*=\s*'([^']*)'/g
  
  while ((match = singleQuoteRegex.exec(headerBlock)) !== null) {
    if (match[1] && match[2] !== undefined && !headers[match[1]]) {
      headers[match[1]] = match[2]
    }
  }
  
  return headers
}

/**
 * 从PowerShell命令中提取Body
 */
function extractBody(normalized: string): string {
  // 匹配 -Body "content" 其中 content 可能包含 `" 转义
  const bodyPatterns = [
    /-Body\s+"((?:[^"`]|`["\\tnr])*)"/i,  // 双引号，处理 `" 转义
    /-Body\s+'([^']*)'/i,                  // 单引号
    /-Body\s+@"([\s\S]*?)"@/i              // Here-String
  ]
  
  for (const pattern of bodyPatterns) {
    const match = normalized.match(pattern)
    if (match && match[1] !== undefined) {
      return unescapePowerShell(match[1])
    }
  }
  
  return ''
}

/**
 * 解析 PowerShell 格式
 * 
 * 支持 Invoke-WebRequest, Invoke-RestMethod, iwr 命令
 * 
 * @param input - PowerShell命令字符串
 * @returns 解析后的HTTP请求，失败返回null
 * 
 * @example
 * parsePowerShell(`Invoke-WebRequest -Uri "https://api.example.com" \`
 *   -Method "POST" \`
 *   -Headers @{"Content-Type"="application/json"} \`
 *   -Body "{\`"name\`":\`"test\`"}"`)
 */
export function parsePowerShell(input: string): ParsedHttpRequest | null {
  try {
    // Step 1: 处理 PowerShell 续行符 (反引号 + 换行)
    const normalized = input.replace(/`\s*\r?\n\s*/g, ' ').trim()
    
    // Step 2: 提取URL
    const url = extractUrl(normalized)
    if (!url) {
      return null
    }
    
    // Step 3: 提取方法
    const { method, hasExplicitMethod } = extractMethod(normalized)
    
    // Step 4: 提取 ContentType
    const contentType = extractContentType(normalized)
    
    // Step 5: 提取 Headers
    const headers = extractHeaders(normalized)
    
    // 如果提取到了 ContentType，添加到 headers
    if (contentType && !headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = contentType
    }
    
    // Step 6: 提取 Body
    const body = extractBody(normalized)
    
    // 如果有 body 但没有明确指定方法，默认为 POST
    const finalMethod = (body && !hasExplicitMethod) ? 'POST' : method
    
    const { host, path, protocol } = parseUrl(url)
    
    return {
      method: finalMethod,
      url,
      host,
      path,
      headers,
      body,
      protocol
    }
  } catch (e) {
    console.error('Parse PowerShell error:', e)
    return null
  }
}
