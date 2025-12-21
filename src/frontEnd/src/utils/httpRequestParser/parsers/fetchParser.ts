/**
 * HTTP请求解析器 - Fetch格式解析模块
 * 
 * 支持解析浏览器fetch API和Node.js fetch格式
 * 
 * 特殊处理：
 * - JavaScript字符串中的转义引号 \"
 * - 嵌套的JSON对象
 * - 多行格式
 */

import { parseUrl } from '../urlParser'
import type { ParsedHttpRequest } from '../types'

/**
 * 从fetch调用中提取URL
 */
function extractUrl(input: string): string {
  // 支持双引号和单引号
  const urlMatch = input.match(/fetch\s*\(\s*(['"])((?:(?!\1)[^\\]|\\.)*)\1/i)
  return urlMatch && urlMatch[2] ? urlMatch[2] : ''
}

/**
 * 匹配JavaScript字符串（处理转义引号）
 * 返回匹配的字符串内容（不含引号）
 */
function matchJsString(str: string, startIndex: number): { value: string; endIndex: number } | null {
  if (startIndex >= str.length) return null
  
  const quoteChar = str[startIndex]
  if (quoteChar !== '"' && quoteChar !== "'") return null
  
  let i = startIndex + 1
  let value = ''
  
  while (i < str.length) {
    const char = str[i]
    
    if (char === '\\' && i + 1 < str.length) {
      // 处理转义字符
      const nextChar = str[i + 1]
      if (nextChar === '"' || nextChar === "'" || nextChar === '\\') {
        value += nextChar
        i += 2
        continue
      } else if (nextChar === 'n') {
        value += '\n'
        i += 2
        continue
      } else if (nextChar === 'r') {
        value += '\r'
        i += 2
        continue
      } else if (nextChar === 't') {
        value += '\t'
        i += 2
        continue
      }
      // 其他转义保持原样
      value += char
      i++
    } else if (char === quoteChar) {
      // 找到结束引号
      return { value, endIndex: i }
    } else {
      value += char
      i++
    }
  }
  
  return null // 未找到结束引号
}

/**
 * 查找匹配的大括号位置
 */
function findMatchingBrace(str: string, startIndex: number): number {
  let depth = 0
  let inString = false
  let stringChar = ''
  
  for (let i = startIndex; i < str.length; i++) {
    const char = str[i]
    
    if (inString) {
      if (char === '\\' && i + 1 < str.length) {
        i++ // 跳过转义字符
        continue
      }
      if (char === stringChar) {
        inString = false
      }
    } else {
      if (char === '"' || char === "'") {
        inString = true
        stringChar = char
      } else if (char === '{') {
        depth++
      } else if (char === '}') {
        depth--
        if (depth === 0) {
          return i
        }
      }
    }
  }
  
  return -1
}

/**
 * 从fetch options对象中提取method
 */
function extractMethod(optionsStr: string): string {
  // 匹配 "method": "POST" 或 method: "POST"
  const methodMatch = optionsStr.match(/['"]?method['"]?\s*:\s*['"](\w+)['"]/i)
  return methodMatch && methodMatch[1] ? methodMatch[1].toUpperCase() : 'GET'
}

/**
 * 从fetch options对象中提取headers
 * 正确处理包含转义引号的header值
 */
function extractHeaders(optionsStr: string): Record<string, string> {
  const headers: Record<string, string> = {}
  
  // 找到 headers: { 的位置
  const headersStartMatch = optionsStr.match(/['"]?headers['"]?\s*:\s*\{/)
  if (!headersStartMatch || headersStartMatch.index === undefined) {
    return headers
  }
  
  const braceStart = headersStartMatch.index + headersStartMatch[0].length - 1
  const braceEnd = findMatchingBrace(optionsStr, braceStart)
  
  if (braceEnd === -1) {
    return headers
  }
  
  // 提取headers对象内容
  const headersContent = optionsStr.substring(braceStart + 1, braceEnd)
  
  // 解析每个 key: value 对
  let i = 0
  while (i < headersContent.length) {
    // 跳过空白和逗号
    let currentChar = headersContent.charAt(i)
    while (i < headersContent.length && /[\s,]/.test(currentChar)) {
      i++
      currentChar = headersContent.charAt(i)
    }
    
    if (i >= headersContent.length) break
    
    // 查找key
    const keyResult = matchJsString(headersContent, i)
    if (!keyResult) {
      // 尝试匹配不带引号的key
      const unquotedKeyMatch = headersContent.substring(i).match(/^(\w+)\s*:/)
      if (unquotedKeyMatch && unquotedKeyMatch[1]) {
        const unquotedKey = unquotedKeyMatch[1]
        i += unquotedKeyMatch[0].length
        // 跳过空白
        currentChar = headersContent.charAt(i)
        while (i < headersContent.length && /\s/.test(currentChar)) {
          i++
          currentChar = headersContent.charAt(i)
        }
        const valueResult = matchJsString(headersContent, i)
        if (valueResult) {
          headers[unquotedKey] = valueResult.value
          i = valueResult.endIndex + 1
        }
      } else {
        i++
      }
      continue
    }
    
    const key = keyResult.value
    i = keyResult.endIndex + 1
    
    // 跳过 : 和空白
    currentChar = headersContent.charAt(i)
    while (i < headersContent.length && /[\s:]/.test(currentChar)) {
      i++
      currentChar = headersContent.charAt(i)
    }
    
    // 查找value
    const valueResult = matchJsString(headersContent, i)
    if (valueResult) {
      headers[key] = valueResult.value
      i = valueResult.endIndex + 1
    } else {
      i++
    }
  }
  
  return headers
}

/**
 * 从fetch options对象中提取body
 * 正确处理包含转义引号的body
 */
function extractBody(optionsStr: string): string {
  // 找到 body: 的位置
  const bodyMatch = optionsStr.match(/['"]?body['"]?\s*:\s*/)
  if (!bodyMatch || bodyMatch.index === undefined) {
    return ''
  }
  
  const valueStart = bodyMatch.index + bodyMatch[0].length
  
  // 检查是否是 JSON.stringify
  const jsonStringifyMatch = optionsStr.substring(valueStart).match(/^JSON\.stringify\s*\(/)
  if (jsonStringifyMatch) {
    // 找到匹配的括号
    const parenStart = valueStart + jsonStringifyMatch[0].length - 1
    let depth = 1
    let i = parenStart + 1
    
    while (i < optionsStr.length && depth > 0) {
      const char = optionsStr[i]
      if (char === '(') depth++
      else if (char === ')') depth--
      i++
    }
    
    if (depth === 0) {
      let content = optionsStr.substring(parenStart + 1, i - 1).trim()
      // 将单引号转换为双引号
      content = content.replace(/'/g, '"')
      return content
    }
  }
  
  // 尝试匹配字符串值
  const valueResult = matchJsString(optionsStr, valueStart)
  if (valueResult) {
    return valueResult.value
  }
  
  return ''
}

/**
 * 从fetch调用中提取options对象
 */
function extractOptions(input: string): string | null {
  // 找到第一个参数后的逗号位置
  const fetchMatch = input.match(/fetch\s*\(\s*(['"])((?:(?!\1)[^\\]|\\.)*)\1\s*,\s*/)
  if (!fetchMatch || fetchMatch.index === undefined) {
    return null
  }
  
  const optionsStart = fetchMatch.index + fetchMatch[0].length
  
  // 找到 { 的位置
  const bracePos = input.indexOf('{', optionsStart)
  if (bracePos === -1) {
    return null
  }
  
  const braceEnd = findMatchingBrace(input, bracePos)
  if (braceEnd === -1) {
    return null
  }
  
  return input.substring(bracePos, braceEnd + 1)
}

/**
 * 解析 fetch (JavaScript) 格式
 * 
 * 支持浏览器fetch API格式，正确处理转义引号
 * 
 * @param input - fetch调用代码字符串
 * @returns 解析后的HTTP请求，失败返回null
 * 
 * @example
 * parseFetch(`fetch("https://api.example.com/users", {
 *   "headers": {
 *     "content-type": "application/json",
 *     "sec-ch-ua": "\"Chromium\";v=\"138\""
 *   },
 *   "body": "{\"name\":\"test\"}",
 *   "method": "POST"
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
