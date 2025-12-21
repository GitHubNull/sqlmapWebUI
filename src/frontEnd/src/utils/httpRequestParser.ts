/**
 * HTTP请求报文解析器
 * 支持从Chrome DevTools复制的多种格式转换为标准HTTP报文
 * 
 * 支持的格式：
 * - cURL (cmd) - Windows命令行格式
 * - cURL (bash) - Linux/Mac命令行格式
 * - PowerShell (Invoke-WebRequest) - PowerShell格式
 * - fetch (JavaScript) - 浏览器fetch API格式
 * - fetch (Node.js) - Node.js fetch格式
 */

// 使用 @scrape-do/curl-parser 库解析 cURL 命令
import { parse as parseCurlLib } from '@scrape-do/curl-parser'

export interface ParsedHttpRequest {
  method: string
  url: string
  host: string
  path: string
  headers: Record<string, string>
  body: string
  protocol: string  // http 或 https
}

export interface ParseResult {
  success: boolean
  data?: ParsedHttpRequest
  rawHttp?: string  // 转换后的原始HTTP报文
  error?: string
  format?: RequestFormat
}

export type RequestFormat = 'curl_cmd' | 'curl_bash' | 'powershell' | 'fetch_js' | 'fetch_nodejs' | 'raw_http' | 'unknown'

/**
 * 检测输入的格式类型
 */
export function detectFormat(input: string): RequestFormat {
  const trimmed = input.trim()
  
  // 检测原始HTTP报文格式 (以 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS 开头)
  if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/[\d.]+/i.test(trimmed)) {
    return 'raw_http'
  }
  
  // 检测 cURL 格式
  if (/^curl\s/i.test(trimmed)) {
    // 区分 cmd 和 bash 格式
    // cmd格式使用 ^ 作为续行符，或使用双引号
    // bash格式使用 \ 作为续行符，或使用单引号
    if (trimmed.includes('^') || /curl\s+"[^"]*"/i.test(trimmed)) {
      return 'curl_cmd'
    }
    return 'curl_bash'
  }
  
  // 检测 PowerShell 格式
  if (/^Invoke-WebRequest/i.test(trimmed) || /^Invoke-RestMethod/i.test(trimmed) || 
      /^\$session\s*=\s*New-Object/i.test(trimmed) || /^iwr\s/i.test(trimmed)) {
    return 'powershell'
  }
  
  // 检测 fetch 格式
  if (/^fetch\s*\(/i.test(trimmed)) {
    // Node.js fetch 通常有 require 或 import
    if (/require\s*\(\s*['"]node-fetch['"]\s*\)/i.test(trimmed) || 
        /import\s+.*from\s+['"]node-fetch['"]/i.test(trimmed)) {
      return 'fetch_nodejs'
    }
    return 'fetch_js'
  }
  
  return 'unknown'
}

/**
 * 解析URL，提取host、path等信息
 */
function parseUrl(urlStr: string): { host: string; path: string; protocol: string } {
  try {
    const url = new URL(urlStr)
    const path = url.pathname + url.search + url.hash
    return {
      host: url.host,
      path: path || '/',
      protocol: url.protocol.replace(':', '')
    }
  } catch {
    // 如果URL解析失败，尝试手动提取
    const match = urlStr.match(/^(https?):\/\/([^\/]+)(\/.*)?$/)
    if (match) {
      return {
        host: match[2] || '',
        path: match[3] || '/',
        protocol: match[1] || 'http'
      }
    }
    return { host: '', path: '/', protocol: 'http' }
  }
}

/**
 * 使用 @scrape-do/curl-parser 库解析 cURL 命令
 * 该库支持浏览器环境，无 WASM 依赖
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
    let body = extractBody(normalizedInput)
    
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
 * 从 cURL 命令中提取 body 内容
 * 支持 -d, --data, --data-raw 等参数
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
 * 解析 cURL (bash) 格式
 * 先处理续行符，然后使用库解析
 */
function parseCurlBash(input: string): ParsedHttpRequest | null {
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
 */
function parseCurlCmd(input: string): ParsedHttpRequest | null {
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
      const restorePlaceholder = (str: string) => str.replace(new RegExp(NESTED_QUOTE_PLACEHOLDER, 'g'), '"')
      
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

/**
 * 解析 PowerShell 格式
 */
function parsePowerShell(input: string): ParsedHttpRequest | null {
  try {
    let normalized = input.replace(/`\s*\n\s*/g, ' ').trim()
    
    // 提取URL
    let url = ''
    const urlMatch = normalized.match(/(?:Invoke-WebRequest|Invoke-RestMethod|iwr)\s+(?:-Uri\s+)?['"]?(https?:\/\/[^\s'"]+)['"]?/i)
    if (urlMatch && urlMatch[1]) {
      url = urlMatch[1]
    }
        
    // 提取方法
    let method = 'GET'
    const methodMatch = normalized.match(/-Method\s+['"]?(\w+)['"]?/i)
    if (methodMatch && methodMatch[1]) {
      method = methodMatch[1].toUpperCase()
    }
        
    // 提取Headers - PowerShell使用 @{ } 语法
    const headers: Record<string, string> = {}
    const headersMatch = normalized.match(/-Headers\s+@\{([^}]+)\}/i)
    if (headersMatch && headersMatch[1]) {
      const headerBlock = headersMatch[1]
      // 解析 "Name"="Value" 或 'Name'='Value' 格式
      const headerPairs = headerBlock.match(/['"]([^'"]+)['"]\s*=\s*['"]([^'"]+)['"]/g)
      if (headerPairs) {
        headerPairs.forEach(pair => {
          const pairMatch = pair.match(/['"]([^'"]+)['"]\s*=\s*['"]([^'"]+)['"]/) 
          if (pairMatch && pairMatch[1] && pairMatch[2]) {
            headers[pairMatch[1]] = pairMatch[2]
          }
        })
      }
    }
        
    // 提取Body
    let body = ''
    const bodyMatch = normalized.match(/-Body\s+['"]([^'"]+)['"]/i) ||
                      normalized.match(/-Body\s+@['"]([^'"]+)['"]/i)
    if (bodyMatch && bodyMatch[1]) {
      body = bodyMatch[1]
      if (!methodMatch) {
        method = 'POST'
      }
    }
    
    if (!url) {
      return null
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
    console.error('Parse PowerShell error:', e)
    return null
  }
}

/**
 * 解析 fetch (JavaScript) 格式
 */
function parseFetch(input: string): ParsedHttpRequest | null {
  try {
    // 提取URL
    let url = ''
    const urlMatch = input.match(/fetch\s*\(\s*['"]([^'"]+)['"]/i)
    if (urlMatch && urlMatch[1]) {
      url = urlMatch[1]
    }
    
    // 提取options对象
    let method = 'GET'
    const headers: Record<string, string> = {}
    let body = ''
    
    // 尝试提取第二个参数（options对象）
    const optionsMatch = input.match(/fetch\s*\([^,]+,\s*(\{[\s\S]*?\})\s*\)/)
    if (optionsMatch && optionsMatch[1]) {
      const optionsStr = optionsMatch[1]
      
      // 提取method
      const methodMatch = optionsStr.match(/['"]?method['"]?\s*:\s*['"](\w+)['"]/i)
      if (methodMatch && methodMatch[1]) {
        method = methodMatch[1].toUpperCase()
      }
      
      // 提取headers
      const headersMatch = optionsStr.match(/['"]?headers['"]?\s*:\s*(\{[^}]+\})/i)
      if (headersMatch && headersMatch[1]) {
        const headersStr = headersMatch[1]
        // 解析 "key": "value" 格式
        const headerPairs = headersStr.match(/['"]([^'"]+)['"]\s*:\s*['"]([^'"]+)['"]/g)
        if (headerPairs) {
          headerPairs.forEach(pair => {
            const pairMatch = pair.match(/['"]([^'"]+)['"]\s*:\s*['"]([^'"]+)['"]/) 
            if (pairMatch && pairMatch[1] && pairMatch[2]) {
              headers[pairMatch[1]] = pairMatch[2]
            }
          })
        }
      }
      
      // 提取body
      const fetchBodyMatch = optionsStr.match(/['"]?body['"]?\s*:\s*['"]([^'"]+)['"]/i) ||
                        optionsStr.match(/['"]?body['"]?\s*:\s*JSON\.stringify\s*\(([^)]+)\)/i)
      if (fetchBodyMatch && fetchBodyMatch[1]) {
        body = fetchBodyMatch[1]
        // 如果是JSON.stringify的内容，尝试格式化
        if (optionsStr.includes('JSON.stringify')) {
          try {
            // 简单清理
            body = body.replace(/'/g, '"')
          } catch {
            // 保持原样
          }
        }
      }
    }
    
    if (!url) {
      return null
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
 * 解析原始HTTP报文格式
 */
function parseRawHttp(input: string): ParsedHttpRequest | null {
  try {
    const lines = input.split(/\r?\n/)
    if (lines.length === 0) return null
    
    // 解析请求行
    const firstLine = lines[0]
    if (!firstLine) return null
    const requestLine = firstLine.trim()
    const requestMatch = requestLine.match(/^(\w+)\s+(\S+)\s+HTTP\/[\d.]+$/i)
    if (!requestMatch || !requestMatch[1] || !requestMatch[2]) return null
    
    const method = requestMatch[1].toUpperCase()
    const path = requestMatch[2]
    
    // 解析Headers
    const headers: Record<string, string> = {}
    let bodyStartIndex = -1
    
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i]
      if (!line || line.trim() === '') {
        bodyStartIndex = i + 1
        break
      }
      const colonIndex = line.indexOf(':')
      if (colonIndex > 0) {
        const name = line.substring(0, colonIndex).trim()
        const value = line.substring(colonIndex + 1).trim()
        headers[name] = value
      }
    }
    
    // 提取Body
    let body = ''
    if (bodyStartIndex > 0 && bodyStartIndex < lines.length) {
      body = lines.slice(bodyStartIndex).join('\n')
    }
    
    // 从Host header提取host
    const host = headers['Host'] || headers['host'] || ''
    const protocol = 'http'  // 默认http，无法从原始报文中确定
    const url = `${protocol}://${host}${path}`
    
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
 * 将解析后的请求转换为原始HTTP报文格式
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
 * 主解析函数 - 自动检测格式并解析
 */
export function parseHttpRequest(input: string): ParseResult {
  if (!input || !input.trim()) {
    return { success: false, error: '输入内容为空' }
  }
  
  const format = detectFormat(input)
  let parsed: ParsedHttpRequest | null = null
  
  switch (format) {
    case 'curl_bash':
      parsed = parseCurlBash(input)
      break
    case 'curl_cmd':
      parsed = parseCurlCmd(input)
      break
    case 'powershell':
      parsed = parsePowerShell(input)
      break
    case 'fetch_js':
    case 'fetch_nodejs':
      parsed = parseFetch(input)
      break
    case 'raw_http':
      parsed = parseRawHttp(input)
      break
    default:
      // 尝试作为cURL解析
      parsed = parseCurlBash(input)
      if (!parsed) {
        return { success: false, error: '无法识别的请求格式，请使用 cURL、PowerShell、fetch 或原始 HTTP 报文格式' }
      }
  }
  
  if (!parsed) {
    return { success: false, error: '解析失败，请检查输入格式是否正确', format }
  }
  
  return {
    success: true,
    data: parsed,
    rawHttp: toRawHttpRequest(parsed),
    format
  }
}

/**
 * 获取格式的显示名称
 */
export function getFormatDisplayName(format: RequestFormat): string {
  const names: Record<RequestFormat, string> = {
    'curl_cmd': 'cURL (Windows CMD)',
    'curl_bash': 'cURL (Bash)',
    'powershell': 'PowerShell',
    'fetch_js': 'fetch (JavaScript)',
    'fetch_nodejs': 'fetch (Node.js)',
    'raw_http': '原始 HTTP 报文',
    'unknown': '未知格式'
  }
  return names[format] || '未知格式'
}

/**
 * 从原始HTTP报文中提取请求信息用于提交
 */
export function extractRequestFromRawHttp(rawHttp: string): {
  url: string
  host: string
  headers: string[]
  body: string
  method: string
} | null {
  const parsed = parseRawHttp(rawHttp)
  if (!parsed) return null
  
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
