/**
 * HTTP请求报文解析器 - 主入口模块
 * 
 * 支持从Chrome DevTools复制的多种格式转换为标准HTTP报文
 * 
 * 支持的格式：
 * - cURL (cmd) - Windows命令行格式
 * - cURL (bash) - Linux/Mac命令行格式
 * - PowerShell (Invoke-WebRequest) - PowerShell格式
 * - fetch (JavaScript) - 浏览器fetch API格式
 * - fetch (Node.js) - Node.js fetch格式
 * - 原始HTTP报文
 * 
 * @example
 * import { parseHttpRequest, detectFormat, toRawHttpRequest } from '@/utils/httpRequestParser'
 * 
 * const result = parseHttpRequest(curlCommand)
 * if (result.success) {
 *   console.log(result.rawHttp)  // 格式化后的HTTP报文
 *   console.log(result.format)   // 检测到的格式类型
 * }
 */

// ============ 类型导出 ============
export type { 
  ParsedHttpRequest, 
  ParseResult, 
  RequestFormat,
  ParserFunction 
} from './types'

export { FORMAT_DISPLAY_NAMES } from './types'

// ============ 格式检测 ============
export { 
  detectFormat, 
  isKnownFormat, 
  isCurlFormat, 
  isFetchFormat 
} from './formatDetector'

// ============ URL工具 ============
export { 
  parseUrl, 
  extractProtocol, 
  isValidUrl, 
  buildUrl 
} from './urlParser'

export type { UrlParseResult } from './urlParser'

// ============ 解析器 ============
export { 
  parseCurlBash, 
  parseCurlCmd, 
  parsePowerShell, 
  parseFetch, 
  parseFetchNodejs, 
  parseRawHttp, 
  isValidRawHttp 
} from './parsers'

// ============ 格式化器 ============
export { 
  toRawHttpRequest, 
  getFormatDisplayName, 
  extractRequestFromRawHttp,
  formatHeadersToArray,
  parseHeadersFromArray
} from './formatters/httpFormatter'

// ============ 主解析函数 ============
import type { ParseResult, ParsedHttpRequest } from './types'
import { detectFormat } from './formatDetector'
import { parseCurlBash, parseCurlCmd, parsePowerShell, parseFetch, parseRawHttp } from './parsers'
import { toRawHttpRequest } from './formatters/httpFormatter'

/**
 * 主解析函数 - 自动检测格式并解析
 * 
 * 这是最常用的入口函数，会自动检测输入格式并选择合适的解析器
 * 
 * @param input - 输入文本（支持多种格式）
 * @returns 解析结果，包含成功标志、解析数据、原始HTTP报文等
 * 
 * @example
 * // 解析cURL命令
 * const result = parseHttpRequest(`curl -X POST 'https://api.example.com' -d '{"key":"value"}'`)
 * if (result.success) {
 *   console.log(result.data.method)  // 'POST'
 *   console.log(result.data.url)     // 'https://api.example.com'
 *   console.log(result.rawHttp)      // 格式化的HTTP报文
 * }
 * 
 * @example
 * // 解析PowerShell命令
 * const result = parseHttpRequest(`Invoke-WebRequest -Uri "https://api.example.com" -Method POST`)
 * 
 * @example
 * // 解析fetch调用
 * const result = parseHttpRequest(`fetch('https://api.example.com', { method: 'GET' })`)
 */
export function parseHttpRequest(input: string): ParseResult {
  // 输入验证
  if (!input || typeof input !== 'string' || !input.trim()) {
    return { 
      success: false, 
      error: '输入内容为空' 
    }
  }
  
  // 检测格式
  const format = detectFormat(input)
  let parsed: ParsedHttpRequest | null = null
  
  // 根据格式选择解析器
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
      // 未知格式时，尝试作为cURL解析（最常见的格式）
      parsed = parseCurlBash(input)
      if (!parsed) {
        return { 
          success: false, 
          error: '无法识别的请求格式，请使用 cURL、PowerShell、fetch 或原始 HTTP 报文格式',
          format 
        }
      }
  }
  
  // 解析失败
  if (!parsed) {
    return { 
      success: false, 
      error: '解析失败，请检查输入格式是否正确', 
      format 
    }
  }
  
  // 解析成功
  return {
    success: true,
    data: parsed,
    rawHttp: toRawHttpRequest(parsed),
    format
  }
}
