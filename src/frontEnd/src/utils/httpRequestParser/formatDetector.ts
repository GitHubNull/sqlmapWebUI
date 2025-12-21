/**
 * HTTP请求解析器 - 格式检测模块
 * 
 * 自动检测输入文本的请求格式类型
 */

import type { RequestFormat } from './types'

/**
 * 格式检测规则配置
 * 使用优先级排序，先匹配的优先
 */
interface FormatRule {
  format: RequestFormat
  patterns: RegExp[]
  /** 额外的区分规则 */
  discriminator?: (input: string) => RequestFormat | null
}

/**
 * 格式检测规则列表
 */
const FORMAT_RULES: FormatRule[] = [
  // 原始HTTP报文格式 - 最先检测
  {
    format: 'raw_http',
    patterns: [
      /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/[\d.]+/i
    ]
  },
  // cURL格式 - 需要区分cmd和bash
  {
    format: 'curl_bash',
    patterns: [/^curl\s/i],
    discriminator: (input) => {
      // cmd格式使用 ^ 作为续行符，或使用特定的双引号模式
      if (input.includes('^') || /curl\s+"[^"]*"/i.test(input)) {
        return 'curl_cmd'
      }
      return 'curl_bash'
    }
  },
  // PowerShell格式
  {
    format: 'powershell',
    patterns: [
      /^Invoke-WebRequest/i,
      /^Invoke-RestMethod/i,
      /^\$session\s*=\s*New-Object/i,
      /^iwr\s/i
    ]
  },
  // fetch格式 - 需要区分js和nodejs
  {
    format: 'fetch_js',
    patterns: [/^fetch\s*\(/i],
    discriminator: (input) => {
      // Node.js fetch 通常有 require 或 import
      if (
        /require\s*\(\s*['"]node-fetch['"]\s*\)/i.test(input) ||
        /import\s+.*from\s+['"]node-fetch['"]/i.test(input)
      ) {
        return 'fetch_nodejs'
      }
      return 'fetch_js'
    }
  }
]

/**
 * 检测输入的格式类型
 * 
 * @param input - 输入文本
 * @returns 检测到的格式类型
 * 
 * @example
 * detectFormat('curl -X POST https://example.com')
 * // => 'curl_bash'
 * 
 * detectFormat('GET /api HTTP/1.1\nHost: example.com')
 * // => 'raw_http'
 */
export function detectFormat(input: string): RequestFormat {
  if (!input || typeof input !== 'string') {
    return 'unknown'
  }
  
  const trimmed = input.trim()
  
  if (!trimmed) {
    return 'unknown'
  }
  
  // 遍历规则进行匹配
  for (const rule of FORMAT_RULES) {
    const matched = rule.patterns.some(pattern => pattern.test(trimmed))
    
    if (matched) {
      // 如果有区分规则，使用区分规则
      if (rule.discriminator) {
        const discriminatedFormat = rule.discriminator(trimmed)
        if (discriminatedFormat) {
          return discriminatedFormat
        }
      }
      return rule.format
    }
  }
  
  return 'unknown'
}

/**
 * 检查是否为已知格式
 */
export function isKnownFormat(format: RequestFormat): boolean {
  return format !== 'unknown'
}

/**
 * 检查是否为cURL格式（包括cmd和bash）
 */
export function isCurlFormat(format: RequestFormat): boolean {
  return format === 'curl_bash' || format === 'curl_cmd'
}

/**
 * 检查是否为fetch格式（包括js和nodejs）
 */
export function isFetchFormat(format: RequestFormat): boolean {
  return format === 'fetch_js' || format === 'fetch_nodejs'
}
