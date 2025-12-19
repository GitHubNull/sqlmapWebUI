import hljs from 'highlight.js'
import type { HLJSApi } from 'highlight.js'

// HTML转义函数
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }
  return text.replace(/[&<>"']/g, (m: string) => map[m] as string)
}

/**
 * 注册自定义日志语法高亮
 */
export function registerLogLanguage(): void {
  // 检查是否已经注册
  if (hljs.getLanguage('log')) {
    return
  }

  hljs.registerLanguage('log', (hljs: HLJSApi) => {
    const SQL_KEYWORDS = [
      'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'AND', 'OR',
      'ORDER BY', 'GROUP BY', 'HAVING', 'LIMIT', 'JOIN', 'INNER JOIN',
      'LEFT JOIN', 'RIGHT JOIN', 'ON', 'AS', 'LIKE', 'IN', 'NOT IN',
      'IS NULL', 'IS NOT NULL', 'COUNT', 'SUM', 'AVG', 'MAX', 'MIN',
      'CREATE', 'TABLE', 'ALTER', 'DROP', 'INDEX', 'DATABASE', 'SCHEMA',
      'PRIMARY KEY', 'FOREIGN KEY', 'UNIQUE', 'NOT NULL', 'DEFAULT'
    ]

    return {
      name: 'Log',
      case_insensitive: true,
      contains: [
        // 日志级别
        {
          className: 'log-info',
          begin: /\[INFO\]/i,
          relevance: 10
        },
        {
          className: 'log-debug',
          begin: /\[DEBUG\]/i,
          relevance: 10
        },
        {
          className: 'log-warning',
          begin: /\[(WARNING|WARN)\]/i,
          relevance: 10
        },
        {
          className: 'log-error',
          begin: /\[(ERROR|CRITICAL|FATAL|EXCEPTION)\]/i,
          relevance: 15
        },
        {
          className: 'log-trace',
          begin: /\[TRACE\]/i,
          relevance: 5
        },
        // 时间戳 - 支持多种格式
        {
          className: 'timestamp',
          // 方括号包围的ISO 8601时间戳: [2025-12-19T10:30:45.123Z]
          begin: /\[\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\]/,
          relevance: 10
        },
        {
          className: 'timestamp',
          // 完整日期时间: 2025-12-19 10:30:45 或 2025/12/19 10:30:45
          begin: /\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/,
          relevance: 8
        },
        {
          className: 'timestamp',
          // 纯时间: 10:30:45 或 10:30:45.123
          begin: /\b\d{2}:\d{2}:\d{2}(\.\d+)?\b/,
          relevance: 5
        },
        // HTTP 方法
        {
          className: 'http-method',
          begin: /\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/i,
          relevance: 5
        },
        // URLs
        {
          className: 'url',
          begin: /https?:\/\/[^\s\)\]"'<>]+/,
          relevance: 10
        },
        // 文件路径
        {
          className: 'file-path',
          begin: /[\w\-./]+\.(py|js|ts|php|asp|aspx|jsp|java|cs|cpp|c|h|hpp|go|rb|json|xml|yml|yaml|ini|conf|config|log|txt)/i,
          relevance: 5
        },
        // IP 地址
        {
          className: 'ip-address',
          begin: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/,
          relevance: 5
        },
        // SQL 关键词
        {
          className: 'sql-keyword',
          begin: new RegExp(`\\b(${SQL_KEYWORDS.join('|')})\\b`, 'i'),
          relevance: 3
        },
        // 数字
        {
          className: 'number',
          begin: /\b\d+\.?\d*\b/,
          relevance: 0
        },
        // 引号字符串
        {
          className: 'string',
          begin: /"/,
          end: /"/,
          contains: [hljs.BACKSLASH_ESCAPE],
          relevance: 0
        },
        {
          className: 'string',
          begin: /'/,
          end: /'/,
          contains: [hljs.BACKSLASH_ESCAPE],
          relevance: 0
        },
        // JSON 格式
        {
          className: 'attr',
          begin: /[\w-]+(?=\s*:)/,
          relevance: 1
        }
      ]
    }
  })
}

/**
 * 使用 highlight.js 高亮日志内容
 */
export function highlightLogContent(logs: string[]): string {
  if (!logs || logs.length === 0) {
    return ''
  }

  // 确保日志语言已注册
  registerLogLanguage()

  const htmlLines: string[] = []

  logs.forEach((line, index) => {
    const lineNumber = index + 1

    // 使用 highlight.js 高亮当前行
    let highlightedLine: string
    try {
      highlightedLine = hljs.highlight(line, { language: 'log', ignoreIllegals: true }).value
    } catch (error) {
      // 如果高亮失败，使用原行
      highlightedLine = escapeHtml(line)
    }

    // 构建带有行号的 HTML
    const lineHtml = `<div class="log-line">
      <span class="line-number">${String(lineNumber).padStart(4, ' ')}</span>
      <span class="line-content">${highlightedLine}</span>
    </div>`

    htmlLines.push(lineHtml)
  })

  return `<div class="highlighted-logs">${htmlLines.join('')}</div>`
}

/**
 * 获取日志统计信息
 */
export interface LogStats {
  total: number
  info: number
  debug: number
  warning: number
  error: number
  critical: number
  trace: number
}

export function getLogStats(logs: string[]): LogStats {
  const stats: LogStats = {
    total: logs.length,
    info: 0,
    debug: 0,
    warning: 0,
    error: 0,
    critical: 0,
    trace: 0
  }

  logs.forEach(line => {
    const upperLine = line.toUpperCase()
    if (upperLine.includes('[INFO]')) stats.info++
    if (upperLine.includes('[DEBUG]')) stats.debug++
    if (upperLine.includes('[WARNING]') || upperLine.includes('[WARN]')) stats.warning++
    if (upperLine.includes('[ERROR]')) stats.error++
    if (upperLine.includes('[CRITICAL]') || upperLine.includes('[FATAL]')) stats.critical++
    if (upperLine.includes('[TRACE]')) stats.trace++
  })

  return stats
}

/**
 * 按等级过滤日志
 */
export function filterLogsByLevel(logs: string[], levels: string[]): string[] {
  const upperLevels = levels.map(l => l.toUpperCase())

  return logs.filter(line => {
    const upperLine = line.toUpperCase()
    return upperLevels.some(level => {
      // 处理 WARNING/WARN 的别名
      if (level === 'WARNING') {
        return upperLine.includes('[WARNING]') || upperLine.includes('[WARN]')
      }
      // 处理 ERROR/CRITICAL/FATAL 作为 error 级别
      if (level === 'ERROR') {
        return upperLine.includes('[ERROR]') ||
               upperLine.includes('[CRITICAL]') ||
               upperLine.includes('[FATAL]')
      }
      return upperLine.includes(`[${level}]`)
    })
  })
}

/**
 * 搜索日志
 */
export function searchLogs(logs: string[], query: string): { lineNumber: number, line: string }[] {
  if (!query) {
    return []
  }

  const results: { lineNumber: number, line: string }[] = []
  const lowerQuery = query.toLowerCase()

  logs.forEach((line, index) => {
    if (line.toLowerCase().includes(lowerQuery)) {
      results.push({
        lineNumber: index + 1,
        line
      })
    }
  })

  return results
}
