import hljs from 'highlight.js'

/**
 * 格式化HTTP请求报文
 */
export function formatHttpRequest(httpInfo: any, task: any): string {
  if (!httpInfo && !task) {
    return ''
  }

  const lines: string[] = []

  // 1. 请求行: METHOD URL HTTP/Version
  const method = httpInfo?.method || 'GET'
  const url = task?.scanUrl || '/'
  const protocol = 'HTTP/1.1' // 默认HTTP/1.1，可以根据需要调整

  try {
    // 提取URL的path部分
    const urlObj = new URL(url)
    const path = urlObj.pathname + urlObj.search
    lines.push(`${method.toUpperCase()} ${path} ${protocol}`)

    // 2. Host头（如果URL包含域名）
    lines.push(`Host: ${urlObj.host}`)
  } catch (e) {
    // 如果URL解析失败，直接使用原始URL
    lines.push(`${method.toUpperCase()} ${url} ${protocol}`)
  }

  // 3. 其他请求头 (优先使用httpInfo.headers，其次是task.headers)
  const headers = httpInfo?.headers || task?.headers
  if (headers && Array.isArray(headers)) {
    headers.forEach((header: string) => {
      lines.push(header)
    })
  }

  // 4. 内容长度头（如果有请求体）
  // 重要：只使用 httpInfo.body，不回退到 task.body
  // 因为后端API已经返回了正确的body信息，task.body可能来自其他数据源
  const body = (httpInfo?.body !== undefined && httpInfo?.body !== null && httpInfo?.body !== '') 
    ? httpInfo.body 
    : null  // 不再回退到 task.body
  if (body) {
    const contentLength = new TextEncoder().encode(body).length
    lines.push(`Content-Length: ${contentLength}`)
  }

  // 5. 空行（HTTP规范：头和体之间必须有空行）
  lines.push('')

  // 6. 请求体
  if (body) {
    lines.push(body)
  }

  return lines.join('\n')
}

/**
 * 高亮选项接口
 */
interface HighlightOptions {
  useRegex?: boolean
  caseSensitive?: boolean
}

/**
 * 高亮HTTP报文
 * @param lines HTTP报文的每一行
 * @param searchKeyword 搜索关键词（用于高亮匹配）
 * @param options 高亮选项
 * @returns HTML字符串
 */
export function highlightHttpRequest(lines: string[], searchKeyword?: string, options?: HighlightOptions): string {
  let html = ''
  let isBody = false // 标记是否进入请求体
  
  const useRegex = options?.useRegex ?? false
  const caseSensitive = options?.caseSensitive ?? false

  lines.forEach((line, index) => {
    const lineNumber = index + 1

    // 检测是否为空行（请求体和请求头的分隔）
    if (line.trim() === '') {
      isBody = true
    }

    // 高亮处理
    let highlightedLine = escapeHtml(line)

    // 1. HTTP请求行高亮 (METHOD URL VERSION)
    if (index === 0 && /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP\/\d+\.\d+$/i.test(line)) {
      const parts = line.split(' ')
      if (parts.length >= 3) {
        const method = parts[0] || ''
        const url = parts.slice(1, -1).join(' ') || ''
        const version = parts[parts.length - 1] || ''

        // 根据HTTP方法的安全性/危险程度标记颜色
        // GET/HEAD/OPTIONS: 绿色（只读，安全）
        // POST/PUT/PATCH: 橙色（写入，有影响）
        // DELETE: 红色（危险，删除数据）
        let methodBgColor = '#10b981' // 默认绿色（安全）
        let methodBorderColor = '#059669'
        
        const upperMethod = method.toUpperCase()
        if (['POST', 'PUT', 'PATCH'].includes(upperMethod)) {
          // 写入方法 - 橙色
          methodBgColor = '#f59e0b'
          methodBorderColor = '#d97706'
        } else if (upperMethod === 'DELETE') {
          // 删除方法 - 红色
          methodBgColor = '#ef4444'
          methodBorderColor = '#dc2626'
        } else {
          // GET/HEAD/OPTIONS等只读方法 - 绿色
          methodBgColor = '#10b981'
          methodBorderColor = '#059669'
        }
        
        // 请求方法、PATH、版本字体大小一致，都使用 inherit 继承父元素的22px
        highlightedLine = `<span style="background-color:${methodBgColor} !important; color:#ffffff !important; font-weight:bold !important; padding:4px 10px !important; border-radius:6px !important; font-size:inherit !important; display:inline-block !important; margin-right:10px !important; border:1px solid ${methodBorderColor} !important; vertical-align:middle !important;">${escapeHtml(method)}</span>` +
          `<span style="color:#34d399 !important; text-decoration:underline !important; font-weight:600 !important; font-size:inherit !important;">${escapeHtml(url)}</span>` +
          ` <span style="color:#06b6d4 !important; font-weight:600 !important; font-size:inherit !important;">${escapeHtml(version)}</span>`
      }
    } else if (!isBody) {
      // 2. HTTP头高亮
      const headerMatch = line.match(/^([^:]+):\s*(.*)$/)
      if (headerMatch) {
        const headerName = headerMatch[1] || ''
        const headerValue = headerMatch[2] || ''
        highlightedLine = `<span style="color:#06b6d4 !important; font-weight:600 !important;">${escapeHtml(headerName)}</span>` +
          `: <span style="color:#e2e8f0 !important;">${escapeHtml(headerValue)}</span>`
      }
    } else {
      // 3. 请求体高亮（根据内容类型使用不同高亮）
      // 尝试使用highlight.js高亮JSON/XML等格式
      if (line.trim()) {
        try {
          // 如果看起来像JSON，高亮JSON
          if (line.includes('{') || line.includes('[')) {
            highlightedLine = hljs.highlight(line, { language: 'json', ignoreIllegals: true }).value
          } else {
            // 普通文本保持原样
            highlightedLine = escapeHtml(line)
          }
        } catch (e) {
          highlightedLine = escapeHtml(line)
        }
      }
    }

    // 4. 搜索关键词高亮
    if (searchKeyword) {
      let shouldHighlight = false
      let regex: RegExp | null = null
      
      try {
        if (useRegex) {
          const flags = caseSensitive ? 'g' : 'gi'
          regex = new RegExp(`(${searchKeyword})`, flags)
          shouldHighlight = regex.test(line)
          // 重置regex的lastIndex
          regex.lastIndex = 0
        } else {
          if (caseSensitive) {
            shouldHighlight = line.includes(searchKeyword)
            regex = new RegExp(`(${escapeRegExp(searchKeyword)})`, 'g')
          } else {
            shouldHighlight = line.toLowerCase().includes(searchKeyword.toLowerCase())
            regex = new RegExp(`(${escapeRegExp(searchKeyword)})`, 'gi')
          }
        }
        
        if (shouldHighlight && regex) {
          // 在已经高亮的基础上，再添加黄色背景的关键字高亮
          highlightedLine = highlightedLine.replace(regex, (match) => {
            return `<span style="background-color:#fbbf24 !important; color:#000000 !important; font-weight:bold !important; padding:0 2px !important; border-radius:3px !important; box-shadow:0 2px 4px rgba(251, 191, 36, 0.4);">${match}</span>`
          })
        }
      } catch (e) {
        // 正则表达式错误，忽略高亮
      }
    }

    // 构建行HTML - 22px大字体，极小的行间距
    const even = index % 2 === 0
    const backgroundColor = even ? 'rgba(15, 23, 42, 0.3)' : 'rgba(15, 23, 42, 0.5)'

    html += `<div style="display:flex; align-items:flex-start; margin:0; white-space:pre; background:${backgroundColor}; line-height:0.9;">
      <span style="flex-shrink:0; width:60px; text-align:right; padding:4px 12px; color:#94a3b8; background-color:rgba(15, 23, 42, 0.7); border-right:1px solid rgba(148, 163, 184, 0.2); font-family:'Monaco','Menlo','Ubuntu Mono',monospace; font-size:14px; line-height:0.9; user-select:none; font-weight:600;">${String(lineNumber).padStart(3, ' ')}</span>
      <span style="flex:1; padding:4px 16px; white-space:pre-wrap; word-break:break-word; color:#e2e8f0; font-family:'Monaco','Menlo','Ubuntu Mono',monospace; font-size:22px; line-height:0.9;">${highlightedLine}</span>
    </div>`
  })

  return html
}

/**
 * 过滤HTTP报文
 * @param lines 原始HTTP报文行
 * @param keyword 搜索关键词
 * @returns 过滤后的行
 */
export function filterHttpRequest(lines: string[], keyword: string): string[] {
  if (!keyword.trim()) {
    return lines
  }

  const lowerKeyword = keyword.toLowerCase()
  return lines.filter(line => line.toLowerCase().includes(lowerKeyword))
}

/**
 * 转义HTML特殊字符
 */
function escapeHtml(text: string): string {
  if (!text) {
    return ''
  }
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
 * 转义正则表达式特殊字符
 */
function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
