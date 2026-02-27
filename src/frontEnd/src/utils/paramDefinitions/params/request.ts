/**
 * Request 请求参数定义
 */
import type { ParamDefinition } from '../types'
import { AUTH_TYPE_OPTIONS, METHOD_OPTIONS, PROXY_TYPE_OPTIONS } from '../types'

export const REQUEST_PARAMS: ParamDefinition[] = [
  // HTTP 方法和数据
  {
    key: 'method',
    cliName: '--method',
    name: 'Method',
    description: '强制使用指定的 HTTP 方法',
    category: 'request',
    type: 'select',
    options: METHOD_OPTIONS
  },
  {
    key: 'data',
    cliName: '--data',
    name: 'Data',
    description: 'POST 数据',
    category: 'request',
    type: 'string',
    placeholder: 'id=1&name=test'
  },
  {
    key: 'paramDel',
    cliName: '--param-del',
    name: 'Param Delimiter',
    description: '参数值分隔符',
    category: 'request',
    type: 'string',
    placeholder: '&',
    advanced: true
  },

  // Headers
  {
    key: 'agent',
    cliName: '-A',
    name: 'User-Agent',
    description: 'HTTP User-Agent 头值',
    category: 'request',
    type: 'string'
  },
  {
    key: 'header',
    cliName: '-H',
    name: 'Header',
    description: '额外的 HTTP 头',
    category: 'request',
    type: 'string',
    placeholder: 'X-Forwarded-For: 127.0.0.1'
  },
  {
    key: 'headers',
    cliName: '--headers',
    name: 'Headers',
    description: '额外的多个 HTTP 头',
    category: 'request',
    type: 'textarea',
    placeholder: 'Accept-Language: fr\\nETag: 123'
  },
  {
    key: 'host',
    cliName: '--host',
    name: 'Host',
    description: 'HTTP Host 头值',
    category: 'request',
    type: 'string'
  },
  {
    key: 'referer',
    cliName: '--referer',
    name: 'Referer',
    description: 'HTTP Referer 头值',
    category: 'request',
    type: 'string'
  },
  {
    key: 'randomAgent',
    cliName: '--random-agent',
    name: 'Random Agent',
    description: '使用随机的 HTTP User-Agent 头',
    category: 'request',
    type: 'boolean'
  },
  {
    key: 'mobile',
    cliName: '--mobile',
    name: 'Mobile',
    description: '模拟智能手机 User-Agent',
    category: 'request',
    type: 'boolean'
  },

  // Cookie
  {
    key: 'cookie',
    cliName: '--cookie',
    name: 'Cookie',
    description: 'HTTP Cookie 头值',
    category: 'request',
    type: 'string',
    placeholder: 'PHPSESSID=a8d127e..'
  },
  {
    key: 'cookieDel',
    cliName: '--cookie-del',
    name: 'Cookie Delimiter',
    description: 'Cookie 值分隔符',
    category: 'request',
    type: 'string',
    placeholder: ';',
    advanced: true
  },
  {
    key: 'liveCookies',
    cliName: '--live-cookies',
    name: 'Live Cookies',
    description: '动态 Cookie 文件',
    category: 'request',
    type: 'string',
    advanced: true
  },
  {
    key: 'loadCookies',
    cliName: '--load-cookies',
    name: 'Load Cookies',
    description: '加载 Netscape/wget 格式的 Cookie 文件',
    category: 'request',
    type: 'string',
    advanced: true
  },
  {
    key: 'dropSetCookie',
    cliName: '--drop-set-cookie',
    name: 'Drop Set-Cookie',
    description: '忽略响应中的 Set-Cookie 头',
    category: 'request',
    type: 'boolean',
    advanced: true
  },

  // HTTP 版本
  {
    key: 'http10',
    cliName: '--http1.0',
    name: 'HTTP 1.0',
    description: '使用 HTTP 1.0 版本',
    category: 'request',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'http2',
    cliName: '--http2',
    name: 'HTTP 2',
    description: '使用 HTTP 2 版本 (实验性)',
    category: 'request',
    type: 'boolean',
    advanced: true
  },

  // 认证
  {
    key: 'authType',
    cliName: '--auth-type',
    name: 'Auth Type',
    description: 'HTTP 认证类型',
    category: 'request',
    type: 'select',
    options: AUTH_TYPE_OPTIONS
  },
  {
    key: 'authCred',
    cliName: '--auth-cred',
    name: 'Auth Credentials',
    description: 'HTTP 认证凭据 (name:password)',
    category: 'request',
    type: 'string',
    placeholder: 'user:pass'
  },
  {
    key: 'authFile',
    cliName: '--auth-file',
    name: 'Auth File',
    description: 'HTTP 认证 PEM 证书/私钥文件',
    category: 'request',
    type: 'string',
    advanced: true
  },

  // HTTP 错误码处理
  {
    key: 'abortCode',
    cliName: '--abort-code',
    name: 'Abort Code',
    description: '遇到指定 HTTP 错误码时中止',
    category: 'request',
    type: 'string',
    placeholder: '401',
    advanced: true
  },
  {
    key: 'ignoreCode',
    cliName: '--ignore-code',
    name: 'Ignore Code',
    description: '忽略指定的 HTTP 错误码',
    category: 'request',
    type: 'string',
    placeholder: '401',
    advanced: true
  },
  {
    key: 'ignoreProxy',
    cliName: '--ignore-proxy',
    name: 'Ignore Proxy',
    description: '忽略系统默认代理设置',
    category: 'request',
    type: 'boolean'
  },
  {
    key: 'ignoreRedirects',
    cliName: '--ignore-redirects',
    name: 'Ignore Redirects',
    description: '忽略重定向尝试',
    category: 'request',
    type: 'boolean'
  },
  {
    key: 'ignoreTimeouts',
    cliName: '--ignore-timeouts',
    name: 'Ignore Timeouts',
    description: '忽略连接超时',
    category: 'request',
    type: 'boolean'
  },

  // 代理
  {
    key: 'proxy',
    cliName: '--proxy',
    name: 'Proxy',
    description: '使用代理连接目标 URL',
    category: 'request',
    type: 'string',
    placeholder: 'http://127.0.0.1:8080'
  },
  {
    key: 'proxyCred',
    cliName: '--proxy-cred',
    name: 'Proxy Credentials',
    description: '代理认证凭据 (name:password)',
    category: 'request',
    type: 'string',
    placeholder: 'user:pass'
  },
  {
    key: 'proxyFile',
    cliName: '--proxy-file',
    name: 'Proxy File',
    description: '从文件加载代理列表',
    category: 'request',
    type: 'string',
    advanced: true
  },
  {
    key: 'proxyFreq',
    cliName: '--proxy-freq',
    name: 'Proxy Frequency',
    description: '代理轮换频率（请求数）',
    category: 'request',
    type: 'integer',
    min: 0,
    advanced: true
  },

  // Tor
  {
    key: 'tor',
    cliName: '--tor',
    name: 'Tor',
    description: '使用 Tor 匿名网络',
    category: 'request',
    type: 'boolean'
  },
  {
    key: 'torPort',
    cliName: '--tor-port',
    name: 'Tor Port',
    description: 'Tor 代理端口',
    category: 'request',
    type: 'integer',
    min: 1,
    max: 65535,
    advanced: true
  },
  {
    key: 'torType',
    cliName: '--tor-type',
    name: 'Tor Type',
    description: 'Tor 代理类型',
    category: 'request',
    type: 'select',
    options: PROXY_TYPE_OPTIONS,
    advanced: true
  },
  {
    key: 'checkTor',
    cliName: '--check-tor',
    name: 'Check Tor',
    description: '检查 Tor 是否正确使用',
    category: 'request',
    type: 'boolean',
    advanced: true
  },

  // 请求时间控制
  {
    key: 'delay',
    cliName: '--delay',
    name: 'Delay',
    description: '每个 HTTP 请求之间的延迟秒数',
    category: 'request',
    type: 'float',
    min: 0,
    max: 60
  },
  {
    key: 'timeout',
    cliName: '--timeout',
    name: 'Timeout',
    description: '连接超时秒数',
    category: 'request',
    type: 'integer',
    defaultValue: 30,
    min: 1,
    max: 300
  },
  {
    key: 'retries',
    cliName: '--retries',
    name: 'Retries',
    description: '连接超时重试次数',
    category: 'request',
    type: 'integer',
    defaultValue: 3,
    min: 0,
    max: 10
  },
  {
    key: 'retryOn',
    cliName: '--retry-on',
    name: 'Retry On',
    description: '匹配正则内容时重试请求',
    category: 'request',
    type: 'string',
    placeholder: 'drop',
    advanced: true
  },

  // 参数随机化
  {
    key: 'randomize',
    cliName: '--randomize',
    name: 'Randomize',
    description: '随机化指定参数的值',
    category: 'request',
    type: 'string',
    placeholder: 'id,token',
    advanced: true
  },

  // Safe URL
  {
    key: 'safeUrl',
    cliName: '--safe-url',
    name: 'Safe URL',
    description: '测试期间频繁访问的安全 URL',
    category: 'request',
    type: 'string',
    advanced: true
  },
  {
    key: 'safePost',
    cliName: '--safe-post',
    name: 'Safe POST',
    description: '发送到安全 URL 的 POST 数据',
    category: 'request',
    type: 'string',
    advanced: true
  },
  {
    key: 'safeReq',
    cliName: '--safe-req',
    name: 'Safe Request',
    description: '从文件加载安全 HTTP 请求',
    category: 'request',
    type: 'string',
    advanced: true
  },
  {
    key: 'safeFreq',
    cliName: '--safe-freq',
    name: 'Safe Frequency',
    description: '访问安全 URL 之间的请求数',
    category: 'request',
    type: 'integer',
    min: 0,
    advanced: true
  },

  // URL 编码
  {
    key: 'skipUrlEncode',
    cliName: '--skip-urlencode',
    name: 'Skip URL Encode',
    description: '跳过 payload 数据的 URL 编码',
    category: 'request',
    type: 'boolean'
  },

  // CSRF
  {
    key: 'csrfToken',
    cliName: '--csrf-token',
    name: 'CSRF Token',
    description: '持有 CSRF token 的参数',
    category: 'request',
    type: 'string',
    placeholder: '_token'
  },
  {
    key: 'csrfUrl',
    cliName: '--csrf-url',
    name: 'CSRF URL',
    description: '提取 CSRF token 的 URL',
    category: 'request',
    type: 'string'
  },
  {
    key: 'csrfMethod',
    cliName: '--csrf-method',
    name: 'CSRF Method',
    description: '访问 CSRF token 页面的 HTTP 方法',
    category: 'request',
    type: 'select',
    options: METHOD_OPTIONS,
    advanced: true
  },
  {
    key: 'csrfData',
    cliName: '--csrf-data',
    name: 'CSRF Data',
    description: '获取 CSRF token 时发送的 POST 数据',
    category: 'request',
    type: 'string',
    advanced: true
  },
  {
    key: 'csrfRetries',
    cliName: '--csrf-retries',
    name: 'CSRF Retries',
    description: 'CSRF token 获取重试次数',
    category: 'request',
    type: 'integer',
    defaultValue: 0,
    min: 0,
    max: 10,
    advanced: true
  },

  // 其他请求选项
  {
    key: 'forceSSL',
    cliName: '--force-ssl',
    name: 'Force SSL',
    description: '强制使用 SSL/HTTPS',
    category: 'request',
    type: 'boolean'
  },
  {
    key: 'chunked',
    cliName: '--chunked',
    name: 'Chunked',
    description: '使用 HTTP chunked 传输编码 (POST)',
    category: 'request',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'hpp',
    cliName: '--hpp',
    name: 'HPP',
    description: '使用 HTTP 参数污染方法',
    category: 'request',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'evalCode',
    cliName: '--eval',
    name: 'Eval Code',
    description: '请求前执行的 Python 代码',
    category: 'request',
    type: 'textarea',
    placeholder: 'import hashlib;id2=hashlib.md5(id).hexdigest()',
    advanced: true
  }
]
