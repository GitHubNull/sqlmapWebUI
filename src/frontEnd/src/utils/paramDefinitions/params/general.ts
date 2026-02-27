/**
 * General 通用参数定义
 */
import type { ParamDefinition } from '../types'
import { DUMP_FORMAT_OPTIONS } from '../types'

export const GENERAL_PARAMS: ParamDefinition[] = [
  // 会话管理
  {
    key: 'sessionFile',
    cliName: '-s',
    name: 'Session File',
    description: '从存储的 (.sqlite) 文件加载会话',
    category: 'general',
    type: 'string',
    advanced: true
  },
  {
    key: 'trafficFile',
    cliName: '-t',
    name: 'Traffic File',
    description: '将所有 HTTP 流量记录到文本文件',
    category: 'general',
    type: 'string',
    advanced: true
  },
  {
    key: 'flushSession',
    cliName: '--flush-session',
    name: 'Flush Session',
    description: '刷新当前目标的会话文件',
    category: 'general',
    type: 'boolean'
  },
  {
    key: 'freshQueries',
    cliName: '--fresh-queries',
    name: 'Fresh Queries',
    description: '忽略会话文件中存储的查询结果',
    category: 'general',
    type: 'boolean'
  },

  // 批处理和交互
  {
    key: 'batch',
    cliName: '--batch',
    name: 'Batch',
    description: '从不询问用户输入，使用默认行为',
    category: 'general',
    type: 'boolean',
    defaultValue: true,
    disabled: true,
    disabledReason: '此参数由后端自动添加'
  },
  {
    key: 'answers',
    cliName: '--answers',
    name: 'Answers',
    description: '预定义的回答',
    category: 'general',
    type: 'string',
    placeholder: 'quit=N,follow=N'
  },

  // 爬虫
  {
    key: 'crawlDepth',
    cliName: '--crawl',
    name: 'Crawl Depth',
    description: '从目标 URL 开始爬取网站的深度',
    category: 'general',
    type: 'integer',
    min: 0,
    max: 10
  },
  {
    key: 'crawlExclude',
    cliName: '--crawl-exclude',
    name: 'Crawl Exclude',
    description: '排除爬取页面的正则表达式',
    category: 'general',
    type: 'string',
    placeholder: 'logout',
    advanced: true
  },
  {
    key: 'forms',
    cliName: '--forms',
    name: 'Forms',
    description: '解析并测试目标 URL 上的表单',
    category: 'general',
    type: 'boolean'
  },

  // 输出控制
  {
    key: 'verbose',
    cliName: '-v',
    name: 'Verbose',
    description: '详细级别 (0-6)',
    category: 'general',
    type: 'integer',
    defaultValue: 1,
    min: 0,
    max: 6
  },
  {
    key: 'abortOnEmpty',
    cliName: '--abort-on-empty',
    name: 'Abort On Empty',
    description: '结果为空时中止数据获取',
    category: 'general',
    type: 'boolean',
    advanced: true
  },

  // 编码和格式
  {
    key: 'base64',
    cliName: '--base64',
    name: 'Base64',
    description: '包含 Base64 编码数据的参数',
    category: 'general',
    type: 'string',
    advanced: true
  },
  {
    key: 'base64Safe',
    cliName: '--base64-safe',
    name: 'Base64 Safe',
    description: '使用 URL 和文件名安全的 Base64 字母表 (RFC 4648)',
    category: 'general',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'binaryFields',
    cliName: '--binary-fields',
    name: 'Binary Fields',
    description: '具有二进制值的结果字段',
    category: 'general',
    type: 'string',
    placeholder: 'digest',
    advanced: true
  },
  {
    key: 'charset',
    cliName: '--charset',
    name: 'Charset',
    description: '盲注入字符集',
    category: 'general',
    type: 'string',
    placeholder: '0123456789abcdef',
    advanced: true
  },
  {
    key: 'encoding',
    cliName: '--encoding',
    name: 'Encoding',
    description: '用于数据获取的字符编码',
    category: 'general',
    type: 'string',
    placeholder: 'GBK',
    advanced: true
  },

  // 导出配置
  {
    key: 'csvDel',
    cliName: '--csv-del',
    name: 'CSV Delimiter',
    description: 'CSV 输出使用的分隔符',
    category: 'general',
    type: 'string',
    defaultValue: ',',
    advanced: true
  },
  {
    key: 'dumpFile',
    cliName: '--dump-file',
    name: 'Dump File',
    description: '将导出数据存储到自定义文件',
    category: 'general',
    type: 'string',
    advanced: true
  },
  {
    key: 'dumpFormat',
    cliName: '--dump-format',
    name: 'Dump Format',
    description: '导出数据的格式',
    category: 'general',
    type: 'select',
    options: DUMP_FORMAT_OPTIONS
  },
  {
    key: 'outputDir',
    cliName: '--output-dir',
    name: 'Output Directory',
    description: '自定义输出目录路径',
    category: 'general',
    type: 'string'
  },
  {
    key: 'harFile',
    cliName: '--har',
    name: 'HAR File',
    description: '将所有 HTTP 流量记录到 HAR 文件',
    category: 'general',
    type: 'string',
    advanced: true
  },

  // 检测控制
  {
    key: 'checkInternet',
    cliName: '--check-internet',
    name: 'Check Internet',
    description: '评估目标前检查 Internet 连接',
    category: 'general',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'cleanup',
    cliName: '--cleanup',
    name: 'Cleanup',
    description: '从 DBMS 清除 sqlmap 特定的 UDF 和表',
    category: 'general',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'skipHeuristics',
    cliName: '--skip-heuristics',
    name: 'Skip Heuristics',
    description: '跳过漏洞启发式检测',
    category: 'general',
    type: 'boolean'
  },
  {
    key: 'skipWaf',
    cliName: '--skip-waf',
    name: 'Skip WAF',
    description: '跳过 WAF/IPS 保护的启发式检测',
    category: 'general',
    type: 'boolean'
  },

  // 处理脚本
  {
    key: 'preprocess',
    cliName: '--preprocess',
    name: 'Preprocess',
    description: '用于预处理（请求）的脚本',
    category: 'general',
    type: 'string',
    advanced: true
  },
  {
    key: 'postprocess',
    cliName: '--postprocess',
    name: 'Postprocess',
    description: '用于后处理（响应）的脚本',
    category: 'general',
    type: 'string',
    advanced: true
  },

  // 其他通用选项
  {
    key: 'eta',
    cliName: '--eta',
    name: 'ETA',
    description: '显示每个输出的预计到达时间',
    category: 'general',
    type: 'boolean',
    disabled: true,
    disabledReason: '此参数由后端自动添加'
  },
  {
    key: 'hex',
    cliName: '--hex',
    name: 'Hex',
    description: '数据获取时使用十六进制转换',
    category: 'general',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'parseErrors',
    cliName: '--parse-errors',
    name: 'Parse Errors',
    description: '从响应中解析并显示 DBMS 错误消息',
    category: 'general',
    type: 'boolean'
  },
  {
    key: 'repair',
    cliName: '--repair',
    name: 'Repair',
    description: '重新导出具有未知字符标记（?）的条目',
    category: 'general',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'saveConfig',
    cliName: '--save',
    name: 'Save Config',
    description: '将选项保存到配置 INI 文件',
    category: 'general',
    type: 'string',
    advanced: true
  },
  {
    key: 'scope',
    cliName: '--scope',
    name: 'Scope',
    description: '过滤目标的正则表达式',
    category: 'general',
    type: 'string',
    advanced: true
  },
  {
    key: 'testFilter',
    cliName: '--test-filter',
    name: 'Test Filter',
    description: '按 payload 和/或标题选择测试',
    category: 'general',
    type: 'string',
    placeholder: 'ROW',
    advanced: true
  },
  {
    key: 'testSkip',
    cliName: '--test-skip',
    name: 'Test Skip',
    description: '按 payload 和/或标题跳过测试',
    category: 'general',
    type: 'string',
    placeholder: 'BENCHMARK',
    advanced: true
  },
  {
    key: 'timeLimit',
    cliName: '--time-limit',
    name: 'Time Limit',
    description: '运行时间限制（秒）',
    category: 'general',
    type: 'integer',
    min: 0,
    placeholder: '3600',
    advanced: true
  },
  {
    key: 'tablePrefix',
    cliName: '--table-prefix',
    name: 'Table Prefix',
    description: '临时表使用的前缀',
    category: 'general',
    type: 'string',
    defaultValue: 'sqlmap',
    advanced: true
  },
  {
    key: 'unsafeNaming',
    cliName: '--unsafe-naming',
    name: 'Unsafe Naming',
    description: '禁用 DBMS 标识符转义',
    category: 'general',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'webRoot',
    cliName: '--web-root',
    name: 'Web Root',
    description: 'Web 服务器文档根目录',
    category: 'general',
    type: 'string',
    placeholder: '/var/www',
    advanced: true
  },
  {
    key: 'gpage',
    cliName: '--gpage',
    name: 'Google Page',
    description: '使用指定页码的 Google dork 结果',
    category: 'general',
    type: 'integer',
    min: 1,
    advanced: true
  }
]
