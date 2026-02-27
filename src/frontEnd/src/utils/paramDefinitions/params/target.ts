/**
 * Target 目标参数定义
 */
import type { ParamDefinition } from '../types'

export const TARGET_PARAMS: ParamDefinition[] = [
  {
    key: 'url',
    cliName: '-u',
    name: 'Target URL',
    description: '目标 URL',
    category: 'target',
    type: 'string',
    placeholder: 'http://www.site.com/vuln.php?id=1'
  },
  {
    key: 'direct',
    cliName: '-d',
    name: 'Direct Connection',
    description: '直接数据库连接字符串',
    category: 'target',
    type: 'string',
    placeholder: 'mysql://USER:PASSWORD@DBMS_IP:DBMS_PORT/DATABASE_NAME',
    advanced: true
  },
  {
    key: 'logFile',
    cliName: '-l',
    name: 'Log File',
    description: '从 Burp/WebScarab 代理日志文件解析目标',
    category: 'target',
    type: 'string',
    advanced: true
  },
  {
    key: 'bulkFile',
    cliName: '-m',
    name: 'Bulk File',
    description: '从文本文件批量扫描多个目标',
    category: 'target',
    type: 'string',
    advanced: true
  },
  {
    key: 'requestFile',
    cliName: '-r',
    name: 'Request File',
    description: '从文件加载 HTTP 请求',
    category: 'target',
    type: 'string',
    disabled: true,
    disabledReason: '此参数由后端自动处理'
  },
  {
    key: 'googleDork',
    cliName: '-g',
    name: 'Google Dork',
    description: '处理 Google dork 搜索结果作为目标 URL',
    category: 'target',
    type: 'string',
    advanced: true
  },
  {
    key: 'configFile',
    cliName: '-c',
    name: 'Config File',
    description: '从配置 INI 文件加载选项',
    category: 'target',
    type: 'string',
    advanced: true
  }
]
