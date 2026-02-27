/**
 * File System 文件系统参数定义
 */
import type { ParamDefinition } from '../types'

export const FILE_SYSTEM_PARAMS: ParamDefinition[] = [
  {
    key: 'fileRead',
    cliName: '--file-read',
    name: 'File Read',
    description: '从后端 DBMS 文件系统读取文件',
    category: 'fileSystem',
    type: 'string',
    placeholder: '/etc/passwd',
    securityLevel: 'warning',
    securityWarning: '中等风险：此参数可访问文件系统，请确保有合法授权！'
  },
  {
    key: 'fileWrite',
    cliName: '--file-write',
    name: 'File Write',
    description: '向后端 DBMS 文件系统写入本地文件',
    category: 'fileSystem',
    type: 'string',
    placeholder: '/path/to/local/file',
    securityLevel: 'warning',
    securityWarning: '中等风险：此参数可访问文件系统，请确保有合法授权！'
  },
  {
    key: 'fileDest',
    cliName: '--file-dest',
    name: 'File Destination',
    description: '后端 DBMS 写入文件的绝对路径',
    category: 'fileSystem',
    type: 'string',
    placeholder: '/var/www/shell.php',
    securityLevel: 'warning',
    securityWarning: '中等风险：此参数可访问文件系统，请确保有合法授权！'
  }
]
