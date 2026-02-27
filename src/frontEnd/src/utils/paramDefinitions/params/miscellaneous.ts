/**
 * Miscellaneous 其他参数定义
 */
import type { ParamDefinition } from '../types'

export const MISCELLANEOUS_PARAMS: ParamDefinition[] = [
  {
    key: 'mnemonics',
    cliName: '-z',
    name: 'Mnemonics',
    description: '使用短助记符',
    category: 'miscellaneous',
    type: 'string',
    placeholder: 'flu,bat,ban,tec=EU',
    advanced: true
  },
  {
    key: 'alert',
    cliName: '--alert',
    name: 'Alert',
    description: '发现 SQL 注入时运行主机 OS 命令',
    category: 'miscellaneous',
    type: 'string',
    advanced: true
  },
  {
    key: 'beep',
    cliName: '--beep',
    name: 'Beep',
    description: '提问和/或发现漏洞时发出蜂鸣声',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'dependencies',
    cliName: '--dependencies',
    name: 'Dependencies',
    description: '检查缺失的（可选）sqlmap 依赖',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'disableColoring',
    cliName: '--disable-coloring',
    name: 'Disable Coloring',
    description: '禁用控制台输出着色',
    category: 'miscellaneous',
    type: 'boolean',
    disabled: true,
    disabledReason: '此参数由后端自动添加'
  },
  {
    key: 'disableHashing',
    cliName: '--disable-hashing',
    name: 'Disable Hashing',
    description: '禁用表导出的哈希分析',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'listTampers',
    cliName: '--list-tampers',
    name: 'List Tampers',
    description: '显示可用的 tamper 脚本列表',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'noLogging',
    cliName: '--no-logging',
    name: 'No Logging',
    description: '禁用记录到文件',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'noTruncate',
    cliName: '--no-truncate',
    name: 'No Truncate',
    description: '禁用控制台输出截断',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'offline',
    cliName: '--offline',
    name: 'Offline',
    description: '离线模式工作（仅使用会话数据）',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'purge',
    cliName: '--purge',
    name: 'Purge',
    description: '安全删除 sqlmap 数据目录中的所有内容',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'resultsFile',
    cliName: '--results-file',
    name: 'Results File',
    description: '多目标模式下 CSV 结果文件位置',
    category: 'miscellaneous',
    type: 'string',
    advanced: true
  },
  {
    key: 'shell',
    cliName: '--shell',
    name: 'Shell',
    description: '交互式 sqlmap shell',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'tmpDir',
    cliName: '--tmp-dir',
    name: 'Temp Directory',
    description: '存储临时文件的本地目录',
    category: 'miscellaneous',
    type: 'string',
    advanced: true
  },
  {
    key: 'unstable',
    cliName: '--unstable',
    name: 'Unstable',
    description: '调整不稳定连接的选项',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'update',
    cliName: '--update',
    name: 'Update',
    description: '更新 sqlmap',
    category: 'miscellaneous',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'wizard',
    cliName: '--wizard',
    name: 'Wizard',
    description: '初学者简单向导界面',
    category: 'miscellaneous',
    type: 'boolean',
    disabled: true,
    disabledReason: 'SQLMap RESTAPI 不支持此参数'
  }
]
