/**
 * Brute Force 暴力破解参数定义
 */
import type { ParamDefinition } from '../types'

export const BRUTE_FORCE_PARAMS: ParamDefinition[] = [
  {
    key: 'commonTables',
    cliName: '--common-tables',
    name: 'Common Tables',
    description: '检查常见表是否存在',
    category: 'bruteForce',
    type: 'boolean'
  },
  {
    key: 'commonColumns',
    cliName: '--common-columns',
    name: 'Common Columns',
    description: '检查常见列是否存在',
    category: 'bruteForce',
    type: 'boolean'
  },
  {
    key: 'commonFiles',
    cliName: '--common-files',
    name: 'Common Files',
    description: '检查常见文件是否存在',
    category: 'bruteForce',
    type: 'boolean'
  }
]
