/**
 * Injection 注入参数定义
 */
import type { ParamDefinition } from '../types'
import { DBMS_OPTIONS, OS_OPTIONS } from '../types'

export const INJECTION_PARAMS: ParamDefinition[] = [
  {
    key: 'testParameter',
    cliName: '-p',
    name: 'Test Parameter',
    description: '指定测试的参数',
    category: 'injection',
    type: 'string',
    placeholder: 'id,name'
  },
  {
    key: 'skip',
    cliName: '--skip',
    name: 'Skip',
    description: '跳过测试的参数',
    category: 'injection',
    type: 'string',
    placeholder: 'token,csrf'
  },
  {
    key: 'skipStatic',
    cliName: '--skip-static',
    name: 'Skip Static',
    description: '跳过非动态参数',
    category: 'injection',
    type: 'boolean'
  },
  {
    key: 'paramExclude',
    cliName: '--param-exclude',
    name: 'Param Exclude',
    description: '排除参数的正则表达式',
    category: 'injection',
    type: 'string',
    placeholder: 'ses|token'
  },
  {
    key: 'paramFilter',
    cliName: '--param-filter',
    name: 'Param Filter',
    description: '按位置选择测试参数',
    category: 'injection',
    type: 'string',
    placeholder: 'POST'
  },
  {
    key: 'dbms',
    cliName: '--dbms',
    name: 'DBMS',
    description: '强制指定后端数据库类型',
    category: 'injection',
    type: 'select',
    options: DBMS_OPTIONS
  },
  {
    key: 'dbmsCred',
    cliName: '--dbms-cred',
    name: 'DBMS Credentials',
    description: 'DBMS 认证凭据 (user:password)',
    category: 'injection',
    type: 'string',
    placeholder: 'user:password',
    advanced: true
  },
  {
    key: 'os',
    cliName: '--os',
    name: 'OS',
    description: '强制指定后端操作系统',
    category: 'injection',
    type: 'select',
    options: OS_OPTIONS
  },
  {
    key: 'invalidBignum',
    cliName: '--invalid-bignum',
    name: 'Invalid Bignum',
    description: '使用大数字使值无效',
    category: 'injection',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'invalidLogical',
    cliName: '--invalid-logical',
    name: 'Invalid Logical',
    description: '使用逻辑操作使值无效',
    category: 'injection',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'invalidString',
    cliName: '--invalid-string',
    name: 'Invalid String',
    description: '使用随机字符串使值无效',
    category: 'injection',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'noCast',
    cliName: '--no-cast',
    name: 'No Cast',
    description: '关闭 payload 转换机制',
    category: 'injection',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'noEscape',
    cliName: '--no-escape',
    name: 'No Escape',
    description: '关闭字符串转义机制',
    category: 'injection',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'prefix',
    cliName: '--prefix',
    name: 'Prefix',
    description: '注入 payload 前缀字符串',
    category: 'injection',
    type: 'string',
    placeholder: "'"
  },
  {
    key: 'suffix',
    cliName: '--suffix',
    name: 'Suffix',
    description: '注入 payload 后缀字符串',
    category: 'injection',
    type: 'string',
    placeholder: '-- -'
  },
  {
    key: 'tamper',
    cliName: '--tamper',
    name: 'Tamper',
    description: 'Tamper 脚本',
    category: 'injection',
    type: 'string',
    placeholder: 'space2comment,randomcase'
  }
]
