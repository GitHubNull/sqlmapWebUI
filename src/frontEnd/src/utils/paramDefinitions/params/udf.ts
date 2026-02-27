/**
 * UDF 用户自定义函数参数定义
 */
import type { ParamDefinition } from '../types'

export const UDF_PARAMS: ParamDefinition[] = [
  {
    key: 'udfInject',
    cliName: '--udf-inject',
    name: 'UDF Inject',
    description: '注入自定义用户函数',
    category: 'udf',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'sharedLib',
    cliName: '--shared-lib',
    name: 'Shared Library',
    description: '共享库的本地路径',
    category: 'udf',
    type: 'string',
    advanced: true
  }
]
