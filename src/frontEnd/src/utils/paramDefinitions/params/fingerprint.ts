/**
 * Fingerprint 指纹参数定义
 */
import type { ParamDefinition } from '../types'

export const FINGERPRINT_PARAMS: ParamDefinition[] = [
  {
    key: 'extensiveFp',
    cliName: '-f',
    name: 'Fingerprint',
    description: '执行深度 DBMS 版本指纹识别',
    category: 'fingerprint',
    type: 'boolean'
  }
]
