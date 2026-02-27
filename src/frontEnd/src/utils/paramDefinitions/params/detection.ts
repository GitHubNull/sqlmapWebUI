/**
 * Detection 检测参数定义
 */
import type { ParamDefinition } from '../types'

export const DETECTION_PARAMS: ParamDefinition[] = [
  {
    key: 'level',
    cliName: '--level',
    name: 'Level',
    description: '检测级别 (1-5)',
    category: 'detection',
    type: 'integer',
    defaultValue: 1,
    min: 1,
    max: 5
  },
  {
    key: 'risk',
    cliName: '--risk',
    name: 'Risk',
    description: '风险级别 (1-3)',
    category: 'detection',
    type: 'integer',
    defaultValue: 1,
    min: 1,
    max: 3
  },
  {
    key: 'string',
    cliName: '--string',
    name: 'String',
    description: '页面包含此字符串时判定为 True',
    category: 'detection',
    type: 'string'
  },
  {
    key: 'notString',
    cliName: '--not-string',
    name: 'Not String',
    description: '页面包含此字符串时判定为 False',
    category: 'detection',
    type: 'string'
  },
  {
    key: 'regexp',
    cliName: '--regexp',
    name: 'Regexp',
    description: '页面匹配此正则表达式时判定为 True',
    category: 'detection',
    type: 'string'
  },
  {
    key: 'code',
    cliName: '--code',
    name: 'HTTP Code',
    description: '页面返回此 HTTP 状态码时判定为 True',
    category: 'detection',
    type: 'integer',
    min: 100,
    max: 599
  },
  {
    key: 'smart',
    cliName: '--smart',
    name: 'Smart',
    description: '仅在积极的启发式检测时执行彻底测试',
    category: 'detection',
    type: 'boolean'
  },
  {
    key: 'textOnly',
    cliName: '--text-only',
    name: 'Text Only',
    description: '仅基于文本内容比较页面',
    category: 'detection',
    type: 'boolean'
  },
  {
    key: 'titles',
    cliName: '--titles',
    name: 'Titles',
    description: '仅基于页面标题比较',
    category: 'detection',
    type: 'boolean'
  }
]
