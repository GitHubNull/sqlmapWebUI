/**
 * Optimization 优化参数定义
 */
import type { ParamDefinition } from '../types'

export const OPTIMIZATION_PARAMS: ParamDefinition[] = [
  {
    key: 'optimize',
    cliName: '-o',
    name: 'Optimize',
    description: '启用所有优化开关',
    category: 'optimization',
    type: 'boolean'
  },
  {
    key: 'predictOutput',
    cliName: '--predict-output',
    name: 'Predict Output',
    description: '预测常见查询输出',
    category: 'optimization',
    type: 'boolean'
  },
  {
    key: 'keepAlive',
    cliName: '--keep-alive',
    name: 'Keep Alive',
    description: '使用持久 HTTP(s) 连接',
    category: 'optimization',
    type: 'boolean'
  },
  {
    key: 'nullConnection',
    cliName: '--null-connection',
    name: 'Null Connection',
    description: '不获取实际 HTTP 响应体获取页面长度',
    category: 'optimization',
    type: 'boolean'
  },
  {
    key: 'threads',
    cliName: '--threads',
    name: 'Threads',
    description: '最大并发 HTTP(s) 请求数',
    category: 'optimization',
    type: 'integer',
    defaultValue: 1,
    min: 1,
    max: 10
  }
]
