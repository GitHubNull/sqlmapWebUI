/**
 * Techniques 技术参数定义
 */
import type { ParamDefinition } from '../types'

export const TECHNIQUES_PARAMS: ParamDefinition[] = [
  {
    key: 'technique',
    cliName: '--technique',
    name: 'Technique',
    description: '注入技术 (B=布尔, E=报错, U=联合, S=堆叠, T=时间, Q=内联)',
    category: 'techniques',
    type: 'string',
    defaultValue: 'BEUSTQ'
  },
  {
    key: 'timeSec',
    cliName: '--time-sec',
    name: 'Time Sec',
    description: '时间盲注延迟秒数',
    category: 'techniques',
    type: 'integer',
    defaultValue: 5,
    min: 1,
    max: 30
  },
  {
    key: 'disableStats',
    cliName: '--disable-stats',
    name: 'Disable Stats',
    description: '禁用检测延迟的统计模型',
    category: 'techniques',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'unionCols',
    cliName: '--union-cols',
    name: 'Union Cols',
    description: 'UNION 查询列数范围',
    category: 'techniques',
    type: 'string',
    placeholder: '1-20'
  },
  {
    key: 'unionChar',
    cliName: '--union-char',
    name: 'Union Char',
    description: 'UNION 查询爆破列数使用的字符',
    category: 'techniques',
    type: 'string',
    placeholder: 'NULL'
  },
  {
    key: 'unionFrom',
    cliName: '--union-from',
    name: 'Union From',
    description: 'UNION 查询 FROM 子句使用的表',
    category: 'techniques',
    type: 'string'
  },
  {
    key: 'unionValues',
    cliName: '--union-values',
    name: 'Union Values',
    description: 'UNION 查询使用的列值',
    category: 'techniques',
    type: 'string',
    advanced: true
  },
  {
    key: 'dnsDomain',
    cliName: '--dns-domain',
    name: 'DNS Domain',
    description: 'DNS 外泄攻击使用的域名',
    category: 'techniques',
    type: 'string',
    advanced: true
  },
  {
    key: 'secondUrl',
    cliName: '--second-url',
    name: 'Second URL',
    description: '二次注入结果页面 URL',
    category: 'techniques',
    type: 'string',
    advanced: true
  },
  {
    key: 'secondReq',
    cliName: '--second-req',
    name: 'Second Request',
    description: '从文件加载二次注入 HTTP 请求',
    category: 'techniques',
    type: 'string',
    advanced: true
  }
]
