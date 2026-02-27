/**
 * Enumeration 枚举参数定义
 */
import type { ParamDefinition } from '../types'
import { DUMP_FORMAT_OPTIONS } from '../types'

export const ENUMERATION_PARAMS: ParamDefinition[] = [
  // 基本枚举
  {
    key: 'getAll',
    cliName: '-a',
    name: 'All',
    description: '枚举所有信息',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getBanner',
    cliName: '-b',
    name: 'Banner',
    description: '获取 DBMS Banner',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getCurrentUser',
    cliName: '--current-user',
    name: 'Current User',
    description: '获取 DBMS 当前用户',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getCurrentDb',
    cliName: '--current-db',
    name: 'Current Database',
    description: '获取 DBMS 当前数据库',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getHostname',
    cliName: '--hostname',
    name: 'Hostname',
    description: '获取 DBMS 服务器主机名',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'isDba',
    cliName: '--is-dba',
    name: 'Is DBA',
    description: '检测当前用户是否为 DBA',
    category: 'enumeration',
    type: 'boolean'
  },

  // 用户相关
  {
    key: 'getUsers',
    cliName: '--users',
    name: 'Users',
    description: '枚举 DBMS 用户',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getPasswordHashes',
    cliName: '--passwords',
    name: 'Passwords',
    description: '获取 DBMS 用户密码哈希',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getPrivileges',
    cliName: '--privileges',
    name: 'Privileges',
    description: '枚举 DBMS 用户权限',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getRoles',
    cliName: '--roles',
    name: 'Roles',
    description: '枚举 DBMS 用户角色',
    category: 'enumeration',
    type: 'boolean'
  },

  // 数据库结构
  {
    key: 'getDbs',
    cliName: '--dbs',
    name: 'Databases',
    description: '枚举 DBMS 数据库',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getTables',
    cliName: '--tables',
    name: 'Tables',
    description: '枚举 DBMS 数据库表',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getColumns',
    cliName: '--columns',
    name: 'Columns',
    description: '枚举 DBMS 数据库表列',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getSchema',
    cliName: '--schema',
    name: 'Schema',
    description: '枚举 DBMS 架构',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getCount',
    cliName: '--count',
    name: 'Count',
    description: '获取表记录数',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'getComments',
    cliName: '--comments',
    name: 'Comments',
    description: '枚举时检查 DBMS 注释',
    category: 'enumeration',
    type: 'boolean',
    advanced: true
  },
  {
    key: 'getStatements',
    cliName: '--statements',
    name: 'Statements',
    description: '获取正在运行的 SQL 语句',
    category: 'enumeration',
    type: 'boolean',
    advanced: true
  },

  // 数据导出
  {
    key: 'dumpTable',
    cliName: '--dump',
    name: 'Dump',
    description: '导出 DBMS 数据库表数据',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'dumpAll',
    cliName: '--dump-all',
    name: 'Dump All',
    description: '导出所有 DBMS 数据库表数据',
    category: 'enumeration',
    type: 'boolean'
  },
  {
    key: 'search',
    cliName: '--search',
    name: 'Search',
    description: '搜索列、表和/或数据库名称',
    category: 'enumeration',
    type: 'boolean'
  },

  // 目标指定
  {
    key: 'db',
    cliName: '-D',
    name: 'Database',
    description: '指定要枚举的 DBMS 数据库',
    category: 'enumeration',
    type: 'string'
  },
  {
    key: 'tbl',
    cliName: '-T',
    name: 'Table',
    description: '指定要枚举的 DBMS 数据库表',
    category: 'enumeration',
    type: 'string'
  },
  {
    key: 'col',
    cliName: '-C',
    name: 'Column',
    description: '指定要枚举的 DBMS 数据库表列',
    category: 'enumeration',
    type: 'string'
  },
  {
    key: 'exclude',
    cliName: '-X',
    name: 'Exclude',
    description: '排除的 DBMS 数据库标识符',
    category: 'enumeration',
    type: 'string',
    advanced: true
  },
  {
    key: 'user',
    cliName: '-U',
    name: 'User',
    description: '指定要枚举的 DBMS 用户',
    category: 'enumeration',
    type: 'string',
    advanced: true
  },
  {
    key: 'excludeSysDbs',
    cliName: '--exclude-sysdbs',
    name: 'Exclude System DBs',
    description: '枚举表时排除 DBMS 系统数据库',
    category: 'enumeration',
    type: 'boolean'
  },

  // 高级枚举选项
  {
    key: 'pivotColumn',
    cliName: '--pivot-column',
    name: 'Pivot Column',
    description: '透视列名',
    category: 'enumeration',
    type: 'string',
    advanced: true
  },
  {
    key: 'dumpWhere',
    cliName: '--where',
    name: 'Where',
    description: '导出表时使用的 WHERE 条件',
    category: 'enumeration',
    type: 'string',
    placeholder: 'id>100'
  },
  {
    key: 'limitStart',
    cliName: '--start',
    name: 'Start',
    description: '开始导出的表记录位置',
    category: 'enumeration',
    type: 'integer',
    min: 0
  },
  {
    key: 'limitStop',
    cliName: '--stop',
    name: 'Stop',
    description: '停止导出的表记录位置',
    category: 'enumeration',
    type: 'integer',
    min: 0
  },
  {
    key: 'firstChar',
    cliName: '--first',
    name: 'First Char',
    description: '开始获取的查询输出字符位置',
    category: 'enumeration',
    type: 'integer',
    min: 0,
    advanced: true
  },
  {
    key: 'lastChar',
    cliName: '--last',
    name: 'Last Char',
    description: '结束获取的查询输出字符位置',
    category: 'enumeration',
    type: 'integer',
    min: 0,
    advanced: true
  },

  // SQL 执行
  {
    key: 'sqlQuery',
    cliName: '--sql-query',
    name: 'SQL Query',
    description: '要执行的 SQL 语句',
    category: 'enumeration',
    type: 'textarea',
    placeholder: 'SELECT * FROM users'
  },
  {
    key: 'sqlShell',
    cliName: '--sql-shell',
    name: 'SQL Shell',
    description: '交互式 SQL shell',
    category: 'enumeration',
    type: 'boolean',
    disabled: true,
    disabledReason: 'SQLMap RESTAPI 不支持此参数'
  },
  {
    key: 'sqlFile',
    cliName: '--sql-file',
    name: 'SQL File',
    description: '从文件执行 SQL 语句',
    category: 'enumeration',
    type: 'string',
    advanced: true
  }
]
