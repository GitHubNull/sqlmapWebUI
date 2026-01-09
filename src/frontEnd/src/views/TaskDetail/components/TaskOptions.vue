<template>
  <div>
    <div v-if="loadingOptions" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="task?.options" class="options-wrapper">
      <!-- 视图切换区域 - 突出显示 -->
      <div class="view-switch-bar">
        <div class="view-switch-tabs">
          <button
            class="view-tab"
            :class="{ active: viewMode === 'table' }"
            @click="viewMode = 'table'"
          >
            <i class="pi pi-table"></i>
            <span>表格视图</span>
          </button>
          <button
            class="view-tab"
            :class="{ active: viewMode === 'cmdline' }"
            @click="viewMode = 'cmdline'"
          >
            <i class="pi pi-code"></i>
            <span>命令行视图</span>
          </button>
        </div>
        <div class="view-switch-hint">
          <i class="pi pi-info-circle"></i>
          <span>点击切换不同的显示方式</span>
        </div>
      </div>

      <!-- 主工具栏 -->
      <div class="options-toolbar">
        <!-- 搜索区域 -->
        <div class="search-section">
          <IconField iconPosition="left" class="search-field">
            <InputIcon class="pi pi-search" />
            <InputText
              v-model="searchQuery"
              :placeholder="viewMode === 'table' ? '搜索配置项...' : '搜索参数...'"
              class="search-input"
            />
          </IconField>
          <Button
            v-if="searchQuery"
            icon="pi pi-times"
            text
            rounded
            size="small"
            @click="searchQuery = ''"
            v-tooltip.top="'清除搜索'"
          />
        </div>

        <!-- 表格视图的排序 -->
        <div v-if="viewMode === 'table'" class="sort-section">
          <span class="sort-label">排序：</span>
          <SelectButton
            v-model="sortOrder"
            :options="sortOptions"
            optionLabel="label"
            optionValue="value"
            :allowEmpty="false"
          />
        </div>

        <!-- 命令行视图的复制按钮 -->
        <div v-if="viewMode === 'cmdline'" class="copy-section">
          <Button
            icon="pi pi-copy"
            label="复制命令"
            size="small"
            severity="secondary"
            @click="copyCommandLine"
            v-tooltip.top="'复制完整命令行参数'"
          />
        </div>

        <!-- 统计信息 -->
        <div class="stats-section">
          <span class="stats-info">
            <i :class="viewMode === 'table' ? 'pi pi-list' : 'pi pi-terminal'"></i>
            <template v-if="viewMode === 'table'">
              共 {{ totalCount }} 项，显示 {{ filteredCount }} 项
            </template>
            <template v-else>
              共 {{ cmdlineArgs.length }} 个参数
              <span v-if="searchQuery">, 匹配 {{ filteredCmdlineArgs.length }} 个</span>
            </template>
          </span>
        </div>
      </div>

      <!-- 表格视图 -->
      <div v-if="viewMode === 'table'" class="options-table-container">
        <table class="options-table">
          <thead>
            <tr>
              <th class="option-key-header" @click="toggleSort">
                <span>配置项</span>
                <i :class="sortIcon"></i>
              </th>
              <th class="option-value-header">配置值</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in filteredAndSortedOptions" :key="item.key" class="option-row">
              <td class="option-key-cell">
                <span v-html="highlightMatch(item.displayKey)"></span>
              </td>
              <td class="option-value-cell">
                <span v-html="highlightMatch(item.displayValue)"></span>
              </td>
            </tr>
            <tr v-if="filteredAndSortedOptions.length === 0">
              <td colspan="2" class="no-results">
                <i class="pi pi-search"></i>
                <span>未找到匹配的配置项</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 命令行参数视图 -->
      <div v-else class="cmdline-container">
        <div v-if="filteredCmdlineArgs.length === 0" class="no-results">
          <i class="pi pi-search"></i>
          <span>未找到匹配的参数</span>
        </div>
        <div v-else class="cmdline-full" v-html="highlightedFullCommand"></div>
      </div>
    </div>
    <span v-else class="text-muted">无配置信息</span>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import type { Task } from '@/types/task'

interface Props {
  task?: Task | null
  loadingOptions?: boolean
}

const props = defineProps<Props>()
const toast = useToast()

// 视图模式
const viewMode = ref<'table' | 'cmdline'>('table')

// 搜索过滤
const searchQuery = ref('')

// 排序状态
const sortOrder = ref<'default' | 'asc' | 'desc'>('default')
const sortOptions = [
  { label: '默认', value: 'default' },
  { label: 'A-Z', value: 'asc' },
  { label: 'Z-A', value: 'desc' }
]

// 排序图标
const sortIcon = computed(() => {
  if (sortOrder.value === 'asc') return 'pi pi-sort-alpha-down'
  if (sortOrder.value === 'desc') return 'pi pi-sort-alpha-up'
  return 'pi pi-sort-alt'
})

// 切换排序
function toggleSort() {
  if (sortOrder.value === 'default') sortOrder.value = 'asc'
  else if (sortOrder.value === 'asc') sortOrder.value = 'desc'
  else sortOrder.value = 'default'
}

// 选项到命令行参数的映射
const optionToCmdMap: Record<string, string> = {
  // 请求相关
  requestFile: '-r',
  url: '-u',
  data: '--data',
  cookie: '--cookie',
  headers: '-H',
  userAgent: '-A',
  randomAgent: '--random-agent',
  proxy: '--proxy',
  proxyAuth: '--proxy-auth',
  proxyFile: '--proxy-file',
  proxyFreq: '--proxy-freq',
  tor: '--tor',
  torType: '--tor-type',
  torPort: '--tor-port',
  checkTor: '--check-tor',
  
  // 请求选项
  method: '--method',
  paramDel: '--param-del',
  cookieDel: '--cookie-del',
  liveCookies: '--live-cookies',
  loadCookies: '--load-cookies',
  dropSetCookie: '--drop-set-cookie',
  mobile: '--mobile',
  host: '--host',
  referer: '--referer',
  authType: '--auth-type',
  authCred: '--auth-cred',
  authFile: '--auth-file',
  abortCode: '--abort-code',
  ignoreCode: '--ignore-code',
  ignoreProxy: '--ignore-proxy',
  ignoreRedirects: '--ignore-redirects',
  ignoreTimeouts: '--ignore-timeouts',
  forceSSL: '--force-ssl',
  chunked: '--chunked',
  hpp: '--hpp',
  evalCode: '--eval',
  
  // 连接选项
  delay: '--delay',
  timeout: '--timeout',
  retries: '--retries',
  retryOn: '--retry-on',
  randomize: '--randomize',
  safeUrl: '--safe-url',
  safePost: '--safe-post',
  safeReq: '--safe-req',
  safeFreq: '--safe-freq',
  skipUrlencode: '--skip-urlencode',
  csrfToken: '--csrf-token',
  csrfUrl: '--csrf-url',
  csrfMethod: '--csrf-method',
  csrfData: '--csrf-data',
  csrfRetries: '--csrf-retries',
  
  // 优化选项
  optimize: '-o',
  predictOutput: '--predict-output',
  keepAlive: '--keep-alive',
  nullConnection: '--null-connection',
  threads: '--threads',
  
  // 检测相关
  level: '--level',
  risk: '--risk',
  string: '--string',
  notString: '--not-string',
  regexp: '--regexp',
  code: '--code',
  smart: '--smart',
  textOnly: '--text-only',
  titles: '--titles',
  
  // 注入相关
  technique: '--technique',
  testParameter: '-p',
  skip: '--skip',
  skipStatic: '--skip-static',
  paramExclude: '--param-exclude',
  paramFilter: '--param-filter',
  dbms: '--dbms',
  dbmsCred: '--dbms-cred',
  os: '--os',
  invalidBignum: '--invalid-bignum',
  invalidLogical: '--invalid-logical',
  invalidString: '--invalid-string',
  noCast: '--no-cast',
  noEscape: '--no-escape',
  prefix: '--prefix',
  suffix: '--suffix',
  tamper: '--tamper',
  timeSec: '--time-sec',
  disableStats: '--disable-stats',
  unionCols: '--union-cols',
  unionChar: '--union-char',
  unionFrom: '--union-from',
  unionValues: '--union-values',
  dnsDomain: '--dns-domain',
  secondUrl: '--second-url',
  secondReq: '--second-req',
  
  // 指纹识别
  fingerprint: '--fingerprint',
  
  // 枚举相关
  getAll: '--all',
  getBanner: '--banner',
  getCurrentUser: '--current-user',
  getCurrentDb: '--current-db',
  getHostname: '--hostname',
  isDba: '--is-dba',
  getUsers: '--users',
  getPasswords: '--passwords',
  getPrivileges: '--privileges',
  getRoles: '--roles',
  getDbs: '--dbs',
  getTables: '--tables',
  getColumns: '--columns',
  getSchema: '--schema',
  getCount: '--count',
  dumpTable: '--dump',
  dumpAll: '--dump-all',
  search: '--search',
  getComments: '--comments',
  getStatements: '--statements',
  db: '-D',
  tbl: '-T',
  col: '-C',
  exclude: '-X',
  user: '-U',
  excludeSysDbs: '--exclude-sysdbs',
  pivotColumn: '--pivot-column',
  dumpWhere: '--where',
  limitStart: '--start',
  limitStop: '--stop',
  firstChar: '--first',
  lastChar: '--last',
  sqlQuery: '--sql-query',
  sqlShell: '--sql-shell',
  sqlFile: '--sql-file',
  
  // 暴力破解
  commonTables: '--common-tables',
  commonColumns: '--common-columns',
  commonFiles: '--common-files',
  
  // UDF
  udfInject: '--udf-inject',
  sharedLib: '--shared-lib',
  
  // 文件系统
  fileRead: '--file-read',
  fileWrite: '--file-write',
  fileDest: '--file-dest',
  
  // 操作系统
  osCmd: '--os-cmd',
  osShell: '--os-shell',
  osPwn: '--os-pwn',
  osSmbrelay: '--os-smbrelay',
  osBof: '--os-bof',
  privEsc: '--priv-esc',
  msfPath: '--msf-path',
  tmpPath: '--tmp-path',
  
  // 注册表
  regRead: '--reg-read',
  regAdd: '--reg-add',
  regDel: '--reg-del',
  regKey: '--reg-key',
  regValue: '--reg-value',
  regData: '--reg-data',
  regType: '--reg-type',
  
  // 通用选项
  sessionFile: '-s',
  trafficFile: '-t',
  abortOnEmpty: '--abort-on-empty',
  answers: '--answers',
  base64Param: '--base64',
  base64Safe: '--base64-safe',
  batch: '--batch',
  binaryFields: '--binary-fields',
  checkInternet: '--check-internet',
  cleanup: '--cleanup',
  crawlDepth: '--crawl',
  crawlExclude: '--crawl-exclude',
  csvDel: '--csv-del',
  charset: '--charset',
  dumpFile: '--dump-file',
  dumpFormat: '--dump-format',
  encoding: '--encoding',
  eta: '--eta',
  flushSession: '--flush-session',
  forms: '--forms',
  freshQueries: '--fresh-queries',
  googlePage: '--gpage',
  harFile: '--har',
  hexConvert: '--hex',
  outputDir: '--output-dir',
  parseErrors: '--parse-errors',
  preprocess: '--preprocess',
  postprocess: '--postprocess',
  repair: '--repair',
  saveConfig: '--save',
  scope: '--scope',
  skipHeuristics: '--skip-heuristics',
  skipWaf: '--skip-waf',
  tablePrefix: '--table-prefix',
  testFilter: '--test-filter',
  testSkip: '--test-skip',
  timeLimit: '--time-limit',
  unsafeNaming: '--unsafe-naming',
  webRoot: '--web-root',
  
  // 杂项
  verbose: '-v',
  mnemonics: '-z',
  alert: '--alert',
  beep: '--beep',
  dependencies: '--dependencies',
  disableColoring: '--disable-coloring',
  disableHashing: '--disable-hashing',
  listTampers: '--list-tampers',
  noLogging: '--no-logging',
  noTruncate: '--no-truncate',
  offline: '--offline',
  purge: '--purge',
  resultsFile: '--results-file',
  shell: '--shell',
  tmpDir: '--tmp-dir',
  unstable: '--unstable',
  updateSqlmap: '--update',
  wizard: '--wizard',
  
  // 内部选项
  api: '--api',
  taskid: '--taskid',
  database: '--database',
}

// 驼峰命名转换为 kebab-case
function camelToKebab(str: string): string {
  return str.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase()
}

// 需要跳过的内部选项
const skipOptions = new Set(['api', 'taskid', 'database', 'disableColoring'])

// 将选项转换为命令行参数
function optionToArg(key: string, value: any): string | null {
  // 跳过内部选项
  if (skipOptions.has(key)) return null
  
  // 跳过空值
  if (value === null || value === undefined || value === '' || value === false) {
    return null
  }
  
  // 获取命令行标志：优先使用映射表，否则将驼峰转为 kebab-case
  const cmdFlag = optionToCmdMap[key] || `--${camelToKebab(key)}`
  
  // 判断是短参数还是长参数
  const isShortParam = cmdFlag.startsWith('-') && !cmdFlag.startsWith('--')
  
  // 布尔值选项
  if (typeof value === 'boolean') {
    return value ? cmdFlag : null
  }
  
  // 数组值
  if (Array.isArray(value)) {
    if (value.length === 0) return null
    const joinedValue = value.join(',')
    // 短参数用空格，长参数用等号
    return isShortParam ? `${cmdFlag} "${joinedValue}"` : `${cmdFlag}="${joinedValue}"`
  }
  
  // 字符串或数字
  const strValue = String(value)
  
  // 如果值包含空格或特殊字符，需要引号包裹
  if (strValue.includes(' ') || strValue.includes('\n') || strValue.includes('"')) {
    // 对于多行文本（如headers），使用简化显示
    if (strValue.includes('\n')) {
      const firstLine = strValue.split('\n')[0]
      return isShortParam ? `${cmdFlag} "${firstLine}..."` : `${cmdFlag}="${firstLine}..."`
    }
    return isShortParam ? `${cmdFlag} "${strValue}"` : `${cmdFlag}="${strValue}"`
  }
  
  // 短参数用空格分隔，长参数用等号
  return isShortParam ? `${cmdFlag} ${strValue}` : `${cmdFlag}=${strValue}`
}

// 计算命令行参数数组
const cmdlineArgs = computed(() => {
  if (!props.task?.options) return []
  
  const args: string[] = []
  const options = props.task.options as Record<string, any>
  
  // 按优先级排序的选项顺序
  const priorityOrder = [
    'requestFile', 'url', 'data',
    'level', 'risk', 'technique',
    'dbms', 'threads', 'timeout',
    'proxy', 'batch'
  ]
  
  // 先添加优先选项
  for (const key of priorityOrder) {
    if (key in options) {
      const arg = optionToArg(key, options[key])
      if (arg) args.push(arg)
    }
  }
  
  // 添加其他选项
  for (const [key, value] of Object.entries(options)) {
    if (priorityOrder.includes(key)) continue
    const arg = optionToArg(key, value)
    if (arg) args.push(arg)
  }
  
  return args
})

// 过滤后的命令行参数
const filteredCmdlineArgs = computed(() => {
  if (!searchQuery.value.trim()) return cmdlineArgs.value
  
  const query = searchQuery.value.toLowerCase().trim()
  return cmdlineArgs.value.filter(arg => 
    arg.toLowerCase().includes(query)
  )
})

// 带语法高亮的完整命令
const highlightedFullCommand = computed(() => {
  const args = searchQuery.value.trim() ? filteredCmdlineArgs.value : cmdlineArgs.value
  if (args.length === 0) return ''
  
  const parts = args.map(arg => {
    // 先进行 HTML 转义
    let escaped = arg
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
    
    // 获取参数类别样式
    const argClass = getArgClass(arg)
    
    // 搜索高亮函数
    const highlightText = (text: string): string => {
      if (!searchQuery.value.trim()) return text
      const query = searchQuery.value.trim()
      const escQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      return text.replace(
        new RegExp(`(${escQuery})`, 'gi'),
        '<mark class="highlight-match">$1</mark>'
      )
    }
    
    // 判断是短参数还是长参数
    const isShortParam = arg.startsWith('-') && !arg.startsWith('--')
    
    // 查找参数名和值的分隔位置
    // 短参数用空格分隔，长参数用等号分隔
    const separator = isShortParam ? ' ' : '='
    const sepIndex = escaped.indexOf(separator)
    
    if (sepIndex > 0) {
      const paramName = escaped.substring(0, sepIndex)
      const paramValue = escaped.substring(sepIndex + 1)
      
      // 构建高亮 HTML
      let result = `<span class="cmd-arg ${argClass}">`
      result += `<span class="arg-name">${highlightText(paramName)}</span>`
      result += isShortParam ? ' ' : `<span class="arg-equals">=</span>`
      
      // 处理引号包裹的值
      if (paramValue.startsWith('&quot;') || paramValue.startsWith('"')) {
        result += `<span class="arg-quoted">${highlightText(paramValue)}</span>`
      } else {
        result += `<span class="arg-value">${highlightText(paramValue)}</span>`
      }
      result += '</span>'
      return result
    } else {
      // 没有分隔符，整个都是参数名（布尔标志）
      return `<span class="cmd-arg ${argClass}"><span class="arg-name">${highlightText(escaped)}</span></span>`
    }
  })
  
  return `<span class="cmd-prefix">python sqlmap.py</span> ${parts.join(' ')}`
})

// 获取参数的CSS类（用于语法高亮）
function getArgClass(arg: string): string {
  // 短参数 (-r, -u, -v 等)
  if (/^-[a-zA-Z]=?/.test(arg)) {
    return 'arg-short'
  }
  // 长参数 (--level, --risk 等)
  if (/^--[a-zA-Z-]+=?/.test(arg)) {
    // 检测/注入相关
    if (/^--(level|risk|technique|dbms|os|prefix|suffix|tamper)/.test(arg)) {
      return 'arg-detection'
    }
    // 性能相关
    if (/^--(threads|timeout|retries|delay|time-sec)/.test(arg)) {
      return 'arg-performance'
    }
    // 枚举相关
    if (/^--(dbs|tables|columns|dump|dump-all)/.test(arg)) {
      return 'arg-enumerate'
    }
    // 代理/网络相关
    if (/^--(proxy|tor|cookie|user-agent|random-agent)/.test(arg)) {
      return 'arg-network'
    }
    return 'arg-long'
  }
  return ''
}

// 复制命令行
function copyCommandLine() {
  const fullCmd = 'python sqlmap.py ' + cmdlineArgs.value.join(' ')
  navigator.clipboard.writeText(fullCmd).then(() => {
    toast.add({
      severity: 'success',
      summary: '已复制',
      detail: `命令行参数已复制到剪贴板 (${cmdlineArgs.value.length} 个参数)`,
      life: 2000,
    })
  }).catch(err => {
    console.error('复制失败:', err)
    toast.add({
      severity: 'error',
      summary: '复制失败',
      detail: '无法访问剪贴板',
      life: 3000,
    })
  })
}

// 格式化配置键名
function formatOptionKey(key: string): string {
  const keyMap: Record<string, string> = {
    level: '检测级别 (Level)',
    risk: '风险级别 (Risk)',
    technique: '注入技术 (Technique)',
    dbms: '数据库类型 (DBMS)',
    threads: '线程数 (Threads)',
    timeout: '超时时间 (Timeout)',
    retries: '重试次数 (Retries)',
    delay: '延迟时间 (Delay)',
    userAgent: 'User-Agent',
    cookie: 'Cookie',
    headers: '请求头 (Headers)',
    proxy: '代理 (Proxy)',
    randomAgent: '随机User-Agent',
    checkTor: '使用Tor',
    safeUrl: '安全URL',
    safePost: '安全POST',
    safeReq: '安全请求',
  }
  return keyMap[key] || key
}

// 格式化配置值
function formatOptionValue(value: any, _key: string): string {
  if (value === null || value === undefined) {
    return '-'
  }

  if (typeof value === 'boolean') {
    return value ? '是' : '否'
  }

  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : '-'
  }

  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2)
  }

  return String(value)
}

// 计算属性：将options转为数组
const optionsArray = computed(() => {
  if (!props.task?.options) return []
  return Object.entries(props.task.options).map(([key, value]) => ({
    key,
    value,
    displayKey: formatOptionKey(key),
    displayValue: formatOptionValue(value, key)
  }))
})

// 计算属性：过滤和排序后的选项
const filteredAndSortedOptions = computed(() => {
  let result = [...optionsArray.value]

  // 搜索过滤
  if (searchQuery.value.trim()) {
    const query = searchQuery.value.toLowerCase().trim()
    result = result.filter(item =>
      item.displayKey.toLowerCase().includes(query) ||
      item.displayValue.toLowerCase().includes(query) ||
      item.key.toLowerCase().includes(query)
    )
  }

  // 排序
  if (sortOrder.value === 'asc') {
    result.sort((a, b) => a.displayKey.localeCompare(b.displayKey, 'zh-CN'))
  } else if (sortOrder.value === 'desc') {
    result.sort((a, b) => b.displayKey.localeCompare(a.displayKey, 'zh-CN'))
  }

  return result
})

// 统计信息
const totalCount = computed(() => optionsArray.value.length)
const filteredCount = computed(() => filteredAndSortedOptions.value.length)

// 高亮匹配文本
function highlightMatch(text: string): string {
  if (!searchQuery.value.trim()) return text
  const query = searchQuery.value.trim()
  const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
  return text.replace(regex, '<mark class="highlight-match">$1</mark>')
}
</script>

<style scoped lang="scss">
.loading-small {
  display: flex;
  justify-content: center;
  padding: 20px;
}

.text-muted {
  color: var(--p-text-muted-color);
  font-style: italic;
  text-align: center;
  padding: 20px;
}

.options-wrapper {
  display: flex;
  flex-direction: column;
  gap: 16px;
  height: 100%;
  min-height: 400px;
}

// 视图切换区域 - 突出显示
.view-switch-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: linear-gradient(135deg, var(--p-primary-50) 0%, var(--p-primary-100) 100%);
  border: 2px solid var(--p-primary-200);
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(99, 102, 241, 0.15);

  .view-switch-tabs {
    display: flex;
    gap: 8px;
    background: var(--p-content-background);
    padding: 4px;
    border-radius: 10px;
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
  }

  .view-tab {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 20px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: var(--p-text-muted-color);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s ease;

    i {
      font-size: 16px;
    }

    &:hover:not(.active) {
      background: var(--p-surface-100);
      color: var(--p-text-color);
    }

    &.active {
      background: var(--p-primary-color);
      color: white;
      box-shadow: 0 2px 8px rgba(99, 102, 241, 0.4);

      i {
        color: white;
      }
    }
  }

  .view-switch-hint {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--p-primary-600);
    opacity: 0.8;

    i {
      font-size: 14px;
    }
  }
}

.options-toolbar {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  padding: 12px 16px;
  background: var(--p-content-background);
  border: 1px solid var(--p-content-border-color);
  border-radius: 8px;

  .search-section {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 200px;
    max-width: 300px;

    .search-field {
      flex: 1;

      :deep(.p-inputicon) {
        display: flex;
        align-items: center;
        top: 50%;
        transform: translateY(-50%);
      }

      .search-input {
        width: 100%;
        padding-left: 2.5rem;
      }
    }
  }

  .sort-section {
    display: flex;
    align-items: center;
    gap: 8px;

    .sort-label {
      font-size: 13px;
      font-weight: 500;
      color: var(--p-text-muted-color);
    }

    :deep(.p-selectbutton) {
      .p-button {
        padding: 6px 12px;
        font-size: 12px;
      }
    }
  }

  .copy-section {
    display: flex;
    align-items: center;
  }

  .stats-section {
    margin-left: auto;

    .stats-info {
      font-size: 12px;
      color: var(--p-text-muted-color);
      display: flex;
      align-items: center;
      gap: 4px;

      i {
        font-size: 14px;
      }
    }
  }
}

.options-table-container {
  background: var(--p-content-background);
  border-radius: 10px;
  padding: 0;
  border: 1px solid var(--p-content-border-color);
  overflow-x: auto;
  // 自适应父容器高度
  flex: 1;
  min-height: 250px;
  max-height: 500px;
  overflow-y: auto;

  &::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  &::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.05);
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(99, 102, 241, 0.3);
    border-radius: 4px;

    &:hover {
      background: rgba(99, 102, 241, 0.5);
    }
  }
}

.options-table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;

  thead {
    position: sticky;
    top: 0;
    z-index: 1;

    tr {
      background: var(--p-surface-100);
    }

    th {
      padding: 12px 16px;
      font-size: 13px;
      font-weight: 600;
      color: var(--p-text-color);
      text-align: left;
      border-bottom: 2px solid var(--p-surface-200);
    }

    .option-key-header {
      cursor: pointer;
      user-select: none;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: background 0.2s;

      &:hover {
        background: var(--p-surface-200);
      }

      i {
        font-size: 12px;
        color: var(--p-text-muted-color);
      }
    }
  }

  tbody {
    tr {
      border-bottom: 1px solid var(--p-surface-100);
      transition: all 0.2s ease;

      &:hover {
        background: var(--p-highlight-background);
      }

      &:last-child {
        border-bottom: none;
      }
    }
  }

  td, th {
    padding: 12px 16px;
    font-size: 14px;
  }
}

.option-key-cell {
  width: 300px;
  font-weight: 600;
  color: var(--p-primary-color);
  background: var(--p-surface-50);
  border-right: 2px solid var(--p-surface-200);
  white-space: nowrap;

  @media (max-width: 768px) {
    width: auto;
    display: block;
    border-right: none;
    border-bottom: 2px solid var(--p-surface-200);
  }
}

.option-value-cell {
  color: var(--p-text-color);
  word-break: break-all;
  background: var(--p-content-background);

  @media (max-width: 768px) {
    display: block;
  }
}

.no-results {
  text-align: center;
  color: var(--p-text-muted-color);
  padding: 32px !important;

  i {
    font-size: 24px;
    margin-bottom: 8px;
    display: block;
  }

  span {
    font-size: 14px;
  }
}

// 命令行视图样式
.cmdline-container {
  background: #1e1e2e;
  border-radius: 10px;
  border: 1px solid var(--p-content-border-color);
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  flex: 1;
  min-height: 200px;
  padding: 20px;
  overflow-y: auto;

  &::-webkit-scrollbar {
    width: 8px;
  }

  &::-webkit-scrollbar-track {
    background: #11111b;
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: #45475a;
    border-radius: 4px;

    &:hover {
      background: #585b70;
    }
  }

  .no-results {
    color: #6c7086;
    background: transparent;
    text-align: center;
    padding: 32px;

    i {
      font-size: 24px;
      margin-bottom: 8px;
      display: block;
    }
  }
}

.cmdline-full {
  font-size: 14px;
  line-height: 2;
  color: #cdd6f4;
  word-break: break-all;
  white-space: pre-wrap;

  // 前缀样式
  :deep(.cmd-prefix) {
    color: #a6e3a1;
    font-weight: 600;
    margin-right: 8px;
  }

  // 参数包装器
  :deep(.cmd-arg) {
    display: inline;
    padding: 2px 0;
    border-radius: 3px;
    
    // 短参数
    &.arg-short .arg-name {
      color: #f9e2af;
    }
    
    // 长参数
    &.arg-long .arg-name {
      color: #89b4fa;
    }
    
    // 检测/注入相关
    &.arg-detection .arg-name {
      color: #f38ba8;
    }
    
    // 性能相关
    &.arg-performance .arg-name {
      color: #a6e3a1;
    }
    
    // 枚举相关
    &.arg-enumerate .arg-name {
      color: #fab387;
    }
    
    // 网络相关
    &.arg-network .arg-name {
      color: #94e2d5;
    }
  }

  // 参数名
  :deep(.arg-name) {
    color: #89b4fa;
    font-weight: 600;
  }

  // 等号
  :deep(.arg-equals) {
    color: #f9e2af;
  }

  // 引号包裹的值
  :deep(.arg-quoted) {
    color: #a6e3a1;
  }

  // 普通值
  :deep(.arg-value) {
    color: #cba6f7;
  }
}

// 高亮匹配样式
:deep(.highlight-match) {
  background: rgba(250, 204, 21, 0.4);
  color: inherit;
  padding: 1px 2px;
  border-radius: 2px;
  font-weight: 600;
}

// 响应式设计
@media (max-width: 768px) {
  .options-toolbar {
    flex-direction: column;
    align-items: stretch;

    .view-switch-section {
      justify-content: flex-start;
    }

    .search-section {
      max-width: none;
    }

    .sort-section {
      justify-content: flex-start;
    }

    .stats-section {
      margin-left: 0;
    }
  }
}
</style>