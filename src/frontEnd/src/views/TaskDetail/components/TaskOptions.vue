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
        <div class="cmdline-header">
          <span class="cmdline-prefix">sqlmap</span>
        </div>
        <div class="cmdline-content">
          <div v-if="filteredCmdlineArgs.length === 0" class="no-results">
            <i class="pi pi-search"></i>
            <span>未找到匹配的参数</span>
          </div>
          <div v-else class="cmdline-args">
            <span
              v-for="(arg, index) in filteredCmdlineArgs"
              :key="index"
              class="cmdline-arg"
              :class="getArgClass(arg)"
              v-html="highlightCmdlineArg(arg)"
            ></span>
          </div>
        </div>
        <!-- 完整命令预览 -->
        <div class="cmdline-preview">
          <div class="preview-label">
            <i class="pi pi-terminal"></i>
            <span>完整命令</span>
          </div>
          <div class="preview-content">
            <code>sqlmap {{ fullCommandLine }}</code>
          </div>
        </div>
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
  tor: '--tor',
  torType: '--tor-type',
  torPort: '--tor-port',
  
  // 检测相关
  level: '--level',
  risk: '--risk',
  technique: '--technique',
  testParameter: '-p',
  skip: '--skip',
  dbms: '--dbms',
  os: '--os',
  
  // 注入相关
  prefix: '--prefix',
  suffix: '--suffix',
  tamper: '--tamper',
  
  // 枚举相关
  getDbs: '--dbs',
  getTables: '--tables',
  getColumns: '--columns',
  dumpTable: '--dump',
  dumpAll: '--dump-all',
  db: '-D',
  tbl: '-T',
  col: '-C',
  
  // 性能相关
  threads: '--threads',
  timeout: '--timeout',
  retries: '--retries',
  delay: '--delay',
  timeSec: '--time-sec',
  
  // 通用选项
  batch: '--batch',
  verbose: '-v',
  flushSession: '--flush-session',
  freshQueries: '--fresh-queries',
  forms: '--forms',
  crawlDepth: '--crawl',
  
  // 输出相关
  outputDir: '-o',
  csvDel: '--csv-del',
  dumpFormat: '--dump-format',
  
  // 其他
  googlePage: '--google-page',
  disableColoring: '--disable-coloring',
  api: '--api',
  taskid: '--taskid',
  database: '--database',
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
  
  const cmdFlag = optionToCmdMap[key] || `--${key}`
  
  // 布尔值选项
  if (typeof value === 'boolean') {
    return value ? cmdFlag : null
  }
  
  // 数组值
  if (Array.isArray(value)) {
    if (value.length === 0) return null
    return `${cmdFlag}="${value.join(',')}"`
  }
  
  // 字符串或数字
  const strValue = String(value)
  
  // 如果值包含空格或特殊字符，需要引号包裹
  if (strValue.includes(' ') || strValue.includes('\n') || strValue.includes('"')) {
    // 对于多行文本（如headers），使用简化显示
    if (strValue.includes('\n')) {
      const firstLine = strValue.split('\n')[0]
      return `${cmdFlag}="${firstLine}..."`
    }
    return `${cmdFlag}="${strValue}"`
  }
  
  return `${cmdFlag}=${strValue}`
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

// 完整命令行字符串
const fullCommandLine = computed(() => {
  return cmdlineArgs.value.join(' ')
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

// 高亮命令行参数
function highlightCmdlineArg(arg: string): string {
  // 先进行 HTML 转义
  let escaped = arg
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
  
  // 提取参数名和值
  const eqIndex = escaped.indexOf('=')
  
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
  
  if (eqIndex > 0) {
    const paramName = escaped.substring(0, eqIndex)
    const paramValue = escaped.substring(eqIndex + 1)
    
    // 构建高亮 HTML
    let result = `<span class="arg-name">${highlightText(paramName)}</span>`
    result += `<span class="arg-equals">=</span>`
    
    // 处理引号包裹的值
    if (paramValue.startsWith('&quot;') || paramValue.startsWith('"')) {
      result += `<span class="arg-quoted">${highlightText(paramValue)}</span>`
    } else {
      result += `<span class="arg-value">${highlightText(paramValue)}</span>`
    }
    return result
  } else {
    // 没有等号，整个都是参数名
    return `<span class="arg-name">${highlightText(escaped)}</span>`
  }
}

// 复制命令行
function copyCommandLine() {
  const fullCmd = 'sqlmap ' + cmdlineArgs.value.join(' ')
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
  // 自适应父容器高度，减去工具栏高度
  height: calc(100% - 80px);
  min-height: 200px;
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
  overflow: hidden;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
}

.cmdline-header {
  display: flex;
  align-items: center;
  padding: 12px 16px;
  background: #11111b;
  border-bottom: 1px solid #313244;

  .cmdline-prefix {
    color: #89b4fa;
    font-weight: 600;
    font-size: 14px;
    
    &::before {
      content: '$ ';
      color: #a6e3a1;
    }
  }
}

.cmdline-content {
  padding: 16px;
  min-height: 150px;
  max-height: 300px;
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
  }
}

.cmdline-args {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 12px;
  line-height: 1.8;
}

.cmdline-arg {
  display: inline-block;
  padding: 4px 8px;
  background: #313244;
  border-radius: 4px;
  font-size: 13px;
  color: #cdd6f4;
  transition: all 0.2s ease;

  &:hover {
    background: #45475a;
    transform: translateY(-1px);
  }

  // 参数类型颜色
  &.arg-short {
    border-left: 3px solid #f9e2af;
  }

  &.arg-long {
    border-left: 3px solid #89b4fa;
  }

  &.arg-detection {
    border-left: 3px solid #f38ba8;
    background: rgba(243, 139, 168, 0.1);
  }

  &.arg-performance {
    border-left: 3px solid #a6e3a1;
    background: rgba(166, 227, 161, 0.1);
  }

  &.arg-enumerate {
    border-left: 3px solid #fab387;
    background: rgba(250, 179, 135, 0.1);
  }

  &.arg-network {
    border-left: 3px solid #94e2d5;
    background: rgba(148, 226, 213, 0.1);
  }

  // 语法高亮
  :deep(.arg-name) {
    color: #89b4fa;
    font-weight: 600;
  }

  :deep(.arg-equals) {
    color: #f9e2af;
  }

  :deep(.arg-quoted) {
    color: #a6e3a1;
  }
}

.cmdline-preview {
  border-top: 1px solid #313244;
  padding: 12px 16px;
  background: #11111b;

  .preview-label {
    display: flex;
    align-items: center;
    gap: 6px;
    color: #6c7086;
    font-size: 12px;
    margin-bottom: 8px;

    i {
      font-size: 14px;
    }
  }

  .preview-content {
    background: #1e1e2e;
    border-radius: 6px;
    padding: 12px;
    overflow-x: auto;

    code {
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
      font-size: 12px;
      color: #cdd6f4;
      white-space: pre-wrap;
      word-break: break-all;
    }

    &::-webkit-scrollbar {
      height: 6px;
    }

    &::-webkit-scrollbar-track {
      background: #11111b;
      border-radius: 3px;
    }

    &::-webkit-scrollbar-thumb {
      background: #45475a;
      border-radius: 3px;
    }
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