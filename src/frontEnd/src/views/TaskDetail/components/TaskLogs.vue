<template>
  <div>
    <div v-if="loadingLogs" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="logs && Array.isArray(logs) && logs.length > 0" class="logs-wrapper">
      <!-- 日志搜索过滤工具栏 -->
      <div class="log-search-toolbar">
        <div class="search-main">
          <IconField iconPosition="left" class="search-input-wrapper">
            <InputIcon class="pi pi-search" />
            <InputText
              v-model="searchQuery"
              placeholder="搜索日志内容..."
              class="search-input"
              @keydown.enter="executeSearch"
            />
          </IconField>
          <Button
            icon="pi pi-search"
            label="搜索"
            @click="executeSearch"
            :disabled="!searchQuery.trim()"
            size="small"
          />
          <Button
            icon="pi pi-filter"
            label="高级搜索"
            @click="toggleAdvancedSearch"
            :severity="showAdvancedSearch ? 'primary' : 'secondary'"
            outlined
            size="small"
          />
          <Button
            icon="pi pi-refresh"
            label="重置"
            @click="resetFilters"
            severity="secondary"
            outlined
            size="small"
          />
          
          <!-- 分隔线 -->
          <div class="toolbar-divider"></div>
          
          <!-- 复制和刷新按钮 -->
          <Button
            v-if="logs && logs.length > 0"
            icon="pi pi-copy"
            label="复制全部"
            @click="copyLogsToClipboard"
            severity="secondary"
            text
            size="small"
          />
          <Button
            icon="pi pi-sync"
            label="刷新"
            @click="loadLogs"
            :loading="loadingLogs"
            severity="secondary"
            text
            size="small"
          />
        </div>

        <!-- 高级搜索面板 -->
        <div v-if="showAdvancedSearch" class="advanced-search-panel">
          <div class="filter-row">
            <div class="filter-group">
              <label class="filter-label">日志级别</label>
              <Select
                v-model="levelFilter"
                :options="levelOptions"
                optionLabel="label"
                optionValue="value"
                placeholder="所有级别"
                class="filter-select"
              />
            </div>
            <div class="filter-group">
              <label class="filter-label">时间范围</label>
              <InputText
                v-model="timeRangeFilter"
                placeholder="例: 2025-12-19 10:00-11:00"
                class="filter-input"
              />
            </div>
            <div class="filter-group">
              <label class="filter-label">日志来源</label>
              <InputText
                v-model="sourceFilter"
                placeholder="例: sqlmap.core"
                class="filter-input"
              />
            </div>
          </div>
          <div class="filter-row">
            <div class="filter-group">
              <Checkbox
                v-model="useRegex"
                binary
                inputId="useRegex"
              />
              <label for="useRegex" class="checkbox-label">使用正则表达式</label>
            </div>
            <div class="filter-group">
              <Checkbox
                v-model="caseSensitive"
                binary
                inputId="caseSensitive"
              />
              <label for="caseSensitive" class="checkbox-label">区分大小写</label>
            </div>
            <div class="filter-group">
              <Checkbox
                v-model="invertMatch"
                binary
                inputId="invertMatch"
              />
              <label for="invertMatch" class="checkbox-label">反转匹配</label>
            </div>
          </div>
        </div>

        <!-- 当前过滤条件标签 -->
        <div v-if="hasActiveFilters" class="filter-tags">
          <span class="filter-tags-title">已应用过滤:</span>
          <Tag
            v-for="filter in activeFilters"
            :key="filter.type"
            :value="filter.label"
            severity="info"
            icon="pi pi-filter"
            :pt="{
              root: { style: 'font-size: 12px; padding: 4px 8px' },
              icon: { style: 'font-size: 12px; margin-right: 4px' }
            }"
          />
        </div>

        <!-- 过滤结果统计 -->
        <div class="filter-stats">
          <span class="stats-info">
            <i class="pi pi-list"></i>
            共 {{ logs.length }} 行，匹配 {{ filteredCount }} 行
          </span>
        </div>
      </div>

      <div class="logs-container" ref="logsContainerRef">
        <pre class="logs-pre">
          <code v-html="highlightedLogsHtml"></code>
        </pre>
      </div>
    </div>
    <span v-else-if="logs === null" class="text-muted">正在加载日志...</span>
    <span v-else class="text-muted">无日志记录</span>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import Select from 'primevue/select'
import { highlightLogContent } from '@/utils/logHighlighter'

interface Props {
  logs: string[] | null
  loadingLogs: boolean
  filteredLogs: string[]
  searchQuery: string
  levelFilter: string | null
  timeRangeFilter: string
  sourceFilter: string
  useRegex: boolean
  caseSensitive: boolean
  invertMatch: boolean
  showAdvancedSearch: boolean
}

interface Emits {
  (e: 'loadLogs'): void
  (e: 'executeSearch'): void
  (e: 'update:searchQuery', value: string): void
  (e: 'update:levelFilter', value: string | null): void
  (e: 'update:timeRangeFilter', value: string): void
  (e: 'update:sourceFilter', value: string): void
  (e: 'update:useRegex', value: boolean): void
  (e: 'update:caseSensitive', value: boolean): void
  (e: 'update:invertMatch', value: boolean): void
  (e: 'resetFilters'): void
  (e: 'toggleAdvancedSearch'): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()
const toast = useToast()

// 日志级别选项
const levelOptions = [
  { label: '所有级别', value: null },
  { label: 'INFO', value: 'INFO' },
  { label: 'WARNING', value: 'WARNING' },
  { label: 'ERROR', value: 'ERROR' },
  { label: 'DEBUG', value: 'DEBUG' },
  { label: 'CRITICAL', value: 'CRITICAL' }
]

// 计算属性：是否显示高级搜索
const showAdvancedSearch = computed({
  get: () => props.showAdvancedSearch,
  set: (_value) => emit('toggleAdvancedSearch')
})

// 计算属性：搜索关键词
const searchQuery = computed({
  get: () => props.searchQuery,
  set: (value) => emit('update:searchQuery', value)
})

// 计算属性：日志级别过滤
const levelFilter = computed({
  get: () => props.levelFilter,
  set: (value) => emit('update:levelFilter', value)
})

// 计算属性：时间范围过滤
const timeRangeFilter = computed({
  get: () => props.timeRangeFilter,
  set: (value) => emit('update:timeRangeFilter', value)
})

// 计算属性：日志来源过滤
const sourceFilter = computed({
  get: () => props.sourceFilter,
  set: (value) => emit('update:sourceFilter', value)
})

// 计算属性：是否使用正则
const useRegex = computed({
  get: () => props.useRegex,
  set: (value) => emit('update:useRegex', value)
})

// 计算属性：是否区分大小写
const caseSensitive = computed({
  get: () => props.caseSensitive,
  set: (value) => emit('update:caseSensitive', value)
})

// 计算属性：是否反转匹配
const invertMatch = computed({
  get: () => props.invertMatch,
  set: (value) => emit('update:invertMatch', value)
})

// 计算属性：是否有活跃的过滤器
const hasActiveFilters = computed(() => {
  return !!props.searchQuery || !!props.levelFilter || !!props.timeRangeFilter || !!props.sourceFilter
})

// 计算属性：活跃的过滤器列表（用于显示标签）
const activeFilters = computed(() => {
  const filters: { type: string; label: string }[] = []

  if (props.searchQuery) {
    filters.push({ type: 'search', label: `关键词: ${props.searchQuery}` })
  }
  if (props.levelFilter) {
    filters.push({ type: 'level', label: `级别: ${props.levelFilter}` })
  }
  if (props.timeRangeFilter) {
    filters.push({ type: 'time', label: `时间: ${props.timeRangeFilter}` })
  }
  if (props.sourceFilter) {
    filters.push({ type: 'source', label: `来源: ${props.sourceFilter}` })
  }
  if (props.useRegex) {
    filters.push({ type: 'regex', label: '正则模式' })
  }
  if (props.caseSensitive) {
    filters.push({ type: 'case', label: '区分大小写' })
  }
  if (props.invertMatch) {
    filters.push({ type: 'invert', label: '反转匹配' })
  }

  return filters
})

// 计算属性：过滤后的日志数量
const filteredCount = computed(() => {
  return props.filteredLogs ? props.filteredLogs.length : 0
})

// 计算属性：高亮后的日志HTML（基于过滤后的日志）
const highlightedLogsHtml = computed(() => {
  if (!props.filteredLogs || props.filteredLogs.length === 0) {
    return ''
  }
  return highlightLogContent(props.filteredLogs)
})

// 执行搜索
function executeSearch() {
  emit('executeSearch')
}

// 切换高级搜索
function toggleAdvancedSearch() {
  emit('toggleAdvancedSearch')
}

// 重置过滤器
function resetFilters() {
  emit('resetFilters')
}


function loadLogs() {
  emit('loadLogs')
}

function copyLogsToClipboard() {
  if (!props.logs || !Array.isArray(props.logs) || props.logs.length === 0) {
    toast.add({
      severity: 'warn',
      summary: '提示',
      detail: '没有日志可复制',
      life: 2000,
    })
    return
  }

  const logsText = props.logs!.join('\n')
  const logCount = props.logs!.length
  navigator.clipboard.writeText(logsText).then(() => {
    toast.add({
      severity: 'success',
      summary: '成功',
      detail: `已复制 ${logCount} 行日志到剪贴板`,
      life: 2000,
    })
  }).catch(err => {
    console.error('复制日志失败:', err)
    toast.add({
      severity: 'error',
      summary: '错误',
      detail: '复制失败',
      life: 2000,
    })
  })
}
</script>

<style scoped lang="scss">
.loading-small {
  display: flex;
  justify-content: center;
  padding: 20px;
}

.text-muted {
  color: #9ca3af;
  font-style: italic;
  text-align: center;
  padding: 20px;
}

.logs-wrapper {
  display: flex;
  flex-direction: column;
  gap: 16px;
  height: 100%;  // 填满父容器高度
  overflow: hidden;  // 防止溢出
}

.log-search-toolbar {
  flex-shrink: 0;  // 不允许工具栏被压缩
  background: var(--p-content-background);
  border-radius: 8px;
  border: 1px solid var(--p-content-border-color);
  backdrop-filter: blur(5px);
  padding: 16px;

  .search-main {
    display: flex;
    gap: 12px;
    align-items: center;
    margin-bottom: 16px;
    flex-wrap: wrap;

    .search-input-wrapper {
      flex: 0 1 300px;
      min-width: 200px;

      // 修复搜索图标垂直对齐
      :deep(.p-inputicon) {
        display: flex;
        align-items: center;
        justify-content: center;
        top: 50%;
        transform: translateY(-50%);
        margin-top: 0;
      }

      .search-input {
        width: 100%;
        border-radius: 6px;
        padding-left: 2.5rem; // 为左侧图标留出空间
      }
    }
    
    .toolbar-divider {
      width: 1px;
      height: 24px;
      background: var(--p-content-border-color);
      margin: 0 4px;
    }
  }

  .advanced-search-panel {
    background: var(--p-surface-100);
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 12px;
    border: 1px solid var(--p-surface-200);

    .filter-row {
      display: flex;
      gap: 16px;
      margin-bottom: 12px;

      &:last-child {
        margin-bottom: 0;
      }

      .filter-group {
        flex: 1;
        display: flex;
        align-items: center;
        gap: 8px;

        .filter-label {
          font-size: 13px;
          font-weight: 500;
          color: var(--p-text-color);
          white-space: nowrap;
          min-width: 60px;
        }

        .filter-select,
        .filter-input {
          flex: 1;
          border-radius: 4px;
          font-size: 12px;
          padding: 6px 8px;
        }

        .checkbox-label {
          font-size: 12px;
          color: var(--p-text-color);
          cursor: pointer;
          margin-left: 4px;
        }
      }
    }
  }

  .filter-tags {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    flex-wrap: wrap;

    .filter-tags-title {
      font-size: 12px;
      font-weight: 500;
      color: var(--p-text-muted-color);
    }
  }

  .filter-stats {
    display: flex;
    align-items: center;
    justify-content: flex-end;

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

.logs-container {
  // 使用flex: 1填充剩余空间，不再使用calc百分比
  flex: 1;
  min-height: 200px;
  overflow-y: auto;
  overflow-x: auto;
  border: 2px solid rgba(99, 102, 241, 0.1);
  border-radius: 8px;
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.5);
  line-height: 0.8;

  &::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  &::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.3);
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(99, 102, 241, 0.5);
    border-radius: 4px;
    border: 1px solid rgba(0, 0, 0, 0.3);

    &:hover {
      background: rgba(99, 102, 241, 0.7);
    }
  }

  // 垂直滚动条
  &::-webkit-scrollbar:vertical {
    width: 8px;
  }

  // 水平滚动条
  &::-webkit-scrollbar:horizontal {
    height: 8px;
  }

  // 消除行间距
  pre {
    line-height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
  }

  * {
    line-height: 0.8 !important;
  }
}

.logs-pre {
  margin: 0 !important;
  padding: 0 !important;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 12px;
  line-height: 0.8 !important;
  overflow: visible;
  background: transparent;

  code {
    background: transparent;
    padding: 0 !important;
    margin: 0 !important;
    color: #e2e8f0;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    display: block;
    line-height: 0.8 !important;
    font-size: 12px;
  }
}
</style>