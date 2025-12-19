<template>
  <div>
    <div v-if="loadingErrors" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="errors && errors.length > 0" class="errors-wrapper">
      <!-- 错误搜索过滤工具栏 -->
      <div class="error-search-toolbar">
        <div class="search-main">
          <IconField iconPosition="left" class="search-input-wrapper">
            <InputIcon class="pi pi-search" />
            <InputText
              v-model="searchQuery"
              placeholder="搜索错误内容..."
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
            v-if="errors && errors.length > 0"
            icon="pi pi-copy"
            label="复制全部"
            @click="copyErrorsToClipboard"
            severity="secondary"
            text
            size="small"
          />
          <Button
            icon="pi pi-sync"
            label="刷新"
            @click="loadErrors"
            :loading="loadingErrors"
            severity="secondary"
            text
            size="small"
          />
        </div>

        <!-- 高级搜索面板 -->
        <div v-if="showAdvancedSearch" class="advanced-search-panel">
          <div class="filter-row">
            <div class="filter-group">
              <Checkbox
                v-model="useRegex"
                binary
                inputId="useRegexError"
              />
              <label for="useRegexError" class="checkbox-label">使用正则表达式</label>
            </div>
            <div class="filter-group">
              <Checkbox
                v-model="caseSensitive"
                binary
                inputId="caseSensitiveError"
              />
              <label for="caseSensitiveError" class="checkbox-label">区分大小写</label>
            </div>
            <div class="filter-group">
              <Checkbox
                v-model="invertMatch"
                binary
                inputId="invertMatchError"
              />
              <label for="invertMatchError" class="checkbox-label">反转匹配</label>
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
            <i class="pi pi-exclamation-triangle"></i>
            共 {{ errors.length }} 条错误，匹配 {{ filteredCount }} 条
          </span>
        </div>
      </div>

      <!-- 错误记录列表 -->
      <div class="errors-container">
        <div 
          v-for="entry in filteredErrors" 
          :key="entry.id" 
          class="error-item"
        >
          <div class="error-line-number">{{ entry.index }}</div>
          <div class="error-content">
            <i class="pi pi-exclamation-circle error-icon"></i>
            <span class="error-text" v-html="highlightError(entry.error)"></span>
          </div>
        </div>
      </div>
    </div>
    <span v-else-if="loadingErrors" class="text-muted">正在加载错误记录...</span>
    <span v-else class="text-muted">无错误记录</span>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { ErrorEntry } from '@/api/task'

interface Props {
  errors: ErrorEntry[]
  loadingErrors: boolean
  filteredErrors: ErrorEntry[]
  searchQuery: string
  caseSensitive: boolean
  useRegex: boolean
  invertMatch: boolean
  showAdvancedSearch: boolean
}

interface Emits {
  (e: 'loadErrors'): void
  (e: 'executeSearch'): void
  (e: 'copyErrorsToClipboard'): void
  (e: 'update:searchQuery', value: string): void
  (e: 'update:caseSensitive', value: boolean): void
  (e: 'update:useRegex', value: boolean): void
  (e: 'update:invertMatch', value: boolean): void
  (e: 'resetFilters'): void
  (e: 'toggleAdvancedSearch'): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

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
  return !!props.searchQuery
})

// 计算属性：活跃的过滤器列表
const activeFilters = computed(() => {
  const filters: { type: string; label: string }[] = []

  if (props.searchQuery) {
    filters.push({ type: 'search', label: `关键词: ${props.searchQuery}` })
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

// 计算属性：过滤后的错误数量
const filteredCount = computed(() => {
  return props.filteredErrors ? props.filteredErrors.length : 0
})

// 高亮错误文本中的搜索关键词
function highlightError(errorText: string): string {
  const query = props.searchQuery.trim()
  if (!query) {
    return escapeHtml(errorText)
  }

  try {
    let regex: RegExp
    if (props.useRegex) {
      const flags = props.caseSensitive ? 'g' : 'gi'
      regex = new RegExp(`(${query})`, flags)
    } else {
      const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const flags = props.caseSensitive ? 'g' : 'gi'
      regex = new RegExp(`(${escapedQuery})`, flags)
    }

    return escapeHtml(errorText).replace(regex, '<mark class="search-highlight">$1</mark>')
  } catch (e) {
    return escapeHtml(errorText)
  }
}

// HTML转义
function escapeHtml(text: string): string {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}

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

function loadErrors() {
  emit('loadErrors')
}

function copyErrorsToClipboard() {
  emit('copyErrorsToClipboard')
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
  display: block;
}

.errors-wrapper {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.error-search-toolbar {
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
        padding-left: 2.5rem;
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
      gap: 24px;

      .filter-group {
        display: flex;
        align-items: center;
        gap: 8px;

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
        color: #ef4444;
      }
    }
  }
}

.errors-container {
  max-height: calc(100vh - 500px);
  min-height: 200px;
  overflow-y: auto;
  border: 2px solid rgba(239, 68, 68, 0.1);
  border-radius: 8px;
  background: linear-gradient(135deg, #fef2f2 0%, #fff5f5 100%);
  box-shadow: inset 0 2px 8px rgba(239, 68, 68, 0.05);

  &::-webkit-scrollbar {
    width: 8px;
  }

  &::-webkit-scrollbar-track {
    background: rgba(239, 68, 68, 0.05);
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(239, 68, 68, 0.3);
    border-radius: 4px;

    &:hover {
      background: rgba(239, 68, 68, 0.5);
    }
  }
}

.error-item {
  display: flex;
  align-items: flex-start;
  padding: 12px 16px;
  border-bottom: 1px solid rgba(239, 68, 68, 0.1);
  transition: background-color 0.2s ease;

  &:hover {
    background: rgba(239, 68, 68, 0.05);
  }

  &:last-child {
    border-bottom: none;
  }

  .error-line-number {
    flex: 0 0 40px;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 12px;
    font-weight: 600;
    color: #ef4444;
    text-align: right;
    padding-right: 12px;
    user-select: none;
  }

  .error-content {
    flex: 1;
    display: flex;
    align-items: flex-start;
    gap: 8px;
    min-width: 0;

    .error-icon {
      flex-shrink: 0;
      font-size: 14px;
      color: #ef4444;
      margin-top: 2px;
    }

    .error-text {
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 13px;
      color: #991b1b;
      line-height: 1.5;
      word-break: break-word;

      :deep(.search-highlight) {
        background: #fef08a;
        color: #92400e;
        padding: 1px 3px;
        border-radius: 2px;
        font-weight: 600;
      }
    }
  }
}
</style>
