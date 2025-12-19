<template>
  <div>
    <div v-if="loadingOptions" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="task?.options" class="options-wrapper">
      <!-- 搜索过滤工具栏 -->
      <div class="options-toolbar">
        <div class="search-section">
          <IconField iconPosition="left" class="search-field">
            <InputIcon class="pi pi-search" />
            <InputText
              v-model="searchQuery"
              placeholder="搜索配置项..."
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
        <div class="sort-section">
          <span class="sort-label">排序：</span>
          <SelectButton
            v-model="sortOrder"
            :options="sortOptions"
            optionLabel="label"
            optionValue="value"
            :allowEmpty="false"
          />
        </div>
        <div class="stats-section">
          <span class="stats-info">
            <i class="pi pi-list"></i>
            共 {{ totalCount }} 项，显示 {{ filteredCount }} 项
          </span>
        </div>
      </div>

      <!-- 配置表格 -->
      <div class="options-table-container">
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
    </div>
    <span v-else class="text-muted">无配置信息</span>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import type { Task } from '@/types/task'

interface Props {
  task?: Task | null
  loadingOptions?: boolean
}

const props = defineProps<Props>()

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