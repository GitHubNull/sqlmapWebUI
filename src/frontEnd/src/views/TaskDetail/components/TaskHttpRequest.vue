<template>
  <div>
    <div v-if="loadingHttp" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="!httpRequest || !httpRequest.trim()" class="text-muted">
      无HTTP请求信息
    </div>
    <div v-else class="http-request-wrapper">
      <!-- 工具栏 -->
      <div class="http-request-toolbar">
        <div class="search-box">
          <i class="pi pi-search"></i>
          <input
            v-model="httpRequestSearch"
            type="text"
            :placeholder="useRegex ? '输入正则表达式...' : '搜索HTTP报文...'"
            class="search-input"
            @keyup.enter="executeSearch"
          />
          <Button
            v-if="httpRequestSearch"
            icon="pi pi-times"
            text
            rounded
            class="clear-search-btn"
            @click="clearSearch"
          />
        </div>
        <div class="toolbar-actions">
          <!-- 高级搜索开关 -->
          <Button
            :icon="showAdvancedSearch ? 'pi pi-chevron-up' : 'pi pi-sliders-h'"
            :label="showAdvancedSearch ? '收起' : '高级'"
            text
            size="small"
            @click="showAdvancedSearch = !showAdvancedSearch"
            v-tooltip.top="'高级搜索选项'"
          />
          <!-- 显示匹配切换 -->
          <ToggleButton
            v-model="showOnlyMatches"
            onLabel="匹配行"
            offLabel="全部"
            onIcon="pi pi-filter"
            offIcon="pi pi-filter-slash"
            class="p-button-sm"
          />
          <!-- 复制按钮 -->
          <Button
            icon="pi pi-copy"
            label="复制"
            severity="secondary"
            size="small"
            @click="copyHttpRequest"
            v-tooltip.top="'复制原始HTTP报文'"
          />
        </div>
      </div>

      <!-- 高级搜索面板 -->
      <div v-if="showAdvancedSearch" class="advanced-search-panel">
        <div class="advanced-options">
          <div class="option-item">
            <Checkbox v-model="useRegex" inputId="useRegex" binary />
            <label for="useRegex">正则匹配</label>
          </div>
          <div class="option-item">
            <Checkbox v-model="caseSensitive" inputId="caseSensitive" binary />
            <label for="caseSensitive">大小写敏感</label>
          </div>
          <div class="option-item">
            <Checkbox v-model="invertMatch" inputId="invertMatch" binary />
            <label for="invertMatch">反转过滤</label>
          </div>
        </div>
        <div class="search-stats" v-if="httpRequestSearch">
          <span v-if="regexError" class="regex-error">
            <i class="pi pi-exclamation-triangle"></i> {{ regexError }}
          </span>
          <span v-else class="match-count">
            匹配 {{ matchCount }} 行 / 共 {{ totalLines }} 行
          </span>
        </div>
      </div>

      <!-- HTTP报文显示 -->
      <div class="http-request-container" ref="httpRequestRef">
        <pre class="http-request-pre">
          <code v-html="highlightedHttpRequest"></code>
        </pre>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import type { Task } from '@/types/task'
import { formatHttpRequest, highlightHttpRequest as highlightHttp } from '@/utils/requestFormatter'

interface Props {
  task: Task
  httpInfo: any
  loadingHttp: boolean
}

const props = defineProps<Props>()
const toast = useToast()

// HTTP请求报文相关状态
const httpRequestSearch = ref('')
const showOnlyMatches = ref(false)
const httpRequestRef = ref<HTMLElement | null>(null)

// 高级搜索状态
const showAdvancedSearch = ref(false)
const useRegex = ref(false)
const caseSensitive = ref(false)
const invertMatch = ref(false)
const regexError = ref('')

// 计算属性：格式化HTTP请求报文
const httpRequest = computed(() => {
  if (!props.httpInfo && !props.task) {
    return ''
  }
  return formatHttpRequest(props.httpInfo, props.task)
})

// 计算属性：总行数
const totalLines = computed(() => {
  if (!httpRequest.value) return 0
  return httpRequest.value.split('\n').length
})

// 高级过滤函数
const filterLines = (lines: string[], keyword: string): string[] => {
  if (!keyword.trim()) return lines
  
  regexError.value = ''
  
  let matchFn: (line: string) => boolean
  
  if (useRegex.value) {
    try {
      const flags = caseSensitive.value ? 'g' : 'gi'
      const regex = new RegExp(keyword, flags)
      matchFn = (line: string) => regex.test(line)
    } catch (e: any) {
      regexError.value = '无效的正则表达式: ' + e.message
      return lines
    }
  } else {
    if (caseSensitive.value) {
      matchFn = (line: string) => line.includes(keyword)
    } else {
      const lowerKeyword = keyword.toLowerCase()
      matchFn = (line: string) => line.toLowerCase().includes(lowerKeyword)
    }
  }
  
  // 应用反转过滤
  if (invertMatch.value) {
    return lines.filter(line => !matchFn(line))
  }
  return lines.filter(matchFn)
}

// 计算属性：匹配行数
const matchCount = computed(() => {
  if (!httpRequest.value || !httpRequestSearch.value.trim()) return 0
  const lines = httpRequest.value.split('\n')
  return filterLines(lines, httpRequestSearch.value.trim()).length
})

// 计算属性：高亮后的HTTP请求报文HTML
const highlightedHttpRequest = computed(() => {
  if (!httpRequest.value || !httpRequest.value.trim()) {
    return ''
  }

  const lines = httpRequest.value.split('\n')

  // 应用高级过滤（如果启用）
  const filteredLines = showOnlyMatches.value && httpRequestSearch.value.trim()
    ? filterLines(lines, httpRequestSearch.value.trim())
    : lines

  // 高亮显示（带搜索关键词高亮）
  return highlightHttp(filteredLines, httpRequestSearch.value.trim(), {
    useRegex: useRegex.value,
    caseSensitive: caseSensitive.value
  })
})

// 执行搜索
const executeSearch = () => {
  // 触发搜索时可以添加额外逻辑
}

// 清除搜索
const clearSearch = () => {
  httpRequestSearch.value = ''
  regexError.value = ''
}

// 复制HTTP报文
const copyHttpRequest = async () => {
  if (!httpRequest.value) {
    toast.add({
      severity: 'warn',
      summary: '无内容',
      detail: '没有可复制的HTTP报文',
      life: 2000
    })
    return
  }
  
  try {
    await navigator.clipboard.writeText(httpRequest.value)
    toast.add({
      severity: 'success',
      summary: '复制成功',
      detail: '原始HTTP报文已复制到剪贴板',
      life: 2000
    })
  } catch (err) {
    toast.add({
      severity: 'error',
      summary: '复制失败',
      detail: '无法复制到剪贴板',
      life: 3000
    })
  }
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

.http-request-wrapper {
  display: flex;
  flex-direction: column;
  gap: 4px;
  line-height: 0.8;
}

.http-request-toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: var(--p-content-background);
  border-radius: 8px;
  border: 1px solid var(--p-content-border-color);
  line-height: 0.9;

  .search-box {
    flex: 0 1 50%;
    min-width: 200px;
    display: flex;
    align-items: center;
    gap: 4px;
    position: relative;

    i {
      color: var(--p-text-muted-color);
      font-size: 14px;
      position: absolute;
      left: 8px;
      pointer-events: none;
    }

    .search-input {
      width: 100%;
      padding: 4px 32px 4px 28px;
      background: var(--p-inputtext-background);
      border: 1px solid var(--p-inputtext-border-color);
      border-style: solid;
      border-radius: 4px;
      color: var(--p-inputtext-color);
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 12px;
      line-height: 0.9;

      &:focus {
        outline: none;
        border-color: var(--p-inputtext-focus-border-color);
        box-shadow: var(--p-inputtext-focus-ring-shadow);
      }

      &::placeholder {
        color: var(--p-inputtext-placeholder-color);
      }
    }

    .clear-search-btn {
      position: absolute;
      right: 4px;
      top: 50%;
      transform: translateY(-50%);
      width: 20px;
      height: 20px;
    }
  }

  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;

    .p-button-sm {
      padding: 4px 8px;
      font-size: 11px;
    }
  }
}

.advanced-search-panel {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 16px;
  padding: 10px 12px;
  background: var(--p-surface-100);
  border: 1px solid var(--p-surface-200);
  border-radius: 6px;

  .advanced-options {
    display: flex;
    align-items: center;
    gap: 16px;

    .option-item {
      display: flex;
      align-items: center;
      gap: 6px;

      label {
        font-size: 12px;
        color: var(--p-text-color);
        cursor: pointer;
        user-select: none;
      }
    }
  }

  .search-stats {
    margin-left: auto;
    font-size: 12px;

    .match-count {
      color: var(--p-text-muted-color);
    }

    .regex-error {
      color: var(--p-red-500);
      display: flex;
      align-items: center;
      gap: 4px;

      i {
        font-size: 12px;
      }
    }
  }
}

.http-request-container {
  // 自适应父容器高度，减去工具栏和高级搜索面板高度
  height: calc(100% - 100px);
  min-height: 200px;
  overflow-y: auto;
  overflow-x: auto;
  border: 2px solid rgba(99, 102, 241, 0.1);
  border-radius: 8px;
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.5);
  line-height: 0.9;

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

  * {
    line-height: 0.9 !important;
  }
}

.http-request-pre {
  margin: 0 !important;
  padding: 0 !important;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 22px;
  line-height: 0.9 !important;
  overflow: visible;
  background: transparent;

  code {
    background: transparent;
    padding: 0 !important;
    margin: 0 !important;
    color: #e2e8f0;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    display: block;
    line-height: 0.9 !important;
    font-size: 22px;
  }
}
</style>