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
            placeholder="搜索HTTP报文..."
            class="search-input"
          />
          <Button
            v-if="httpRequestSearch"
            icon="pi pi-times"
            text
            rounded
            class="clear-search-btn"
            @click="httpRequestSearch = ''"
          />
        </div>
        <div class="filter-controls">
          <ToggleButton
            v-model="showOnlyMatches"
            onLabel="显示匹配"
            offLabel="显示全部"
            onIcon="pi pi-filter"
            offIcon="pi pi-filter-slash"
            class="p-button-sm"
          />
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
import type { Task } from '@/types/task'
import { formatHttpRequest, highlightHttpRequest, filterHttpRequest } from '@/utils/requestFormatter'

interface Props {
  task: Task
  httpInfo: any
  loadingHttp: boolean
}

const props = defineProps<Props>()

// HTTP请求报文相关状态
const httpRequestSearch = ref('')
const showOnlyMatches = ref(false)
const httpRequestRef = ref<HTMLElement | null>(null)

// 计算属性：格式化HTTP请求报文
const httpRequest = computed(() => {
  if (!props.httpInfo && !props.task) {
    return ''
  }
  return formatHttpRequest(props.httpInfo, props.task)
})

// 计算属性：高亮后的HTTP请求报文HTML
const highlightedHttpRequest = computed(() => {
  if (!httpRequest.value || !httpRequest.value.trim()) {
    return ''
  }

  const lines = httpRequest.value.split('\n')

  // 应用过滤（如果启用）
  const filteredLines = showOnlyMatches.value && httpRequestSearch.value.trim()
    ? filterHttpRequest(lines, httpRequestSearch.value.trim())
    : lines

  // 高亮显示（带搜索关键词高亮）
  return highlightHttpRequest(filteredLines, httpRequestSearch.value.trim())
})
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
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(59, 130, 246, 0.04) 100%);
  border-radius: 8px;
  border: 1px solid rgba(99, 102, 241, 0.15);
  line-height: 0.9;

  .search-box {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 4px;
    position: relative;

    i {
      color: #94a3b8;
      font-size: 14px;
      position: absolute;
      left: 8px;
      pointer-events: none;
    }

    .search-input {
      width: 100%;
      padding: 4px 32px 4px 28px;
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 4px;
      color: #e2e8f0;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 12px;
      line-height: 0.9;

      &:focus {
        outline: none;
        border-color: #6366f1;
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.3);
      }

      &::placeholder {
        color: #64748b;
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

  .filter-controls {
    flex-shrink: 0;

    .p-button-sm {
      padding: 4px 8px;
      font-size: 11px;

      .p-button-label {
        font-size: 11px;
      }
    }
  }
}

.http-request-container {
  max-height: 600px;
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