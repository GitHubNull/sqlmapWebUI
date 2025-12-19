<template>
  <div>
    <div v-if="loadingLogs" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="logs && Array.isArray(logs) && logs.length > 0" class="logs-wrapper">
      <div class="log-stats">
        <div class="stat-item">
          <i class="pi pi-list"></i>
          <span>总行数：{{ logs.length }}</span>
        </div>
        <div class="stat-item">
          <i class="pi pi-filter"></i>
          <span>INFO: {{ logs.filter(l => l.includes('[INFO]')).length }}</span>
        </div>
        <div class="stat-item">
          <i class="pi pi-exclamation-triangle"></i>
          <span>警告: {{ logs.filter(l => l.includes('[WARNING]')).length }}</span>
        </div>
        <div class="stat-item">
          <i class="pi pi-times-circle"></i>
          <span>错误: {{ logs.filter(l => l.includes('[ERROR]')).length }}</span>
        </div>
      </div>
      <div class="log-actions" style="margin-bottom: 16px;">
        <Button
          v-if="logs && logs.length > 0"
          icon="pi pi-copy"
          :label="'复制全部日志'"
          text
          @click="copyLogsToClipboard"
          class="p-button-sm"
        />
        <Button
          icon="pi pi-refresh"
          :label="'刷新'"
          text
          @click="loadLogs"
          :loading="loadingLogs"
          class="p-button-sm"
        />
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
import { ref, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import { highlightLogContent, getLogStats, type LogStats } from '@/utils/logHighlighter'

interface Props {
  logs: string[] | null
  loadingLogs: boolean
}

interface Emits {
  (e: 'loadLogs'): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()
const toast = useToast()

const logsContainerRef = ref<HTMLElement | null>(null)

// 计算属性：日志统计信息
const logStats = computed<LogStats>(() => {
  return getLogStats(props.logs || [])
})

// 计算属性：高亮后的日志HTML
const highlightedLogsHtml = computed(() => {
  if (!props.logs || props.logs.length === 0) {
    return ''
  }
  return highlightLogContent(props.logs)
})

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

  const logsText = props.logs.join('\n')
  navigator.clipboard.writeText(logsText).then(() => {
    toast.add({
      severity: 'success',
      summary: '成功',
      detail: `已复制 ${props.logs.length} 行日志到剪贴板`,
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
}

.log-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
  padding: 16px;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(59, 130, 246, 0.04) 100%);
  border-radius: 8px;
  border: 1px solid rgba(99, 102, 241, 0.15);
  backdrop-filter: blur(5px);

  .stat-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: #e2e8f0;
    padding: 6px 12px;
    background: rgba(15, 23, 42, 0.4);
    border-radius: 6px;
    border: 1px solid rgba(148, 163, 184, 0.1);

    i {
      font-size: 15px;
      color: #6366f1;
      font-weight: 600;
    }

    span {
      font-weight: 500;
    }
  }
}

.log-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;

  .p-button-sm {
    padding: 4px 8px;
    font-size: 12px;
  }
}

.logs-container {
  max-height: 600px;
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