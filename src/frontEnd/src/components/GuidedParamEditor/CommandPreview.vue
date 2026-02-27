<template>
  <div class="command-preview">
    <div class="section-title">
      命令行参数预览
      <span v-if="dangerousCount > 0" class="danger-count">
        <i class="pi pi-exclamation-triangle"></i>
        {{ dangerousCount }} 个危险参数
      </span>
    </div>
    <div class="preview-content" v-html="commandPreviewHtml"></div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { getParamDefinition } from '@/utils/paramDefinitions'

const props = defineProps<{
  params: Record<string, any>
}>()

// 危险参数数量
const dangerousCount = computed(() => {
  let count = 0
  for (const key of Object.keys(props.params)) {
    const param = getParamDefinition(key)
    if (param?.securityLevel === 'danger' || param?.securityLevel === 'warning') {
      count++
    }
  }
  return count
})

// 命令行预览HTML
const commandPreviewHtml = computed(() => {
  const parts: string[] = []
  
  for (const [key, value] of Object.entries(props.params)) {
    const param = getParamDefinition(key)
    const cliName = param?.cliName || `--${key}`
    const isDanger = param?.securityLevel === 'danger'
    const isWarning = param?.securityLevel === 'warning'
    
    // 根据安全级别选择样式类
    let paramClass = 'param'
    if (isDanger) paramClass = 'param-danger'
    else if (isWarning) paramClass = 'param-warning'
    
    if (param?.type === 'boolean') {
      if (value === true) {
        parts.push(`<span class="${paramClass}" title="${param?.description || ''}">${cliName}</span>`)
      }
    } else if (value !== null && value !== undefined && value !== '') {
      const strValue = String(value)
      const escapedValue = escapeHtml(strValue)
      if (strValue.includes(' ') || strValue.includes('"')) {
        parts.push(`<span class="${paramClass}" title="${param?.description || ''}">${cliName}</span>=<span class="value">"${escapedValue}"</span>`)
      } else {
        parts.push(`<span class="${paramClass}" title="${param?.description || ''}">${cliName}</span>=<span class="value">${escapedValue}</span>`)
      }
    }
  }
  
  if (parts.length === 0) {
    return '<span class="empty">暂无参数，请从左侧选择参数添加</span>'
  }
  
  return parts.join(' ')
})

// HTML 转义
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
</script>

<style scoped lang="scss">
.command-preview {
  background: var(--p-surface-900);
  border-radius: 8px;
  overflow: hidden;
}

.section-title {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--p-surface-0);
  background: var(--p-surface-800);
  margin: 0;
  padding: 10px 14px;
  border-bottom: 1px solid var(--p-surface-700);
  font-weight: 600;
  font-size: 13px;
  
  .danger-count {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
    color: var(--p-orange-400);
    font-weight: 400;
  }
}

.preview-content {
  padding: 14px;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 13px;
  line-height: 1.8;
  color: var(--p-surface-0);
  min-height: 50px;
  word-break: break-all;
  
  :deep(.param) { 
    color: var(--p-blue-400); 
    font-weight: bold; 
    cursor: help;
  }
  :deep(.param-danger) { 
    color: var(--p-red-400); 
    font-weight: bold;
    cursor: help;
  }
  :deep(.param-warning) { 
    color: var(--p-orange-400); 
    font-weight: bold;
    cursor: help;
  }
  :deep(.value) { 
    color: var(--p-green-400); 
    font-weight: bold; 
  }
  :deep(.empty) { 
    color: var(--p-surface-400); 
    font-style: italic; 
  }
}
</style>
