<template>
  <div class="command-preview">
    <div class="preview-header">
      <span class="preview-title">{{ title }}</span>
      <Button
        v-if="showCopy"
        icon="pi pi-copy"
        text
        rounded
        size="small"
        @click="copyCommand"
        v-tooltip.top="'复制'"
      />
    </div>
    <pre class="preview-content"><code v-html="highlightedCommand"></code></pre>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'

interface Props {
  command: string
  title?: string
  showCopy?: boolean
  highlight?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  title: '命令行预览',
  showCopy: true,
  highlight: true
})

const toast = useToast()

const highlightedCommand = computed(() => {
  if (!props.highlight) {
    return props.command
  }
  
  // 简单的语法高亮
  return props.command
    .replace(/(--[a-zA-Z0-9-]+)/g, '<span class="param">$1</span>')
    .replace(/(-[a-zA-Z0-9])/g, '<span class="flag">$1</span>')
    .replace(/(".*?")/g, '<span class="string">$1</span>')
    .replace(/(\d+)/g, '<span class="number">$1</span>')
})

async function copyCommand() {
  try {
    await navigator.clipboard.writeText(props.command)
    toast.add({
      severity: 'success',
      summary: '已复制',
      detail: '命令已复制到剪贴板',
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

<style scoped>
.command-preview {
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
  overflow: hidden;
}

.preview-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0.75rem;
  background: var(--p-surface-section);
  border-bottom: 1px solid var(--p-surface-border);
}

.preview-title {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--p-text-secondary-color);
}

.preview-content {
  margin: 0;
  padding: 0.75rem;
  background: var(--p-surface-card);
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--p-text-color);
}

.preview-content :deep(.param) {
  color: var(--p-primary-color);
  font-weight: 500;
}

.preview-content :deep(.flag) {
  color: var(--p-primary-color);
  font-weight: 500;
}

.preview-content :deep(.string) {
  color: var(--p-green-500);
}

.preview-content :deep(.number) {
  color: var(--p-orange-500);
}

:deep(.app-dark) .preview-content :deep(.string) {
  color: var(--p-green-400);
}

:deep(.app-dark) .preview-content :deep(.number) {
  color: var(--p-orange-400);
}
</style>
