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

  const escapeHtml = (str: string) =>
    str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

  // 单次扫描正则：按优先级匹配各类 token，避免级联替换污染
  const tokenRegex = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(--[a-zA-Z][a-zA-Z0-9-]*)|(?<=\s|^)(-[a-zA-Z0-9])(?=\s|=|$)|(?<=[\s=])(\d+)(?=[\s,]|$)/g

  const cmd = props.command
  let result = ''
  let lastIndex = 0

  let match: RegExpExecArray | null
  while ((match = tokenRegex.exec(cmd)) !== null) {
    if (match.index > lastIndex) {
      result += escapeHtml(cmd.slice(lastIndex, match.index))
    }

    if (match[1]) {
      result += `<span class="string">${escapeHtml(match[1])}</span>`
    } else if (match[2]) {
      result += `<span class="param">${escapeHtml(match[2])}</span>`
    } else if (match[3]) {
      result += `<span class="flag">${escapeHtml(match[3])}</span>`
    } else if (match[4]) {
      result += `<span class="number">${escapeHtml(match[4])}</span>`
    }

    lastIndex = match.index + match[0].length
  }

  if (lastIndex < cmd.length) {
    result += escapeHtml(cmd.slice(lastIndex))
  }

  return result
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
