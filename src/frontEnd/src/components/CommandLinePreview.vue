<template>
  <div class="terminal-window">
    <div class="terminal-header">
      <div class="traffic-lights">
        <span class="dot red"></span>
        <span class="dot yellow"></span>
        <span class="dot green"></span>
      </div>
      <span class="terminal-title">{{ title }}</span>
      <div class="terminal-actions">
        <button
          v-if="showCopy"
          class="copy-btn"
          @click="copyCommand"
          v-tooltip.top="'复制'"
        >
          <i class="pi pi-copy"></i>
        </button>
      </div>
    </div>
    <div class="terminal-body">
      <pre><code><span class="prompt">$ </span><span v-html="highlightedCommand"></span></code></pre>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
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
/* ===== Terminal Window ===== */
.terminal-window {
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #30363d;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
}

/* ===== Title Bar ===== */
.terminal-header {
  display: flex;
  align-items: center;
  padding: 10px 14px;
  background: #161b22;
  border-bottom: 1px solid #30363d;
}

.traffic-lights {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.traffic-lights .dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.traffic-lights .dot.red {
  background: #ff5f56;
}

.traffic-lights .dot.yellow {
  background: #ffbd2e;
}

.traffic-lights .dot.green {
  background: #27c93f;
}

.terminal-title {
  flex: 1;
  text-align: center;
  font-size: 13px;
  font-weight: 500;
  color: #8b949e;
  user-select: none;
}

.terminal-actions {
  display: flex;
  align-items: center;
  flex-shrink: 0;
}

.copy-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: #8b949e;
  cursor: pointer;
  transition: background 0.2s, color 0.2s;
}

.copy-btn:hover {
  background: #30363d;
  color: #e6edf3;
}

.copy-btn i {
  font-size: 14px;
}

/* ===== Terminal Body ===== */
.terminal-body {
  background: #0d1117;
  padding: 16px;
  overflow-x: auto;
}

.terminal-body pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
}

.terminal-body code {
  font-family: 'JetBrains Mono', 'SF Mono', Monaco, 'Cascadia Code', Consolas, 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
  color: #e6edf3;
}

/* ===== Prompt ===== */
.prompt {
  color: #7ee787;
  font-weight: 600;
  user-select: none;
}

/* ===== Syntax Highlighting - GitHub Dark Default ===== */
.terminal-body :deep(.param) {
  color: #79c0ff;
  font-weight: 500;
}

.terminal-body :deep(.flag) {
  color: #d2a8ff;
  font-weight: 500;
}

.terminal-body :deep(.string) {
  color: #a5d6ff;
}

.terminal-body :deep(.number) {
  color: #ffa657;
}
</style>
