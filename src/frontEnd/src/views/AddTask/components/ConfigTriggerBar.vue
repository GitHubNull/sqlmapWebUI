<template>
  <div class="config-trigger-section">
    <div class="config-summary">
      <div class="config-summary-left">
        <i class="pi pi-sliders-h"></i>
        <span class="config-status-label">当前配置:</span>
        <span class="config-status-text">{{ configStatusText }}</span>
      </div>
      <div class="cmdline-preview-inline" v-if="cmdlineArgs.length > 0">
        <span class="cmdline-prefix-inline">sqlmap</span>
        <span 
          v-for="(arg, index) in inlinePreviewArgs" 
          :key="index" 
          class="cmdline-arg-inline"
          :class="getArgClass(arg)"
        >{{ arg }}</span>
        <span v-if="cmdlineArgs.length > 6" class="cmdline-more">... (+{{ cmdlineArgs.length - 6 }})</span>
      </div>
      <div class="cmdline-preview-inline cmdline-default-inline" v-else>
        <span class="cmdline-prefix-inline">sqlmap</span>
        <span class="cmdline-hint">(默认参数)</span>
      </div>
    </div>
    <div class="config-trigger-actions">
      <Button 
        label="配置扫描参数" 
        icon="pi pi-cog" 
        severity="secondary"
        outlined
        @click="$emit('openConfig')"
      />
      <Button 
        label="提交扫描任务" 
        icon="pi pi-send" 
        :loading="submitting"
        :disabled="!canSubmit"
        @click="$emit('submit')"
        v-tooltip.top="!canSubmit ? submitDisabledReason : ''"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import Button from 'primevue/button'

interface Props {
  configStatusText: string
  cmdlineArgs: string[]
  canSubmit: boolean
  submitDisabledReason?: string
  submitting: boolean
}

const props = defineProps<Props>()

defineEmits<{
  openConfig: []
  submit: []
}>()

// 计算属性
const inlinePreviewArgs = computed(() => props.cmdlineArgs.slice(0, 6))

// 方法
function getArgClass(arg: string): string {
  if (/^-[a-zA-Z]=?/.test(arg)) return 'arg-short'
  if (/^--(level|risk|technique|dbms|os|prefix|suffix|tamper)/.test(arg)) return 'arg-detection'
  if (/^--(threads|timeout|retries|delay|time-sec)/.test(arg)) return 'arg-performance'
  if (/^--(banner|current-user|current-db|is-dba|dbs|tables|columns|dump)/.test(arg)) return 'arg-enumerate'
  if (/^--(proxy|tor|cookie|user-agent|random-agent)/.test(arg)) return 'arg-network'
  if (/^--(batch|smart|text-only|forms|flush-session|fresh-queries)/.test(arg)) return 'arg-switch'
  return 'arg-long'
}
</script>

<style scoped>
.config-trigger-section {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.5rem;
  padding: 1rem 1.25rem;
  background: var(--p-surface-50);
  border: 1px solid var(--surface-border);
  border-radius: 10px;
  margin-top: 0.5rem;
}

.config-summary {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.config-summary-left {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.config-summary-left i {
  color: var(--p-primary-color);
  font-size: 1.1rem;
}

.config-status-label {
  font-weight: 500;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}

.config-status-text {
  font-weight: 600;
  color: var(--text-color);
  font-size: 0.85rem;
}

.cmdline-preview-inline {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  align-items: baseline;
  padding: 0.4rem 0.65rem;
  background: #1e1e2e;
  border-radius: 6px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.75rem;
  line-height: 1.5;
  overflow: hidden;
}

.cmdline-prefix-inline {
  color: #89b4fa;
  font-weight: 600;
}

.cmdline-arg-inline {
  padding: 1px 4px;
  border-radius: 3px;
  color: #cba6f7;
}

.cmdline-arg-inline.arg-detection { background: rgba(249, 115, 22, 0.15); }
.cmdline-arg-inline.arg-performance { background: rgba(34, 197, 94, 0.15); }
.cmdline-arg-inline.arg-enumerate { background: rgba(168, 85, 247, 0.15); }
.cmdline-arg-inline.arg-network { background: rgba(59, 130, 246, 0.15); }
.cmdline-arg-inline.arg-switch { background: rgba(236, 72, 153, 0.15); }
.cmdline-arg-inline.arg-short { background: rgba(251, 191, 36, 0.15); }

.cmdline-more {
  color: #6c7086;
  font-style: italic;
}

.cmdline-default-inline {
  opacity: 0.7;
}

.cmdline-hint {
  color: #6c7086;
  font-style: italic;
}

.config-trigger-actions {
  display: flex;
  gap: 0.75rem;
  flex-shrink: 0;
}

@media (max-width: 900px) {
  .config-trigger-section {
    flex-direction: column;
    align-items: stretch;
  }
  
  .config-trigger-actions {
    justify-content: center;
  }
}
</style>
