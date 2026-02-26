<template>
  <Dialog 
    :visible="visible"
    @update:visible="$emit('update:visible', $event)"
    header="扫描配置"
    :modal="true"
    :maximizable="true"
    :blockScroll="true"
    :dismissableMask="false"
    :draggable="false"
    :closable="true"
    :style="{ width: '90vw' }"
    :breakpoints="{ '1400px': '95vw', '768px': '98vw' }"
    :contentStyle="{ padding: '1.25rem', overflowY: 'auto', maxHeight: 'calc(90vh - 8rem)' }"
    class="config-dialog"
  >
    <!-- 模式切换栏 -->
    <div class="config-mode-switch-bar">
      <div class="mode-switch-tabs">
        <button
          class="mode-tab"
          :class="{ active: configMode === 'preset' }"
          @click="$emit('update:configMode', 'preset')"
        >
          <i class="pi pi-bookmark"></i>
          <span>使用预设</span>
        </button>
        <button
          class="mode-tab"
          :class="{ active: configMode === 'custom' }"
          @click="$emit('update:configMode', 'custom')"
        >
          <i class="pi pi-sliders-h"></i>
          <span>自定义配置</span>
        </button>
      </div>
      <div class="mode-switch-right">
        <div class="mode-switch-hint">
          <i class="pi pi-info-circle"></i>
          <span>{{ configMode === 'preset' ? '选择一个预设配置' : '手动配置扫描参数' }}</span>
        </div>
        <Button 
          icon="pi pi-refresh" 
          severity="secondary" 
          text 
          rounded 
          size="small"
          @click="$emit('reset')"
          v-tooltip="'重置配置'"
        />
      </div>
    </div>

    <!-- 配置内容区 -->
    <div class="config-content-area">
      <!-- 预设模式 -->
      <PresetModePanel
        v-if="configMode === 'preset'"
        :presetCategory="presetCategory"
        :selectedPresetId="selectedPresetId"
        @update:presetCategory="$emit('update:presetCategory', $event)"
        @select="$emit('presetSelect', $event)"
      />

      <!-- 自定义配置模式 -->
      <CustomModePanel
        v-else
        :options="currentOptions"
        :selectedTechniques="selectedTechniques"
        @update:options="$emit('update:currentOptions', $event)"
        @update:selectedTechniques="$emit('update:selectedTechniques', $event)"
      />
    </div>

    <!-- 参数预览区 -->
    <div class="config-middle-section">
      <div class="param-preview-header">
        <div class="param-preview-title">
          <i class="pi pi-terminal"></i>
          <span>当前扫描参数</span>
        </div>
        <Button 
          icon="pi pi-copy" 
          text 
          rounded 
          size="small"
          @click="copyCommandLine"
          v-tooltip="'复制命令'"
        />
      </div>
      <div class="cmdline-preview-box">
        <span class="cmdline-prefix">sqlmap</span>
        <template v-if="cmdlineArgs.length > 0">
          <span 
            v-for="(arg, index) in cmdlineArgs" 
            :key="index" 
            class="cmdline-arg"
            :class="getArgClass(arg)"
            v-html="formatArg(arg)"
          ></span>
        </template>
        <span v-else class="cmdline-default">(默认参数)</span>
      </div>
    </div>

    <!-- Dialog Footer -->
    <template #footer>
      <div class="dialog-footer">
        <Button 
          label="取消" 
          icon="pi pi-times"
          severity="secondary"
          @click="$emit('update:visible', false)"
        />
        <div class="footer-spacer"></div>
        <Button 
          label="保存为预设" 
          icon="pi pi-save" 
          severity="secondary"
          outlined
          @click="$emit('savePreset')"
          :disabled="configMode !== 'custom'"
          v-tooltip.top="configMode !== 'custom' ? '只有自定义配置模式才能保存为预设' : ''"
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
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'
import PresetModePanel from './PresetModePanel.vue'
import CustomModePanel from './CustomModePanel.vue'
import type { ScanOptions } from '@/types/scanPreset'

interface Props {
  visible: boolean
  configMode: 'preset' | 'custom'
  presetCategory: 'default' | 'common' | 'history'
  selectedPresetId: number | null
  currentOptions: ScanOptions
  selectedTechniques: string[]
  cmdlineArgs: string[]
  canSubmit: boolean
  submitDisabledReason?: string
  submitting: boolean
}

const props = defineProps<Props>()

defineEmits<{
  'update:visible': [value: boolean]
  'update:configMode': [mode: 'preset' | 'custom']
  'update:presetCategory': [category: string]
  'update:selectedPresetId': [id: number | null]
  'update:currentOptions': [options: ScanOptions]
  'update:selectedTechniques': [techniques: string[]]
  presetSelect: [preset: any]
  reset: []
  savePreset: []
  submit: []
}>()

const toast = useToast()

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

function formatArg(arg: string): string {
  const eqIndex = arg.indexOf('=')
  if (eqIndex > 0) {
    const name = arg.substring(0, eqIndex)
    const value = arg.substring(eqIndex + 1)
    return `<span class="arg-name">${name}</span><span class="arg-equals">=</span><span class="arg-value">${value}</span>`
  }
  return `<span class="arg-name">${arg}</span>`
}

function copyCommandLine() {
  const fullCmd = 'sqlmap ' + props.cmdlineArgs.join(' ')
  navigator.clipboard.writeText(fullCmd).then(() => {
    toast.add({
      severity: 'success',
      summary: '已复制',
      detail: `命令行参数已复制到剪贴板`,
      life: 2000
    })
  }).catch(err => {
    console.error('复制失败:', err)
    toast.add({
      severity: 'error',
      summary: '复制失败',
      detail: '无法访问剪贴板',
      life: 3000
    })
  })
}
</script>

<style scoped>
.config-dialog :deep(.p-dialog-content) {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

/* 模式切换栏 */
.config-mode-switch-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: var(--p-surface-100);
  border: 1px solid var(--surface-border);
  border-radius: 12px;
}

.mode-switch-tabs {
  display: flex;
  gap: 8px;
  background: var(--p-content-background);
  padding: 4px;
  border-radius: 10px;
}

.mode-tab {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--p-text-muted-color);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
}

.mode-tab i {
  font-size: 16px;
}

.mode-tab:hover:not(.active) {
  background: var(--p-surface-100);
  color: var(--p-text-color);
}

.mode-tab.active {
  background: var(--p-primary-color);
  color: white;
}

.mode-tab.active i {
  color: white;
}

.mode-switch-right {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.mode-switch-hint {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--p-primary-600);
  opacity: 0.8;
}

.mode-switch-hint i {
  font-size: 14px;
}

/* 配置内容区 */
.config-content-area {
  min-height: 0;
}

/* 参数预览区 */
.config-middle-section {
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  background: var(--surface-ground);
  overflow: hidden;
}

.param-preview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 0.75rem;
  background: var(--surface-card);
  border-bottom: 1px solid var(--surface-border);
}

.param-preview-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
  font-size: 0.85rem;
  color: var(--primary-color);
}

.param-preview-title i {
  font-size: 0.9rem;
}

.cmdline-preview-box {
  background: #1e1e2e;
  padding: 0.75rem 1rem;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.85rem;
  line-height: 1.8;
  overflow-x: auto;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: baseline;
}

.cmdline-prefix {
  color: #89b4fa;
  font-weight: 600;
}

.cmdline-default {
  color: #6c7086;
  font-style: italic;
}

.cmdline-arg {
  display: inline-flex;
  align-items: baseline;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.05);
}

.cmdline-arg.arg-detection { background: rgba(249, 115, 22, 0.15); }
.cmdline-arg.arg-performance { background: rgba(34, 197, 94, 0.15); }
.cmdline-arg.arg-enumerate { background: rgba(168, 85, 247, 0.15); }
.cmdline-arg.arg-network { background: rgba(59, 130, 246, 0.15); }
.cmdline-arg.arg-switch { background: rgba(236, 72, 153, 0.15); }
.cmdline-arg.arg-short { background: rgba(251, 191, 36, 0.15); }

.cmdline-arg :deep(.arg-name) {
  color: #cba6f7;
  font-weight: 500;
}

.cmdline-arg :deep(.arg-equals) {
  color: #6c7086;
  margin: 0 2px;
}

.cmdline-arg :deep(.arg-value) {
  color: #a6e3a1;
}

/* Dialog Footer */
.dialog-footer {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
}

.footer-spacer {
  flex: 1;
}

@media (max-width: 768px) {
  .config-mode-switch-bar {
    flex-direction: column;
    gap: 0.75rem;
    align-items: stretch;
  }

  .mode-switch-right {
    justify-content: space-between;
  }
}
</style>
