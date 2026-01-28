<template>
  <div class="default-config-panel">
    <div class="panel-container">
      <!-- 上半部分：左右布局 -->
      <div class="top-section">
        <!-- 左侧：扫描参数 -->
        <div class="left-panel">
          <div class="section-title">扫描参数</div>
          <div class="param-grid">
            <!-- Level -->
            <div class="param-row">
              <label>Level (1-5):</label>
              <InputNumber v-model="options.level" :min="1" :max="5" :showButtons="true" buttonLayout="horizontal" class="param-input" @input="updatePreview" />
              <span class="param-desc">检测级别</span>
            </div>
            <!-- Risk -->
            <div class="param-row">
              <label>Risk (1-3):</label>
              <InputNumber v-model="options.risk" :min="1" :max="3" :showButtons="true" buttonLayout="horizontal" class="param-input" @input="updatePreview" />
              <span class="param-desc">风险级别</span>
            </div>
            <!-- DBMS -->
            <div class="param-row">
              <label>DBMS:</label>
              <Select v-model="options.dbms" :options="dbmsOptions" optionLabel="label" optionValue="value" placeholder="自动检测" class="param-select" @change="updatePreview" />
              <span class="param-desc">数据库类型</span>
            </div>
            <!-- Technique -->
            <div class="param-row">
              <label>Technique:</label>
              <InputText v-model="techniqueDisplay" disabled class="param-input technique-display" />
            </div>
            <!-- Technique Checkboxes -->
            <div class="technique-checkboxes">
              <label v-for="tech in techniqueOptions" :key="tech.value" class="tech-checkbox" :title="tech.title">
                <Checkbox :modelValue="isTechSelected(tech.value)" :binary="true" @change="toggleTech(tech.value)" />
                <span>{{ tech.value }}</span>
              </label>
            </div>
            <!-- Proxy -->
            <div class="param-row">
              <label>HTTP代理:</label>
              <InputText v-model="options.proxy" placeholder="http://127.0.0.1:8080" class="param-input-wide" @input="updatePreview" />
            </div>
            <!-- Force SSL -->
            <div class="param-row">
              <label>强制SSL:</label>
              <Checkbox v-model="options.forceSSL" :binary="true" @change="updatePreview" />
              <span class="checkbox-label">启用</span>
            </div>
            <!-- Batch -->
            <div class="param-row">
              <label>Batch模式:</label>
              <Checkbox v-model="options.batch" :binary="true" @change="updatePreview" />
              <span class="checkbox-label">启用</span>
            </div>
          </div>
        </div>

        <!-- 右侧：扫描配置来源选择 -->
        <div class="right-panel">
          <div class="section-title">右键菜单扫描使用的配置</div>
          <div class="config-source">
            <!-- 使用默认配置 -->
            <div class="source-option">
              <RadioButton v-model="configSource" value="default" inputId="source_default" />
              <label for="source_default">使用默认配置</label>
            </div>
            <div class="source-desc">使用左侧配置的参数进行扫描</div>

            <!-- 使用常用配置 -->
            <div class="source-option">
              <RadioButton v-model="configSource" value="preset" inputId="source_preset" :disabled="presetList.length === 0" />
              <label for="source_preset">使用常用配置</label>
            </div>
            <Select 
              v-model="selectedPreset" 
              :options="presetList" 
              optionLabel="name" 
              optionValue="id"
              placeholder="选择配置"
              class="preset-select"
              :disabled="configSource !== 'preset' || presetList.length === 0"
            />

            <!-- 使用最近历史配置 -->
            <div class="source-option">
              <RadioButton v-model="configSource" value="history" inputId="source_history" :disabled="!hasHistory" />
              <label for="source_history">使用最近历史配置</label>
            </div>
            <div class="source-desc">使用最近一次扫描的参数配置</div>

            <Button label="刷新配置列表" icon="pi pi-refresh" size="small" severity="secondary" class="refresh-btn" @click="refreshConfigList" />
          </div>

          <Divider />

          <!-- 批量扫描选项 -->
          <div class="batch-options">
            <div class="section-subtitle">批量扫描选项</div>
            <div class="option-row">
              <Checkbox v-model="autoDedupe" :binary="true" />
              <label>自动过滤重复请求</label>
            </div>
            <div class="option-desc">判断标准: 协议/方法/主机/端口/Path/参数</div>
          </div>
        </div>
      </div>

      <!-- 按钮栏 -->
      <div class="button-bar">
        <div class="persist-option">
          <Checkbox v-model="persistArgs" :binary="true" />
          <label>参数持久化</label>
        </div>
        <Button label="保存默认配置" icon="pi pi-save" @click="saveDefaultConfig" />
        <Button label="恢复初始值" icon="pi pi-refresh" severity="secondary" @click="resetConfig" />
      </div>

      <!-- 命令行参数预览 -->
      <div class="preview-section">
        <div class="section-title">命令行参数预览</div>
        <div class="command-preview" v-html="commandPreviewHtml"></div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Checkbox from 'primevue/checkbox'
import RadioButton from 'primevue/radiobutton'
import Button from 'primevue/button'
import Divider from 'primevue/divider'
import type { ScanOptions, ScanPreset } from '@/types/scanPreset'
import { DEFAULT_SCAN_OPTIONS, DBMS_OPTIONS } from '@/types/scanPreset'
import { useScanPresetStore } from '@/stores/scanPreset'

const emit = defineEmits<{
  'update:options': [options: ScanOptions]
}>()

const toast = useToast()
const scanPresetStore = useScanPresetStore()

// 扫描参数
const options = ref<ScanOptions>({ ...DEFAULT_SCAN_OPTIONS })

// DBMS选项
const dbmsOptions = DBMS_OPTIONS

// 注入技术选项
const techniqueOptions = [
  { value: 'B', title: 'Boolean-based blind - 布尔型盲注' },
  { value: 'E', title: 'Error-based - 报错注入' },
  { value: 'U', title: 'UNION query-based - 联合查询注入' },
  { value: 'S', title: 'Stacked queries - 堆叠查询注入' },
  { value: 'T', title: 'Time-based blind - 时间盲注' },
  { value: 'Q', title: 'Inline queries - 内联查询注入' },
]

// 配置来源
const configSource = ref('default')
const selectedPreset = ref<number | null>(null)
const presetList = ref<ScanPreset[]>([])
const hasHistory = ref(false)

// 批量选项
const autoDedupe = ref(true)
const persistArgs = ref(true)

// 计算technique显示
const techniqueDisplay = computed(() => options.value.technique || 'BEUSTQ')

// 检查技术是否选中
function isTechSelected(tech: string): boolean {
  return (options.value.technique || '').includes(tech)
}

// 切换技术选择
function toggleTech(tech: string) {
  let current = options.value.technique || ''
  if (current.includes(tech)) {
    current = current.replace(tech, '')
  } else {
    // 按顺序添加
    const order = 'BEUSTQ'
    let result = ''
    for (const c of order) {
      if (c === tech || current.includes(c)) {
        result += c
      }
    }
    current = result
  }
  options.value.technique = current || 'BEUSTQ'
  updatePreview()
}

// 命令行预览HTML
const commandPreviewHtml = computed(() => {
  const parts: string[] = []
  
  if (options.value.level && options.value.level !== 1) {
    parts.push(`<span class="param">--level</span>=<span class="value">${options.value.level}</span>`)
  }
  if (options.value.risk && options.value.risk !== 1) {
    parts.push(`<span class="param">--risk</span>=<span class="value">${options.value.risk}</span>`)
  }
  if (options.value.dbms) {
    parts.push(`<span class="param">--dbms</span>=<span class="value">${options.value.dbms}</span>`)
  }
  if (options.value.technique && options.value.technique !== 'BEUSTQ') {
    parts.push(`<span class="param">--technique</span>=<span class="value">${options.value.technique}</span>`)
  }
  if (options.value.proxy) {
    parts.push(`<span class="param">--proxy</span>=<span class="value">${options.value.proxy}</span>`)
  }
  if (options.value.forceSSL) {
    parts.push(`<span class="flag">--force-ssl</span>`)
  }
  if (options.value.batch) {
    parts.push(`<span class="flag">--batch</span>`)
  }
  
  if (parts.length === 0) {
    return '<span class="empty">（使用默认参数，无额外命令行选项）</span>'
  }
  
  return parts.join(' ')
})

// 更新预览
function updatePreview() {
  emit('update:options', { ...options.value })
}

// 刷新配置列表
async function refreshConfigList() {
  await scanPresetStore.loadConfigOptions()
  presetList.value = scanPresetStore.presets
  hasHistory.value = scanPresetStore.history.length > 0
  toast.add({ severity: 'info', summary: '已刷新', detail: '配置列表已更新', life: 2000 })
}

// 保存默认配置
async function saveDefaultConfig() {
  try {
    await scanPresetStore.updateDefaultPreset(options.value)
    toast.add({ severity: 'success', summary: '保存成功', detail: '默认配置已保存', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: '保存失败', life: 3000 })
  }
}

// 重置配置
function resetConfig() {
  options.value = { ...DEFAULT_SCAN_OPTIONS }
  updatePreview()
  toast.add({ severity: 'info', summary: '已重置', detail: '已恢复为默认配置', life: 2000 })
}

// 初始化
onMounted(async () => {
  await scanPresetStore.loadConfigOptions()
  presetList.value = scanPresetStore.presets
  hasHistory.value = scanPresetStore.history.length > 0
  
  if (scanPresetStore.defaultPreset) {
    options.value = { ...DEFAULT_SCAN_OPTIONS, ...scanPresetStore.defaultPreset.options }
  }
})
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.default-config-panel {
  padding: 16px;
}

.panel-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.top-section {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

.left-panel, .right-panel {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.7) 100%);
  border: 1px solid rgba(226, 232, 240, 0.5);
  border-radius: var(--p-border-radius);
  padding: 16px;
}

.section-title {
  font-weight: 600;
  font-size: 15px;
  color: var(--p-text-color);
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 2px solid var(--p-primary-color);
}

.section-subtitle {
  font-weight: 600;
  font-size: 14px;
  color: var(--p-text-color);
  margin-bottom: 12px;
}

.param-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.param-row {
  display: flex;
  align-items: center;
  gap: 10px;
  
  > label {
    min-width: 100px;
    font-size: 13px;
    font-weight: 500;
    color: var(--p-text-color);
  }
  
  .param-desc {
    font-size: 12px;
    color: var(--p-text-color)-secondary;
  }
  
  .checkbox-label {
    font-size: 13px;
    color: var(--p-text-color);
  }
}

.param-input {
  width: 100px;
}

.param-input-wide {
  flex: 1;
  max-width: 250px;
}

.param-select {
  width: 180px;
}

.technique-display {
  background: #f1f5f9 !important;
}

.technique-checkboxes {
  display: flex;
  gap: 12px;
  margin-left: 110px;
  flex-wrap: wrap;
  
  .tech-checkbox {
    display: flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    
    span {
      font-size: 13px;
      font-weight: 500;
    }
  }
}

.config-source {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.source-option {
  display: flex;
  align-items: center;
  gap: 8px;
  
  label {
    font-size: 14px;
    cursor: pointer;
  }
}

.source-desc {
  font-size: 12px;
  color: var(--p-text-color)-secondary;
  margin-left: 28px;
  margin-bottom: 8px;
}

.preset-select {
  width: 100%;
  margin-left: 28px;
  margin-bottom: 8px;
}

.refresh-btn {
  margin-top: 8px;
  align-self: center;
}

.batch-options {
  .option-row {
    display: flex;
    align-items: center;
    gap: 8px;
    
    label {
      font-size: 14px;
    }
  }
  
  .option-desc {
    font-size: 12px;
    color: var(--p-text-color)-secondary;
    margin-left: 28px;
    margin-top: 4px;
  }
}

.button-bar {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  padding: 12px;
  background: rgba(248, 250, 252, 0.5);
  border-radius: var(--p-border-radius);
  
  .persist-option {
    display: flex;
    align-items: center;
    gap: 6px;
    
    label {
      font-size: 14px;
    }
  }
}

.preview-section {
  background: #1e1e1e;
  border-radius: var(--p-border-radius);
  overflow: hidden;
  
  .section-title {
    color: #d4d4d4;
    background: #2d2d2d;
    margin: 0;
    padding: 12px 16px;
    border-bottom: 1px solid #3d3d3d;
  }
  
  .command-preview {
    padding: 16px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    line-height: 1.8;
    color: #d4d4d4;
    min-height: 60px;
    
    :deep(.param) {
      color: #2980b9;
      font-weight: bold;
    }
    
    :deep(.value) {
      color: #27ae60;
      font-weight: bold;
    }
    
    :deep(.flag) {
      color: #8e44ad;
      font-weight: bold;
    }
    
    :deep(.empty) {
      color: #888;
    }
  }
}
</style>
