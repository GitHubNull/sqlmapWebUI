<template>
  <div class="add-task-container">
    <Card>
      <template #title>
        <div class="page-title-row">
          <span>添加扫描任务</span>
        </div>
      </template>
      <template #content>
        <p class="subtitle">从浏览器DevTools复制HTTP请求报文，转换后提交扫描</p>

        <!-- 报文输入区 -->
        <RequestInputPanel
          v-model="inputContent"
          @parse="handleParse"
          @parseError="handleParseError"
          @clear="handleClear"
        />

        <!-- HTTP报文编辑区 -->
        <HttpMessageEditor
          v-model="rawHttpContent"
          :parsedRequest="parsedRequest"
        />

        <!-- 配置触发区 -->
        <ConfigTriggerBar
          :configStatusText="configStatusText"
          :cmdlineArgs="cmdlineArgs"
          :canSubmit="canSubmit"
          :submitDisabledReason="submitDisabledReason"
          :submitting="submitting"
          @openConfig="configDialogVisible = true"
          @submit="submitTask"
        />

        <small class="submit-hint" v-if="!canSubmit && (rawHttpContent.trim() || parsedRequest)">
          {{ submitDisabledReason }}
        </small>
      </template>
    </Card>

    <!-- 扫描配置 Dialog -->
    <ScanConfigDialog
      v-model:visible="configDialogVisible"
      v-model:configMode="configMode"
      v-model:presetCategory="presetCategory"
      v-model:currentOptions="currentOptions"
      v-model:selectedTechniques="selectedTechniques"
      :selectedPresetId="selectedPresetId"
      :cmdlineArgs="cmdlineArgs"
      :canSubmit="canSubmit"
      :submitDisabledReason="submitDisabledReason"
      :submitting="submitting"
      @update:selectedPresetId="selectedPresetId = $event"
      @presetSelect="selectPreset"
      @reset="resetConfig"
      @savePreset="showSavePresetDialog = true"
      @submit="submitTaskFromDialog"
    />

    <!-- 保存预设对话框 -->
    <SavePresetDialog
      v-model:visible="showSavePresetDialog"
      @save="saveAsPreset"
    />

    <!-- 消息提示 -->
    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import Card from 'primevue/card'
import Toast from 'primevue/toast'

// 子组件
import RequestInputPanel from './components/RequestInputPanel.vue'
import HttpMessageEditor from './components/HttpMessageEditor.vue'
import ConfigTriggerBar from './components/ConfigTriggerBar.vue'
import ScanConfigDialog from './components/ScanConfigDialog.vue'
import SavePresetDialog from './components/SavePresetDialog.vue'

import { useScanPresetStore } from '@/stores/scanPreset'
import { 
  extractRequestFromRawHttp,
  type ParsedHttpRequest
} from '@/utils/httpRequestParser'
import { 
  DEFAULT_SCAN_OPTIONS,
  type ScanOptions
} from '@/types/scanPreset'
import { convertOptionToCliArg } from '@/utils/paramDefinitions'
import { request as apiRequest } from '@/api/request'

const router = useRouter()
const toast = useToast()
const presetStore = useScanPresetStore()

// 输入状态
const inputContent = ref('')
const rawHttpContent = ref('')
const parsedRequest = ref<ParsedHttpRequest | null>(null)

// 配置状态
const configMode = ref<'preset' | 'custom'>('preset')
const presetCategory = ref<'default' | 'common' | 'history'>('default')
const selectedPresetId = ref<number | null>(null)
const currentOptions = ref<ScanOptions>({ ...DEFAULT_SCAN_OPTIONS })
const selectedTechniques = ref<string[]>(['B', 'E', 'U', 'S', 'T', 'Q'])

// 提交状态
const submitting = ref(false)

// 对话框状态
const configDialogVisible = ref(false)
const showSavePresetDialog = ref(false)

// 计算属性
const canSubmit = computed(() => {
  if (!rawHttpContent.value.trim() || !parsedRequest.value) {
    return false
  }
  if (configMode.value === 'preset' && !selectedPresetId.value) {
    return false
  }
  return true
})

const submitDisabledReason = computed(() => {
  if (!rawHttpContent.value.trim() || !parsedRequest.value) {
    return '请先输入并解析HTTP报文'
  }
  if (configMode.value === 'preset' && !selectedPresetId.value) {
    return '请先选择一个预设配置'
  }
  return ''
})

// 配置状态摘要文本
const configStatusText = computed(() => {
  if (configMode.value === 'preset') {
    if (selectedPresetId.value) {
      const all = [
        presetStore.defaultPreset,
        ...presetStore.presetConfigs,
        ...presetStore.historyConfigs
      ]
      const preset = all.find(p => p?.id === selectedPresetId.value)
      return preset ? `预设: ${preset.name}` : '自定义配置'
    }
    return '未选择预设'
  }
  return '自定义配置'
})

// 命令行参数数组
const cmdlineArgs = computed(() => {
  const args: string[] = []
  const opts = currentOptions.value
  const defaults = DEFAULT_SCAN_OPTIONS
  
  // 遍历所有选项，使用通用转换函数
  for (const [key, value] of Object.entries(opts)) {
    // 跳过空值
    if (value === null || value === undefined || value === '') continue
    // 跳过 false 布尔值
    if (value === false) continue
    // 跳过等于默认值的参数（batch 除外）
    if (key !== 'batch' && defaults[key as keyof ScanOptions] === value) continue
    
    // 使用通用转换函数
    const arg = convertOptionToCliArg(key, value)
    if (arg) args.push(arg)
  }
  
  return args
})

// 监听技术选择变化
watch(selectedTechniques, (newVal) => {
  currentOptions.value.technique = newVal.join('')
}, { deep: true })

// 事件处理方法
function handleParse(data: ParsedHttpRequest, rawHttp: string) {
  parsedRequest.value = data
  rawHttpContent.value = rawHttp
  toast.add({
    severity: 'success',
    summary: '解析成功',
    detail: '已将报文转换为HTTP格式',
    life: 3000
  })
}

function handleParseError(error: string) {
  toast.add({
    severity: 'error',
    summary: '解析失败',
    detail: error,
    life: 5000
  })
}

function handleClear() {
  inputContent.value = ''
  rawHttpContent.value = ''
  parsedRequest.value = null
}

async function selectPreset(preset: any) {
  if (!preset || !preset.id) return
  
  try {
    selectedPresetId.value = preset.id
    
    if (preset.options && typeof preset.options === 'object') {
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...preset.options }
    } else {
      await presetStore.selectPreset(preset.id)
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...presetStore.currentOptions }
    }
    
    if (currentOptions.value.technique) {
      selectedTechniques.value = currentOptions.value.technique.split('')
    } else {
      selectedTechniques.value = ['B', 'E', 'U', 'S', 'T', 'Q']
    }
    
    toast.add({
      severity: 'success',
      summary: '已选择预设',
      detail: `已应用 "${preset.name}" 配置`,
      life: 2000
    })
  } catch (error) {
    console.error('Failed to apply preset:', error)
    toast.add({
      severity: 'error',
      summary: '应用失败',
      detail: '无法应用预设配置',
      life: 3000
    })
  }
}

function resetConfig() {
  currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
  selectedPresetId.value = null
  selectedTechniques.value = ['B', 'E', 'U', 'S', 'T', 'Q']
}

async function saveAsPreset(name: string, description?: string) {
  const result = await presetStore.saveCurrentAsPreset(name, description)
  
  if (result) {
    toast.add({
      severity: 'success',
      summary: '保存成功',
      detail: `预设 "${name}" 已保存`,
      life: 3000
    })
    showSavePresetDialog.value = false
  } else {
    toast.add({
      severity: 'error',
      summary: '保存失败',
      detail: '无法保存预设配置',
      life: 5000
    })
  }
}

function getEffectiveOptions(): Record<string, any> {
  const result: Record<string, any> = {}
  const defaults = DEFAULT_SCAN_OPTIONS
  
  for (const [key, value] of Object.entries(currentOptions.value)) {
    const defaultValue = (defaults as any)[key]
    if (value !== defaultValue && value !== null && value !== undefined && value !== '') {
      result[key] = value
    }
  }
  
  result.batch = true
  
  return result
}

async function submitTask() {
  if (!canSubmit.value) return
  
  const requestInfo = extractRequestFromRawHttp(rawHttpContent.value)
  if (!requestInfo) {
    toast.add({
      severity: 'error',
      summary: '提交失败',
      detail: '无法解析HTTP报文，请检查格式',
      life: 5000
    })
    return
  }
  
  submitting.value = true
  
  try {
    const taskData = {
      scanUrl: requestInfo.url,
      host: requestInfo.host,
      method: requestInfo.method,
      headers: requestInfo.headers,
      body: requestInfo.body,
      options: getEffectiveOptions()
    }
    
    await apiRequest.post('/web/admin/task/add', taskData)
    
    const urlPath = requestInfo.url.split('?')[0] || ''
    const hostPart = requestInfo.host && urlPath ? urlPath.split(requestInfo.host)[1] : ''
    const historyName = `${requestInfo.method} ${requestInfo.host}${hostPart || '/'}`
    await presetStore.addToHistory(historyName.substring(0, 50))
    
    toast.add({
      severity: 'success',
      summary: '提交成功',
      detail: '扫描任务已创建',
      life: 3000
    })
    
    router.push('/tasks').catch(() => {})
    
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '提交失败',
      detail: error.message || '创建扫描任务失败',
      life: 5000
    })
  } finally {
    submitting.value = false
  }
}

async function submitTaskFromDialog() {
  await submitTask()
}

onMounted(async () => {
  try {
    await presetStore.loadConfigOptions()
    if (presetStore.defaultPreset) {
      selectedPresetId.value = presetStore.defaultPreset.id || null
    }
  } catch (error) {
    console.error('Failed to load config options:', error)
    currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
  }
})
</script>

<style scoped>
.add-task-container {
  width: 100%;
  margin: 0;
  padding: 0;
}

.page-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.subtitle {
  margin: 0 0 1rem 0;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}

.submit-hint {
  display: block;
  text-align: right;
  color: var(--text-color-secondary);
  margin-top: 0.5rem;
  font-size: 0.8rem;
}
</style>
