<template>
  <div class="add-task-container">
    <div class="page-header">
      <h2>添加扫描任务</h2>
      <p class="subtitle">从浏览器DevTools复制HTTP请求报文，转换后提交扫描</p>
    </div>

    <div class="content-wrapper">
      <!-- 左侧：报文输入和编辑 -->
      <div class="left-panel">
        <!-- 格式输入区域 -->
        <Card class="input-card">
          <template #title>
            <div class="card-title-row">
              <span>报文输入</span>
              <div class="format-indicator" v-if="detectedFormat !== 'unknown'">
                <Tag :severity="formatSeverity">{{ formatDisplayName }}</Tag>
              </div>
            </div>
          </template>
          <template #content>
            <Textarea
              v-model="inputContent"
              :placeholder="inputPlaceholder"
              rows="8"
              class="input-textarea"
              @input="onInputChange"
            />
            <div class="input-actions">
              <Button 
                label="解析转换" 
                icon="pi pi-sync" 
                @click="parseInput"
                :disabled="!inputContent.trim()"
              />
              <Button 
                label="清空" 
                icon="pi pi-trash" 
                severity="secondary"
                @click="clearInput"
              />
            </div>
          </template>
        </Card>

        <!-- HTTP报文编辑器 -->
        <Card class="editor-card">
          <template #title>
            <div class="card-title-row">
              <span>HTTP报文编辑</span>
              <Tag severity="info" v-tooltip="'在参数值中添加 * 标记注入点'">
                <i class="pi pi-info-circle"></i> 使用 * 标记注入点
              </Tag>
            </div>
          </template>
          <template #content>
            <Textarea
              v-model="rawHttpContent"
              :placeholder="httpPlaceholder"
              rows="12"
              class="http-textarea"
              :class="{ 'has-content': rawHttpContent.trim() }"
            />
            <div class="editor-status" v-if="parsedRequest">
              <span class="status-item">
                <i class="pi pi-globe"></i>
                {{ parsedRequest.method }} {{ parsedRequest.host }}
              </span>
              <span class="status-item">
                <i class="pi pi-link"></i>
                {{ parsedRequest.path }}
              </span>
            </div>
          </template>
        </Card>
      </div>

      <!-- 右侧：扫描配置 -->
      <div class="right-panel">
        <!-- 配置预设选择 -->
        <Card class="config-card">
          <template #title>
            <div class="card-title-row">
              <span>扫描配置</span>
              <Button 
                icon="pi pi-refresh" 
                severity="secondary" 
                text 
                rounded 
                size="small"
                @click="resetConfig"
                v-tooltip="'重置配置'"
              />
            </div>
          </template>
          <template #content>
            <!-- 配置预设 -->
            <div class="config-group">
              <label>配置预设</label>
              <Select
                v-model="selectedPresetId"
                :options="presetOptions"
                optionLabel="label"
                optionValue="value"
                optionDisabled="disabled"
                placeholder="选择配置预设"
                class="w-full"
                @change="onPresetChange"
              />
            </div>

            <!-- Detection 检测选项 -->
            <Fieldset legend="检测选项" :toggleable="true" :collapsed="false" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item">
                  <label>检测等级 (Level)</label>
                  <Select
                    v-model="currentOptions.level"
                    :options="LEVEL_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>风险等级 (Risk)</label>
                  <Select
                    v-model="currentOptions.risk"
                    :options="RISK_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-grid">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.smart" inputId="smart" binary />
                  <label for="smart">智能检测 (--smart)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.textOnly" inputId="textOnly" binary />
                  <label for="textOnly">仅文本比较 (--text-only)</label>
                </div>
              </div>
            </Fieldset>

            <!-- Injection 注入选项 -->
            <Fieldset legend="注入选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item">
                  <label>目标数据库 (DBMS)</label>
                  <Select
                    v-model="currentOptions.dbms"
                    :options="DBMS_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    placeholder="自动检测"
                    showClear
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>操作系统 (OS)</label>
                  <Select
                    v-model="currentOptions.os"
                    :options="OS_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    placeholder="自动检测"
                    showClear
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-item full-width">
                <label>测试参数 (-p)</label>
                <InputText 
                  v-model="currentOptions.testParameter" 
                  placeholder="指定测试参数，如: id,name" 
                  class="w-full"
                />
              </div>
              <div class="config-item full-width">
                <label>跳过参数 (--skip)</label>
                <InputText 
                  v-model="currentOptions.skip" 
                  placeholder="跳过测试的参数，如: token,csrf" 
                  class="w-full"
                />
              </div>
              <div class="config-grid">
                <div class="config-item">
                  <label>注入前缀 (--prefix)</label>
                  <InputText 
                    v-model="currentOptions.prefix" 
                    placeholder="如: '" 
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>注入后缀 (--suffix)</label>
                  <InputText 
                    v-model="currentOptions.suffix" 
                    placeholder="如: -- -" 
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-item full-width">
                <label>Tamper脚本 (--tamper)</label>
                <InputText 
                  v-model="currentOptions.tamper" 
                  placeholder="如: space2comment,randomcase" 
                  class="w-full"
                />
              </div>
            </Fieldset>

            <!-- Techniques 技术选项 -->
            <Fieldset legend="技术选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-item full-width">
                <label>注入技术 (--technique)</label>
                <div class="technique-checkboxes">
                  <div v-for="tech in TECHNIQUE_ITEMS" :key="tech.value" class="technique-item">
                    <Checkbox 
                      v-model="selectedTechniques" 
                      :inputId="'tech-' + tech.value" 
                      :value="tech.value" 
                    />
                    <label :for="'tech-' + tech.value">{{ tech.label }}</label>
                  </div>
                </div>
              </div>
              <div class="config-item">
                <label>时间盲注延迟 (--time-sec)</label>
                <InputNumber
                  v-model="currentOptions.timeSec"
                  :min="1"
                  :max="60"
                  suffix=" 秒"
                  showButtons
                  class="w-full"
                />
              </div>
            </Fieldset>

            <!-- Request 请求选项 -->
            <Fieldset legend="请求选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item">
                  <label>线程数 (--threads)</label>
                  <InputNumber
                    v-model="currentOptions.threads"
                    :min="1"
                    :max="10"
                    showButtons
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>超时时间 (--timeout)</label>
                  <InputNumber
                    v-model="currentOptions.timeout"
                    :min="1"
                    :max="300"
                    suffix=" 秒"
                    showButtons
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-grid">
                <div class="config-item">
                  <label>重试次数 (--retries)</label>
                  <InputNumber
                    v-model="currentOptions.retries"
                    :min="0"
                    :max="10"
                    showButtons
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>请求延迟 (--delay)</label>
                  <InputNumber
                    v-model="currentOptions.delay"
                    :min="0"
                    :max="60"
                    suffix=" 秒"
                    showButtons
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-grid">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.randomAgent" inputId="randomAgent" binary />
                  <label for="randomAgent">随机User-Agent</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.tor" inputId="tor" binary />
                  <label for="tor">使用Tor代理</label>
                </div>
              </div>
              <div class="config-item full-width">
                <label>代理 (--proxy)</label>
                <InputText 
                  v-model="currentOptions.proxy" 
                  placeholder="如: http://127.0.0.1:8080" 
                  class="w-full"
                />
              </div>
            </Fieldset>

            <!-- Enumeration 枚举选项 -->
            <Fieldset legend="枚举选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="enum-checkboxes">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getBanner" inputId="getBanner" binary />
                  <label for="getBanner">获取Banner (--banner)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getCurrentUser" inputId="getCurrentUser" binary />
                  <label for="getCurrentUser">当前用户 (--current-user)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getCurrentDb" inputId="getCurrentDb" binary />
                  <label for="getCurrentDb">当前数据库 (--current-db)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.isDba" inputId="isDba" binary />
                  <label for="isDba">是否DBA (--is-dba)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getDbs" inputId="getDbs" binary />
                  <label for="getDbs">获取所有数据库 (--dbs)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getTables" inputId="getTables" binary />
                  <label for="getTables">获取所有表 (--tables)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getColumns" inputId="getColumns" binary />
                  <label for="getColumns">获取所有列 (--columns)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.dumpTable" inputId="dumpTable" binary />
                  <label for="dumpTable">导出表数据 (--dump)</label>
                </div>
              </div>
            </Fieldset>

            <!-- General 通用选项 -->
            <Fieldset legend="通用选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.batch" inputId="batch" binary />
                  <label for="batch">批处理模式 (--batch)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.forms" inputId="forms" binary />
                  <label for="forms">解析表单 (--forms)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.flushSession" inputId="flushSession" binary />
                  <label for="flushSession">刷新会话 (--flush-session)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.freshQueries" inputId="freshQueries" binary />
                  <label for="freshQueries">刷新查询 (--fresh-queries)</label>
                </div>
              </div>
              <div class="config-item">
                <label>详细级别 (--verbose)</label>
                <Select
                  v-model="currentOptions.verbose"
                  :options="VERBOSE_OPTIONS"
                  optionLabel="label"
                  optionValue="value"
                  class="w-full"
                />
              </div>
            </Fieldset>

            <!-- 提交按钮 -->
            <div class="submit-section">
              <Button 
                label="保存为预设" 
                icon="pi pi-save" 
                severity="secondary"
                @click="showSavePresetDialog = true"
                class="save-preset-btn"
              />
              <Button 
                label="提交扫描任务" 
                icon="pi pi-send" 
                class="submit-btn"
                :loading="submitting"
                :disabled="!canSubmit"
                @click="submitTask"
              />
            </div>
            <small class="submit-hint" v-if="!canSubmit">
              请先输入并解析HTTP报文
            </small>
          </template>
        </Card>
      </div>
    </div>

    <!-- 保存预设对话框 -->
    <Dialog 
      v-model:visible="showSavePresetDialog" 
      header="保存为预设" 
      :modal="true"
      :style="{ width: '400px' }"
    >
      <div class="dialog-content">
        <div class="field">
          <label for="presetName">预设名称 *</label>
          <InputText id="presetName" v-model="newPresetName" class="w-full" />
        </div>
        <div class="field">
          <label for="presetDesc">描述（可选）</label>
          <Textarea id="presetDesc" v-model="newPresetDescription" rows="3" class="w-full" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" @click="showSavePresetDialog = false" />
        <Button label="保存" @click="saveAsPreset" :disabled="!newPresetName.trim()" />
      </template>
    </Dialog>

    <!-- 消息提示 -->
    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import Card from 'primevue/card'
import Button from 'primevue/button'
import Textarea from 'primevue/textarea'
import Select from 'primevue/select'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Checkbox from 'primevue/checkbox'
import Fieldset from 'primevue/fieldset'
import Tag from 'primevue/tag'
import Dialog from 'primevue/dialog'
import Toast from 'primevue/toast'

import { useScanPresetStore } from '@/stores/scanPreset'
import { 
  parseHttpRequest, 
  detectFormat, 
  getFormatDisplayName,
  extractRequestFromRawHttp,
  type ParsedHttpRequest,
  type RequestFormat
} from '@/utils/httpRequestParser'
import { 
  LEVEL_OPTIONS, 
  RISK_OPTIONS, 
  DBMS_OPTIONS,
  DEFAULT_SCAN_OPTIONS,
  type ScanOptions
} from '@/types/scanPreset'
import { request } from '@/api/request'

const router = useRouter()
const toast = useToast()
const presetStore = useScanPresetStore()

// OS选项
const OS_OPTIONS = [
  { label: '自动检测', value: '' },
  { label: 'Linux', value: 'Linux' },
  { label: 'Windows', value: 'Windows' }
]

// 注入技术单独选项
const TECHNIQUE_ITEMS = [
  { label: 'B (布尔盲注)', value: 'B' },
  { label: 'E (报错注入)', value: 'E' },
  { label: 'U (联合查询)', value: 'U' },
  { label: 'S (堆叠查询)', value: 'S' },
  { label: 'T (时间盲注)', value: 'T' },
  { label: 'Q (内联查询)', value: 'Q' }
]

// Verbose选项
const VERBOSE_OPTIONS = [
  { label: '0 (静默)', value: 0 },
  { label: '1 (默认)', value: 1 },
  { label: '2 (调试)', value: 2 },
  { label: '3 (更多调试)', value: 3 },
  { label: '4 (HTTP请求)', value: 4 },
  { label: '5 (HTTP响应头)', value: 5 },
  { label: '6 (HTTP响应体)', value: 6 }
]

// 输入状态
const inputContent = ref('')
const rawHttpContent = ref('')
const parsedRequest = ref<ParsedHttpRequest | null>(null)
const detectedFormat = ref<RequestFormat>('unknown')

// 配置状态
const selectedPresetId = ref<number | null>(null)
const currentOptions = ref<ScanOptions>({ ...DEFAULT_SCAN_OPTIONS })
const selectedTechniques = ref<string[]>(['B', 'E', 'U', 'S', 'T', 'Q'])

// 提交状态
const submitting = ref(false)

// 对话框状态
const showSavePresetDialog = ref(false)
const newPresetName = ref('')
const newPresetDescription = ref('')

// 计算属性
const formatDisplayName = computed(() => getFormatDisplayName(detectedFormat.value))

const formatSeverity = computed(() => {
  switch (detectedFormat.value) {
    case 'curl_bash':
    case 'curl_cmd':
    case 'raw_http':
      return 'success'
    case 'powershell':
      return 'info'
    case 'fetch_js':
    case 'fetch_nodejs':
      return 'warn'
    default:
      return 'secondary'
  }
})

const canSubmit = computed(() => {
  return rawHttpContent.value.trim() && parsedRequest.value
})

// 预设选项
const presetOptions = computed(() => {
  const options: any[] = []
  
  // 默认配置
  if (presetStore.defaultPreset) {
    options.push({
      label: `【默认】${presetStore.defaultPreset.name}`,
      value: presetStore.defaultPreset.id || 0
    })
  }
  
  // 常用配置
  if (presetStore.presetConfigs.length > 0) {
    options.push({ label: '── 常用配置 ──', value: 'separator-1', disabled: true })
    presetStore.presetConfigs.forEach(preset => {
      options.push({ label: preset.name, value: preset.id || 0 })
    })
  }
  
  // 历史配置
  if (presetStore.historyConfigs.length > 0) {
    options.push({ label: '── 历史配置 ──', value: 'separator-2', disabled: true })
    presetStore.historyConfigs.forEach(preset => {
      options.push({ label: preset.name, value: preset.id || 0 })
    })
  }
  
  return options
})

// 监听技术选择变化
watch(selectedTechniques, (newVal) => {
  currentOptions.value.technique = newVal.join('')
}, { deep: true })

const inputPlaceholder = `粘贴从Chrome DevTools复制的HTTP请求报文

支持的格式：
• cURL (bash/cmd)
• PowerShell (Invoke-WebRequest)
• fetch (JavaScript/Node.js)
• 原始HTTP报文

示例 (cURL):
curl 'https://example.com/api/user?id=1' \\
  -H 'Content-Type: application/json'`

const httpPlaceholder = `转换后的HTTP报文将显示在这里...

您可以直接编辑报文内容
使用 * 标记注入点，例如：
GET /api/user?id=1* HTTP/1.1`

// 方法
function onInputChange() {
  detectedFormat.value = detectFormat(inputContent.value)
}

function parseInput() {
  const result = parseHttpRequest(inputContent.value)
  
  if (result.success && result.data && result.rawHttp) {
    parsedRequest.value = result.data
    rawHttpContent.value = result.rawHttp
    detectedFormat.value = result.format || 'unknown'
    
    toast.add({
      severity: 'success',
      summary: '解析成功',
      detail: `已将 ${formatDisplayName.value} 格式转换为HTTP报文`,
      life: 3000
    })
  } else {
    toast.add({
      severity: 'error',
      summary: '解析失败',
      detail: result.error || '无法解析输入内容',
      life: 5000
    })
  }
}

function clearInput() {
  inputContent.value = ''
  rawHttpContent.value = ''
  parsedRequest.value = null
  detectedFormat.value = 'unknown'
}

async function onPresetChange(event: any) {
  const presetId = event.value
  if (presetId && typeof presetId === 'number') {
    try {
      await presetStore.selectPreset(presetId)
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...presetStore.currentOptions }
      // 更新technique选择
      if (currentOptions.value.technique) {
        selectedTechniques.value = currentOptions.value.technique.split('')
      }
    } catch (error) {
      console.error('Failed to apply preset:', error)
    }
  }
}

function resetConfig() {
  currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
  selectedPresetId.value = null
  selectedTechniques.value = ['B', 'E', 'U', 'S', 'T', 'Q']
}

async function saveAsPreset() {
  if (!newPresetName.value.trim()) return
  
  const result = await presetStore.saveCurrentAsPreset(
    newPresetName.value.trim(),
    newPresetDescription.value.trim() || undefined
  )
  
  if (result) {
    toast.add({
      severity: 'success',
      summary: '保存成功',
      detail: `预设 "${newPresetName.value}" 已保存`,
      life: 3000
    })
    showSavePresetDialog.value = false
    newPresetName.value = ''
    newPresetDescription.value = ''
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
  
  // 确保batch选项始终存在
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
      headers: requestInfo.headers,
      body: requestInfo.body,
      options: getEffectiveOptions()
    }
    
    // 调用Web端专用的任务添加API
    await request.post('/web/admin/task/add', taskData)
    
    // 保存到历史记录
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
    
    router.push('/tasks')
    
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

// 生命周期
onMounted(async () => {
  try {
    await presetStore.loadConfigOptions()
    if (presetStore.defaultPreset) {
      selectedPresetId.value = presetStore.defaultPreset.id || null
    }
  } catch (error) {
    console.error('Failed to load config options:', error)
    // 使用默认配置
    currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
  }
})
</script>

<style scoped>
.add-task-container {
  padding: 1.5rem;
  max-width: 1600px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 1.5rem;
}

.page-header h2 {
  margin: 0 0 0.5rem 0;
  color: var(--text-color);
}

.page-header .subtitle {
  margin: 0;
  color: var(--text-color-secondary);
  font-size: 0.9rem;
}

.content-wrapper {
  display: grid;
  grid-template-columns: 1fr 480px;
  gap: 1.5rem;
}

.left-panel {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.right-panel {
  display: flex;
  flex-direction: column;
}

.card-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.input-textarea,
.http-textarea {
  width: 100%;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 0.85rem;
  resize: vertical;
}

.http-textarea.has-content {
  background-color: var(--surface-ground);
}

.input-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 1rem;
}

.editor-status {
  display: flex;
  gap: 1rem;
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--surface-border);
}

.status-item {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}

/* 配置卡片 */
.config-card :deep(.p-card-body) {
  max-height: calc(100vh - 200px);
  overflow-y: auto;
}

.config-group {
  margin-bottom: 1rem;
}

.config-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: var(--text-color);
}

/* Fieldset样式 */
.config-fieldset {
  margin-bottom: 0.75rem;
}

.config-fieldset :deep(.p-fieldset-legend) {
  font-size: 0.9rem;
  padding: 0.5rem 0.75rem;
}

.config-fieldset :deep(.p-fieldset-content) {
  padding: 0.75rem;
}

/* 配置项网格 */
.config-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}

.config-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.config-item.full-width {
  grid-column: 1 / -1;
  margin-bottom: 0.5rem;
}

.config-item label {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.config-item.checkbox-item {
  flex-direction: row;
  align-items: center;
  gap: 0.5rem;
}

.config-item.checkbox-item label {
  font-size: 0.85rem;
  color: var(--text-color);
}

/* 技术选项复选框 */
.technique-checkboxes {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.5rem;
}

.technique-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.technique-item label {
  font-size: 0.8rem;
  color: var(--text-color);
}

/* 枚举选项 */
.enum-checkboxes {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}

/* 提交区域 */
.submit-section {
  display: flex;
  gap: 0.75rem;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--surface-border);
}

.save-preset-btn {
  flex-shrink: 0;
}

.submit-btn {
  flex: 1;
  height: 2.75rem;
}

.submit-hint {
  display: block;
  text-align: center;
  color: var(--text-color-secondary);
  margin-top: 0.5rem;
}

/* 对话框 */
.dialog-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.field label {
  font-weight: 500;
}

.w-full {
  width: 100%;
}

/* 响应式布局 */
@media (max-width: 1200px) {
  .content-wrapper {
    grid-template-columns: 1fr;
  }
  
  .config-card :deep(.p-card-body) {
    max-height: none;
  }
}

@media (max-width: 768px) {
  .config-grid {
    grid-template-columns: 1fr;
  }
  
  .technique-checkboxes {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .enum-checkboxes {
    grid-template-columns: 1fr;
  }
}
</style>
