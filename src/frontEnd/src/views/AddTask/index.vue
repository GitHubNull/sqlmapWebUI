<template>
  <div class="add-task-page">
    <div class="page-header">
      <h2>添加扫描任务</h2>
      <p>从浏览器DevTools复制HTTP请求报文，转换后提交扫描</p>
    </div>

    <div class="content-grid">
      <!-- 左侧：请求输入 -->
      <div class="left-column">
        <Card>
          <template #title>
            <div class="card-header">
              <span>报文输入</span>
              <Tag v-if="detectedFormat !== 'unknown'" :severity="formatSeverity">
                {{ formatDisplayName }}
              </Tag>
            </div>
          </template>
          
          <template #content>
            <HttpCodeEditor
              v-model="inputContent"
              :placeholder="inputPlaceholder"
              min-height="120px"
              @change="onInputChange"
            />
            
            <div class="button-group">
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

        <Card>
          <template #title>
            <div class="card-header">
              <span>HTTP报文编辑</span>
              <Tag severity="info"><i class="pi pi-info-circle"></i> 使用 * 标记注入点</Tag>
            </div>
          </template>
          
          <template #content>
            <HttpCodeEditor
              v-model="rawHttpContent"
              :placeholder="httpPlaceholder"
              min-height="150px"
            />
            
            <div v-if="parsedRequest" class="request-info">
              <span><i class="pi pi-globe"></i> {{ parsedRequest.method }} {{ parsedRequest.host }}</span>
              <span><i class="pi pi-link"></i> {{ parsedRequest.path }}</span>
            </div>
          </template>
        </Card>
      </div>

      <!-- 右侧：扫描配置 -->
      <div class="right-column">
        <Card>
          <template #title>
            <div class="card-header">
              <span>扫描配置</span>
              <Button icon="pi pi-refresh" text rounded @click="resetConfig" />
            </div>
          </template>
          
          <template #content>
            <div class="config-section">
              <label>配置预设</label>
              <Select
                v-model="selectedPreset"
                :options="presetOptions"
                option-label="name"
                option-value="id"
                placeholder="选择预设配置"
                class="w-full"
              />
            </div>

            <Divider />

            <div class="config-section">
              <label>扫描选项</label>
              <div class="options-grid">
                <div class="option-item">
                  <Checkbox v-model="configOptions.level" :binary="true" input-id="level" />
                  <label for="level">风险等级 ({{ configOptions.levelValue }})</label>
                  <Slider v-if="configOptions.level" v-model="configOptions.levelValue" :min="1" :max="5" />
                </div>

                <div class="option-item">
                  <Checkbox v-model="configOptions.threads" :binary="true" input-id="threads" />
                  <label for="threads">线程数 ({{ configOptions.threadsValue }})</label>
                  <Slider v-if="configOptions.threads" v-model="configOptions.threadsValue" :min="1" :max="10" />
                </div>

                <div class="option-item">
                  <Checkbox v-model="configOptions.dump" :binary="true" input-id="dump" />
                  <label for="dump">导出数据</label>
                </div>

                <div class="option-item">
                  <Checkbox v-model="configOptions.batch" :binary="true" input-id="batch" />
                  <label for="batch">批量模式</label>
                </div>
              </div>
            </div>

            <Divider />

            <CommandLinePreview
              :command="generatedCommand"
              title="生成的命令"
            />

            <div class="submit-section">
              <Button
                label="提交扫描任务"
                icon="pi pi-send"
                severity="primary"
                :loading="submitting"
                :disabled="!canSubmit"
                @click="submitTask"
                class="w-full"
              />
            </div>
          </template>
        </Card>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import Card from 'primevue/card'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Select from 'primevue/select'
import Checkbox from 'primevue/checkbox'
import Slider from 'primevue/slider'
import Divider from 'primevue/divider'
import HttpCodeEditor from '@/components/HttpCodeEditor.vue'
import CommandLinePreview from '@/components/CommandLinePreview.vue'
import { parseHttpRequest } from '@/utils/httpRequestParser'
import { addTask } from '@/api/task'

const router = useRouter()
const toast = useToast()

const inputContent = ref('')
const rawHttpContent = ref('')
const detectedFormat = ref('unknown')
const parsedRequest = ref<any>(null)
const submitting = ref(false)

const selectedPreset = ref('default')

const presetOptions = [
  { id: 'default', name: '默认配置' },
  { id: 'fast', name: '快速扫描' },
  { id: 'thorough', name: ' thorough扫描' },
  { id: 'custom', name: '自定义配置' },
]

const configOptions = reactive({
  level: false,
  levelValue: 1,
  threads: false,
  threadsValue: 1,
  dump: false,
  batch: true,
})

const formatSeverity = computed(() => {
  const map: Record<string, string> = {
    curl: 'success',
    raw: 'info',
    powershell: 'warn',
    fetch: 'secondary',
  }
  return map[detectedFormat.value] || 'secondary'
})

const formatDisplayName = computed(() => {
  const map: Record<string, string> = {
    curl: 'cURL',
    raw: 'Raw HTTP',
    powershell: 'PowerShell',
    fetch: 'Fetch API',
  }
  return map[detectedFormat.value] || detectedFormat.value
})

const inputPlaceholder = `支持格式：
- Raw HTTP 请求
- cURL 命令
- PowerShell Invoke-WebRequest
- JavaScript fetch`

const httpPlaceholder = `GET /api/users?id=1* HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0

在参数值后添加 * 标记注入点`

const generatedCommand = computed(() => {
  let cmd = 'sqlmap'
  
  if (parsedRequest.value?.url) {
    cmd += ` -u "${parsedRequest.value.url}"`
  }
  
  if (configOptions.level) {
    cmd += ` --level=${configOptions.levelValue}`
  }
  
  if (configOptions.threads) {
    cmd += ` --threads=${configOptions.threadsValue}`
  }
  
  if (configOptions.dump) {
    cmd += ' --dump'
  }
  
  if (configOptions.batch) {
    cmd += ' --batch'
  }
  
  return cmd
})

const canSubmit = computed(() => {
  return rawHttpContent.value.trim().length > 0
})

function onInputChange() {
  const content = inputContent.value.trim()
  if (!content) {
    detectedFormat.value = 'unknown'
    return
  }
  
  if (content.startsWith('curl')) {
    detectedFormat.value = 'curl'
  } else if (content.includes('Invoke-WebRequest')) {
    detectedFormat.value = 'powershell'
  } else if (content.includes('fetch(')) {
    detectedFormat.value = 'fetch'
  } else if (content.includes('HTTP/1.') || content.includes('HTTP/2')) {
    detectedFormat.value = 'raw'
  }
}

function parseInput() {
  try {
    const result = parseHttpRequest(inputContent.value)
    if (result.success) {
      rawHttpContent.value = result.rawHttp || ''
      parsedRequest.value = result.data
      toast.add({ severity: 'success', summary: '解析成功', life: 2000 })
    } else {
      toast.add({ severity: 'error', summary: '解析失败', detail: result.error, life: 3000 })
    }
  } catch (error) {
    toast.add({ severity: 'error', summary: '解析失败', detail: String(error), life: 3000 })
  }
}

function clearInput() {
  inputContent.value = ''
  rawHttpContent.value = ''
  detectedFormat.value = 'unknown'
  parsedRequest.value = null
}

function resetConfig() {
  selectedPreset.value = 'default'
  configOptions.level = false
  configOptions.levelValue = 1
  configOptions.threads = false
  configOptions.threadsValue = 1
  configOptions.dump = false
  configOptions.batch = true
}

async function submitTask() {
  if (!canSubmit.value) return
  
  submitting.value = true
  try {
    const result = await addTask({
      scanUrl: rawHttpContent.value,
      options: {
        level: configOptions.level ? configOptions.levelValue : undefined,
        threads: configOptions.threads ? configOptions.threadsValue : undefined,
        dump: configOptions.dump,
        batch: configOptions.batch,
      }
    })
    
    toast.add({
      severity: 'success',
      summary: '任务创建成功',
      detail: `任务ID: ${result.taskid}`,
      life: 3000
    })
    
    router.push(`/tasks/${result.taskid}`)
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: '创建失败',
      detail: String(error),
      life: 3000
    })
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.add-task-page {
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 1.5rem;
}

.page-header h2 {
  margin: 0 0 0.5rem;
  font-size: 1.5rem;
}

.page-header p {
  margin: 0;
  color: var(--p-text-secondary-color);
}

.content-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.left-column,
.right-column {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.button-group {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
}

.request-info {
  display: flex;
  gap: 1rem;
  margin-top: 0.75rem;
  font-size: 0.875rem;
  color: var(--p-text-secondary-color);
}

.request-info i {
  margin-right: 0.25rem;
}

.config-section {
  margin-bottom: 1rem;
}

.config-section label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.options-grid {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.option-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.option-item > label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 0;
  cursor: pointer;
}

.submit-section {
  margin-top: 1rem;
}

@media (max-width: 1024px) {
  .content-grid {
    grid-template-columns: 1fr;
  }
}
</style>
