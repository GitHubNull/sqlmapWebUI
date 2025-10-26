<template>
  <div class="batch-import-dialog">
    <Dialog
      v-model:visible="visible"
      header="批量导入Header规则"
      :style="{ width: '1000px', maxHeight: '90vh' }"
      modal
      class="import-dialog"
    >
      <div class="dialog-content">
        <!-- 导入模式选择 -->
        <Card class="mode-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>选择导入模式</span>
            </div>
          </template>
          <template #content>
            <div class="mode-selection">
              <div class="mode-options">
                <div
                  class="mode-option"
                  :class="{ active: importMode === 'text' }"
                  @click="importMode = 'text'"
                >
                  <div class="mode-icon">
                    <i class="pi pi-align-left"></i>
                  </div>
                  <div class="mode-content">
                    <h4>文本导入</h4>
                    <p>支持 Header-Name: Header-Value 格式</p>
                  </div>
                </div>

                <div
                  class="mode-option"
                  :class="{ active: importMode === 'json' }"
                  @click="importMode = 'json'"
                >
                  <div class="mode-icon">
                    <i class="pi pi-code"></i>
                  </div>
                  <div class="mode-content">
                    <h4>JSON导入</h4>
                    <p>标准JSON格式批量导入</p>
                  </div>
                </div>

                <div
                  class="mode-option"
                  :class="{ active: importMode === 'file' }"
                  @click="importMode = 'file'"
                >
                  <div class="mode-icon">
                    <i class="pi pi-file-import"></i>
                  </div>
                  <div class="mode-content">
                    <h4>文件导入</h4>
                    <p>上传JSON文件导入</p>
                  </div>
                </div>
              </div>
            </div>
          </template>
        </Card>

        <!-- 文本导入模式 -->
        <Card v-if="importMode === 'text'" class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-align-left text-primary"></i>
              <span>文本输入</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false" class="mb-3">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>每行一个Header规则，格式：<code>规则名称|Header名称|Header值|策略|优先级</code></span>
              </div>
            </Message>

            <div class="input-area">
              <Textarea
                v-model="textInput"
                rows="15"
                placeholder="示例格式：
API认证|Authorization|Bearer token123|REPLACE|80
用户代理|User-Agent|CustomAgent/1.0|REPLACE|50
API密钥|X-API-Key|key123|REPLACE|90

支持格式：
规则名称|Header名称|Header值|策略|优先级
或简写：
Header名称: Header值"
                class="text-input"
                :autoResize="false"
              />
              <div class="input-stats">
                <small class="text-color-secondary">
                  <i class="pi pi-info-circle mr-1"></i>
                  输入行数: {{ textInput.split('\n').filter(line => line.trim()).length }}
                </small>
              </div>
            </div>
          </template>
        </Card>

        <!-- JSON导入模式 -->
        <Card v-if="importMode === 'json'" class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-code text-primary"></i>
              <span>JSON输入</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false" class="mb-3">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>输入标准JSON格式的Header规则数组</span>
              </div>
            </Message>

            <div class="input-area">
              <Textarea
                v-model="jsonInput"
                rows="15"
                placeholder='[
  {
    "name": "API认证",
    "header_name": "Authorization",
    "header_value": "Bearer token123",
    "replace_strategy": "REPLACE",
    "priority": 80,
    "is_active": true
  },
  {
    "name": "用户代理",
    "header_name": "User-Agent",
    "header_value": "CustomAgent/1.0",
    "replace_strategy": "REPLACE",
    "priority": 50,
    "is_active": true
  }
]'
                class="json-input"
                :autoResize="false"
              />
            </div>
          </template>
        </Card>

        <!-- 文件导入模式 -->
        <Card v-if="importMode === 'file'" class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-file-import text-primary"></i>
              <span>文件上传</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false" class="mb-3">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>上传JSON格式的Header规则文件</span>
              </div>
            </Message>

            <FileUpload
              mode="basic"
              name="file"
              accept=".json"
              :maxFileSize="1000000"
              @select="onFileSelect"
              @clear="onFileClear"
              chooseLabel="选择JSON文件"
              class="file-upload"
            />

            <div v-if="uploadedFile" class="file-info mt-3">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-file text-primary"></i>
                <span>{{ uploadedFile.name }}</span>
                <Tag :value="formatFileSize(uploadedFile.size)" severity="info"></Tag>
              </div>
            </div>
          </template>
        </Card>

        <!-- 批量配置选项 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>批量配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-4 mb-3">
                <FloatLabel>
                  <Dropdown
                    id="default_strategy"
                    v-model="defaultStrategy"
                    :options="strategyOptions"
                    optionLabel="label"
                    optionValue="value"
                  />
                  <label for="default_strategy">默认策略</label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">批量导入时的默认替换策略</small>
              </div>

              <div class="field col-12 md:col-4 mb-3">
                <FloatLabel>
                  <InputNumber
                    id="default_priority"
                    v-model="defaultPriority"
                    :min="0"
                    :max="100"
                    showButtons
                    buttonLayout="horizontal"
                    :step="1"
                  />
                  <label for="default_priority">默认优先级</label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">批量导入时的默认优先级</small>
              </div>

              <div class="field col-12 md:col-4 mb-0">
                <div class="flex align-items-center gap-2">
                  <Checkbox
                    inputId="default_active"
                    v-model="defaultActive"
                    :binary="true"
                  />
                  <label for="default_active" class="font-medium">
                    默认启用
                  </label>
                </div>
                <small class="text-color-secondary ml-6">导入的规则默认启用状态</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 域控配置 -->
        <Card class="scope-card">
          <template #title>
            <div class="flex align-items-center gap-2 w-full">
              <Checkbox
                inputId="has_scope"
                v-model="hasScope"
                :binary="true"
              />
              <i class="pi pi-filter text-primary"></i>
              <span>批量作用域配置（可选）</span>
            </div>
          </template>
          <template #content>
            <Message v-if="hasScope" severity="info" :closable="false" class="mb-3">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>为批量导入的所有规则统一设置作用域</span>
              </div>
            </Message>

            <Fieldset v-if="hasScope" legend="作用域规则配置" class="scope-fieldset">
              <div class="formgrid grid p-fluid">
                <div class="field col-12 md:col-4 mb-3">
                  <FloatLabel>
                    <InputText
                      id="protocol_pattern"
                      v-model="scopeData.protocol_pattern"
                    />
                    <label for="protocol_pattern">
                      <i class="pi pi-globe mr-2"></i>
                      协议匹配
                    </label>
                  </FloatLabel>
                  <small class="text-color-secondary mt-1">例如: https 或 http,https</small>
                </div>

                <div class="field col-12 md:col-4 mb-3">
                  <FloatLabel>
                    <InputText
                      id="host_pattern"
                      v-model="scopeData.host_pattern"
                    />
                    <label for="host_pattern">
                      <i class="pi pi-server mr-2"></i>
                      主机名匹配
                    </label>
                  </FloatLabel>
                  <small class="text-color-secondary mt-1">例如: *.example.com（支持通配符*）</small>
                </div>

                <div class="field col-12 md:col-4 mb-3">
                  <FloatLabel>
                    <InputText
                      id="path_pattern"
                      v-model="scopeData.path_pattern"
                    />
                    <label for="path_pattern">
                      <i class="pi pi-link mr-2"></i>
                      路径匹配
                    </label>
                  </FloatLabel>
                  <small class="text-color-secondary mt-1">例如: /api/*（支持通配符*）</small>
                </div>

                <div class="field col-12 mb-0">
                  <div class="flex align-items-center gap-2">
                    <Checkbox
                      inputId="use_regex"
                      v-model="scopeData.use_regex"
                      :binary="true"
                    />
                    <label for="use_regex" class="font-medium">
                      <i class="pi pi-code mr-2 text-primary"></i>
                      使用正则表达式匹配
                    </label>
                  </div>
                  <small class="text-color-secondary ml-6">启用后上述模式将作为正则表达式解析</small>
                </div>
              </div>
            </Fieldset>
          </template>
        </Card>
      </div>

      <template #footer>
        <div class="footer-actions">
          <div class="validation-info" v-if="validationErrors.length > 0">
            <Message severity="error" :closable="false">
              <div class="error-list">
                <div v-for="(error, index) in validationErrors" :key="index" class="error-item">
                  <i class="pi pi-times-circle mr-2"></i>
                  <span>{{ error }}</span>
                </div>
              </div>
            </Message>
          </div>

          <div class="button-group">
            <Button
              label="取消"
              icon="pi pi-times"
              severity="secondary"
              @click="closeDialog"
            />
            <Button
              label="预览"
              icon="pi pi-eye"
              severity="info"
              @click="previewImport"
              :loading="previewing"
              v-if="currentInput.trim()"
            />
            <Button
              label="导入"
              icon="pi pi-check"
              @click="confirmImport"
              :loading="importing"
              :disabled="!canImport"
              severity="success"
            />
          </div>
        </div>
      </template>
    </Dialog>

    <!-- 预览对话框 -->
    <Dialog
      v-model:visible="previewVisible"
      header="导入预览"
      :style="{ width: '900px', maxHeight: '80vh' }"
      modal
      class="preview-dialog"
    >
      <div class="preview-content">
        <Message severity="info" :closable="false" class="mb-3">
          <div class="flex align-items-center gap-2">
            <i class="pi pi-info-circle"></i>
            <span>共找到 {{ previewData.length }} 条有效规则，确认无误后点击导入</span>
          </div>
        </Message>

        <DataTable
          :value="previewData"
          stripedRows
          :paginator="previewData.length > 10"
          :rows="10"
          class="preview-table"
        >
          <Column field="name" header="规则名称" style="width: 25%"></Column>
          <Column field="header_name" header="Header名称" style="width: 20%"></Column>
          <Column field="header_value" header="Header值">
            <template #body="{ data }">
              <span class="header-value-preview">{{ truncate(data.header_value, 50) }}</span>
            </template>
          </Column>
          <Column field="replace_strategy" header="策略" style="width: 15%"></Column>
          <Column field="priority" header="优先级" style="width: 10%">
            <template #body="{ data }">
              <Tag :value="data.priority" :severity="getPrioritySeverity(data.priority)"></Tag>
            </template>
          </Column>
        </DataTable>
      </div>

      <template #footer>
        <Button
          label="返回编辑"
          icon="pi pi-arrow-left"
          severity="secondary"
          @click="previewVisible = false"
        />
        <Button
          label="确认导入"
          icon="pi pi-check"
          @click="executeImport"
          :loading="importing"
          severity="success"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import type { PersistentHeaderRuleCreate, ReplaceStrategy, HeaderScope } from '@/types/headerRule'

const props = defineProps<{
  visible: boolean
}>()

const emit = defineEmits<{
  'update:visible': [value: boolean]
  'import': [rules: PersistentHeaderRuleCreate[]]
}>()

const toast = useToast()

// 导入模式
const importMode = ref<'text' | 'json' | 'file'>('text')

// 输入数据
const textInput = ref('')
const jsonInput = ref('')
const uploadedFile = ref<File | null>(null)

// 默认配置
const defaultStrategy = ref<ReplaceStrategy>('REPLACE' as ReplaceStrategy)
const defaultPriority = ref(50)
const defaultActive = ref(true)
const hasScope = ref(false)

const scopeData = reactive<HeaderScope>({
  protocol_pattern: '',
  host_pattern: '',
  path_pattern: '',
  use_regex: false,
})

// 预览相关
const previewVisible = ref(false)
const previewData = ref<PersistentHeaderRuleCreate[]>([])
const previewing = ref(false)

// 导入状态
const importing = ref(false)
const validationErrors = ref<string[]>([])

// 策略选项
const strategyOptions = [
  { label: '完全替换', value: 'REPLACE' },
  { label: '追加', value: 'APPEND' },
  { label: '前置', value: 'PREPEND' },
  { label: '条件替换', value: 'CONDITIONAL' },
  { label: '存在则替换', value: 'UPSERT' },
]

// 当前输入内容
const currentInput = computed(() => {
  switch (importMode.value) {
    case 'text':
      return textInput.value
    case 'json':
      return jsonInput.value
    case 'file':
      return uploadedFile.value ? uploadedFile.value.name : ''
    default:
      return ''
  }
})

// 是否可以导入
const canImport = computed(() => {
  return currentInput.value.trim() && validationErrors.value.length === 0
})

// 监听输入变化，清除验证错误
watch([textInput, jsonInput], () => {
  validationErrors.value = []
})

// 文件选择处理
function onFileSelect(event: any) {
  const file = event.files[0]
  if (file) {
    uploadedFile.value = file
    readFileContent(file)
  }
}

function onFileClear() {
  uploadedFile.value = null
}

// 读取文件内容
function readFileContent(file: File) {
  const reader = new FileReader()
  reader.onload = (e) => {
    try {
      const content = e.target?.result as string
      if (content) {
        jsonInput.value = content
        importMode.value = 'json'
      }
    } catch (error) {
      toast.add({
        severity: 'error',
        summary: '文件读取失败',
        detail: '无法读取文件内容',
        life: 3000,
      })
    }
  }
  reader.onerror = () => {
    toast.add({
      severity: 'error',
      summary: '文件读取失败',
      detail: '无法读取文件内容',
      life: 3000,
    })
  }
  reader.readAsText(file)
}

// 格式化文件大小
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  const size = sizes[i]
  if (!size) return '0 Bytes'
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + size
}

// 解析文本输入
function parseTextInput(): PersistentHeaderRuleCreate[] {
  const lines = textInput.value.split('\n').filter(line => line.trim())
  const rules: PersistentHeaderRuleCreate[] = []

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim()
    if (!line) continue

    try {
      // 尝试完整格式：规则名称|Header名称|Header值|策略|优先级
      if (line.includes('|')) {
        const parts = line.split('|').map(p => p.trim())
        if (parts.length >= 3) {
          rules.push({
            name: parts[0] || `规则${i + 1}`,
            header_name: parts[1] || '',
            header_value: parts[2] || '',
            replace_strategy: (parts[3] as ReplaceStrategy) || defaultStrategy.value,
            priority: parts[4] ? parseInt(parts[4]) : defaultPriority.value,
            is_active: defaultActive.value,
            scope: hasScope.value ? { ...scopeData } : null
          })
        }
      }
      // 简写格式：Header名称: Header值
      else if (line.includes(':')) {
        const [name, ...valueParts] = line.split(':')
        if (name && valueParts.length > 0) {
          rules.push({
            name: `${name.trim()}规则`,
            header_name: name.trim(),
            header_value: valueParts.join(':').trim(),
            replace_strategy: defaultStrategy.value,
            priority: defaultPriority.value,
            is_active: defaultActive.value,
            scope: hasScope.value ? { ...scopeData } : null
          })
        }
      }
    } catch (error) {
      validationErrors.value.push(`第${i + 1}行格式错误: ${line}`)
    }
  }

  return rules
}

// 解析JSON输入
function parseJsonInput(): PersistentHeaderRuleCreate[] {
  try {
    const rules = JSON.parse(jsonInput.value) as PersistentHeaderRuleCreate[]
    if (!Array.isArray(rules)) {
      throw new Error('JSON必须是数组格式')
    }

    return rules.map(rule => ({
      ...rule,
      replace_strategy: rule.replace_strategy || defaultStrategy.value,
      priority: rule.priority || defaultPriority.value,
      is_active: rule.is_active !== undefined ? rule.is_active : defaultActive.value,
      scope: hasScope.value ? { ...scopeData } : rule.scope
    }))
  } catch (error) {
    validationErrors.value.push('JSON格式错误: ' + (error as Error).message)
    return []
  }
}

// 验证规则
function validateRules(rules: PersistentHeaderRuleCreate[]): boolean {
  validationErrors.value = []

  if (rules.length === 0) {
    validationErrors.value.push('没有找到有效的规则')
    return false
  }

  rules.forEach((rule, index) => {
    if (!rule.name || rule.name.trim() === '') {
      validationErrors.value.push(`第${index + 1}条规则缺少规则名称`)
    }
    if (!rule.header_name || rule.header_name.trim() === '') {
      validationErrors.value.push(`第${index + 1}条规则缺少Header名称`)
    }
    if (!rule.header_value || rule.header_value.trim() === '') {
      validationErrors.value.push(`第${index + 1}条规则缺少Header值`)
    }
    if (rule.priority !== undefined && (rule.priority < 0 || rule.priority > 100)) {
      validationErrors.value.push(`第${index + 1}条规则优先级必须在0-100之间`)
    }
  })

  return validationErrors.value.length === 0
}

// 预览导入
async function previewImport() {
  previewing.value = true
  validationErrors.value = []

  try {
    let rules: PersistentHeaderRuleCreate[] = []

    switch (importMode.value) {
      case 'text':
        rules = parseTextInput()
        break
      case 'json':
      case 'file':
        rules = parseJsonInput()
        break
    }

    if (validateRules(rules)) {
      previewData.value = rules
      previewVisible.value = true
    }
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: '预览失败',
      detail: (error as Error).message,
      life: 3000,
    })
  } finally {
    previewing.value = false
  }
}

// 执行导入
async function executeImport() {
  importing.value = true

  try {
    emit('import', previewData.value)
    toast.add({
      severity: 'success',
      summary: '导入成功',
      detail: `成功导入 ${previewData.value.length} 条规则`,
      life: 3000,
    })
    closeDialog()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: '导入失败',
      detail: (error as Error).message,
      life: 3000,
    })
  } finally {
    importing.value = false
  }
}

// 确认导入
function confirmImport() {
  if (!canImport.value) return

  // 直接预览并导入
  previewImport().then(() => {
    if (validationErrors.value.length === 0 && previewData.value.length > 0) {
      executeImport()
    }
  })
}

// 关闭对话框
function closeDialog() {
  visible.value = false
  // 重置状态
  textInput.value = ''
  jsonInput.value = ''
  uploadedFile.value = null
  validationErrors.value = []
  previewData.value = []
  hasScope.value = false
  Object.assign(scopeData, {
    protocol_pattern: '',
    host_pattern: '',
    path_pattern: '',
    use_regex: false
  })
}

// 获取优先级严重程度
function getPrioritySeverity(priority: number) {
  if (priority >= 80) return 'danger'
  if (priority >= 50) return 'warning'
  return 'info'
}

// 截断文本
function truncate(text: string, length: number) {
  if (text.length <= length) return text
  return text.substring(0, length) + '...'
}

// 计算属性：visible的setter和getter
const visible = computed({
  get: () => props.visible,
  set: (value) => emit('update:visible', value)
})
</script>

<style scoped lang="scss">
.batch-import-dialog {
  // 对话框内容样式
  :deep(.import-dialog) {
    .p-dialog-content {
      padding: 0;
      overflow-y: auto;
    }
  }

  .dialog-content {
    padding: 1.5rem;
    max-height: calc(90vh - 140px);
    overflow-y: auto;

    // 卡片通用样式
    :deep(.p-card) {
      border-radius: 12px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      transition: all 0.3s ease;

      &:hover {
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
      }

      .p-card-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--primary-color);
        margin-bottom: 1rem;
      }

      .p-card-content {
        padding-top: 0;
      }
    }

    // 模式选择样式
    .mode-selection {
      .mode-options {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 1rem;

        .mode-option {
          border: 2px solid var(--surface-border);
          border-radius: 12px;
          padding: 1.5rem;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          align-items: center;
          gap: 1rem;

          &:hover {
            border-color: var(--primary-color);
            background: var(--primary-50);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(var(--primary-color-rgb), 0.15);
          }

          &.active {
            border-color: var(--primary-color);
            background: linear-gradient(135deg, var(--primary-50) 0%, var(--primary-100) 100%);
            box-shadow: 0 4px 12px rgba(var(--primary-color-rgb), 0.2);
          }

          .mode-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.5rem;
          }

          .mode-content {
            flex: 1;

            h4 {
              margin: 0 0 0.5rem 0;
              color: var(--text-color);
              font-weight: 600;
            }

            p {
              margin: 0;
              color: var(--text-color-secondary);
              font-size: 0.9rem;
            }
          }
        }
      }
    }

    // 输入区域样式
    .input-area {
      .text-input,
      .json-input {
        border-radius: 8px;
        border: 2px solid var(--surface-border);
        transition: all 0.2s ease;
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
        font-size: 0.9em;
        line-height: 1.6;
        resize: vertical;
        min-height: 300px;

        &:focus {
          border-color: var(--primary-color);
          box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
        }

        &::placeholder {
          color: var(--text-color-secondary);
          opacity: 0.7;
        }
      }

      .input-stats {
        margin-top: 0.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
    }

    // 文件上传样式
    .file-upload {
      :deep(.p-fileupload-basic) {
        border-radius: 8px;
        border: 2px dashed var(--surface-border);
        background: var(--surface-50);
        transition: all 0.2s ease;

        &:hover {
          border-color: var(--primary-color);
          background: var(--primary-50);
        }
      }
    }

    .file-info {
      padding: 1rem;
      background: var(--surface-100);
      border-radius: 8px;
      border: 1px solid var(--surface-border);
    }

    // 浮动标签样式
    :deep(.p-float-label) {
      margin-bottom: 0.5rem;

      label {
        font-weight: 500;
        color: var(--text-color-secondary);

        i {
          color: var(--primary-color);
        }
      }
    }

    // 输入组件样式
    :deep(.p-inputtext),
    :deep(.p-dropdown),
    :deep(.p-inputnumber-input) {
      border-radius: 8px;
      border: 2px solid var(--surface-border);
      transition: all 0.2s ease;

      &:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
      }
    }

    // 复选框样式
    :deep(.p-checkbox) {
      .p-checkbox-box {
        border-radius: 4px;
        border: 2px solid var(--surface-border);
        transition: all 0.2s ease;

        &.p-highlight {
          background: var(--primary-color);
          border-color: var(--primary-color);
        }
      }
    }

    // 字段集样式
    .scope-fieldset {
      :deep(.p-fieldset-legend) {
        font-weight: 600;
        color: var(--text-color);
        background: var(--surface-card);
        border: 1px solid var(--surface-border);
        border-radius: 6px;
        padding: 0.5rem 1rem;
      }
    }

    // 代码样式
    code {
      background: var(--primary-50);
      color: var(--primary-700);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.9em;
      font-weight: 600;
      border: 1px solid var(--primary-200);
    }
  }

  // 底部操作区域
  .footer-actions {
    display: flex;
    flex-direction: column;
    gap: 1rem;

    .validation-info {
      .error-list {
        .error-item {
          display: flex;
          align-items: center;
          padding: 0.25rem 0;

          &:not(:last-child) {
            border-bottom: 1px solid var(--red-200);
          }
        }
      }
    }

    .button-group {
      display: flex;
      gap: 0.5rem;
      justify-content: flex-end;
    }
  }

  // 预览对话框样式
  :deep(.preview-dialog) {
    .p-dialog-content {
      padding: 0;
      overflow-y: auto;
    }
  }

  .preview-content {
    padding: 1.5rem;

    .preview-table {
      .header-value-preview {
        font-family: monospace;
        font-size: 0.9em;
        word-break: break-all;
      }
    }
  }
}
</style>