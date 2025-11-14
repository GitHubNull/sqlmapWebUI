<template>
  <div class="header-rules-config">
    <!-- 搜索过滤工具栏 -->
    <Card class="search-filter-card mb-4">
      <template #content>
        <div class="search-filter-toolbar">
          <!-- 搜索区域 -->
          <div class="search-area">
            <IconField iconPosition="left">
              <InputIcon class="pi pi-search" />
              <InputText
                v-model="searchQuery"
                placeholder="搜索规则名称、Header名称或值..."
                class="search-input"
              />
            </IconField>
          </div>

          <!-- 过滤器区域 -->
          <div class="filter-area">
            <div class="filter-group">
              <label class="filter-label">状态:</label>
              <Select
                v-model="statusFilter"
                :options="statusOptions"
                optionLabel="label"
                optionValue="value"
                placeholder="全部状态"
                class="filter-dropdown"
                :showClear="true"
              />
            </div>

            <div class="filter-group">
              <label class="filter-label">策略:</label>
              <Select
                v-model="strategyFilter"
                :options="strategyOptions"
                optionLabel="label"
                optionValue="value"
                placeholder="全部策略"
                class="filter-dropdown"
                :showClear="true"
              />
            </div>

            <div class="filter-group">
              <label class="filter-label">作用域:</label>
              <Select
                v-model="scopeFilter"
                :options="scopeOptions"
                optionLabel="label"
                optionValue="value"
                placeholder="全部"
                class="filter-dropdown"
                :showClear="true"
              />
            </div>
          </div>

          <!-- 操作按钮区域 -->
          <div class="action-area">
            <Button
              icon="pi pi-filter-slash"
              @click="clearFilters"
              severity="secondary"
              outlined
              v-tooltip.top="'清除过滤器'"
            />
            <Button
              label="单条添加"
              icon="pi pi-plus"
              @click="showCreateDialog"
              severity="success"
            />
            <Button
              label="文本导入"
              icon="pi pi-file-edit"
              @click="showTextImportDialog"
              severity="info"
              outlined
            />
            <Button
              label="JSON导入"
              icon="pi pi-code"
              @click="showJsonImportDialog"
              severity="info"
              outlined
            />
            <Button
              label="文件导入"
              icon="pi pi-file-import"
              @click="showFileImportDialog"
              severity="info"
              outlined
            />
            <Button
              label="刷新"
              icon="pi pi-refresh"
              @click="loadRules"
              :loading="loading"
              severity="secondary"
              outlined
            />
          </div>
        </div>
      </template>
    </Card>

    <!-- 规则列表 -->
    <DataTable
      :value="filteredRules"
      :loading="loading"
      stripedRows
      paginator
      :rows="pageSize"
      :rowsPerPageOptions="[5, 10, 20, 50]"
      sortField="priority"
      :sortOrder="-1"
      class="rules-table"
      :globalFilterFields="['name', 'header_name', 'header_value']"
      responsiveLayout="stack"
      breakpoint="768px"
      :resizableColumns="true"
      columnResizeMode="fit"
    >
      <Column field="id" header="ID" sortable style="width: 80px"></Column>
      <Column field="name" header="规则名称" sortable></Column>
      <Column field="header_name" header="Header名称" sortable></Column>
      <Column field="header_value" header="Header值">
        <template #body="{ data }">
          <span class="header-value">{{ truncate(data.header_value, 30) }}</span>
        </template>
      </Column>
      <Column field="replace_strategy" header="替换策略" sortable style="width: 120px"></Column>
      <Column field="priority" header="优先级" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.priority" :severity="getPrioritySeverity(data.priority)"></Tag>
        </template>
      </Column>
      <Column field="is_active" header="状态" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.is_active ? '启用' : '禁用'" :severity="data.is_active ? 'success' : 'danger'"></Tag>
        </template>
      </Column>
      <Column field="scope" header="作用域" style="width: 120px">
        <template #body="{ data }">
          <Tag :value="data.scope ? '有作用域' : '全局'" :severity="data.scope ? 'info' : 'secondary'"></Tag>
        </template>
      </Column>
      <Column header="操作" style="width: 200px">
        <template #body="{ data }">
          <Button
            icon="pi pi-pencil"
            text
            rounded
            @click="showEditDialog(data)"
            v-tooltip.top="'编辑'"
          />
          <Button
            icon="pi pi-trash"
            text
            rounded
            severity="danger"
            @click="confirmDelete(data)"
            v-tooltip.top="'删除'"
          />
          <Button
            :icon="data.is_active ? 'pi pi-eye-slash' : 'pi pi-eye'"
            text
            rounded
            :severity="data.is_active ? 'warning' : 'success'"
            @click="toggleActive(data)"
            v-tooltip.top="data.is_active ? '禁用' : '启用'"
          />
        </template>
      </Column>
    </DataTable>

    <!-- 批量导入对话框 -->
    <BatchImportDialog
      v-model:visible="batchImportVisible"
      @import="handleBatchImport"
    />

    <!-- 创建/编辑对话框 -->
    <Dialog
      v-model:visible="dialogVisible"
      :header="editingRule ? '编辑规则' : '创建规则'"
      :style="{ width: '1200px', maxHeight: '90vh' }"
      modal
      class="rule-dialog"
    >
      <div class="dialog-content">
        <!-- 基本信息卡片 -->
        <Card class="basic-info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-bookmark text-primary"></i>
              <span>基本信息</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-4">
                <label for="name" class="block mb-2 font-medium">
                  规则名称 <span class="text-red-500">*</span>
                </label>
                <InputText
                  id="name"
                  v-model="formData.name"
                  :invalid="!formData.name && showValidation"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">用于标识此规则的用途</small>
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="header_name" class="block mb-2 font-medium">
                  Header名称 <span class="text-red-500">*</span>
                </label>
                <InputText
                  id="header_name"
                  v-model="formData.header_name"
                  :invalid="!formData.header_name && showValidation"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">HTTP请求头的名称，区分大小写</small>
              </div>

              <div class="field col-12 mb-0">
                <label for="header_value" class="block mb-2 font-medium">
                  Header值 <span class="text-red-500">*</span>
                </label>
                <Textarea
                  id="header_value"
                  v-model="formData.header_value"
                  :autoResize="true"
                  rows="3"
                  :invalid="!formData.header_value && showValidation"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">Header的实际值内容</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 高级配置卡片 -->
        <Card class="advanced-config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>高级配置</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-8 mb-4">
                <label for="replace_strategy" class="block mb-2 font-medium">替换策略</label>
                <Select
                  id="replace_strategy"
                  v-model="formData.replace_strategy"
                  :options="replaceStrategies"
                  optionLabel="label"
                  optionValue="value"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">定义如何处理已存在的Header</small>
              </div>

              <div class="field col-12 md:col-4 mb-4">
                <label for="priority" class="block mb-2 font-medium">优先级</label>
                <InputNumber
                  id="priority"
                  v-model="formData.priority"
                  :min="0"
                  :max="100"
                  showButtons
                  buttonLayout="horizontal"
                  :step="1"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">0-100，越大优先级越高</small>
              </div>

              <div class="field col-12 mb-0">
                <div class="flex align-items-center gap-2">
                  <Checkbox
                    ref="isActiveCheckboxRef"
                    inputId="is_active"
                    v-model="formData.is_active"
                    :binary="true"
                  />
                  <label for="is_active" class="font-medium cursor-pointer m-0">
                    <i class="pi pi-power-off mr-2 text-primary"></i>
                    启用此规则
                  </label>
                </div>
                <small class="text-color-secondary ml-6">禁用后规则不会生效</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 作用域配置 -->
        <ScopeConfigPanel
          v-model="scopeData"
          title="配置作用域（可选）"
          description="不勾选则对所有请求全局生效。作用域支持协议、主机名、路径等多维度过滤。"
          :show-templates="true"
          :show-info="true"
          :show-advanced="false"
          ref="scopePanel"
        />
      </div>

      <template #footer>
        <Button 
          label="取消" 
          icon="pi pi-times"
          severity="secondary" 
          @click="dialogVisible = false" 
        />
        <Button 
          label="保存" 
          icon="pi pi-check"
          @click="saveRule" 
          :loading="saving" 
        />
      </template>
    </Dialog>

    <!-- 文本导入对话框 -->
    <Dialog
      v-model:visible="textImportVisible"
      header="文本导入规则"
      :style="{ width: '60vw', maxWidth: '800px' }"
      :maximizable="true"
      :modal="true"
    >
      <div class="field-horizontal mb-6">
        <div class="field-label-left">
          <label><i class="pi pi-file-edit mr-2"></i>文本内容</label>
        </div>
        <div class="field-content">
          <textarea
            v-model="textImportContent"
            class="uniform-textarea"
            rows="12"
            placeholder="请输入规则文本，每行一条规则，格式：&#10;规则名称|Header名称|Header值|替换策略|优先级&#10;例如：&#10;User-Agent Override|User-Agent|Mozilla/5.0 (Custom)|replace|100&#10;Authorization Header|Authorization|Bearer token|append|80"
          ></textarea>
          <div class="field-help">
            支持批量导入，每行一条规则。字段顺序：规则名称、Header名称、Header值、替换策略、优先级（可选）
          </div>
        </div>
      </div>

      <template #footer>
        <Button
          label="取消"
          icon="pi pi-times"
          severity="secondary"
          @click="textImportVisible = false"
        />
        <Button
          label="导入规则"
          icon="pi pi-upload"
          @click="handleTextImport"
          :loading="importing"
        />
      </template>
    </Dialog>

    <!-- JSON导入对话框 -->
    <Dialog
      v-model:visible="jsonImportVisible"
      header="JSON导入规则"
      :style="{ width: '60vw', maxWidth: '800px' }"
      :maximizable="true"
      :modal="true"
    >
      <div class="field-horizontal mb-6">
        <div class="field-label-left">
          <label><i class="pi pi-code mr-2"></i>JSON内容</label>
        </div>
        <div class="field-content">
          <textarea
            v-model="jsonImportContent"
            class="uniform-textarea"
            rows="12"
            placeholder='请输入JSON格式的规则数据，例如：&#10;[&#10;  {&#10;    &quot;name&quot;: &quot;User-Agent Override&quot;,&#10;    &quot;header_name&quot;: &quot;User-Agent&quot;,&#10;    &quot;header_value&quot;: &quot;Mozilla/5.0 (Custom)&quot;,&#10;    &quot;replace_strategy&quot;: &quot;replace&quot;,&#10;    &quot;priority&quot;: 100&#10;  }&#10;]'
          ></textarea>
          <div class="field-help">
            请输入有效的JSON格式数据，可以是单个规则对象或规则数组
          </div>
        </div>
      </div>

      <template #footer>
        <Button
          label="取消"
          icon="pi pi-times"
          severity="secondary"
          @click="jsonImportVisible = false"
        />
        <Button
          label="导入规则"
          icon="pi pi-upload"
          @click="handleJsonImport"
          :loading="importing"
        />
      </template>
    </Dialog>

    <!-- 文件导入对话框 -->
    <Dialog
      v-model:visible="fileImportVisible"
      header="文件导入规则"
      :style="{ width: '60vw', maxWidth: '800px' }"
      :maximizable="true"
      :modal="true"
    >
      <div class="dialog-content">
        <!-- 文件选择区域 -->
        <Card class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-file-import text-primary"></i>
              <span>选择文件</span>
            </div>
          </template>
          <template #content>
            <div class="field-horizontal mb-6">
              <div class="field-label-left">
                <label><i class="pi pi-file mr-2"></i>选择文件</label>
              </div>
              <div class="field-content">
                <input
                  ref="fileInput"
                  type="file"
                  accept=".txt,.json"
                  @change="onFileSelect"
                  style="display: none"
                />
                <Button
                  label="选择文件"
                  icon="pi pi-folder-open"
                  @click="selectFile"
                  severity="secondary"
                  outlined
                />
                <div v-if="selectedFile" class="mt-3">
                  <Message severity="info" :closable="false">
                    <div class="flex align-items-center gap-2">
                      <i class="pi pi-file"></i>
                      <span>{{ selectedFile.name }}</span>
                      <small>({{ formatFileSize(selectedFile.size) }})</small>
                    </div>
                  </Message>
                </div>
                <div class="field-help">
                  支持 .txt 和 .json 格式文件
                </div>
              </div>
            </div>
          </template>
        </Card>

        <!-- 文件预览区域 -->
        <Card v-if="filePreview" class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-eye text-primary"></i>
              <span>文件预览</span>
            </div>
          </template>
          <template #content>
            <div class="field-horizontal mb-6">
              <div class="field-label-left">
                <label><i class="pi pi-code mr-2"></i>文件内容</label>
              </div>
              <div class="field-content">
                <textarea
                  v-model="filePreview"
                  class="uniform-textarea"
                  rows="8"
                  readonly
                  placeholder="文件内容将在此处显示..."
                ></textarea>
                <div class="field-help">
                  文件内容预览（只读）
                </div>
              </div>
            </div>
          </template>
        </Card>
      </div>

      <template #footer>
        <Button
          label="取消"
          icon="pi pi-times"
          severity="secondary"
          @click="fileImportVisible = false"
        />
        <Button
          label="导入规则"
          icon="pi pi-upload"
          @click="handleFileImport"
          :loading="importing"
          :disabled="!selectedFile"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed, watch, nextTick } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import Select from 'primevue/select'
import BatchImportDialog from './BatchImportDialog.vue'
import ScopeConfigPanel from './ScopeConfigPanel.vue'
import {
  getPersistentRules,
  createPersistentRule,
  updatePersistentRule,
  deletePersistentRule,
} from '@/api/headerRule'
import type {
  PersistentHeaderRule,
  PersistentHeaderRuleCreate,
  HeaderScope,
  ReplaceStrategy,
} from '@/types/headerRule'

const toast = useToast()
const confirm = useConfirm()

const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const rules = ref<PersistentHeaderRule[]>([])
const editingRule = ref<PersistentHeaderRule | null>(null)
const showValidation = ref(false)
const batchImportVisible = ref(false) // 批量导入对话框显示状态
const textImportVisible = ref(false) // 文本导入对话框显示状态
const jsonImportVisible = ref(false) // JSON导入对话框显示状态
const fileImportVisible = ref(false) // 文件导入对话框显示状态
const importing = ref(false) // 批量导入状态

// 导入内容状态
const textImportContent = ref('') // 文本导入内容
const jsonImportContent = ref('') // JSON导入内容

// 文件导入状态
const selectedFile = ref<File | null>(null) // 选中的文件
const filePreview = ref('') // 文件预览内容
const fileInput = ref<HTMLInputElement | null>(null) // 文件输入引用
const scopePanel = ref<InstanceType<typeof ScopeConfigPanel>>() // 作用域面板引用
const isActiveCheckboxRef = ref<InstanceType<any>>() // 启用规则复选框引用

// 搜索和过滤相关
const searchQuery = ref('')
const statusFilter = ref<boolean | null>(null)
const strategyFilter = ref<string | null>(null)
const scopeFilter = ref<string | null>(null)
const pageSize = ref(10)

const replaceStrategies = [
  { label: '完全替换', value: 'REPLACE' },
  { label: '追加', value: 'APPEND' },
  { label: '前置', value: 'PREPEND' },
  { label: '条件替换', value: 'CONDITIONAL' },
  { label: '存在则替换', value: 'UPSERT' },
]

// 过滤选项
const statusOptions = [
  { label: '启用', value: true },
  { label: '禁用', value: false },
]

const strategyOptions = replaceStrategies

const scopeOptions = [
  { label: '全局', value: 'global' },
  { label: '有作用域', value: 'scoped' },
]

const formData = reactive<PersistentHeaderRuleCreate>({
  name: '',
  header_name: '',
  header_value: '',
  replace_strategy: 'REPLACE' as ReplaceStrategy,
  priority: 50,
  is_active: true,
})

let scopeData = reactive<HeaderScope>({
  protocol_pattern: '',
  host_pattern: '',
  path_pattern: '',
  use_regex: false,
})

onMounted(() => {
  loadRules()
})

// 监听启用状态变化，手动添加/移除p-highlight类
watch(() => formData.is_active, async (newValue) => {
  await nextTick()
  if (isActiveCheckboxRef.value) {
    const checkboxBox = isActiveCheckboxRef.value.$el?.querySelector('.p-checkbox-box')
    if (checkboxBox) {
      if (newValue) {
        checkboxBox.classList.add('p-highlight')
      } else {
        checkboxBox.classList.remove('p-highlight')
      }
    }
  }
})

async function loadRules() {
  loading.value = true
  try {
    const res = await getPersistentRules(false)
    if (res.success) {
      rules.value = res.data.rules || []
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '加载失败',
      detail: error.message || '加载规则列表失败',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

function showCreateDialog() {
  editingRule.value = null
  resetForm()
  dialogVisible.value = true
}

function showEditDialog(rule: PersistentHeaderRule) {
  editingRule.value = rule
  formData.name = rule.name
  formData.header_name = rule.header_name
  formData.header_value = rule.header_value
  formData.replace_strategy = rule.replace_strategy
  formData.priority = rule.priority
  formData.is_active = rule.is_active

  // 加载作用域配置
  Object.assign(scopeData, rule.scope || {
    protocol_pattern: '',
    host_pattern: '',
    path_pattern: '',
    use_regex: false,
  })

  dialogVisible.value = true
}

function resetForm() {
  formData.name = ''
  formData.header_name = ''
  formData.header_value = ''
  formData.replace_strategy = 'REPLACE' as ReplaceStrategy
  formData.priority = 50
  formData.is_active = true
  showValidation.value = false
}

async function saveRule() {
  showValidation.value = true

  // 验证必填字段
  if (!formData.name || !formData.header_name || !formData.header_value) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请填写必填字段',
      life: 3000,
    })
    return
  }

  // 验证作用域配置（简化版本，暂时不移交验证给子组件）
  // TODO: 可以添加更详细的作用域验证逻辑

  saving.value = true
  try {
    const payload: any = { ...formData }
    
    // 处理作用域配置
    payload.scope = scopeData

    if (editingRule.value) {
      await updatePersistentRule(editingRule.value.id, payload)
      toast.add({
        severity: 'success',
        summary: '更新成功',
        detail: '规则已更新',
        life: 3000,
      })
    } else {
      await createPersistentRule(payload)
      toast.add({
        severity: 'success',
        summary: '创建成功',
        detail: '规则已创建',
        life: 3000,
      })
    }

    dialogVisible.value = false
    await loadRules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '保存规则失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function confirmDelete(rule: PersistentHeaderRule) {
  confirm.require({
    message: `确定要删除规则 "${rule.name}" 吗？`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    accept: () => deleteRule(rule.id),
  })
}

async function deleteRule(ruleId: number) {
  try {
    await deletePersistentRule(ruleId)
    toast.add({
      severity: 'success',
      summary: '删除成功',
      detail: '规则已删除',
      life: 3000,
    })
    await loadRules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '删除失败',
      detail: error.message || '删除规则失败',
      life: 3000,
    })
  }
}

async function toggleActive(rule: PersistentHeaderRule) {
  try {
    await updatePersistentRule(rule.id, { is_active: !rule.is_active })
    toast.add({
      severity: 'success',
      summary: '状态已更新',
      detail: `规则已${!rule.is_active ? '启用' : '禁用'}`,
      life: 3000,
    })
    await loadRules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '更新状态失败',
      life: 3000,
    })
  }
}

function getPrioritySeverity(priority: number) {
  if (priority >= 80) return 'danger'
  if (priority >= 50) return 'warning'
  return 'info'
}

function truncate(text: string, length: number) {
  if (text.length <= length) return text
  return text.substring(0, length) + '...'
}

// 计算属性：过滤后的规则列表
const filteredRules = computed(() => {
  let filtered = rules.value

  // 搜索过滤
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(rule =>
      rule.name.toLowerCase().includes(query) ||
      rule.header_name.toLowerCase().includes(query) ||
      rule.header_value.toLowerCase().includes(query)
    )
  }

  // 状态过滤
  if (statusFilter.value !== null) {
    filtered = filtered.filter(rule => rule.is_active === statusFilter.value)
  }

  // 策略过滤
  if (strategyFilter.value) {
    filtered = filtered.filter(rule => rule.replace_strategy === strategyFilter.value)
  }

  // 作用域过滤
  if (scopeFilter.value) {
    if (scopeFilter.value === 'global') {
      filtered = filtered.filter(rule => !rule.scope)
    } else if (scopeFilter.value === 'scoped') {
      filtered = filtered.filter(rule => rule.scope)
    }
  }

  return filtered
})

// 清除过滤器
function clearFilters() {
  searchQuery.value = ''
  statusFilter.value = null
  strategyFilter.value = null
  scopeFilter.value = null
}

// 显示批量导入对话框
function showBatchImportDialog() {
  batchImportVisible.value = true
}

// 显示文件导入对话框
function showFileImportDialog() {
  fileImportVisible.value = true
}

function showTextImportDialog() {
  textImportVisible.value = true
}

function showJsonImportDialog() {
  jsonImportVisible.value = true
}

// 处理批量导入
async function handleBatchImport(rules: PersistentHeaderRuleCreate[]) {
  importing.value = true
  try {
    let successCount = 0
    let errorCount = 0

    // 批量创建规则
    for (const rule of rules) {
      try {
        await createPersistentRule(rule)
        successCount++
      } catch (error) {
        errorCount++
        console.error('创建规则失败:', error)
      }
    }

    if (errorCount === 0) {
      toast.add({
        severity: 'success',
        summary: '批量导入成功',
        detail: `成功导入 ${successCount} 条规则`,
        life: 3000,
      })
    } else {
      toast.add({
        severity: 'warn',
        summary: '批量导入完成',
        detail: `成功导入 ${successCount} 条，失败 ${errorCount} 条`,
        life: 5000,
      })
    }

    // 刷新规则列表
    await loadRules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '批量导入失败',
      detail: error.message || '导入过程中发生错误',
      life: 3000,
    })
  } finally {
    importing.value = false
    batchImportVisible.value = false
  }
}

// 处理文本导入
async function handleTextImport() {
  if (!textImportContent.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '导入失败',
      detail: '请输入要导入的文本内容',
      life: 3000,
    })
    return
  }

  importing.value = true
  try {
    const lines = textImportContent.value.trim().split('\n')
    const rules: PersistentHeaderRuleCreate[] = []

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim()
      if (!line) continue

      const parts = line.split('|').map(part => part.trim())
      if (parts.length < 4) {
        throw new Error(`第 ${i + 1} 行格式错误：至少需要4个字段（规则名称|Header名称|Header值|替换策略）`)
      }

      const [name, header_name, header_value, replace_strategy, priorityStr] = parts
      const priority = priorityStr ? parseInt(priorityStr, 10) : 50

      if (isNaN(priority) || priority < 0 || priority > 100) {
        throw new Error(`第 ${i + 1} 行优先级错误：必须是0-100之间的数字`)
      }

      if (!['replace', 'append', 'skip'].includes(replace_strategy)) {
        throw new Error(`第 ${i + 1} 行替换策略错误：必须是 replace、append 或 skip`)
      }

      rules.push({
        name,
        header_name,
        header_value,
        replace_strategy: replace_strategy as 'replace' | 'append' | 'skip',
        priority,
        is_active: true
      })
    }

    await handleBatchImport(rules)
    textImportContent.value = ''
    textImportVisible.value = false

    toast.add({
      severity: 'success',
      summary: '文本导入成功',
      detail: `成功导入 ${rules.length} 条规则`,
      life: 3000,
    })
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '文本导入失败',
      detail: error.message || '导入过程中发生错误',
      life: 3000,
    })
  } finally {
    importing.value = false
  }
}

// 处理JSON导入
async function handleJsonImport() {
  if (!jsonImportContent.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '导入失败',
      detail: '请输入要导入的JSON内容',
      life: 3000,
    })
    return
  }

  importing.value = true
  try {
    const jsonData = JSON.parse(jsonImportContent.value)
    let rules: PersistentHeaderRuleCreate[] = []

    if (Array.isArray(jsonData)) {
      rules = jsonData
    } else if (typeof jsonData === 'object') {
      rules = [jsonData]
    } else {
      throw new Error('JSON格式错误：必须是对象或数组')
    }

    // 验证规则格式
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i]
      if (!rule.name || !rule.header_name || !rule.header_value || !rule.replace_strategy) {
        throw new Error(`第 ${i + 1} 条规则缺少必要字段：name、header_name、header_value、replace_strategy`)
      }

      if (!['replace', 'append', 'skip'].includes(rule.replace_strategy)) {
        throw new Error(`第 ${i + 1} 条规则替换策略错误：必须是 replace、append 或 skip`)
      }

      if (rule.priority !== undefined) {
        if (typeof rule.priority !== 'number' || rule.priority < 0 || rule.priority > 100) {
          throw new Error(`第 ${i + 1} 条规则优先级错误：必须是0-100之间的数字`)
        }
      } else {
        rule.priority = 50
      }

      rule.is_active = rule.is_active !== undefined ? rule.is_active : true
    }

    await handleBatchImport(rules)
    jsonImportContent.value = ''
    jsonImportVisible.value = false

    toast.add({
      severity: 'success',
      summary: 'JSON导入成功',
      detail: `成功导入 ${rules.length} 条规则`,
      life: 3000,
    })
  } catch (error: any) {
    if (error instanceof SyntaxError) {
      toast.add({
        severity: 'error',
        summary: 'JSON解析失败',
        detail: '请输入有效的JSON格式数据',
        life: 3000,
      })
    } else {
      toast.add({
        severity: 'error',
        summary: 'JSON导入失败',
        detail: error.message || '导入过程中发生错误',
        life: 3000,
      })
    }
  } finally {
    importing.value = false
  }
}

// 文件选择方法
function selectFile() {
  fileInput.value?.click()
}

// 文件选择处理
function onFileSelect(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]

  if (!file) return

  // 检查文件类型
  const fileName = file.name.toLowerCase()
  if (!fileName.endsWith('.txt') && !fileName.endsWith('.json')) {
    toast.add({
      severity: 'warn',
      summary: '文件格式错误',
      detail: '只支持 .txt 和 .json 格式文件',
      life: 3000,
    })
    return
  }

  selectedFile.value = file

  // 读取文件内容进行预览
  const reader = new FileReader()
  reader.onload = (e) => {
    const content = e.target?.result as string
    filePreview.value = content
  }
  reader.onerror = () => {
    toast.add({
      severity: 'error',
      summary: '文件读取失败',
      detail: '无法读取文件内容，请重试',
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

// 处理文件导入
async function handleFileImport() {
  if (!selectedFile.value || !filePreview.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '导入失败',
      detail: '请选择要导入的文件',
      life: 3000,
    })
    return
  }

  importing.value = true
  try {
    const fileName = selectedFile.value.name.toLowerCase()
    let rules: PersistentHeaderRuleCreate[] = []

    if (fileName.endsWith('.json')) {
      // JSON文件导入
      try {
        const jsonData = JSON.parse(filePreview.value)
        if (Array.isArray(jsonData)) {
          rules = jsonData
        } else if (typeof jsonData === 'object') {
          rules = [jsonData]
        } else {
          throw new Error('JSON格式错误：必须是对象或数组')
        }

        // 验证规则格式
        for (let i = 0; i < rules.length; i++) {
          const rule = rules[i]
          if (!rule.name || !rule.header_name || !rule.header_value || !rule.replace_strategy) {
            throw new Error(`第 ${i + 1} 条规则缺少必要字段：name、header_name、header_value、replace_strategy`)
          }

          if (!['replace', 'append', 'skip'].includes(rule.replace_strategy)) {
            throw new Error(`第 ${i + 1} 条规则替换策略错误：必须是 replace、append 或 skip`)
          }

          if (rule.priority !== undefined) {
            if (typeof rule.priority !== 'number' || rule.priority < 0 || rule.priority > 100) {
              throw new Error(`第 ${i + 1} 条规则优先级错误：必须是0-100之间的数字`)
            }
          } else {
            rule.priority = 50
          }

          rule.is_active = rule.is_active !== undefined ? rule.is_active : true
        }
      } catch (error: any) {
        if (error instanceof SyntaxError) {
          throw new Error('JSON解析失败：请输入有效的JSON格式数据')
        } else {
          throw error
        }
      }
    } else if (fileName.endsWith('.txt')) {
      // 文本文件导入
      const lines = filePreview.value.trim().split('\n')

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim()
        if (!line) continue

        const parts = line.split('|').map(part => part.trim())
        if (parts.length < 4) {
          throw new Error(`第 ${i + 1} 行格式错误：至少需要4个字段（规则名称|Header名称|Header值|替换策略）`)
        }

        const [name, header_name, header_value, replace_strategy, priorityStr] = parts
        const priority = priorityStr ? parseInt(priorityStr, 10) : 50

        if (isNaN(priority) || priority < 0 || priority > 100) {
          throw new Error(`第 ${i + 1} 行优先级错误：必须是0-100之间的数字`)
        }

        if (!['replace', 'append', 'skip'].includes(replace_strategy)) {
          throw new Error(`第 ${i + 1} 行替换策略错误：必须是 replace、append 或 skip`)
        }

        rules.push({
          name,
          header_name,
          header_value,
          replace_strategy: replace_strategy as 'replace' | 'append' | 'skip',
          priority,
          is_active: true
        })
      }
    }

    // 执行批量导入
    await handleBatchImport(rules)

    // 清理状态
    selectedFile.value = null
    filePreview.value = ''
    fileImportVisible.value = false

    toast.add({
      severity: 'success',
      summary: '文件导入成功',
      detail: `成功从 ${selectedFile.value?.name} 导入 ${rules.length} 条规则`,
      life: 3000,
    })
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '文件导入失败',
      detail: error.message || '导入过程中发生错误',
      life: 3000,
    })
  } finally {
    importing.value = false
  }
}
</script>

<style scoped lang="scss">
.header-rules-config {
  // 搜索过滤工具栏样式
  .search-filter-card {
    :deep(.p-card-content) {
      padding: 1rem;
    }

    .search-filter-toolbar {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;

      .search-area {
        flex: 0 0 280px;
        max-width: 280px;

        :deep(.p-iconfield) {
          display: flex;
          align-items: center;
          position: relative;

          .p-inputicon {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            left: 0.75rem;
            color: var(--text-color-secondary);
          }
        }

        .search-input {
          width: 100%;
          border-radius: 8px;
          border: 2px solid var(--surface-border);
          transition: all 0.2s ease;
          padding-left: 2.5rem;

          &:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
          }
        }
      }

      .filter-area {
        display: flex;
        gap: 1rem;
        align-items: center;

        .filter-group {
          display: flex;
          align-items: center;
          gap: 0.5rem;

          .filter-label {
            font-weight: 500;
            color: var(--text-color-secondary);
            white-space: nowrap;
          }

          .filter-dropdown {
            min-width: 120px;
          }
        }
      }

      .action-area {
        display: flex;
        gap: 0.5rem;
        align-items: center;
        margin-left: auto;
        flex-wrap: wrap;
      }
    }
  }

  .rules-table {
    .header-value {
      font-family: monospace;
      font-size: 0.9em;
    }
  }
}

// 对话框样式优化
:deep(.rule-dialog) {
  .p-dialog-header {
    padding: 1.5rem;
    border-bottom: 1px solid var(--surface-border);
  }

  .p-dialog-content {
    padding: 0;
    overflow: hidden;
  }

  .p-dialog-footer {
    padding: 1.5rem 1.5rem 1.25rem 1.5rem; // 增加顶部padding，提供更好间距
    border-top: 1px solid var(--surface-border);
    background: var(--surface-50);
    display: flex;
    gap: 0.75rem; // 按钮之间的间距
    justify-content: flex-end; // 按钮右对齐
  }
}

.dialog-content {
  padding: 2rem 2rem 3rem 2rem; // 增加底部padding，避免按钮贴边
  max-height: calc(80vh - 180px);
  overflow-y: auto;
  overflow-x: hidden;

  // 卡片通用样式
  :deep(.p-card) {
    border-radius: 12px;
    border: 1px solid var(--surface-border);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    margin-bottom: 1.5rem;
    background: var(--surface-0);

    &:last-child {
      margin-bottom: 0;
    }

    .p-card-header {
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid var(--surface-border);
      background: var(--surface-50);
    }

    .p-card-title {
      font-size: 1rem;
      font-weight: 600;
      color: var(--text-color);
      margin: 0;
      display: flex;
      align-items: center;
      gap: 0.5rem;

      i {
        color: var(--primary-color);
        font-size: 1.1rem;
      }
    }

    .p-card-content {
      padding: 1.5rem;
    }
  }

  // 表单字段样式
  .field {
    margin-bottom: 1.5rem;

    &:last-child {
      margin-bottom: 0;
    }

    // 确保full-width字段不受grid限制
    &.col-12 {
      :deep(.p-float-label),
      :deep(.p-floatlabel),
      :deep(.p-inputtextarea),
      :deep(.p-textarea) {
        width: 100% !important;
        max-width: 100% !important;
      }
    }
  }

  // 浮动标签优化
  :deep(.p-float-label),
  :deep(.p-floatlabel) {
    width: 100% !important;
    display: block !important;

    label {
      font-weight: 500;
      font-size: 0.95rem;
      color: var(--text-color-secondary);
      left: 0.75rem;
      transition: all 0.2s ease;

      i {
        color: var(--primary-color);
        margin-right: 0.25rem;
      }
    }

    input:focus ~ label,
    input.p-filled ~ label,
    textarea:focus ~ label,
    textarea.p-filled ~ label,
    .p-inputwrapper-focus ~ label,
    .p-inputwrapper-filled ~ label {
      top: -0.75rem;
      font-size: 0.875rem;
      background: var(--surface-0);
      padding: 0 0.25rem;
    }
  }

  // 输入组件样式
  :deep(.p-inputtext),
  :deep(.p-inputnumber-input) {
    width: 100% !important;
    padding: 0.75rem !important;
    font-size: 0.95rem !important;
    border: 1px solid var(--p-form-field-border-color, #cbd5e1) !important;
    border-style: solid !important;
    border-radius: 6px !important;
    transition: all 0.2s ease !important;
    background: var(--surface-0) !important;

    &:enabled:hover {
      border-color: var(--p-primary-color, #10b981) !important;
      border-style: solid !important;
      box-shadow: 0 0 0 1px var(--p-primary-color, #10b981) !important;
    }

    &:enabled:focus {
      border: 2px solid var(--p-primary-color, #10b981) !important;
      border-style: solid !important;
      box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15) !important;
      outline: none !important;
    }

    &.p-invalid {
      border-color: var(--p-inputtext-invalid-border-color, #f87171) !important;
      border-style: solid !important;

      &:enabled:focus {
        border-width: 2px !important;
        border-style: solid !important;
        box-shadow: 0 0 0 3px rgba(255, 0, 0, 0.15) !important;
      }
    }
  }

  :deep(.p-inputtextarea),
  :deep(.p-textarea) {
    width: 100% !important;
    padding: 0.75rem !important;
    font-size: 0.95rem !important;
    border: 1px solid var(--p-form-field-border-color, #cbd5e1) !important;
    border-style: solid !important;
    border-radius: 6px !important;
    transition: all 0.2s ease !important;
    resize: vertical !important;
    min-height: 80px !important;
    background: var(--surface-0) !important;
    font-family: inherit !important;
    line-height: 1.5 !important;

    &:enabled:hover {
      border-color: var(--p-primary-color, #10b981) !important;
      border-style: solid !important;
      box-shadow: 0 0 0 1px var(--p-primary-color, #10b981) !important;
    }

    &:enabled:focus {
      border: 2px solid var(--p-primary-color, #10b981) !important;
      border-style: solid !important;
      box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15) !important;
      outline: none !important;
    }

    &.p-invalid {
      border-color: var(--p-inputtext-invalid-border-color, #f87171) !important;
      border-style: solid !important;

      &:enabled:focus {
        border-width: 2px !important;
        border-style: solid !important;
        box-shadow: 0 0 0 3px rgba(255, 0, 0, 0.15) !important;
      }
    }
  }

  // 针对FloatLabel容器内的textarea额外强化
  :deep(.p-floatlabel) {
    .p-inputtextarea,
    .p-textarea,
    textarea {
      border: 1px solid var(--p-form-field-border-color, #cbd5e1) !important;
      border-style: solid !important;
      
      &:hover {
        border: 1px solid var(--p-primary-color, #10b981) !important;
        border-style: solid !important;
        box-shadow: 0 0 0 1px var(--p-primary-color, #10b981) !important;
      }
      
      &:focus {
        border: 2px solid var(--p-primary-color, #10b981) !important;
        border-style: solid !important;
        border-width: 2px !important;
        border-color: var(--p-primary-color, #10b981) !important;
        box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15) !important;
        outline: none !important;
      }
    }
  }

  :deep(.p-dropdown) {
    width: 100%;
    border: 1px solid var(--surface-border);
    border-radius: 6px;
    transition: all 0.2s ease;

    &:not(.p-disabled):hover {
      border-color: var(--primary-color);
    }

    &:not(.p-disabled).p-focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 2px rgba(var(--primary-color-rgb), 0.1);
    }
  }

  // 提示文本样式
  small {
    display: block;
    margin-top: 0.5rem;
    font-size: 0.875rem;
    color: var(--text-color-secondary);
    line-height: 1.4;

    &.text-color-secondary {
      color: var(--text-color-secondary);
    }
  }

  // 复选框样式
  :deep(.p-checkbox) {
    .p-checkbox-box {
      width: 18px;
      height: 18px;
      border-radius: 4px;
      border: 1px solid var(--surface-border);
      background: var(--surface-0);
      transition: all 0.2s ease;

      &.p-highlight {
        background: var(--primary-color);
        border-color: var(--primary-color);

        // 修复：确保SVG图标显示
        .p-checkbox-icon {
          display: inline-flex !important;
          color: white !important;  // SVG图标使用currentColor，设置color即可
          width: 14px !important;
          height: 14px !important;
        }
      }
    }
  }

  // 消息组件样式
  :deep(.p-message) {
    border-radius: 8px;
    border: none;
    margin: 0;

    .p-message-wrapper {
      border-radius: 8px;
      padding: 0.875rem 1rem;
    }

    .p-message-icon {
      font-size: 1.25rem;
    }

    &.p-message-info .p-message-wrapper {
      background: var(--blue-50);
      color: var(--blue-900);
      border-left: 3px solid var(--blue-500);
    }
  }

  // 统一输入框样式
  .uniform-input {
    width: 100% !important;
    height: 40px !important;
    border: 2px solid var(--surface-border) !important;
    border-radius: 8px !important;
    padding: 0 0.75rem !important;
    font-size: 14px !important;
    line-height: 1.5 !important;
    transition: all 0.2s ease !important;
    box-sizing: border-box !important;
    background: var(--surface-0) !important;
    color: var(--text-color) !important;

    &:hover:not(.p-disabled) {
      border-color: var(--primary-color) !important;
    }

    &:focus {
      border-color: var(--primary-color) !important;
      box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1) !important;
      outline: none !important;
    }

    &::placeholder {
      color: var(--text-color-secondary) !important;
      opacity: 0.7 !important;
    }
  }

  // 统一文本域样式
  .uniform-textarea {
    width: 100% !important;
    min-height: 120px !important;
    border: 2px solid var(--surface-border) !important;
    border-radius: 8px !important;
    padding: 0.75rem !important;
    font-size: 14px !important;
    line-height: 1.5 !important;
    transition: all 0.2s ease !important;
    box-sizing: border-box !important;
    background: var(--surface-0) !important;
    color: var(--text-color) !important;
    resize: vertical !important;
    font-family: inherit !important;

    &:hover:not(.p-disabled) {
      border-color: var(--primary-color) !important;
    }

    &:focus {
      border-color: var(--primary-color) !important;
      box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1) !important;
      outline: none !important;
    }

    &::placeholder {
      color: var(--text-color-secondary) !important;
      opacity: 0.7 !important;
    }
  }

  // 统一配色方案 - 按钮样式
  .uniform-button {
    background: var(--primary-color) !important;
    border: 1px solid var(--primary-color) !important;
    color: white !important;
    padding: 0.5rem 1.5rem !important;
    font-size: 0.95rem !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
    transition: all 0.2s ease !important;

    &:hover {
      background: var(--primary-100) !important;
      border-color: var(--primary-100) !important;
      transform: translateY(-1px) !important;
    }

    &.p-button-secondary {
      background: var(--surface-100) !important;
      border-color: var(--surface-300) !important;
      color: var(--text-color) !important;

      &:hover {
        background: var(--surface-200) !important;
        border-color: var(--surface-400) !important;
      }
    }

    &.p-button-danger {
      background: var(--red-500) !important;
      border-color: var(--red-500) !important;

      &:hover {
        background: var(--red-600) !important;
        border-color: var(--red-600) !important;
      }
    }

    &.p-button-success {
      background: var(--green-500) !important;
      border-color: var(--green-500) !important;

      &:hover {
        background: var(--green-600) !important;
        border-color: var(--green-600) !important;
      }
    }

    &.p-button-warning {
      background: var(--orange-500) !important;
      border-color: var(--orange-500) !important;

      &:hover {
        background: var(--orange-600) !important;
        border-color: var(--orange-600) !important;
      }
    }

    &.p-button-info {
      background: var(--blue-500) !important;
      border-color: var(--blue-500) !important;

      &:hover {
        background: var(--blue-600) !important;
        border-color: var(--blue-600) !important;
      }
    }
  }

  // 统一配色方案 - 卡片样式
  .uniform-card {
    background: var(--surface-card) !important;
    border: 1px solid var(--surface-border) !important;
    border-radius: 12px !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08) !important;
    transition: all 0.3s ease !important;

    &:hover {
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12) !important;
      border-color: var(--primary-200) !important;
    }

    .p-card-header {
      background: linear-gradient(135deg, var(--surface-0), var(--surface-50)) !important;
      border-bottom: 1px solid var(--surface-border) !important;
      border-radius: 12px 12px 0 0 !important;
      padding: 1rem 1.5rem !important;
    }

    .p-card-content {
      padding: 1.5rem !important;
    }

    .p-card-title {
      color: var(--text-color) !important;
      font-size: 1.1rem !important;
      font-weight: 600 !important;
      margin: 0 !important;
    }

    .p-card-subtitle {
      color: var(--text-color-secondary) !important;
      font-size: 0.9rem !important;
      margin-top: 0.25rem !important;
    }
  }

  // 统一配色方案 - 图标样式
  .uniform-icon {
    color: var(--primary-color) !important;

    &.text-success {
      color: var(--green-500) !important;
    }

    &.text-info {
      color: var(--blue-500) !important;
    }

    &.text-warning {
      color: var(--orange-500) !important;
    }

    &.text-danger {
      color: var(--red-500) !important;
    }
  }

  // 统一配色方案 - 标签样式
  .uniform-tag {
    background: var(--primary-50) !important;
    color: var(--primary-600) !important;
    border: 1px solid var(--primary-200) !important;
    border-radius: 16px !important;
    padding: 0.25rem 0.75rem !important;
    font-size: 0.75rem !important;
    font-weight: 500 !important;

    &.success {
      background: var(--green-50) !important;
      color: var(--green-600) !important;
      border-color: var(--green-200) !important;
    }

    &.info {
      background: var(--blue-50) !important;
      color: var(--blue-600) !important;
      border-color: var(--blue-200) !important;
    }

    &.warning {
      background: var(--orange-50) !important;
      color: var(--orange-600) !important;
      border-color: var(--orange-200) !important;
    }

    &.danger {
      background: var(--red-50) !important;
      color: var(--red-600) !important;
      border-color: var(--red-200) !important;
    }

    &.secondary {
      background: var(--surface-100) !important;
      color: var(--text-color-secondary) !important;
      border-color: var(--surface-300) !important;
    }
  }

  // 应用统一样式到卡片组件
  :deep(.p-card) {
    @extend .uniform-card;
    margin-bottom: 1.5rem;
    &:last-child {
      margin-bottom: 0;
    }
  }

  // 在field-horizontal中应用统一样式
  .field-horizontal {
    @apply flex flex-col lg:flex-row lg:items-start lg:gap-4 mb-6;
    width: 100%;
    max-width: 100%;
    box-sizing: border-box;

    .field-label-left {
      @apply lg:w-48 lg:pt-2 lg:text-right font-medium text-sm mb-2 lg:mb-0;
      min-width: 120px;
      max-width: 100%;
      flex-shrink: 0;
    }

    .field-content {
      @apply flex-1 min-w-0 max-w-full;

      // 应用统一的输入组件样式
      .p-inputtext,
      .p-inputnumber input,
      .p-dropdown,
      .p-multiselect {
        @extend .uniform-input;
      }

      .p-textarea {
        @extend .uniform-textarea;
      }

      .p-checkbox,
      .p-radiobutton {
        max-width: 100%;
        box-sizing: border-box;
        overflow: hidden;
      }

      .field-help {
        @apply text-xs mt-2 block;
        word-wrap: break-word;
        max-width: 100%;
      }
    }
  }
}
</style>

<!-- 暴力强制的全局样式，强制修复footer间距问题 -->
<style lang="scss">
/* 强制覆盖所有Dialog组件的footer样式 */
.p-dialog-footer {
  padding: 1.5rem 2rem 2rem 2rem !important;
  display: flex !important;
  gap: 0.75rem !important;
  justify-content: flex-end !important;
  align-items: center !important;
  border-top: 1px solid var(--surface-border) !important;
  background: var(--surface-50) !important;
}

/* 超暴力强制样式，使用更高权重 */
div.p-dialog > div.p-dialog-footer {
  padding: 1.5rem 2rem 2rem 2rem !important;
}

div[class*="p-dialog"] > div[class*="p-dialog-footer"] {
  padding: 1.5rem 2rem 2rem 2rem !important;
}

/* 最后的保险措施 */
.p-dialog-content + .p-dialog-footer {
  padding: 1.5rem 2rem 2rem 2rem !important;
}
</style>
