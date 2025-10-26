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
              label="批量添加"
              icon="pi pi-list"
              @click="showBatchImportDialog"
              severity="success"
              outlined
            />
            <Button
              label="文件导入"
              icon="pi pi-file-import"
              @click="showFileImportDialog"
              severity="success"
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
      :style="{ width: '1000px', maxHeight: '85vh' }"
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
              <div class="field col-12 md:col-6 mb-3">
                <FloatLabel>
                  <InputText
                    id="name"
                    v-model="formData.name"
                    :invalid="!formData.name && showValidation"
                  />
                  <label for="name">
                    规则名称 <span class="text-red-500">*</span>
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">用于标识此规则的用途</small>
              </div>

              <div class="field col-12 md:col-6 mb-3">
                <FloatLabel>
                  <InputText
                    id="header_name"
                    v-model="formData.header_name"
                    :invalid="!formData.header_name && showValidation"
                  />
                  <label for="header_name">
                    Header名称 <span class="text-red-500">*</span>
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">HTTP请求头的名称，区分大小写</small>
              </div>

              <div class="field col-12 mb-0">
                <FloatLabel>
                  <Textarea
                    id="header_value"
                    v-model="formData.header_value"
                    :autoResize="true"
                    rows="3"
                    :invalid="!formData.header_value && showValidation"
                  />
                  <label for="header_value">
                    Header值 <span class="text-red-500">*</span>
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">Header的实际值内容</small>
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
              <div class="field col-12 md:col-8 mb-3">
                <FloatLabel>
                  <Select
                    id="replace_strategy"
                    v-model="formData.replace_strategy"
                    :options="replaceStrategies"
                    optionLabel="label"
                    optionValue="value"
                  />
                  <label for="replace_strategy">替换策略</label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">定义如何处理已存在的Header</small>
              </div>

              <div class="field col-12 md:col-4 mb-3">
                <FloatLabel>
                  <InputNumber
                    id="priority"
                    v-model="formData.priority"
                    :min="0"
                    :max="100"
                    showButtons
                    buttonLayout="horizontal"
                    :step="1"
                  />
                  <label for="priority">优先级</label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">0-100，越大优先级越高</small>
              </div>

              <div class="field col-12 mb-0">
                <div class="flex align-items-center gap-2">
                  <Checkbox
                    inputId="is_active"
                    v-model="formData.is_active"
                    :binary="true"
                  />
                  <label for="is_active" class="font-medium cursor-pointer">
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
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
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
const importing = ref(false) // 批量导入状态
const scopePanel = ref<InstanceType<typeof ScopeConfigPanel>>() // 作用域面板引用

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
  // TODO: 实现文件导入对话框
  toast.add({
    severity: 'info',
    summary: '功能开发中',
    detail: '文件导入功能正在开发中',
    life: 3000,
  })
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
            border-radius: 8px;
            border: 2px solid var(--surface-border);
            transition: all 0.2s ease;

            &:focus {
              border-color: var(--primary-color);
              box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
            }
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
  .p-dialog-content {
    padding: 0;
    overflow-y: auto;
  }
}

.dialog-content {
  padding: 1.5rem;
  max-height: calc(85vh - 140px);
  overflow-y: auto;

  // 基本信息卡片样式
  .basic-info-card {
    :deep(.p-card-title) {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--primary-color);
      margin-bottom: 1rem;
    }

    :deep(.p-card-content) {
      padding-top: 0;
    }
  }

  // 高级配置卡片样式
  .advanced-config-card {
    :deep(.p-card-title) {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--primary-color);
      margin-bottom: 1rem;
    }

    :deep(.p-card-content) {
      padding-top: 0;
    }
  }

  // 作用域配置面板样式
  .scope-config-panel {
    margin-top: 1rem;
  }

  // 浮动标签优化
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

    &.p-invalid {
      border-color: var(--red-500);
      box-shadow: 0 0 0 3px rgba(var(--red-500-rgb), 0.1);
    }
  }

  :deep(.p-inputtextarea) {
    border-radius: 8px;
    border: 2px solid var(--surface-border);
    transition: all 0.2s ease;
    resize: vertical;

    &:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
    }

    &.p-invalid {
      border-color: var(--red-500);
      box-shadow: 0 0 0 3px rgba(var(--red-500-rgb), 0.1);
    }
  }

  // 复选框样式
  :deep(.p-checkbox) {
    .p-checkbox-box {
      width: 20px;
      height: 20px;
      border-radius: 4px;
      border: 2px solid var(--surface-border);
      transition: all 0.2s ease;
      cursor: pointer;

      &:hover {
        border-color: var(--primary-color);
      }

      &.p-highlight {
        background: var(--primary-color);
        border-color: var(--primary-color);
      }

      .p-checkbox-icon {
        transition: all 0.2s ease;
      }
    }

    &:not(.p-disabled):hover .p-checkbox-box {
      border-color: var(--primary-color);
    }
  }

  // 消息组件样式
  :deep(.p-message) {
    border-radius: 8px;
    border: none;
    margin: 0;

    .p-message-wrapper {
      border-radius: 8px;
      padding: 1rem;
    }

    &.p-message-info .p-message-wrapper {
      background: linear-gradient(135deg,
        var(--blue-50) 0%,
        var(--blue-100) 100%);
      border-left: 4px solid var(--blue-500);
    }
  }

  // 分隔线样式
  :deep(.p-divider) {
    margin: 1.5rem 0;

    &.my-4 {
      margin: 1.5rem 0;
    }
  }
}
</style>
