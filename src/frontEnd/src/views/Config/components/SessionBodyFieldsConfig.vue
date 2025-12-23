<template>
  <div class="session-body-fields-config">
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
                placeholder="搜索字段名称或值..."
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
                placeholder="全部"
                class="filter-select"
                :showClear="true"
              />
            </div>

            <div class="filter-group">
              <label class="filter-label">匹配策略:</label>
              <Select
                v-model="matchStrategyFilter"
                :options="matchStrategyFilterOptions"
                optionLabel="label"
                optionValue="value"
                placeholder="全部"
                class="filter-select"
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
              class="toolbar-btn"
              v-tooltip.top="'清除过滤器'"
            />
            <Button
              label="添加字段"
              icon="pi pi-plus"
              @click="showAddDialog"
              severity="success"
              class="toolbar-btn"
            />
            <Button
              label="刷新"
              icon="pi pi-refresh"
              @click="loadSessionBodyFields"
              :loading="loading"
              severity="secondary"
              outlined
              class="toolbar-btn"
            />
            <Button
              label="清除所有"
              icon="pi pi-trash"
              @click="confirmClearAll"
              severity="danger"
              outlined
              class="toolbar-btn"
            />
          </div>
        </div>
      </template>
    </Card>

    <!-- 批量操作工具栏 -->
    <div v-if="selectedFields.length > 0" class="batch-actions-toolbar mb-4">
      <Card>
        <template #content>
          <div class="flex align-items-center justify-content-between">
            <div class="flex align-items-center gap-2">
              <i class="pi pi-check-square text-primary text-xl"></i>
              <span class="font-medium">已选择 {{ selectedFields.length }} 项</span>
            </div>
            <div class="flex align-items-center gap-2">
              <Button
                label="批量删除"
                icon="pi pi-trash"
                severity="danger"
                @click="confirmBatchDelete"
                size="small"
              />
              <Button
                label="取消选择"
                icon="pi pi-times"
                severity="secondary"
                @click="clearSelection"
                size="small"
                outlined
              />
            </div>
          </div>
        </template>
      </Card>
    </div>

    <!-- Body字段列表 -->
    <DataTable
      :value="filteredFields"
      :loading="loading"
      v-model:selection="selectedFields"
      dataKey="id"
      stripedRows
      paginator
      :rows="pageSize"
      :rowsPerPageOptions="[5, 10, 20, 50]"
      sortField="created_at"
      :sortOrder="-1"
      class="session-table"
      responsiveLayout="stack"
      breakpoint="768px"
      :resizableColumns="true"
      columnResizeMode="fit"
    >
      <template #empty>
        <div class="empty-table-message">
          <i class="pi pi-inbox"></i>
          <p>暂无Body字段规则</p>
          <small>点击上方「添加字段」按钮创建新规则</small>
        </div>
      </template>
      <template #loading>
        <div class="loading-table-message">
          <i class="pi pi-spin pi-spinner"></i>
          <p>加载中...</p>
        </div>
      </template>
      <Column selectionMode="multiple" headerStyle="width: 50px; text-align: center;" bodyStyle="text-align: center;"></Column>
      <Column field="id" header="ID" sortable style="width: 80px"></Column>
      <Column field="field_name" header="字段名称" sortable></Column>
      <Column field="field_value" header="字段值">
        <template #body="{ data }">
          <span class="field-value" v-tooltip.top="data.field_value">{{ truncate(data.field_value, 30) }}</span>
        </template>
      </Column>
      <Column field="match_strategy" header="匹配策略" sortable style="width: 120px">
        <template #body="{ data }">
          <Tag :value="getMatchStrategyLabel(data.match_strategy)" :severity="getMatchStrategySeverity(data.match_strategy)"></Tag>
        </template>
      </Column>
      <Column field="content_types" header="适用类型" style="width: 180px">
        <template #body="{ data }">
          <div class="content-type-tags">
            <Tag 
              v-for="ct in (data.content_types || [])" 
              :key="ct" 
              :value="getContentTypeShortLabel(ct)" 
              severity="info"
              class="mr-1 mb-1"
            />
            <span v-if="!data.content_types || data.content_types.length === 0" class="text-color-secondary">所有</span>
          </div>
        </template>
      </Column>
      <Column field="priority" header="优先级" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.priority" :severity="getPrioritySeverity(data.priority)"></Tag>
        </template>
      </Column>
      <Column field="scope" header="作用域" style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.scope ? '有作用域' : '全局'" :severity="data.scope ? 'info' : 'secondary'"></Tag>
        </template>
      </Column>
      <Column field="is_active" header="状态" sortable style="width: 80px">
        <template #body="{ data }">
          <Tag :value="data.is_active ? '启用' : '禁用'" :severity="data.is_active ? 'success' : 'danger'"></Tag>
        </template>
      </Column>
      <Column field="expires_at" header="过期时间" sortable style="width: 160px">
        <template #body="{ data }">
          <span class="expires-time" :class="{ 'text-red-500': isExpired(data.expires_at) }">
            {{ formatExpiresAt(data.expires_at) }}
          </span>
        </template>
      </Column>
      <Column header="操作" style="width: 150px">
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

    <!-- 添加/编辑对话框 -->
    <Dialog
      v-model:visible="dialogVisible"
      :header="isEditing ? '编辑Body字段' : '添加Body字段'"
      :style="{
        width: '90vw',
        maxWidth: '900px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 基本信息 -->
        <Card class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-info-circle text-primary"></i>
              <span>基本信息</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-4">
                <label for="field_name" class="block mb-2 font-medium">
                  字段名称 <span class="text-red-500">*</span>
                </label>
                <InputText
                  id="field_name"
                  v-model="formData.field_name"
                  :disabled="isEditing"
                  class="uniform-input w-full"
                  placeholder="例如: token, sessionId"
                />
                <small class="text-color-secondary mt-1 block">Body中要替换的字段名</small>
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="match_strategy" class="block mb-2 font-medium">
                  匹配策略 <span class="text-red-500">*</span>
                </label>
                <Select
                  id="match_strategy"
                  v-model="formData.match_strategy"
                  :options="matchStrategyOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="选择匹配策略"
                  class="uniform-input w-full"
                />
                <small class="text-color-secondary mt-1 block">{{ getMatchStrategyDescription(formData.match_strategy) }}</small>
              </div>

              <div class="field col-12 mb-4">
                <label for="field_value" class="block mb-2 font-medium">
                  字段值 <span class="text-red-500">*</span>
                </label>
                <Textarea
                  id="field_value"
                  v-model="formData.field_value"
                  rows="3"
                  placeholder="例如: eyJhbGciOiJIUzI1NiIs..."
                  class="uniform-textarea w-full"
                  :autoResize="false"
                />
                <small class="text-color-secondary mt-1 block">要设置的新值（如新的Token）</small>
              </div>

              <div class="field col-12 mb-4" v-if="showMatchPattern">
                <label for="match_pattern" class="block mb-2 font-medium">
                  匹配模式
                </label>
                <InputText
                  id="match_pattern"
                  v-model="formData.match_pattern"
                  class="uniform-input w-full"
                  :placeholder="getMatchPatternPlaceholder(formData.match_strategy)"
                />
                <small class="text-color-secondary mt-1 block">{{ getMatchPatternDescription(formData.match_strategy) }}</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项 -->
        <Card class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-4">
                <label for="replace_strategy" class="block mb-2 font-medium">
                  替换策略
                </label>
                <Select
                  id="replace_strategy"
                  v-model="formData.replace_strategy"
                  :options="replaceStrategyOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="选择替换策略"
                  class="uniform-input w-full"
                />
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="content_types" class="block mb-2 font-medium">
                  适用Content-Type
                </label>
                <MultiSelect
                  id="content_types"
                  v-model="formData.content_types"
                  :options="contentTypeOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="选择适用的Content-Type"
                  class="uniform-input w-full"
                  display="chip"
                />
                <small class="text-color-secondary mt-1 block">不选则对所有类型生效</small>
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="priority" class="block mb-2 font-medium">
                  优先级 (0-100)
                </label>
                <InputNumber
                  id="priority"
                  v-model="formData.priority"
                  :min="0"
                  :max="100"
                  showButtons
                  buttonLayout="horizontal"
                  :step="1"
                  class="uniform-input w-full"
                />
                <small class="text-color-secondary mt-1 block">数值越大优先级越高</small>
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="ttl" class="block mb-2 font-medium">
                  生存时间 (秒)
                </label>
                <InputNumber
                  id="ttl"
                  v-model="formData.ttl"
                  :min="60"
                  :max="86400"
                  showButtons
                  buttonLayout="horizontal"
                  :step="60"
                  class="uniform-input w-full"
                />
                <small class="text-color-secondary mt-1 block">默认3600秒(1小时)，最大86400秒(24小时)</small>
              </div>

              <div class="field col-12 mb-4">
                <div class="flex align-items-center gap-3">
                  <Checkbox
                    id="is_active"
                    v-model="formData.is_active"
                    binary
                  />
                  <label for="is_active" class="font-medium cursor-pointer">
                    启用此字段规则
                  </label>
                </div>
              </div>
            </div>
          </template>
        </Card>

        <!-- 作用域配置 -->
        <ScopeConfigPanel
          :model-value="formData.scope ?? null"
          @update:model-value="(val) => formData.scope = val"
          title="作用域配置（可选）"
          description="配置规则的生效范围，不配置则对所有请求生效"
          :show-templates="true"
          :show-info="true"
          :show-advanced="false"
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
          :label="isEditing ? '保存' : '添加'"
          icon="pi pi-check"
          @click="saveField"
          :loading="saving"
        />
      </template>
    </Dialog>

    <!-- 预览对话框 -->
    <Dialog
      v-model:visible="previewDialogVisible"
      header="Body处理预览"
      :style="{
        width: '90vw',
        maxWidth: '900px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <Card class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-code text-primary"></i>
              <span>输入原始Body</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 mb-4">
                <label for="preview_content_type" class="block mb-2 font-medium">
                  Content-Type
                </label>
                <Select
                  id="preview_content_type"
                  v-model="previewForm.content_type"
                  :options="contentTypeOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="选择Content-Type"
                  class="uniform-input w-full"
                />
              </div>
              <div class="field col-12 mb-4">
                <label for="preview_body" class="block mb-2 font-medium">
                  原始Body
                </label>
                <Textarea
                  id="preview_body"
                  v-model="previewForm.body"
                  rows="8"
                  placeholder='{"token":"old-token","user":"test"}'
                  class="uniform-textarea w-full"
                  :autoResize="false"
                />
              </div>
              <div class="field col-12">
                <Button
                  label="预览处理结果"
                  icon="pi pi-eye"
                  @click="executePreview"
                  :loading="previewing"
                />
              </div>
            </div>
          </template>
        </Card>

        <Card v-if="previewResult">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-check-circle text-success"></i>
              <span>处理结果</span>
            </div>
          </template>
          <template #content>
            <div class="mb-4">
              <label class="block mb-2 font-medium">应用的规则</label>
              <div class="flex flex-wrap gap-2">
                <Tag v-for="rule in previewResult.applied_rules" :key="rule" :value="rule" severity="success" />
                <span v-if="previewResult.applied_rules.length === 0" class="text-color-secondary">无规则匹配</span>
              </div>
            </div>
            <div>
              <label class="block mb-2 font-medium">处理后Body</label>
              <Textarea
                :value="previewResult.processed_body"
                rows="8"
                readonly
                class="uniform-textarea w-full"
                :autoResize="false"
              />
            </div>
          </template>
        </Card>
      </div>

      <template #footer>
        <Button
          label="关闭"
          icon="pi pi-times"
          severity="secondary"
          @click="previewDialogVisible = false"
        />
      </template>
    </Dialog>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import type { SessionBodyField, SessionBodyFieldCreate, SessionBodyFieldUpdate, BodyPreviewResponse } from '@/types/bodyField'
import { MatchStrategy, matchStrategyOptions, bodyReplaceStrategyOptions, contentTypeOptions } from '@/types/bodyField'
import {
  getSessionBodyFields,
  setSessionBodyFields,
  updateSessionBodyField,
  deleteSessionBodyField,
  clearSessionBodyFields,
  previewBodyProcessing,
  createDefaultSessionBodyField,
  validateSessionBodyField,
  getMatchStrategyLabel as apiGetMatchStrategyLabel,
  formatExpiresAt as apiFormatExpiresAt
} from '@/api/bodyField'
import ScopeConfigPanel from './ScopeConfigPanel.vue'

// PrimeVue 组件显式导入
import Select from 'primevue/select'
import MultiSelect from 'primevue/multiselect'
import InputNumber from 'primevue/inputnumber'
import Textarea from 'primevue/textarea'
import Checkbox from 'primevue/checkbox'

// 组件状态
const toast = useToast()
const confirm = useConfirm()

const loading = ref(false)
const saving = ref(false)
const previewing = ref(false)
const bodyFields = ref<SessionBodyField[]>([])
const selectedFields = ref<SessionBodyField[]>([])
const pageSize = ref(10)

// 搜索和过滤
const searchQuery = ref('')
const statusFilter = ref<boolean | null>(null)
const matchStrategyFilter = ref<MatchStrategy | null>(null)

const statusOptions = [
  { label: '启用', value: true },
  { label: '禁用', value: false }
]

const matchStrategyFilterOptions = [
  { label: '关键字', value: MatchStrategy.KEYWORD },
  { label: '正则', value: MatchStrategy.REGEX },
  { label: 'JSONPath', value: MatchStrategy.JSONPATH },
  { label: 'XPath', value: MatchStrategy.XPATH }
]

const replaceStrategyOptions = bodyReplaceStrategyOptions

// 对话框状态
const dialogVisible = ref(false)
const isEditing = ref(false)
const editingFieldName = ref('')
const formData = ref<SessionBodyFieldCreate>(createDefaultSessionBodyField())

// 预览对话框
const previewDialogVisible = ref(false)
const previewForm = ref({
  body: '',
  content_type: 'application/json',
  target_url: ''
})
const previewResult = ref<BodyPreviewResponse | null>(null)

// 计算属性
const filteredFields = computed(() => {
  let result = [...bodyFields.value]
  
  // 搜索过滤
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    result = result.filter(f => 
      f.field_name.toLowerCase().includes(query) ||
      f.field_value.toLowerCase().includes(query)
    )
  }
  
  // 状态过滤
  if (statusFilter.value !== null) {
    result = result.filter(f => f.is_active === statusFilter.value)
  }
  
  // 匹配策略过滤
  if (matchStrategyFilter.value) {
    result = result.filter(f => f.match_strategy === matchStrategyFilter.value)
  }
  
  return result
})

const showMatchPattern = computed(() => {
  return formData.value.match_strategy && formData.value.match_strategy !== MatchStrategy.KEYWORD
})

// 生命周期
onMounted(() => {
  loadSessionBodyFields()
})

// 方法
async function loadSessionBodyFields() {
  loading.value = true
  try {
    const response = await getSessionBodyFields(false)
    if (response.success && response.data) {
      bodyFields.value = response.data.fields || []
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '加载失败',
      detail: error.message || '加载Body字段列表失败',
      life: 3000
    })
  } finally {
    loading.value = false
  }
}

function showAddDialog() {
  isEditing.value = false
  editingFieldName.value = ''
  formData.value = createDefaultSessionBodyField()
  dialogVisible.value = true
}

function showEditDialog(field: SessionBodyField) {
  isEditing.value = true
  editingFieldName.value = field.field_name
  formData.value = {
    field_name: field.field_name,
    field_value: field.field_value,
    match_strategy: field.match_strategy,
    match_pattern: field.match_pattern || '',
    replace_strategy: field.replace_strategy,
    content_types: field.content_types || [],
    priority: field.priority || 50,
    is_active: field.is_active !== false,
    ttl: 3600, // 编辑时重置TTL
    scope: field.scope || null
  }
  dialogVisible.value = true
}

async function saveField() {
  // 验证
  const error = validateSessionBodyField(formData.value)
  if (error) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: error,
      life: 3000
    })
    return
  }

  saving.value = true
  try {
    if (isEditing.value) {
      const updateData: SessionBodyFieldUpdate = {
        field_value: formData.value.field_value,
        match_strategy: formData.value.match_strategy,
        match_pattern: formData.value.match_pattern,
        replace_strategy: formData.value.replace_strategy,
        content_types: formData.value.content_types,
        priority: formData.value.priority,
        is_active: formData.value.is_active,
        ttl: formData.value.ttl,
        scope: formData.value.scope
      }
      await updateSessionBodyField(editingFieldName.value, updateData)
      toast.add({
        severity: 'success',
        summary: '更新成功',
        detail: '字段规则已更新',
        life: 3000
      })
    } else {
      await setSessionBodyFields({ fields: [formData.value] })
      toast.add({
        severity: 'success',
        summary: '添加成功',
        detail: '字段规则已添加',
        life: 3000
      })
    }
    dialogVisible.value = false
    await loadSessionBodyFields()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: isEditing.value ? '更新失败' : '添加失败',
      detail: error.message || '操作失败',
      life: 3000
    })
  } finally {
    saving.value = false
  }
}

function confirmDelete(field: SessionBodyField) {
  confirm.require({
    message: `确定要删除字段 "${field.field_name}" 吗？`,
    header: '删除确认',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await deleteSessionBodyField(field.field_name)
        toast.add({
          severity: 'success',
          summary: '删除成功',
          detail: '字段规则已删除',
          life: 3000
        })
        await loadSessionBodyFields()
      } catch (error: any) {
        toast.add({
          severity: 'error',
          summary: '删除失败',
          detail: error.message || '删除失败',
          life: 3000
        })
      }
    }
  })
}

function confirmClearAll() {
  confirm.require({
    message: '确定要清除所有Body字段规则吗？此操作不可恢复。',
    header: '清除确认',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await clearSessionBodyFields()
        toast.add({
          severity: 'success',
          summary: '清除成功',
          detail: '所有字段规则已清除',
          life: 3000
        })
        await loadSessionBodyFields()
      } catch (error: any) {
        toast.add({
          severity: 'error',
          summary: '清除失败',
          detail: error.message || '清除失败',
          life: 3000
        })
      }
    }
  })
}

function confirmBatchDelete() {
  confirm.require({
    message: `确定要删除选中的 ${selectedFields.value.length} 个字段规则吗？`,
    header: '批量删除确认',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        for (const field of selectedFields.value) {
          await deleteSessionBodyField(field.field_name)
        }
        toast.add({
          severity: 'success',
          summary: '删除成功',
          detail: `已删除 ${selectedFields.value.length} 个字段规则`,
          life: 3000
        })
        selectedFields.value = []
        await loadSessionBodyFields()
      } catch (error: any) {
        toast.add({
          severity: 'error',
          summary: '删除失败',
          detail: error.message || '批量删除失败',
          life: 3000
        })
      }
    }
  })
}

async function toggleActive(field: SessionBodyField) {
  try {
    await updateSessionBodyField(field.field_name, {
      is_active: !field.is_active
    })
    toast.add({
      severity: 'success',
      summary: '状态已更新',
      detail: `字段 "${field.field_name}" 已${field.is_active ? '禁用' : '启用'}`,
      life: 3000
    })
    await loadSessionBodyFields()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '更新失败',
      detail: error.message || '更新状态失败',
      life: 3000
    })
  }
}

async function executePreview() {
  if (!previewForm.value.body) {
    toast.add({
      severity: 'warn',
      summary: '请输入Body',
      detail: '请先输入要预览处理的Body内容',
      life: 3000
    })
    return
  }

  previewing.value = true
  try {
    const response = await previewBodyProcessing(previewForm.value)
    if (response.success && response.data) {
      previewResult.value = response.data
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '预览失败',
      detail: error.message || '预览处理失败',
      life: 3000
    })
  } finally {
    previewing.value = false
  }
}

function clearFilters() {
  searchQuery.value = ''
  statusFilter.value = null
  matchStrategyFilter.value = null
}

function clearSelection() {
  selectedFields.value = []
}

// 工具函数
function truncate(text: string, maxLength: number = 30): string {
  if (!text) return ''
  return text.length > maxLength ? text.substring(0, maxLength) + '...' : text
}

function formatExpiresAt(expiresAt: string | undefined): string {
  return apiFormatExpiresAt(expiresAt)
}

function isExpired(expiresAt: string | undefined): boolean {
  if (!expiresAt) return false
  return new Date(expiresAt) < new Date()
}

function getMatchStrategyLabel(strategy: MatchStrategy): string {
  return apiGetMatchStrategyLabel(strategy)
}

function getMatchStrategySeverity(strategy: MatchStrategy): string {
  const severities: Record<MatchStrategy, string> = {
    [MatchStrategy.KEYWORD]: 'success',
    [MatchStrategy.REGEX]: 'warning',
    [MatchStrategy.JSONPATH]: 'info',
    [MatchStrategy.XPATH]: 'secondary'
  }
  return severities[strategy] || 'info'
}

function getMatchStrategyDescription(strategy: MatchStrategy | undefined): string {
  const descriptions: Record<MatchStrategy, string> = {
    [MatchStrategy.KEYWORD]: '简单字段名匹配，适用于JSON键名、表单字段名等',
    [MatchStrategy.REGEX]: '使用正则表达式进行复杂模式匹配',
    [MatchStrategy.JSONPATH]: '使用JSONPath表达式定位JSON中的字段，如 $.auth.token',
    [MatchStrategy.XPATH]: '使用XPath表达式定位XML中的节点'
  }
  return strategy ? descriptions[strategy] : ''
}

function getMatchPatternPlaceholder(strategy: MatchStrategy | undefined): string {
  const placeholders: Record<MatchStrategy, string> = {
    [MatchStrategy.KEYWORD]: '',
    [MatchStrategy.REGEX]: '"token"\\s*:\\s*"([^"]+)"',
    [MatchStrategy.JSONPATH]: '$.auth.token',
    [MatchStrategy.XPATH]: '//auth/token/text()'
  }
  return strategy ? placeholders[strategy] : ''
}

function getMatchPatternDescription(strategy: MatchStrategy | undefined): string {
  const descriptions: Record<MatchStrategy, string> = {
    [MatchStrategy.KEYWORD]: '',
    [MatchStrategy.REGEX]: '输入正则表达式，用于匹配和提取字段值',
    [MatchStrategy.JSONPATH]: '输入JSONPath路径，如 $.data.user.token',
    [MatchStrategy.XPATH]: '输入XPath表达式，如 //session/id/text()'
  }
  return strategy ? descriptions[strategy] : ''
}

function getContentTypeShortLabel(contentType: string): string {
  const labels: Record<string, string> = {
    'application/json': 'JSON',
    'application/xml': 'XML',
    'text/xml': 'TextXML',
    'application/x-www-form-urlencoded': 'Form'
  }
  return labels[contentType] || contentType
}

function getPrioritySeverity(priority: number | undefined): string {
  if (priority === undefined) return 'info'
  if (priority >= 80) return 'danger'
  if (priority >= 50) return 'warning'
  return 'info'
}
</script>

<style scoped lang="scss">
.session-body-fields-config {
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

      // 统一工具栏元素高度
      $toolbar-height: 38px;

      .search-area {
        flex: 0 0 280px;
        max-width: 280px;

        :deep(.p-iconfield) {
          display: flex;
          align-items: center;
          position: relative;
          width: 100%;
          height: $toolbar-height;

          .p-inputicon {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            left: 0.75rem;
            color: var(--p-text-muted-color, #64748b);
            z-index: 1;
            font-size: 14px;
          }

          .p-inputtext {
            width: 100%;
            height: $toolbar-height !important;
            border-radius: 6px !important;
            border: 1px solid var(--p-surface-300, #cbd5e1) !important;
            padding-left: 2.5rem !important;
            padding-right: 0.75rem !important;
            font-size: 14px !important;
            background: #ffffff !important;
            transition: all 0.2s ease;
            box-sizing: border-box;

            &:focus {
              border-color: var(--p-primary-color, #6366f1) !important;
              box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1) !important;
            }

            &::placeholder {
              color: var(--p-text-muted-color, #94a3b8);
            }
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
          height: $toolbar-height;

          .filter-label {
            font-weight: 500;
            color: var(--p-text-muted-color, #64748b);
            white-space: nowrap;
            font-size: 14px;
            line-height: $toolbar-height;
          }

                    // filter-select 类直接应用在 p-select 元素上
          :deep(.p-select.filter-select) {
            height: $toolbar-height !important;
            min-height: $toolbar-height !important;
            min-width: 140px !important;
            width: 140px !important;
            border-radius: 6px !important;
            border: 1px solid var(--p-surface-300, #cbd5e1) !important;
            background: #ffffff !important;

            &:hover:not(.p-disabled) {
              border-color: var(--p-primary-color, #6366f1) !important;
            }

            &.p-focus {
              border-color: var(--p-primary-color, #6366f1) !important;
              box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1) !important;
            }

            .p-select-label {
              padding: 0 0.75rem !important;
              font-size: 14px !important;
              display: flex !important;
              align-items: center !important;
              height: 100% !important;
              line-height: 1.2 !important;
              color: var(--p-text-color, #1e293b) !important;
            }

            .p-select-dropdown {
              width: 2rem;
              display: flex;
              align-items: center;
              justify-content: center;
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

        .toolbar-btn {
          height: $toolbar-height !important;
          min-height: $toolbar-height !important;
          font-size: 14px !important;
          padding: 0 1rem !important;
          border-radius: 6px !important;

          &.p-button-icon-only {
            width: $toolbar-height !important;
            padding: 0 !important;
          }
        }
      }
    }
  }

  .batch-actions-toolbar {
    :deep(.p-card) {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.05) 100%);
      border: 1px solid rgba(99, 102, 241, 0.2);
    }
  }

  .session-table {
    :deep(.p-datatable-wrapper) {
      border-radius: 8px;
      border: 1px solid var(--surface-border);
    }

    .field-value {
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 0.875rem;
      color: var(--text-color-secondary);
    }

    .content-type-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
    }

    .expires-time {
      font-size: 0.875rem;
    }

    // 空数据提示
    .empty-table-message {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 4rem 2rem;
      color: var(--text-color-secondary);

      i {
        font-size: 4rem;
        margin-bottom: 1rem;
        color: var(--surface-400);
      }

      p {
        font-size: 1.25rem;
        font-weight: 500;
        margin: 0 0 0.5rem 0;
        color: var(--text-color);
      }

      small {
        font-size: 0.875rem;
        color: var(--text-color-secondary);
      }
    }

    // 加载中提示
    .loading-table-message {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 4rem 2rem;
      color: var(--text-color-secondary);

      i {
        font-size: 3rem;
        margin-bottom: 1rem;
        color: var(--primary-color);
      }

      p {
        font-size: 1rem;
        margin: 0;
      }
    }

    // 选择列checkbox居中
    :deep(.p-datatable-thead > tr > th:first-child),
    :deep(.p-datatable-tbody > tr > td:first-child) {
      text-align: center !important;
      vertical-align: middle !important;
      
      .p-checkbox {
        margin: 0 auto;
        display: flex !important;
        align-items: center;
        justify-content: center;
      }
    }
  }
}

// 过滤器Select样式 - 全局
.filter-select {
  :deep(.p-select) {
    height: 38px;
    min-width: 120px;
    border-radius: 6px;
    border: 1px solid var(--surface-border);
    background: var(--surface-0);

    &:hover:not(.p-disabled) {
      border-color: var(--primary-color);
    }

    &.p-focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1);
    }

    .p-select-label {
      padding: 0.5rem 0.75rem;
      font-size: 14px;
      display: flex;
      align-items: center;
      line-height: 1.2;
    }

    .p-select-dropdown {
      width: 2rem;
    }
  }
}

// Session对话框样式优化
:deep(.session-dialog) {
  max-width: calc(100vw - 4rem);
  max-height: calc(100vh - 4rem);

  .p-dialog-header {
    padding: 1.5rem;
    border-bottom: 1px solid var(--surface-border);
  }

  .p-dialog-content {
    padding: 0;
    overflow: hidden;
  }

  .p-dialog-footer {
    padding: 1.5rem 2rem 2rem 2rem !important;
    border-top: 1px solid var(--surface-border);
    background: var(--surface-50);
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
  }
}

// 统一输入框样式
.uniform-input {
  width: 100% !important;
  height: 42px !important;
  border: 1px solid var(--surface-border) !important;
  border-radius: 8px !important;
  padding: 0 0.75rem !important;
  font-size: 14px !important;
  transition: all 0.2s ease !important;
  background: var(--surface-0) !important;
  color: var(--text-color) !important;

  &:hover:not(.p-disabled) {
    border-color: var(--primary-color) !important;
  }

  &:focus {
    border-color: var(--primary-color) !important;
    box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1) !important;
    outline: none !important;
  }
}

// 统一文本域样式
.uniform-textarea {
  width: 100% !important;
  min-height: 100px !important;
  border: 1px solid var(--surface-border) !important;
  border-radius: 8px !important;
  padding: 0.75rem !important;
  font-size: 14px !important;
  transition: all 0.2s ease !important;
  background: var(--surface-0) !important;
  color: var(--text-color) !important;
  font-family: 'Consolas', 'Monaco', monospace !important;
  resize: vertical !important;

  &:hover:not(.p-disabled) {
    border-color: var(--primary-color) !important;
  }

  &:focus {
    border-color: var(--primary-color) !important;
    box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1) !important;
    outline: none !important;
  }
}

.dialog-content {
  padding: 2rem;
  max-height: calc(85vh - 200px);
  overflow-y: auto;
  overflow-x: hidden;

  // 防止内容溢出的通用设置
  * {
    box-sizing: border-box;
  }

  // 自定义滚动条样式
  &::-webkit-scrollbar {
    width: 8px;
  }

  &::-webkit-scrollbar-track {
    background: var(--surface-100);
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: var(--surface-300);
    border-radius: 4px;

    &:hover {
      background: var(--surface-400);
    }
  }

  // 卡片通用样式
  :deep(.p-card) {
    border-radius: 12px;
    border: 1px solid var(--surface-border);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
    background: var(--surface-0);
    margin-bottom: 1.5rem;

    &:last-child {
      margin-bottom: 0;
    }

    .p-card-title {
      font-size: 1rem;
      font-weight: 600;
      color: var(--text-color);
      margin: 0;

      i {
        color: var(--primary-color);
      }
    }

    .p-card-body {
      padding: 1.25rem;
    }

    .p-card-content {
      padding: 0;
    }
  }

  // 表单样式
  .formgrid {
    margin: 0;

    .field {
      margin-bottom: 1.5rem;

      &:last-child {
        margin-bottom: 0;
      }

      label {
        font-weight: 500;
        color: var(--text-color);
        font-size: 0.9rem;
      }

      small {
        color: var(--text-color-secondary);
        font-size: 0.8rem;
        display: block;
        margin-top: 0.5rem;
      }
    }
  }

  // 下拉选择框样式 - 对话框内
  :deep(.p-select) {
    width: 100%;
    height: 42px;
    border: 1px solid var(--surface-border);
    border-radius: 8px;
    background: var(--surface-0);

    &:hover:not(.p-disabled) {
      border-color: var(--primary-color);
    }

    &.p-focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1);
    }

    .p-select-label {
      padding: 0.5rem 0.75rem;
      font-size: 14px;
      display: flex;
      align-items: center;
      color: var(--text-color);
    }

    .p-select-dropdown {
      width: 2.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    // 确保选中的值显示
    .p-select-label:not(.p-placeholder) {
      color: var(--text-color);
    }
  }

  // 多选框样式 - 对话框内
  :deep(.p-multiselect) {
    width: 100%;
    min-height: 42px;
    border: 1px solid var(--surface-border);
    border-radius: 8px;
    background: var(--surface-0);

    &:hover:not(.p-disabled) {
      border-color: var(--primary-color);
    }

    &.p-focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1);
    }

    .p-multiselect-label-container {
      padding: 0.25rem 0.75rem;
    }

    .p-multiselect-label {
      padding: 0.25rem 0;
      font-size: 14px;
    }

    .p-multiselect-token {
      margin: 2px;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 12px;
      background: var(--primary-100);
      color: var(--primary-700);
    }

    .p-multiselect-trigger {
      width: 2.5rem;
    }
  }

  // 数字输入框样式 - 对话框内
  :deep(.p-inputnumber) {
    width: 100%;

    .p-inputnumber-input {
      height: 42px;
      border-radius: 8px;
      font-size: 14px;
      border: 1px solid var(--surface-border);

      &:hover:not(.p-disabled) {
        border-color: var(--primary-color);
      }

      &:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1);
      }
    }

    &.p-inputnumber-buttons-horizontal {
      .p-inputnumber-input {
        border-radius: 0;
        border-left: none;
        border-right: none;
      }

      .p-inputnumber-button-down {
        border-radius: 8px 0 0 8px;
        border: 1px solid var(--surface-border);
      }

      .p-inputnumber-button-up {
        border-radius: 0 8px 8px 0;
        border: 1px solid var(--surface-border);
      }
    }
  }

  // 复选框样式 - 对话框内
  :deep(.p-checkbox) {
    .p-checkbox-box {
      width: 20px;
      height: 20px;
      border-radius: 4px;
      border: 2px solid var(--surface-border);
      transition: all 0.2s ease;

      &.p-highlight {
        background: var(--primary-color);
        border-color: var(--primary-color);
      }
    }
  }

  // Textarea样式 - 对话框内
  :deep(.p-textarea) {
    width: 100%;
    min-height: 100px;
    border: 1px solid var(--surface-border);
    border-radius: 8px;
    padding: 0.75rem;
    font-size: 14px;
    font-family: 'Consolas', 'Monaco', monospace;
    resize: vertical;
    background: var(--surface-0);

    &:hover:not(.p-disabled) {
      border-color: var(--primary-color);
    }

    &:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1);
      outline: none;
    }
  }

  // InputText样式 - 对话框内
  :deep(.p-inputtext) {
    width: 100%;
    height: 42px;
    border: 1px solid var(--surface-border);
    border-radius: 8px;
    padding: 0 0.75rem;
    font-size: 14px;
    background: var(--surface-0);

    &:hover:not(.p-disabled) {
      border-color: var(--primary-color);
    }

    &:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.1);
      outline: none;
    }

    &:disabled {
      background: var(--surface-100);
      cursor: not-allowed;
    }
  }
}

@media (max-width: 768px) {
  .session-body-fields-config {
    .search-filter-card {
      .search-filter-toolbar {
        flex-direction: column;
        align-items: stretch;

        .search-area {
          flex: 1;
          max-width: none;
        }

        .filter-area {
          flex-direction: column;
          width: 100%;

          .filter-group {
            width: 100%;

            .filter-dropdown {
              flex: 1;
            }
          }
        }

        .action-area {
          margin-left: 0;
          justify-content: flex-start;
          width: 100%;
        }
      }
    }
  }
}
</style>

<!-- 全局样式 - 用于Select下拉面板（teleport到body） -->
<style lang="scss">
// PrimeVue 4使用 --p- 前缀的CSS变量
// Select下拉面板样式 - 修复透明背景问题
.p-select-overlay {
  background-color: #ffffff !important;
  background: #ffffff !important;
  border: 1px solid var(--p-surface-200, #e2e8f0) !important;
  border-radius: 8px !important;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15) !important;
  z-index: 9999 !important;
  min-width: 120px !important;
  backdrop-filter: none !important;
  -webkit-backdrop-filter: none !important;

  .p-select-list-container {
    max-height: 300px;
    overflow-y: auto;
    background: #ffffff !important;
  }

  .p-select-list {
    padding: 0.5rem 0;
    background: #ffffff !important;
  }

  .p-select-option {
    padding: 0.75rem 1rem !important;
    font-size: 14px !important;
    color: var(--p-text-color, #1e293b) !important;
    background: #ffffff !important;
    transition: all 0.15s ease !important;
    cursor: pointer !important;

    &:hover {
      background: var(--p-primary-50, #eef2ff) !important;
      color: var(--p-primary-color, #6366f1) !important;
    }

    &.p-selected,
    &.p-highlight {
      background: var(--p-primary-100, #e0e7ff) !important;
      color: var(--p-primary-700, #4338ca) !important;
      font-weight: 500 !important;
    }

    .p-select-option-check-icon {
      color: var(--p-primary-color, #6366f1) !important;
      margin-right: 0.5rem;
    }
  }
}

// MultiSelect下拉面板样式 - 修复透明背景问题
.p-multiselect-overlay {
  background-color: #ffffff !important;
  background: #ffffff !important;
  border: 1px solid var(--p-surface-200, #e2e8f0) !important;
  border-radius: 8px !important;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15) !important;
  z-index: 9999 !important;
  backdrop-filter: none !important;
  -webkit-backdrop-filter: none !important;

  .p-multiselect-header {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--p-surface-200, #e2e8f0);
    background: #ffffff !important;
  }

  .p-multiselect-list-container {
    background: #ffffff !important;
  }

  .p-multiselect-list {
    padding: 0.5rem 0;
    background: #ffffff !important;
  }

  .p-multiselect-option {
    padding: 0.75rem 1rem !important;
    font-size: 14px !important;
    color: var(--p-text-color, #1e293b) !important;
    background: #ffffff !important;
    transition: all 0.15s ease !important;

    &:hover {
      background: var(--p-primary-50, #eef2ff) !important;
    }

    &.p-selected,
    &.p-highlight {
      background: var(--p-primary-100, #e0e7ff) !important;
      color: var(--p-primary-700, #4338ca) !important;
    }
  }
}
</style>
