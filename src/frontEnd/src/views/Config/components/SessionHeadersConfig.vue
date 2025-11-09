<template>
  <div class="session-headers-config">
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
                placeholder="搜索Header名称或值..."
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
                class="filter-dropdown"
                :showClear="true"
              />
            </div>

            <div class="filter-group">
              <label class="filter-label">优先级:</label>
              <Select
                v-model="priorityFilter"
                :options="priorityOptions"
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
              @click="showAddDialog"
              severity="success"
            />
            <Button
              label="批量添加"
              icon="pi pi-list"
              @click="showBatchAddDialog"
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
              @click="loadSessionHeaders"
              :loading="loading"
              severity="secondary"
              outlined
            />
            <Button
              label="清除所有"
              icon="pi pi-trash"
              @click="confirmClearAll"
              severity="danger"
              outlined
            />
          </div>
        </div>
      </template>
    </Card>

    <!-- 信息提示 -->
    <Message severity="info" :closable="false" class="mb-3">
      <i class="pi pi-info-circle mr-2"></i>
      会话Header仅在当前浏览器会话中有效，关闭浏览器后将自动清除
    </Message>

    <!-- Session Headers列表 -->
    <DataTable
      :value="filteredSessionHeaders"
      :loading="loading"
      v-model:selection="selectedSessionHeaders"
      stripedRows
      paginator
      :rows="pageSize"
      :rowsPerPageOptions="[5, 10, 20, 50]"
      sortField="created_at"
      :sortOrder="-1"
      class="session-table"
      :globalFilterFields="['header_name', 'header_value', 'id']"
      responsiveLayout="stack"
      breakpoint="768px"
      :resizableColumns="true"
      columnResizeMode="fit"
    >
      <Column selectionMode="multiple" style="width: 50px"></Column>
      <Column field="id" header="ID" sortable style="width: 80px"></Column>
      <Column field="header_name" header="Header名称" sortable></Column>
      <Column field="header_value" header="Header值">
        <template #body="{ data }">
          <span class="header-value">{{ truncate(data.header_value, 40) }}</span>
        </template>
      </Column>
      <Column field="replace_strategy" header="替换策略" sortable style="width: 120px"></Column>
      <Column field="priority" header="优先级" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.priority" severity="info"></Tag>
        </template>
      </Column>
      <Column field="scope" header="作用域" style="width: 120px">
        <template #body="{ data }">
          <Tag :value="data.scope ? '有作用域' : '全局'" :severity="data.scope ? 'info' : 'secondary'"></Tag>
        </template>
      </Column>
      <Column field="is_active" header="状态" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.is_active ? '启用' : '禁用'" :severity="data.is_active ? 'success' : 'danger'"></Tag>
        </template>
      </Column>
      <Column field="created_at" header="创建时间" sortable style="width: 200px">
        <template #body="{ data }">
          <span class="create-time">{{ formatTime(data.created_at) }}</span>
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

    <!-- 批量添加对话框 -->
    <Dialog
      v-model:visible="dialogVisible"
      header="添加Session Headers"
      :style="{ width: '1200px', maxHeight: '90vh' }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-book text-primary"></i>
              <span>批量添加格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>每行一个Header，格式：</span>
                <code class="format-code">Header-Name: Header-Value</code>
              </div>
            </Message>
          </template>
        </Card>

        <!-- Header输入区域卡片 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-list text-primary"></i>
              <span>Header列表</span>
            </div>
          </template>
          <template #content>
            <div class="input-area">
              <Textarea
                v-model="rawHeaders"
                rows="12"
                placeholder="例如:
Authorization: Bearer your-token-here
X-Custom-Header: custom-value
Cookie: session_id=abc123
X-API-Key: your-api-key
User-Agent: CustomUserAgent/1.0"
                class="headers-textarea"
                :autoResize="false"
              />
              <div class="input-stats">
                <small class="text-color-secondary">
                  <i class="pi pi-info-circle mr-1"></i>
                  输入行数: {{ rawHeaders.split('\n').filter(line => line.trim()).length }}
                </small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项卡片 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-4">
                <label for="priority" class="block mb-2 font-medium">
                  <i class="pi pi-sort-amount-up mr-2"></i>
                  优先级 (0-100)
                </label>
                <InputNumber
                  id="priority"
                  v-model="defaultPriority"
                  :min="0"
                  :max="100"
                  showButtons
                  buttonLayout="horizontal"
                  :step="1"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">数值越大优先级越高</small>
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="ttl" class="block mb-2 font-medium">
                  <i class="pi pi-clock mr-2"></i>
                  生存时间 (秒)
                </label>
                <InputNumber
                  id="ttl"
                  v-model="defaultTtl"
                  :min="60"
                  :max="86400"
                  showButtons
                  buttonLayout="horizontal"
                  :step="60"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">默认3600秒(1小时)，最大86400秒(24小时)</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 域控配置 -->
        <ScopeConfigPanel
          v-model="sessionScope"
          title="作用域配置（可选）"
          description="为批量添加的Header统一设置作用域，不配置则对所有请求生效"
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
          label="添加" 
          icon="pi pi-check"
          @click="addSessionHeaders" 
          :loading="saving" 
        />
      </template>
    </Dialog>

    <!-- 批量添加对话框 -->
    <Dialog
      v-model:visible="batchDialogVisible"
      header="批量添加Session Headers"
      :style="{ width: '900px', maxHeight: '90vh' }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-book text-primary"></i>
              <span>批量添加格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>每行一个Header，格式：</span>
                <code class="format-code">Header-Name: Header-Value</code>
              </div>
            </Message>
          </template>
        </Card>

        <!-- Header输入区域卡片 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-list text-primary"></i>
              <span>Header列表</span>
            </div>
          </template>
          <template #content>
            <div class="input-area">
              <Textarea
                v-model="batchRawHeaders"
                rows="12"
                placeholder="例如:
Authorization: Bearer your-token-here
X-Custom-Header: custom-value
Cookie: session_id=abc123
X-API-Key: your-api-key
User-Agent: CustomUserAgent/1.0"
                class="headers-textarea"
                :autoResize="false"
              />
              <div class="input-stats">
                <small class="text-color-secondary">
                  <i class="pi pi-info-circle mr-1"></i>
                  输入行数: {{ batchRawHeaders.split('\n').filter(line => line.trim()).length }}
                </small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项卡片 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-3">
                <FloatLabel>
                  <InputNumber
                    id="batch_priority"
                    v-model="defaultPriority"
                    :min="0"
                    :max="100"
                  />
                  <label for="batch_priority">
                    <i class="pi pi-sort-numeric-down mr-2"></i>
                    默认优先级
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">0-100，越大优先级越高</small>
              </div>

              <div class="field col-12 md:col-6 mb-0">
                <FloatLabel>
                  <InputNumber
                    id="batch_ttl"
                    v-model="defaultTtl"
                    :min="60"
                    :max="86400"
                    suffix=" 秒"
                  />
                  <label for="batch_ttl">
                    <i class="pi pi-clock mr-2"></i>
                    默认过期时间
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">60-86400秒（1分钟-24小时）</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 域控配置 -->
        <ScopeConfigPanel
          v-model="sessionScope"
          title="作用域配置（可选）"
          description="为批量添加的Header统一设置作用域，不配置则对所有请求生效"
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
          @click="batchDialogVisible = false" 
        />
        <Button 
          label="添加" 
          icon="pi pi-check"
          @click="handleBatchAdd" 
          :loading="saving" 
        />
      </template>
    </Dialog>

    <!-- 文件导入对话框 -->
    <Dialog
      v-model:visible="fileImportDialogVisible"
      header="从文件导入Session Headers"
      :style="{ width: '900px', maxHeight: '90vh' }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-book text-primary"></i>
              <span>文件格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div>
                <div class="mb-2">
                  <i class="pi pi-info-circle mr-2"></i>
                  支持的文件格式：
                </div>
                <ul class="ml-4">
                  <li>文本文件 (.txt)：每行一个Header，格式为 <code class="format-code">Header-Name: Header-Value</code></li>
                  <li>JSON文件 (.json)：对象数组格式，每个对象包含header_name和header_value字段</li>
                </ul>
              </div>
            </Message>
          </template>
        </Card>

        <!-- 文件上传区域 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-upload text-primary"></i>
              <span>选择文件</span>
            </div>
          </template>
          <template #content>
            <div class="file-upload-area">
              <input
                type="file"
                ref="fileInput"
                accept=".txt,.json"
                @change="handleFileSelect"
                class="file-input"
              />
              <div class="file-preview" v-if="fileContent">
                <div class="file-preview-header">
                  <span class="font-semibold">文件内容预览：</span>
                </div>
                <Textarea
                  v-model="fileContent"
                  rows="10"
                  class="headers-textarea"
                  :autoResize="false"
                  readonly
                />
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项卡片 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-3">
                <FloatLabel>
                  <InputNumber
                    id="file_priority"
                    v-model="defaultPriority"
                    :min="0"
                    :max="100"
                  />
                  <label for="file_priority">
                    <i class="pi pi-sort-numeric-down mr-2"></i>
                    默认优先级
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">0-100，越大优先级越高</small>
              </div>

              <div class="field col-12 md:col-6 mb-0">
                <FloatLabel>
                  <InputNumber
                    id="file_ttl"
                    v-model="defaultTtl"
                    :min="60"
                    :max="86400"
                    suffix=" 秒"
                  />
                  <label for="file_ttl">
                    <i class="pi pi-clock mr-2"></i>
                    默认过期时间
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">60-86400秒（1分钟-24小时）</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 域控配置 -->
        <ScopeConfigPanel
          v-model="sessionScope"
          title="作用域配置（可选）"
          description="为导入的Header统一设置作用域，不配置则对所有请求生效"
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
          @click="fileImportDialogVisible = false" 
        />
        <Button 
          label="导入" 
          icon="pi pi-check"
          @click="handleFileImport" 
          :loading="saving"
          :disabled="!fileContent" 
        />
      </template>
    </Dialog>

    <!-- 编辑对话框 -->
    <Dialog
      v-model:visible="editDialogVisible"
      header="编辑Session Header"
      :style="{ width: '800px', maxHeight: '90vh' }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 基本信息 -->
        <Card class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-pencil text-primary"></i>
              <span>基本信息</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-4">
                <label for="edit_header_name" class="block mb-2 font-medium">
                  Header名称 <span class="text-red-500">*</span>
                </label>
                <InputText
                  id="edit_header_name"
                  v-model="editFormData.header_name"
                  class="w-full"
                  placeholder="例如: Authorization"
                />
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="edit_replace_strategy" class="block mb-2 font-medium">
                  替换策略
                </label>
                <Select
                  id="edit_replace_strategy"
                  v-model="editFormData.replace_strategy"
                  :options="replaceStrategyOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="选择替换策略"
                  class="w-full"
                />
              </div>

              <div class="field col-12 mb-4">
                <label for="edit_header_value" class="block mb-2 font-medium">
                  Header值 <span class="text-red-500">*</span>
                </label>
                <Textarea
                  id="edit_header_value"
                  v-model="editFormData.header_value"
                  rows="3"
                  placeholder="例如: Bearer your-token-here"
                  class="w-full"
                  :autoResize="false"
                />
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
                <label for="edit_priority" class="block mb-2 font-medium">
                  优先级 (0-100)
                </label>
                <InputNumber
                  id="edit_priority"
                  v-model="editFormData.priority"
                  :min="0"
                  :max="100"
                  showButtons
                  buttonLayout="horizontal"
                  :step="1"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">数值越大优先级越高</small>
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="edit_ttl" class="block mb-2 font-medium">
                  生存时间 (秒)
                </label>
                <InputNumber
                  id="edit_ttl"
                  v-model="editFormData.ttl"
                  :min="60"
                  :max="86400"
                  showButtons
                  buttonLayout="horizontal"
                  :step="60"
                  class="w-full"
                />
                <small class="text-color-secondary mt-1 block">默认3600秒(1小时)，最大86400秒(24小时)</small>
              </div>

              <div class="field col-12 mb-4">
                <div class="flex align-items-center gap-3">
                  <Checkbox
                    id="edit_is_active"
                    v-model="editFormData.is_active"
                    binary
                  />
                  <label for="edit_is_active" class="font-medium cursor-pointer">
                    启用此Header
                  </label>
                </div>
                <small class="text-color-secondary mt-1 block">禁用后此Header不会生效</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 作用域配置 -->
        <ScopeConfigPanel
          v-model="editFormData.scope"
          title="作用域配置（可选）"
          description="配置Header的生效范围，不配置则对所有请求生效"
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
          @click="editDialogVisible = false"
        />
        <Button
          label="保存"
          icon="pi pi-check"
          @click="updateHeader"
          :loading="saving"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import Select from 'primevue/select'
import ScopeConfigPanel from './ScopeConfigPanel.vue'
import {
  getSessionHeaders,
  setSessionHeaders,
  deleteSessionHeader,
  updateSessionHeader,
  clearSessionHeaders,
} from '@/api/headerRule'
import type { SessionHeader, HeaderScope } from '@/types/headerRule'
import { ReplaceStrategy } from '@/types/headerRule'

const toast = useToast()
const confirm = useConfirm()

const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const batchDialogVisible = ref(false)
const fileImportDialogVisible = ref(false)
const editDialogVisible = ref(false) // 编辑对话框可见性
const sessionHeaders = ref<any[]>([])
const selectedSessionHeaders = ref<any[]>([]) // 多选
const rawHeaders = ref('')
const batchRawHeaders = ref('')
const fileContent = ref('')
const defaultPriority = ref(50)
const defaultTtl = ref(3600) // 默认1小时

// 编辑相关状态
const editingHeader = ref<any>(null) // 当前编辑的Header
const editFormData = ref({
  header_name: '',
  header_value: '',
  replace_strategy: 'REPLACE' as any,
  priority: 50,
  is_active: true,
  ttl: 3600,
  scope: null as any
})

// 搜索和过滤相关
const searchQuery = ref('')
const statusFilter = ref<string | null>(null)
const priorityFilter = ref<string | null>(null)
const pageSize = ref(10)
const sessionScope = ref<HeaderScope | null>(null) // Session Header作用域配置

// 过滤选项
const statusOptions = [
  { label: '有效', value: 'valid' },
  { label: '已过期', value: 'expired' },
]

const priorityOptions = [
  { label: '高 (80-100)', value: 'high' },
  { label: '中 (50-79)', value: 'medium' },
  { label: '低 (0-49)', value: 'low' },
]

// 替换策略选项
const replaceStrategyOptions = [
  { label: '完全替换', value: ReplaceStrategy.REPLACE },
  { label: '追加', value: ReplaceStrategy.APPEND },
  { label: '前置', value: ReplaceStrategy.PREPEND },
  { label: '条件性替换', value: ReplaceStrategy.CONDITIONAL },
  { label: '存在则替换，不存在则新增', value: ReplaceStrategy.UPSERT },
]

onMounted(() => {
  loadSessionHeaders()
})

async function loadSessionHeaders() {
  loading.value = true
  try {
    const res = await getSessionHeaders()
    if (res.success) {
      sessionHeaders.value = res.data.headers || []
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '加载失败',
      detail: error.message || '加载Session Headers失败',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

function showAddDialog() {
  rawHeaders.value = ''
  defaultPriority.value = 50
  defaultTtl.value = 3600
  dialogVisible.value = true
}

function showBatchAddDialog() {
  batchRawHeaders.value = ''
  defaultPriority.value = 50
  defaultTtl.value = 3600
  sessionScope.value = null
  batchDialogVisible.value = true
}

function showFileImportDialog() {
  fileContent.value = ''
  defaultPriority.value = 50
  defaultTtl.value = 3600
  sessionScope.value = null
  fileImportDialogVisible.value = true
}

async function addSessionHeaders() {
  if (!rawHeaders.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请输入Header内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    // 解析Headers
    const lines = rawHeaders.value.split('\n').filter((line) => line.trim())
    const headers: SessionHeader[] = []

    for (const line of lines) {
      const [name, ...valueParts] = line.split(':')
      if (name && valueParts.length > 0) {
        headers.push({
          header_name: name.trim(),
          header_value: valueParts.join(':').trim(),
          priority: defaultPriority.value,
          ttl: defaultTtl.value,
          scope: sessionScope.value, // 添加作用域配置
        })
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未能解析出有效的Header',
        life: 3000,
      })
      return
    }

    await setSessionHeaders({ headers })
    toast.add({
      severity: 'success',
      summary: '添加成功',
      detail: `成功添加 ${headers.length} 个Session Header`,
      life: 3000,
    })

    dialogVisible.value = false
    await loadSessionHeaders()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '添加失败',
      detail: error.message || '添加Session Headers失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

async function handleBatchAdd() {
  if (!batchRawHeaders.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请输入Header内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    // 解析Headers
    const lines = batchRawHeaders.value.split('\n').filter((line) => line.trim())
    const headers: SessionHeader[] = []

    for (const line of lines) {
      const [name, ...valueParts] = line.split(':')
      if (name && valueParts.length > 0) {
        headers.push({
          header_name: name.trim(),
          header_value: valueParts.join(':').trim(),
          priority: defaultPriority.value,
          ttl: defaultTtl.value,
          scope: sessionScope.value,
        })
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未能解析出有效的Header',
        life: 3000,
      })
      return
    }

    await setSessionHeaders({ headers })
    toast.add({
      severity: 'success',
      summary: '批量添加成功',
      detail: `成功添加 ${headers.length} 个Session Header`,
      life: 3000,
    })

    batchDialogVisible.value = false
    await loadSessionHeaders()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '批量添加失败',
      detail: error.message || '批量添加Session Headers失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function handleFileSelect(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  if (!file) return

  const reader = new FileReader()
  reader.onload = (e) => {
    fileContent.value = e.target?.result as string
  }
  reader.readAsText(file)
}

async function handleFileImport() {
  if (!fileContent.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请选择文件',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    let headers: SessionHeader[] = []

    // 尝试解析为JSON
    try {
      const jsonData = JSON.parse(fileContent.value)
      if (Array.isArray(jsonData)) {
        headers = jsonData.map(item => ({
          header_name: item.header_name || item.name,
          header_value: item.header_value || item.value,
          priority: item.priority || defaultPriority.value,
          ttl: item.ttl || defaultTtl.value,
          scope: item.scope || sessionScope.value,
        }))
      }
    } catch {
      // JSON解析失败，尝试作为文本文件解析
      const lines = fileContent.value.split('\n').filter((line) => line.trim())
      for (const line of lines) {
        const [name, ...valueParts] = line.split(':')
        if (name && valueParts.length > 0) {
          headers.push({
            header_name: name.trim(),
            header_value: valueParts.join(':').trim(),
            priority: defaultPriority.value,
            ttl: defaultTtl.value,
            scope: sessionScope.value,
          })
        }
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未能从文件中解析出有效的Header',
        life: 3000,
      })
      return
    }

    await setSessionHeaders({ headers })
    toast.add({
      severity: 'success',
      summary: '导入成功',
      detail: `成功导入 ${headers.length} 个Session Header`,
      life: 3000,
    })

    fileImportDialogVisible.value = false
    fileContent.value = ''
    await loadSessionHeaders()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '导入失败',
      detail: error.message || '导入Session Headers失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function confirmClearAll() {
  if (sessionHeaders.value.length === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '当前没有Session Headers',
      life: 3000,
    })
    return
  }

  confirm.require({
    message: '确定要清除所有Session Headers吗？',
    header: '确认清除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '清除',
    rejectLabel: '取消',
    accept: async () => {
      try {
        await clearSessionHeaders()
        toast.add({
          severity: 'success',
          summary: '清除成功',
          detail: 'Session Headers已清除',
          life: 3000,
        })
        await loadSessionHeaders()
      } catch (error: any) {
        toast.add({
          severity: 'error',
          summary: '清除失败',
          detail: error.message || '清除Session Headers失败',
          life: 3000,
        })
      }
    },
  })
}

function formatTime(timeStr: string) {
  if (!timeStr) return '-'
  return new Date(timeStr).toLocaleString('zh-CN')
}

function truncate(text: string, length: number) {
  if (text.length <= length) return text
  return text.substring(0, length) + '...'
}

// 计算属性：过滤后的Session Headers
const filteredSessionHeaders = computed(() => {
  let filtered = sessionHeaders.value

  // 搜索过滤
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(header =>
      header.header_name.toLowerCase().includes(query) ||
      header.header_value.toLowerCase().includes(query)
    )
  }

  // 状态过滤（有效/过期）
  if (statusFilter.value) {
    const now = new Date()
    if (statusFilter.value === 'valid') {
      filtered = filtered.filter(header => new Date(header.expires_at) > now)
    } else if (statusFilter.value === 'expired') {
      filtered = filtered.filter(header => new Date(header.expires_at) <= now)
    }
  }

  // 优先级过滤
  if (priorityFilter.value) {
    if (priorityFilter.value === 'high') {
      filtered = filtered.filter(header => (header.priority || 50) >= 80)
    } else if (priorityFilter.value === 'medium') {
      filtered = filtered.filter(header => {
        const priority = header.priority || 50
        return priority >= 50 && priority < 80
      })
    } else if (priorityFilter.value === 'low') {
      filtered = filtered.filter(header => (header.priority || 50) < 50)
    }
  }

  return filtered
})

// 清除过滤器
function clearFilters() {
  searchQuery.value = ''
  statusFilter.value = null
  priorityFilter.value = null
}

// 编辑Session Header
function showEditDialog(header: any) {
  editingHeader.value = header
  editFormData.value = {
    header_name: header.header_name || '',
    header_value: header.header_value || '',
    replace_strategy: header.replace_strategy || ReplaceStrategy.REPLACE,
    priority: header.priority || 50,
    is_active: header.is_active !== undefined ? header.is_active : true,
    ttl: header.ttl || 3600,
    scope: header.scope || null
  }
  editDialogVisible.value = true
}

// 更新Session Header
async function updateHeader() {
  if (!editFormData.value.header_name.trim() || !editFormData.value.header_value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请填写Header名称和值',
      life: 3000,
    })
    return
  }

  if (!editingHeader.value?.id) {
    toast.add({
      severity: 'error',
      summary: '错误',
      detail: '无效的Header ID',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    const res = await updateSessionHeader(editingHeader.value.id, editFormData.value)
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '更新成功',
        detail: 'Session Header已更新',
        life: 3000,
      })
      editDialogVisible.value = false
      // 重新加载数据
      await loadSessionHeaders()
    } else {
      toast.add({
        severity: 'error',
        summary: '更新失败',
        detail: res.message || '更新失败',
        life: 3000,
      })
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '更新失败',
      detail: error.message || '更新失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

// 确认删除
function confirmDelete(header: any) {
  confirm.require({
    message: `确定要删除Header "${header.header_name}" 吗？`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    accept: () => deleteHeader(header.id),
  })
}

// 删除Session Header
async function deleteHeader(headerId: number) {
  try {
    // 调用删除API
    const res = await deleteSessionHeader(headerId)
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '删除成功',
        detail: 'Session Header已删除',
        life: 3000,
      })
      // 重新加载数据
      await loadSessionHeaders()
    } else {
      toast.add({
        severity: 'error',
        summary: '删除失败',
        detail: res.message || '删除失败',
        life: 3000,
      })
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '删除失败',
      detail: error.message || '删除失败',
      life: 3000,
    })
  }
}

// 切换启用状态
async function toggleActive(header: any) {
  try {
    const newStatus = !header.is_active
    // 更新本地状态
    const index = sessionHeaders.value.findIndex(h => h.id === header.id)
    if (index !== -1) {
      sessionHeaders.value[index].is_active = newStatus
    }
    // TODO: 调用实际的更新API
    toast.add({
      severity: 'success',
      summary: '状态已更新',
      detail: `已${newStatus ? '启用' : '禁用'} "${header.header_name}"`,
      life: 3000,
    })
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '更新状态失败',
      life: 3000,
    })
  }
}
</script>

<style scoped lang="scss">
.session-headers-config {
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

  .session-table {
    .header-value {
      font-family: monospace;
      font-size: 0.9em;
    }

    .expire-time,
    .create-time {
      font-size: 0.9em;
      color: var(--text-color-secondary);
    }
  }

  code {
    font-family: monospace;
  }
}

// Session对话框样式优化
:deep(.session-dialog) {
  .p-dialog-header {
    padding: 1.5rem;
    border-bottom: 1px solid var(--surface-border);
  }

  .p-dialog-content {
    padding: 0;
    overflow: hidden;
  }

  .p-dialog-footer {
    padding: 1.25rem 1.5rem;
    border-top: 1px solid var(--surface-border);
    background: var(--surface-50);
  }
}

.dialog-content {
  padding: 2rem;
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

  // 信息卡片样式
  .info-card {
    .format-code {
      background: var(--blue-50);
      color: var(--blue-700);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
      font-size: 0.875rem;
      font-weight: 500;
      border: 1px solid var(--blue-200);
    }

    ul {
      margin: 0.5rem 0 0 0;
      padding-left: 1.5rem;

      li {
        margin-bottom: 0.5rem;
        line-height: 1.6;
        color: var(--text-color-secondary);

        &:last-child {
          margin-bottom: 0;
        }
      }
    }
  }

  // 输入区域卡片样式
  .input-card {
    .input-area {
      .headers-textarea {
        width: 100%;
        padding: 0.875rem;
        font-size: 0.9rem;
        border: 1px solid var(--surface-border);
        border-radius: 6px;
        transition: all 0.2s ease;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        line-height: 1.6;
        resize: vertical;
        min-height: 240px;
        background: var(--surface-0);

        &:enabled:hover {
          border-color: var(--primary-color);
        }

        &:enabled:focus {
          border-color: var(--primary-color);
          box-shadow: 0 0 0 2px rgba(var(--primary-color-rgb), 0.1);
          outline: none;
        }

        &::placeholder {
          color: var(--text-color-secondary);
          opacity: 0.6;
        }
      }

      .input-stats {
        margin-top: 0.75rem;
        display: flex;
        justify-content: space-between;
        align-items: center;

        small {
          font-size: 0.875rem;
          color: var(--text-color-secondary);
        }
      }
    }

    .file-upload-area {
      .file-input {
        width: 100%;
        padding: 1rem;
        border: 2px dashed var(--surface-border);
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s ease;
        background: var(--surface-0);

        &:hover {
          border-color: var(--primary-color);
          background: var(--primary-50);
        }
      }

      .file-preview {
        margin-top: 1.25rem;

        .file-preview-header {
          margin-bottom: 0.75rem;
          padding: 0.75rem 1rem;
          background: var(--surface-50);
          border-radius: 6px;
          border-left: 3px solid var(--primary-color);

          .font-semibold {
            font-weight: 600;
            color: var(--text-color);
          }
        }
      }
    }
  }

  // 配置卡片样式
  .config-card {
    .field {
      margin-bottom: 1.5rem;

      &:last-child {
        margin-bottom: 0;
      }
    }

    // 浮动标签优化
    :deep(.p-float-label) {
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
      .p-inputwrapper-focus ~ label,
      .p-inputwrapper-filled ~ label {
        top: -0.75rem;
        font-size: 0.875rem;
        background: var(--surface-0);
        padding: 0 0.25rem;
      }
    }

    // 输入数字组件样式
    :deep(.p-inputnumber) {
      width: 100%;

      .p-inputnumber-input {
        width: 100%;
        padding: 0.75rem;
        font-size: 0.95rem;
        border: 1px solid var(--surface-border);
        border-radius: 6px;
        transition: all 0.2s ease;
        background: var(--surface-0);

        &:enabled:hover {
          border-color: var(--primary-color);
        }

        &:enabled:focus {
          border-color: var(--primary-color);
          box-shadow: 0 0 0 2px rgba(var(--primary-color-rgb), 0.1);
          outline: none;
        }
      }
    }

    small {
      display: block;
      margin-top: 0.5rem;
      font-size: 0.875rem;
      color: var(--text-color-secondary);
      line-height: 1.4;
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
}
</style>
