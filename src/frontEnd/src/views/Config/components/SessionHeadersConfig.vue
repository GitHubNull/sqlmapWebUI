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
      stripedRows
      paginator
      :rows="pageSize"
      :rowsPerPageOptions="[5, 10, 20, 50]"
      sortField="created_at"
      :sortOrder="-1"
      class="session-table"
      :globalFilterFields="['header_name', 'header_value']"
      responsiveLayout="stack"
      breakpoint="768px"
      :resizableColumns="true"
      columnResizeMode="fit"
    >
      <Column field="header_name" header="Header名称"></Column>
      <Column field="header_value" header="Header值">
        <template #body="{ data }">
          <span class="header-value">{{ truncate(data.header_value, 40) }}</span>
        </template>
      </Column>
      <Column field="priority" header="优先级" style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.priority" severity="info"></Tag>
        </template>
      </Column>
      <Column field="expires_at" header="过期时间" style="width: 200px">
        <template #body="{ data }">
          <span class="expire-time">{{ formatTime(data.expires_at) }}</span>
        </template>
      </Column>
      <Column field="created_at" header="创建时间" style="width: 200px">
        <template #body="{ data }">
          <span class="create-time">{{ formatTime(data.created_at) }}</span>
        </template>
      </Column>
    </DataTable>

    <!-- 批量添加对话框 -->
    <Dialog
      v-model:visible="dialogVisible"
      header="添加Session Headers"
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
              <div class="field col-12 md:col-6 mb-3">
                <FloatLabel>
                  <InputNumber
                    id="priority"
                    v-model="defaultPriority"
                    :min="0"
                    :max="100"
                    showButtons
                    buttonLayout="horizontal"
                    :step="1"
                  />
                  <label for="priority">
                    <i class="pi pi-sort-amount-up mr-2"></i>
                    优先级 (0-100)
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">数值越大优先级越高</small>
              </div>

              <div class="field col-12 md:col-6 mb-0">
                <FloatLabel>
                  <InputNumber
                    id="ttl"
                    v-model="defaultTtl"
                    :min="60"
                    :max="86400"
                    showButtons
                    buttonLayout="horizontal"
                    :step="60"
                  />
                  <label for="ttl">
                    <i class="pi pi-clock mr-2"></i>
                    生存时间 (秒)
                  </label>
                </FloatLabel>
                <small class="text-color-secondary mt-1">默认3600秒(1小时)，最大86400秒(24小时)</small>
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
  clearSessionHeaders,
} from '@/api/headerRule'
import type { SessionHeader, HeaderScope } from '@/types/headerRule'

const toast = useToast()
const confirm = useConfirm()

const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const batchDialogVisible = ref(false)
const fileImportDialogVisible = ref(false)
const sessionHeaders = ref<any[]>([])
const rawHeaders = ref('')
const batchRawHeaders = ref('')
const fileContent = ref('')
const defaultPriority = ref(50)
const defaultTtl = ref(3600) // 默认1小时

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
  .p-dialog-content {
    padding: 0;
    overflow-y: auto;
  }
}

.dialog-content {
  padding: 1.5rem;
  max-height: calc(85vh - 140px);
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

  // 信息卡片样式
  .info-card {
    :deep(.p-card-content) {
      padding-bottom: 1rem;
    }

    .format-code {
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

  // 输入区域卡片样式
  .input-card {
    .input-area {
      .headers-textarea {
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

    .file-upload-area {
      .file-input {
        width: 100%;
        padding: 1rem;
        border: 2px dashed var(--surface-border);
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s ease;

        &:hover {
          border-color: var(--primary-color);
          background: var(--surface-50);
        }
      }

      .file-preview {
        margin-top: 1rem;

        .file-preview-header {
          margin-bottom: 0.5rem;
          padding: 0.5rem;
          background: var(--surface-50);
          border-radius: 4px;
        }
      }
    }
  }

  // 配置卡片样式
  .config-card {
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

    // 输入数字组件样式
    :deep(.p-inputnumber) {
      .p-inputnumber-input {
        border-radius: 8px;
        border: 2px solid var(--surface-border);
        transition: all 0.2s ease;

        &:focus {
          border-color: var(--primary-color);
          box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
        }
      }

      .p-inputnumber-button {
        border-radius: 0;
        border: 2px solid var(--surface-border);
        border-left: none;
        background: var(--surface-50);
        transition: all 0.2s ease;

        &:hover {
          background: var(--primary-50);
          border-color: var(--primary-color);
        }

        &.p-inputnumber-button-up {
          border-top-right-radius: 8px;
          border-bottom: 1px solid var(--surface-border);
        }

        &.p-inputnumber-button-down {
          border-bottom-right-radius: 8px;
          border-top: 1px solid var(--surface-border);
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
      padding: 1rem;
    }

    &.p-message-info .p-message-wrapper {
      background: linear-gradient(135deg,
        var(--blue-50) 0%,
        var(--blue-100) 100%);
      border-left: 4px solid var(--blue-500);
    }
  }
}
</style>
