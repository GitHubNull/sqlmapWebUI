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
              label="文本导入"
              icon="pi pi-file-edit"
              @click="textImportDialogVisible = true"
              severity="info"
              outlined
            />
            <Button
              label="JSON导入"
              icon="pi pi-code"
              @click="jsonImportDialogVisible = true"
              severity="info"
              outlined
            />
            <Button
              label="文件导入"
              icon="pi pi-file-import"
              @click="fileImportDialogVisible = true"
              severity="info"
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

    <!-- 批量操作工具栏 -->
    <div v-if="selectedSessionHeaders.length > 0" class="batch-actions-toolbar mb-4">
      <Card>
        <template #content>
          <div class="flex align-items-center justify-content-between">
            <div class="flex align-items-center gap-2">
              <i class="pi pi-check-square text-primary text-xl"></i>
              <span class="font-medium">已选择 {{ selectedSessionHeaders.length }} 项</span>
            </div>
            <div class="flex align-items-center gap-2">
              <Button
                label="批量删除"
                icon="pi pi-trash"
                severity="danger"
                @click="confirmBatchDeleteHeaders"
                size="small"
              />
              <Button
                label="批量启用"
                icon="pi pi-eye"
                severity="success"
                @click="batchToggleActiveHeaders(true)"
                size="small"
              />
              <Button
                label="批量禁用"
                icon="pi pi-eye-slash"
                severity="warning"
                @click="batchToggleActiveHeaders(false)"
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

    <!-- Session Headers列表 -->
    <DataTable
      :value="filteredSessionHeaders"
      :loading="loading"
      v-model:selection="selectedSessionHeaders"
      dataKey="id"
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
      <template #empty>
        <div class="empty-table-message">
          <i class="pi pi-inbox"></i>
          <p>暂无会话Header</p>
          <small>点击上方「单条添加」按钮创建新Header</small>
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

    <!-- 添加/编辑对话框 -->
    <EditDialog
      v-model="editDialogVisible"
      :edit-data="editFormData"
      :loading="saving"
      @submit="handleEditSubmit"
    />

    <!-- 文本导入对话框 -->
    <TextImportDialog
      v-model="textImportDialogVisible"
      :loading="saving"
      @import="handleTextImport"
      @download-template="downloadTextTemplate"
    />

    <!-- JSON导入对话框 -->
    <JsonImportDialog
      v-model="jsonImportDialogVisible"
      :loading="saving"
      @import="handleJsonImport"
      @download-template="downloadJsonTemplate"
    />

    <!-- 文件导入对话框 -->
    <FileImportDialog
      v-model="fileImportDialogVisible"
      :loading="saving"
      @import="handleFileImport"
      @download-text-template="downloadTextTemplate"
      @download-json-template="downloadJsonTemplate"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'

// 子组件
import { 
  TextImportDialog, 
  JsonImportDialog, 
  FileImportDialog, 
  EditDialog,
  STATUS_OPTIONS,
  PRIORITY_OPTIONS,
  TEXT_TEMPLATE,
  JSON_TEMPLATE_DATA,
  DEFAULT_PRIORITY,
  DEFAULT_TTL,
  DEFAULT_PAGE_SIZE,
  FIELD_SEPARATOR
} from './SessionHeaders'

// API
import {
  getSessionHeaders,
  setSessionHeaders,
  clearSessionHeaders,
  updateSessionHeader,
  deleteSessionHeader,
} from '@/api/headerRule'

// 类型
import type { HeaderScope, SessionHeader } from '@/types/headerRule'

// Toast & Confirm
const toast = useToast()
const confirm = useConfirm()

// 状态
const loading = ref(false)
const saving = ref(false)
const sessionHeaders = ref<SessionHeader[]>([])
const selectedSessionHeaders = ref<SessionHeader[]>([])
const pageSize = ref(DEFAULT_PAGE_SIZE)

// 搜索过滤
const searchQuery = ref('')
const statusFilter = ref<string | null>(null)
const priorityFilter = ref<string | null>(null)

// 过滤选项
const statusOptions = [...STATUS_OPTIONS]
const priorityOptions = [...PRIORITY_OPTIONS]

// 对话框状态
const editDialogVisible = ref(false)
const textImportDialogVisible = ref(false)
const jsonImportDialogVisible = ref(false)
const fileImportDialogVisible = ref(false)

// 编辑表单数据
const editFormData = ref<any>(null)
const editingHeader = ref<SessionHeader | null>(null)

// 生命周期
onMounted(() => {
  loadSessionHeaders()
})

// 加载Session Headers
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

// 过滤后的Session Headers
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

  // 状态过滤
  if (statusFilter.value) {
    const now = new Date()
    if (statusFilter.value === 'valid') {
      filtered = filtered.filter(header => {
        const expiresAt = (header as any).expires_at
        return expiresAt ? new Date(expiresAt) > now : true
      })
    } else if (statusFilter.value === 'expired') {
      filtered = filtered.filter(header => {
        const expiresAt = (header as any).expires_at
        return expiresAt ? new Date(expiresAt) <= now : false
      })
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

// 显示添加对话框
function showAddDialog() {
  editFormData.value = null
  editingHeader.value = null
  editDialogVisible.value = true
}

// 显示编辑对话框
function showEditDialog(header: SessionHeader) {
  editingHeader.value = header
  editFormData.value = {
    header_name: header.header_name,
    header_value: header.header_value,
    replace_strategy: header.replace_strategy,
    priority: header.priority || DEFAULT_PRIORITY,
    ttl: header.ttl || DEFAULT_TTL,
    is_active: header.is_active !== undefined ? header.is_active : true,
    scope: header.scope || null
  }
  editDialogVisible.value = true
}

// 处理编辑提交
async function handleEditSubmit(form: any, scope: HeaderScope | null) {
  if (!form.header_name.trim() || !form.header_value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请填写Header名称和值',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    if (editingHeader.value) {
      // 更新
      const res = await updateSessionHeader(editingHeader.value.header_name, {
        ...form,
        scope
      })
      if (res.success) {
        toast.add({
          severity: 'success',
          summary: '更新成功',
          detail: 'Session Header已更新',
          life: 3000,
        })
        editDialogVisible.value = false
        await loadSessionHeaders()
      } else {
        throw new Error(res.message)
      }
    } else {
      // 新增
      const headers = [{
        ...form,
        scope
      }]
      const res = await setSessionHeaders({ headers })
      if (res.success) {
        toast.add({
          severity: 'success',
          summary: '添加成功',
          detail: 'Session Header已添加',
          life: 3000,
        })
        editDialogVisible.value = false
        await loadSessionHeaders()
      } else {
        throw new Error(res.message)
      }
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '操作失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

// 文本导入处理
async function handleTextImport(content: string, scope: HeaderScope | null) {
  if (!content.trim()) {
    toast.add({
      severity: 'warn',
      summary: '输入为空',
      detail: '请输入要导入的文本内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    const lines = content.split('\n').filter(line => {
      const trimmed = line.trim()
      return trimmed && !trimmed.startsWith('#')
    })
    const headers: any[] = []

    for (const line of lines) {
      const parts = line.trim().split(FIELD_SEPARATOR)
      if (parts.length >= 2) {
        const headerName = parts[0]?.trim()
        const headerValue = parts[1]?.trim()
        const replaceStrategy = parts[2]?.trim() || 'REPLACE'
        const priority = parts[3] ? parseInt(parts[3].trim(), 10) : DEFAULT_PRIORITY
        const ttl = parts[4] ? parseInt(parts[4].trim(), 10) : DEFAULT_TTL

        if (headerName && headerValue) {
          headers.push({
            header_name: headerName,
            header_value: headerValue,
            replace_strategy: replaceStrategy,
            priority: isNaN(priority) ? DEFAULT_PRIORITY : priority,
            ttl: isNaN(ttl) ? DEFAULT_TTL : ttl,
            scope
          })
        }
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未找到有效的Header格式',
        life: 3000,
      })
      return
    }

    const res = await setSessionHeaders({ headers })
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '导入成功',
        detail: `成功导入 ${headers.length} 个Header`,
        life: 3000,
      })
      textImportDialogVisible.value = false
      await loadSessionHeaders()
    } else {
      throw new Error(res.message)
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '导入失败',
      detail: error.message || '文本导入失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

// JSON导入处理
async function handleJsonImport(content: string, scope: HeaderScope | null) {
  if (!content.trim()) {
    toast.add({
      severity: 'warn',
      summary: '输入为空',
      detail: '请输入要导入的JSON内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    const jsonData = JSON.parse(content)
    if (!Array.isArray(jsonData)) {
      throw new Error('JSON格式错误：必须是对象数组')
    }

    const headers: any[] = []
    for (const item of jsonData) {
      if (item.header_name && item.header_value) {
        headers.push({
          header_name: item.header_name,
          header_value: item.header_value,
          replace_strategy: item.replace_strategy || 'REPLACE',
          priority: item.priority || DEFAULT_PRIORITY,
          ttl: item.ttl || DEFAULT_TTL,
          scope: item.scope || scope
        })
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: 'JSON中未找到有效的Header数据',
        life: 3000,
      })
      return
    }

    const res = await setSessionHeaders({ headers })
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '导入成功',
        detail: `成功导入 ${headers.length} 个Header`,
        life: 3000,
      })
      jsonImportDialogVisible.value = false
      await loadSessionHeaders()
    } else {
      throw new Error(res.message)
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '导入失败',
      detail: 'JSON导入失败：' + error.message,
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

// 文件导入处理
async function handleFileImport(file: File, scope: HeaderScope | null) {
  saving.value = true
  try {
    const content = await file.text()
    let headers: any[] = []

    // 尝试解析为JSON
    if (file.name.endsWith('.json')) {
      try {
        const jsonData = JSON.parse(content)
        if (Array.isArray(jsonData)) {
          headers = jsonData.map(item => ({
            header_name: item.header_name || item.name,
            header_value: item.header_value || item.value,
            replace_strategy: item.replace_strategy || 'REPLACE',
            priority: item.priority || DEFAULT_PRIORITY,
            ttl: item.ttl || DEFAULT_TTL,
            scope: item.scope || scope,
          }))
        }
      } catch {
        throw new Error('JSON文件格式错误')
      }
    } else {
      // 文本文件解析
      const lines = content.split('\n').filter(line => {
        const trimmed = line.trim()
        return trimmed && !trimmed.startsWith('#')
      })
      
      for (const line of lines) {
        const parts = line.trim().split(FIELD_SEPARATOR)
        if (parts.length >= 2) {
          const headerName = parts[0]?.trim()
          const headerValue = parts[1]?.trim()
          const replaceStrategy = parts[2]?.trim() || 'REPLACE'
          const priority = parts[3] ? parseInt(parts[3].trim(), 10) : DEFAULT_PRIORITY
          const ttl = parts[4] ? parseInt(parts[4].trim(), 10) : DEFAULT_TTL

          if (headerName && headerValue) {
            headers.push({
              header_name: headerName,
              header_value: headerValue,
              replace_strategy: replaceStrategy,
              priority: isNaN(priority) ? DEFAULT_PRIORITY : priority,
              ttl: isNaN(ttl) ? DEFAULT_TTL : ttl,
              scope,
            })
          }
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

    const res = await setSessionHeaders({ headers })
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '导入成功',
        detail: `成功导入 ${headers.length} 个Session Header`,
        life: 3000,
      })
      fileImportDialogVisible.value = false
      await loadSessionHeaders()
    } else {
      throw new Error(res.message)
    }
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

// 模板下载
function downloadTextTemplate() {
  downloadFile(TEXT_TEMPLATE, 'session_headers_template.txt', 'text/plain')
}

function downloadJsonTemplate() {
  const template = JSON.stringify(JSON_TEMPLATE_DATA, null, 2)
  downloadFile(template, 'session_headers_template.json', 'application/json')
}

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

// 确认清除所有
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

// 确认删除
function confirmDelete(header: SessionHeader) {
  confirm.require({
    message: `确定要删除Header "${header.header_name}" 吗？`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    accept: () => deleteHeader(header.header_name),
  })
}

// 删除
async function deleteHeader(headerName: string) {
  try {
    const res = await deleteSessionHeader(headerName)
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '删除成功',
        detail: 'Session Header已删除',
        life: 3000,
      })
      await loadSessionHeaders()
    } else {
      throw new Error(res.message)
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
async function toggleActive(header: SessionHeader) {
  try {
    const newStatus = !header.is_active
    const res = await updateSessionHeader(header.header_name, {
      header_value: header.header_value,
      replace_strategy: header.replace_strategy,
      priority: header.priority,
      is_active: newStatus,
      scope: header.scope
    })
    
    if (res.success) {
      const index = sessionHeaders.value.findIndex(h => h.id === header.id)
      if (index !== -1 && sessionHeaders.value[index]) {
        sessionHeaders.value[index].is_active = newStatus
      }
      toast.add({
        severity: 'success',
        summary: '状态已更新',
        detail: `已${newStatus ? '启用' : '禁用'} "${header.header_name}"`,
        life: 3000,
      })
    } else {
      throw new Error(res.message)
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '更新状态失败',
      life: 3000,
    })
  }
}

// 批量操作
function clearSelection() {
  selectedSessionHeaders.value = []
}

function confirmBatchDeleteHeaders() {
  if (selectedSessionHeaders.value.length === 0) return
  
  confirm.require({
    message: `确定要删除选中的 ${selectedSessionHeaders.value.length} 条会话Header吗？此操作不可撤销。`,
    header: '批量删除确认',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: '取消',
    acceptLabel: '删除',
    acceptClass: 'p-button-danger',
    accept: batchDeleteHeaders,
  })
}

async function batchDeleteHeaders() {
  let successCount = 0
  let errorCount = 0
  
  for (const header of selectedSessionHeaders.value) {
    try {
      await deleteSessionHeader(header.header_name)
      successCount++
    } catch {
      errorCount++
    }
  }
  
  await loadSessionHeaders()
  
  if (errorCount === 0) {
    toast.add({
      severity: 'success',
      summary: '批量删除成功',
      detail: `成功删除 ${successCount} 条会话Header`,
      life: 3000,
    })
  } else {
    toast.add({
      severity: 'warning',
      summary: '批量删除部分成功',
      detail: `成功删除 ${successCount} 条，失败 ${errorCount} 条`,
      life: 3000,
    })
  }
  
  clearSelection()
}

async function batchToggleActiveHeaders(active: boolean) {
  let successCount = 0
  let errorCount = 0
  
  for (const header of selectedSessionHeaders.value) {
    try {
      await updateSessionHeader(header.header_name, {
        header_value: header.header_value,
        replace_strategy: header.replace_strategy,
        priority: header.priority,
        is_active: active,
        scope: header.scope
      })
      successCount++
    } catch {
      errorCount++
    }
  }
  
  await loadSessionHeaders()
  
  const action = active ? '启用' : '禁用'
  if (errorCount === 0) {
    toast.add({
      severity: 'success',
      summary: `批量${action}成功`,
      detail: `成功${action} ${successCount} 条会话Header`,
      life: 3000,
    })
  } else {
    toast.add({
      severity: 'warning',
      summary: `批量${action}部分成功`,
      detail: `成功${action} ${successCount} 条，失败 ${errorCount} 条`,
      life: 3000,
    })
  }
  
  clearSelection()
}

// 工具函数
function formatTime(timeStr: string) {
  if (!timeStr) return '-'
  return new Date(timeStr).toLocaleString('zh-CN')
}

function truncate(text: string, length: number) {
  if (text.length <= length) return text
  return text.substring(0, length) + '...'
}
</script>

<style scoped lang="scss">
@import './SessionHeaders/session-headers.scss';
</style>
