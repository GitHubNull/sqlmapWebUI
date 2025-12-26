/**
 * Session Headers Composable
 * 管理Session Headers的状态和业务逻辑
 */
import { ref, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import {
  getSessionHeaders,
  setSessionHeaders,
  deleteSessionHeader,
  updateSessionHeader,
  clearSessionHeaders as clearAllSessionHeaders,
} from '@/api/headerRule'
import type { SessionHeader, HeaderScope } from '@/types/headerRule'
import { ReplaceStrategy } from '@/types/headerRule'
import {
  DEFAULT_PRIORITY,
  DEFAULT_TTL,
  DEFAULT_PAGE_SIZE,
  TEXT_TEMPLATE,
  JSON_TEMPLATE_DATA,
  FIELD_SEPARATOR,
} from '../components/SessionHeaders/constants'

export function useSessionHeaders() {
  const toast = useToast()
  const confirm = useConfirm()

  // ================== 状态定义 ==================
  const loading = ref(false)
  const saving = ref(false)
  const sessionHeaders = ref<any[]>([])
  const selectedSessionHeaders = ref<any[]>([])
  
  // 对话框可见性
  const dialogVisible = ref(false)
  const batchDialogVisible = ref(false)
  const fileImportDialogVisible = ref(false)
  const textImportDialogVisible = ref(false)
  const jsonImportDialogVisible = ref(false)
  const editDialogVisible = ref(false)
  
  // 表单数据
  const rawHeaders = ref('')
  const batchRawHeaders = ref('')
  const fileContent = ref('')
  const defaultPriority = ref(DEFAULT_PRIORITY)
  const defaultTtl = ref(DEFAULT_TTL)
  const defaultReplaceStrategy = ref(ReplaceStrategy.REPLACE)
  const sessionScope = ref<HeaderScope | null>(null)
  const fileInput = ref<HTMLInputElement | null>(null)
  
  // 编辑相关
  const editingHeader = ref<any>(null)
  const editFormData = ref({
    header_name: '',
    header_value: '',
    replace_strategy: 'REPLACE' as any,
    priority: DEFAULT_PRIORITY,
    is_active: true,
    ttl: DEFAULT_TTL,
    scope: null as any
  })
  
  // 过滤相关
  const searchQuery = ref('')
  const statusFilter = ref<string | null>(null)
  const priorityFilter = ref<string | null>(null)
  const pageSize = ref(DEFAULT_PAGE_SIZE)

  // ================== 计算属性 ==================
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

  // ================== 工具函数 ==================
  function formatTime(timeStr: string) {
    if (!timeStr) return '-'
    return new Date(timeStr).toLocaleString('zh-CN')
  }

  function truncate(text: string, length: number) {
    if (text.length <= length) return text
    return text.substring(0, length) + '...'
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

  // ================== 数据加载 ==================
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

  // ================== 对话框控制 ==================
  function showAddDialog() {
    rawHeaders.value = ''
    defaultPriority.value = DEFAULT_PRIORITY
    defaultTtl.value = DEFAULT_TTL
    dialogVisible.value = true
  }

  function showFileImportDialog() {
    fileContent.value = ''
    fileImportDialogVisible.value = true
  }

  function showTextImportDialog() {
    fileContent.value = ''
    textImportDialogVisible.value = true
  }

  function showJsonImportDialog() {
    fileContent.value = ''
    jsonImportDialogVisible.value = true
  }

  function showEditDialog(header: any) {
    editingHeader.value = header
    editFormData.value = {
      header_name: header.header_name || '',
      header_value: header.header_value || '',
      replace_strategy: header.replace_strategy || ReplaceStrategy.REPLACE,
      priority: header.priority || DEFAULT_PRIORITY,
      is_active: header.is_active !== undefined ? header.is_active : true,
      ttl: header.ttl || DEFAULT_TTL,
      scope: header.scope || null
    }
    editDialogVisible.value = true
  }

  function selectFile() {
    fileInput.value?.click()
  }

  // ================== 模板下载 ==================
  function downloadTextTemplate() {
    downloadFile(TEXT_TEMPLATE, 'session_headers_template.txt', 'text/plain')
  }

  function downloadJsonTemplate() {
    const template = JSON.stringify(JSON_TEMPLATE_DATA, null, 2)
    downloadFile(template, 'session_headers_template.json', 'application/json')
  }

  // ================== 添加操作 ==================
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
      const lines = rawHeaders.value.split('\n').filter((line) => line.trim())
      const headers: SessionHeader[] = []

      for (const line of lines) {
        const [name, ...valueParts] = line.split(':')
        if (name && valueParts.length > 0) {
          headers.push({
            header_name: name.trim(),
            header_value: valueParts.join(':').trim(),
            replace_strategy: defaultReplaceStrategy.value,
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

  // ================== 导入操作 ==================
  async function handleTextImport() {
    if (!fileContent.value.trim()) {
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
      const lines = fileContent.value.split('\n').filter(line => {
        const trimmed = line.trim()
        return trimmed && !trimmed.startsWith('#')
      })
      const headers = []

      for (const line of lines) {
        const trimmedLine = line.trim()
        const parts = trimmedLine.split(FIELD_SEPARATOR)
        
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
              replace_strategy: replaceStrategy as ReplaceStrategy,
              priority: isNaN(priority) ? DEFAULT_PRIORITY : priority,
              ttl: isNaN(ttl) ? DEFAULT_TTL : ttl,
              scope: sessionScope.value
            })
          }
        }
      }

      if (headers.length === 0) {
        toast.add({
          severity: 'warn',
          summary: '解析失败',
          detail: '未找到有效的Header格式，请检查输入格式（使用 ||| 分隔）',
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
        fileContent.value = ''
        await loadSessionHeaders()
      } else {
        throw new Error(res.message || '导入失败')
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

  async function handleJsonImport() {
    if (!fileContent.value.trim()) {
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
      const jsonData = JSON.parse(fileContent.value)

      if (!Array.isArray(jsonData)) {
        throw new Error('JSON格式错误：必须是对象数组')
      }

      const headers = []
      for (const item of jsonData) {
        if (item.header_name && item.header_value) {
          headers.push({
            header_name: item.header_name,
            header_value: item.header_value,
            replace_strategy: item.replace_strategy || defaultReplaceStrategy.value,
            priority: item.priority || defaultPriority.value,
            ttl: item.ttl || defaultTtl.value,
            scope: item.scope || sessionScope.value
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
        fileContent.value = ''
        await loadSessionHeaders()
      } else {
        throw new Error(res.message || '导入失败')
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
            replace_strategy: item.replace_strategy || defaultReplaceStrategy.value,
            priority: item.priority || defaultPriority.value,
            ttl: item.ttl || defaultTtl.value,
            scope: item.scope || sessionScope.value,
          }))
        }
      } catch {
        // JSON解析失败，尝试作为文本文件解析
        const lines = fileContent.value.split('\n').filter(line => {
          const trimmed = line.trim()
          return trimmed && !trimmed.startsWith('#')
        })
        for (const line of lines) {
          const trimmedLine = line.trim()
          const parts = trimmedLine.split(FIELD_SEPARATOR)
          
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
                replace_strategy: replaceStrategy as ReplaceStrategy,
                priority: isNaN(priority) ? DEFAULT_PRIORITY : priority,
                ttl: isNaN(ttl) ? DEFAULT_TTL : ttl,
                scope: sessionScope.value,
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

  // ================== 编辑操作 ==================
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
      const res = await updateSessionHeader(editingHeader.value.header_name, editFormData.value)
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

  // ================== 删除操作 ==================
  function confirmDelete(header: any) {
    confirm.require({
      message: `确定要删除Header "${header.header_name}" 吗？`,
      header: '确认删除',
      icon: 'pi pi-exclamation-triangle',
      acceptLabel: '删除',
      rejectLabel: '取消',
      accept: () => deleteHeader(header.header_name),
    })
  }

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
          await clearAllSessionHeaders()
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

  // ================== 状态切换 ==================
  async function toggleActive(header: any) {
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
        if (index !== -1) {
          sessionHeaders.value[index].is_active = newStatus
        }
        toast.add({
          severity: 'success',
          summary: '状态已更新',
          detail: `已${newStatus ? '启用' : '禁用'} "${header.header_name}"`,
          life: 3000,
        })
      } else {
        toast.add({
          severity: 'error',
          summary: '操作失败',
          detail: res.message || '更新状态失败',
          life: 3000,
        })
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

  // ================== 批量操作 ==================
  function clearSelection() {
    selectedSessionHeaders.value = []
  }

  function clearFilters() {
    searchQuery.value = ''
    statusFilter.value = null
    priorityFilter.value = null
  }

  function confirmBatchDeleteHeaders() {
    if (selectedSessionHeaders.value.length === 0) return
    
    confirm.require({
      message: `确定要删除选中的 ${selectedSessionHeaders.value.length} 条会话Header吗？此操作不可撤销。`,
      header: '批量删除确认',
      icon: 'pi pi-exclamation-triangle',
      rejectClass: 'p-button-secondary p-button-outlined',
      rejectLabel: '取消',
      acceptLabel: '删除',
      acceptClass: 'p-button-danger',
      accept: () => {
        batchDeleteHeaders()
      },
    })
  }

  async function batchDeleteHeaders() {
    if (selectedSessionHeaders.value.length === 0) return
    
    let successCount = 0
    let errorCount = 0
    
    for (const header of selectedSessionHeaders.value) {
      try {
        await deleteSessionHeader(header.header_name)
        successCount++
      } catch (error) {
        errorCount++
        console.error('删除会话Header失败:', error)
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

  async function batchToggleActiveHeaders(isActive: boolean) {
    if (selectedSessionHeaders.value.length === 0) return
    
    let successCount = 0
    let errorCount = 0
    
    for (const header of selectedSessionHeaders.value) {
      try {
        await updateSessionHeader(header.header_name, {
          header_name: header.header_name,
          header_value: header.header_value,
          replace_strategy: header.replace_strategy,
          priority: header.priority,
          scope: header.scope,
          is_active: isActive
        })
        successCount++
      } catch (error) {
        errorCount++
        console.error(`${isActive ? '启用' : '禁用'}会话Header失败:`, error)
      }
    }
    
    await loadSessionHeaders()
    
    const action = isActive ? '启用' : '禁用'
    
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

  // ================== 返回 ==================
  return {
    // 状态
    loading,
    saving,
    sessionHeaders,
    selectedSessionHeaders,
    filteredSessionHeaders,
    
    // 对话框可见性
    dialogVisible,
    batchDialogVisible,
    fileImportDialogVisible,
    textImportDialogVisible,
    jsonImportDialogVisible,
    editDialogVisible,
    
    // 表单数据
    rawHeaders,
    batchRawHeaders,
    fileContent,
    defaultPriority,
    defaultTtl,
    defaultReplaceStrategy,
    sessionScope,
    fileInput,
    editingHeader,
    editFormData,
    
    // 过滤
    searchQuery,
    statusFilter,
    priorityFilter,
    pageSize,
    
    // 工具函数
    formatTime,
    truncate,
    
    // 数据操作
    loadSessionHeaders,
    addSessionHeaders,
    updateHeader,
    deleteHeader,
    toggleActive,
    confirmDelete,
    confirmClearAll,
    
    // 对话框控制
    showAddDialog,
    showFileImportDialog,
    showTextImportDialog,
    showJsonImportDialog,
    showEditDialog,
    selectFile,
    
    // 导入操作
    handleTextImport,
    handleJsonImport,
    handleFileSelect,
    handleFileImport,
    downloadTextTemplate,
    downloadJsonTemplate,
    
    // 批量操作
    clearSelection,
    clearFilters,
    confirmBatchDeleteHeaders,
    batchDeleteHeaders,
    batchToggleActiveHeaders,
  }
}
