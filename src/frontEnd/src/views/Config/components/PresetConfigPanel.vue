<template>
  <div class="preset-config-panel">
    <!-- 顶部工具栏 -->
    <div class="toolbar">
      <!-- 搜索过滤 -->
      <div class="search-section">
        <div class="search-title">搜索过滤</div>
        <div class="search-row">
          <label>关键字:</label>
          <InputText v-model="searchKeyword" placeholder="输入关键字搜索（名称、描述、参数）" class="search-input" @keyup="applyFilter" />
          
          <Checkbox v-model="useRegex" :binary="true" @change="applyFilter" />
          <span class="checkbox-text">正则表达式</span>
          
          <Checkbox v-model="caseSensitive" :binary="true" @change="applyFilter" />
          <span class="checkbox-text">大小写敏感</span>
          
          <Checkbox v-model="invertFilter" :binary="true" @change="applyFilter" />
          <span class="checkbox-text">反选</span>
          
          <Button label="清除" size="small" severity="secondary" @click="clearSearch" />
        </div>
      </div>
      
      <!-- 操作按钮 -->
      <div class="action-buttons">
        <Button label="新增配置" icon="pi pi-plus" size="small" @click="showAddDialog" />
        <Button label="引导式添加" icon="pi pi-compass" size="small" severity="secondary" @click="showGuidedAddDialog" />
        <span class="separator">|</span>
        <Button label="编辑" icon="pi pi-pencil" size="small" severity="secondary" @click="showEditDialog" :disabled="!selectedRow" />
        <Button label="引导式编辑" icon="pi pi-sliders-h" size="small" severity="secondary" @click="showGuidedEditDialog" :disabled="!selectedRow" />
        <Button label="删除选中" icon="pi pi-trash" size="small" severity="danger" @click="deleteSelected" :disabled="selectedRows.length === 0" />
        <Button label="刷新" icon="pi pi-refresh" size="small" severity="secondary" @click="refreshTable" />
        <span class="separator">|</span>
        <Button label="导入" icon="pi pi-upload" size="small" severity="secondary" @click="showImportDialog" />
        <Button label="导出" icon="pi pi-download" size="small" severity="secondary" @click="showExportDialog" :disabled="filteredPresets.length === 0" />
      </div>
    </div>

    <!-- 配置列表表格 -->
    <div class="table-section">
      <div class="table-title">配置列表</div>
      <DataTable 
        v-model:selection="selectedRows"
        :value="filteredPresets" 
        :loading="loading"
        dataKey="id"
        selectionMode="multiple"
        :metaKeySelection="false"
        scrollable
        scrollHeight="400px"
        @rowDblclick="onRowDoubleClick"
        class="config-table"
      >
        <Column selectionMode="multiple" headerStyle="width: 3rem" />
        <Column field="id" header="序号" :sortable="true" style="width: 70px" />
        <Column field="name" header="名称" :sortable="true" style="min-width: 120px" />
        <Column field="description" header="描述" :sortable="true" style="min-width: 180px">
          <template #body="{ data }">
            {{ data.description || '-' }}
          </template>
        </Column>
        <Column field="parameter_string" header="命令行参数" style="min-width: 300px">
          <template #body="{ data }">
            <code class="param-code">{{ formatParamString(data) }}</code>
          </template>
        </Column>
        <Column field="created_at" header="创建时间" :sortable="true" style="width: 160px">
          <template #body="{ data }">
            {{ formatTime(data.created_at) }}
          </template>
        </Column>
        <Column field="updated_at" header="最后修改时间" :sortable="true" style="width: 160px">
          <template #body="{ data }">
            {{ formatTime(data.updated_at) }}
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- 状态栏 -->
    <div class="status-bar">
      {{ statusText }}
    </div>

    <!-- 新增/编辑对话框 -->
    <Dialog v-model:visible="showDialog" :header="dialogTitle" :modal="true" :style="{ width: '550px' }">
      <div class="dialog-form">
        <div class="form-row">
          <label>配置名称 *</label>
          <InputText v-model="editForm.name" placeholder="输入配置名称" class="w-full" />
        </div>
        <div class="form-row">
          <label>描述</label>
          <Textarea v-model="editForm.description" placeholder="输入配置描述（可选）" :rows="2" class="w-full" />
        </div>
        <div class="form-row">
          <label>命令行参数</label>
          <Textarea v-model="editForm.parameter_string" placeholder="如: --level=5 --risk=3 --dbms=mysql" :rows="4" class="w-full" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" @click="showDialog = false" />
        <Button label="保存" icon="pi pi-check" @click="saveConfig" :disabled="!editForm.name" />
      </template>
    </Dialog>

    <!-- 导入对话框 -->
    <Dialog v-model:visible="showImport" header="导入配置" :modal="true" :style="{ width: '500px' }">
      <div class="import-form">
        <Textarea v-model="importData" placeholder="粘贴JSON格式的配置数据" :rows="10" class="w-full" />
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" @click="showImport = false" />
        <Button label="导入" icon="pi pi-upload" @click="doImport" :disabled="!importData" />
      </template>
    </Dialog>

    <!-- 引导式参数编辑器对话框 -->
    <GuidedParamEditorDialog
      v-model="showGuidedEditor"
      :title="guidedEditorTitle"
      :initial-params="guidedEditorInitialParams"
      :preset-name="guidedEditorPresetName"
      :preset-description="guidedEditorPresetDescription"
      @confirm="onGuidedEditorConfirm"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Checkbox from 'primevue/checkbox'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import dayjs from 'dayjs'
import type { ScanPreset, ScanPresetCreate, ScanPresetUpdate } from '@/types/scanPreset'
import { useScanPresetStore } from '@/stores/scanPreset'
import { toParameterString, parseParameterString } from '@/utils/scanConfigParser'
import GuidedParamEditorDialog, { type GuidedEditorResult } from '@/components/GuidedParamEditorDialog.vue'

const emit = defineEmits<{
  select: [preset: ScanPreset]
  edit: [preset: ScanPreset]
}>()

const toast = useToast()
const scanPresetStore = useScanPresetStore()

// 状态
const loading = ref(false)
const presets = ref<ScanPreset[]>([])
const selectedRows = ref<ScanPreset[]>([])

// 搜索
const searchKeyword = ref('')
const useRegex = ref(false)
const caseSensitive = ref(false)
const invertFilter = ref(false)

// 对话框
const showDialog = ref(false)
const dialogTitle = ref('新增配置')
const editingId = ref<number | null>(null)
const editForm = ref<ScanPresetUpdate & { name: string }>({
  name: '',
  description: '',
  parameter_string: ''
})

// 导入
const showImport = ref(false)
const importData = ref('')

// 引导式编辑器
const showGuidedEditor = ref(false)
const guidedEditorTitle = ref('引导式参数配置 - 新建')
const guidedEditorInitialParams = ref('')
const guidedEditorMode = ref<'add' | 'edit'>('add')
const guidedEditorPresetName = ref('')       // 编辑模式下显示的配置名称
const guidedEditorPresetDescription = ref('') // 编辑模式下显示的配置描述

// 计算选中的单行
const selectedRow = computed(() => selectedRows.value.length === 1 ? selectedRows.value[0] : null)

// 过滤后的列表
const filteredPresets = computed(() => {
  if (!searchKeyword.value.trim()) return presets.value
  
  const keyword = searchKeyword.value.trim()
  
  return presets.value.filter(p => {
    let match = false
    const searchIn = [p.name, p.description || '', p.parameter_string || ''].join(' ')
    
    if (useRegex.value) {
      try {
        const flags = caseSensitive.value ? '' : 'i'
        const regex = new RegExp(keyword, flags)
        match = regex.test(searchIn)
      } catch {
        match = false
      }
    } else {
      const target = caseSensitive.value ? searchIn : searchIn.toLowerCase()
      const search = caseSensitive.value ? keyword : keyword.toLowerCase()
      match = target.includes(search)
    }
    
    return invertFilter.value ? !match : match
  })
})

// 状态文本
const statusText = computed(() => {
  const total = presets.value.length
  const visible = filteredPresets.value.length
  if (total === visible) {
    return `共 ${total} 条配置`
  }
  return `显示 ${visible} / ${total} 条配置`
})

// 格式化时间
function formatTime(timeStr?: string): string {
  if (!timeStr) return '-'
  return dayjs(timeStr).format('YYYY-MM-DD HH:mm')
}

// 格式化参数字符串
function formatParamString(preset: ScanPreset): string {
  // 优先使用 parameter_string
  if (preset.parameter_string && preset.parameter_string.trim()) {
    return preset.parameter_string
  }
  // 尝试从 options 生成
  if (preset.options && typeof preset.options === 'object') {
    const paramStr = toParameterString(preset.options)
    if (paramStr && paramStr.trim()) {
      return paramStr
    }
  }
  return '(默认参数)'
}

// 应用过滤
function applyFilter() {
  // 触发 computed 重新计算
}

// 清除搜索
function clearSearch() {
  searchKeyword.value = ''
  useRegex.value = false
  caseSensitive.value = false
  invertFilter.value = false
}

// 刷新表格
async function refreshTable() {
  loading.value = true
  try {
    await scanPresetStore.loadConfigOptions()
    presets.value = scanPresetStore.presets
    selectedRows.value = []
  } catch (e) {
    toast.add({ severity: 'error', summary: '加载失败', life: 3000 })
  } finally {
    loading.value = false
  }
}

// 显示新增对话框
function showAddDialog() {
  dialogTitle.value = '新增配置'
  editingId.value = null
  editForm.value = { name: '', description: '', parameter_string: '' }
  showDialog.value = true
}

// 显示引导式添加对话框
function showGuidedAddDialog() {
  guidedEditorTitle.value = '引导式参数配置 - 新建'
  guidedEditorInitialParams.value = ''
  guidedEditorMode.value = 'add'
  guidedEditorPresetName.value = ''
  guidedEditorPresetDescription.value = ''
  showGuidedEditor.value = true
}

// 显示引导式编辑对话框
function showGuidedEditDialog() {
  if (!selectedRow.value) {
    toast.add({ severity: 'warn', summary: '提示', detail: '请先选择要编辑的配置', life: 2000 })
    return
  }
  
  const preset = selectedRow.value
  guidedEditorTitle.value = '引导式参数配置 - 编辑'
  guidedEditorInitialParams.value = preset.parameter_string || toParameterString(preset.options)
  guidedEditorMode.value = 'edit'
  guidedEditorPresetName.value = preset.name
  guidedEditorPresetDescription.value = preset.description || ''
  editingId.value = preset.id || null
  editForm.value = {
    name: preset.name,
    description: preset.description || '',
    parameter_string: preset.parameter_string || toParameterString(preset.options)
  }
  showGuidedEditor.value = true
}

// 引导式编辑器确认回调
async function onGuidedEditorConfirm(result: GuidedEditorResult) {
  try {
    const parseResult = parseParameterString(result.paramString)
    
    if (guidedEditorMode.value === 'edit' && editingId.value) {
      // 编辑模式：更新现有配置
      await scanPresetStore.updatePreset(editingId.value, {
        name: result.name,
        description: result.description,
        parameter_string: result.paramString,
        options: parseResult.options
      })
      toast.add({ severity: 'success', summary: '更新成功', life: 2000 })
    } else {
      // 新增模式：直接保存，名称和描述已经在结果中
      await scanPresetStore.createPreset({
        name: result.name,
        description: result.description,
        preset_type: 'preset',
        parameter_string: result.paramString,
        options: parseResult.options
      })
      toast.add({ severity: 'success', summary: '添加成功', life: 2000 })
    }
    
    await refreshTable()
  } catch (e) {
    toast.add({ severity: 'error', summary: '保存失败', life: 3000 })
  }
}

// 显示编辑对话框
function showEditDialog() {
  if (!selectedRow.value) {
    toast.add({ severity: 'warn', summary: '提示', detail: '请先选择要编辑的配置', life: 2000 })
    return
  }
  
  const preset = selectedRow.value
  dialogTitle.value = '编辑配置'
  editingId.value = preset.id || null
  editForm.value = {
    name: preset.name,
    description: preset.description || '',
    parameter_string: preset.parameter_string || toParameterString(preset.options)
  }
  showDialog.value = true
}

// 双击编辑
function onRowDoubleClick(event: { data: ScanPreset }) {
  selectedRows.value = [event.data]
  showEditDialog()
}

// 保存配置
async function saveConfig() {
  if (!editForm.value.name) return
  
  try {
    const parseResult = parseParameterString(editForm.value.parameter_string || '')
    
    if (editingId.value) {
      await scanPresetStore.updatePreset(editingId.value, {
        name: editForm.value.name,
        description: editForm.value.description,
        parameter_string: editForm.value.parameter_string,
        options: parseResult.options
      })
      toast.add({ severity: 'success', summary: '更新成功', life: 2000 })
    } else {
      await scanPresetStore.createPreset({
        name: editForm.value.name,
        description: editForm.value.description,
        preset_type: 'preset',
        parameter_string: editForm.value.parameter_string,
        options: parseResult.options
      })
      toast.add({ severity: 'success', summary: '添加成功', life: 2000 })
    }
    
    showDialog.value = false
    await refreshTable()
  } catch (e) {
    toast.add({ severity: 'error', summary: '保存失败', life: 3000 })
  }
}

// 删除选中
async function deleteSelected() {
  if (selectedRows.value.length === 0) return
  
  const count = selectedRows.value.length
  if (!confirm(`确定要删除选中的 ${count} 条配置吗？此操作不可恢复！`)) return
  
  try {
    for (const preset of selectedRows.value) {
      if (preset.id) {
        await scanPresetStore.deletePreset(preset.id)
      }
    }
    toast.add({ severity: 'success', summary: '删除成功', detail: `已删除 ${count} 条配置`, life: 2000 })
    await refreshTable()
  } catch (e) {
    toast.add({ severity: 'error', summary: '删除失败', life: 3000 })
  }
}

// 显示导入对话框
function showImportDialog() {
  importData.value = ''
  showImport.value = true
}

// 导入
async function doImport() {
  if (!importData.value.trim()) return
  
  try {
    const data = JSON.parse(importData.value)
    const configs: ScanPresetCreate[] = Array.isArray(data) ? data : [data]
    
    let imported = 0
    for (const config of configs) {
      if (config.name) {
        await scanPresetStore.createPreset({
          name: config.name,
          description: config.description,
          preset_type: 'preset',
          parameter_string: config.parameter_string,
          options: config.options
        })
        imported++
      }
    }
    
    toast.add({ severity: 'success', summary: '导入成功', detail: `已导入 ${imported} 条配置`, life: 2000 })
    showImport.value = false
    await refreshTable()
  } catch (e) {
    toast.add({ severity: 'error', summary: '导入失败', detail: '请检查JSON格式', life: 3000 })
  }
}

// 导出
function showExportDialog() {
  const data = filteredPresets.value.map(p => ({
    name: p.name,
    description: p.description,
    parameter_string: p.parameter_string || toParameterString(p.options)
  }))
  
  const json = JSON.stringify(data, null, 2)
  const blob = new Blob([json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `scan-presets-${dayjs().format('YYYYMMDD-HHmmss')}.json`
  a.click()
  URL.revokeObjectURL(url)
  
  toast.add({ severity: 'success', summary: '导出成功', life: 2000 })
}

onMounted(() => {
  refreshTable()
})
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.preset-config-panel {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.toolbar {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.search-section {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.7) 100%);
  border: 1px solid rgba(226, 232, 240, 0.5);
  border-radius: $border-radius;
  padding: 12px;
  
  .search-title {
    font-weight: 600;
    font-size: 13px;
    color: $text-color;
    margin-bottom: 8px;
  }
  
  .search-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    
    label {
      font-size: 13px;
      color: $text-color;
    }
    
    .search-input {
      width: 280px;
    }
    
    .checkbox-text {
      font-size: 13px;
      color: $text-color;
    }
  }
}

.action-buttons {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  
  .separator {
    color: #ccc;
    margin: 0 4px;
  }
}

.table-section {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.7) 100%);
  border: 1px solid rgba(226, 232, 240, 0.5);
  border-radius: $border-radius;
  padding: 12px;
  
  .table-title {
    font-weight: 600;
    font-size: 14px;
    color: $text-color;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 2px solid $primary-color;
  }
}

.param-code {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  color: #334155;
  background: #f1f5f9;
  padding: 2px 6px;
  border-radius: 4px;
}

.status-bar {
  font-size: 13px;
  color: $text-color-secondary;
  padding: 8px 12px;
  background: rgba(248, 250, 252, 0.5);
  border-radius: $border-radius;
}

.dialog-form, .import-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
  
  .form-row {
    display: flex;
    flex-direction: column;
    gap: 6px;
    
    label {
      font-size: 13px;
      font-weight: 500;
      color: $text-color-secondary;
    }
  }
}

.w-full {
  width: 100%;
}
</style>
