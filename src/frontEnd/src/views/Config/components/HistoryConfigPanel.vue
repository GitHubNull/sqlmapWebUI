<template>
  <div class="history-config-panel">
    <!-- 搜索面板 -->
    <div class="search-section">
      <div class="search-title">搜索过滤</div>
      <div class="search-row">
        <label>搜索:</label>
        <InputText v-model="searchKeyword" placeholder="输入关键词过滤历史记录" class="search-input" @keyup.enter="handleSearch" />
        <Button label="搜索" size="small" @click="handleSearch" />
      </div>
      <div class="advanced-options">
        <span class="options-label">高级选项:</span>
        <Checkbox v-model="useRegex" :binary="true" />
        <span class="checkbox-text">正则表达式</span>
        
        <Checkbox v-model="caseSensitive" :binary="true" />
        <span class="checkbox-text">大小写敏感</span>
        
        <Checkbox v-model="invertFilter" :binary="true" />
        <span class="checkbox-text">反选</span>
        
        <Button label="清除过滤" size="small" severity="secondary" @click="clearSearch" />
      </div>
    </div>

    <!-- 历史记录表格 -->
    <div class="table-section">
      <div class="table-title">历史扫描配置记录</div>
      <DataTable 
        v-model:selection="selectedRows"
        :value="displayList" 
        :loading="loading"
        dataKey="id"
        selectionMode="multiple"
        :metaKeySelection="false"
        scrollable
        scrollHeight="300px"
        class="history-table"
        :sortField="sortField"
        :sortOrder="sortOrder"
        @sort="onSort"
        @row-dblclick="handleRowDblClick"
      >
        <Column selectionMode="multiple" headerStyle="width: 3rem" />
        <Column field="id" header="ID" sortable style="width: 80px">
          <template #body="{ data }">
            <span class="id-badge">#{{ data.id }}</span>
          </template>
        </Column>
        <Column field="parameter_string" header="命令行参数" sortable style="min-width: 400px">
          <template #body="{ data }">
            <code class="param-code">{{ formatParamString(data) }}</code>
          </template>
        </Column>
        <Column field="last_used_at" header="最后使用" sortable style="width: 160px">
          <template #body="{ data }">
            {{ formatTime(data.last_used_at || data.created_at) }}
          </template>
        </Column>
        <Column field="use_count" header="使用次数" sortable style="width: 100px">
          <template #body="{ data }">
            <span class="use-count">{{ data.use_count || 0 }}</span>
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- 分页组件 -->
    <div class="pagination-section">
      <div class="pagination-info">
        <span>每页显示:</span>
        <Select
          v-model="pageSize"
          :options="pageSizeOptions"
          optionLabel="label"
          optionValue="value"
          class="page-size-select"
          @change="onPageSizeChange"
        />
        <span class="total-info">共 {{ totalRecords }} 条记录</span>
      </div>
      <Paginator
        :rows="pageSize"
        :totalRecords="totalRecords"
        :first="(currentPage - 1) * pageSize"
        @page="onPageChange"
        template="FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink"
      />
    </div>

    <!-- 操作栏 -->
    <div class="action-bar">
      <!-- 左侧按钮 -->
      <div class="left-buttons">
        <Button label="全选当前页" size="small" severity="secondary" @click="selectAllCurrentPage" />
        <Button label="取消全选" size="small" severity="secondary" @click="deselectAll" />
      </div>
      
      <!-- 状态栏 -->
      <div class="status-text">
        {{ statusText }}
      </div>
      
      <!-- 右侧按钮 -->
      <div class="right-buttons">
        <Button label="应用选中" size="small" severity="success" icon="pi pi-check" @click="applySelected" :disabled="selectedRows.length !== 1" />
        <Button label="删除选中" size="small" severity="danger" @click="deleteSelected" :disabled="selectedRows.length === 0" />
        <Button label="清空全部" size="small" severity="danger" @click="clearAll" :disabled="totalRecords === 0" />
        <Button label="刷新" size="small" severity="secondary" icon="pi pi-refresh" @click="refreshTable" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import InputText from 'primevue/inputtext'
import Checkbox from 'primevue/checkbox'
import Button from 'primevue/button'
import Select from 'primevue/select'
import DataTable, { type DataTableSortEvent } from 'primevue/datatable'
import Column from 'primevue/column'
import Paginator from 'primevue/paginator'
import dayjs from 'dayjs'
import type { ScanPreset } from '@/types/scanPreset'
import { useScanPresetStore } from '@/stores/scanPreset'
import { toParameterString } from '@/utils/scanConfigParser'
import * as scanPresetApi from '@/api/scanPreset'

const emit = defineEmits<{
  select: [preset: ScanPreset]
}>()

const toast = useToast()
const scanPresetStore = useScanPresetStore()

// 数据状态
const loading = ref(false)
const historyList = ref<ScanPreset[]>([])
const selectedRows = ref<ScanPreset[]>([])
const totalRecords = ref(0)

// 分页状态
const currentPage = ref(1)
const pageSize = ref(10)

// 排序状态
const sortField = ref('last_used_at')
const sortOrder = ref(-1) // -1 = desc, 1 = asc

// 搜索状态
const searchKeyword = ref('')
const useRegex = ref(false)
const caseSensitive = ref(false)
const invertFilter = ref(false)

// 分页选项
const pageSizeOptions = [
  { label: '10 条', value: 10 },
  { label: '20 条', value: 20 },
  { label: '50 条', value: 50 },
  { label: '100 条', value: 100 }
]

// 显示列表（本地过滤后的数据）
const displayList = computed(() => {
  if (!searchKeyword.value.trim()) return historyList.value
  
  const keyword = searchKeyword.value.trim()
  
  return historyList.value.filter(h => {
    const paramStr = h.parameter_string || toParameterString(h.options)
    let match = false
    
    if (useRegex.value) {
      try {
        const flags = caseSensitive.value ? '' : 'i'
        const regex = new RegExp(keyword, flags)
        match = regex.test(paramStr)
      } catch {
        match = false
      }
    } else {
      const target = caseSensitive.value ? paramStr : paramStr.toLowerCase()
      const search = caseSensitive.value ? keyword : keyword.toLowerCase()
      match = target.includes(search)
    }
    
    return invertFilter.value ? !match : match
  })
})

// 状态文本
const statusText = computed(() => {
  const selected = selectedRows.value.length
  const visible = displayList.value.length
  
  if (searchKeyword.value.trim()) {
    return `搜索结果 ${visible} 条，已选中 ${selected} 条`
  }
  return `第 ${currentPage.value}/${Math.ceil(totalRecords.value / pageSize.value) || 1} 页，已选中 ${selected} 条`
})

// 格式化时间
function formatTime(timeStr?: string): string {
  if (!timeStr) return '-'
  return dayjs(timeStr).format('YYYY-MM-DD HH:mm:ss')
}

// 格式化参数字符串
function formatParamString(preset: ScanPreset): string {
  if (preset.parameter_string) return preset.parameter_string
  if (preset.options) {
    const str = toParameterString(preset.options)
    return str || '(默认参数)'
  }
  return '(默认参数)'
}

// 加载数据
async function loadData() {
  loading.value = true
  try {
    const sortFieldApi = sortField.value
    const sortOrderApi = sortOrder.value === -1 ? 'desc' : 'asc'
    
    const result = await scanPresetApi.getHistoryConfigs(
      currentPage.value,
      pageSize.value,
      sortFieldApi,
      sortOrderApi
    )
    
    historyList.value = result.presets
    totalRecords.value = result.total
    selectedRows.value = []
  } catch (e) {
    toast.add({ severity: 'error', summary: '加载失败', life: 3000 })
  } finally {
    loading.value = false
  }
}

// 处理搜索
function handleSearch() {
  // 搜索时重置到第一页
  currentPage.value = 1
  loadData()
}

// 清除搜索
function clearSearch() {
  searchKeyword.value = ''
  useRegex.value = false
  caseSensitive.value = false
  invertFilter.value = false
}

// 排序变化
function onSort(event: DataTableSortEvent) {
  if (event.sortField && typeof event.sortField === 'string') {
    sortField.value = event.sortField
  }
  if (event.sortOrder !== undefined && event.sortOrder !== null) {
    sortOrder.value = event.sortOrder
  }
  currentPage.value = 1
  loadData()
}

// 分页变化
function onPageChange(event: { page: number; first: number; rows: number }) {
  currentPage.value = event.page + 1
  loadData()
}

// 每页数量变化
function onPageSizeChange() {
  currentPage.value = 1
  loadData()
}

// 全选当前页
function selectAllCurrentPage() {
  selectedRows.value = [...displayList.value]
}

// 取消全选
function deselectAll() {
  selectedRows.value = []
}

// 双击行选择
function handleRowDblClick(event: { data: ScanPreset }) {
  const preset = event.data
  if (preset && preset.id) {
    emit('select', preset)
    toast.add({
      severity: 'info',
      summary: '已选择历史配置',
      detail: `ID: #${preset.id} - ${preset.name}`,
      life: 2000
    })
  }
}

// 应用选中的配置
function applySelected() {
  if (selectedRows.value.length === 1) {
    const preset = selectedRows.value[0]
    if (preset && preset.id) {
      emit('select', preset)
      toast.add({
        severity: 'success',
        summary: '已应用历史配置',
        detail: `ID: #${preset.id} - ${preset.name}`,
        life: 2000
      })
    }
  }
}

// 刷新表格
async function refreshTable() {
  await loadData()
  // 同时更新 store 中的历史配置
  await scanPresetStore.loadConfigOptions()
}

// 删除选中
async function deleteSelected() {
  if (selectedRows.value.length === 0) {
    toast.add({ severity: 'warn', summary: '提示', detail: '请先选择要删除的记录', life: 2000 })
    return
  }
  
  const count = selectedRows.value.length
  if (!confirm(`确定要删除选中的 ${count} 条记录吗？`)) return
  
  try {
    for (const item of selectedRows.value) {
      if (item.id) {
        await scanPresetStore.deletePreset(item.id)
      }
    }
    toast.add({ severity: 'success', summary: '删除成功', detail: `已删除 ${count} 条历史记录`, life: 2000 })
    await refreshTable()
  } catch (e) {
    toast.add({ severity: 'error', summary: '删除失败', life: 3000 })
  }
}

// 清空全部
async function clearAll() {
  if (totalRecords.value === 0) {
    toast.add({ severity: 'info', summary: '提示', detail: '历史记录已为空', life: 2000 })
    return
  }
  
  if (!confirm(`确定要清空所有 ${totalRecords.value} 条历史记录吗？`)) return
  
  try {
    // 先获取所有历史配置
    const allResult = await scanPresetApi.getHistoryConfigs(1, 1000, 'id', 'asc')
    for (const item of allResult.presets) {
      if (item.id) {
        await scanPresetStore.deletePreset(item.id)
      }
    }
    toast.add({ severity: 'success', summary: '清空成功', detail: '已清空所有历史记录', life: 2000 })
    await refreshTable()
  } catch (e) {
    toast.add({ severity: 'error', summary: '清空失败', life: 3000 })
  }
}

onMounted(() => {
  loadData()
})
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.history-config-panel {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.search-section {
  background: var(--p-surface-card);
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
  padding: 12px;
  
  .search-title {
    font-weight: 600;
    font-size: 14px;
    color: var(--p-text-color);
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 2px solid var(--p-primary-color);
  }
  
  .search-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
    
    label {
      font-size: 13px;
      color: var(--p-text-color);
    }
    
    .search-input {
      width: 300px;
    }
  }
  
  .advanced-options {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    
    .options-label {
      font-size: 13px;
      color: var(--p-text-muted-color);
    }
    
    .checkbox-text {
      font-size: 13px;
      color: var(--p-text-color);
    }
  }
}

.table-section {
  background: var(--p-surface-card);
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
  padding: 12px;
  
  .table-title {
    font-weight: 600;
    font-size: 14px;
    color: var(--p-text-color);
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 2px solid var(--p-primary-color);
  }
}

.param-code {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  color: var(--p-text-color);
  background: var(--p-surface-section);
  padding: 2px 6px;
  border-radius: 4px;
}

.id-badge {
  display: inline-block;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  font-weight: 600;
  color: var(--p-primary-color);
  background: rgba(var(--p-primary-color-rgb, 99, 102, 241), 0.1);
  padding: 2px 8px;
  border-radius: 4px;
}

.use-count {
  display: inline-block;
  font-size: 12px;
  font-weight: 500;
  color: var(--p-text-muted-color);
  background: var(--p-surface-100);
  padding: 2px 8px;
  border-radius: 4px;
}

.pagination-section {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--p-surface-card);
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
  padding: 8px 12px;
  
  .pagination-info {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
    color: var(--p-text-muted-color);
    
    .page-size-select {
      width: 100px;
    }
    
    .total-info {
      font-weight: 500;
      color: var(--p-text-color);
    }
  }
}

.action-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  background: var(--p-surface-section);
  border-radius: var(--p-border-radius);
  
  .left-buttons, .right-buttons {
    display: flex;
    gap: 8px;
  }
  
  .status-text {
    font-size: 13px;
    color: var(--p-text-muted-color);
  }
}

:deep(.p-paginator) {
  background: transparent;
  border: none;
  padding: 0;
}
</style>
