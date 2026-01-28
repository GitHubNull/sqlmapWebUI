<template>
  <div class="history-config-panel">
    <!-- 搜索面板 -->
    <div class="search-section">
      <div class="search-title">搜索过滤</div>
      <div class="search-row">
        <label>搜索:</label>
        <InputText v-model="searchKeyword" placeholder="输入关键词过滤历史记录" class="search-input" @keyup.enter="applyFilter" />
        <Button label="搜索" size="small" @click="applyFilter" />
      </div>
      <div class="advanced-options">
        <span class="options-label">高级选项:</span>
        <Checkbox v-model="useRegex" :binary="true" @change="applyFilter" />
        <span class="checkbox-text">正则表达式</span>
        
        <Checkbox v-model="caseSensitive" :binary="true" @change="applyFilter" />
        <span class="checkbox-text">大小写敏感</span>
        
        <Checkbox v-model="invertFilter" :binary="true" @change="applyFilter" />
        <span class="checkbox-text">反选</span>
        
        <Button label="清除过滤" size="small" severity="secondary" @click="clearSearch" />
      </div>
    </div>

    <!-- 历史记录表格 -->
    <div class="table-section">
      <div class="table-title">历史扫描配置记录</div>
      <DataTable 
        v-model:selection="selectedRows"
        :value="filteredHistory" 
        :loading="loading"
        dataKey="id"
        selectionMode="multiple"
        :metaKeySelection="false"
        scrollable
        scrollHeight="350px"
        class="history-table"
      >
        <Column selectionMode="multiple" headerStyle="width: 3rem" />
        <Column header="序号" style="width: 60px">
          <template #body="{ index }">
            {{ index + 1 }}
          </template>
        </Column>
        <Column field="parameter_string" header="命令行参数" style="min-width: 450px">
          <template #body="{ data }">
            <code class="param-code">{{ formatParamString(data) }}</code>
          </template>
        </Column>
        <Column header="日期时间" style="width: 160px">
          <template #body="{ data }">
            {{ formatTime(data.last_used_at || data.created_at) }}
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- 操作栏 -->
    <div class="action-bar">
      <!-- 左侧按钮 -->
      <div class="left-buttons">
        <Button label="全选" size="small" severity="secondary" @click="selectAll" />
        <Button label="取消全选" size="small" severity="secondary" @click="deselectAll" />
        <Button label="反选" size="small" severity="secondary" @click="invertSelection" />
      </div>
      
      <!-- 状态栏 -->
      <div class="status-text">
        {{ statusText }}
      </div>
      
      <!-- 右侧按钮 -->
      <div class="right-buttons">
        <Button label="删除选中" size="small" severity="danger" @click="deleteSelected" :disabled="selectedRows.length === 0" />
        <Button label="清空全部" size="small" severity="danger" @click="clearAll" :disabled="historyList.length === 0" />
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
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import dayjs from 'dayjs'
import type { ScanPreset } from '@/types/scanPreset'
import { useScanPresetStore } from '@/stores/scanPreset'
import { toParameterString } from '@/utils/scanConfigParser'

const emit = defineEmits<{
  select: [preset: ScanPreset]
}>()

const toast = useToast()
const scanPresetStore = useScanPresetStore()

// 状态
const loading = ref(false)
const historyList = ref<ScanPreset[]>([])
const selectedRows = ref<ScanPreset[]>([])

// 搜索
const searchKeyword = ref('')
const useRegex = ref(false)
const caseSensitive = ref(false)
const invertFilter = ref(false)

// 过滤后的列表
const filteredHistory = computed(() => {
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
  const total = historyList.value.length
  const visible = filteredHistory.value.length
  const selected = selectedRows.value.length
  
  if (total !== visible) {
    return `显示 ${visible}/${total} 条记录，已选中 ${selected} 条`
  }
  return `共 ${total} 条记录，已选中 ${selected} 条`
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

// 全选
function selectAll() {
  selectedRows.value = [...filteredHistory.value]
}

// 取消全选
function deselectAll() {
  selectedRows.value = []
}

// 反选
function invertSelection() {
  const currentIds = new Set(selectedRows.value.map(r => r.id))
  selectedRows.value = filteredHistory.value.filter(h => !currentIds.has(h.id))
}

// 刷新表格
async function refreshTable() {
  loading.value = true
  try {
    await scanPresetStore.loadConfigOptions()
    historyList.value = scanPresetStore.history
    selectedRows.value = []
  } catch (e) {
    toast.add({ severity: 'error', summary: '加载失败', life: 3000 })
  } finally {
    loading.value = false
  }
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
  if (historyList.value.length === 0) {
    toast.add({ severity: 'info', summary: '提示', detail: '历史记录已为空', life: 2000 })
    return
  }
  
  if (!confirm('确定要清空所有历史记录吗？')) return
  
  try {
    for (const item of historyList.value) {
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
  refreshTable()
})
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.history-config-panel {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.search-section {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.7) 100%);
  border: 1px solid rgba(226, 232, 240, 0.5);
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
      color: var(--p-text-color)-secondary;
    }
    
    .checkbox-text {
      font-size: 13px;
      color: var(--p-text-color);
    }
  }
}

.table-section {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.7) 100%);
  border: 1px solid rgba(226, 232, 240, 0.5);
  border-radius: var(--p-border-radius);
  padding: 12px;
  flex: 1;
  
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
  color: #334155;
  background: #f1f5f9;
  padding: 2px 6px;
  border-radius: 4px;
}

.action-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  background: rgba(248, 250, 252, 0.5);
  border-radius: var(--p-border-radius);
  
  .left-buttons, .right-buttons {
    display: flex;
    gap: 8px;
  }
  
  .status-text {
    font-size: 13px;
    color: var(--p-text-color)-secondary;
  }
}
</style>
