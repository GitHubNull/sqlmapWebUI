<template>
  <div class="task-options">
    <div v-if="loadingOptions" class="loading-container">
      <ProgressSpinner />
    </div>
    
    <div v-else-if="task?.options" class="options-content">
      <!-- 视图切换 -->
      <div class="view-toggle">
        <SelectButton
          v-model="viewMode"
          :options="viewOptions"
          option-label="label"
          option-value="value"
        />
      </div>

      <!-- 搜索栏 -->
      <div class="search-bar">
        <IconField>
          <InputIcon class="pi pi-search" />
          <InputText
            v-model="searchQuery"
            :placeholder="viewMode === 'table' ? '搜索配置项...' : '搜索参数...'"
          />
        </IconField>
        
        <Button
          v-if="searchQuery"
          icon="pi pi-times"
          text
          rounded
          @click="searchQuery = ''"
        />
      </div>

      <!-- 表格视图 -->
      <DataTable
        v-if="viewMode === 'table'"
        :value="filteredOptions"
        striped-rows
        show-gridlines
        class="options-table"
      >
        <Column field="name" header="配置项" sortable />
        <Column field="value" header="值">
          <template #body="{ data }">
            <Tag v-if="data.value === true" value="是" severity="success" />
            <Tag v-else-if="data.value === false" value="否" severity="secondary" />
            <span v-else>{{ data.value }}</span>
          </template>
        </Column>
        
        <Column field="description" header="说明" />
      </DataTable>

      <!-- 命令行视图 -->
      <CommandLinePreview
        v-else
        :command="commandLine"
        title="命令行"
      />
    </div>
    
    <div v-else class="empty-state">
      <i class="pi pi-info-circle"></i>
      <p>暂无扫描配置信息</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import type { Task } from '@/types/task'
import ProgressSpinner from 'primevue/progressspinner'
import SelectButton from 'primevue/selectbutton'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import CommandLinePreview from '@/components/CommandLinePreview.vue'

interface Props {
  task: Task | null
  loadingOptions: boolean
}

const props = defineProps<Props>()

const viewMode = ref('table')
const searchQuery = ref('')

const viewOptions = [
  { label: '表格视图', value: 'table', icon: 'pi pi-table' },
  { label: '命令行视图', value: 'cmdline', icon: 'pi pi-code' },
]

const optionsList = computed(() => {
  if (!props.task?.options) return []
  return Object.entries(props.task.options).map(([name, value]) => ({
    name,
    value,
    description: getOptionDescription(name)
  }))
})

const filteredOptions = computed(() => {
  if (!searchQuery.value) return optionsList.value
  const query = searchQuery.value.toLowerCase()
  return optionsList.value.filter(opt =>
    opt.name.toLowerCase().includes(query) ||
    String(opt.value).toLowerCase().includes(query)
  )
})

const commandLine = computed(() => {
  if (!props.task?.options) return 'sqlmap'
  
  const args = Object.entries(props.task.options)
    .filter(([_, value]) => value !== false && value !== undefined && value !== null)
    .map(([key, value]) => {
      if (value === true) return `--${key}`
      return `--${key}=${value}`
    })
  
  return `sqlmap ${args.join(' ')}`
})

function getOptionDescription(name: string): string {
  const descriptions: Record<string, string> = {
    level: '检测等级 (1-5)',
    risk: '风险等级 (1-3)',
    threads: '并发线程数',
    timeout: '请求超时时间',
    retries: '失败重试次数',
    batch: '批量模式',
    dump: '导出数据',
    dumpAll: '导出所有数据',
    getTables: '获取表名',
    getColumns: '获取列名',
    getDbs: '获取数据库名',
  }
  return descriptions[name] || ''
}
</script>

<style scoped>
.task-options {
  height: 100%;
}

.loading-container {
  display: flex;
  justify-content: center;
  padding: 2rem;
}

.options-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.view-toggle {
  display: flex;
  justify-content: center;
}

.search-bar {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.search-bar :deep(.p-icon-field) {
  flex: 1;
}

.options-table {
  margin-top: 0.5rem;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  color: var(--p-text-secondary-color);
}

.empty-state i {
  font-size: 2rem;
  margin-bottom: 0.5rem;
}
</style>
