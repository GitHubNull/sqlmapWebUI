<template>
  <div class="task-filter">
    <div class="filter-grid">
      <!-- URL关键字搜索 -->
      <div class="filter-item">
        <label class="filter-label">URL关键字</label>
        <InputText 
          v-model="localFilters.urlKeyword" 
          placeholder="搜索URL..." 
          @input="onFilterChange"
          class="w-full"
        />
      </div>
      
      <!-- 报文关键字搜索 -->
      <div class="filter-item">
        <label class="filter-label">报文关键字</label>
        <InputText 
          v-model="localFilters.messageKeyword" 
          placeholder="搜索Headers/Body..." 
          @input="onFilterChange"
          class="w-full"
        />
      </div>
      
      <!-- 状态筛选 -->
      <div class="filter-item">
        <label class="filter-label">任务状态</label>
        <Dropdown 
          v-model="localFilters.status" 
          :options="statusOptions" 
          optionLabel="label" 
          optionValue="value"
          placeholder="所有状态" 
          @change="onFilterChange"
          class="w-full"
          showClear
        />
      </div>
      
      <!-- 日期范围 -->
      <div class="filter-item">
        <label class="filter-label">创建时间</label>
        <Calendar 
          v-model="dateRange" 
          selectionMode="range" 
          :showButtonBar="true"
          dateFormat="yy-mm-dd"
          placeholder="选择时间范围" 
          @date-select="onDateChange"
          class="w-full"
        />
      </div>
      
      <!-- 仅显示可注入 -->
      <div class="filter-item">
        <label class="filter-label">注入状态</label>
        <div class="checkbox-wrapper">
          <Checkbox 
            v-model="localFilters.injectableOnly" 
            :binary="true" 
            inputId="injectable"
            @change="onFilterChange"
          />
          <label for="injectable" class="checkbox-label">仅显示可注入</label>
        </div>
      </div>
      
      <!-- 重置按钮 -->
      <div class="filter-item">
        <label class="filter-label">&nbsp;</label>
        <Button 
          label="重置" 
          icon="pi pi-refresh" 
          @click="resetFilters" 
          severity="secondary"
          outlined
          class="w-full"
        />
      </div>
    </div>
    
    <!-- 过滤结果提示 -->
    <div v-if="hasActiveFilters" class="filter-summary">
      <i class="pi pi-filter"></i>
      <span>已过滤 {{ filteredCount }} / {{ totalCount }} 条任务</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { TaskStatus } from '@/types/task'
import type { TaskFilters } from '@/types/task'

interface Props {
  filters: TaskFilters
  filteredCount: number
  totalCount: number
}

interface Emits {
  (e: 'update:filters', filters: TaskFilters): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

// 本地过滤条件
const localFilters = ref<TaskFilters>({ ...props.filters })

// 日期范围
const dateRange = ref<Date[] | null>(null)

// 状态选项
const statusOptions = [
  { label: '所有状态', value: undefined },
  { label: '等待中', value: TaskStatus.PENDING },
  { label: '运行中', value: TaskStatus.RUNNING },
  { label: '已完成', value: TaskStatus.SUCCESS },
  { label: '失败', value: TaskStatus.FAILED },
  { label: '已停止', value: TaskStatus.STOPPED },
  { label: '已终止', value: TaskStatus.TERMINATED },
]

// 是否有激活的过滤条件
const hasActiveFilters = computed(() => {
  return !!(
    localFilters.value.urlKeyword ||
    localFilters.value.messageKeyword ||
    localFilters.value.status !== undefined ||
    localFilters.value.startDate ||
    localFilters.value.endDate ||
    localFilters.value.injectableOnly
  )
})

// 监听父组件传递的filters变化
watch(() => props.filters, (newFilters) => {
  localFilters.value = { ...newFilters }
}, { deep: true })

// 防抖定时器
let debounceTimer: number | null = null

// 过滤条件变化
function onFilterChange() {
  // 清除之前的定时器
  if (debounceTimer) {
    clearTimeout(debounceTimer)
  }
  
  // 设置300ms防抖
  debounceTimer = window.setTimeout(() => {
    emit('update:filters', { ...localFilters.value })
  }, 300)
}

// 日期变化
function onDateChange() {
  if (dateRange.value && dateRange.value.length === 2) {
    localFilters.value.startDate = dateRange.value[0]?.toISOString() || undefined
    localFilters.value.endDate = dateRange.value[1]?.toISOString() || undefined
  } else {
    localFilters.value.startDate = undefined
    localFilters.value.endDate = undefined
  }
  onFilterChange()
}

// 重置过滤条件
function resetFilters() {
  localFilters.value = {}
  dateRange.value = null
  emit('update:filters', {})
}
</script>

<style scoped lang="scss">
.task-filter {
  margin-bottom: 24px;
}

.filter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 16px;
  
  @media (min-width: 1200px) {
    grid-template-columns: repeat(3, 1fr);
  }
  
  @media (min-width: 768px) and (max-width: 1199px) {
    grid-template-columns: repeat(2, 1fr);
  }
}

.filter-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.filter-label {
  font-size: 14px;
  font-weight: 500;
  color: var(--text-color);
}

.checkbox-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 40px;
}

.checkbox-label {
  font-size: 14px;
  color: var(--text-color);
  cursor: pointer;
  user-select: none;
}

.filter-summary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  background: var(--blue-50);
  color: var(--blue-700);
  border-radius: 6px;
  font-size: 14px;
  
  i {
    font-size: 16px;
  }
}

.w-full {
  width: 100%;
}
</style>
