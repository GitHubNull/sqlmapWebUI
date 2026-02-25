<template>
  <div class="task-filter">
    <!-- 第一行：关键字搜索 -->
    <div class="filter-row keyword-row">
      <div class="filter-item keyword-item">
        <label class="filter-label">URL关键字</label>
        <InputText 
          v-model="localFilters.urlKeyword" 
          placeholder="搜索URL..." 
          @input="onFilterChange"
          class="w-full"
        />
      </div>
      <div class="filter-item keyword-item">
        <label class="filter-label">报文关键字</label>
        <InputText 
          v-model="localFilters.messageKeyword" 
          placeholder="搜索Headers/Body..." 
          @input="onFilterChange"
          class="w-full"
        />
      </div>
    </div>
    
    <!-- 第二行：筛选条件 -->
    <div class="filter-row condition-row">
      <div class="filter-item compact-item">
        <label class="filter-label">任务状态</label>
        <Select 
          v-model="localFilters.status" 
          :options="statusOptions" 
          optionLabel="label" 
          optionValue="value"
          placeholder="所有" 
          @change="onFilterChange"
          class="compact-select"
          showClear
        />
      </div>
      
      <div class="filter-item compact-item">
        <label class="filter-label">注入状态</label>
        <Select 
          v-model="localFilters.injectableStatus" 
          :options="injectableOptions" 
          optionLabel="label" 
          optionValue="value"
          placeholder="所有" 
          @change="onFilterChange"
          class="compact-select"
          showClear
        />
      </div>
      
      <div class="filter-item date-item">
        <label class="filter-label">创建时间</label>
        <DatePicker 
          ref="createDatePickerRef"
          v-model="createDateRange" 
          selectionMode="range" 
          :showButtonBar="true"
          :showTime="true"
          hourFormat="24"
          dateFormat="yy-mm-dd"
          placeholder="选择时间范围" 
          class="date-picker"
        >
          <template #footer>
            <div class="datepicker-footer">
              <Button label="确定" size="small" @click="confirmCreateDate" />
            </div>
          </template>
        </DatePicker>
      </div>
      
      <div class="filter-item date-item">
        <label class="filter-label">执行时间</label>
        <DatePicker 
          ref="execDatePickerRef"
          v-model="execDateRange" 
          selectionMode="range" 
          :showButtonBar="true"
          :showTime="true"
          hourFormat="24"
          dateFormat="yy-mm-dd"
          placeholder="选择时间范围" 
          class="date-picker"
        >
          <template #footer>
            <div class="datepicker-footer">
              <Button label="确定" size="small" @click="confirmExecDate" />
            </div>
          </template>
        </DatePicker>
      </div>
      
      <div class="filter-item action-item">
        <Button 
          label="重置" 
          icon="pi pi-undo" 
          @click="resetFilters" 
          severity="secondary"
          outlined
          size="small"
          class="reset-btn"
        />
        <Button 
          label="刷新" 
          icon="pi pi-refresh" 
          @click="emit('refresh')" 
          severity="primary"
          :loading="props.loading"
          size="small"
          class="refresh-btn"
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
import Select from 'primevue/select'
import DatePicker from 'primevue/datepicker'
import { TaskStatus } from '@/types/task'
import type { TaskFilters } from '@/types/task'

interface Props {
  filters: TaskFilters
  filteredCount: number
  totalCount: number
  loading?: boolean
}

interface Emits {
  (e: 'update:filters', filters: TaskFilters): void
  (e: 'refresh'): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

// 本地过滤条件
const localFilters = ref<TaskFilters>({ ...props.filters })

// 日期范围
const createDateRange = ref<Date[] | null>(null)
const execDateRange = ref<Date[] | null>(null)

// DatePicker refs
const createDatePickerRef = ref()
const execDatePickerRef = ref()

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

// 注入状态选项
const injectableOptions = [
  { label: '所有状态', value: undefined },
  { label: '存在注入', value: 'injectable' },
  { label: '无注入', value: 'not_injectable' },
  { label: '未知', value: 'unknown' },
]

// 是否有激活的过滤条件
const hasActiveFilters = computed(() => {
  return !!(
    localFilters.value.urlKeyword ||
    localFilters.value.messageKeyword ||
    localFilters.value.status !== undefined ||
    localFilters.value.startDate ||
    localFilters.value.endDate ||
    localFilters.value.execStartDate ||
    localFilters.value.execEndDate ||
    localFilters.value.injectableStatus !== undefined
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

// 创建时间确认
function confirmCreateDate() {
  if (createDateRange.value && createDateRange.value.length === 2) {
    localFilters.value.startDate = createDateRange.value[0]?.toISOString() || undefined
    localFilters.value.endDate = createDateRange.value[1]?.toISOString() || undefined
  } else {
    localFilters.value.startDate = undefined
    localFilters.value.endDate = undefined
  }
  // 关闭弹窗
  if (createDatePickerRef.value) {
    createDatePickerRef.value.overlayVisible = false
  }
  onFilterChange()
}

// 执行时间确认
function confirmExecDate() {
  if (execDateRange.value && execDateRange.value.length === 2) {
    localFilters.value.execStartDate = execDateRange.value[0]?.toISOString() || undefined
    localFilters.value.execEndDate = execDateRange.value[1]?.toISOString() || undefined
  } else {
    localFilters.value.execStartDate = undefined
    localFilters.value.execEndDate = undefined
  }
  // 关闭弹窗
  if (execDatePickerRef.value) {
    execDatePickerRef.value.overlayVisible = false
  }
  onFilterChange()
}

// 重置过滤条件
function resetFilters() {
  localFilters.value = {}
  createDateRange.value = null
  execDateRange.value = null
  emit('update:filters', {})
}
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.task-filter {
  margin-bottom: 12px;
  background: var(--p-surface-0);
  border-radius: $border-radius-lg;
  border: 1px solid var(--p-surface-200);
  padding: 12px 16px;
}

// 行布局
.filter-row {
  display: flex;
  align-items: flex-end;
  gap: 12px;
  flex-wrap: wrap;
}

// 第一行：关键字搜索
.keyword-row {
  margin-bottom: 10px;
  
  .keyword-item {
    flex: 1;
    min-width: 200px;
  }
}

// 第二行：筛选条件
.condition-row {
  margin-bottom: 8px;
  
  .compact-item {
    flex: 0 0 auto;
    width: 130px;
  }
  
  .date-item {
    flex: 0 0 auto;
    width: 260px;
  }
  
  .action-item {
    flex: 0 0 auto;
    display: flex;
    flex-direction: row;
    align-items: flex-end;
    gap: 8px;
  }
}

.filter-item {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.compact-select {
  width: 100%;
}

.date-picker {
  width: 100%;
}

// DatePicker 整体宽度
:deep(.date-item .p-datepicker) {
  width: 100%;
  
  .p-datepicker-input-icon-container {
    width: 100%;
  }
  
  input.p-datepicker-input {
    min-width: 160px;
    width: 100%;
  }
}

.reset-btn {
  height: 36px;
  font-size: 12px;
}

.refresh-btn {
  height: 36px;
  font-size: 12px;
}

.datepicker-footer {
  display: flex;
  justify-content: flex-end;
  padding: 8px;
  border-top: 1px solid var(--p-surface-200);
}

.filter-label {
  font-size: 12px;
  font-weight: $font-weight-medium;
  color: var(--p-text-muted-color);
  margin-bottom: 0;
}

.checkbox-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 4px 12px;
  background: var(--p-surface-0);
  border-radius: $border-radius;
  border: 1px solid var(--p-surface-200);
  cursor: pointer;
}

.checkbox-label {
  font-size: 13px;
  color: var(--p-text-color);
  font-weight: $font-weight-medium;
  cursor: pointer;
  user-select: none;
}

.filter-summary {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: var(--p-surface-100);
  color: var(--p-primary-color);
  border-radius: $border-radius;
  font-size: 12px;
  font-weight: $font-weight-medium;

  i {
    font-size: 12px;
  }
}

.w-full {
  width: 100%;
}

// PrimeVue 表单控件尺寸调整
:deep(.p-inputtext),
:deep(.p-select) {
  font-size: 13px;
  padding: 6px 10px;
  height: 36px;
}

// DatePicker 输入框
:deep(.p-datepicker) {
  input.p-datepicker-input {
    font-size: 13px;
    padding: 6px 10px;
    height: 36px;
  }

  .p-datepicker-dropdown {
    width: 36px;
    border-radius: 0 $border-radius $border-radius 0;
  }
}

// 复选框样式
:deep(.p-checkbox) {
  .p-checkbox-box {
    width: 16px;
    height: 16px;
    display: inline-flex !important;
    align-items: center;
    justify-content: center;
    border-radius: 3px;
  }

  &.p-checkbox-checked .p-checkbox-box {
    .p-checkbox-icon {
      font-size: 10px;
    }
  }

  .p-checkbox-box.p-highlight {
    .p-checkbox-icon {
      font-size: 10px;
    }
  }
}
</style>
