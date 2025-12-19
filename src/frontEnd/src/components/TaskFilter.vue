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
          icon="pi pi-refresh" 
          @click="resetFilters" 
          severity="secondary"
          outlined
          size="small"
          class="reset-btn"
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
}

interface Emits {
  (e: 'update:filters', filters: TaskFilters): void
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
@use '@/assets/styles/index.scss' as *;

.task-filter {
  margin-bottom: 12px;
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.85) 0%, rgba(248, 250, 252, 0.7) 100%);
  border-radius: $border-radius-lg;
  border: 1px solid rgba(226, 232, 240, 0.6);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
  padding: 12px 16px;
  position: relative;
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
    align-items: flex-end;
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

.datepicker-footer {
  display: flex;
  justify-content: flex-end;
  padding: 8px;
  border-top: 1px solid #e2e8f0;
}

.filter-label {
  font-size: 12px;
  font-weight: $font-weight-medium;
  color: #64748b;
  margin-bottom: 0;
}

.checkbox-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 4px 12px;
  background: #ffffff;
  border-radius: $border-radius;
  border: 1px solid #e2e8f0;
  box-shadow: none;
  transition: all 0.2s ease;
  cursor: pointer;

  &:hover {
    border-color: #cbd5e1;
    background: #f8fafc;
  }
}

.checkbox-label {
  font-size: 13px;
  color: $text-color;
  font-weight: $font-weight-medium;
  cursor: pointer;
  user-select: none;
  transition: color 0.2s ease;

  .checkbox-wrapper:hover & {
    color: $primary-color;
  }
}

.filter-summary {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: rgba(99, 102, 241, 0.08);
  color: $primary-color;
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

// ==================== PrimeVue表单控件 Normal 尺寸 ====================
:deep(.p-inputtext),
:deep(.p-select) {
  @include input-3d();
  font-size: 13px;
  padding: 6px 10px;
  height: 36px;
  transition: $transition-base;

  &:hover {
    transform: translateY(-1px);
    box-shadow:
      $shadow-inset-dark,
      $shadow-raised;
  }

  &:focus {
    border-color: $primary-color;
    box-shadow:
      $shadow-inset-dark,
      $shadow-glow;
    transform: translateY(-1px);
  }
}

// DatePicker 特殊处理：只样式化输入框
:deep(.p-datepicker) {
  input.p-datepicker-input {
    @include input-3d();
    font-size: 13px;
    padding: 6px 10px;
    height: 36px;
    transition: $transition-base;

    &:hover {
      transform: translateY(-1px);
      box-shadow:
        $shadow-inset-dark,
        $shadow-raised;
    }

    &:focus {
      border-color: $primary-color;
      box-shadow:
        $shadow-inset-dark,
        $shadow-glow;
      transform: translateY(-1px);
    }
  }

  .p-datepicker-dropdown {
    background: $gradient-primary;
    border: none;
    color: white;
    width: 36px;
    border-radius: 0 $border-radius $border-radius 0;
    transition: $transition-base;

    &:hover {
      background: $gradient-secondary;
      transform: scale(1.02);
    }

    .p-icon {
      color: white;
      width: 14px;
      height: 14px;
    }
  }
}

// 复选框简洁扁平样式
:deep(.p-checkbox) {
  .p-checkbox-box {
    width: 16px;
    height: 16px;
    display: inline-flex !important;
    align-items: center;
    justify-content: center;
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 3px;
    box-shadow: none;
    transition: all 0.2s ease;

    &:hover {
      border-color: #94a3b8;
      background: #f8fafc;
    }
  }

  // PrimeVue v4 使用 .p-checkbox-checked 类
  &.p-checkbox-checked .p-checkbox-box {
    background: #6366f1 !important;
    border-color: #6366f1 !important;

    .p-checkbox-icon {
      color: white !important;
      display: block !important;
      font-size: 10px;
      filter: none;
    }

    &:hover {
      background: #4f46e5 !important;
    }
  }

  // 兼容旧版 .p-highlight 类
  .p-checkbox-box.p-highlight {
    background: #6366f1 !important;
    border-color: #6366f1 !important;

    .p-checkbox-icon {
      color: white !important;
      font-size: 10px;
      display: block !important;
      filter: none;
    }

    &:hover {
      background: #4f46e5 !important;
    }
  }

  .p-checkbox-box.p-focus {
    outline: 2px solid rgba(99, 102, 241, 0.2);
    outline-offset: 1px;
  }
}

// 下拉面板3D效果
:deep(.p-select-overlay) {
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.95) 0%, rgba(248, 250, 252, 0.9) 100%);
  backdrop-filter: blur(10px);
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: $border-radius-lg;
  box-shadow: $shadow-floating;

  .p-select-option {
    transition: $transition-base;

    &:hover {
      background: $gradient-primary;
      color: white;
      transform: translateX(4px);
    }

    &.p-selected {
      background: rgba(99, 102, 241, 0.1);
      color: $primary-color;
    }
  }
}

// 日期选择器面板3D效果
:deep(.p-datepicker-panel) {
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.95) 0%, rgba(248, 250, 252, 0.9) 100%);
  backdrop-filter: blur(10px);
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: $border-radius-lg;
  box-shadow: $shadow-floating;

  .p-datepicker-calendar {
    td > span {
      transition: $transition-base;

      &:hover {
        background: $gradient-primary;
        color: white;
        transform: scale(1.1);
        border-radius: $border-radius;
      }

      &.p-selected {
        background: $gradient-primary;
        transform: scale(1.05);
        box-shadow: $shadow-raised;
      }
    }
  }
}
</style>
