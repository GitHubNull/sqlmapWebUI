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
        <Select 
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
        <DatePicker 
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
      <div class="filter-item reset-item">
        <label class="filter-label">&nbsp;</label>
        <Button 
          label="重置" 
          icon="pi pi-refresh" 
          @click="resetFilters" 
          severity="secondary"
          outlined
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
@use '@/assets/styles/variables.scss' as *;
@use '@/assets/styles/index.scss' as *;

.task-filter {
  margin-bottom: 32px;
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%);
  border-radius: $border-radius-xl;
  border: 2px solid rgba(255, 255, 255, 0.4);
  box-shadow:
    $shadow-elevated,
    inset 0 2px 4px rgba(255, 255, 255, 0.5);
  padding: 24px;
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      radial-gradient(circle at 20% 20%, rgba(99, 102, 241, 0.03) 0%, transparent 50%),
      radial-gradient(circle at 80% 80%, rgba(6, 182, 212, 0.03) 0%, transparent 50%);
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

.filter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 24px;
  margin-bottom: 24px;

  @media (min-width: 1400px) {
    grid-template-columns: repeat(3, 1fr);
  }

  @media (min-width: 900px) and (max-width: 1399px) {
    grid-template-columns: repeat(2, 1fr);
  }

  @media (max-width: 899px) {
    grid-template-columns: 1fr;
    gap: 20px;
  }
}

.filter-item {
  display: flex;
  flex-direction: column;
  gap: 12px;
  position: relative;

  &.reset-item {
    justify-content: flex-end;
  }
}

.reset-btn {
  width: auto;
  min-width: 100px;
  max-width: 120px;
}

.filter-label {
  font-size: 16px;
  font-weight: $font-weight-semibold;
  color: $text-color;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  background: $gradient-primary;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  position: relative;

  &::after {
    content: '';
    position: absolute;
    bottom: -4px;
    left: 0;
    width: 30px;
    height: 2px;
    background: $gradient-primary;
    border-radius: 1px;
    opacity: 0.6;
  }
}

.checkbox-wrapper {
  display: flex;
  align-items: center;
  gap: 12px;
  height: 48px;
  padding: 8px 16px;
  background: #ffffff;
  border-radius: $border-radius;
  border: 2px solid #e2e8f0;
  box-shadow: none;
  transition: all 0.2s ease;
  cursor: pointer;

  &:hover {
    border-color: #cbd5e1;
    background: #f8fafc;
  }
}

.checkbox-label {
  font-size: 15px;
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
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 20px;
  background:
    linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
  color: $primary-color;
  border-radius: $border-radius-lg;
  border: 2px solid rgba(99, 102, 241, 0.2);
  box-shadow:
    $shadow-raised,
    inset 0 1px 2px rgba(255, 255, 255, 0.4);
  font-size: 16px;
  font-weight: $font-weight-medium;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
      transparent 0%,
      rgba(255, 255, 255, 0.2) 50%,
      transparent 100%);
    animation: filter-summary-glow 2s ease-in-out infinite;
  }

  i {
    font-size: 20px;
    background: $gradient-primary;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.1));
  }
}

@keyframes filter-summary-glow {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(200%);
    opacity: 1;
  }
}

.w-full {
  width: 100%;
}

// ==================== PrimeVue表单控件3D增强 ====================
:deep(.p-inputtext),
:deep(.p-select) {
  @include input-3d();
  font-size: 15px;
  padding: 12px 16px;
  height: 48px;
  transition: $transition-base;

  &:hover {
    transform: translateY(-1px);
    box-shadow:
      $shadow-inset-dark,
      $shadow-elevated;
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
    font-size: 15px;
    padding: 12px 16px;
    height: 48px;
    transition: $transition-base;

    &:hover {
      transform: translateY(-1px);
      box-shadow:
        $shadow-inset-dark,
        $shadow-elevated;
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
    width: 48px;
    border-radius: 0 $border-radius $border-radius 0;
    transition: $transition-base;

    &:hover {
      background: $gradient-secondary;
      transform: scale(1.05);
    }

    .p-icon {
      color: white;
      filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.3));
    }
  }
}

// 复选框简洁扁平样式
:deep(.p-checkbox) {
  .p-checkbox-box {
    width: 20px;
    height: 20px;
    display: inline-flex !important;
    align-items: center;
    justify-content: center;
    background: #ffffff;
    border: 2px solid #cbd5e1;
    border-radius: 4px;
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
    box-shadow: 0 1px 3px rgba(99, 102, 241, 0.2);

    .p-checkbox-icon {
      color: white !important;
      display: block !important;
      filter: none;
    }

    &:hover {
      background: #4f46e5 !important;
      box-shadow: 0 2px 4px rgba(99, 102, 241, 0.3);
    }
  }

  // 兼容旧版 .p-highlight 类
  .p-checkbox-box.p-highlight {
    background: #6366f1 !important;
    border-color: #6366f1 !important;
    box-shadow: 0 1px 3px rgba(99, 102, 241, 0.2);

    .p-checkbox-icon {
      color: white !important;
      font-size: 14px;
      display: block !important;
      filter: none;
    }

    &:hover {
      background: #4f46e5 !important;
      box-shadow: 0 2px 4px rgba(99, 102, 241, 0.3);
    }
  }

  .p-checkbox-box.p-focus {
    outline: 2px solid rgba(99, 102, 241, 0.2);
    outline-offset: 2px;
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
