<template>
  <div class="param-config-panel">
    <div class="section-title">参数设置</div>
    <div v-if="param" class="input-area">
      <div class="param-label">
        <span class="name">{{ param.cliName }}</span>
        <span class="desc">- {{ param.description }}</span>
      </div>
      
      <!-- 安全警告 -->
      <div v-if="param.securityLevel && param.securityLevel !== 'normal'" 
           class="security-warning" 
           :class="param.securityLevel">
        <i class="pi pi-exclamation-triangle"></i>
        <span>{{ param.securityWarning }}</span>
      </div>
      
      <!-- 动态输入控件 -->
      <div class="input-control">
        <!-- technique参数特殊处理：使用多选复选框 -->
        <TechniqueInput 
          v-if="param.key === 'technique'" 
          v-model="localValue"
        />
        <!-- Select 类型 -->
        <Select 
          v-else-if="param.type === 'select'"
          v-model="localValue"
          :options="selectOptions"
          optionLabel="label"
          optionValue="value"
          :placeholder="param.placeholder || '请选择'"
          class="w-full"
        />
        <!-- Boolean 类型 -->
        <div v-else-if="param.type === 'boolean'" class="boolean-input">
          <Checkbox v-model="localValue" :binary="true" :inputId="'param-' + param.key" />
          <label :for="'param-' + param.key">启用此选项</label>
        </div>
        <!-- Integer 类型 -->
        <InputNumber 
          v-else-if="param.type === 'integer'"
          v-model="localValue"
          :min="param.min"
          :max="param.max"
          showButtons
          class="w-full"
        />
        <!-- Float 类型 -->
        <InputNumber 
          v-else-if="param.type === 'float'"
          v-model="localValue"
          :min="param.min"
          :max="param.max"
          :minFractionDigits="1"
          :maxFractionDigits="2"
          class="w-full"
        />
        <!-- Textarea 类型 -->
        <Textarea 
          v-else-if="param.type === 'textarea'"
          v-model="localValue"
          :placeholder="param.placeholder"
          rows="3"
          class="w-full"
        />
        <!-- String 类型 (默认) -->
        <InputText 
          v-else
          v-model="localValue"
          :placeholder="param.placeholder"
          class="w-full"
        />
      </div>
      
      <div class="button-row">
        <Button 
          :label="isSelected ? '更新参数' : '添加参数'" 
          size="small"
          :severity="param.securityLevel === 'danger' ? 'danger' : 'primary'"
          @click="onAdd"
        />
      </div>
    </div>
    <div v-else class="no-selection">请从左侧选择参数</div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Textarea from 'primevue/textarea'
import Checkbox from 'primevue/checkbox'
import Button from 'primevue/button'
import TechniqueInput from './inputs/TechniqueInput.vue'
import type { ParamDefinition } from '@/utils/paramDefinitions'

const props = defineProps<{
  param: ParamDefinition | null
  modelValue: any
  isSelected: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: any]
  add: []
}>()

// 本地值
const localValue = ref<any>(null)

// Select 选项
const selectOptions = computed(() => {
  if (props.param?.options) {
    return props.param.options.map(o => ({ label: o || '(空)', value: o }))
  }
  return []
})

// 监听参数变化，重置本地值
watch(() => props.param, (newParam) => {
  if (newParam) {
    localValue.value = props.modelValue ?? newParam.defaultValue ?? 
      (newParam.type === 'boolean' ? false : '')
  }
}, { immediate: true })

// 监听 modelValue 变化
watch(() => props.modelValue, (newVal) => {
  if (newVal !== undefined) {
    localValue.value = newVal
  }
})

// 监听本地值变化
watch(localValue, (newVal) => {
  emit('update:modelValue', newVal)
})

// 添加参数
function onAdd() {
  emit('add')
}
</script>

<style scoped lang="scss">
.param-config-panel {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 12px;
  min-height: 160px;
}

.section-title {
  font-weight: 600;
  font-size: 13px;
  color: var(--text-color);
  margin-bottom: 10px;
  padding-bottom: 6px;
  border-bottom: 2px solid var(--primary-color);
}

.input-area {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.param-label {
  .name { 
    font-weight: 600; 
    color: var(--primary-color); 
    font-family: 'Consolas', monospace;
  }
  .desc { 
    color: var(--text-color-secondary); 
    font-size: 12px; 
    margin-left: 6px; 
  }
}

.security-warning {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 4px;
  font-size: 12px;
  
  i {
    margin-top: 2px;
  }
  
  &.danger {
    background: var(--p-red-50);
    color: var(--p-red-700);
    border: 1px solid var(--p-red-200);
  }
  
  &.warning {
    background: var(--p-orange-50);
    color: var(--p-orange-700);
    border: 1px solid var(--p-orange-200);
  }
}

.input-control {
  padding: 4px 0;
}

.boolean-input {
  display: flex;
  align-items: center;
  gap: 8px;
  
  label {
    cursor: pointer;
    font-size: 13px;
  }
}

.button-row {
  display: flex;
  justify-content: flex-end;
}

.no-selection {
  color: var(--text-color-secondary);
  font-size: 13px;
  text-align: center;
  padding: 30px;
}

.w-full { width: 100%; }
</style>
