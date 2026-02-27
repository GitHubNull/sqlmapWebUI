<template>
  <div class="custom-mode-content">
    <!-- 左侧：参数选择 -->
    <ParamSelectPanel 
      :selected-params="selectedParams"
      @select="onParamSelect"
      class="param-select-panel"
    />

    <!-- 右侧：参数配置和已选列表 -->
    <div class="param-config-area">
      <!-- 参数配置区域 -->
      <ParamConfigPanel 
        :param="currentParam"
        v-model="inputValue"
        :is-selected="isCurrentParamSelected"
        @add="addOrUpdateParam"
        class="param-config-panel"
      />
      
      <!-- 已选参数列表 -->
      <SelectedParamsPanel 
        :params="selectedParams"
        @edit="editParam"
        @remove="removeParam"
        @clear="clearAll"
        class="selected-params-panel"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import ParamSelectPanel from '@/components/GuidedParamEditor/ParamSelectPanel.vue'
import ParamConfigPanel from '@/components/GuidedParamEditor/ParamConfigPanel.vue'
import SelectedParamsPanel from '@/components/GuidedParamEditor/SelectedParamsPanel.vue'
import { getParamDefinition, type ParamDefinition } from '@/utils/paramDefinitions'
import type { ScanOptions } from '@/types/scanPreset'
import { 
  scanOptionsToSelectedParams, 
  selectedParamsToScanOptions 
} from './CustomModePanel/scanOptionsConverter'

interface Props {
  options: ScanOptions
  selectedTechniques: string[]
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'update:options': [options: ScanOptions]
  'update:selectedTechniques': [techniques: string[]]
}>()

// 内部状态 — selectedParams 是唯一数据源，不受 props 回写影响
const selectedParams = ref<Record<string, any>>(
  scanOptionsToSelectedParams(props.options)
)
const currentParam = ref<ParamDefinition | null>(null)
const inputValue = ref<any>(null)

// 当前参数是否已选中
const isCurrentParamSelected = computed(() => {
  return currentParam.value ? currentParam.value.key in selectedParams.value : false
})

// 发出 options 更新事件
function emitOptionsUpdate() {
  const newOptions = selectedParamsToScanOptions(selectedParams.value)
  emit('update:options', newOptions)
  
  // 同步 technique 到 selectedTechniques
  const technique = selectedParams.value.technique
  if (technique) {
    emit('update:selectedTechniques', technique.split(''))
  }
}

// 选中参数
function onParamSelect(param: ParamDefinition) {
  currentParam.value = param
  
  // 如果已选中，加载已有值
  const existingValue = selectedParams.value[param.key]
  if (existingValue !== undefined) {
    inputValue.value = existingValue
  } else {
    inputValue.value = param.defaultValue ?? (param.type === 'boolean' ? false : '')
  }
}

// 添加或更新参数
function addOrUpdateParam() {
  if (!currentParam.value) return
  
  const key = currentParam.value.key
  const value = inputValue.value
  
  // 布尔值为 false 时移除
  if (currentParam.value.type === 'boolean' && !value) {
    delete selectedParams.value[key]
  } else if (value !== null && value !== undefined && value !== '') {
    selectedParams.value[key] = value
  }
  
  emitOptionsUpdate()
}

// 编辑参数
function editParam(key: string) {
  const param = getParamDefinition(key)
  if (!param) return
  
  currentParam.value = param
  inputValue.value = selectedParams.value[key]
}

// 移除参数
function removeParam(key: string) {
  delete selectedParams.value[key]
  emitOptionsUpdate()
}

// 清空全部
function clearAll() {
  selectedParams.value = {}
  currentParam.value = null
  inputValue.value = null
  emitOptionsUpdate()
}
</script>

<style scoped lang="scss">
.custom-mode-content {
  display: grid;
  grid-template-columns: 260px 1fr;
  gap: 12px;
  height: 450px;
  min-height: 0;
}

.param-select-panel {
  min-height: 0;
  overflow: hidden;
}

.param-config-area {
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-height: 0;
  overflow: hidden;
}

.param-config-panel {
  flex-shrink: 0;
}

.selected-params-panel {
  flex: 1;
  min-height: 0;
  overflow: hidden;
  
  // 覆盖子组件的 Listbox 高度，确保在容器内正确滚动
  :deep(.selected-params-panel) {
    height: 100%;
    display: flex;
    flex-direction: column;
  }
  
  :deep(.selected-listbox) {
    flex: 1;
    min-height: 0;
    
    .p-listbox-list-container {
      max-height: none;
      height: 100%;
      overflow-y: auto;
    }
  }
}

@media (max-width: 1200px) {
  .custom-mode-content {
    grid-template-columns: 220px 1fr;
  }
}

@media (max-width: 900px) {
  .custom-mode-content {
    grid-template-columns: 1fr;
    grid-template-rows: 200px 1fr;
    height: auto;
    max-height: 600px;
  }
}
</style>
