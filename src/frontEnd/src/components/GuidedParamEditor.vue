<template>
  <div class="guided-param-editor">
    <!-- 上半部分：左右布局 -->
    <div class="editor-main">
      <!-- 左侧：参数选择 -->
      <ParamSelectPanel 
        :selected-params="selectedParams"
        @select="onParamSelect"
      />

      <!-- 右侧：参数设置和已选列表 -->
      <div class="param-config-area">
        <!-- 参数设置区域 -->
        <ParamConfigPanel 
          :param="currentParam"
          v-model="inputValue"
          :is-selected="isCurrentParamSelected"
          @add="addOrUpdateParam"
        />
        
        <!-- 已选参数列表 -->
        <SelectedParamsPanel 
          :params="selectedParams"
          @edit="editParam"
          @remove="removeParam"
          @clear="clearAll"
        />
      </div>
    </div>

    <!-- 下方：命令行预览 -->
    <CommandPreview :params="selectedParams" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import ParamSelectPanel from './GuidedParamEditor/ParamSelectPanel.vue'
import ParamConfigPanel from './GuidedParamEditor/ParamConfigPanel.vue'
import SelectedParamsPanel from './GuidedParamEditor/SelectedParamsPanel.vue'
import CommandPreview from './GuidedParamEditor/CommandPreview.vue'
import { 
  getParamDefinition,
  type ParamDefinition 
} from '@/utils/paramDefinitions'
import { parseParameterString } from '@/utils/scanConfigParser'

const props = defineProps<{
  initialParams?: string
}>()

const emit = defineEmits<{
  change: [paramString: string]
}>()

// 状态
const currentParam = ref<ParamDefinition | null>(null)
const inputValue = ref<any>(null)
const selectedParams = ref<Record<string, any>>({})

// 当前参数是否已选中
const isCurrentParamSelected = computed(() => {
  return currentParam.value ? currentParam.value.key in selectedParams.value : false
})

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
  
  // 布尔值为false时移除
  if (currentParam.value.type === 'boolean' && !value) {
    delete selectedParams.value[key]
  } else if (value !== null && value !== undefined && value !== '') {
    selectedParams.value[key] = value
  }
  
  emitChange()
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
  emitChange()
}

// 清空全部
function clearAll() {
  selectedParams.value = {}
  emitChange()
}

// 生成命令行字符串
function getCommandLine(): string {
  const parts: string[] = []
  
  for (const [key, value] of Object.entries(selectedParams.value)) {
    const param = getParamDefinition(key)
    const cliName = param?.cliName || `--${key}`
    
    if (param?.type === 'boolean') {
      if (value === true) parts.push(cliName)
    } else if (value !== null && value !== undefined && value !== '') {
      const strValue = String(value)
      if (strValue.includes(' ') || strValue.includes('"')) {
        parts.push(`${cliName}="${strValue.replace(/"/g, '\\"')}"`)
      } else {
        parts.push(`${cliName}=${strValue}`)
      }
    }
  }
  
  return parts.join(' ')
}

// 从参数字符串加载
function loadFromParamString(paramString: string) {
  if (!paramString.trim()) {
    selectedParams.value = {}
    return
  }
  
  const result = parseParameterString(paramString)
  // 只加载命令行中明确出现的参数（使用parsedParams）
  const explicitParams: Record<string, any> = {}
  for (const paramName of result.parsedParams) {
    const value = result.options[paramName as keyof typeof result.options]
    if (value !== undefined && value !== null) {
      explicitParams[paramName] = value
    }
  }
  selectedParams.value = explicitParams
}

// 发出change事件
function emitChange() {
  emit('change', getCommandLine())
}

// 暴露方法给父组件
defineExpose({
  getCommandLine,
  loadFromParamString
})

// 初始化
onMounted(() => {
  if (props.initialParams) {
    loadFromParamString(props.initialParams)
  }
})

// 监听initialParams变化
watch(() => props.initialParams, (newVal) => {
  if (newVal !== undefined) {
    loadFromParamString(newVal)
  }
})
</script>

<style scoped lang="scss">
.guided-param-editor {
  display: flex;
  flex-direction: column;
  gap: 12px;
  height: 100%;
}

.editor-main {
  display: grid;
  grid-template-columns: 300px 1fr;
  gap: 16px;
  flex: 1;
  min-height: 380px;
}

.param-config-area {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
</style>
