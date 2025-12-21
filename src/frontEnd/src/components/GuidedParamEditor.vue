<template>
  <div class="guided-param-editor">
    <!-- 上半部分：左右布局 -->
    <div class="editor-main">
      <!-- 左侧：参数选择 -->
      <div class="param-select-panel">
        <div class="section-title">参数选择</div>
        <!-- 分类选择 -->
        <Select 
          v-model="selectedCategory" 
          :options="categoryOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="全部"
          class="w-full mb-2"
          @change="filterParams"
        />
        <!-- 搜索框 -->
        <InputText 
          v-model="searchKeyword"
          placeholder="搜索参数名或描述..."
          class="w-full mb-2"
          @input="filterParams"
        />
        <!-- 搜索选项 -->
        <div class="search-options">
          <div class="option-item">
            <Checkbox v-model="useRegex" :binary="true" inputId="regex" @change="filterParams" />
            <label for="regex">正则</label>
          </div>
          <div class="option-item">
            <Checkbox v-model="caseSensitive" :binary="true" inputId="case" @change="filterParams" />
            <label for="case">大小写</label>
          </div>
          <div class="option-item">
            <Checkbox v-model="invertFilter" :binary="true" inputId="invert" @change="filterParams" />
            <label for="invert">反转</label>
          </div>
        </div>
        <!-- 参数列表 -->
        <Listbox 
          v-model="currentParam"
          :options="filteredParams"
          optionLabel="name"
          class="param-listbox"
          @change="onParamSelect"
        >
          <template #option="{ option }">
            <div class="param-item" :class="{ 'is-selected': isParamSelected(option.key) }">
              <span class="param-name">{{ option.name }}</span>
              <span class="param-desc">{{ option.description }}</span>
              <Tag v-if="isParamSelected(option.key)" value="已添加" severity="success" class="param-tag" />
            </div>
          </template>
        </Listbox>
      </div>

      <!-- 右侧：参数设置和已选列表 -->
      <div class="param-config-panel">
        <!-- 参数设置区域 -->
        <div class="param-input-section">
          <div class="section-title">参数设置</div>
          <div v-if="currentParam" class="input-area">
            <div class="param-label">
              <span class="name">{{ currentParam.name }}</span>
              <span class="desc">- {{ currentParam.description }}</span>
            </div>
            <!-- 动态输入控件 -->
            <div class="input-control">
              <!-- technique参数特殊处理：使用多选复选框 -->
              <div v-if="currentParam.key === 'technique'" class="technique-checkboxes">
                <div v-for="tech in TECHNIQUE_OPTIONS" :key="tech.value" class="technique-item">
                  <Checkbox 
                    v-model="techniqueSelections" 
                    :inputId="'tech-' + tech.value" 
                    :value="tech.value"
                    @change="onTechniqueChange"
                  />
                  <label :for="'tech-' + tech.value">{{ tech.value }}</label>
                </div>
              </div>
              <!-- 其他参数使用动态组件 -->
              <component v-else :is="getInputComponent()" v-bind="getInputProps()" v-model="inputValue" />
            </div>
            <div class="button-row">
              <Button 
                :label="(isParamSelected(currentParam.key) ? '更新参数' : '添加参数') + ' ▼'" 
                size="small"
                @click="addOrUpdateParam"
              />
            </div>
          </div>
          <div v-else class="no-selection">请从左侧选择参数</div>
        </div>
        
        <!-- 已选参数列表 -->
        <div class="selected-params-section">
          <div class="section-title">已选参数 <span class="hint">(双击编辑)</span></div>
          <Listbox
            v-model="selectedParamKey"
            :options="selectedParamsList"
            optionLabel="display"
            optionValue="key"
            class="selected-listbox"
            @dblclick="onSelectedParamDblClick"
          >
            <template #option="{ option }">
              <div class="selected-param-item" @dblclick.stop="editSelectedParam(option.key)">
                <span class="cli-name">{{ option.cliName }}</span>
                <span class="cli-value">{{ option.valueDisplay }}</span>
              </div>
            </template>
          </Listbox>
          <div class="action-buttons">
            <Button label="编辑" size="small" severity="info" @click="editCurrentSelected" :disabled="!selectedParamKey" />
            <Button label="移除" size="small" severity="secondary" @click="removeSelectedParam" :disabled="!selectedParamKey" />
            <Button label="清空全部" size="small" severity="secondary" @click="clearAll" :disabled="selectedParamsCount === 0" />
          </div>
        </div>
      </div>
    </div>

    <!-- 下方：命令行预览 -->
    <div class="preview-section">
      <div class="section-title">命令行参数预览</div>
      <div class="command-preview" v-html="commandPreviewHtml"></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Checkbox from 'primevue/checkbox'
import Listbox from 'primevue/listbox'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import { PARAM_DEFINITIONS, PARAM_CATEGORIES, type ParamDefinition } from '@/utils/paramDefinitions'
import { parseParameterString } from '@/utils/scanConfigParser'

const props = defineProps<{
  initialParams?: string
}>()

const emit = defineEmits<{
  change: [paramString: string]
}>()

// 状态
const selectedCategory = ref('all')
const searchKeyword = ref('')
const useRegex = ref(false)
const caseSensitive = ref(false)
const invertFilter = ref(false)
const currentParam = ref<ParamDefinition | null>(null)
const inputValue = ref<any>(null)
const selectedParams = ref<Record<string, any>>({})
const selectedParamKey = ref<string | null>(null)
const techniqueSelections = ref<string[]>([])  // technique多选状态

// Technique选项
const TECHNIQUE_OPTIONS = [
  { value: 'B', label: '布尔盲注' },
  { value: 'E', label: '报错注入' },
  { value: 'U', label: '联合查询' },
  { value: 'S', label: '堆叠查询' },
  { value: 'T', label: '时间盲注' },
  { value: 'Q', label: '内联查询' }
]

// 分类选项
const categoryOptions = computed(() => [
  { label: '全部', value: 'all' },
  ...PARAM_CATEGORIES.map(c => ({ label: c.label, value: c.key }))
])

// 过滤后的参数列表
const filteredParams = computed(() => {
  let params = [...PARAM_DEFINITIONS]
  
  // 按分类过滤
  if (selectedCategory.value !== 'all') {
    params = params.filter(p => p.category === selectedCategory.value)
  }
  
  // 按关键字过滤
  const keyword = searchKeyword.value.trim()
  if (keyword) {
    params = params.filter(p => {
      let match = false
      const searchIn = `${p.name} ${p.description}`
      
      if (useRegex.value) {
        try {
          const flags = caseSensitive.value ? '' : 'i'
          const regex = new RegExp(keyword, flags)
          match = regex.test(searchIn)
        } catch { match = false }
      } else {
        const target = caseSensitive.value ? searchIn : searchIn.toLowerCase()
        const search = caseSensitive.value ? keyword : keyword.toLowerCase()
        match = target.includes(search)
      }
      
      return invertFilter.value ? !match : match
    })
  }
  
  return params
})

// 已选参数数量
const selectedParamsCount = computed(() => Object.keys(selectedParams.value).length)

// 命令行预览HTML
const commandPreviewHtml = computed(() => {
  const parts: string[] = []
  
  for (const [key, value] of Object.entries(selectedParams.value)) {
    const param = PARAM_DEFINITIONS.find(p => p.key === key)
    const cliName = param?.cliName || `--${key}`
    
    if (param?.type === 'boolean') {
      if (value === true) {
        parts.push(`<span class="flag">${cliName}</span>`)
      }
    } else if (value !== null && value !== undefined && value !== '') {
      const strValue = String(value)
      if (strValue.includes(' ')) {
        parts.push(`<span class="param">${cliName}</span>=<span class="value">"${strValue}"</span>`)
      } else {
        parts.push(`<span class="param">${cliName}</span>=<span class="value">${strValue}</span>`)
      }
    }
  }
  
  if (parts.length === 0) {
    return '<span class="empty">暂无参数，请从左侧选择参数添加</span>'
  }
  
  return parts.join(' ')
})

// 过滤参数
function filterParams() {
  // computed会自动处理
}

// 选中参数
function onParamSelect() {
  if (currentParam.value) {
    // 如果已选中，加载已有值
    const existingValue = selectedParams.value[currentParam.value.key]
    if (existingValue !== undefined) {
      inputValue.value = existingValue
      // technique特殊处理
      if (currentParam.value.key === 'technique') {
        techniqueSelections.value = String(existingValue).split('')
      }
    } else {
      inputValue.value = currentParam.value.defaultValue ?? (currentParam.value.type === 'boolean' ? false : '')
      // technique默认全选
      if (currentParam.value.key === 'technique') {
        techniqueSelections.value = ['B', 'E', 'U', 'S', 'T', 'Q']
      }
    }
  }
}

// technique多选变化
function onTechniqueChange() {
  inputValue.value = techniqueSelections.value.join('')
}

// 已选参数列表（用于Listbox显示）
const selectedParamsList = computed(() => {
  return Object.entries(selectedParams.value).map(([key, value]) => {
    const param = PARAM_DEFINITIONS.find(p => p.key === key)
    const cliName = param?.cliName || `--${key}`
    const valueDisplay = param?.type === 'boolean' ? '' : String(value)
    return {
      key,
      cliName,
      valueDisplay,
      display: valueDisplay ? `${cliName} ${valueDisplay}` : cliName
    }
  })
})

// 检查参数是否已选中
function isParamSelected(key: string | undefined): boolean {
  if (!key) return false
  return key in selectedParams.value
}

// 获取输入组件类型
function getInputComponent() {
  if (!currentParam.value) return 'div'
  const type = currentParam.value.type
  switch (type) {
    case 'boolean': return Checkbox
    case 'integer':
    case 'float': return InputNumber
    case 'select': return Select
    default: return InputText
  }
}

// 获取输入组件属性
function getInputProps() {
  if (!currentParam.value) return {}
  const param = currentParam.value
  const type = param.type
  
  switch (type) {
    case 'boolean':
      return { binary: true }
    case 'integer':
      return { min: param.min, max: param.max, showButtons: true }
    case 'float':
      return { min: param.min, max: param.max, minFractionDigits: 1, maxFractionDigits: 2 }
    case 'select':
      return { options: param.options?.map(o => ({ label: o, value: o })), optionLabel: 'label', optionValue: 'value' }
    default:
      return { placeholder: param.description }
  }
}

// 添加或更新参数
function addOrUpdateParam() {
  if (!currentParam.value) return
  
  const key = currentParam.value.key
  let value = inputValue.value
  
  // technique特殊处理
  if (key === 'technique') {
    value = techniqueSelections.value.join('')
  }
  
  // 布尔值为false时移除
  if (currentParam.value.type === 'boolean' && !value) {
    delete selectedParams.value[key]
  } else if (value !== null && value !== undefined && value !== '') {
    selectedParams.value[key] = value
  }
  
  emitChange()
}

// 移除参数
function removeParam(key: string | undefined) {
  if (!key) return
  delete selectedParams.value[key]
  emitChange()
}

// 移除已选参数列表中选中的参数
function removeSelectedParam() {
  if (selectedParamKey.value) {
    removeParam(selectedParamKey.value)
    selectedParamKey.value = null
  }
}

// 双击已选参数列表项进行编辑
function editSelectedParam(key: string) {
  if (!key) return
  
  // 查找对应的参数定义
  const param = PARAM_DEFINITIONS.find(p => p.key === key)
  if (!param) return
  
  // 设置当前参数
  currentParam.value = param
  
  // 加载已有值
  const existingValue = selectedParams.value[key]
  if (existingValue !== undefined) {
    inputValue.value = existingValue
    // technique特殊处理
    if (key === 'technique') {
      techniqueSelections.value = String(existingValue).split('')
    }
  }
}

// 编辑当前选中的已选参数
function editCurrentSelected() {
  if (selectedParamKey.value) {
    editSelectedParam(selectedParamKey.value)
  }
}

// 双击事件处理（备用）
function onSelectedParamDblClick() {
  if (selectedParamKey.value) {
    editSelectedParam(selectedParamKey.value)
  }
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
    const param = PARAM_DEFINITIONS.find(p => p.key === key)
    const cliName = param?.cliName || `--${key}`
    
    if (param?.type === 'boolean') {
      if (value === true) parts.push(cliName)
    } else if (value !== null && value !== undefined && value !== '') {
      const strValue = String(value)
      if (strValue.includes(' ')) {
        parts.push(`${cliName}="${strValue}"`)
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
  grid-template-columns: 280px 1fr;
  gap: 16px;
  flex: 1;
  min-height: 350px;
}

.section-title {
  font-weight: 600;
  font-size: 13px;
  color: var(--text-color);
  margin-bottom: 10px;
  padding-bottom: 6px;
  border-bottom: 2px solid var(--primary-color);
  
  .hint {
    font-weight: 400;
    font-size: 11px;
    color: var(--text-color-secondary);
  }
}

.param-select-panel {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 12px;
  display: flex;
  flex-direction: column;
}

.search-options {
  display: flex;
  gap: 12px;
  margin-bottom: 10px;
  
  .option-item {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
  }
}

.param-listbox {
  flex: 1;
  min-height: 200px;
  
  :deep(.p-listbox-list-container) {
    max-height: 280px;
  }
}

.param-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 4px 0;
  
  &.is-selected {
    background: rgba(var(--primary-color-rgb), 0.1);
  }
  
  .param-name {
    font-weight: 600;
    font-size: 13px;
  }
  
  .param-desc {
    font-size: 11px;
    color: var(--text-color-secondary);
  }
  
  .param-tag {
    margin-top: 2px;
    font-size: 10px;
  }
}

.param-config-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.param-input-section {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 12px;
  min-height: 140px;
  
  .input-area {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  
  .param-label {
    .name { font-weight: 600; color: var(--primary-color); }
    .desc { color: var(--text-color-secondary); font-size: 12px; margin-left: 6px; }
  }
  
  .input-control {
    padding: 8px 0;
  }
  
  .technique-checkboxes {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    
    .technique-item {
      display: flex;
      align-items: center;
      gap: 4px;
      
      label {
        font-size: 13px;
        cursor: pointer;
      }
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
    padding: 20px;
  }
}

.selected-params-section {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 12px;
  flex: 1;
  display: flex;
  flex-direction: column;
  
  .selected-listbox {
    flex: 1;
    min-height: 120px;
    
    :deep(.p-listbox-list-container) {
      max-height: 180px;
    }
  }
  
  .selected-param-item {
    display: flex;
    gap: 10px;
    padding: 4px 0;
    cursor: pointer;
    transition: background-color 0.15s;
    
    &:hover {
      background-color: rgba(var(--primary-color-rgb), 0.08);
    }
    
    .cli-name {
      font-family: 'Consolas', monospace;
      font-size: 13px;
      color: var(--primary-color);
      font-weight: 600;
    }
    
    .cli-value {
      font-family: 'Consolas', monospace;
      font-size: 13px;
      color: #27ae60;
    }
  }
  
  .action-buttons {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 8px;
  }
}

.preview-section {
  background: #1e1e1e;
  border-radius: 8px;
  overflow: hidden;
  
  .section-title {
    color: #d4d4d4;
    background: #2d2d2d;
    margin: 0;
    padding: 10px 14px;
    border-bottom: 1px solid #3d3d3d;
  }
  
  .command-preview {
    padding: 14px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    line-height: 1.8;
    color: #d4d4d4;
    min-height: 50px;
    
    :deep(.param) { color: #2980b9; font-weight: bold; }
    :deep(.value) { color: #27ae60; font-weight: bold; }
    :deep(.flag) { color: #8e44ad; font-weight: bold; }
    :deep(.empty) { color: #888; font-style: italic; }
  }
}

.w-full { width: 100%; }
.mb-2 { margin-bottom: 8px; }
</style>
