<template>
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
    />
    <!-- 搜索框 -->
    <InputText 
      v-model="searchKeyword"
      placeholder="搜索参数名或描述..."
      class="w-full mb-2"
    />
    <!-- 搜索选项 -->
    <div class="search-options">
      <div class="option-item">
        <Checkbox v-model="useRegex" :binary="true" inputId="regex" />
        <label for="regex">正则</label>
      </div>
      <div class="option-item">
        <Checkbox v-model="caseSensitive" :binary="true" inputId="case" />
        <label for="case">大小写</label>
      </div>
      <div class="option-item">
        <Checkbox v-model="invertFilter" :binary="true" inputId="invert" />
        <label for="invert">反转</label>
      </div>
      <div class="option-item">
        <Checkbox v-model="showAdvanced" :binary="true" inputId="advanced" />
        <label for="advanced">高级</label>
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
        <div class="param-item" :class="{ 
          'is-selected': isParamSelected(option.key),
          'is-disabled': option.disabled,
          'is-dangerous': isDangerous(option)
        }">
          <div class="param-header">
            <span class="param-name">{{ option.name }}</span>
            <span v-if="option.disabled" class="disabled-badge" :title="option.disabledReason">禁用</span>
            <span v-if="isDangerous(option)" class="danger-badge" :title="option.securityWarning">
              {{ option.securityLevel === 'danger' ? '危险' : '警告' }}
            </span>
            <Tag v-if="isParamSelected(option.key)" value="已添加" severity="success" class="param-tag" />
          </div>
          <span class="param-desc">{{ option.description }}</span>
        </div>
      </template>
    </Listbox>
    <!-- 参数统计 -->
    <div class="param-stats">
      显示 {{ filteredParams.length }} / {{ totalParamCount }} 个参数
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'
import Checkbox from 'primevue/checkbox'
import Listbox from 'primevue/listbox'
import Tag from 'primevue/tag'
import { 
  PARAM_DEFINITIONS, 
  PARAM_CATEGORIES,
  type ParamDefinition,
  type ParamCategoryKey
} from '@/utils/paramDefinitions'

const props = defineProps<{
  selectedParams: Record<string, any>
}>()

const emit = defineEmits<{
  select: [param: ParamDefinition]
}>()

// 状态
const selectedCategory = ref<string>('all')
const searchKeyword = ref('')
const useRegex = ref(false)
const caseSensitive = ref(false)
const invertFilter = ref(false)
const showAdvanced = ref(false)
const currentParam = ref<ParamDefinition | null>(null)

// 分类选项
const categoryOptions = computed(() => [
  { label: '全部', value: 'all' },
  ...PARAM_CATEGORIES.map(c => ({ 
    label: `${c.label} (${getParamCountForCategory(c.key)})`, 
    value: c.key 
  }))
])

// 获取分类参数数量
function getParamCountForCategory(category: ParamCategoryKey): number {
  return PARAM_DEFINITIONS.filter(p => p.category === category && !p.disabled).length
}

// 总参数数量
const totalParamCount = computed(() => 
  PARAM_DEFINITIONS.filter(p => !p.disabled && (showAdvanced.value || !p.advanced)).length
)

// 过滤后的参数列表
const filteredParams = computed(() => {
  let params = [...PARAM_DEFINITIONS]
  
  // 过滤禁用参数
  params = params.filter(p => !p.disabled)
  
  // 过滤高级参数
  if (!showAdvanced.value) {
    params = params.filter(p => !p.advanced)
  }
  
  // 按分类过滤
  if (selectedCategory.value !== 'all') {
    params = params.filter(p => p.category === selectedCategory.value)
  }
  
  // 按关键字过滤
  const keyword = searchKeyword.value.trim()
  if (keyword) {
    params = params.filter(p => {
      let match = false
      const searchIn = `${p.name} ${p.cliName} ${p.description}`
      
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

// 检查参数是否已选中
function isParamSelected(key: string | undefined): boolean {
  if (!key) return false
  return key in props.selectedParams
}

// 检查是否为危险参数
function isDangerous(param: ParamDefinition): boolean {
  return param.securityLevel === 'danger' || param.securityLevel === 'warning'
}

// 选中参数
function onParamSelect() {
  if (currentParam.value && !currentParam.value.disabled) {
    emit('select', currentParam.value)
  }
}
</script>

<style scoped lang="scss">
.param-select-panel {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 12px;
  display: flex;
  flex-direction: column;
}

.section-title {
  font-weight: 600;
  font-size: 13px;
  color: var(--text-color);
  margin-bottom: 10px;
  padding-bottom: 6px;
  border-bottom: 2px solid var(--primary-color);
}

.search-options {
  display: flex;
  gap: 10px;
  margin-bottom: 10px;
  flex-wrap: wrap;
  
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
    max-height: 320px;
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
  
  &.is-disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  
  &.is-dangerous {
    border-left: 3px solid var(--p-orange-500);
    padding-left: 8px;
    margin-left: -8px;
  }
  
  .param-header {
    display: flex;
    align-items: center;
    gap: 6px;
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
    font-size: 10px;
  }
  
  .disabled-badge,
  .danger-badge {
    font-size: 10px;
    padding: 1px 4px;
    border-radius: 3px;
  }
  
  .disabled-badge {
    background: var(--surface-400);
    color: var(--surface-0);
  }
  
  .danger-badge {
    background: var(--p-orange-500);
    color: white;
  }
}

.param-stats {
  margin-top: 8px;
  font-size: 11px;
  color: var(--text-color-secondary);
  text-align: center;
}

.w-full { width: 100%; }
.mb-2 { margin-bottom: 8px; }
</style>
