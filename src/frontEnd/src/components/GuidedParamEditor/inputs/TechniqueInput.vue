<template>
  <div class="technique-input">
    <div v-for="tech in TECHNIQUE_OPTIONS" :key="tech.value" class="technique-item">
      <Checkbox 
        v-model="selectedTechniques" 
        :inputId="'tech-' + tech.value" 
        :value="tech.value"
        @change="onTechniqueChange"
      />
      <label :for="'tech-' + tech.value">
        <span class="tech-value">{{ tech.value }}</span>
        <span class="tech-label">{{ tech.label }}</span>
      </label>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import Checkbox from 'primevue/checkbox'
import { TECHNIQUE_OPTIONS } from '@/utils/paramDefinitions'

const props = defineProps<{
  modelValue: string
}>()

const emit = defineEmits<{
  'update:modelValue': [value: string]
}>()

const selectedTechniques = ref<string[]>([])

// 初始化
onMounted(() => {
  if (props.modelValue) {
    selectedTechniques.value = props.modelValue.split('')
  } else {
    // 默认全选
    selectedTechniques.value = TECHNIQUE_OPTIONS.map(t => t.value)
  }
})

// 监听外部值变化
watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    selectedTechniques.value = newVal.split('')
  }
})

// 值变化时触发更新
function onTechniqueChange() {
  // 按 BEUSTQ 顺序排列
  const order = 'BEUSTQ'
  const sorted = selectedTechniques.value.sort((a, b) => order.indexOf(a) - order.indexOf(b))
  emit('update:modelValue', sorted.join(''))
}
</script>

<style scoped lang="scss">
.technique-input {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.technique-item {
  display: flex;
  align-items: center;
  gap: 6px;
  
  label {
    cursor: pointer;
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 4px;
    
    .tech-value {
      font-weight: 600;
      color: var(--primary-color);
    }
    
    .tech-label {
      color: var(--text-color-secondary);
      font-size: 12px;
    }
  }
}
</style>
