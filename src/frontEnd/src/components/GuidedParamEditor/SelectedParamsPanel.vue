<template>
  <div class="selected-params-panel">
    <div class="section-title">已选参数 <span class="hint">(双击编辑)</span></div>
    <Listbox
      v-model="selectedKey"
      :options="paramsList"
      optionLabel="display"
      optionValue="key"
      class="selected-listbox"
    >
      <template #option="{ option }">
        <div class="selected-param-item" @dblclick.stop="onEdit(option.key)">
          <span class="cli-name" :class="{ 'is-dangerous': option.isDangerous }">
            {{ option.cliName }}
          </span>
          <span class="cli-value">{{ option.valueDisplay }}</span>
        </div>
      </template>
    </Listbox>
    <div class="action-buttons">
      <Button 
        label="编辑" 
        size="small" 
        severity="info" 
        @click="onEditCurrent" 
        :disabled="!selectedKey" 
      />
      <Button 
        label="移除" 
        size="small" 
        severity="secondary" 
        @click="onRemove" 
        :disabled="!selectedKey" 
      />
      <Button 
        label="清空全部" 
        size="small" 
        severity="secondary" 
        @click="onClear" 
        :disabled="paramsList.length === 0" 
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import Listbox from 'primevue/listbox'
import Button from 'primevue/button'
import { getParamDefinition } from '@/utils/paramDefinitions'

const props = defineProps<{
  params: Record<string, any>
}>()

const emit = defineEmits<{
  edit: [key: string]
  remove: [key: string]
  clear: []
}>()

const selectedKey = ref<string | null>(null)

// 参数列表
const paramsList = computed(() => {
  return Object.entries(props.params).map(([key, value]) => {
    const param = getParamDefinition(key)
    const cliName = param?.cliName || `--${key}`
    const valueDisplay = param?.type === 'boolean' ? '' : String(value)
    const isDangerous = param?.securityLevel === 'danger' || param?.securityLevel === 'warning'
    return {
      key,
      cliName,
      valueDisplay,
      display: valueDisplay ? `${cliName} ${valueDisplay}` : cliName,
      isDangerous
    }
  })
})

function onEdit(key: string) {
  emit('edit', key)
}

function onEditCurrent() {
  if (selectedKey.value) {
    emit('edit', selectedKey.value)
  }
}

function onRemove() {
  if (selectedKey.value) {
    emit('remove', selectedKey.value)
    selectedKey.value = null
  }
}

function onClear() {
  emit('clear')
  selectedKey.value = null
}
</script>

<style scoped lang="scss">
.selected-params-panel {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 12px;
  flex: 1;
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
  
  .hint {
    font-weight: 400;
    font-size: 11px;
    color: var(--text-color-secondary);
  }
}

.selected-listbox {
  flex: 1;
  min-height: 120px;
  
  :deep(.p-listbox-list-container) {
    max-height: 200px;
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
    
    &.is-dangerous {
      color: var(--p-orange-500);
    }
  }
  
  .cli-value {
    font-family: 'Consolas', monospace;
    font-size: 13px;
    color: var(--p-green-500);
  }
}

.action-buttons {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 8px;
}
</style>
