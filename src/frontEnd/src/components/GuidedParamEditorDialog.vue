<template>
  <Dialog
    v-model:visible="visible"
    :header="dialogHeader"
    :modal="true"
    :closable="true"
    :draggable="false"
    :style="{ width: '900px' }"
    class="guided-param-editor-dialog"
    @hide="onCancel"
  >
    <!-- 编辑模式下显示配置信息 -->
    <div v-if="presetName" class="preset-info">
      <div class="preset-name">
        <i class="pi pi-bookmark"></i>
        <span class="label">配置名称：</span>
        <span class="value">{{ presetName }}</span>
      </div>
      <div class="preset-desc">
        <i class="pi pi-info-circle"></i>
        <span class="label">描    述：</span>
        <span class="value" :class="{ 'empty': !presetDescription }">{{ presetDescription || '(无描述)' }}</span>
      </div>
    </div>
    
    <GuidedParamEditor 
      ref="editorRef"
      :initial-params="initialParams"
      @change="onEditorChange"
    />
    
    <template #footer>
      <div class="dialog-footer">
        <Button label="取消" icon="pi pi-times" severity="secondary" @click="onCancel" />
        <Button label="确定" icon="pi pi-check" @click="onConfirm" />
      </div>
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import GuidedParamEditor from './GuidedParamEditor.vue'

const props = defineProps<{
  modelValue: boolean
  title?: string
  initialParams?: string
  presetName?: string        // 配置名称（编辑模式显示）
  presetDescription?: string // 配置描述（编辑模式显示）
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  confirm: [paramString: string]
  cancel: []
}>()

const editorRef = ref<InstanceType<typeof GuidedParamEditor> | null>(null)
const currentParamString = ref('')

const visible = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit('update:modelValue', value)
})

const dialogHeader = computed(() => {
  if (props.presetName) {
    return `${props.title || '引导式参数配置'}`
  }
  return props.title || '引导式参数配置'
})

function onEditorChange(paramString: string) {
  currentParamString.value = paramString
}

function onConfirm() {
  const paramString = editorRef.value?.getCommandLine() || ''
  emit('confirm', paramString)
  visible.value = false
}

function onCancel() {
  emit('cancel')
  visible.value = false
}

// 暴露给父组件
defineExpose({
  getCommandLine: () => editorRef.value?.getCommandLine() || ''
})
</script>

<style scoped lang="scss">
.guided-param-editor-dialog {
  :deep(.p-dialog-content) {
    padding: 16px;
    min-height: 500px;
  }
}

.preset-info {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.05) 100%);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 12px 16px;
  margin-bottom: 16px;
  
  .preset-name, .preset-desc {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    
    i {
      color: var(--primary-color);
      font-size: 14px;
    }
    
    .label {
      color: var(--text-color-secondary);
    }
    
    .value {
      font-weight: 600;
      color: var(--text-color);
    }
  }
  
  .preset-name {
    margin-bottom: 6px;
    
    .value {
      color: var(--primary-color);
    }
  }
  
  .preset-desc {
    .value {
      font-weight: 400;
      font-style: italic;
      
      &.empty {
        color: var(--text-color-secondary);
        opacity: 0.7;
      }
    }
  }
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
