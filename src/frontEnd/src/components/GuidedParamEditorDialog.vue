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
    <!-- 配置信息区域：新增模式可编辑，编辑模式也可编辑 -->
    <div class="preset-info-form">
      <div class="form-row">
        <label>
          <i class="pi pi-bookmark"></i>
          配置名称 <span class="required">*</span>
        </label>
        <InputText 
          v-model="formName" 
          placeholder="输入配置名称" 
          class="name-input"
        />
      </div>
      <div class="form-row">
        <label>
          <i class="pi pi-info-circle"></i>
          描    述
        </label>
        <InputText 
          v-model="formDescription" 
          placeholder="输入配置描述（可选）" 
          class="desc-input"
        />
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
        <Button label="保存" icon="pi pi-check" @click="onConfirm" :disabled="!formName.trim()" />
      </div>
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import GuidedParamEditor from './GuidedParamEditor.vue'

const props = defineProps<{
  modelValue: boolean
  title?: string
  initialParams?: string
  presetName?: string        // 配置名称（编辑模式传入）
  presetDescription?: string // 配置描述（编辑模式传入）
}>()

export interface GuidedEditorResult {
  name: string
  description: string
  paramString: string
}

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  confirm: [result: GuidedEditorResult]
  cancel: []
}>()

const editorRef = ref<InstanceType<typeof GuidedParamEditor> | null>(null)
const currentParamString = ref('')

// 表单字段
const formName = ref('')
const formDescription = ref('')

// 监听弹窗打开，初始化表单数据
watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    // 弹窗打开时初始化
    formName.value = props.presetName || ''
    formDescription.value = props.presetDescription || ''
  }
})

const visible = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit('update:modelValue', value)
})

const dialogHeader = computed(() => {
  return props.title || '引导式参数配置'
})

function onEditorChange(paramString: string) {
  currentParamString.value = paramString
}

function onConfirm() {
  if (!formName.value.trim()) return
  
  const paramString = editorRef.value?.getCommandLine() || ''
  emit('confirm', {
    name: formName.value.trim(),
    description: formDescription.value.trim(),
    paramString
  })
  visible.value = false
}

function onCancel() {
  emit('cancel')
  visible.value = false
}

// 暴露给父组件
defineExpose({
  getCommandLine: () => editorRef.value?.getCommandLine() || '',
  getFormData: () => ({
    name: formName.value.trim(),
    description: formDescription.value.trim()
  })
})
</script>

<style scoped lang="scss">
.guided-param-editor-dialog {
  :deep(.p-dialog-content) {
    padding: 16px;
    min-height: 500px;
  }
}

.preset-info-form {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.05) 100%);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 12px 16px;
  margin-bottom: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  
  .form-row {
    display: flex;
    align-items: center;
    gap: 12px;
    
    label {
      display: flex;
      align-items: center;
      gap: 6px;
      min-width: 100px;
      font-size: 13px;
      color: var(--text-color-secondary);
      
      i {
        color: var(--primary-color);
        font-size: 14px;
      }
      
      .required {
        color: #ef4444;
      }
    }
    
    .name-input, .desc-input {
      flex: 1;
      font-size: 13px;
    }
  }
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
