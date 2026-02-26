<template>
  <Dialog 
    :visible="visible"
    @update:visible="$emit('update:visible', $event)"
    header="保存为预设" 
    :modal="true"
    :style="{ width: '400px' }"
  >
    <div class="dialog-content">
      <div class="field">
        <label for="presetName">预设名称 *</label>
        <InputText id="presetName" v-model="presetName" class="w-full" />
      </div>
      <div class="field">
        <label for="presetDesc">描述（可选）</label>
        <Textarea id="presetDesc" v-model="presetDescription" rows="3" class="w-full" />
      </div>
    </div>
    <template #footer>
      <Button label="取消" severity="secondary" @click="handleCancel" />
      <Button label="保存" @click="handleSave" :disabled="!presetName.trim()" />
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'

interface Props {
  visible: boolean
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'update:visible': [value: boolean]
  save: [name: string, description?: string]
}>()

const presetName = ref('')
const presetDescription = ref('')

// 重置表单当对话框关闭时
watch(() => props.visible, (newVal) => {
  if (!newVal) {
    presetName.value = ''
    presetDescription.value = ''
  }
})

function handleCancel() {
  emit('update:visible', false)
}

function handleSave() {
  if (!presetName.value.trim()) return
  emit('save', presetName.value.trim(), presetDescription.value.trim() || undefined)
}
</script>

<style scoped>
.dialog-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.field label {
  font-weight: 500;
}

.w-full {
  width: 100%;
}
</style>
