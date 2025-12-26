<template>
  <Dialog
    v-model:visible="visible"
    header="文件导入Session Headers"
    :style="{
      width: '90vw',
      maxWidth: '900px',
      maxHeight: '85vh'
    }"
    modal
    class="session-dialog"
  >
    <div class="dialog-content">
      <!-- 格式说明卡片 -->
      <Card class="info-card mb-4">
        <template #title>
          <div class="flex align-items-center justify-content-between">
            <div class="flex align-items-center gap-2">
              <i class="pi pi-file text-primary"></i>
              <span>文件导入格式说明</span>
            </div>
            <div class="flex gap-2">
              <Button
                label="文本模板"
                icon="pi pi-download"
                severity="secondary"
                size="small"
                outlined
                @click="$emit('download-text-template')"
              />
              <Button
                label="JSON模板"
                icon="pi pi-download"
                severity="secondary"
                size="small"
                outlined
                @click="$emit('download-json-template')"
              />
            </div>
          </div>
        </template>
        <template #content>
          <div class="format-description">
            <Message severity="info" :closable="false" class="mb-3">
              <div class="format-info">
                <div class="mb-2"><strong>支持两种文件格式</strong></div>
              </div>
            </Message>

            <div class="format-types">
              <div class="format-type mb-3">
                <div class="font-semibold text-primary mb-2">📄 文本格式 (.txt)</div>
                <div class="format-pattern">
                  <code>Header名称|||Header值|||替换策略|||优先级|||TTL(秒)</code>
                </div>
                <pre class="example-code mt-2">Authorization|||Bearer token|||REPLACE|||80|||3600
X-Custom-Header|||custom-value|||APPEND|||50|||7200</pre>
              </div>

              <Divider />

              <div class="format-type">
                <div class="font-semibold text-primary mb-2">📋 JSON格式 (.json)</div>
                <pre class="example-code">[
  {
    "header_name": "Authorization",
    "header_value": "Bearer token",
    "replace_strategy": "REPLACE",
    "priority": 80,
    "ttl": 3600
  }
]</pre>
              </div>
            </div>
          </div>
        </template>
      </Card>

      <!-- 文件选择区域 -->
      <Card class="input-card mb-4">
        <template #title>
          <div class="flex align-items-center gap-2">
            <i class="pi pi-upload text-primary"></i>
            <span>选择文件</span>
          </div>
        </template>
        <template #content>
          <div class="file-upload-area">
            <div 
              class="drop-zone" 
              :class="{ 'drag-over': isDragOver }"
              @dragover.prevent="isDragOver = true"
              @dragleave="isDragOver = false"
              @drop.prevent="handleDrop"
            >
              <input 
                ref="fileInputRef"
                type="file" 
                accept=".txt,.json"
                class="hidden-input"
                @change="handleFileSelect"
              />
              <div class="drop-content" @click="triggerFileInput">
                <i class="pi pi-cloud-upload text-4xl text-color-secondary mb-3"></i>
                <div class="text-lg mb-2">拖放文件到此处或点击选择</div>
                <div class="text-color-secondary">支持 .txt 或 .json 文件</div>
              </div>
            </div>
            
            <div v-if="selectedFile" class="selected-file mt-3">
              <div class="flex align-items-center gap-3">
                <i :class="fileIcon" class="text-2xl"></i>
                <div class="flex-grow-1">
                  <div class="font-semibold">{{ selectedFile.name }}</div>
                  <small class="text-color-secondary">{{ formatFileSize(selectedFile.size) }}</small>
                </div>
                <Button
                  icon="pi pi-times"
                  severity="secondary"
                  text
                  rounded
                  @click="clearFile"
                />
              </div>
            </div>
          </div>
        </template>
      </Card>

      <!-- 文件预览 -->
      <Card v-if="fileContent" class="preview-card mb-4">
        <template #title>
          <div class="flex align-items-center gap-2">
            <i class="pi pi-eye text-primary"></i>
            <span>文件内容预览</span>
          </div>
        </template>
        <template #content>
          <pre class="file-preview">{{ truncatedContent }}</pre>
          <small v-if="isContentTruncated" class="text-color-secondary">
            ...内容已截断，共 {{ fileContent.length }} 字符
          </small>
        </template>
      </Card>

      <!-- 作用域配置 -->
      <ScopeConfigPanel
        v-model="localScope"
        :title="'作用域配置（可选）'"
        :description="'为文件中未指定scope的Header统一设置作用域'"
        :show-templates="true"
        :show-info="true"
        :show-advanced="false"
      />
    </div>

    <template #footer>
      <Button
        label="取消"
        icon="pi pi-times"
        severity="secondary"
        @click="visible = false"
      />
      <Button
        label="导入"
        icon="pi pi-check"
        @click="handleImport"
        :disabled="!selectedFile"
        :loading="loading"
      />
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import ScopeConfigPanel from '../ScopeConfigPanel.vue'
import type { HeaderScope } from '@/types/headerRule'

const props = defineProps<{
  modelValue: boolean
  loading?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'import', file: File, scope: HeaderScope | null): void
  (e: 'download-text-template'): void
  (e: 'download-json-template'): void
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
})

const fileInputRef = ref<HTMLInputElement | null>(null)
const selectedFile = ref<File | null>(null)
const fileContent = ref('')
const isDragOver = ref(false)
const localScope = ref<HeaderScope | null>(null)

const MAX_PREVIEW_LENGTH = 2000

const fileIcon = computed(() => {
  if (!selectedFile.value) return 'pi pi-file'
  return selectedFile.value.name.endsWith('.json') 
    ? 'pi pi-file text-blue-500' 
    : 'pi pi-file-edit text-green-500'
})

const truncatedContent = computed(() => {
  if (fileContent.value.length <= MAX_PREVIEW_LENGTH) {
    return fileContent.value
  }
  return fileContent.value.slice(0, MAX_PREVIEW_LENGTH)
})

const isContentTruncated = computed(() => {
  return fileContent.value.length > MAX_PREVIEW_LENGTH
})

watch(visible, (newVal) => {
  if (newVal) {
    clearFile()
    localScope.value = null
  }
})

function triggerFileInput() {
  fileInputRef.value?.click()
}

function handleFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) {
    processFile(file)
  }
}

function handleDrop(event: DragEvent) {
  isDragOver.value = false
  const file = event.dataTransfer?.files?.[0]
  if (file) {
    processFile(file)
  }
}

function processFile(file: File) {
  const validExtensions = ['.txt', '.json']
  const isValid = validExtensions.some(ext => file.name.toLowerCase().endsWith(ext))
  
  if (!isValid) {
    return
  }
  
  selectedFile.value = file
  
  const reader = new FileReader()
  reader.onload = (e) => {
    fileContent.value = e.target?.result as string || ''
  }
  reader.readAsText(file)
}

function clearFile() {
  selectedFile.value = null
  fileContent.value = ''
  if (fileInputRef.value) {
    fileInputRef.value.value = ''
  }
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function handleImport() {
  if (selectedFile.value) {
    emit('import', selectedFile.value, localScope.value)
  }
}
</script>

<style scoped lang="scss">
.drop-zone {
  border: 2px dashed var(--surface-border);
  border-radius: 8px;
  padding: 2rem;
  text-align: center;
  transition: all 0.3s ease;
  cursor: pointer;
  
  &:hover, &.drag-over {
    border-color: var(--primary-color);
    background: var(--primary-50);
  }
}

.hidden-input {
  display: none;
}

.selected-file {
  background: var(--surface-ground);
  border-radius: 8px;
  padding: 1rem;
}

.file-preview {
  background: var(--surface-ground);
  border-radius: 6px;
  padding: 1rem;
  font-size: 0.85rem;
  max-height: 200px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.dialog-content {
  padding: 1.5rem;
  
  .info-card {
    margin-bottom: 1.5rem;
    
    :deep(.p-card-content) {
      padding: 1rem 1.25rem;
    }
    
    .format-description {
      .format-types {
        .format-type {
          .format-pattern {
            code {
              background: var(--blue-50);
              color: var(--blue-700);
              padding: 0.375rem 0.75rem;
              border-radius: 4px;
              font-family: 'Consolas', 'Monaco', monospace;
              font-size: 0.9rem;
              display: inline-block;
            }
          }
          
          .example-code {
            background: var(--surface-50);
            border: 1px solid var(--surface-200);
            border-radius: 6px;
            padding: 1rem;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre;
            margin: 0.5rem 0;
          }
        }
      }
    }
  }
  
  .input-card, .preview-card {
    margin-bottom: 1.5rem;
    
    :deep(.p-card-content) {
      padding: 1rem 1.25rem;
    }
  }
}
</style>
