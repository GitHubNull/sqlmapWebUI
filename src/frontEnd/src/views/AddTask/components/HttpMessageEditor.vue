<template>
  <div class="editor-section">
    <div class="section-header">
      <span>HTTP报文编辑</span>
      <Tag severity="info" v-tooltip="'在参数值中添加 * 标记注入点'">
        <i class="pi pi-info-circle"></i> 使用 * 标记注入点
      </Tag>
    </div>
    <HttpCodeEditor
      :modelValue="modelValue"
      @update:modelValue="$emit('update:modelValue', $event)"
      :placeholder="placeholder || defaultPlaceholder"
      min-height="120px"
      max-height="260px"
    />
    <div class="editor-status" v-if="parsedRequest">
      <span class="status-item">
        <i class="pi pi-globe"></i>
        {{ parsedRequest.method }} {{ parsedRequest.host }}
      </span>
      <span class="status-item">
        <i class="pi pi-link"></i>
        {{ parsedRequest.path }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import Tag from 'primevue/tag'
import HttpCodeEditor from '@/components/HttpCodeEditor.vue'
import type { ParsedHttpRequest } from '@/utils/httpRequestParser'

interface Props {
  modelValue: string
  parsedRequest: ParsedHttpRequest | null
  placeholder?: string
}

defineProps<Props>()

defineEmits<{
  'update:modelValue': [value: string]
}>()

const defaultPlaceholder = `转换后的HTTP报文将显示在这里...

您可以直接编辑报文内容
使用 * 标记注入点，例如：
GET /api/user?id=1* HTTP/1.1`
</script>

<style scoped>
.editor-section {
  margin-bottom: 1rem;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
  font-weight: 600;
  font-size: 0.95rem;
  color: var(--text-color);
}

.editor-status {
  display: flex;
  gap: 1rem;
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--surface-border);
}

.status-item {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}
</style>
