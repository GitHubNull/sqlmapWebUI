<template>
  <div class="input-section">
    <div class="section-header">
      <span>报文输入</span>
      <div class="format-indicator" v-if="detectedFormat !== 'unknown'">
        <Tag :severity="formatSeverity">{{ formatDisplayName }}</Tag>
      </div>
    </div>
    <HttpCodeEditor
      :modelValue="modelValue"
      @update:modelValue="$emit('update:modelValue', $event)"
      :placeholder="placeholder || defaultPlaceholder"
      min-height="120px"
      max-height="260px"
      @change="onInputChange"
    />
    <div class="input-actions">
      <Button 
        label="解析转换" 
        icon="pi pi-sync" 
        @click="parseInput"
        :disabled="!modelValue.trim()"
      />
      <Button 
        label="清空" 
        icon="pi pi-trash" 
        severity="secondary"
        @click="handleClear"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import HttpCodeEditor from '@/components/HttpCodeEditor.vue'
import { 
  parseHttpRequest, 
  detectFormat, 
  getFormatDisplayName,
  type ParsedHttpRequest,
  type RequestFormat
} from '@/utils/httpRequestParser'

interface Props {
  modelValue: string
  placeholder?: string
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'update:modelValue': [value: string]
  parse: [data: ParsedHttpRequest, rawHttp: string]
  parseError: [error: string]
  clear: []
}>()

// 内部状态
const detectedFormat = ref<RequestFormat>('unknown')

// 计算属性
const formatDisplayName = computed(() => getFormatDisplayName(detectedFormat.value))

const formatSeverity = computed(() => {
  switch (detectedFormat.value) {
    case 'curl_bash':
    case 'curl_cmd':
    case 'raw_http':
      return 'success'
    case 'powershell':
      return 'info'
    case 'fetch_js':
    case 'fetch_nodejs':
      return 'warn'
    default:
      return 'secondary'
  }
})

const defaultPlaceholder = `粘贴从Chrome DevTools复制的HTTP请求报文

支持的格式：
• cURL (bash/cmd)
• PowerShell (Invoke-WebRequest)
• fetch (JavaScript/Node.js)
• 原始HTTP报文

示例 (cURL):
curl 'https://example.com/api/user?id=1' \\
  -H 'Content-Type: application/json'`

// 方法
function onInputChange() {
  detectedFormat.value = detectFormat(props.modelValue)
}

function parseInput() {
  const result = parseHttpRequest(props.modelValue)
  
  if (result.success && result.data && result.rawHttp) {
    detectedFormat.value = result.format || 'unknown'
    emit('parse', result.data, result.rawHttp)
  } else {
    emit('parseError', result.error || '无法解析输入内容')
  }
}

function handleClear() {
  detectedFormat.value = 'unknown'
  emit('clear')
}

// 监听输入变化
watch(() => props.modelValue, () => {
  onInputChange()
})
</script>

<style scoped>
.input-section {
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

.input-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
}
</style>
