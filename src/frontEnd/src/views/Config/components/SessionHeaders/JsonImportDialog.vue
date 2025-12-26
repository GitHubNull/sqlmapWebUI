<template>
  <Dialog
    v-model:visible="visible"
    header="JSON导入Session Headers"
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
              <i class="pi pi-code text-primary"></i>
              <span>JSON导入格式说明</span>
            </div>
            <Button
              label="下载模板"
              icon="pi pi-download"
              severity="secondary"
              size="small"
              outlined
              @click="$emit('download-template')"
            />
          </div>
        </template>
        <template #content>
          <div class="format-description">
            <Message severity="info" :closable="false" class="mb-3">
              <div class="format-info">
                <div class="mb-2"><strong>JSON格式，对象数组</strong></div>
              </div>
            </Message>

            <div class="field-description mb-3">
              <div class="font-semibold mb-2">字段说明：</div>
              <ul class="m-0 pl-4">
                <li><strong>header_name</strong>：必填，字符串，Header名称</li>
                <li><strong>header_value</strong>：必填，字符串，Header值</li>
                <li><strong>replace_strategy</strong>：可选，字符串，可选值：<code>REPLACE</code>、<code>APPEND</code>、<code>PREPEND</code>、<code>UPSERT</code>，默认<code>REPLACE</code></li>
                <li><strong>priority</strong>：可选，数字，0-100，默认50</li>
                <li><strong>ttl</strong>：可选，数字，生存时间(秒)，默认3600</li>
                <li><strong>is_active</strong>：可选，布尔值，是否启用，默认true</li>
              </ul>
            </div>

            <div class="example-section">
              <div class="font-semibold mb-2">示例：</div>
              <pre class="example-code">[
  {
    "header_name": "Authorization",
    "header_value": "Bearer eyJhbGciOiJIUzI1NiJ9...",
    "replace_strategy": "REPLACE",
    "priority": 80,
    "ttl": 3600
  },
  {
    "header_name": "Cookie",
    "header_value": "session_id=abc123",
    "replace_strategy": "UPSERT",
    "priority": 50
  },
  {
    "header_name": "X-API-Key",
    "header_value": "your-api-key"
  }
]</pre>
              <small class="text-color-secondary">未指定的可选字段将使用默认值</small>
            </div>
          </div>
        </template>
      </Card>

      <!-- JSON输入区域卡片 -->
      <Card class="input-card mb-4">
        <template #title>
          <div class="flex align-items-center gap-2">
            <i class="pi pi-code text-primary"></i>
            <span>JSON数据</span>
          </div>
        </template>
        <template #content>
          <div class="input-area">
            <Textarea
              v-model="localContent"
              rows="12"
              class="uniform-textarea"
              :placeholder="placeholder"
            />
            <div class="input-stats mt-2">
              <small class="text-color-secondary">JSON数据长度: {{ localContent.length }} 字符</small>
            </div>
          </div>
        </template>
      </Card>

      <!-- 作用域配置 -->
      <ScopeConfigPanel
        v-model="localScope"
        :title="'作用域配置（可选）'"
        :description="'为JSON中未指定scope的Header统一设置作用域'"
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
        :loading="loading"
      />
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import ScopeConfigPanel from '../ScopeConfigPanel.vue'
import type { HeaderScope } from '@/types/headerRule'
import { JSON_PLACEHOLDER } from './constants'

const props = defineProps<{
  modelValue: boolean
  loading?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'import', content: string, scope: HeaderScope | null): void
  (e: 'download-template'): void
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
})

const localContent = ref('')
const localScope = ref<HeaderScope | null>(null)
const placeholder = JSON_PLACEHOLDER

watch(visible, (newVal) => {
  if (newVal) {
    localContent.value = ''
    localScope.value = null
  }
})

function handleImport() {
  emit('import', localContent.value, localScope.value)
}
</script>

<style scoped lang="scss">
.dialog-content {
  padding: 1.5rem;
  
  .info-card {
    margin-bottom: 1.5rem;
    
    :deep(.p-card-content) {
      padding: 1rem 1.25rem;
    }
    
    .format-description {
      .field-description {
        ul {
          margin: 0.5rem 0;
          li {
            margin-bottom: 0.5rem;
            line-height: 1.6;
            code {
              background: var(--surface-100);
              padding: 0.125rem 0.375rem;
              border-radius: 3px;
              font-family: 'Consolas', 'Monaco', monospace;
              font-size: 0.85rem;
            }
          }
        }
      }
      
      .example-section {
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
  
  .input-card {
    margin-bottom: 1.5rem;
    
    :deep(.p-card-content) {
      padding: 1rem 1.25rem;
    }
    
    .input-area {
      :deep(.p-textarea) {
        width: 100%;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.9rem;
        line-height: 1.6;
      }
      
      .input-stats {
        margin-top: 0.5rem;
      }
    }
  }
}
</style>
