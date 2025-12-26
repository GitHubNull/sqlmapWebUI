<template>
  <Dialog
    v-model:visible="visible"
    header="文本导入Session Headers"
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
              <i class="pi pi-file-edit text-primary"></i>
              <span>文本导入格式说明</span>
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
                <div class="mb-2"><strong>每行一个Header，字段使用 <code>|||</code> 分隔</strong></div>
                <div class="format-pattern">
                  <code>Header名称|||Header值|||替换策略|||优先级|||TTL(秒)</code>
                </div>
              </div>
            </Message>

            <div class="field-description mb-3">
              <div class="font-semibold mb-2">字段说明：</div>
              <ul class="m-0 pl-4">
                <li><strong>Header名称</strong>：必填，如 <code>Authorization</code>、<code>Cookie</code></li>
                <li><strong>Header值</strong>：必填，如 <code>Bearer token123</code></li>
                <li><strong>替换策略</strong>：可选，默认 <code>REPLACE</code>，可选值：<code>REPLACE</code>、<code>APPEND</code>、<code>PREPEND</code>、<code>UPSERT</code></li>
                <li><strong>优先级</strong>：可选，0-100，默认50</li>
                <li><strong>TTL</strong>：可选，生存时间(秒)，默认3600</li>
              </ul>
            </div>

            <div class="example-section">
              <div class="font-semibold mb-2">示例：</div>
              <pre class="example-code">Authorization|||Bearer eyJhbGciOiJIUzI1NiJ9...|||REPLACE|||80|||3600
Cookie|||session_id=abc123|||UPSERT|||50|||7200
X-Custom-Header|||custom-value|||APPEND|||60|||1800
X-API-Key|||your-api-key</pre>
              <small class="text-color-secondary">最后一行省略了可选字段，将使用默认值</small>
            </div>
          </div>
        </template>
      </Card>

      <!-- 文本输入区域卡片 -->
      <Card class="input-card mb-4">
        <template #title>
          <div class="flex align-items-center gap-2">
            <i class="pi pi-list text-primary"></i>
            <span>Header列表</span>
          </div>
        </template>
        <template #content>
          <div class="input-area">
            <Textarea
              v-model="localContent"
              rows="12"
              class="uniform-textarea"
              placeholder="Authorization|||Bearer your-token-here|||REPLACE|||80|||3600
Cookie|||session_id=abc123|||UPSERT|||50|||7200
X-Custom-Header|||custom-value|||APPEND|||60|||1800"
            />
            <div class="input-stats mt-2">
              <small class="text-color-secondary">输入行数: {{ lineCount }}</small>
            </div>
          </div>
        </template>
      </Card>

      <!-- 作用域配置 -->
      <ScopeConfigPanel
        v-model="localScope"
        :title="'作用域配置（可选）'"
        :description="'为导入的Header统一设置作用域，不配置则对所有请求生效'"
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

const lineCount = computed(() => {
  return localContent.value.split('\n').filter(line => line.trim()).length
})

// 重置内容当对话框打开
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
      .format-info {
        .format-pattern {
          margin-top: 0.5rem;
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
      }
      
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
