<template>
  <div class="scope-config-panel">
    <Card class="scope-card">
      <template #title>
        <div class="flex align-items-center gap-2 w-full cursor-pointer">
          <Checkbox
            ref="hasScopeCheckboxRef"
            inputId="has_scope"
            v-model="hasScope"
            :binary="true"
          />
          <i class="pi pi-filter text-primary"></i>
          <label for="has_scope" class="cursor-pointer m-0" @click="handleScopeToggle">{{ title }}</label>
          <div class="scope-info" v-if="showInfo" @click.stop>
            <Button
              icon="pi pi-info-circle"
              text
              rounded
              severity="info"
              @click="showHelpDialog = true"
              v-tooltip.top="'查看帮助信息'"
            />
          </div>
        </div>
      </template>
      <template #content>
        <Message v-if="hasScope" severity="info" :closable="false" class="mb-3">
          <div class="flex align-items-center gap-2">
            <i class="pi pi-info-circle"></i>
            <span>{{ scopeDescription }}</span>
          </div>
        </Message>

        <Fieldset v-if="hasScope" legend="作用域规则配置" class="scope-fieldset">
          <div class="formgrid grid p-fluid">
            <!-- 协议匹配 -->
            <div class="field col-12 md:col-6 mb-3">
              <FloatLabel>
                <InputText
                  id="protocol_pattern"
                  v-model="scopeData.protocol_pattern"
                  :invalid="!!validationErrors.protocol_pattern"
                />
                <label for="protocol_pattern">
                  <i class="pi pi-globe mr-2"></i>
                  协议匹配
                </label>
              </FloatLabel>
              <small class="text-color-secondary mt-1">例如: https 或 http,https（多个用逗号分隔）</small>
              <InlineMessage v-if="validationErrors.protocol_pattern" severity="error" class="mt-1">
                {{ validationErrors.protocol_pattern }}
              </InlineMessage>
            </div>

            <!-- 主机名匹配 -->
            <div class="field col-12 md:col-6 mb-3">
              <FloatLabel>
                <InputText
                  id="host_pattern"
                  v-model="scopeData.host_pattern"
                  :invalid="!!validationErrors.host_pattern"
                />
                <label for="host_pattern">
                  <i class="pi pi-server mr-2"></i>
                  主机名匹配
                </label>
              </FloatLabel>
              <small class="text-color-secondary mt-1">例如: *.example.com（支持通配符*）</small>
              <InlineMessage v-if="validationErrors.host_pattern" severity="error" class="mt-1">
                {{ validationErrors.host_pattern }}
              </InlineMessage>
            </div>

            <!-- 路径匹配 -->
            <div class="field col-12 md:col-6 mb-3">
              <FloatLabel>
                <InputText
                  id="path_pattern"
                  v-model="scopeData.path_pattern"
                  :invalid="!!validationErrors.path_pattern"
                />
                <label for="path_pattern">
                  <i class="pi pi-link mr-2"></i>
                  路径匹配
                </label>
              </FloatLabel>
              <small class="text-color-secondary mt-1">例如: /api/*（支持通配符*）</small>
              <InlineMessage v-if="validationErrors.path_pattern" severity="error" class="mt-1">
                {{ validationErrors.path_pattern }}
              </InlineMessage>
            </div>

            <!-- 端口匹配 -->
            <div class="field col-12 md:col-6 mb-3" v-if="showAdvanced">
              <FloatLabel>
                <InputText
                  id="port_pattern"
                  v-model="scopeData.port_pattern"
                  :invalid="!!validationErrors.port_pattern"
                />
                <label for="port_pattern">
                  <i class="pi pi-hashtag mr-2"></i>
                  端口匹配
                </label>
              </FloatLabel>
              <small class="text-color-secondary mt-1">例如: 80,443,8080（多个用逗号分隔）</small>
              <InlineMessage v-if="validationErrors.port_pattern" severity="error" class="mt-1">
                {{ validationErrors.port_pattern }}
              </InlineMessage>
            </div>

            <!-- IP地址匹配 -->
            <div class="field col-12 md:col-6 mb-3" v-if="showAdvanced">
              <FloatLabel>
                <InputText
                  id="ip_pattern"
                  v-model="scopeData.ip_pattern"
                  :invalid="!!validationErrors.ip_pattern"
                />
                <label for="ip_pattern">
                  <i class="pi pi-map-marker mr-2"></i>
                  IP地址匹配
                </label>
              </FloatLabel>
              <small class="text-color-secondary mt-1">例如: 192.168.1.*（支持通配符*）</small>
              <InlineMessage v-if="validationErrors.ip_pattern" severity="error" class="mt-1">
                {{ validationErrors.ip_pattern }}
              </InlineMessage>
            </div>

            <!-- 高级选项 -->
            <div class="field col-12 mb-0">
              <div class="flex align-items-center justify-content-between">
                <div class="flex align-items-center gap-2">
                  <Checkbox
                    ref="useRegexCheckboxRef"
                    inputId="use_regex"
                    v-model="scopeData.use_regex"
                    :binary="true"
                  />
                  <label for="use_regex" class="font-medium cursor-pointer m-0">
                    <i class="pi pi-code mr-2 text-primary"></i>
                    使用正则表达式匹配
                  </label>
                </div>
                <Button
                  v-if="!showAdvanced"
                  label="高级选项"
                  icon="pi pi-chevron-down"
                  text
                  severity="info"
                  @click="showAdvanced = true"
                  size="small"
                />
                <Button
                  v-else
                  label="高级选项"
                  icon="pi pi-chevron-up"
                  text
                  severity="info"
                  @click="showAdvanced = false"
                  size="small"
                />
              </div>
              <small class="text-color-secondary ml-6">启用后上述模式将作为正则表达式解析</small>
            </div>
          </div>

          <Divider class="my-4" />

          <!-- 预设模板 -->
          <div class="template-section" v-if="showTemplates">
            <div class="flex align-items-center justify-content-between mb-3">
              <h5 class="mb-0">
                <i class="pi pi-bookmark mr-2"></i>
                预设模板
              </h5>
              <Button
                v-if="!showTemplateSelector"
                label="选择模板"
                icon="pi pi-chevron-down"
                text
                severity="info"
                @click="showTemplateSelector = true"
                size="small"
              />
              <Button
                v-else
                label="选择模板"
                icon="pi pi-chevron-up"
                text
                severity="info"
                @click="showTemplateSelector = false"
                size="small"
              />
            </div>

            <div v-if="showTemplateSelector" class="template-selector">
              <div class="template-grid">
                <div
                  v-for="template in scopeTemplates"
                  :key="template.name"
                  class="template-item"
                  :class="{ active: isTemplateActive(template) }"
                  @click="applyTemplate(template)"
                >
                  <div class="template-header">
                    <h6 class="mb-1">{{ template.name }}</h6>
                    <small class="text-color-secondary">{{ template.description }}</small>
                  </div>
                  <div class="template-preview">
                    <div v-if="template.scope.protocol_pattern" class="preview-item">
                      <i class="pi pi-globe mr-1"></i>
                      <span>{{ template.scope.protocol_pattern }}</span>
                    </div>
                    <div v-if="template.scope.host_pattern" class="preview-item">
                      <i class="pi pi-server mr-1"></i>
                      <span>{{ template.scope.host_pattern }}</span>
                    </div>
                    <div v-if="template.scope.path_pattern" class="preview-item">
                      <i class="pi pi-link mr-1"></i>
                      <span>{{ template.scope.path_pattern }}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 匹配示例 -->
          <Message severity="success" :closable="false" class="examples-message">
            <div class="font-semibold mb-3 flex align-items-center gap-2">
              <i class="pi pi-lightbulb"></i>
              <span>匹配示例</span>
            </div>
            <div class="grid">
              <div class="col-12 md:col-6">
                <ul class="examples-list">
                  <li><strong>全局生效：</strong>不勾选"{{ title }}"</li>
                  <li><strong>仅HTTPS：</strong>协议=https</li>
                  <li><strong>特定域名：</strong>主机名=api.example.com</li>
                </ul>
              </div>
              <div class="col-12 md:col-6">
                <ul class="examples-list">
                  <li><strong>所有子域名：</strong>主机名=*.example.com</li>
                  <li><strong>API路径：</strong>路径=/api/*</li>
                  <li><strong>正则匹配：</strong>路径=^/v[0-9]+/.*</li>
                </ul>
              </div>
            </div>
          </Message>
        </Fieldset>
      </template>
    </Card>

    <!-- 帮助对话框 -->
    <Dialog
      v-model:visible="showHelpDialog"
      header="作用域配置帮助"
      :style="{ width: '700px' }"
      modal
    >
      <div class="help-content">
        <Message severity="info" :closable="false" class="mb-3">
          <div class="flex align-items-center gap-2">
            <i class="pi pi-info-circle"></i>
            <span>作用域配置用于限定Header规则的生效范围，支持多维度组合匹配</span>
          </div>
        </Message>

        <div class="help-sections">
          <div class="help-section">
            <h5><i class="pi pi-globe mr-2"></i>协议匹配</h5>
            <p>限定请求协议类型，支持单个或多个协议：</p>
            <ul>
              <li><code>https</code> - 仅HTTPS协议</li>
              <li><code>http,https</code> - HTTP和HTTPS协议</li>
            </ul>
          </div>

          <div class="help-section">
            <h5><i class="pi pi-server mr-2"></i>主机名匹配</h5>
            <p>限定请求的目标主机名，支持通配符：</p>
            <ul>
              <li><code>api.example.com</code> - 精确匹配</li>
              <li><code>*.example.com</code> - 匹配所有子域名</li>
              <li><code>*.api.*</code> - 多级通配符</li>
            </ul>
          </div>

          <div class="help-section">
            <h5><i class="pi pi-link mr-2"></i>路径匹配</h5>
            <p>限定请求的URL路径，支持通配符：</p>
            <ul>
              <li><code>/api/users</code> - 精确匹配</li>
              <li><code>/api/*</code> - 匹配/api/下所有路径</li>
              <li><code>*/v1/*</code> - 多级通配符</li>
            </ul>
          </div>

          <div class="help-section">
            <h5><i class="pi pi-code mr-2"></i>正则表达式</h5>
            <p>启用后支持完整的正则表达式语法：</p>
            <ul>
              <li><code>^/api/v[0-9]+/.*</code> - 匹配API版本路径</li>
              <li><code>.*\\.(jpg|png|gif)$</code> - 匹配图片文件</li>
            </ul>
          </div>
        </div>
      </div>

      <template #footer>
        <Button
          label="关闭"
          icon="pi pi-times"
          severity="secondary"
          @click="showHelpDialog = false"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch, nextTick } from 'vue'
import type { HeaderScope } from '@/types/headerRule'

const props = defineProps<{
  modelValue: HeaderScope | null
  title?: string
  description?: string
  showTemplates?: boolean
  showInfo?: boolean
  showAdvanced?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [scope: HeaderScope | null]
  'change': [scope: HeaderScope | null]
}>()

// 状态
const hasScope = ref(false)
const showAdvanced = ref(props.showAdvanced || false)
const showTemplateSelector = ref(false)
const showHelpDialog = ref(false)
const hasScopeCheckboxRef = ref<InstanceType<any>>()
const useRegexCheckboxRef = ref<InstanceType<any>>()

const scopeData = reactive<HeaderScope>({
  protocol_pattern: '',
  host_pattern: '',
  path_pattern: '',
  port_pattern: '',
  ip_pattern: '',
  use_regex: false,
})

// 监听hasScope变化
watch(hasScope, async (newValue) => {
  await nextTick()
  if (hasScopeCheckboxRef.value?.$el) {
    const checkboxBox = hasScopeCheckboxRef.value.$el.querySelector('.p-checkbox-box')
    if (checkboxBox) {
      if (newValue) {
        checkboxBox.classList.add('p-highlight')
      } else {
        checkboxBox.classList.remove('p-highlight')
      }
    }
  }
})

// 监听use_regex变化
watch(() => scopeData.use_regex, async (newValue) => {
  await nextTick()
  if (useRegexCheckboxRef.value?.$el) {
    const checkboxBox = useRegexCheckboxRef.value.$el.querySelector('.p-checkbox-box')
    if (checkboxBox) {
      if (newValue) {
        checkboxBox.classList.add('p-highlight')
      } else {
        checkboxBox.classList.remove('p-highlight')
      }
    }
  }
})

// 验证错误
const validationErrors = reactive<Record<string, string>>({
  protocol_pattern: '',
  host_pattern: '',
  path_pattern: '',
  port_pattern: '',
  ip_pattern: '',
})

// 预设模板数据
const scopeTemplatesData = [
  {
    name: '开发环境',
    description: '本地开发服务器',
    scope: {
      host_pattern: 'localhost,127.0.0.1',
      protocol_pattern: 'http'
    }
  },
  {
    name: '测试环境',
    description: '测试服务器',
    scope: {
      host_pattern: '*.test.com,*.testing.com',
      protocol_pattern: 'https'
    }
  },
  {
    name: 'API服务',
    description: 'API接口服务',
    scope: {
      path_pattern: '/api/*',
      protocol_pattern: 'https'
    }
  },
  {
    name: 'HTTPS限定',
    description: '仅HTTPS协议',
    scope: {
      protocol_pattern: 'https'
    }
  },
  {
    name: '图片资源',
    description: '图片文件请求',
    scope: {
      path_pattern: '*/images/*,*.jpg,*.png,*.gif',
      use_regex: true
    }
  },
  {
    name: '前后端分离',
    description: '前端调用后端API',
    scope: {
      host_pattern: 'api.*',
      path_pattern: '/api/*',
      protocol_pattern: 'https'
    }
  }
]

// 默认值
const defaultTitle = '配置作用域（可选）'
const defaultDescription = '不勾选则对所有请求全局生效。作用域支持协议、主机名、路径等多维度过滤。'

// 计算属性
const title = computed(() => props.title || defaultTitle)
const scopeDescription = computed(() => props.description || defaultDescription)
const scopeTemplates = computed(() => scopeTemplatesData)
const showTemplates = computed(() => props.showTemplates || false)

// 监听modelValue变化
watch(() => props.modelValue, (newValue) => {
  hasScope.value = !!newValue
  if (newValue) {
    Object.assign(scopeData, newValue)
  } else {
    resetScopeData()
  }
}, { immediate: true })

// 监听scope数据变化
watch([scopeData, hasScope], () => {
  if (hasScope.value) {
    const scope = { ...scopeData }
    // 移除空值
    Object.keys(scope).forEach(key => {
      if (scope[key as keyof HeaderScope] === '') {
        delete scope[key as keyof HeaderScope]
      }
    })
    emit('update:modelValue', scope)
    emit('change', scope)
  } else {
    emit('update:modelValue', null)
    emit('change', null)
  }
}, { deep: true })

// 重置作用域数据
function resetScopeData() {
  Object.assign(scopeData, {
    protocol_pattern: '',
    host_pattern: '',
    path_pattern: '',
    port_pattern: '',
    ip_pattern: '',
    use_regex: false,
  })
}

// 处理作用域切换
function handleScopeToggle() {
  if (!hasScope.value) {
    // 清除作用域数据
    resetScopeData()
    clearValidationErrors()
  }
}

// 清除验证错误
function clearValidationErrors() {
  Object.keys(validationErrors).forEach(key => {
    validationErrors[key] = ''
  })
}

// 验证作用域配置
function validateScope(): boolean {
  clearValidationErrors()
  let isValid = true

  // 验证协议格式
  if (scopeData.protocol_pattern) {
    const protocols = scopeData.protocol_pattern.split(',').map(p => p.trim())
    const validProtocols = ['http', 'https', 'ws', 'wss']
    const invalidProtocols = protocols.filter(p => !validProtocols.includes(p))
    if (invalidProtocols.length > 0) {
      validationErrors.protocol_pattern = `无效协议: ${invalidProtocols.join(', ')}`
      isValid = false
    }
  }

  // 验证端口格式
  if (scopeData.port_pattern) {
    const ports = scopeData.port_pattern.split(',').map(p => p.trim())
    const invalidPorts = ports.filter(p => {
      const port = parseInt(p)
      return isNaN(port) || port < 1 || port > 65535
    })
    if (invalidPorts.length > 0) {
      validationErrors.port_pattern = `无效端口: ${invalidPorts.join(', ')}`
      isValid = false
    }
  }

  // 验证正则表达式
  if (scopeData.use_regex) {
    const patterns = ['host_pattern', 'path_pattern', 'protocol_pattern', 'port_pattern', 'ip_pattern']
    patterns.forEach(pattern => {
      const value = scopeData[pattern as keyof HeaderScope]
      if (value && typeof value === 'string') {
        try {
          new RegExp(value)
        } catch (error) {
          validationErrors[pattern] = '正则表达式格式错误'
          isValid = false
        }
      }
    })
  }

  return isValid
}

// 检查模板是否激活
function isTemplateActive(template: any): boolean {
  return JSON.stringify(template.scope) === JSON.stringify(getNonEmptyScope())
}

// 获取非空的作用域配置
function getNonEmptyScope() {
  const scope = { ...scopeData }
  Object.keys(scope).forEach(key => {
    if (scope[key as keyof HeaderScope] === '') {
      delete scope[key as keyof HeaderScope]
    }
  })
  return scope
}

// 应用模板
function applyTemplate(template: any) {
  Object.assign(scopeData, {
    protocol_pattern: '',
    host_pattern: '',
    path_pattern: '',
    port_pattern: '',
    ip_pattern: '',
    use_regex: false,
    ...template.scope
  })
}

// 暴露验证方法
defineExpose({
  validateScope
})
</script>

<style scoped lang="scss">
.scope-config-panel {
  .scope-card {
    :deep(.p-card-title) {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--primary-color);
      margin-bottom: 1rem;
    }

    :deep(.p-card-content) {
      padding-top: 0;
    }

    .scope-info {
      margin-left: auto;
    }
  }

  .scope-fieldset {
    :deep(.p-fieldset-legend) {
      font-weight: 600;
      color: var(--text-color);
      background: var(--surface-card);
      border: 1px solid var(--surface-border);
      border-radius: 6px;
      padding: 0.5rem 1rem;
    }
  }

  // 模板选择器样式
  .template-section {
    .template-selector {
      .template-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 1rem;

        .template-item {
          border: 2px solid var(--surface-border);
          border-radius: 8px;
          padding: 1rem;
          cursor: pointer;
          transition: all 0.2s ease;

          &:hover {
            border-color: var(--primary-color);
            background: var(--primary-50);
          }

          &.active {
            border-color: var(--primary-color);
            background: linear-gradient(135deg, var(--primary-50) 0%, var(--primary-100) 100%);
          }

          .template-header {
            margin-bottom: 0.5rem;

            h6 {
              margin: 0;
              color: var(--text-color);
              font-weight: 600;
            }

            small {
              color: var(--text-color-secondary);
            }
          }

          .template-preview {
            .preview-item {
              display: flex;
              align-items: center;
              gap: 0.5rem;
              padding: 0.25rem 0;
              font-size: 0.9rem;
              color: var(--text-color-secondary);

              i {
                color: var(--primary-color);
              }
            }
          }
        }
      }
    }
  }

  // 示例消息样式
  .examples-message {
    :deep(.p-message-wrapper) {
      background: linear-gradient(135deg,
        var(--green-50) 0%,
        var(--green-100) 100%);
      border-left: 4px solid var(--green-500);
    }

    .examples-list {
      list-style: none;
      padding-left: 0;
      margin: 0;

      li {
        padding: 0.25rem 0;
        line-height: 1.5;

        &:not(:last-child) {
          border-bottom: 1px solid var(--green-200);
        }
      }
    }
  }

  // 帮助内容样式
  .help-content {
    padding: 1rem;

    .help-sections {
      .help-section {
        margin-bottom: 1.5rem;

        h5 {
          margin: 0 0 0.5rem 0;
          color: var(--text-color);
          font-weight: 600;

          i {
            color: var(--primary-color);
          }
        }

        p {
          margin: 0 0 0.5rem 0;
          color: var(--text-color-secondary);
        }

        ul {
          margin: 0;
          padding-left: 1.5rem;

          li {
            margin-bottom: 0.25rem;
            color: var(--text-color-secondary);

            code {
              background: var(--primary-50);
              color: var(--primary-700);
              padding: 0.125rem 0.25rem;
              border-radius: 3px;
              font-family: monospace;
              font-size: 0.85em;
            }
          }
        }
      }
    }
  }

  // 浮动标签优化
  :deep(.p-float-label) {
    margin-bottom: 0.5rem;

    label {
      font-weight: 500;
      color: var(--text-color-secondary);

      i {
        color: var(--primary-color);
      }
    }
  }

  // 输入组件样式
  :deep(.p-inputtext) {
    border-radius: 8px;
    border: 2px solid var(--surface-border);
    transition: all 0.2s ease;

    &:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
    }

    &.p-invalid {
      border-color: var(--red-500);
      box-shadow: 0 0 0 3px rgba(var(--red-500-rgb), 0.1);
    }
  }

  // 复选框样式
  // 复选框样式
  :deep(.p-checkbox) {
    .p-checkbox-box {
      border-radius: 4px;
      border: 2px solid var(--surface-border);
      transition: all 0.2s ease;

      &.p-highlight {
        background: var(--primary-color);
        border-color: var(--primary-color);

        // 修复：确保SVG图标显示
        .p-checkbox-icon {
          display: inline-flex !important;
          color: white !important;
          width: 14px !important;
          height: 14px !important;
        }
      }
    }
  }

  // 消息组件样式
  :deep(.p-message) {
    border-radius: 8px;
    border: none;
    margin: 0;

    .p-message-wrapper {
      border-radius: 8px;
      padding: 1rem;
    }

    &.p-message-info .p-message-wrapper {
      background: linear-gradient(135deg,
        var(--blue-50) 0%,
        var(--blue-100) 100%);
      border-left: 4px solid var(--blue-500);
    }
  }

  // 内联消息样式
  :deep(.p-inline-message) {
    margin-top: 0.25rem;
    font-size: 0.85rem;
  }

  // 分隔线样式
  :deep(.p-divider) {
    margin: 1.5rem 0;

    &.my-4 {
      margin: 1.5rem 0;
    }
  }
}
</style>