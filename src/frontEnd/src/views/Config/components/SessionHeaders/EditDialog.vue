<template>
  <Dialog
    v-model:visible="visible"
    :header="isAdd ? '添加Session Header' : '编辑Session Header'"
    :style="{
      width: '90vw',
      maxWidth: '700px',
      maxHeight: '85vh'
    }"
    modal
    class="session-dialog"
  >
    <div class="dialog-content">
      <!-- 基本信息 -->
      <Card class="mb-4">
        <template #title>
          <div class="flex align-items-center gap-2">
            <i class="pi pi-info-circle text-primary"></i>
            <span>基本信息</span>
          </div>
        </template>
        <template #content>
          <div class="form-grid">
            <div class="field">
              <label for="header_name" class="required-field">Header名称</label>
              <InputText
                id="header_name"
                v-model="localForm.header_name"
                class="w-full"
                placeholder="如: Authorization, X-Custom-Header"
              />
            </div>

            <div class="field">
              <label for="header_value" class="required-field">Header值</label>
              <Textarea
                id="header_value"
                v-model="localForm.header_value"
                rows="3"
                class="w-full"
                placeholder="Header的值"
              />
            </div>

            <div class="field-row">
              <div class="field">
                <label for="replace_strategy">替换策略</label>
                <Select
                  id="replace_strategy"
                  v-model="localForm.replace_strategy"
                  :options="replaceStrategyOptions"
                  optionLabel="label"
                  optionValue="value"
                  class="w-full"
                />
              </div>

              <div class="field">
                <label for="priority">优先级</label>
                <InputNumber
                  id="priority"
                  v-model="localForm.priority"
                  :min="0"
                  :max="100"
                  class="w-full"
                />
              </div>
            </div>

            <div class="field-row">
              <div class="field">
                <label for="ttl">生存时间(秒)</label>
                <InputNumber
                  id="ttl"
                  v-model="localForm.ttl"
                  :min="0"
                  class="w-full"
                  placeholder="0表示不过期"
                />
              </div>

              <div class="field flex align-items-center">
                <label for="is_active" class="mr-2">启用状态</label>
                <ToggleSwitch id="is_active" v-model="localForm.is_active" />
              </div>
            </div>
          </div>
        </template>
      </Card>

      <!-- 作用域配置 -->
      <ScopeConfigPanel
        v-model="localScope"
        :title="'作用域配置（可选）'"
        :description="'设置此Header的生效范围，留空表示全局生效'"
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
        :label="isAdd ? '添加' : '保存'"
        icon="pi pi-check"
        @click="handleSubmit"
        :loading="loading"
        :disabled="!isFormValid"
      />
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import ScopeConfigPanel from '../ScopeConfigPanel.vue'
import type { HeaderScope } from '@/types/headerRule'
import { ReplaceStrategy } from '@/types/headerRule'
import { REPLACE_STRATEGY_OPTIONS, DEFAULT_PRIORITY, DEFAULT_TTL } from './constants'

interface FormData {
  header_name: string
  header_value: string
  replace_strategy: ReplaceStrategy
  priority: number
  ttl: number
  is_active: boolean
}

interface EditData {
  header_name?: string
  header_value?: string
  replace_strategy?: ReplaceStrategy
  priority?: number
  ttl?: number
  is_active?: boolean
  scope?: HeaderScope | null
}

const props = defineProps<{
  modelValue: boolean
  editData?: EditData | null
  loading?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'submit', form: FormData, scope: HeaderScope | null): void
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
})

const isAdd = computed(() => !props.editData)

const replaceStrategyOptions = [...REPLACE_STRATEGY_OPTIONS]

const defaultForm: FormData = {
  header_name: '',
  header_value: '',
  replace_strategy: ReplaceStrategy.REPLACE,
  priority: DEFAULT_PRIORITY,
  ttl: DEFAULT_TTL,
  is_active: true
}

const localForm = ref<FormData>({ ...defaultForm })
const localScope = ref<HeaderScope | null>(null)

const isFormValid = computed(() => {
  return localForm.value.header_name.trim() !== '' && 
         localForm.value.header_value.trim() !== ''
})

watch(visible, (newVal) => {
  if (newVal) {
    if (props.editData) {
      localForm.value = {
        header_name: props.editData.header_name || '',
        header_value: props.editData.header_value || '',
        replace_strategy: props.editData.replace_strategy || ReplaceStrategy.REPLACE,
        priority: props.editData.priority ?? DEFAULT_PRIORITY,
        ttl: props.editData.ttl ?? DEFAULT_TTL,
        is_active: props.editData.is_active ?? true
      }
      localScope.value = props.editData.scope || null
    } else {
      localForm.value = { ...defaultForm }
      localScope.value = null
    }
  }
})

function handleSubmit() {
  emit('submit', { ...localForm.value }, localScope.value)
}
</script>

<style scoped lang="scss">
.form-grid {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.field-row {
  display: flex;
  gap: 1rem;
  
  .field {
    flex: 1;
  }
}

.required-field::after {
  content: '*';
  color: var(--red-500);
  margin-left: 0.25rem;
}

@media (max-width: 576px) {
  .field-row {
    flex-direction: column;
  }
}

.dialog-content {
  padding: 1.5rem;
  
  :deep(.p-card) {
    margin-bottom: 1.5rem;
    
    .p-card-content {
      padding: 1rem 1.25rem;
    }
  }
}
</style>
