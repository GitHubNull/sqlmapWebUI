<template>
  <div class="header-rules-config">
    <!-- 工具栏 -->
    <div class="toolbar">
      <Button
        label="添加规则"
        icon="pi pi-plus"
        @click="showCreateDialog"
        severity="success"
      />
      <Button
        label="刷新"
        icon="pi pi-refresh"
        @click="loadRules"
        :loading="loading"
      />
    </div>

    <!-- 规则列表 -->
    <DataTable
      :value="rules"
      :loading="loading"
      stripedRows
      paginator
      :rows="10"
      :rowsPerPageOptions="[5, 10, 20, 50]"
      sortField="priority"
      :sortOrder="-1"
      class="rules-table"
    >
      <Column field="id" header="ID" sortable style="width: 80px"></Column>
      <Column field="name" header="规则名称" sortable></Column>
      <Column field="header_name" header="Header名称" sortable></Column>
      <Column field="header_value" header="Header值">
        <template #body="{ data }">
          <span class="header-value">{{ truncate(data.header_value, 30) }}</span>
        </template>
      </Column>
      <Column field="replace_strategy" header="替换策略" sortable style="width: 120px"></Column>
      <Column field="priority" header="优先级" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.priority" :severity="getPrioritySeverity(data.priority)"></Tag>
        </template>
      </Column>
      <Column field="is_active" header="状态" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.is_active ? '启用' : '禁用'" :severity="data.is_active ? 'success' : 'danger'"></Tag>
        </template>
      </Column>
      <Column field="scope" header="作用域" style="width: 120px">
        <template #body="{ data }">
          <Tag :value="data.scope ? '有作用域' : '全局'" :severity="data.scope ? 'info' : 'secondary'"></Tag>
        </template>
      </Column>
      <Column header="操作" style="width: 200px">
        <template #body="{ data }">
          <Button
            icon="pi pi-pencil"
            text
            rounded
            @click="showEditDialog(data)"
            v-tooltip.top="'编辑'"
          />
          <Button
            icon="pi pi-trash"
            text
            rounded
            severity="danger"
            @click="confirmDelete(data)"
            v-tooltip.top="'删除'"
          />
          <Button
            :icon="data.is_active ? 'pi pi-eye-slash' : 'pi pi-eye'"
            text
            rounded
            :severity="data.is_active ? 'warning' : 'success'"
            @click="toggleActive(data)"
            v-tooltip.top="data.is_active ? '禁用' : '启用'"
          />
        </template>
      </Column>
    </DataTable>

    <!-- 创建/编辑对话框 -->
    <Dialog
      v-model:visible="dialogVisible"
      :header="editingRule ? '编辑规则' : '创建规则'"
      :style="{ width: '750px' }"
      modal
    >
      <!-- 基本信息面板 -->
      <Panel header="基本信息" class="mb-3">
        <div class="p-fluid">
          <div class="field mb-3">
            <label for="name">
              <i class="pi pi-bookmark mr-2"></i>
              规则名称 <span class="text-red-500">*</span>
            </label>
            <InputText
              id="name"
              v-model="formData.name"
              placeholder="例如: API认证Token规则"
            />
            <small class="text-color-secondary">用于标识此规则的用途</small>
          </div>

          <div class="field mb-3">
            <label for="header_name">
              <i class="pi pi-tag mr-2"></i>
              Header名称 <span class="text-red-500">*</span>
            </label>
            <InputText
              id="header_name"
              v-model="formData.header_name"
              placeholder="例如: Authorization, X-API-Key, Cookie"
            />
            <small class="text-color-secondary">HTTP请求头的名称，区分大小写</small>
          </div>

          <div class="field">
            <label for="header_value">
              <i class="pi pi-align-left mr-2"></i>
              Header值 <span class="text-red-500">*</span>
            </label>
            <Textarea
              id="header_value"
              v-model="formData.header_value"
              placeholder="请输入Header值"
              :autoResize="true"
              rows="3"
            />
            <small class="text-color-secondary">Header的实际值内容</small>
          </div>
        </div>
      </Panel>

      <Divider />

      <!-- 高级配置面板 -->
      <Panel header="高级配置" :toggleable="true" class="mb-3">
        <div class="p-fluid">
          <div class="formgrid grid">
            <div class="field col-8 mb-3">
              <label for="replace_strategy">
                <i class="pi pi-sync mr-2"></i>
                替换策略
              </label>
              <Dropdown
                id="replace_strategy"
                v-model="formData.replace_strategy"
                :options="replaceStrategies"
                optionLabel="label"
                optionValue="value"
                placeholder="选择替换策略"
              />
              <small class="text-color-secondary">定义如何处理已存在的Header</small>
            </div>

            <div class="field col-4 mb-3">
              <label for="priority">
                <i class="pi pi-sort-amount-up mr-2"></i>
                优先级
              </label>
              <InputNumber
                id="priority"
                v-model="formData.priority"
                :min="0"
                :max="100"
                showButtons
              />
              <small class="text-color-secondary">0-100，越大优先级越高</small>
            </div>
          </div>

          <div class="field">
            <div class="flex align-items-center">
              <Checkbox
                inputId="is_active"
                v-model="formData.is_active"
                :binary="true"
              />
              <label for="is_active" class="ml-2">
                <i class="pi pi-power-off mr-2"></i>
                启用此规则
              </label>
            </div>
            <small class="text-color-secondary ml-4">禁用后规则不会生效</small>
          </div>
        </div>
      </Panel>

      <Divider />

      <!-- 作用域配置面板 -->
      <Panel :toggleable="true" :collapsed="!hasScope" class="mb-3">
        <template #header>
          <div class="flex align-items-center gap-2 w-full">
            <Checkbox
              inputId="has_scope"
              v-model="hasScope"
              :binary="true"
              @click.stop
            />
            <span>
              <i class="pi pi-filter mr-2"></i>
              配置作用域（可选）
            </span>
          </div>
        </template>

        <Message severity="info" :closable="false" class="mb-3">
          <i class="pi pi-info-circle mr-2"></i>
          不勾选则对所有请求全局生效。作用域支持协议、主机名、路径等多维度过滤。
        </Message>

        <div v-if="hasScope" class="p-fluid">
          <div class="field mb-3">
            <label for="protocol_pattern">
              <i class="pi pi-globe mr-2"></i>
              协议匹配
            </label>
            <InputText
              id="protocol_pattern"
              v-model="scopeData.protocol_pattern"
              placeholder="例如: https 或 http,https（多个用逗号分隔）"
            />
            <small class="text-color-secondary">限定请求协议类型</small>
          </div>

          <div class="field mb-3">
            <label for="host_pattern">
              <i class="pi pi-server mr-2"></i>
              主机名匹配
            </label>
            <InputText
              id="host_pattern"
              v-model="scopeData.host_pattern"
              placeholder="例如: api.example.com 或 *.example.com（支持通配符*）"
            />
            <small class="text-color-secondary">限定请求的目标主机名，支持通配符</small>
          </div>

          <div class="field mb-3">
            <label for="path_pattern">
              <i class="pi pi-link mr-2"></i>
              路径匹配
            </label>
            <InputText
              id="path_pattern"
              v-model="scopeData.path_pattern"
              placeholder="例如: /api/* 或 /v1/users（支持通配符*）"
            />
            <small class="text-color-secondary">限定请求的URL路径，支持通配符</small>
          </div>

          <div class="field mb-3">
            <div class="flex align-items-center">
              <Checkbox
                inputId="use_regex"
                v-model="scopeData.use_regex"
                :binary="true"
              />
              <label for="use_regex" class="ml-2">
                <i class="pi pi-code mr-2"></i>
                使用正则表达式匹配
              </label>
            </div>
            <small class="text-color-secondary ml-4">启用后上述模式将作为正则表达式解析</small>
          </div>

          <Divider />

          <Message severity="success" :closable="false">
            <p class="font-semibold mb-2">
              <i class="pi pi-lightbulb mr-2"></i>
              匹配示例
            </p>
            <ul class="pl-4 mt-0 mb-0 line-height-3">
              <li><strong>全局生效：</strong>不勾选"配置作用域"</li>
              <li><strong>仅HTTPS：</strong>协议=https</li>
              <li><strong>特定域名：</strong>主机名=api.example.com</li>
              <li><strong>所有子域名：</strong>主机名=*.example.com</li>
              <li><strong>API路径：</strong>路径=/api/*</li>
            </ul>
          </Message>
        </div>
      </Panel>

      <template #footer>
        <Button 
          label="取消" 
          icon="pi pi-times"
          severity="secondary" 
          @click="dialogVisible = false" 
        />
        <Button 
          label="保存" 
          icon="pi pi-check"
          @click="saveRule" 
          :loading="saving" 
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import {
  getPersistentRules,
  createPersistentRule,
  updatePersistentRule,
  deletePersistentRule,
} from '@/api/headerRule'
import type {
  PersistentHeaderRule,
  PersistentHeaderRuleCreate,
  PersistentHeaderRuleUpdate,
  HeaderScope,
  ReplaceStrategy,
} from '@/types/headerRule'

const toast = useToast()
const confirm = useConfirm()

const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const rules = ref<PersistentHeaderRule[]>([])
const editingRule = ref<PersistentHeaderRule | null>(null)
const hasScope = ref(false)

const replaceStrategies = [
  { label: '完全替换', value: 'REPLACE' },
  { label: '追加', value: 'APPEND' },
  { label: '前置', value: 'PREPEND' },
  { label: '条件替换', value: 'CONDITIONAL' },
  { label: '存在则替换', value: 'UPSERT' },
]

const formData = reactive<PersistentHeaderRuleCreate>({
  name: '',
  header_name: '',
  header_value: '',
  replace_strategy: 'REPLACE' as ReplaceStrategy,
  priority: 50,
  is_active: true,
})

const scopeData = reactive<HeaderScope>({
  protocol_pattern: '',
  host_pattern: '',
  path_pattern: '',
  use_regex: false,
})

onMounted(() => {
  loadRules()
})

async function loadRules() {
  loading.value = true
  try {
    const res = await getPersistentRules(false)
    if (res.success) {
      rules.value = res.data.rules || []
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '加载失败',
      detail: error.message || '加载规则列表失败',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

function showCreateDialog() {
  editingRule.value = null
  resetForm()
  dialogVisible.value = true
}

function showEditDialog(rule: PersistentHeaderRule) {
  editingRule.value = rule
  formData.name = rule.name
  formData.header_name = rule.header_name
  formData.header_value = rule.header_value
  formData.replace_strategy = rule.replace_strategy
  formData.priority = rule.priority
  formData.is_active = rule.is_active

  // 加载作用域配置
  if (rule.scope) {
    hasScope.value = true
    Object.assign(scopeData, rule.scope)
  } else {
    hasScope.value = false
    resetScope()
  }

  dialogVisible.value = true
}

function resetForm() {
  formData.name = ''
  formData.header_name = ''
  formData.header_value = ''
  formData.replace_strategy = 'REPLACE' as ReplaceStrategy
  formData.priority = 50
  formData.is_active = true
  hasScope.value = false
  resetScope()
}

function resetScope() {
  scopeData.protocol_pattern = ''
  scopeData.host_pattern = ''
  scopeData.path_pattern = ''
  scopeData.use_regex = false
}

async function saveRule() {
  if (!formData.name || !formData.header_name || !formData.header_value) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请填写必填字段',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    const payload: any = { ...formData }
    
    // 处理作用域配置
    if (hasScope.value) {
      // 只添加非空字段
      const scope: any = {}
      if (scopeData.protocol_pattern) scope.protocol_pattern = scopeData.protocol_pattern
      if (scopeData.host_pattern) scope.host_pattern = scopeData.host_pattern
      if (scopeData.path_pattern) scope.path_pattern = scopeData.path_pattern
      scope.use_regex = scopeData.use_regex

      payload.scope = scope
    } else {
      payload.scope = null
    }

    if (editingRule.value) {
      await updatePersistentRule(editingRule.value.id, payload)
      toast.add({
        severity: 'success',
        summary: '更新成功',
        detail: '规则已更新',
        life: 3000,
      })
    } else {
      await createPersistentRule(payload)
      toast.add({
        severity: 'success',
        summary: '创建成功',
        detail: '规则已创建',
        life: 3000,
      })
    }

    dialogVisible.value = false
    await loadRules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '保存规则失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function confirmDelete(rule: PersistentHeaderRule) {
  confirm.require({
    message: `确定要删除规则 "${rule.name}" 吗？`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    accept: () => deleteRule(rule.id),
  })
}

async function deleteRule(ruleId: number) {
  try {
    await deletePersistentRule(ruleId)
    toast.add({
      severity: 'success',
      summary: '删除成功',
      detail: '规则已删除',
      life: 3000,
    })
    await loadRules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '删除失败',
      detail: error.message || '删除规则失败',
      life: 3000,
    })
  }
}

async function toggleActive(rule: PersistentHeaderRule) {
  try {
    await updatePersistentRule(rule.id, { is_active: !rule.is_active })
    toast.add({
      severity: 'success',
      summary: '状态已更新',
      detail: `规则已${!rule.is_active ? '启用' : '禁用'}`,
      life: 3000,
    })
    await loadRules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '更新状态失败',
      life: 3000,
    })
  }
}

function getPrioritySeverity(priority: number) {
  if (priority >= 80) return 'danger'
  if (priority >= 50) return 'warning'
  return 'info'
}

function truncate(text: string, length: number) {
  if (text.length <= length) return text
  return text.substring(0, length) + '...'
}
</script>

<style scoped lang="scss">
.header-rules-config {
  .toolbar {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
  }

  .rules-table {
    .header-value {
      font-family: monospace;
      font-size: 0.9em;
    }
  }
}
</style>
