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
      :style="{ width: '600px' }"
      modal
    >
      <div class="dialog-content">
        <div class="field">
          <label for="name">规则名称 *</label>
          <InputText
            id="name"
            v-model="formData.name"
            placeholder="请输入规则名称"
            class="w-full"
          />
        </div>

        <div class="field">
          <label for="header_name">Header名称 *</label>
          <InputText
            id="header_name"
            v-model="formData.header_name"
            placeholder="例如: Authorization"
            class="w-full"
          />
        </div>

        <div class="field">
          <label for="header_value">Header值 *</label>
          <Textarea
            id="header_value"
            v-model="formData.header_value"
            placeholder="请输入Header值"
            rows="3"
            class="w-full"
          />
        </div>

        <div class="field">
          <label for="replace_strategy">替换策略</label>
          <Dropdown
            id="replace_strategy"
            v-model="formData.replace_strategy"
            :options="replaceStrategies"
            optionLabel="label"
            optionValue="value"
            placeholder="选择替换策略"
            class="w-full"
          />
        </div>

        <div class="field">
          <label for="priority">优先级 (0-100)</label>
          <InputNumber
            id="priority"
            v-model="formData.priority"
            :min="0"
            :max="100"
            showButtons
            class="w-full"
          />
        </div>

        <div class="field-checkbox">
          <Checkbox
            id="is_active"
            v-model="formData.is_active"
            :binary="true"
          />
          <label for="is_active">启用规则</label>
        </div>

        <!-- 作用域配置 -->
        <div class="field">
          <div class="scope-header">
            <Checkbox
              id="has_scope"
              v-model="hasScope"
              :binary="true"
            />
            <label for="has_scope">配置作用域（不勾选则全局生效）</label>
          </div>
          
          <div v-if="hasScope" class="scope-config">
            <div class="field">
              <label for="protocol_pattern">协议匹配</label>
              <InputText
                id="protocol_pattern"
                v-model="scopeData.protocol_pattern"
                placeholder="例如: https 或 http,https"
                class="w-full"
              />
            </div>

            <div class="field">
              <label for="host_pattern">主机名匹配</label>
              <InputText
                id="host_pattern"
                v-model="scopeData.host_pattern"
                placeholder="例如: api.example.com 或 *.example.com"
                class="w-full"
              />
            </div>

            <div class="field">
              <label for="path_pattern">路径匹配</label>
              <InputText
                id="path_pattern"
                v-model="scopeData.path_pattern"
                placeholder="例如: /api/* 或 /v1/users"
                class="w-full"
              />
            </div>

            <div class="field-checkbox">
              <Checkbox
                id="use_regex"
                v-model="scopeData.use_regex"
                :binary="true"
              />
              <label for="use_regex">使用正则表达式匹配</label>
            </div>
          </div>
        </div>
      </div>

      <template #footer>
        <Button label="取消" severity="secondary" @click="dialogVisible = false" />
        <Button label="保存" @click="saveRule" :loading="saving" />
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

  .dialog-content {
    .field {
      margin-bottom: 20px;

      label {
        display: block;
        margin-bottom: 8px;
        font-weight: 600;
      }
    }

    .field-checkbox {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 20px;
    }

    .scope-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--surface-border);

      label {
        font-weight: 600;
        color: var(--primary-color);
      }
    }

    .scope-config {
      padding: 16px;
      background: var(--surface-50);
      border-radius: 8px;
      border: 1px solid var(--surface-border);
    }
  }
}
</style>
