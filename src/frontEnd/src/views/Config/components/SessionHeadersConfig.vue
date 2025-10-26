<template>
  <div class="session-headers-config">
    <div class="info-banner">
      <i class="pi pi-info-circle"></i>
      <span>会话Header仅在当前浏览器会话中有效，关闭浏览器后将自动清除</span>
    </div>

    <!-- 工具栏 -->
    <div class="toolbar">
      <Button
        label="添加Header"
        icon="pi pi-plus"
        @click="showAddDialog"
        severity="success"
      />
      <Button
        label="刷新"
        icon="pi pi-refresh"
        @click="loadSessionHeaders"
        :loading="loading"
      />
      <Button
        label="清除所有"
        icon="pi pi-trash"
        @click="confirmClearAll"
        severity="danger"
        outlined
      />
    </div>

    <!-- Session Headers列表 -->
    <DataTable
      :value="sessionHeaders"
      :loading="loading"
      stripedRows
      class="session-table"
    >
      <Column field="header_name" header="Header名称"></Column>
      <Column field="header_value" header="Header值">
        <template #body="{ data }">
          <span class="header-value">{{ truncate(data.header_value, 40) }}</span>
        </template>
      </Column>
      <Column field="priority" header="优先级" style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.priority" severity="info"></Tag>
        </template>
      </Column>
      <Column field="expires_at" header="过期时间" style="width: 200px">
        <template #body="{ data }">
          <span class="expire-time">{{ formatTime(data.expires_at) }}</span>
        </template>
      </Column>
      <Column field="created_at" header="创建时间" style="width: 200px">
        <template #body="{ data }">
          <span class="create-time">{{ formatTime(data.created_at) }}</span>
        </template>
      </Column>
    </DataTable>

    <!-- 批量添加对话框 -->
    <Dialog
      v-model:visible="dialogVisible"
      header="添加Session Headers"
      :style="{ width: '600px' }"
      modal
    >
      <div class="dialog-content">
        <p class="help-text">
          每行一个Header，格式：<code>Header-Name: Header-Value</code>
        </p>

        <Textarea
          v-model="rawHeaders"
          rows="10"
          placeholder="例如:
Authorization: Bearer your-token
X-Custom-Header: custom-value"
          class="w-full"
        />

        <div class="field">
          <label for="priority">优先级 (0-100)</label>
          <InputNumber
            id="priority"
            v-model="defaultPriority"
            :min="0"
            :max="100"
            showButtons
            class="w-full"
          />
        </div>

        <div class="field">
          <label for="ttl">生存时间 (秒)</label>
          <InputNumber
            id="ttl"
            v-model="defaultTtl"
            :min="60"
            :max="86400"
            showButtons
            class="w-full"
          />
          <small class="field-help">默认3600秒(1小时)，最大86400秒(24小时)</small>
        </div>
      </div>

      <template #footer>
        <Button label="取消" severity="secondary" @click="dialogVisible = false" />
        <Button label="添加" @click="addSessionHeaders" :loading="saving" />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import {
  getSessionHeaders,
  setSessionHeaders,
  clearSessionHeaders,
} from '@/api/headerRule'
import type { SessionHeader } from '@/types/headerRule'

const toast = useToast()
const confirm = useConfirm()

const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const sessionHeaders = ref<any[]>([])
const rawHeaders = ref('')
const defaultPriority = ref(50)
const defaultTtl = ref(3600) // 默认1小时

onMounted(() => {
  loadSessionHeaders()
})

async function loadSessionHeaders() {
  loading.value = true
  try {
    const res = await getSessionHeaders()
    if (res.success) {
      sessionHeaders.value = res.data.headers || []
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '加载失败',
      detail: error.message || '加载Session Headers失败',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

function showAddDialog() {
  rawHeaders.value = ''
  defaultPriority.value = 50
  defaultTtl.value = 3600
  dialogVisible.value = true
}

async function addSessionHeaders() {
  if (!rawHeaders.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请输入Header内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    // 解析Headers
    const lines = rawHeaders.value.split('\n').filter((line) => line.trim())
    const headers: SessionHeader[] = []

    for (const line of lines) {
      const [name, ...valueParts] = line.split(':')
      if (name && valueParts.length > 0) {
        headers.push({
          header_name: name.trim(),
          header_value: valueParts.join(':').trim(),
          priority: defaultPriority.value,
          ttl: defaultTtl.value,
        })
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未能解析出有效的Header',
        life: 3000,
      })
      return
    }

    await setSessionHeaders({ headers })
    toast.add({
      severity: 'success',
      summary: '添加成功',
      detail: `成功添加 ${headers.length} 个Session Header`,
      life: 3000,
    })

    dialogVisible.value = false
    await loadSessionHeaders()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '添加失败',
      detail: error.message || '添加Session Headers失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function confirmClearAll() {
  if (sessionHeaders.value.length === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '当前没有Session Headers',
      life: 3000,
    })
    return
  }

  confirm.require({
    message: '确定要清除所有Session Headers吗？',
    header: '确认清除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '清除',
    rejectLabel: '取消',
    accept: async () => {
      try {
        await clearSessionHeaders()
        toast.add({
          severity: 'success',
          summary: '清除成功',
          detail: 'Session Headers已清除',
          life: 3000,
        })
        await loadSessionHeaders()
      } catch (error: any) {
        toast.add({
          severity: 'error',
          summary: '清除失败',
          detail: error.message || '清除Session Headers失败',
          life: 3000,
        })
      }
    },
  })
}

function formatTime(timeStr: string) {
  if (!timeStr) return '-'
  return new Date(timeStr).toLocaleString('zh-CN')
}

function truncate(text: string, length: number) {
  if (text.length <= length) return text
  return text.substring(0, length) + '...'
}
</script>

<style scoped lang="scss">
.session-headers-config {
  .info-banner {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px;
    margin-bottom: 20px;
    background: var(--blue-50);
    border: 1px solid var(--blue-200);
    border-radius: 8px;
    color: var(--blue-900);

    i {
      font-size: 1.5rem;
      color: var(--blue-500);
    }
  }

  .toolbar {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
  }

  .session-table {
    .header-value {
      font-family: monospace;
      font-size: 0.9em;
    }

    .expire-time,
    .create-time {
      font-size: 0.9em;
      color: var(--text-color-secondary);
    }
  }

  .dialog-content {
    .help-text {
      margin-bottom: 16px;
      padding: 12px;
      background: var(--surface-50);
      border-radius: 6px;
      color: var(--text-color-secondary);

      code {
        padding: 2px 6px;
        background: var(--surface-100);
        border-radius: 4px;
        font-family: monospace;
        color: var(--primary-color);
      }
    }

    .field {
      margin-top: 20px;

      label {
        display: block;
        margin-bottom: 8px;
        font-weight: 600;
      }

      .field-help {
        display: block;
        margin-top: 6px;
        color: var(--text-color-secondary);
        font-size: 0.9em;
      }
    }
  }
}
</style>
