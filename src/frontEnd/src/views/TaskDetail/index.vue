<template>
  <div class="task-detail-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <Button 
        icon="pi pi-arrow-left" 
        label="返回列表" 
        @click="router.back()" 
        text
      />
      <div class="header-actions">
        <Button 
          icon="pi pi-refresh" 
          label="刷新" 
          @click="refreshData" 
          :loading="loading"
        />
        <Button 
          v-if="task && task.status === TaskStatus.RUNNING"
          icon="pi pi-stop" 
          label="停止任务" 
          severity="warning"
          @click="handleStopTask"
        />
        <Button 
          v-if="task && task.status !== TaskStatus.RUNNING"
          icon="pi pi-trash" 
          label="删除任务" 
          severity="danger"
          @click="handleDeleteTask"
        />
      </div>
    </div>

    <!-- 加载状态 -->
    <div v-if="loading && !task" class="loading-container">
      <ProgressSpinner />
    </div>

    <!-- 错误状态 -->
    <Message v-else-if="error" severity="error" :closable="false">
      {{ error }}
    </Message>

    <!-- 详情内容 -->
    <div v-else-if="task" class="detail-content">
      <!-- 基础信息 -->
      <Card class="info-card">
        <template #title>
          <div class="card-header">
            <i class="pi pi-info-circle"></i>
            <span>基础信息</span>
          </div>
        </template>
        <template #content>
          <div class="info-grid">
            <div class="info-item">
              <label>任务ID</label>
              <span class="value">{{ task.taskid }}</span>
            </div>
            <div class="info-item">
              <label>引擎ID</label>
              <span class="value">{{ task.engineid }}</span>
            </div>
            <div class="info-item">
              <label>任务状态</label>
              <Tag :value="getStatusLabel(task.status)" :severity="getStatusSeverity(task.status)" />
            </div>
            <div class="info-item">
              <label>注入状态</label>
              <Tag 
                v-if="task.injected === true" 
                value="可注入" 
                severity="danger" 
                icon="pi pi-shield"
              />
              <Tag 
                v-else-if="task.injected === false" 
                value="不可注入" 
                severity="success" 
                icon="pi pi-lock"
              />
              <span v-else class="value text-muted">未知</span>
            </div>
            <div class="info-item full-width">
              <label>扫描URL</label>
              <div class="url-display">
                <span class="value url">{{ task.scanUrl }}</span>
                <Button 
                  icon="pi pi-copy" 
                  text 
                  rounded 
                  @click="copyToClipboard(task.scanUrl)"
                  v-tooltip.top="'复制URL'"
                />
              </div>
            </div>
            <div class="info-item">
              <label>目标主机</label>
              <span class="value">{{ task.host }}</span>
            </div>
            <div class="info-item">
              <label>创建时间</label>
              <span class="value">{{ formatDateTime(task.createTime) }}</span>
            </div>
            <div class="info-item">
              <label>更新时间</label>
              <span class="value">{{ task.updateTime ? formatDateTime(task.updateTime) : '-' }}</span>
            </div>
            <div class="info-item">
              <label>来源IP</label>
              <span class="value">{{ task.remote_addr || '-' }}</span>
            </div>
          </div>
        </template>
      </Card>

      <!-- HTTP请求信息 -->
      <Card class="info-card">
        <template #title>
          <div class="card-header">
            <i class="pi pi-globe"></i>
            <span>HTTP请求信息</span>
          </div>
        </template>
        <template #content>
          <div v-if="loadingHttp" class="loading-small">
            <ProgressSpinner style="width: 30px; height: 30px" />
          </div>
          <div v-else-if="httpInfo">
            <div class="info-item">
              <label>请求方法</label>
              <Tag :value="httpInfo.method || 'GET'" />
            </div>
            <div class="info-section">
              <h4>请求头</h4>
              <div v-if="task.headers && task.headers.length > 0" class="headers-list">
                <div v-for="(header, index) in task.headers" :key="index" class="header-item">
                  {{ header }}
                </div>
              </div>
              <span v-else class="text-muted">无</span>
            </div>
            <div class="info-section">
              <h4>请求体</h4>
              <pre v-if="task.body" class="code-block">{{ task.body }}</pre>
              <span v-else class="text-muted">无</span>
            </div>
          </div>
        </template>
      </Card>

      <!-- 扫描配置 -->
      <Card class="info-card">
        <template #title>
          <div class="card-header">
            <i class="pi pi-cog"></i>
            <span>扫描配置</span>
          </div>
        </template>
        <template #content>
          <div v-if="loadingOptions" class="loading-small">
            <ProgressSpinner style="width: 30px; height: 30px" />
          </div>
          <div v-else-if="task.options" class="info-grid">
            <div class="info-item">
              <label>检测级别</label>
              <span class="value">{{ task.options.level || '-' }}</span>
            </div>
            <div class="info-item">
              <label>风险级别</label>
              <span class="value">{{ task.options.risk || '-' }}</span>
            </div>
            <div class="info-item">
              <label>注入技术</label>
              <span class="value">{{ task.options.technique || '-' }}</span>
            </div>
            <div class="info-item">
              <label>数据库类型</label>
              <span class="value">{{ task.options.dbms || '-' }}</span>
            </div>
            <div class="info-item">
              <label>线程数</label>
              <span class="value">{{ task.options.threads || '-' }}</span>
            </div>
          </div>
          <span v-else class="text-muted">无配置信息</span>
        </template>
      </Card>

      <!-- 扫描结果 -->
      <Card class="info-card">
        <template #title>
          <div class="card-header">
            <i class="pi pi-chart-bar"></i>
            <span>扫描结果</span>
          </div>
        </template>
        <template #content>
          <div v-if="loadingPayload" class="loading-small">
            <ProgressSpinner style="width: 30px; height: 30px" />
          </div>
          <div v-else-if="payloadData">
            <DataTable :value="payloadData" stripedRows>
              <Column field="index" header="序号" style="width: 80px" />
              <Column field="status" header="状态" style="width: 100px" />
              <Column field="contentType" header="内容类型" style="width: 150px" />
              <Column field="value" header="载荷内容">
                <template #body="{ data }">
                  <div class="payload-value">{{ data.value }}</div>
                </template>
              </Column>
            </DataTable>
          </div>
          <span v-else class="text-muted">无扫描结果</span>
        </template>
      </Card>

      <!-- 任务日志 -->
      <Card class="info-card">
        <template #title>
          <div class="card-header">
            <i class="pi pi-file"></i>
            <span>任务日志</span>
            <Button 
              icon="pi pi-refresh" 
              text 
              rounded 
              @click="() => loadLogs()" 
              :loading="loadingLogs"
              v-tooltip.top="'刷新日志'"
            />
          </div>
        </template>
        <template #content>
          <div v-if="loadingLogs" class="loading-small">
            <ProgressSpinner style="width: 30px; height: 30px" />
          </div>
          <div v-else-if="logs && logs.length > 0" class="logs-container">
            <div v-for="(log, index) in logs" :key="index" class="log-item">
              {{ log }}
            </div>
          </div>
          <span v-else class="text-muted">无日志记录</span>
        </template>
      </Card>

      <!-- 错误记录 -->
      <Card v-if="errors && errors.length > 0" class="info-card">
        <template #title>
          <div class="card-header">
            <i class="pi pi-exclamation-triangle"></i>
            <span>错误记录</span>
          </div>
        </template>
        <template #content>
          <div class="errors-container">
            <Message 
              v-for="(error, index) in errors" 
              :key="index" 
              severity="error" 
              :closable="false"
            >
              {{ error }}
            </Message>
          </div>
        </template>
      </Card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import type { Task } from '@/types/task'
import { formatDateTime } from '@/utils/format'
import { 
  getTaskLogs, 
  getScanOptions, 
  getHttpRequestInfo, 
  getPayloadDetail, 
  getErrors 
} from '@/api/task'

const route = useRoute()
const router = useRouter()
const confirm = useConfirm()
const toast = useToast()
const taskStore = useTaskStore()

const task = ref<Task | null>(null)
const loading = ref(false)
const error = ref('')

const loadingHttp = ref(false)
const httpInfo = ref<any>(null)

const loadingOptions = ref(false)

const loadingPayload = ref(false)
const payloadData = ref<any[]>([])

const loadingLogs = ref(false)
const logs = ref<string[]>([])

const errors = ref<string[]>([])

onMounted(() => {
  loadTaskDetail()
})

async function loadTaskDetail() {
  const taskId = route.params.id as string
  if (!taskId) {
    error.value = '任务ID不存在'
    return
  }

  loading.value = true
  try {
    // 从 store中获取任务基本信息
    await taskStore.fetchTaskList()
    const foundTask = taskStore.taskList.find(t => t.taskid === taskId)
    
    if (!foundTask) {
      error.value = '任务不存在'
      return
    }
    
    task.value = foundTask
    
    // 并行加载其他数据
    await Promise.all([
      loadHttpInfo(taskId),
      loadPayloadDetail(taskId),
      loadLogs(taskId),
      loadErrors(taskId),
    ])
  } catch (err: any) {
    error.value = err.message || '加载失败'
  } finally {
    loading.value = false
  }
}

async function loadHttpInfo(taskId: string) {
  loadingHttp.value = true
  try {
    httpInfo.value = await getHttpRequestInfo(taskId)
  } catch (err) {
    console.error('Failed to load HTTP info:', err)
  } finally {
    loadingHttp.value = false
  }
}

async function loadPayloadDetail(taskId: string) {
  loadingPayload.value = true
  try {
    payloadData.value = await getPayloadDetail(taskId)
  } catch (err) {
    console.error('Failed to load payload detail:', err)
  } finally {
    loadingPayload.value = false
  }
}

async function loadLogs(taskId?: string) {
  const id = taskId || (route.params.id as string)
  loadingLogs.value = true
  try {
    logs.value = await getTaskLogs(id)
  } catch (err) {
    console.error('Failed to load logs:', err)
  } finally {
    loadingLogs.value = false
  }
}

async function loadErrors(taskId: string) {
  try {
    errors.value = await getErrors(taskId)
  } catch (err) {
    console.error('Failed to load errors:', err)
  }
}

async function refreshData() {
  await loadTaskDetail()
  toast.add({
    severity: 'success',
    summary: '成功',
    detail: '数据已刷新',
    life: 2000,
  })
}

function getStatusLabel(status: TaskStatus): string {
  const labels = {
    [TaskStatus.PENDING]: '等待中',
    [TaskStatus.RUNNING]: '运行中',
    [TaskStatus.SUCCESS]: '已完成',
    [TaskStatus.FAILED]: '失败',
    [TaskStatus.STOPPED]: '已停止',
    [TaskStatus.TERMINATED]: '已终止',
  }
  return labels[status] || '未知'
}

function getStatusSeverity(status: TaskStatus): string {
  const severities = {
    [TaskStatus.PENDING]: 'info',
    [TaskStatus.RUNNING]: 'primary',
    [TaskStatus.SUCCESS]: 'success',
    [TaskStatus.FAILED]: 'danger',
    [TaskStatus.STOPPED]: 'warn',
    [TaskStatus.TERMINATED]: 'secondary',
  }
  return severities[status] || 'secondary'
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(() => {
    toast.add({
      severity: 'success',
      summary: '成功',
      detail: '已复制到剪贴板',
      life: 2000,
    })
  })
}

function handleStopTask() {
  if (!task.value) return
  
  confirm.require({
    message: '确定要停止该任务吗？',
    header: '确认停止',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '停止',
    rejectLabel: '取消',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await taskStore.stopTask(task.value!.taskid)
        await refreshData()
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: '任务已停止',
          life: 3000,
        })
      } catch (err) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '停止失败',
          life: 3000,
        })
      }
    },
  })
}

function handleDeleteTask() {
  if (!task.value) return
  
  confirm.require({
    message: '确定要删除该任务吗？此操作不可恢复。',
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await taskStore.deleteTask(task.value!.taskid)
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: '任务已删除',
          life: 3000,
        })
        router.push('/tasks')
      } catch (err) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '删除失败',
          life: 3000,
        })
      }
    },
  })
}
</script>

<style scoped lang="scss">
.task-detail-page {
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--surface-border);
  
  @media (max-width: 768px) {
    flex-direction: column;
    gap: 16px;
    align-items: stretch;
  }
}

.header-actions {
  display: flex;
  gap: 8px;
  
  @media (max-width: 768px) {
    flex-direction: column;
  }
}

.loading-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
}

.loading-small {
  display: flex;
  justify-content: center;
  padding: 20px;
}

.detail-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.info-card {
  :deep(.p-card-title) {
    font-size: 18px;
    font-weight: 600;
  }
}

.card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  
  i {
    font-size: 20px;
    color: var(--primary-color);
  }
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  
  @media (max-width: 768px) {
    grid-template-columns: 1fr;
  }
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
  
  &.full-width {
    grid-column: 1 / -1;
  }
  
  label {
    font-size: 14px;
    font-weight: 500;
    color: var(--text-color-secondary);
  }
  
  .value {
    font-size: 14px;
    color: var(--text-color);
    word-break: break-all;
    
    &.url {
      flex: 1;
    }
  }
  
  .text-muted {
    color: var(--text-color-secondary);
  }
}

.url-display {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: var(--surface-50);
  border-radius: 6px;
  border: 1px solid var(--surface-border);
}

.info-section {
  margin-top: 16px;
  
  h4 {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 12px;
    color: var(--text-color);
  }
}

.headers-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.header-item {
  padding: 8px 12px;
  background: var(--surface-50);
  border-radius: 4px;
  font-size: 13px;
  font-family: monospace;
  border-left: 3px solid var(--primary-color);
}

.code-block {
  padding: 16px;
  background: var(--surface-900);
  color: var(--surface-0);
  border-radius: 6px;
  font-family: monospace;
  font-size: 13px;
  line-height: 1.6;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.payload-value {
  font-family: monospace;
  font-size: 13px;
  max-width: 500px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.logs-container {
  max-height: 400px;
  overflow-y: auto;
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  padding: 12px;
  background: var(--surface-50);
}

.log-item {
  padding: 6px 0;
  font-family: monospace;
  font-size: 13px;
  line-height: 1.5;
  border-bottom: 1px solid var(--surface-border);
  
  &:last-child {
    border-bottom: none;
  }
}

.errors-container {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
</style>
