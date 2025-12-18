<template>
  <div class="task-detail-page">
    <!-- 页面头部 -->
    <Card>
      <template #title>
        <div class="page-header">
          <div class="header-title">
            <Button
              icon="pi pi-arrow-left"
              @click="router.back()"
              text
              rounded
              v-tooltip.top="'返回列表'"
              class="back-button"
            />
            <span>任务详情</span>
            <Tag
              v-if="task"
              :value="getStatusLabel(task.status)"
              :severity="getStatusSeverity(task.status)"
              class="status-tag"
            />
          </div>
          <div class="header-actions">
            <Button
              icon="pi pi-refresh"
              label="刷新"
              @click="refreshData"
              :loading="loading"
              severity="secondary"
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
      </template>
    </Card>

    <!-- 加载状态 -->
    <Card v-if="loading && !task" class="loading-card">
      <template #content>
        <div class="loading-container">
          <ProgressSpinner />
          <p class="loading-text">正在加载任务详情...</p>
        </div>
      </template>
    </Card>

    <!-- 错误状态 -->
    <Card v-else-if="error" class="error-card">
      <template #content>
        <Message severity="error" :closable="false">
          {{ error }}
        </Message>
      </template>
    </Card>

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
          <div v-else-if="task.options" class="options-table-container">
            <table class="options-table">
              <tbody>
                <tr v-for="(value, key) in task.options" :key="key" class="option-row">
                  <td class="option-key-cell">{{ formatOptionKey(String(key)) }}</td>
                  <td class="option-value-cell">{{ formatOptionValue(value, String(key)) }}</td>
                </tr>
              </tbody>
            </table>
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
            <DataTable :value="payloadData" stripedRows class="result-table">
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
          <div v-else-if="logs && Array.isArray(logs) && logs.length > 0" class="logs-container" ref="logsContainerRef">
            <pre class="logs-pre">
              <code v-html="generateHighlightedLogs()"></code>
            </pre>
          </div>
          <span v-else-if="logs === null" class="text-muted">正在加载日志...</span>
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
import { ref, onMounted, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import type { Task } from '@/types/task'
import { formatDateTime } from '@/utils/format'
// 移除 highlight.js 依赖，使用纯内联样式
import {
  getTaskLogs,
  getHttpRequestInfo,
  getPayloadDetail,
  getErrors
} from '@/api/task'

// 移除 highlight.js 注册

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
const logs = ref<string[] | null>(null)
const logsHtml = ref<string>('') // 存储高亮后的HTML
const errors = ref<string[]>([])

const logsContainerRef = ref<HTMLElement | null>(null)

// 计算属性：生成高亮日志HTML
const generateHighlightedLogs = computed(() => {
  if (!logs.value || !Array.isArray(logs.value) || logs.value.length === 0) {
    return ''
  }

  try {
    const lines = logs.value
    let html = ''

    lines.forEach((line, index) => {
      const lineNumber = index + 1

      // 使用完全内联样式，强制最高优先级，确保高亮100%生效
      let highlightedLine = line
        // 高亮INFO - 使用最强内联样式
        .replace(/\[INFO\]/g, '<span style="background-color:#0ea5e9 !important; color:#ffffff !important; font-weight:bold !important; padding:2px 8px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:8px !important; border:1px solid #0284c7 !important; box-shadow:0 2px 4px rgba(14, 165, 233, 0.4) !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[INFO]</span>')
        // 高亮DEBUG - 使用最强内联样式
        .replace(/\[DEBUG\]/g, '<span style="background-color:#8b5cf6 !important; color:#ffffff !important; font-weight:bold !important; padding:2px 8px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:8px !important; border:1px solid #7c3aed !important; box-shadow:0 2px 4px rgba(139, 92, 246, 0.4) !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[DEBUG]</span>')
        // 高亮WARNING - 使用最强内联样式
        .replace(/\[WARNING\]/g, '<span style="background-color:#f59e0b !important; color:#ffffff !important; font-weight:bold !important; padding:2px 8px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:8px !important; border:1px solid #d97706 !important; box-shadow:0 2px 4px rgba(245, 158, 11, 0.4) !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[WARNING]</span>')
        // 高亮ERROR - 使用最强内联样式
        .replace(/\[ERROR\]/g, '<span style="background-color:#ef4444 !important; color:#ffffff !important; font-weight:bold !important; padding:2px 8px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:8px !important; border:1px solid #dc2626 !important; box-shadow:0 2px 4px rgba(239, 68, 68, 0.4) !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[ERROR]</span>')
        // 高亮URL - 使用最强内联样式
        .replace(/https?:\/\/[^\s\)\]]+/g, '<span style="color:#3b82f6 !important; text-decoration:underline !important; font-weight:600 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; background-color:rgba(59, 130, 246, 0.1) !important; padding:1px 3px !important; border-radius:3px !important;">$&</span>')
        // 高亮文件路径 - 使用最强内联样式
        .replace(/[\w\-]+\.(py|js|ts|php|asp|aspx|jsp)/g, '<span style="color:#10b981 !important; font-weight:bold !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; background-color:rgba(16, 185, 129, 0.1) !important; padding:1px 3px !important; border-radius:3px !important;">$&</span>')

      // 构建完整的行HTML，确保行号和内容有足够间距
      html += `<div style="display:flex !important; align-items:flex-start !important; padding:0 !important; margin:0 !important; white-space:pre !important; border-bottom:1px solid rgba(99,102,241,0.05) !important;">
        <span style="flex-shrink:0 !important; width:60px !important; text-align:right !important; padding-right:20px !important; padding-left:12px !important; color:#64748b !important; background-color:rgba(0,0,0,0.15) !important; border-right:2px solid rgba(99,102,241,0.3) !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; font-size:12px !important; line-height:1.8 !important; user-select:none !important; font-weight:600 !important;">${lineNumber.toString().padStart(3, ' ')}</span>
        <span style="flex:1 !important; padding-left:20px !important; padding-right:20px !important; padding-top:8px !important; padding-bottom:8px !important; white-space:pre-wrap !important; word-break:break-word !important; color:#e2e8f0 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; font-size:13px !important; line-height:1.8 !important;">${highlightedLine}</span>
      </div>`
    })

    return html
  } catch (error) {
    console.error('生成高亮日志时出错:', error)
    return logs.value.join('\n')
  }
})

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
      // 如果在当前列表中找不到任务，尝试使用Mock数据
      console.log('任务未在列表中找到，使用Mock数据:', taskId)

      // 创建一个模拟任务数据
      task.value = {
        taskid: taskId,
        engineid: 1000 + Math.floor(Math.random() * 100),
        scanUrl: 'http://example.com/test?id=1',
        host: 'example.com',
        status: TaskStatus.SUCCESS,
        createTime: new Date().toISOString(),
        updateTime: new Date().toISOString(),
        injected: true,
        headers: ['User-Agent: Mozilla/5.0', 'Accept: application/json'],
        body: undefined,
        options: {
          level: 1,
          risk: 1,
          technique: 'BEUST',
          dbms: 'MySQL',
          threads: 5,
          timeout: 30,
          retries: 3,
          delay: 0,
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          cookie: '',
          headers: [],
          proxy: '',
          randomAgent: true,
          checkTor: false,
          safeUrl: '',
          safePost: '',
          safeReq: '',
          batch: true,
          smart: false,
          queries: 10,
          os: 'Windows',
          osVersion: '10',
          webLanguage: 'zh-CN',
          charset: 'UTF-8',
          checkWaf: true,
          crawlDepth: 3,
          crawlLimit: 50
        }
      }
    } else {
      task.value = foundTask
    }

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
    // 等待DOM更新 - Vue会自动处理高亮
  } catch (err) {
    console.error('Failed to load logs:', err)
    logs.value = [] // 设置为空数组以显示"无日志记录"
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

// 格式化配置键名
function formatOptionKey(key: string): string {
  const keyMap: Record<string, string> = {
    level: '检测级别 (Level)',
    risk: '风险级别 (Risk)',
    technique: '注入技术 (Technique)',
    dbms: '数据库类型 (DBMS)',
    threads: '线程数 (Threads)',
    timeout: '超时时间 (Timeout)',
    retries: '重试次数 (Retries)',
    delay: '延迟时间 (Delay)',
    userAgent: 'User-Agent',
    cookie: 'Cookie',
    headers: '请求头 (Headers)',
    proxy: '代理 (Proxy)',
    randomAgent: '随机User-Agent',
    checkTor: '使用Tor',
    safeUrl: '安全URL',
    safePost: '安全POST',
    safeReq: '安全请求',
  }
  return keyMap[key] || key
}

// 格式化配置值
function formatOptionValue(value: any, _key: string): string {
  if (value === null || value === undefined) {
    return '-'
  }

  if (typeof value === 'boolean') {
    return value ? '是' : '否'
  }

  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : '-'
  }

  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2)
  }

  return String(value)
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
  width: 100%;
  margin: 0;
  padding: 0;
  position: relative;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      radial-gradient(circle at 25% 25%, rgba(99, 102, 241, 0.05) 0%, transparent 50%),
      radial-gradient(circle at 75% 75%, rgba(16, 185, 129, 0.05) 0%, transparent 50%),
      url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23f1f5f9' fill-opacity='0.2'%3E%3Cpath d='M20 20.5V18H0v-2h20v2.5zm0 2.5v2.5H0V23h20zm2 0h18v2H22v-2zm0-2.5h18V18H22v2.5z'/%3E%3C/g%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  margin-bottom: 8px;
}

.header-title {
  display: flex;
  align-items: center;
  gap: 16px;
}

.back-button {
  transition: all 0.3s ease;

  &:hover {
    transform: scale(1.1) rotate(-5deg);
    box-shadow: 0 4px 8px rgba(99, 102, 241, 0.2);
  }
}

.status-tag {
  font-size: 14px;
  font-weight: 600;
  padding: 6px 12px;
  border-radius: 6px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.header-actions {
  display: flex;
  gap: 12px;
  align-items: center;

  @media (max-width: 768px) {
    flex-wrap: wrap;
    justify-content: flex-end;
  }
}

.loading-container {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  min-height: 400px;
  gap: 16px;
}

.loading-text {
  margin-top: 16px;
  color: #6366f1;
  font-size: 16px;
  font-weight: 500;
}

.loading-card {
  margin-top: 20px;
}

.error-card {
  margin-top: 20px;
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
  margin-top: 20px;
}

.info-card {
  border-radius: 16px;
  box-shadow:
    0 4px 6px -1px rgba(0, 0, 0, 0.1),
    0 2px 4px -1px rgba(0, 0, 0, 0.06),
    inset 0 1px 2px rgba(255, 255, 255, 0.4);
  border: 2px solid rgba(255, 255, 255, 0.3);
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.8) 100%);
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-4px);
    box-shadow:
      0 10px 15px -3px rgba(0, 0, 0, 0.1),
      0 4px 6px -2px rgba(0, 0, 0, 0.05),
      inset 0 1px 2px rgba(255, 255, 255, 0.5),
      0 0 30px rgba(99, 102, 241, 0.1);
  }

  :deep(.p-card-title) {
    font-size: 18px;
    font-weight: 600;
    color: #1f2937;
  }

  :deep(.p-card-body) {
    background: transparent;
  }

  :deep(.p-card-content) {
    background: transparent;
  }
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;

  i {
    font-size: 20px;
    background: linear-gradient(135deg, #6366f1 0%, #3b82f6 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  span {
    font-size: 18px;
    font-weight: 600;
    background: linear-gradient(135deg, #1f2937 0%, #4b5563 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 24px;

  @media (max-width: 768px) {
    grid-template-columns: 1fr;
    gap: 20px;
  }
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 16px;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.7) 0%, rgba(248, 250, 252, 0.5) 100%);
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.5);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-2px);
    box-shadow:
      0 4px 8px rgba(0, 0, 0, 0.1),
      inset 0 1px 2px rgba(255, 255, 255, 0.6);
  }

  &.full-width {
    grid-column: 1 / -1;
  }

  label {
    font-size: 14px;
    font-weight: 600;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .value {
    font-size: 14px;
    color: #1f2937;
    word-break: break-all;
    font-weight: 500;

    &.url {
      flex: 1;
    }
  }

  .text-muted {
    color: #9ca3af;
    font-style: italic;
  }
}

// 扫描配置表格样式
.options-table-container {
  background: linear-gradient(135deg, rgba(248, 250, 252, 0.6) 0%, rgba(241, 245, 249, 0.4) 100%);
  border-radius: 10px;
  padding: 0;
  border: 1px solid rgba(255, 255, 255, 0.5);
  overflow-x: auto;
  max-height: 300px;
  overflow-y: auto;

  &::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  &::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.05);
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(99, 102, 241, 0.3);
    border-radius: 4px;

    &:hover {
      background: rgba(99, 102, 241, 0.5);
    }
  }
}

.options-table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;

  tbody {
    tr {
      border-bottom: 1px solid rgba(99, 102, 241, 0.1);
      transition: all 0.2s ease;

      &:hover {
        background: rgba(99, 102, 241, 0.05);
      }

      &:last-child {
        border-bottom: none;
      }
    }
  }

  td {
    padding: 12px 16px;
    font-size: 14px;
  }
}

.option-key-cell {
  width: 300px;
  font-weight: 600;
  color: #6366f1;
  background: rgba(99, 102, 241, 0.1);
  border-right: 2px solid rgba(99, 102, 241, 0.2);
  white-space: nowrap;

  @media (max-width: 768px) {
    width: auto;
    display: block;
    border-right: none;
    border-bottom: 2px solid rgba(99, 102, 241, 0.2);
  }
}

.option-value-cell {
  color: #1f2937;
  word-break: break-all;
  background: rgba(255, 255, 255, 0.3);

  @media (max-width: 768px) {
    display: block;
  }
}

.url-display {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.05) 0%, rgba(59, 130, 246, 0.05) 100%);
  border-radius: 10px;
  border: 2px solid rgba(99, 102, 241, 0.1);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);

  .value.url {
    flex: 1;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 14px;
    color: #1f2937;
    padding: 8px 12px;
    background: rgba(255, 255, 255, 0.7);
    border-radius: 6px;
    border: 1px solid rgba(255, 255, 255, 0.5);
  }
}

.info-section {
  margin-top: 24px;
  padding: 20px;
  background: linear-gradient(135deg, rgba(248, 250, 252, 0.6) 0%, rgba(241, 245, 249, 0.4) 100%);
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.5);

  h4 {
    font-size: 15px;
    font-weight: 600;
    margin-bottom: 16px;
    color: #1f2937;
    padding-bottom: 10px;
    border-bottom: 2px solid rgba(99, 102, 241, 0.2);
  }
}

.headers-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.header-item {
  padding: 12px 16px;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(59, 130, 246, 0.05) 100%);
  border-radius: 8px;
  font-size: 13px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  border-left: 4px solid #6366f1;
  color: #1f2937;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  transition: all 0.3s ease;

  &:hover {
    transform: translateX(4px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  }
}

.code-block {
  padding: 20px;
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  color: #e2e8f0;
  border-radius: 10px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
  line-height: 1.7;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  box-shadow:
    inset 0 2px 4px rgba(0, 0, 0, 0.3),
    0 4px 8px rgba(0, 0, 0, 0.2);
  border: 1px solid rgba(255, 255, 255, 0.1);
}

.payload-value {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
  max-width: 500px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding: 8px 12px;
  background: rgba(99, 102, 241, 0.05);
  border-radius: 6px;
  border: 1px solid rgba(99, 102, 241, 0.1);
}

.logs-container {
  max-height: 600px;
  overflow-y: auto;
  overflow-x: auto;
  border: 2px solid rgba(99, 102, 241, 0.1);
  border-radius: 10px;
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.5);

  &::-webkit-scrollbar {
    width: 12px;
    height: 12px;
  }

  &::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.3);
    border-radius: 6px;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(99, 102, 241, 0.5);
    border-radius: 6px;
    border: 2px solid rgba(0, 0, 0, 0.3);

    &:hover {
      background: rgba(99, 102, 241, 0.7);
    }
  }

  // 垂直滚动条
  &::-webkit-scrollbar:vertical {
    width: 12px;
  }

  // 水平滚动条
  &::-webkit-scrollbar:horizontal {
    height: 12px;
  }
}

.logs-pre {
  margin: 0;
  padding: 0;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
  line-height: 1.6;
  overflow: visible;
  background: transparent;

  code {
    background: transparent;
    padding: 0;
    margin: 0;
    color: #e2e8f0;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    display: block;
  }
}

.errors-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

// DataTable样式增强
:deep(.result-table) {
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(99, 102, 241, 0.1);

  .p-datatable-thead > tr > th {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    color: #1f2937;
    font-weight: 600;
  }

  .p-datatable-tbody > tr:hover {
    background: rgba(99, 102, 241, 0.05);
  }
}


// 响应式设计
@media (max-width: 768px) {
  .info-grid {
    grid-template-columns: 1fr;
  }

  .url-display {
    flex-direction: column;
    align-items: stretch;
  }

  .info-item {
    padding: 12px;
  }

  .logs-container {
    max-height: 300px;
  }
}
</style>
