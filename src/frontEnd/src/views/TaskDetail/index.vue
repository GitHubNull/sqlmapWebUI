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
      <TabView class="detail-tabs">
        <!-- 基础信息 -->
        <TabPanel>
          <template #header>
            <div class="tab-header">
              <i class="pi pi-info-circle"></i>
              <span>基础信息</span>
            </div>
          </template>
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
        </TabPanel>

        <!-- HTTP请求信息 -->
        <TabPanel>
          <template #header>
            <div class="tab-header">
              <i class="pi pi-globe"></i>
              <span>HTTP请求信息</span>
            </div>
          </template>
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
        </TabPanel>

        <!-- 扫描配置 -->
        <TabPanel>
          <template #header>
            <div class="tab-header">
              <i class="pi pi-cog"></i>
              <span>扫描配置</span>
            </div>
          </template>
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
        </TabPanel>

        <!-- 扫描结果 -->
        <TabPanel v-if="payloadData && payloadData.length > 0">
          <template #header>
            <div class="tab-header">
              <i class="pi pi-chart-bar"></i>
              <span>扫描结果</span>
            </div>
          </template>
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
        </TabPanel>

        <!-- 任务日志 -->
        <TabPanel>
          <template #header>
            <div class="tab-header">
              <i class="pi pi-file"></i>
              <span>任务日志</span>
            </div>
          </template>
          <div v-if="loadingLogs" class="loading-small">
            <ProgressSpinner style="width: 30px; height: 30px" />
          </div>
          <div v-else-if="logs && Array.isArray(logs) && logs.length > 0" class="logs-wrapper">
            <div class="log-stats">
              <div class="stat-item">
                <i class="pi pi-list"></i>
                <span>总行数：{{ logs.length }}</span>
              </div>
              <div class="stat-item">
                <i class="pi pi-filter"></i>
                <span>INFO: {{ logs.filter(l => l.includes('[INFO]')).length }}</span>
              </div>
              <div class="stat-item">
                <i class="pi pi-exclamation-triangle"></i>
                <span>警告: {{ logs.filter(l => l.includes('[WARNING]')).length }}</span>
              </div>
              <div class="stat-item">
                <i class="pi pi-times-circle"></i>
                <span>错误: {{ logs.filter(l => l.includes('[ERROR]')).length }}</span>
              </div>
            </div>
            <div class="log-actions" style="margin-bottom: 16px;">
              <Button
                v-if="logs && logs.length > 0"
                icon="pi pi-copy"
                :label="'复制全部日志'"
                text
                @click="copyLogsToClipboard"
                class="p-button-sm"
              />
              <Button
                icon="pi pi-refresh"
                :label="'刷新'"
                text
                @click="() => loadLogs()"
                :loading="loadingLogs"
                class="p-button-sm"
              />
            </div>
            <div class="logs-container" ref="logsContainerRef">
              <pre class="logs-pre">
                <code v-html="generateHighlightedLogs()"></code>
              </pre>
            </div>
          </div>
          <span v-else-if="logs === null" class="text-muted">正在加载日志...</span>
          <span v-else class="text-muted">无日志记录</span>
        </TabPanel>

        <!-- 错误记录 -->
        <TabPanel v-if="errors && errors.length > 0">
          <template #header>
            <div class="tab-header">
              <i class="pi pi-exclamation-triangle"></i>
              <span>错误记录</span>
            </div>
          </template>
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
        </TabPanel>
      </TabView>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import type { Task } from '@/types/task'
import { formatDateTime } from '@/utils/format'
import { highlightLogContent, getLogStats, type LogStats } from '@/utils/logHighlighter'
import {
  getTaskLogs,
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
const logs = ref<string[] | null>(null)
const logsHtml = ref<string>('') // 存储高亮后的HTML
const errors = ref<string[]>([])

const logsContainerRef = ref<HTMLElement | null>(null)

// 计算属性：日志统计信息
const logStats = computed<LogStats>(() => {
  return getLogStats(logs.value || [])
})

// 计算属性：高亮后的日志HTML
const highlightedLogsHtml = computed(() => {
  if (!logs.value || logs.value.length === 0) {
    return ''
  }
  return highlightLogContent(logs.value)
})

// 原有的生成高亮日志函数（保持向后兼容）
const generateHighlightedLogs = () => {
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
        .replace(/\[INFO\]/g, '<span style="background-color:#0ea5e9 !important; color:#ffffff !important; font-weight:bold !important; padding:2px 6px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:10px !important; border:1px solid #0284c7 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[INFO]</span>')
        // 高亮DEBUG - 使用最强内联样式
        .replace(/\[DEBUG\]/g, '<span style="background-color:#8b5cf6 !important; color:#ffffff !important; font-weight:bold !important; padding:2px 6px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:10px !important; border:1px solid #7c3aed !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[DEBUG]</span>')
        // 高亮WARNING - 使用最强内联样式
        .replace(/\[WARNING\]/g, '<span style="background-color:#f59e0b !important; color:#000000 !important; font-weight:bold !important; padding:2px 6px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:10px !important; border:1px solid #d97706 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(255,255,255,0.3) !important;">[WARNING]</span>')
        // 高亮ERROR - 使用最强内联样式
        .replace(/\[ERROR\]/g, '<span style="background-color:#ef4444 !important; color:#ffffff !important; font-weight:bold !important; padding:2px 6px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:10px !important; border:1px solid #dc2626 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[ERROR]</span>')
        // 高亮CRITICAL - 添加新级别
        .replace(/\[CRITICAL\]/g, '<span style="background-color:#dc2626 !important; color:#ffffff !important; font-weight:bold !important; padding:2px 6px !important; border-radius:4px !important; font-size:12px !important; display:inline-block !important; margin-right:10px !important; border:1px solid #b91c1c !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; text-shadow:0 1px 2px rgba(0,0,0,0.3) !important;">[CRITICAL]</span>')
        // 高亮URL - 使用最强内联样式
        .replace(/https?:\/\/[^\s\)\]]+/g, '<span style="color:#3b82f6 !important; text-decoration:underline !important; font-weight:500 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; background-color:rgba(59, 130, 246, 0.1) !important; padding:0 2px !important; border-radius:3px !important; cursor:pointer !important; transition:all 0.2s ease !important;" onmouseover="this.style.backgroundColor=\'rgba(59, 130, 246, 0.2)\'" onmouseout="this.style.backgroundColor=\'rgba(59, 130, 246, 0.1)\'">$&</span>')
        // 高亮文件路径 - 使用最强内联样式
        .replace(/[\w\-]+\.(py|js|ts|php|asp|aspx|jsp|java|cs|cpp|c|h|hpp|json|xml|yml|yaml|ini|conf|config)/g, '<span style="color:#10b981 !important; font-weight:500 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; background-color:rgba(16, 185, 129, 0.1) !important; padding:0 3px !important; border-radius:3px !important;">$&</span>')
        // 高亮时间戳 - 新增
        .replace(/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g, '<span style="color:#06b6d4 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important; background-color:rgba(6, 182, 212, 0.1) !important; padding:0 3px !important; border-radius:3px !important; font-weight:500 !important;">$&</span>')
        // 高亮SQL语句 - 新增
        .replace(/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|ORDER BY|GROUP BY|HAVING|LIMIT|JOIN|INNER JOIN|LEFT JOIN|RIGHT JOIN|ON|AS|LIKE|IN|NOT IN|IS NULL|IS NOT NULL|COUNT|SUM|AVG|MAX|MIN|CREATE|TABLE|ALTER|DROP|INDEX)\b/gi, '<span style="color:#ec4899 !important; font-weight:500 !important; font-family:\'Monaco\',\'Menlo\',\'Ubuntu Mono\',monospace !important;">$&</span>')

      // 构建完整的行HTML，优化行号和内容样式
      html += `<div style="display:flex; align-items:flex-start; margin:0; white-space:pre; border-bottom:1px solid rgba(148, 163, 184, 0.1); background:${index % 2 === 0 ? 'rgba(15, 23, 42, 0.5)' : 'rgba(15, 23, 42, 0.3)'};">
        <span style="flex-shrink:0; width:50px; text-align:right; padding:8px 12px; color:#94a3b8; background-color:rgba(15, 23, 42, 0.7); border-right:1px solid rgba(148, 163, 184, 0.2); font-family:'Monaco','Menlo','Ubuntu Mono',monospace; font-size:11px; line-height:1.5; user-select:none; font-weight:600;">${lineNumber.toString().padStart(3, ' ')}</span>
        <span style="flex:1; padding:8px 16px; white-space:pre-wrap; word-break:break-word; color:#e2e8f0; font-family:'Monaco','Menlo','Ubuntu Mono',monospace; font-size:13px; line-height:1.5;">${highlightedLine}</span>
      </div>`
    })

    return html
  } catch (error) {
    console.error('生成高亮日志时出错:', error)
    return logs.value.join('\n')
  }
}

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

function copyLogsToClipboard() {
  if (!logs.value || !Array.isArray(logs.value) || logs.value.length === 0) {
    toast.add({
      severity: 'warn',
      summary: '提示',
      detail: '没有日志可复制',
      life: 2000,
    })
    return
  }

  const logsText = logs.value.join('\n')
  navigator.clipboard.writeText(logsText).then(() => {
    toast.add({
      severity: 'success',
      summary: '成功',
      detail: `已复制 ${logs.value.length} 行日志到剪贴板`,
      life: 2000,
    })
  }).catch(err => {
    console.error('复制日志失败:', err)
    toast.add({
      severity: 'error',
      summary: '错误',
      detail: '复制失败',
      life: 2000,
    })
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

.log-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;

  .log-action-btn {
    transition: all 0.3s ease;

    &:hover {
      transform: scale(1.1) rotate(5deg);
      box-shadow: 0 4px 8px rgba(99, 102, 241, 0.2);
    }
  }
}

.logs-wrapper {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.log-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
  padding: 16px;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(59, 130, 246, 0.04) 100%);
  border-radius: 8px;
  border: 1px solid rgba(99, 102, 241, 0.15);
  backdrop-filter: blur(5px);

  .stat-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: #e2e8f0;
    padding: 6px 12px;
    background: rgba(15, 23, 42, 0.4);
    border-radius: 6px;
    border: 1px solid rgba(148, 163, 184, 0.1);

    i {
      font-size: 15px;
      color: #6366f1;
      font-weight: 600;
    }

    span {
      font-weight: 500;
    }
  }
}

:deep(.p-card-title) {
  width: 100%;

  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;

    & > i:first-child,
    & > span:first-of-type {
      flex-shrink: 0;
    }
  }
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

// TabView 样式增强
.detail-tabs {
  :deep(.p-tabview-nav) {
    border: none;
    background: transparent;
    display: flex;
    gap: 16px;
    padding: 0 16px;
  }

  :deep(.p-tabview-nav li) {
    margin: 0;
    background: transparent;
    flex: 0 0 auto;
  }

  :deep(.p-tabview-nav-link) {
    border: none !important;
    border-top: 3px solid transparent !important;
    background: linear-gradient(145deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%) !important;
    border-radius: 10px 10px 0 0 !important;
    padding: 14px 28px !important;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);

    &:hover {
      background: linear-gradient(145deg, rgba(255, 255, 255, 0.95) 0%, rgba(248, 250, 252, 0.8) 100%) !important;
      transform: translateY(-3px);
      box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
      border-top: 3px solid rgba(99, 102, 241, 0.3) !important;
    }

    .p-tabview-title {
      color: #4b5563;
      font-weight: 600;
      transition: all 0.3s ease;
    }

    i {
      transition: all 0.3s ease;
    }
  }

  :deep(.p-tabview-nav li.p-highlight .p-tabview-nav-link) {
    background: linear-gradient(135deg, #6366f1 0%, #3b82f6 100%) !important;
    border-top: 3px solid #0ea5e9 !important;
    box-shadow: 0 8px 16px rgba(99, 102, 241, 0.4), 0 0 20px rgba(99, 102, 241, 0.2) !important;
    transform: translateY(-4px);

    .p-tabview-title {
      color: white !important;
      font-weight: 700;
      text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
    }

    i {
      color: white !important;
      filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.3));
    }
  }

  :deep(.p-tabview-panels) {
    background: linear-gradient(145deg, rgba(255, 255, 255, 0.95) 0%, rgba(248, 250, 252, 0.85) 100%);
    border: 2px solid rgba(255, 255, 255, 0.4);
    border-radius: 0 0 16px 16px;
    box-shadow:
      0 8px 12px -2px rgba(0, 0, 0, 0.1),
      0 4px 6px -2px rgba(0, 0, 0, 0.05),
      inset 0 1px 2px rgba(255, 255, 255, 0.6);
    padding: 32px;
    margin-top: -4px;
  }

  :deep(.p-tabview-panel) {
    background: transparent;
    padding: 0;
  }
}

.tab-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 6px 12px;

  i {
    font-size: 18px;
    color: #6366f1;
    transition: all 0.3s ease;
  }

  span {
    font-size: 16px;
    font-weight: 600;
    transition: all 0.3s ease;
  }
}

// 响应式Tab样式
@media (max-width: 768px) {
  .detail-tabs {
    :deep(.p-tabview-nav) {
      flex-wrap: nowrap;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      padding: 0 12px;
      gap: 8px;
    }

    :deep(.p-tabview-nav-link) {
      padding: 12px 16px !important;
      min-width: auto;
    }

    :deep(.p-tabview-panels) {
      padding: 20px;
    }

    .tab-header {
      gap: 8px;
      padding: 4px 8px;

      i {
        font-size: 16px;
      }

      span {
        font-size: 14px;
      }
    }
  }
}

// 暗黑模式Tab样式
.dark-mode {
  .detail-tabs {
    :deep(.p-tabview-nav-link) {
      background: linear-gradient(145deg, rgba(51, 65, 85, 0.8) 0%, rgba(30, 41, 59, 0.6) 100%) !important;
      border-top: 3px solid transparent !important;

      .p-tabview-title {
        color: #e2e8f0 !important;
      }

      i {
        color: #a5b4fc !important;
      }

      &:hover {
        background: linear-gradient(145deg, rgba(71, 85, 105, 0.9) 0%, rgba(51, 65, 85, 0.7) 100%) !important;
        border-top: 3px solid rgba(99, 102, 241, 0.4) !important;
      }
    }

    :deep(.p-tabview-nav li.p-highlight .p-tabview-nav-link) {
      background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%) !important;
      border-top: 3px solid #0ea5e9 !important;
      box-shadow: 0 8px 16px rgba(99, 102, 241, 0.5), 0 0 25px rgba(99, 102, 241, 0.3) !important;

      .p-tabview-title {
        font-weight: 700 !important;
        text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5) !important;
      }

      i {
        filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.5));
      }
    }

    :deep(.p-tabview-panels) {
      background: linear-gradient(145deg, #334155 0%, #1e293b 100%);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
  }
}
</style>
