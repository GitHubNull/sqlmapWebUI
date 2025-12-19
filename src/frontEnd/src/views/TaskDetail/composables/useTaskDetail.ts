/**
 * TaskDetail 页面组合式函数
 * 包含所有数据加载和管理逻辑
 */
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import type { Task } from '@/types/task'
import { highlightLogContent, getLogStats, type LogStats } from '@/utils/logHighlighter'
import { formatHttpRequest, highlightHttpRequest, filterHttpRequest } from '@/utils/requestFormatter'
import {
  getTaskLogs,
  getHttpRequestInfo,
  getPayloadDetail,
  getErrors
} from '@/api/task'

// 生成随机body（用于Mock数据）
function generateMockBody(): string | undefined {
  const bodyTypes = [
    // POST表单数据（30%）
    () => {
      const params: string[] = []
      const paramCount = Math.floor(Math.random() * 5) + 3
      for (let i = 0; i < paramCount; i++) {
        const keys = ['username', 'password', 'email', 'id', 'name', 'value', 'action', 'page', 'limit']
        const key = keys[Math.floor(Math.random() * keys.length)]
        const value = Math.random().toString(36).substring(2, 10)
        params.push(`${key}=${value}`)
      }
      return params.join('&')
    },
    // JSON数据（30%）
    () => {
      return JSON.stringify({
        user: 'testUser',
        id: Math.floor(Math.random() * 1000),
        active: true,
        data: Math.random().toString(36).substring(2, 15)
      }, null, 2)
    },
    // XML数据（20%）
    () => {
      return `<?xml version="1.0" encoding="UTF-8"?>
<request>
  <id>${Math.floor(Math.random() * 1000)}</id>
  <name>test</name>
</request>`
    },
    // 没有body（20%）
    () => undefined
  ]
  const randomType = bodyTypes[Math.floor(Math.random() * bodyTypes.length)]
  return randomType ? randomType() : undefined
}

export function useTaskDetail() {
  const route = useRoute()
  const router = useRouter()
  const confirm = useConfirm()
  const toast = useToast()
  const taskStore = useTaskStore()

  // 状态变量
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
  const errors = ref<string[]>([])

  // HTTP请求报文相关状态
  const httpRequestSearch = ref('')
  const showOnlyMatches = ref(false)

  // 日志搜索过滤相关状态
  const logSearchQuery = ref('')
  const logLevelFilter = ref<string | null>(null)
  const logTimeRangeFilter = ref('')
  const logSourceFilter = ref('')
  const logUseRegex = ref(false)
  const logCaseSensitive = ref(false)
  const logInvertMatch = ref(false)
  const showAdvancedLogSearch = ref(false)

  // 计算属性：格式化HTTP请求报文
  const httpRequest = computed(() => {
    if (!httpInfo.value && !task.value) {
      return ''
    }
    return formatHttpRequest(httpInfo.value, task.value)
  })

  // 计算属性：高亮后的HTTP请求报文HTML
  const highlightedHttpRequest = computed(() => {
    if (!httpRequest.value || !httpRequest.value.trim()) {
      return ''
    }

    const lines = httpRequest.value.split('\n')

    // 应用过滤（如果启用）
    const filteredLines = showOnlyMatches.value && httpRequestSearch.value.trim()
      ? filterHttpRequest(lines, httpRequestSearch.value.trim())
      : lines

    // 高亮显示（带搜索关键词高亮）
    return highlightHttpRequest(filteredLines, httpRequestSearch.value.trim())
  })

  // 计算属性：过滤后的日志
  const filteredLogs = computed(() => {
    if (!logs.value || logs.value.length === 0) {
      return []
    }

    const searchQuery = logSearchQuery.value.trim()
    const levelFilter = logLevelFilter.value
    const timeFilter = logTimeRangeFilter.value.trim()
    const sourceFilter = logSourceFilter.value.trim()

    return logs.value.filter((line) => {
      let match = true

      // 关键词搜索
      if (searchQuery) {
        let lineMatches = false
        try {
          if (logUseRegex.value) {
            // 使用正则表达式
            const flags = logCaseSensitive.value ? 'g' : 'gi'
            const regex = new RegExp(searchQuery, flags)
            lineMatches = regex.test(line)
          } else {
            // 普通字符串搜索
            if (logCaseSensitive.value) {
              lineMatches = line.includes(searchQuery)
            } else {
              lineMatches = line.toLowerCase().includes(searchQuery.toLowerCase())
            }
          }

          // 处理反转匹配
          if (logInvertMatch.value) {
            lineMatches = !lineMatches
          }
        } catch (e) {
          // 正则表达式错误时，回退到简单搜索
          if (logCaseSensitive.value) {
            lineMatches = line.includes(searchQuery)
          } else {
            lineMatches = line.toLowerCase().includes(searchQuery.toLowerCase())
          }

          if (logInvertMatch.value) {
            lineMatches = !lineMatches
          }
        }

        match = match && lineMatches
      }

      // 日志级别过滤
      if (levelFilter && match) {
        const levelPatterns: Record<string, string[]> = {
          'INFO': ['[INFO]'],
          'WARNING': ['[WARNING]', '[WARN]'],
          'ERROR': ['[ERROR]', '[ERR]'],
          'DEBUG': ['[DEBUG]', '[DBG]'],
          'CRITICAL': ['[CRITICAL]', '[CRIT]']
        }

        const patterns = levelPatterns[levelFilter] || []
        const levelMatches = patterns.some(pattern =>
          logCaseSensitive.value
            ? line.includes(pattern)
            : line.toLowerCase().includes(pattern.toLowerCase())
        )
        match = match && levelMatches
      }

      // 日志来源过滤
      if (sourceFilter && match) {
        match = logCaseSensitive.value
          ? line.includes(sourceFilter)
          : line.toLowerCase().includes(sourceFilter.toLowerCase())
      }

      // TODO: 时间范围过滤（需要日志包含时间戳）
      if (timeFilter && match) {
        // 简单的时间过滤实现（根据日志中的日期格式灵活匹配）
        const timePattern = /\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}/
        const matchResult = line.match(timePattern)

        if (matchResult) {
          // 解析时间过滤器（支持多种格式）
          const filterRange = ['-', ' '].find((separator: string) => timeFilter.includes(separator)) || '-'
          const parts = timeFilter.split(filterRange)
          if (parts.length === 2) {
            // TODO: 实现时间范围比较
            // 当前简化实现：检查日志中是否包含时间字符串
            const containsTime = timeFilter.split(/[-\s]/).every(part =>
              part.trim() === '' || line.includes(part.trim())
            )
            match = match && containsTime
          } else {
            // 简化的包含检查
            match = match && line.includes(timeFilter)
          }
        }
      }

      return match
    })
  })

  // 计算属性：日志统计信息（基于过滤后的日志）
  const logStats = computed<LogStats>(() => {
    return getLogStats(filteredLogs.value || [])
  })

  // 计算属性：高亮后的日志HTML（基于过滤后的日志）
  const highlightedLogsHtml = computed(() => {
    if (!filteredLogs.value || filteredLogs.value.length === 0) {
      return ''
    }
    return highlightLogContent(filteredLogs.value)
  })

  // 数据加载函数
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
        const mockBody = generateMockBody()
        task.value = {
          taskid: taskId,
          engineid: 1000 + Math.floor(Math.random() * 100),
          scanUrl: 'http://example.com/api/test',
          host: 'example.com',
          status: TaskStatus.SUCCESS,
          createTime: new Date().toISOString(),
          updateTime: new Date().toISOString(),
          injected: true,
          headers: [
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept: application/json, text/plain, */*',
            'Accept-Language: zh-CN,zh;q=0.9',
            mockBody ? `Content-Type: ${mockBody.includes('{') ? 'application/json' : mockBody.includes('<?xml') ? 'application/xml' : mockBody.includes('=') ? 'application/x-www-form-urlencoded' : 'text/plain'}` : ''
          ].filter(Boolean),
          body: mockBody,
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
        // 如果找到的task没有body，添加一个随机body（仅用于测试显示效果）
        if (!task.value.body && Math.random() < 0.7) {
          const mockBody = generateMockBody()
          if (mockBody) {
            task.value.body = mockBody
          }
        }
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

  // 日志搜索过滤相关方法
  function executeLogSearch() {
    // 搜索逻辑已经在computed filteredLogs中实现
    // 这里可以添加额外的搜索逻辑，如过滤结果提示
    if (!logSearchQuery.value.trim() && !logLevelFilter.value &&
        !logTimeRangeFilter.value && !logSourceFilter.value) {
      return
    }

    const matchCount = filteredLogs.value.length
    if (matchCount === 0) {
      toast.add({
        severity: 'info',
        summary: '搜索完成',
        detail: '没有找到匹配的日志',
        life: 3000,
      })
    } else {
      toast.add({
        severity: 'success',
        summary: '搜索完成',
        detail: `找到 ${matchCount} 条匹配的日志`,
        life: 2000,
      })
    }
  }

  function resetLogFilters() {
    logSearchQuery.value = ''
    logLevelFilter.value = null
    logTimeRangeFilter.value = ''
    logSourceFilter.value = ''
    logUseRegex.value = false
    logCaseSensitive.value = false
    logInvertMatch.value = false
    showAdvancedLogSearch.value = false

    toast.add({
      severity: 'success',
      summary: '过滤器已重置',
      detail: '所有搜索过滤条件已清除',
      life: 2000,
    })
  }

  function toggleAdvancedLogSearch() {
    showAdvancedLogSearch.value = !showAdvancedLogSearch.value
  }

  function handleStopTask(event: Event) {
    if (!task.value) return

    confirm.require({
      target: event.currentTarget as HTMLElement,
      group: 'popup',
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

  function handleDeleteTask(event: Event) {
    if (!task.value) return

    confirm.require({
      target: event.currentTarget as HTMLElement,
      group: 'popup',
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
    const logCount = logs.value.length
    navigator.clipboard.writeText(logsText).then(() => {
      toast.add({
        severity: 'success',
        summary: '成功',
        detail: `已复制 ${logCount} 行日志到剪贴板`,
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

  // 生命周期
  onMounted(() => {
    loadTaskDetail()
  })

  return {
    // 状态
    task,
    loading,
    error,
    loadingHttp,
    httpInfo,
    loadingOptions,
    loadingPayload,
    payloadData,
    loadingLogs,
    logs,
    errors,
    httpRequestSearch,
    showOnlyMatches,

    // 日志搜索过滤相关状态
    logSearchQuery,
    logLevelFilter,
    logTimeRangeFilter,
    logSourceFilter,
    logUseRegex,
    logCaseSensitive,
    logInvertMatch,
    showAdvancedLogSearch,

    // 计算属性
    httpRequest,
    highlightedHttpRequest,
    filteredLogs,
    logStats,
    highlightedLogsHtml,

    // 方法
    loadTaskDetail,
    loadHttpInfo,
    loadPayloadDetail,
    loadLogs,
    loadErrors,
    refreshData,
    getStatusLabel,
    getStatusSeverity,
    copyToClipboard,
    executeLogSearch,
    resetLogFilters,
    toggleAdvancedLogSearch,
    handleStopTask,
    handleDeleteTask,
    copyLogsToClipboard,
  }
}
