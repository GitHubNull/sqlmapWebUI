/**
 * 任务状态管理
 */
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import {
  getTaskList as getTaskListApi,
  addTask as addTaskApi,
  deleteTask as deleteTaskApi,
  stopTask as stopTaskApi,
  batchDeleteTasks as batchDeleteTasksApi,
  flushTasks as flushTasksApi,
} from '@/api/task'
import type { Task, TaskFilters, TaskStats, SortConfig, TaskDetail } from '@/types/task'
import { TaskStatus } from '@/types/task'

export const useTaskStore = defineStore('task', () => {
  // 状态
  const taskList = ref<Task[]>([])
  const currentTask = ref<Task | null>(null)
  const currentTaskDetail = ref<TaskDetail | null>(null)
  const loading = ref<boolean>(false)
  const filters = ref<TaskFilters>({})
  const sortConfig = ref<SortConfig>({ field: 'createTime', order: 'desc' })
  const selectedTaskIds = ref<string[]>([])

  // 动作
  async function fetchTaskList(): Promise<void> {
    loading.value = true
    try {
      const data = await getTaskListApi()
      taskList.value = data
    } catch (error) {
      // 错误已在request.ts中统一处理，这里只需记录调试信息
      console.debug('fetchTaskList error:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  async function createTask(taskData: Partial<Task>): Promise<Task> {
    loading.value = true
    try {
      const result = await addTaskApi(taskData)
      // 刷新任务列表
      await fetchTaskList()
      // 返回新创建的任务
      const newTask = taskList.value.find((t) => t.taskid === result.taskid)
      return newTask || ({} as Task)
    } catch (error) {
      console.debug('createTask error:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  async function deleteTask(taskId: string): Promise<void> {
    loading.value = true
    try {
      await deleteTaskApi(taskId)
      // 从列表中移除
      taskList.value = taskList.value.filter((t) => t.taskid !== taskId)
    } catch (error) {
      console.debug('deleteTask error:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  async function stopTask(taskId: string): Promise<void> {
    loading.value = true
    try {
      await stopTaskApi(taskId)
      // 刷新任务列表
      await fetchTaskList()
    } catch (error) {
      console.debug('stopTask error:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  function updateTaskStatus(taskId: string, status: number): void {
    const task = taskList.value.find((t) => t.taskid === taskId)
    if (task) {
      task.status = status
    }
  }

  function setCurrentTask(task: Task | null): void {
    currentTask.value = task
  }

  function setFilters(newFilters: TaskFilters): void {
    filters.value = { ...filters.value, ...newFilters }
  }

  function clearFilters(): void {
    filters.value = {}
  }

  function setSortConfig(config: SortConfig): void {
    sortConfig.value = config
  }

  function setSelectedTaskIds(ids: string[]): void {
    selectedTaskIds.value = ids
  }

  function toggleTaskSelection(taskId: string): void {
    const index = selectedTaskIds.value.indexOf(taskId)
    if (index > -1) {
      selectedTaskIds.value.splice(index, 1)
    } else {
      selectedTaskIds.value.push(taskId)
    }
  }

  function clearSelection(): void {
    selectedTaskIds.value = []
  }

  // 计算属性 - 统计数据
  const taskStats = computed<TaskStats>(() => {
    const stats: TaskStats = {
      total: taskList.value.length,
      running: 0,
      pending: 0,
      success: 0,
      failed: 0,
      stopped: 0,
      terminated: 0,
      injectable: 0,
      nonInjectable: 0,
    }

    taskList.value.forEach((task) => {
      switch (task.status) {
        case TaskStatus.RUNNING:
          stats.running++
          break
        case TaskStatus.PENDING:
          stats.pending++
          break
        case TaskStatus.SUCCESS:
          stats.success++
          break
        case TaskStatus.FAILED:
          stats.failed++
          break
        case TaskStatus.STOPPED:
          stats.stopped++
          break
        case TaskStatus.TERMINATED:
          stats.terminated++
          break
      }

      // 统计注入状态
      if (task.injected === true) {
        stats.injectable++
      } else if (task.injected === false && task.status === TaskStatus.SUCCESS) {
        stats.nonInjectable++
      }
    })

    return stats
  })

  // 计算属性 - 过滤后的任务列表
  const filteredTaskList = computed<Task[]>(() => {
    let result = [...taskList.value]

    // URL关键字过滤
    if (filters.value.urlKeyword) {
      const keyword = filters.value.urlKeyword.toLowerCase()
      result = result.filter((task) => task.scanUrl.toLowerCase().includes(keyword))
    }

    // 报文关键字过滤
    if (filters.value.messageKeyword) {
      const keyword = filters.value.messageKeyword.toLowerCase()
      result = result.filter((task) => {
        // 搜索headers
        const headersMatch = task.headers?.some((header) =>
          header.toLowerCase().includes(keyword)
        )
        // 搜索body
        const bodyMatch = task.body?.toLowerCase().includes(keyword)
        // 搜索host
        const hostMatch = task.host.toLowerCase().includes(keyword)
        return headersMatch || bodyMatch || hostMatch
      })
    }

    // 状态过滤
    if (filters.value.status !== undefined) {
      result = result.filter((task) => task.status === filters.value.status)
    }

    // 时间范围过滤
    if (filters.value.startDate) {
      result = result.filter((task) => task.createTime >= filters.value.startDate!)
    }
    if (filters.value.endDate) {
      result = result.filter((task) => task.createTime <= filters.value.endDate!)
    }

    // 仅显示可注入
    if (filters.value.injectableOnly) {
      result = result.filter((task) => task.injected === true)
    }

    return result
  })

  // 计算属性 - 排序后的任务列表
  const sortedTaskList = computed<Task[]>(() => {
    if (!sortConfig.value.order) {
      return filteredTaskList.value
    }

    const result = [...filteredTaskList.value]
    const { field, order } = sortConfig.value
    const multiplier = order === 'asc' ? 1 : -1

    result.sort((a, b) => {
      let valueA: any
      let valueB: any

      switch (field) {
        case 'createTime':
          valueA = new Date(a.createTime).getTime()
          valueB = new Date(b.createTime).getTime()
          break
        case 'taskid':
          valueA = a.taskid
          valueB = b.taskid
          break
        case 'status':
          // 状态排序优先级: RUNNING > PENDING > FAILED > STOPPED > SUCCESS > TERMINATED
          const statusPriority: Record<TaskStatus, number> = {
            [TaskStatus.RUNNING]: 6,
            [TaskStatus.PENDING]: 5,
            [TaskStatus.FAILED]: 4,
            [TaskStatus.STOPPED]: 3,
            [TaskStatus.SUCCESS]: 2,
            [TaskStatus.TERMINATED]: 1,
          }
          valueA = statusPriority[a.status] || 0
          valueB = statusPriority[b.status] || 0
          break
        case 'urlLength':
          valueA = a.scanUrl.length
          valueB = b.scanUrl.length
          break
        case 'errors':
          valueA = a.errors || 0
          valueB = b.errors || 0
          break
        case 'logs':
          valueA = a.logs || 0
          valueB = b.logs || 0
          break
        default:
          valueA = (a as any)[field]
          valueB = (b as any)[field]
      }

      if (valueA < valueB) return -1 * multiplier
      if (valueA > valueB) return 1 * multiplier
      return 0
    })

    return result
  })

  // 批量删除任务
  async function batchDeleteTasks(taskIds: string[]): Promise<void> {
    loading.value = true
    try {
      await batchDeleteTasksApi(taskIds)
      // 从列表中移除
      taskList.value = taskList.value.filter((t) => !taskIds.includes(t.taskid))
      // 清空选中
      clearSelection()
    } catch (error) {
      console.debug('batchDeleteTasks error:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  // 删除全部任务
  async function deleteAllTasks(): Promise<void> {
    loading.value = true
    try {
      await flushTasksApi()
      // 清空列表
      taskList.value = []
      // 清空选中
      clearSelection()
    } catch (error) {
      console.debug('deleteAllTasks error:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  return {
    // 状态
    taskList,
    currentTask,
    currentTaskDetail,
    loading,
    filters,
    sortConfig,
    selectedTaskIds,
    // 计算属性
    taskStats,
    filteredTaskList,
    sortedTaskList,
    // 动作
    fetchTaskList,
    createTask,
    deleteTask,
    stopTask,
    updateTaskStatus,
    setCurrentTask,
    setFilters,
    clearFilters,
    setSortConfig,
    setSelectedTaskIds,
    toggleTaskSelection,
    clearSelection,
    batchDeleteTasks,
    deleteAllTasks,
  }
})
