/**
 * 任务状态管理
 */
import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  getTaskList as getTaskListApi,
  addTask as addTaskApi,
  deleteTask as deleteTaskApi,
  stopTask as stopTaskApi,
} from '@/api/task'
import type { Task, TaskFilters } from '@/types/task'

export const useTaskStore = defineStore('task', () => {
  // 状态
  const taskList = ref<Task[]>([])
  const currentTask = ref<Task | null>(null)
  const loading = ref<boolean>(false)
  const filters = ref<TaskFilters>({})

  // 动作
  async function fetchTaskList(): Promise<void> {
    loading.value = true
    try {
      const data = await getTaskListApi()
      taskList.value = data
    } catch (error) {
      console.error('Failed to fetch task list:', error)
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
      console.error('Failed to create task:', error)
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
      console.error('Failed to delete task:', error)
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
      console.error('Failed to stop task:', error)
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

  return {
    // 状态
    taskList,
    currentTask,
    loading,
    filters,
    // 动作
    fetchTaskList,
    createTask,
    deleteTask,
    stopTask,
    updateTaskStatus,
    setCurrentTask,
    setFilters,
  }
})
