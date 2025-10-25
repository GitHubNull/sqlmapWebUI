<template>
  <div class="task-list-page">
    <Card>
      <template #title>
        <div class="flex-between">
          <span>任务列表 (共 {{ taskStore.taskList.length }} 条)</span>
          <Button label="刷新" icon="pi pi-refresh" @click="fetchTasks" :loading="taskStore.loading" />
        </div>
      </template>
      <template #content>
        <!-- 搜索过滤面板 -->
        <TaskFilter 
          :filters="taskStore.filters"
          :filteredCount="taskStore.sortedTaskList.length"
          :totalCount="taskStore.taskList.length"
          @update:filters="handleFilterChange"
        />
        
        <!-- 批量操作栏 -->
        <div v-if="selectedTasks.length > 0" class="batch-actions">
          <div class="batch-info">
            <i class="pi pi-check-circle"></i>
            <span>已选择 {{ selectedTasks.length }} 项</span>
          </div>
          <div class="batch-buttons">
            <Button 
              label="删除选中" 
              icon="pi pi-trash" 
              severity="danger"
              @click="confirmBatchDelete"
            />
            <Button 
              label="删除全部" 
              icon="pi pi-trash" 
              severity="danger"
              outlined
              @click="confirmDeleteAll"
            />
            <Button 
              label="取消选择" 
              icon="pi pi-times" 
              severity="secondary"
              outlined
              @click="clearSelection"
            />
          </div>
        </div>
        
        <DataTable 
          v-model:selection="selectedTasks"
          :value="taskStore.sortedTaskList" 
          :loading="taskStore.loading" 
          stripedRows
          paginator
          :rows="20"
          :rowsPerPageOptions="[10, 20, 50, 100]"
          :scrollable="true"
          scrollHeight="calc(100vh - 450px)"
          :virtualScrollerOptions="{ itemSize: 60 }"
          showGridlines
          responsiveLayout="scroll"
          sortMode="single"
          :sortField="taskStore.sortConfig.field"
          :sortOrder="taskStore.sortConfig.order === 'asc' ? 1 : taskStore.sortConfig.order === 'desc' ? -1 : 0"
          @sort="handleSort"
          dataKey="taskid"
        >
          <!-- 选择列 -->
          <Column selectionMode="multiple" headerStyle="width: 3rem" :exportable="false" frozen />
          <Column field="engineid" header="任务ID" :style="{ minWidth: '100px' }" sortable />
          <Column field="scanUrl" header="扫描URL" :style="{ minWidth: '300px', maxWidth: '400px' }">
            <template #body="{ data }">
              <div class="url-cell" :title="data.scanUrl">
                {{ data.scanUrl }}
              </div>
            </template>
          </Column>
          <Column field="host" header="主机" :style="{ minWidth: '150px' }" />
          <Column field="status" header="状态" :style="{ minWidth: '100px' }" sortable>
            <template #body="{ data }">
              <Tag :value="getStatusLabel(data.status)" :severity="getStatusSeverity(data.status)" />
            </template>
          </Column>
          <Column field="createTime" header="创建时间" :style="{ minWidth: '180px' }" sortable>
            <template #body="{ data }">
              {{ formatDateTime(data.createTime) }}
            </template>
          </Column>
          <Column header="操作" :style="{ minWidth: '150px', width: '150px' }" frozen alignFrozen="right">
            <template #body="{ data }">
              <div class="action-buttons">
                <Button icon="pi pi-eye" @click="viewTask(data)" text rounded v-tooltip.top="'查看详情'" />
                <Button icon="pi pi-stop" @click="stopTask(data.taskid)" text rounded severity="warning" v-if="data.status === 1" v-tooltip.top="'停止任务'" />
                <Button icon="pi pi-trash" @click="deleteTask(data.taskid)" text rounded severity="danger" v-tooltip.top="'删除任务'" />
              </div>
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import type { Task, TaskFilters } from '@/types/task'
import { formatDateTime } from '@/utils/format'
import TaskFilter from '@/components/TaskFilter.vue'

const router = useRouter()
const taskStore = useTaskStore()
const confirm = useConfirm()
const toast = useToast()

// 选中的任务
const selectedTasks = ref<Task[]>([])

// 轮询定时器
let pollingTimer: number | null = null
const POLLING_INTERVAL = 5000 // 5秒

onMounted(() => {
  fetchTasks()
  startPolling()
  
  // 监听页面可见性
  document.addEventListener('visibilitychange', handleVisibilityChange)
})

onUnmounted(() => {
  stopPolling()
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})

// 监听任务列表变化，根据是否有运行中的任务决定是否轮询
watch(
  () => taskStore.taskList,
  (newList) => {
    const hasRunningTasks = newList.some(t => t.status === TaskStatus.RUNNING)
    if (hasRunningTasks && !pollingTimer && !document.hidden) {
      startPolling()
    } else if (!hasRunningTasks && pollingTimer) {
      stopPolling()
    }
  },
  { deep: true }
)

async function fetchTasks() {
  await taskStore.fetchTaskList()
}

// 开始轮询
function startPolling() {
  if (pollingTimer) return
  
  pollingTimer = window.setInterval(async () => {
    // 静默刷新，不显示加载状态
    try {
      await taskStore.fetchTaskList()
    } catch (error) {
      console.error('Polling error:', error)
    }
  }, POLLING_INTERVAL)
}

// 停止轮询
function stopPolling() {
  if (pollingTimer) {
    clearInterval(pollingTimer)
    pollingTimer = null
  }
}

// 处理页面可见性变化
function handleVisibilityChange() {
  if (document.hidden) {
    // 页面隐藏，停止轮询
    stopPolling()
  } else {
    // 页面显示，检查是否需要启动轮询
    const hasRunningTasks = taskStore.taskList.some(t => t.status === TaskStatus.RUNNING)
    if (hasRunningTasks) {
      // 立即刷新一次
      fetchTasks()
      startPolling()
    }
  }
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

function viewTask(task: any) {
  router.push(`/tasks/${task.taskid}`)
}

async function stopTask(taskId: string) {
  await taskStore.stopTask(taskId)
}

async function deleteTask(taskId: string) {
  await taskStore.deleteTask(taskId)
}

function handleFilterChange(filters: TaskFilters) {
  taskStore.setFilters(filters)
}

function handleSort(event: any) {
  const order = event.sortOrder === 1 ? 'asc' : event.sortOrder === -1 ? 'desc' : null
  taskStore.setSortConfig({ field: event.sortField, order })
}

// 清空选择
function clearSelection() {
  selectedTasks.value = []
}

// 确认批量删除
function confirmBatchDelete() {
  // 过滤掉运行中的任务
  const runningTasks = selectedTasks.value.filter(t => t.status === TaskStatus.RUNNING)
  const deletableTasks = selectedTasks.value.filter(t => t.status !== TaskStatus.RUNNING)
  
  if (runningTasks.length > 0) {
    toast.add({
      severity: 'warn',
      summary: '警告',
      detail: `${runningTasks.length} 个运行中的任务已跳过`,
      life: 3000,
    })
  }
  
  if (deletableTasks.length === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '没有可删除的任务',
      life: 3000,
    })
    return
  }
  
  confirm.require({
    message: `确定要删除选中的 ${deletableTasks.length} 个任务吗？此操作不可恢复。`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        const taskIds = deletableTasks.map(t => t.taskid)
        await taskStore.batchDeleteTasks(taskIds)
        selectedTasks.value = []
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: `已删除 ${deletableTasks.length} 个任务`,
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '删除失败，请重试',
          life: 3000,
        })
      }
    },
  })
}

// 确认删除全部
function confirmDeleteAll() {
  const totalCount = taskStore.taskList.length
  
  if (totalCount === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '没有任务可删除',
      life: 3000,
    })
    return
  }
  
  confirm.require({
    message: `这将删除系统中的所有 ${totalCount} 个任务，包括正在运行的任务！

此操作不可恢复，所有扫描结果和日志将永久丢失！

请输入“删除全部”以确认此操作`,
    header: '危险操作！删除所有任务',
    icon: 'pi pi-exclamation-circle',
    acceptLabel: '确认删除',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await taskStore.deleteAllTasks()
        selectedTasks.value = []
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: '已删除所有任务',
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '删除失败，请重试',
          life: 3000,
        })
      }
    },
  })
}
</script>

<style scoped lang="scss">
.task-list-page {
  max-width: 1600px;
  margin: 0 auto;
  padding: 1rem;
}

.flex-between {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.batch-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  background: var(--blue-50);
  border-radius: 8px;
  margin-bottom: 16px;
  
  @media (max-width: 768px) {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }
}

.batch-info {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--blue-700);
  font-weight: 500;
  
  i {
    font-size: 18px;
  }
}

.batch-buttons {
  display: flex;
  gap: 8px;
  
  @media (max-width: 768px) {
    flex-direction: column;
  }
}

.url-cell {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 100%;
}

.action-buttons {
  display: flex;
  gap: 0.25rem;
  justify-content: center;
  align-items: center;
}

// 确保DataTable在大数据量时不会布局错乱
:deep(.p-datatable) {
  .p-datatable-wrapper {
    overflow-x: auto;
  }
  
  .p-datatable-thead > tr > th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--surface-ground);
  }
  
  .p-column-title {
    white-space: nowrap;
  }
}
</style>
