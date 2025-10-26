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
              label="停止选中" 
              icon="pi pi-stop" 
              severity="warning"
              @click="confirmBatchStop"
            />
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
          scrollHeight="flex"
          showGridlines
          responsiveLayout="scroll"
          sortMode="single"
          :sortField="taskStore.sortConfig.field"
          :sortOrder="taskStore.sortConfig.order === 'asc' ? 1 : taskStore.sortConfig.order === 'desc' ? -1 : 0"
          @sort="handleSort"
          dataKey="taskid"
          class="fixed-paginator-table"
        >
          <!-- 选择列 -->
          <Column selectionMode="multiple" headerStyle="width: 3rem" :exportable="false" frozen />
          <Column field="engineid" header="任务ID" :style="{ minWidth: '100px' }" sortable />
          <Column field="scanUrl" header="扫描URL" :style="{ minWidth: '300px', maxWidth: '400px' }" sortable>
            <template #body="{ data }">
              <div class="url-cell" :title="data.scanUrl">
                {{ data.scanUrl }}
              </div>
            </template>
          </Column>
          <Column field="host" header="主机" :style="{ minWidth: '150px' }" sortable />
          <Column field="injected" header="是否存在注入" :style="{ minWidth: '120px' }" sortable>
            <template #body="{ data }">
              <Tag 
                v-if="data.injected !== undefined && data.injected !== null" 
                :value="data.injected ? '存在注入' : '无注入'" 
                :severity="data.injected ? 'danger' : 'success'" 
                :icon="data.injected ? 'pi pi-exclamation-triangle' : 'pi pi-check-circle'"
              />
              <Tag v-else value="未知" severity="secondary" icon="pi pi-question-circle" />
            </template>
          </Column>
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
import { useConfigStore } from '@/stores/config'
import { TaskStatus } from '@/types/task'
import type { Task, TaskFilters } from '@/types/task'
import { formatDateTime } from '@/utils/format'
import TaskFilter from '@/components/TaskFilter.vue'

const router = useRouter()
const taskStore = useTaskStore()
const configStore = useConfigStore()
const confirm = useConfirm()
const toast = useToast()

// 选中的任务
const selectedTasks = ref<Task[]>([])

// 轮询定时器
let pollingTimer: number | null = null
// 从配置读取轮询间隔（毫秒）
const getPollingInterval = () => configStore.autoRefreshInterval * 60 * 1000

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

// 监听刷新间隔配置变化，重启轮询
watch(
  () => configStore.autoRefreshInterval,
  () => {
    if (pollingTimer) {
      stopPolling()
      const hasRunningTasks = taskStore.taskList.some(t => t.status === TaskStatus.RUNNING)
      if (hasRunningTasks && !document.hidden) {
        startPolling()
      }
    }
  }
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
  }, getPollingInterval())
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

// 确认批量停止
function confirmBatchStop() {
  // 过滤出运行中的任务
  const runningTasks = selectedTasks.value.filter(t => t.status === TaskStatus.RUNNING)
  
  if (runningTasks.length === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '选中的任务中没有正在运行的任务',
      life: 3000,
    })
    return
  }
  
  confirm.require({
    message: `确定要停止选中的 ${runningTasks.length} 个运行中的任务吗？`,
    header: '确认停止',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '停止',
    rejectLabel: '取消',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        const taskIds = runningTasks.map(t => t.taskid)
        await taskStore.batchStopTasks(taskIds)
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: `已停止 ${runningTasks.length} 个任务`,
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '停止任务失败，请重试',
          life: 3000,
        })
      }
    },
  })
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
@use '@/assets/styles/variables.scss' as *;

.task-list-page {
  width: 100%;  // 占满主内容区域，不限制最大宽度
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
      radial-gradient(circle at 25% 25%, rgba(99, 102, 241, 0.03) 0%, transparent 50%),
      radial-gradient(circle at 75% 75%, rgba(16, 185, 129, 0.03) 0%, transparent 50%),
      url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23f1f5f9' fill-opacity='0.2'%3E%3Cpath d='M20 20.5V18H0v-2h20v2.5zm0 2.5v2.5H0V23h20zm2 0h18v2H22v-2zm0-2.5h18V18H22v2.5z'/%3E%3C/g%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
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
  padding: 12px 20px;
  background:
    linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
  border-radius: $border-radius-lg;
  border: 2px solid rgba(99, 102, 241, 0.1);
  box-shadow:
    $shadow-raised,
    inset 0 1px 2px rgba(255, 255, 255, 0.4);
  margin-bottom: 16px;
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
      transparent 0%,
      rgba(255, 255, 255, 0.2) 50%,
      transparent 100%);
    animation: shimmer-batch 3s ease-in-out infinite;
  }

  @media (max-width: 768px) {
    flex-direction: column;
    gap: 16px;
    align-items: stretch;
    padding: 16px 20px;
  }
}

@keyframes shimmer-batch {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(200%);
    opacity: 1;
  }
}

.batch-info {
  display: flex;
  align-items: center;
  gap: 12px;
  color: $primary-color;
  font-weight: $font-weight-semibold;
  font-size: 16px;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  position: relative;
  z-index: 2;

  i {
    font-size: 20px;
    background: $gradient-primary;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.1));
  }
}

.batch-buttons {
  display: flex;
  gap: 12px;
  position: relative;
  z-index: 2;

  @media (max-width: 768px) {
    flex-direction: column;
    gap: 8px;
  }
}

.url-cell {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 100%;
  padding: 8px 12px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 14px;
  transition: $transition-base;

  &:hover {
    background: rgba(99, 102, 241, 0.05);
  }
}

.action-buttons {
  display: flex;
  gap: 8px;
  justify-content: center;
  align-items: center;
  padding: 4px;
}

// ==================== DataTable 3D增强 ====================
:deep(.p-datatable) {
  border-radius: $border-radius-lg;
  overflow: hidden;
  box-shadow: $shadow-elevated;
  border: 2px solid rgba(255, 255, 255, 0.3);
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.8) 100%);

  .p-datatable-wrapper {
    overflow-x: auto;
    border-radius: inherit;
  }

  // 表头3D效果
  .p-datatable-thead > tr > th {
    position: sticky;
    top: 0;
    z-index: 10;
    background:
      linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    backdrop-filter: blur(10px);
    border-bottom: 2px solid rgba(99, 102, 241, 0.2);
    box-shadow:
      inset 0 1px 2px rgba(255, 255, 255, 0.4),
      0 2px 4px rgba(0, 0, 0, 0.1);
    color: $text-color;
    font-weight: $font-weight-semibold;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    transition: $transition-base;

    &:hover {
      background:
        linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(59, 130, 246, 0.1) 100%);
      transform: translateY(-1px);
      box-shadow:
        inset 0 1px 2px rgba(255, 255, 255, 0.5),
        0 4px 8px rgba(0, 0, 0, 0.15);
    }
  }

  // 表格行3D效果
  .p-datatable-tbody > tr {
    border-bottom: 1px solid rgba(0, 0, 0, 0.05);
    transition: $transition-base;

    &:hover {
      background:
        linear-gradient(135deg, rgba(99, 102, 241, 0.05) 0%, rgba(59, 130, 246, 0.02) 100%);
      box-shadow:
        0 1px 4px rgba(0, 0, 0, 0.08),
        inset 0 1px 2px rgba(255, 255, 255, 0.3);
    }

    td {
      border-bottom: none;
      padding: 16px 12px;
      vertical-align: middle;
    }
  }

  // 选中行效果
  .p-datatable-tbody > tr.p-selected {
    background:
      linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    box-shadow:
      inset 0 2px 4px rgba(99, 102, 241, 0.1),
      0 2px 8px rgba(99, 102, 241, 0.2);

    &:hover {
      background:
        linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(59, 130, 246, 0.1) 100%);
    }
  }

  .p-column-title {
    white-space: nowrap;
    font-size: 15px;
  }

  // 复选框简洁样式（无3D效果）
  .p-checkbox {
    width: 20px;
    height: 20px;

    .p-checkbox-box {
      background: #ffffff;
      border: 2px solid #cbd5e1;
      border-radius: 4px;
      width: 20px;
      height: 20px;
      display: inline-flex !important;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
      position: relative;

      &:hover {
        border-color: #94a3b8;
        background: #f8fafc;
      }

      &.p-highlight {
        background: #6366f1 !important;
        border-color: #6366f1 !important;
      }

      &:has(.p-checkbox-icon) {
        background: #6366f1 !important;
        border-color: #6366f1 !important;
      }

      .p-checkbox-icon {
        color: white !important;
        font-size: 14px;
        display: block;
      }

      &.p-focus {
        outline: 2px solid rgba(99, 102, 241, 0.2);
        outline-offset: 2px;
      }
    }

    input {
      opacity: 0;
      position: absolute;
    }
  }
}

// ==================== 固定分页器样式 ====================
:deep(.fixed-paginator-table) {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 580px);  // 从540px改为580px，完全消除滚动条

  .p-datatable-wrapper {
    flex: 1;
    overflow-y: auto;
    overflow-x: auto;
  }

  .p-paginator {
    position: sticky;
    bottom: 0;
    z-index: 5;
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.98) 0%, rgba(248, 250, 252, 0.95) 100%);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    box-shadow: 
      0 -2px 8px rgba(0, 0, 0, 0.08),
      inset 0 1px 2px rgba(255, 255, 255, 0.4);
    border-top: 2px solid rgba(99, 102, 241, 0.1);
    padding: 12px 16px;
    margin: 0;
  }
}
</style>
