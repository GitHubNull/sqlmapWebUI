<template>
  <div class="task-list-page">
    <Card>
      <template #title>任务列表</template>
      
      <template #content>
        <SearchFilterBar
          v-model="searchQuery"
          :filter-options="statusOptions"
          v-model:filter-value="selectedStatus"
          filter-placeholder="状态筛选"
          @search="handleSearch"
          @filter="handleFilter"
        >
          <template #actions>
            <Button
              icon="pi pi-refresh"
              @click="fetchTasks"
              :loading="taskStore.loading"
              text
              rounded
              v-tooltip.top="'刷新'"
            />
          </template>
        </SearchFilterBar>

        <BatchActionsToolbar
          :selected-count="selectedTasks.length"
          :actions="batchActions"
        />

        <DataTable
          v-model:selection="selectedTasks"
          :value="filteredTasks"
          :loading="taskStore.loading"
          striped-rows
          paginator
          :rows="20"
          :rows-per-page-options="[10, 20, 50, 100]"
          scrollable
          scroll-height="flex"
          show-gridlines
          sort-mode="single"
          :sort-field="sortField"
          :sort-order="sortOrder"
          @sort="handleSort"
          data-key="taskid"
          class="task-table"
          resizable-columns
          column-resize-mode="fit"
        >
          <template #empty>
            <div class="empty-message">
              <i class="pi pi-inbox"></i>
              <p>暂无扫描任务</p>
              <small>点击底部「添加任务」按钮创建新任务</small>
            </div>
          </template>

          <Column selection-mode="multiple" header-style="width: 3rem" body-style="text-align: center" frozen />
          
          <Column field="engineid" header="任务ID" sortable style="min-width: 80px" />
          
          <Column field="scanUrl" header="扫描URL" sortable style="min-width: 250px">
            <template #body="{ data }">
              <span class="url-cell" @click="viewTask(data)">{{ data.scanUrl }}</span>
            </template>
          </Column>
          
          <Column field="host" header="主机" sortable style="min-width: 120px" />
          
          <Column field="injected" header="是否存在注入" sortable style="min-width: 120px">
            <template #body="{ data }">
              <Tag
                v-if="data.injected !== undefined && data.injected !== null"
                :value="data.injected ? '存在注入' : '无注入'"
                :severity="data.injected ? 'danger' : 'success'"
              />
              <Tag v-else value="未知" severity="secondary" />
            </template>
          </Column>
          
          <Column field="status" header="状态" sortable style="min-width: 100px">
            <template #body="{ data }">
              <Tag :value="getStatusLabel(data.status)" :severity="getStatusSeverity(data.status)" />
            </template>
          </Column>
          
          <Column field="createTime" header="创建时间" sortable style="min-width: 160px">
            <template #body="{ data }">{{ formatDateTime(data.createTime) }}</template>
          </Column>
          
          <Column field="errors" header="错误数" sortable style="min-width: 80px">
            <template #body="{ data }">
              <Tag v-if="data.errors > 0" :value="data.errors" severity="danger" />
              <span v-else class="text-muted">0</span>
            </template>
          </Column>
          
          <Column header="操作" style="min-width: 120px" frozen align-frozen="right">
            <template #body="{ data }">
              <div class="action-buttons">
                <Button icon="pi pi-eye" @click="viewTask(data)" text rounded size="small" />
                <Button
                  v-if="data.status === 1"
                  icon="pi pi-stop"
                  @click="stopTask(data.taskid)"
                  text
                  rounded
                  size="small"
                  severity="warn"
                />
                <Button
                  icon="pi pi-trash"
                  @click="deleteTask(data.taskid)"
                  text
                  rounded
                  size="small"
                  severity="danger"
                />
              </div>
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import type { Task } from '@/types/task'
import { formatDateTime } from '@/utils/format'
import Card from 'primevue/card'
import Button from 'primevue/button'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import SearchFilterBar from '@/components/SearchFilterBar.vue'
import BatchActionsToolbar from '@/components/BatchActionsToolbar.vue'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'

const router = useRouter()
const taskStore = useTaskStore()
const confirm = useConfirm()
const toast = useToast()

const searchQuery = ref('')
const selectedStatus = ref(null)
const selectedTasks = ref<Task[]>([])
const sortField = ref('createTime')
const sortOrder = ref(-1)

const statusOptions = [
  { label: '等待中', value: TaskStatus.PENDING },
  { label: '运行中', value: TaskStatus.RUNNING },
  { label: '已完成', value: TaskStatus.SUCCESS },
  { label: '失败', value: TaskStatus.FAILED },
  { label: '已停止', value: TaskStatus.STOPPED },
  { label: '已终止', value: TaskStatus.TERMINATED },
]

const filteredTasks = computed(() => {
  let tasks = taskStore.sortedTaskList
  
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    tasks = tasks.filter(t =>
      t.scanUrl?.toLowerCase().includes(query) ||
      t.host?.toLowerCase().includes(query)
    )
  }
  
  if (selectedStatus.value !== null) {
    tasks = tasks.filter(t => t.status === selectedStatus.value)
  }
  
  return tasks
})

const batchActions = computed(() => [
  {
    label: '停止选中',
    icon: 'pi pi-stop',
    severity: 'warn' as const,
    onClick: batchStop
  },
  {
    label: '删除选中',
    icon: 'pi pi-trash',
    severity: 'danger' as const,
    onClick: batchDelete
  },
  {
    label: '取消选择',
    icon: 'pi pi-times',
    severity: 'secondary' as const,
    outlined: true,
    onClick: () => selectedTasks.value = []
  }
])

onMounted(() => {
  fetchTasks()
})

async function fetchTasks() {
  await taskStore.fetchTaskList()
}

function handleSearch() {
  // 搜索逻辑在 computed 中处理
}

function handleFilter() {
  // 筛选逻辑在 computed 中处理
}

function handleSort(event: any) {
  sortField.value = event.sortField
  sortOrder.value = event.sortOrder
}

function getStatusLabel(status: TaskStatus): string {
  const labels: Record<number, string> = {
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
  const severities: Record<number, string> = {
    [TaskStatus.PENDING]: 'info',
    [TaskStatus.RUNNING]: 'primary',
    [TaskStatus.SUCCESS]: 'success',
    [TaskStatus.FAILED]: 'danger',
    [TaskStatus.STOPPED]: 'warn',
    [TaskStatus.TERMINATED]: 'secondary',
  }
  return severities[status] || 'secondary'
}

function viewTask(task: Task) {
  router.push(`/tasks/${task.taskid}`)
}

function stopTask(taskId: string) {
  confirm.require({
    message: '确定要停止这个任务吗？',
    header: '确认停止',
    icon: 'pi pi-exclamation-triangle',
    accept: async () => {
      try {
        await taskStore.stopTask(taskId)
        toast.add({ severity: 'success', summary: '成功', detail: '任务已停止', life: 3000 })
      } catch {
        toast.add({ severity: 'error', summary: '错误', detail: '停止任务失败', life: 3000 })
      }
    }
  })
}

function deleteTask(taskId: string) {
  confirm.require({
    message: '确定要删除这个任务吗？此操作不可恢复。',
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    accept: async () => {
      try {
        await taskStore.deleteTask(taskId)
        toast.add({ severity: 'success', summary: '成功', detail: '任务已删除', life: 3000 })
      } catch {
        toast.add({ severity: 'error', summary: '错误', detail: '删除任务失败', life: 3000 })
      }
    }
  })
}

async function batchStop() {
  const runningTasks = selectedTasks.value.filter(t => t.status === TaskStatus.RUNNING)
  if (runningTasks.length === 0) {
    toast.add({ severity: 'info', summary: '提示', detail: '选中的任务中没有正在运行的任务', life: 3000 })
    return
  }
  
  confirm.require({
    message: `确定要停止选中的 ${runningTasks.length} 个运行中的任务吗？`,
    header: '确认停止',
    icon: 'pi pi-exclamation-triangle',
    accept: async () => {
      try {
        await taskStore.batchStopTasks(runningTasks.map(t => t.taskid))
        selectedTasks.value = []
        toast.add({ severity: 'success', summary: '成功', detail: `已停止 ${runningTasks.length} 个任务`, life: 3000 })
      } catch {
        toast.add({ severity: 'error', summary: '错误', detail: '停止任务失败', life: 3000 })
      }
    }
  })
}

async function batchDelete() {
  const deletableTasks = selectedTasks.value.filter(t => t.status !== TaskStatus.RUNNING)
  if (deletableTasks.length === 0) {
    toast.add({ severity: 'info', summary: '提示', detail: '没有可删除的任务', life: 3000 })
    return
  }
  
  confirm.require({
    message: `确定要删除选中的 ${deletableTasks.length} 个任务吗？此操作不可恢复。`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    accept: async () => {
      try {
        await taskStore.batchDeleteTasks(deletableTasks.map(t => t.taskid))
        selectedTasks.value = []
        toast.add({ severity: 'success', summary: '成功', detail: `已删除 ${deletableTasks.length} 个任务`, life: 3000 })
      } catch {
        toast.add({ severity: 'error', summary: '错误', detail: '删除失败', life: 3000 })
      }
    }
  })
}
</script>

<style scoped>
.task-list-page {
  height: 100%;
}

.task-table {
  margin-top: 1rem;
}

.url-cell {
  cursor: pointer;
  color: var(--p-primary-color);
}

.url-cell:hover {
  text-decoration: underline;
}

.action-buttons {
  display: flex;
  gap: 0.25rem;
  justify-content: center;
}

.empty-message {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem 1rem;
  color: var(--p-text-secondary-color);
}

.empty-message i {
  font-size: 3rem;
  margin-bottom: 1rem;
  color: var(--p-surface-400);
}

.empty-message p {
  font-size: 1.125rem;
  font-weight: 500;
  margin: 0 0 0.5rem;
  color: var(--p-text-color);
}

.empty-message small {
  font-size: 0.875rem;
}
</style>
