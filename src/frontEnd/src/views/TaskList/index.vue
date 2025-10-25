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
        <DataTable 
          :value="taskStore.taskList" 
          :loading="taskStore.loading" 
          stripedRows
          paginator
          :rows="20"
          :rowsPerPageOptions="[10, 20, 50, 100]"
          :scrollable="true"
          scrollHeight="calc(100vh - 300px)"
          :virtualScrollerOptions="{ itemSize: 60 }"
          showGridlines
          responsiveLayout="scroll"
        >
          <Column field="engineid" header="任务ID" :style="{ minWidth: '100px' }" />
          <Column field="scanUrl" header="扫描URL" :style="{ minWidth: '300px', maxWidth: '400px' }">
            <template #body="{ data }">
              <div class="url-cell" :title="data.scanUrl">
                {{ data.scanUrl }}
              </div>
            </template>
          </Column>
          <Column field="host" header="主机" :style="{ minWidth: '150px' }" />
          <Column field="status" header="状态" :style="{ minWidth: '100px' }">
            <template #body="{ data }">
              <Tag :value="getStatusLabel(data.status)" :severity="getStatusSeverity(data.status)" />
            </template>
          </Column>
          <Column field="createTime" header="创建时间" :style="{ minWidth: '180px' }">
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
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import { formatDateTime } from '@/utils/format'

const router = useRouter()
const taskStore = useTaskStore()

onMounted(() => {
  fetchTasks()
})

async function fetchTasks() {
  await taskStore.fetchTaskList()
}

function getStatusLabel(status: TaskStatus): string {
  const labels = {
    [TaskStatus.PENDING]: '等待中',
    [TaskStatus.RUNNING]: '运行中',
    [TaskStatus.SUCCESS]: '已完成',
    [TaskStatus.FAILED]: '失败',
    [TaskStatus.STOPPED]: '已停止',
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
