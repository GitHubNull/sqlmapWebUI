<template>
  <div class="task-list-page">
    <Card>
      <template #title>
        <div class="flex-between">
          <span>任务列表</span>
          <Button label="刷新" icon="pi pi-refresh" @click="fetchTasks" :loading="taskStore.loading" />
        </div>
      </template>
      <template #content>
        <DataTable :value="taskStore.taskList" :loading="taskStore.loading" stripedRows>
          <Column field="engineid" header="任务ID" />
          <Column field="scanUrl" header="扫描URL" />
          <Column field="host" header="主机" />
          <Column field="status" header="状态">
            <template #body="{ data }">
              <Tag :value="getStatusLabel(data.status)" :severity="getStatusSeverity(data.status)" />
            </template>
          </Column>
          <Column field="createTime" header="创建时间">
            <template #body="{ data }">
              {{ formatDateTime(data.createTime) }}
            </template>
          </Column>
          <Column header="操作">
            <template #body="{ data }">
              <Button icon="pi pi-eye" @click="viewTask(data)" text rounded />
              <Button icon="pi pi-stop" @click="stopTask(data.taskid)" text rounded severity="warning" v-if="data.status === 1" />
              <Button icon="pi pi-trash" @click="deleteTask(data.taskid)" text rounded severity="danger" />
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
  max-width: 1400px;
  margin: 0 auto;
}

.flex-between {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}
</style>
