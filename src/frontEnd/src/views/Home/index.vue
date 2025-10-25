<template>
  <div class="home-page">
    <Card>
      <template #title>欢迎使用 SqlmapWebUI</template>
      <template #content>
        <p>这是一个基于Vue 3的SQL注入安全测试Web管理界面。</p>
        <div class="stats-grid mt-md">
          <Card>
            <template #title>{{ taskStats.total }}</template>
            <template #subtitle>总任务数</template>
          </Card>
          <Card>
            <template #title>{{ taskStats.running }}</template>
            <template #subtitle>运行中</template>
          </Card>
          <Card>
            <template #title>{{ taskStats.success }}</template>
            <template #subtitle>已完成</template>
          </Card>
        </div>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'

const taskStore = useTaskStore()

const taskStats = ref({
  total: 0,
  running: 0,
  success: 0,
})

onMounted(async () => {
  await taskStore.fetchTaskList()
  taskStats.value = {
    total: taskStore.taskList.length,
    running: taskStore.taskList.filter(t => t.status === TaskStatus.RUNNING).length,
    success: taskStore.taskList.filter(t => t.status === TaskStatus.SUCCESS).length,
  }
})
</script>

<style scoped lang="scss">
.home-page {
  max-width: 1200px;
  margin: 0 auto;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}
</style>
