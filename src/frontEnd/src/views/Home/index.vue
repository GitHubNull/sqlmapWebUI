<template>
  <div class="home-page">
    <Card>
      <template #title>
        <div class="page-header">
          <span>欢迎使用 SqlmapWebUI</span>
          <Button
            label="刷新"
            icon="pi pi-refresh"
            @click="refreshData"
            :loading="taskStore.loading"
            severity="secondary"
            text
          />
        </div>
      </template>
      
      <template #content>
        <p class="intro">这是一个基于Vue 3的SQL注入安全测试Web管理界面。</p>
        
        <!-- 任务状态统计 -->
        <section class="stats-section">
          <h3>任务状态统计</h3>
          <div class="stats-grid">
            <StatCard
              v-for="stat in statusStats"
              :key="stat.key"
              :icon="stat.icon"
              :value="taskStore.taskStats[stat.key]"
              :label="stat.label"
              :severity="stat.severity"
              @click="navigateToTasks(stat.filter)"
            />
          </div>
        </section>
        
        <!-- 注入结果统计 -->
        <section class="stats-section">
          <h3>注入结果统计</h3>
          <div class="stats-grid">
            <StatCard
              v-for="stat in injectionStats"
              :key="stat.key"
              :icon="stat.icon"
              :value="taskStore.taskStats[stat.key]"
              :label="stat.label"
              :severity="stat.severity"
              @click="navigateToTasks(stat.filter)"
            />
          </div>
        </section>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import Card from 'primevue/card'
import Button from 'primevue/button'
import StatCard from '@/components/StatCard.vue'

const router = useRouter()
const taskStore = useTaskStore()

const statusStats = [
  { key: 'total', label: '总任务数', icon: 'pi pi-list', severity: 'info' as const, filter: 'all' },
  { key: 'running', label: '运行中', icon: 'pi pi-spin pi-spinner', severity: 'primary' as const, filter: 'running' },
  { key: 'pending', label: '等待中', icon: 'pi pi-clock', severity: 'warn' as const, filter: 'pending' },
  { key: 'success', label: '已完成', icon: 'pi pi-check-circle', severity: 'success' as const, filter: 'success' },
  { key: 'failed', label: '失败', icon: 'pi pi-times-circle', severity: 'danger' as const, filter: 'failed' },
  { key: 'stopped', label: '已停止', icon: 'pi pi-stop-circle', severity: 'secondary' as const, filter: 'stopped' },
  { key: 'terminated', label: '已终止', icon: 'pi pi-ban', severity: 'secondary' as const, filter: 'terminated' },
]

const injectionStats = [
  { key: 'injectable', label: '存在注入', icon: 'pi pi-exclamation-triangle', severity: 'danger' as const, filter: 'injectable' },
  { key: 'nonInjectable', label: '无注入', icon: 'pi pi-check-circle', severity: 'success' as const, filter: 'not_injectable' },
  { key: 'unknown', label: '未知状态', icon: 'pi pi-question-circle', severity: 'secondary' as const, filter: 'unknown' },
]

onMounted(async () => {
  await refreshData()
})

async function refreshData() {
  await taskStore.fetchTaskList()
}

type FilterType = 'all' | 'running' | 'pending' | 'success' | 'failed' | 'stopped' | 'terminated' | 'injectable' | 'not_injectable' | 'unknown'

function navigateToTasks(filterType: FilterType) {
  const query: Record<string, string> = {}
  
  switch (filterType) {
    case 'running':
      query.status = String(TaskStatus.RUNNING)
      break
    case 'pending':
      query.status = String(TaskStatus.PENDING)
      break
    case 'success':
      query.status = String(TaskStatus.SUCCESS)
      break
    case 'failed':
      query.status = String(TaskStatus.FAILED)
      break
    case 'stopped':
      query.status = String(TaskStatus.STOPPED)
      break
    case 'terminated':
      query.status = String(TaskStatus.TERMINATED)
      break
    case 'injectable':
      query.injectable = 'injectable'
      break
    case 'not_injectable':
      query.injectable = 'not_injectable'
      break
    case 'unknown':
      query.injectable = 'unknown'
      break
  }
  
  router.push({ path: '/tasks', query })
}
</script>

<style scoped>
.home-page {
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.intro {
  color: var(--p-text-secondary-color);
  margin-bottom: 1.5rem;
}

.stats-section {
  margin-bottom: 2rem;
}

.stats-section:last-child {
  margin-bottom: 0;
}

.stats-section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  margin-bottom: 1rem;
  color: var(--p-text-color);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 1rem;
}

@media (max-width: 640px) {
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
