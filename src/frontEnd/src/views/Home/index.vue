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
        <p class="intro-text">这是一个基于Vue 3的SQL注入安全测试Web管理界面。</p>
        
        <!-- 任务状态类统计 -->
        <div class="stats-section">
          <h3 class="section-title">任务状态统计</h3>
          <div class="stats-grid status-stats">
            <Card class="stat-card total" @click="navigateToTasks('all')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-list"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.total }}</div>
                    <div class="stat-label">总任务数</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card running" @click="navigateToTasks('running')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-spin pi-spinner"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.running }}</div>
                    <div class="stat-label">运行中</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card pending" @click="navigateToTasks('pending')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-clock"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.pending }}</div>
                    <div class="stat-label">等待中</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card success" @click="navigateToTasks('success')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-check-circle"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.success }}</div>
                    <div class="stat-label">已完成</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card failed" @click="navigateToTasks('failed')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-times-circle"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.failed }}</div>
                    <div class="stat-label">失败</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card stopped" @click="navigateToTasks('stopped')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-stop-circle"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.stopped }}</div>
                    <div class="stat-label">已停止</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card terminated" @click="navigateToTasks('terminated')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-ban"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.terminated }}</div>
                    <div class="stat-label">已终止</div>
                  </div>
                </div>
              </template>
            </Card>
          </div>
        </div>
        
        <!-- 注入结果类统计 -->
        <div class="stats-section">
          <h3 class="section-title">注入结果统计</h3>
          <div class="stats-grid injection-stats">
            <Card class="stat-card injectable" @click="navigateToTasks('injectable')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-exclamation-triangle"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.injectable }}</div>
                    <div class="stat-label">存在注入</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card non-injectable" @click="navigateToTasks('not_injectable')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-check-circle"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.nonInjectable }}</div>
                    <div class="stat-label">不存在注入</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card unknown" @click="navigateToTasks('unknown')">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-question-circle"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.unknown }}</div>
                    <div class="stat-label">未知状态</div>
                  </div>
                </div>
              </template>
            </Card>
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'

const router = useRouter()
const taskStore = useTaskStore()

onMounted(async () => {
  await refreshData()
})

async function refreshData() {
  await taskStore.fetchTaskList()
}

// 点击统计卡片跳转到任务列表页并设置过滤条件
type FilterType = 'all' | 'running' | 'pending' | 'success' | 'failed' | 'stopped' | 'terminated' | 'injectable' | 'not_injectable' | 'unknown'

function navigateToTasks(filterType: FilterType) {
  const query: Record<string, string> = {}
  
  switch (filterType) {
    case 'all':
      // 不设置过滤条件，显示全部
      break
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

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;
@use '@/assets/styles/index.scss' as *;

.home-page {
  width: 100%;  // 占满主内容区域，不限制最大宽度
  margin: 0;
  padding: 20px 0;  // 只保留上下内边距
  position: relative;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      radial-gradient(circle at 30% 20%, rgba(139, 92, 246, 0.05) 0%, transparent 50%),
      radial-gradient(circle at 70% 80%, rgba(6, 182, 212, 0.05) 0%, transparent 50%);
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  margin-bottom: 8px;
}

.intro-text {
  margin-bottom: 24px;
  color: $text-color-secondary;
  font-size: 14px;
  line-height: 1.6;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.6) 0%, rgba(248, 250, 252, 0.4) 100%);
  padding: 14px 18px;
  border-radius: $border-radius-lg;
  border: 1px solid rgba(255, 255, 255, 0.3);
  box-shadow: $shadow-raised;
  transition: $transition-base;

  &:hover {
    transform: translateY(-2px);
    box-shadow: $shadow-elevated;
    color: $text-color;
  }
}

.stats-section {
  margin-bottom: 28px;

  &:last-child {
    margin-bottom: 0;
  }
}

.section-title {
  font-size: 20px;
  font-weight: $font-weight-bold;
  margin-bottom: 16px;
  color: $text-color;
  text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  background: $gradient-primary;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  position: relative;

  &::after {
    content: '';
    position: absolute;
    bottom: -6px;
    left: 0;
    width: 60px;
    height: 3px;
    background: $gradient-primary;
    border-radius: 2px;
    box-shadow: 0 2px 4px rgba(99, 102, 241, 0.3);
  }
}

.stats-grid {
  display: grid;
  gap: 16px;

  &.status-stats {
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));

    @media (min-width: 1400px) {
      grid-template-columns: repeat(4, 1fr);
    }

    @media (min-width: 1200px) and (max-width: 1399px) {
      grid-template-columns: repeat(3, 1fr);
    }

    @media (min-width: 768px) and (max-width: 1199px) {
      grid-template-columns: repeat(2, 1fr);
    }

    @media (max-width: 767px) {
      grid-template-columns: 1fr;
      gap: 12px;
    }
  }

  &.injection-stats {
    grid-template-columns: repeat(3, 1fr);

    @media (max-width: 1024px) {
      grid-template-columns: repeat(2, 1fr);
    }

    @media (max-width: 767px) {
      grid-template-columns: 1fr;
      gap: 12px;
    }
  }
}

.stat-card {
  @include card-3d($elevation: high);
  border-radius: $border-radius-xl;
  cursor: pointer;
  position: relative;
  overflow: hidden;
  border: 2px solid rgba(255, 255, 255, 0.3);

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg,
      rgba(255, 255, 255, 0.1) 0%,
      rgba(255, 255, 255, 0.05) 50%,
      rgba(255, 255, 255, 0.1) 100%);
    opacity: 0;
    transition: $transition-base;
  }

  &:hover {
    transform: translateY(-8px) rotateX(5deg) rotateY(-2deg);
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(139, 92, 246, 0.2);

    &::before {
      opacity: 1;
    }
  }

  &:active {
    transform: translateY(-4px) rotateX(2deg) rotateY(-1deg);
    box-shadow: $shadow-elevated;
  }

  :deep(.p-card-body) {
    padding: 0;
    background: transparent;
  }

  :deep(.p-card-content) {
    padding: 0;
    background: transparent;
  }
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 18px 20px;
  position: relative;
  z-index: 2;
}

.stat-icon {
  width: 48px;
  height: 48px;
  border-radius: $border-radius;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 22px;
  flex-shrink: 0;
  position: relative;
  transition: $transition-base;
  box-shadow:
    $shadow-elevated,
    inset 0 2px 4px rgba(255, 255, 255, 0.3);
  border: 2px solid rgba(255, 255, 255, 0.2);

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: inherit;
    border-radius: inherit;
    filter: blur(1px);
    opacity: 0.5;
    z-index: -1;
  }

  &:hover {
    transform: scale(1.1) rotateY(15deg);
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 30px currentColor;
  }

  i {
    filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.2));
    transition: $transition-base;
  }
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 26px;
  font-weight: $font-weight-bold;
  line-height: 1.2;
  margin-bottom: 4px;
  text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  position: relative;
  transition: $transition-base;

  .stat-card:hover & {
    transform: scale(1.05);
    text-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
  }
}

.stat-label {
  font-size: 13px;
  color: $text-color-secondary;
  font-weight: $font-weight-medium;
  line-height: 1.3;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
  transition: $transition-base;

  .stat-card:hover & {
    color: $text-color;
    transform: translateX(2px);
  }
}

// ==================== 状态类卡片3D颜色效果 ====================
.stat-card.total {
  .stat-icon {
    background: $gradient-ocean;
    color: white;
  }

  .stat-value {
    background: $gradient-ocean;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(102, 126, 234, 0.3);
  }
}

.stat-card.running {
  .stat-icon {
    background: $gradient-primary;
    color: white;

    i {
      animation: spin 2s linear infinite;
    }
  }

  .stat-value {
    background: $gradient-primary;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(99, 102, 241, 0.4);
  }
}

.stat-card.pending {
  .stat-icon {
    background: $gradient-warning;
    color: white;
  }

  .stat-value {
    background: $gradient-warning;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(245, 158, 11, 0.4);
  }
}

.stat-card.success {
  .stat-icon {
    background: $gradient-success;
    color: white;
  }

  .stat-value {
    background: $gradient-success;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(16, 185, 129, 0.4);
  }
}

.stat-card.failed {
  .stat-icon {
    background: $gradient-danger;
    color: white;
  }

  .stat-value {
    background: $gradient-danger;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(239, 68, 68, 0.4);
  }
}

.stat-card.stopped {
  .stat-icon {
    background: $gradient-sunset;
    color: white;
  }

  .stat-value {
    background: $gradient-sunset;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(255, 107, 107, 0.3);
  }
}

.stat-card.terminated {
  .stat-icon {
    background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
    color: white;
  }

  .stat-value {
    background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(107, 114, 128, 0.3);
  }
}

// ==================== 注入类卡片3D颜色效果 ====================
.stat-card.injectable {
  .stat-icon {
    background: $gradient-danger;
    color: white;

    &:hover {
      animation: pulse3d 1.5s ease-in-out infinite;
    }
  }

  .stat-value {
    background: $gradient-danger;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(239, 68, 68, 0.4);
  }
}

.stat-card.non-injectable {
  .stat-icon {
    background: $gradient-success;
    color: white;
  }

  .stat-value {
    background: $gradient-success;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(16, 185, 129, 0.4);
  }
}

.stat-card.unknown {
  .stat-icon {
    background: linear-gradient(135deg, #9ca3af 0%, #6b7280 100%);
    color: white;
  }

  .stat-value {
    background: linear-gradient(135deg, #9ca3af 0%, #6b7280 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  &:hover {
    box-shadow:
      $shadow-floating,
      inset 0 2px 4px rgba(255, 255, 255, 0.4),
      0 0 40px rgba(156, 163, 175, 0.4);
  }
}

// ==================== 动画效果 ====================
@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

@keyframes pulse3d {
  0%, 100% {
    transform: scale(1);
  }
  50% {
    transform: scale(1.05);
  }
}
</style>
