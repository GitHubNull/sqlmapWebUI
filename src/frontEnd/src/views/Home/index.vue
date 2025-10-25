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
            <Card class="stat-card total">
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
            
            <Card class="stat-card running">
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
            
            <Card class="stat-card pending">
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
            
            <Card class="stat-card success">
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
            
            <Card class="stat-card failed">
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
            
            <Card class="stat-card stopped">
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
            
            <Card class="stat-card terminated">
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
            <Card class="stat-card injectable">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-shield"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.injectable }}</div>
                    <div class="stat-label">可注入任务</div>
                  </div>
                </div>
              </template>
            </Card>
            
            <Card class="stat-card non-injectable">
              <template #content>
                <div class="stat-content">
                  <div class="stat-icon">
                    <i class="pi pi-lock"></i>
                  </div>
                  <div class="stat-info">
                    <div class="stat-value">{{ taskStore.taskStats.nonInjectable }}</div>
                    <div class="stat-label">不可注入任务</div>
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
import { useTaskStore } from '@/stores/task'

const taskStore = useTaskStore()

onMounted(async () => {
  await refreshData()
})

async function refreshData() {
  await taskStore.fetchTaskList()
}
</script>

<style scoped lang="scss">
.home-page {
  max-width: 1600px;
  margin: 0 auto;
  padding: 24px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.intro-text {
  margin-bottom: 32px;
  color: var(--text-color-secondary);
  font-size: 14px;
  line-height: 1.6;
}

.stats-section {
  margin-bottom: 32px;
  
  &:last-child {
    margin-bottom: 0;
  }
}

.section-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
  color: var(--text-color);
}

.stats-grid {
  display: grid;
  gap: 16px;
  
  &.status-stats {
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    
    @media (min-width: 1200px) {
      grid-template-columns: repeat(4, 1fr);
    }
    
    @media (min-width: 768px) and (max-width: 1199px) {
      grid-template-columns: repeat(3, 1fr);
    }
    
    @media (max-width: 767px) {
      grid-template-columns: repeat(2, 1fr);
    }
  }
  
  &.injection-stats {
    grid-template-columns: repeat(2, 1fr);
    
    @media (max-width: 767px) {
      grid-template-columns: 1fr;
    }
  }
}

.stat-card {
  border-radius: 8px;
  transition: all 0.3s ease;
  cursor: pointer;
  
  &:hover {
    transform: translateY(-4px);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
  }
  
  :deep(.p-card-body) {
    padding: 0;
  }
  
  :deep(.p-card-content) {
    padding: 0;
  }
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 24px;
}

.stat-icon {
  width: 56px;
  height: 56px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  flex-shrink: 0;
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  line-height: 1.3;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 14px;
  color: var(--text-color-secondary);
  line-height: 1.5;
}

// 状态类卡片颜色
.stat-card.total {
  .stat-icon {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }
  
  .stat-value {
    color: #667eea;
  }
}

.stat-card.running {
  .stat-icon {
    background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
    color: white;
  }
  
  .stat-value {
    color: #6366f1;
  }
}

.stat-card.pending {
  .stat-icon {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    color: white;
  }
  
  .stat-value {
    color: #f59e0b;
  }
}

.stat-card.success {
  .stat-icon {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
  }
  
  .stat-value {
    color: #10b981;
  }
}

.stat-card.failed {
  .stat-icon {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: white;
  }
  
  .stat-value {
    color: #ef4444;
  }
}

.stat-card.stopped {
  .stat-icon {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    color: white;
  }
  
  .stat-value {
    color: #f59e0b;
  }
}

.stat-card.terminated {
  .stat-icon {
    background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
    color: white;
  }
  
  .stat-value {
    color: #6b7280;
  }
}

// 注入类卡片颜色
.stat-card.injectable {
  .stat-icon {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: white;
  }
  
  .stat-value {
    color: #ef4444;
  }
}

.stat-card.non-injectable {
  .stat-icon {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
  }
  
  .stat-value {
    color: #10b981;
  }
}
</style>
