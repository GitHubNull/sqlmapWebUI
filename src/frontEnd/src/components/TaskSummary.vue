<template>
  <div class="task-summary">
    <div class="summary-title">
      <i class="pi pi-chart-bar"></i>
      <span>任务汇总统计</span>
    </div>

    <div class="summary-grid">
      <!-- 总任务数 -->
      <div class="summary-item total">
        <div class="summary-icon">
          <i class="pi pi-list"></i>
        </div>
        <div class="summary-content">
          <div class="summary-label">总任务数</div>
          <div class="summary-value">{{ stats.total }}</div>
        </div>
      </div>

      <!-- 任务状态统计 -->
      <div class="summary-section">
        <div class="section-title">
          <i class="pi pi-flag"></i>
          <span>任务状态</span>
        </div>
        <div class="stats-grid">
          <div class="summary-item">
            <div class="summary-icon pending">
              <i class="pi pi-clock"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">等待中</div>
              <div class="summary-value">{{ stats.pending }}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon running">
              <i class="pi pi-spin pi-spinner"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">运行中</div>
              <div class="summary-value">{{ stats.running }}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon success">
              <i class="pi pi-check-circle"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">已完成</div>
              <div class="summary-value">{{ stats.success }}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon failed">
              <i class="pi pi-times-circle"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">失败</div>
              <div class="summary-value">{{ stats.failed }}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon stopped">
              <i class="pi pi-stop"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">已停止</div>
              <div class="summary-value">{{ stats.stopped }}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon terminated">
              <i class="pi pi-ban"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">已终止</div>
              <div class="summary-value">{{ stats.terminated }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- SQL注入统计 -->
      <div class="summary-section">
        <div class="section-title">
          <i class="pi pi-shield"></i>
          <span>SQL注入检测</span>
        </div>
        <div class="stats-grid">
          <div class="summary-item">
            <div class="summary-icon injectable">
              <i class="pi pi-exclamation-triangle"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">存在注入</div>
              <div class="summary-value">{{ stats.injectable }}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon non-injectable">
              <i class="pi pi-check"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">无注入</div>
              <div class="summary-value">{{ stats.nonInjectable }}</div>
            </div>
          </div>

          <div class="summary-item">
            <div class="summary-icon unknown">
              <i class="pi pi-question-circle"></i>
            </div>
            <div class="summary-content">
              <div class="summary-label">未知</div>
              <div class="summary-value">{{ stats.unknown }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { TaskStats } from '@/types/task'

interface Props {
  stats: TaskStats
}

defineProps<Props>()
</script>

<style scoped lang="scss">
.task-summary {
  padding: 24px;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.95) 0%, rgba(248, 250, 252, 0.9) 100%);
  border-radius: 16px;
  border: 2px solid rgba(99, 102, 241, 0.1);
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
  margin: 20px 0;
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      radial-gradient(circle at 20% 20%, rgba(99, 102, 241, 0.03) 0%, transparent 50%),
      radial-gradient(circle at 80% 80%, rgba(16, 185, 129, 0.03) 0%, transparent 50%);
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

.summary-title {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
  font-size: 20px;
  font-weight: 700;
  color: #1f2937;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);

  i {
    font-size: 24px;
    background: linear-gradient(135deg, #6366f1 0%, #3b82f6 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }
}

.summary-grid {
  display: grid;
  gap: 24px;
}

.summary-section {
  .section-title {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 16px;
    font-size: 16px;
    font-weight: 600;
    color: #6b7280;

    i {
      font-size: 18px;
      color: #6366f1;
    }
  }
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
}

.summary-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.8) 100%);
  border-radius: 12px;
  border: 1px solid rgba(0, 0, 0, 0.05);
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
  }

  &.total {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    border: 2px solid rgba(99, 102, 241, 0.2);
    padding: 20px;
  }
}

.summary-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: rgba(0, 0, 0, 0.05);
  flex-shrink: 0;

  i {
    font-size: 20px;
    color: #6b7280;
  }

  // 状态颜色
  &.pending {
    background: rgba(59, 130, 246, 0.1);
    i {
      color: #3b82f6;
    }
  }

  &.running {
    background: rgba(99, 102, 241, 0.1);
    i {
      color: #6366f1;
    }
  }

  &.success {
    background: rgba(16, 185, 129, 0.1);
    i {
      color: #10b981;
    }
  }

  &.failed {
    background: rgba(239, 68, 68, 0.1);
    i {
      color: #ef4444;
    }
  }

  &.stopped {
    background: rgba(245, 158, 11, 0.1);
    i {
      color: #f59e0b;
    }
  }

  &.terminated {
    background: rgba(107, 114, 128, 0.1);
    i {
      color: #6b7280;
    }
  }

  // 注入状态颜色
  &.injectable {
    background: rgba(239, 68, 68, 0.1);
    i {
      color: #ef4444;
    }
  }

  &.non-injectable {
    background: rgba(16, 185, 129, 0.1);
    i {
      color: #10b981;
    }
  }

  &.unknown {
    background: rgba(156, 163, 175, 0.1);
    i {
      color: #9ca3af;
    }
  }
}

.summary-content {
  flex: 1;
  min-width: 0;
}

.summary-label {
  font-size: 14px;
  color: #6b7280;
  margin-bottom: 4px;
  white-space: nowrap;
}

.summary-value {
  font-size: 24px;
  font-weight: 700;
  color: #1f2937;
  line-height: 1;

  .total & {
    font-size: 32px;
    background: linear-gradient(135deg, #6366f1 0%, #3b82f6 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }
}

@media (max-width: 768px) {
  .task-summary {
    padding: 16px;
    margin: 12px 0;
  }

  .summary-title {
    font-size: 18px;
    margin-bottom: 16px;
  }

  .stats-grid {
    grid-template-columns: 1fr;
    gap: 12px;
  }

  .summary-item {
    padding: 12px;

    &.total {
      padding: 16px;
    }
  }

  .summary-icon {
    width: 40px;
    height: 40px;

    i {
      font-size: 18px;
    }
  }

  .summary-value {
    font-size: 20px;

    .total & {
      font-size: 28px;
    }
  }
}
</style>
