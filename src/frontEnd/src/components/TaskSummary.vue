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
  background: var(--p-surface-0);
  border-radius: 16px;
  border: 1px solid var(--p-surface-200);
  margin: 20px 0;
}

.summary-title {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
  font-size: 20px;
  font-weight: 700;
  color: var(--p-text-color);

  i {
    font-size: 24px;
    color: var(--p-primary-color);
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
    color: var(--p-text-muted-color);

    i {
      font-size: 18px;
      color: var(--p-primary-color);
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
  background: var(--p-surface-100);
  border-radius: 12px;
  border: 1px solid var(--p-surface-border);

  &.total {
    background: var(--p-surface-100);
    border: 2px solid var(--p-primary-color);
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
  background: var(--p-surface-200);
  flex-shrink: 0;

  i {
    font-size: 20px;
    color: var(--p-text-muted-color);
  }

  // 状态颜色
  &.pending {
    background: rgba(59, 130, 246, 0.15);
    i { color: #3b82f6; }
  }

  &.running {
    background: rgba(99, 102, 241, 0.15);
    i { color: var(--p-primary-color); }
  }

  &.success {
    background: rgba(34, 197, 94, 0.15);
    i { color: #22c55e; }
  }

  &.failed {
    background: rgba(239, 68, 68, 0.15);
    i { color: #ef4444; }
  }

  &.stopped {
    background: rgba(249, 115, 22, 0.15);
    i { color: #f97316; }
  }

  &.terminated {
    background: var(--p-surface-200);
    i { color: var(--p-surface-500); }
  }

  // 注入状态颜色
  &.injectable {
    background: rgba(239, 68, 68, 0.15);
    i { color: #ef4444; }
  }

  &.non-injectable {
    background: rgba(34, 197, 94, 0.15);
    i { color: #22c55e; }
  }

  &.unknown {
    background: var(--p-surface-200);
    i { color: var(--p-surface-400); }
  }
}

.summary-content {
  flex: 1;
  min-width: 0;
}

.summary-label {
  font-size: 14px;
  color: var(--p-text-muted-color);
  margin-bottom: 4px;
  white-space: nowrap;
}

.summary-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--p-text-color);
  line-height: 1;

  .total & {
    font-size: 32px;
    color: var(--p-primary-color);
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
