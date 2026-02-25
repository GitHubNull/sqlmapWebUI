<template>
  <div class="info-grid">
    <div class="info-item">
      <label>任务ID</label>
      <span class="value">{{ task.taskid }}</span>
    </div>
    <div class="info-item">
      <label>引擎ID</label>
      <span class="value">{{ task.engineid }}</span>
    </div>
    <div class="info-item">
      <label>任务状态</label>
      <Tag :value="getStatusLabel(task.status)" :severity="getStatusSeverity(task.status)" />
    </div>
    <div class="info-item">
      <label>注入状态</label>
      <Tag
        v-if="task.injected === true"
        value="可注入"
        severity="danger"
        icon="pi pi-shield"
      />
      <Tag
        v-else-if="task.injected === false"
        value="不可注入"
        severity="success"
        icon="pi pi-lock"
      />
      <span v-else class="value text-muted">未知</span>
    </div>
    <div class="info-item full-width">
      <label>扫描URL</label>
      <div class="url-display">
        <span class="value url">{{ task.scanUrl }}</span>
        <Button
          icon="pi pi-copy"
          text
          rounded
          @click="copyToClipboard(task.scanUrl)"
          v-tooltip.top="'复制URL'"
        />
      </div>
    </div>
    <div class="info-item">
      <label>目标主机</label>
      <span class="value">{{ task.host }}</span>
    </div>
    <div class="info-item">
      <label>创建时间</label>
      <span class="value">{{ formatDateTime(task.createTime) }}</span>
    </div>
    <div class="info-item">
      <label>更新时间</label>
      <span class="value">{{ task.updateTime ? formatDateTime(task.updateTime) : '-' }}</span>
    </div>
    <div class="info-item">
      <label>来源IP</label>
      <span class="value">{{ task.remote_addr || '-' }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useToast } from 'primevue/usetoast'
import { TaskStatus } from '@/types/task'
import type { Task } from '@/types/task'
import { formatDateTime } from '@/utils/format'

interface Props {
  task: Task
}

defineProps<Props>()
const toast = useToast()

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

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(() => {
    toast.add({
      severity: 'success',
      summary: '成功',
      detail: '已复制到剪贴板',
      life: 2000,
    })
  })
}
</script>

<style scoped lang="scss">
.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 24px;
  // 自适应父容器高度
  height: 100%;
  max-height: 100%;
  overflow-y: auto;
  padding-right: 8px;

  &::-webkit-scrollbar {
    width: 6px;
  }

  &::-webkit-scrollbar-track {
    background: var(--p-surface-100);
    border-radius: 3px;
  }

  &::-webkit-scrollbar-thumb {
    background: var(--p-surface-300);
    border-radius: 3px;

    &:hover {
      background: var(--p-surface-400);
    }
  }

  @media (max-width: 768px) {
    grid-template-columns: 1fr;
    gap: 20px;
  }
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 16px;
  background: var(--p-surface-50);
  border-radius: 8px;
  border: 1px solid var(--p-surface-200);

  &.full-width {
    grid-column: 1 / -1;
  }

  label {
    font-size: 14px;
    font-weight: 600;
    color: var(--p-text-muted-color);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .value {
    font-size: 14px;
    color: var(--p-text-color);
    word-break: break-all;
    font-weight: 500;

    &.url {
      flex: 1;
    }
  }

  .text-muted {
    color: var(--p-text-muted-color);
    font-style: italic;
  }
}

.url-display {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  background: var(--p-surface-100);
  border-radius: 8px;
  border: 1px solid var(--p-surface-200);

  .value.url {
    flex: 1;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 14px;
    color: var(--p-text-color);
    padding: 8px 12px;
    background: var(--p-surface-0);
    border-radius: 6px;
    border: 1px solid var(--p-surface-200);
  }
}
</style>