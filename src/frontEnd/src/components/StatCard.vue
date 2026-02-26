<template>
  <Card
    class="stat-card"
    :class="`severity-${severity}`"
    @click="$emit('click')"
  >
    <template #content>
      <div class="stat-content">
        <i :class="icon"></i>
        <div class="stat-info">
          <span class="stat-value">{{ value }}</span>
          <span class="stat-label">{{ label }}</span>
        </div>
      </div>
    </template>
  </Card>
</template>

<script setup lang="ts">
import Card from 'primevue/card'

interface Props {
  icon: string
  value: number
  label: string
  severity: 'primary' | 'secondary' | 'success' | 'info' | 'warn' | 'danger'
}

defineProps<Props>()

defineEmits<{
  click: []
}>()
</script>

<style scoped>
.stat-card {
  cursor: pointer;
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem;
}

.stat-content > i {
  font-size: 1.5rem;
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: var(--p-surface-100);
  color: var(--p-primary-color);
}

/* 修复旋转动画：只旋转图标本身，不旋转容器 */
.stat-content > i.pi-spin {
  animation: none;
}

.stat-content > i.pi-spin::before {
  display: inline-block;
  animation: fa-spin 2s linear infinite;
}

.stat-info {
  display: flex;
  flex-direction: column;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--p-text-color);
  line-height: 1.2;
}

.stat-label {
  font-size: 0.875rem;
  color: var(--p-text-secondary-color);
}

/* Severity variants */
.severity-primary .stat-content > i {
  background: var(--p-surface-100);
  color: var(--p-primary-color);
}

.severity-secondary .stat-content > i {
  background: var(--p-surface-100);
  color: var(--p-surface-600);
}

.severity-success .stat-content > i {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}

.severity-info .stat-content > i {
  background: rgba(59, 130, 246, 0.15);
  color: #3b82f6;
}

.severity-warn .stat-content > i {
  background: rgba(249, 115, 22, 0.15);
  color: #f97316;
}

.severity-danger .stat-content > i {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
}

:deep(.app-dark) .severity-primary .stat-content > i {
  background: var(--p-primary-900);
}

:deep(.app-dark) .severity-secondary .stat-content > i {
  background: var(--p-surface-800);
}

:deep(.app-dark) .severity-success .stat-content > i {
  background: var(--p-green-900);
}

:deep(.app-dark) .severity-info .stat-content > i {
  background: var(--p-blue-900);
}

:deep(.app-dark) .severity-warn .stat-content > i {
  background: var(--p-orange-900);
}

:deep(.app-dark) .severity-danger .stat-content > i {
  background: var(--p-red-900);
}
</style>
