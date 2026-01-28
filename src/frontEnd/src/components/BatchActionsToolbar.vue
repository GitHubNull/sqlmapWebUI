<template>
  <div v-if="selectedCount > 0" class="batch-actions-toolbar">
    <div class="selection-info">
      <i class="pi pi-check-circle"></i>
      <span>已选择 {{ selectedCount }} 项</span>
    </div>
    
    <div class="action-buttons">
      <Button
        v-for="action in actions"
        :key="action.label"
        :label="action.label"
        :icon="action.icon"
        :severity="action.severity"
        :outlined="action.outlined"
        @click="action.onClick"
        size="small"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import Button from 'primevue/button'

interface Action {
  label: string
  icon: string
  severity?: 'primary' | 'secondary' | 'success' | 'info' | 'warn' | 'danger'
  outlined?: boolean
  onClick: () => void
}

interface Props {
  selectedCount: number
  actions: Action[]
}

defineProps<Props>()
</script>

<style scoped>
.batch-actions-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1rem;
  background: var(--p-primary-50);
  border: 1px solid var(--p-primary-200);
  border-radius: var(--p-border-radius);
  margin-bottom: 1rem;
}

.selection-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--p-primary-color);
  font-weight: 500;
}

.action-buttons {
  display: flex;
  gap: 0.5rem;
}

@media (max-width: 640px) {
  .batch-actions-toolbar {
    flex-direction: column;
    gap: 0.75rem;
    align-items: stretch;
  }
  
  .action-buttons {
    flex-direction: column;
  }
}
</style>
