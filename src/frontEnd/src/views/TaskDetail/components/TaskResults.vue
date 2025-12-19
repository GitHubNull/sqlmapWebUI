<template>
  <div>
    <div v-if="loadingPayload" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="payloadData" class="results-container">
      <DataTable :value="payloadData" stripedRows class="result-table" scrollable scrollHeight="flex">
        <Column field="index" header="序号" style="width: 80px" />
        <Column field="status" header="状态" style="width: 100px" />
        <Column field="contentType" header="内容类型" style="width: 150px" />
        <Column field="value" header="载荷内容">
          <template #body="{ data }">
            <div class="payload-value">{{ data.value }}</div>
          </template>
        </Column>
      </DataTable>
    </div>
    <span v-else class="text-muted">无扫描结果</span>
  </div>
</template>

<script setup lang="ts">
interface Props {
  payloadData: any[]
  loadingPayload: boolean
}

defineProps<Props>()
</script>

<style scoped lang="scss">
.results-container {
  // 自适应父容器高度
  height: 100%;
  min-height: 200px;
  overflow: hidden;
}

.loading-small {
  display: flex;
  justify-content: center;
  padding: 20px;
}

.text-muted {
  color: #9ca3af;
  font-style: italic;
  text-align: center;
  padding: 20px;
}

.payload-value {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
  max-width: 500px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding: 8px 12px;
  background: rgba(99, 102, 241, 0.05);
  border-radius: 6px;
  border: 1px solid rgba(99, 102, 241, 0.1);
}

// DataTable样式增强
:deep(.result-table) {
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(99, 102, 241, 0.1);

  .p-datatable-thead > tr > th {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    color: #1f2937;
    font-weight: 600;
  }

  .p-datatable-tbody > tr:hover {
    background: rgba(99, 102, 241, 0.05);
  }
}
</style>