<template>
  <div class="task-detail-page">
    <Card>
      <template #title>任务详情</template>
      <template #content>
        <p>任务ID: {{ route.params.id }}</p>
        <p>功能开发中...</p>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()
</script>

<style scoped lang="scss">
.task-detail-page {
  max-width: 1200px;
  margin: 0 auto;
}
</style>
