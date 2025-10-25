<template>
  <div class="config-page">
    <Card>
      <template #title>配置管理</template>
      <template #content>
        <div class="config-section">
          <h3>数据刷新设置</h3>
          <div class="field">
            <label>自动刷新间隔 ({{ configStore.autoRefreshInterval }} 分钟)</label>
            <Slider 
              v-model="configStore.autoRefreshInterval" 
              :min="5" 
              :max="60" 
              :step="5"
              @change="handleRefreshIntervalChange"
              class="refresh-slider"
            />
            <div class="slider-marks">
              <span>5分钟</span>
              <span>15分钟</span>
              <span>30分钟</span>
              <span>60分钟</span>
            </div>
            <small class="field-help">
              设置任务列表页面的自动刷新间隔，范围为5-60分钟，每5分钟一个间隔
            </small>
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { useConfigStore } from '@/stores/config'
import { useToast } from 'primevue/usetoast'

const configStore = useConfigStore()
const toast = useToast()

function handleRefreshIntervalChange() {
  configStore.updateAutoRefreshInterval(configStore.autoRefreshInterval)
  toast.add({
    severity: 'success',
    summary: '成功',
    detail: `自动刷新间隔已设置为 ${configStore.autoRefreshInterval} 分钟`,
    life: 3000,
  })
}
</script>

<style scoped lang="scss">
.config-page {
  max-width: 1200px;
  margin: 0 auto;
}

.config-section {
  margin-bottom: 24px;

  h3 {
    margin-bottom: 16px;
    color: #1f2937;
    font-weight: 600;
  }
}

.field {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-width: 500px;
  
  label {
    font-weight: 500;
    color: #374151;
  }
}

.refresh-slider {
  width: 100%;
}

.slider-marks {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  color: #6b7280;
  margin-top: -8px;
}

.field-help {
  color: #6b7280;
  line-height: 1.5;
}
</style>
