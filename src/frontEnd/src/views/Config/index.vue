<template>
  <div class="config-page">
    <Card>
      <template #title>配置管理</template>
      <template #content>
        <div class="config-section">
          <h3>主题设置</h3>
          <div class="field">
            <label>主题模式</label>
            <SelectButton v-model="configStore.theme" :options="themeOptions" optionLabel="label" optionValue="value" @change="handleThemeChange" />
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { useConfigStore } from '@/stores/config'

const configStore = useConfigStore()

const themeOptions = [
  { label: '亮色', value: 'light' },
  { label: '暗色', value: 'dark' },
]

function handleThemeChange() {
  configStore.updateTheme(configStore.theme)
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
  }
}

.field {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-width: 300px;
}
</style>
