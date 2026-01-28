<template>
  <div class="config-page">
    <Card>
      <template #title>配置管理</template>
      
      <template #content>
        <Tabs v-model:value="activeTab">
          <TabList>
            <Tab value="0"><i class="pi pi-cog"></i><span>系统配置</span></Tab>
            <Tab value="1"><i class="pi pi-sliders-h"></i><span>扫描配置</span></Tab>
            <Tab value="2"><i class="pi pi-list"></i><span>Header规则</span></Tab>
            <Tab value="3"><i class="pi pi-clock"></i><span>会话Header</span></Tab>
            <Tab value="4"><i class="pi pi-code"></i><span>Body字段</span></Tab>
          </TabList>

          <TabPanels>
            <TabPanel value="0">
              <div class="config-section">
                <label>自动刷新间隔 ({{ configStore.autoRefreshInterval }} 分钟)</label>
                <Slider
                  v-model="sliderValue"
                  :min="1"
                  :max="60"
                  :step="1"
                  @slideend="handleSliderEnd"
                  :disabled="isSaving"
                />
                
                <small class="help-text">
                  设置任务列表页面的自动刷新间隔，范围为 1-60 分钟
                </small>
              </div>
            </TabPanel>

            <TabPanel value="1">
              <ScanPresetConfig />
            </TabPanel>

            <TabPanel value="2">
              <HeaderRulesConfig />
            </TabPanel>

            <TabPanel value="3">
              <SessionHeadersConfig />
            </TabPanel>

            <TabPanel value="4">
              <SessionBodyFieldsConfig />
            </TabPanel>
          </TabPanels>
        </Tabs>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useConfigStore } from '@/stores/config'
import Card from 'primevue/card'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import Slider from 'primevue/slider'
import ScanPresetConfig from './components/ScanPresetConfig.vue'
import HeaderRulesConfig from './components/HeaderRulesConfig.vue'
import SessionHeadersConfig from './components/SessionHeadersConfig.vue'
import SessionBodyFieldsConfig from './components/SessionBodyFieldsConfig.vue'
import { useToast } from 'primevue/usetoast'

const configStore = useConfigStore()
const toast = useToast()

const activeTab = ref('0')
const isSaving = ref(false)

const sliderValue = computed({
  get: () => configStore.autoRefreshInterval,
  set: (val) => {
    if (typeof val === 'number') {
      configStore.autoRefreshInterval = val
    }
  }
})

async function handleSliderEnd() {
  isSaving.value = true
  try {
    const success = await configStore.updateAutoRefreshInterval(sliderValue.value)
    if (success) {
      toast.add({
        severity: 'success',
        summary: '保存成功',
        detail: `刷新间隔已设置为 ${sliderValue.value} 分钟`,
        life: 3000
      })
    }
  } catch {
    toast.add({
      severity: 'error',
      summary: '保存失败',
      detail: '更新刷新间隔失败',
      life: 3000
    })
  } finally {
    isSaving.value = false
  }
}
</script>

<style scoped>
.config-page {
  max-width: 1200px;
  margin: 0 auto;
}

.config-section {
  padding: 1rem 0;
}

.config-section label {
  display: block;
  margin-bottom: 0.75rem;
  font-weight: 500;
}

.help-text {
  display: block;
  margin-top: 0.5rem;
  color: var(--p-text-secondary-color);
}
</style>
