<template>
  <div class="scan-preset-config">
    <!-- 子标签页 -->
    <Tabs v-model:value="activeSubTab" class="preset-tabs">
      <TabList>
        <Tab value="default">
          <i class="pi pi-star"></i>
          <span>默认配置</span>
        </Tab>
        <Tab value="preset">
          <i class="pi pi-bookmark"></i>
          <span>常用配置</span>
        </Tab>
        <Tab value="history">
          <i class="pi pi-history"></i>
          <span>历史配置</span>
        </Tab>
      </TabList>

      <TabPanels>
        <!-- 默认配置 -->
        <TabPanel value="default">
          <DefaultConfigPanel 
            @update:options="handleOptionsUpdate" 
            @preview="handlePreview"
          />
        </TabPanel>

        <!-- 常用配置 -->
        <TabPanel value="preset">
          <PresetConfigPanel 
            @select="handlePresetSelect"
            @edit="handlePresetEdit"
          />
        </TabPanel>

        <!-- 历史配置 -->
        <TabPanel value="history">
          <HistoryConfigPanel 
            @select="handleHistorySelect"
          />
        </TabPanel>
      </TabPanels>
    </Tabs>

    <!-- 命令行参数预览对话框 -->
    <Dialog 
      v-model:visible="showPreviewDialog" 
      header="命令行参数预览" 
      :modal="true"
      :style="{ width: '700px' }"
    >
      <div class="preview-content">
        <pre class="command-preview">{{ previewCommand }}</pre>
      </div>
      <template #footer>
        <Button label="复制" icon="pi pi-copy" @click="copyCommand" />
        <Button label="关闭" icon="pi pi-times" severity="secondary" @click="showPreviewDialog = false" />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useToast } from 'primevue/usetoast'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import DefaultConfigPanel from './DefaultConfigPanel.vue'
import PresetConfigPanel from './PresetConfigPanel.vue'
import HistoryConfigPanel from './HistoryConfigPanel.vue'
import type { ScanOptions, ScanPreset } from '@/types/scanPreset'
import { toParameterString } from '@/utils/scanConfigParser'

const toast = useToast()
const activeSubTab = ref('default')

// 预览相关
const showPreviewDialog = ref(false)
const previewCommand = ref('')

// 处理选项更新
function handleOptionsUpdate(options: ScanOptions) {
  console.log('Options updated:', options)
}

// 处理预览
function handlePreview(options: ScanOptions) {
  previewCommand.value = toParameterString(options)
  showPreviewDialog.value = true
}

// 处理预设选择
function handlePresetSelect(preset: ScanPreset) {
  toast.add({
    severity: 'info',
    summary: '配置已选择',
    detail: `已选择配置: ${preset.name}`,
    life: 2000
  })
}

// 处理预设编辑
function handlePresetEdit(preset: ScanPreset) {
  console.log('Edit preset:', preset)
}

// 处理历史选择
function handleHistorySelect(preset: ScanPreset) {
  toast.add({
    severity: 'info',
    summary: '历史配置已选择',
    detail: `已选择: ${preset.name}`,
    life: 2000
  })
}

// 复制命令
async function copyCommand() {
  try {
    await navigator.clipboard.writeText(previewCommand.value)
    toast.add({
      severity: 'success',
      summary: '已复制',
      detail: '命令行参数已复制到剪贴板',
      life: 2000
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: '复制失败',
      detail: '无法访问剪贴板',
      life: 3000
    })
  }
}
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.scan-preset-config {
  padding: 16px 0;
}

:deep(.preset-tabs) {
  .p-tablist {
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%);
    border-radius: var(--p-border-radius);
    padding: 4px 8px;
    gap: 8px;
    margin-bottom: 16px;
  }

  .p-tab {
    padding: 10px 20px;
    border-radius: var(--p-border-radius);
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 500;
    transition: all 0.2s ease;

    i {
      font-size: 1rem;
    }

    &:hover {
      background: rgba(99, 102, 241, 0.1);
    }
  }

  .p-tab[data-p-active="true"] {
    background: var(--p-primary-color);
    color: white;

    i {
      color: white;
    }
  }

  .p-tabpanels {
    padding: 0;
    background: transparent;
  }
}

.preview-content {
  .command-preview {
    background: #1e1e1e;
    color: #d4d4d4;
    padding: 16px;
    border-radius: var(--p-border-radius);
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow: auto;
  }
}
</style>
