<template>
  <div class="preset-mode-content">
    <!-- 预设类型选择器 -->
    <div class="preset-category-selector">
      <label class="selector-label">选择预设类型</label>
      <Select
        :modelValue="presetCategory"
        @update:modelValue="$emit('update:presetCategory', $event)"
        :options="PRESET_CATEGORY_OPTIONS"
        optionLabel="label"
        optionValue="value"
        class="w-full preset-category-select"
        style="max-width: 300px;"
      >
        <template #value="slotProps">
          <div v-if="slotProps.value" class="preset-category-item">
            <i :class="getCategoryOption(slotProps.value)?.icon"></i>
            <span>{{ getCategoryOption(slotProps.value)?.label }}</span>
          </div>
          <span v-else>选择预设类型</span>
        </template>
        <template #option="slotProps">
          <div class="preset-category-item">
            <i :class="slotProps.option.icon" :style="{ color: slotProps.option.color }"></i>
            <span>{{ slotProps.option.label }}</span>
          </div>
        </template>
      </Select>
    </div>

    <!-- 预设列表显示区域 -->
    <div class="preset-list-area">
      <!-- 默认配置 -->
      <div v-if="presetCategory === 'default'" class="preset-list-container preset-default">
        <div class="preset-list-header">
          <i class="pi pi-star"></i>
          <span>默认配置</span>
          <span class="preset-count">{{ presetStore.defaultPreset ? 1 : 0 }} 项</span>
        </div>
        <div class="preset-list-content preset-grid">
          <div 
            v-if="presetStore.defaultPreset"
            class="preset-card preset-card-default"
            :class="{ selected: selectedPresetId === presetStore.defaultPreset.id }"
            @click="handleSelect(presetStore.defaultPreset)"
          >
            <div class="preset-card-header">
              <span class="preset-name">{{ presetStore.defaultPreset.name }}</span>
              <Tag severity="success" value="默认" />
            </div>
            <div class="preset-card-desc">{{ presetStore.defaultPreset.description || '系统默认扫描配置' }}</div>
            <div class="preset-card-params">
              <code v-if="presetStore.defaultPreset.parameter_string">{{ truncateParams(presetStore.defaultPreset.parameter_string) }}</code>
              <span v-else class="default-params-hint">--batch (使用默认参数)</span>
            </div>
          </div>
          <div v-else class="preset-empty-hint">
            <i class="pi pi-info-circle"></i>
            <span>暂无默认配置</span>
          </div>
        </div>
      </div>

      <!-- 常用配置 -->
      <div v-else-if="presetCategory === 'common'" class="preset-list-container preset-common">
        <div class="preset-list-header">
          <i class="pi pi-bookmark"></i>
          <span>常用配置</span>
          <span class="preset-count">{{ presetStore.presetConfigs.length }} 项</span>
        </div>
        <div class="preset-list-content preset-grid">
          <div 
            v-for="preset in presetStore.presetConfigs" 
            :key="preset.id"
            class="preset-card preset-card-common"
            :class="{ selected: selectedPresetId === preset.id }"
            @click="handleSelect(preset)"
          >
            <div class="preset-card-header">
              <span class="preset-name">{{ preset.name }}</span>
            </div>
            <div class="preset-card-desc">{{ preset.description || '暂无描述' }}</div>
            <div class="preset-card-params">
              <code v-if="preset.parameter_string">{{ truncateParams(preset.parameter_string) }}</code>
              <span v-else class="default-params-hint">--batch (使用默认参数)</span>
            </div>
          </div>
          <div v-if="presetStore.presetConfigs.length === 0" class="preset-empty-hint">
            <i class="pi pi-inbox"></i>
            <span>暂无常用配置，您可以在自定义配置后保存为预设</span>
          </div>
        </div>
      </div>

      <!-- 历史配置 -->
      <div v-else-if="presetCategory === 'history'" class="preset-list-container preset-history">
        <div class="preset-list-header">
          <i class="pi pi-history"></i>
          <span>历史配置</span>
          <span class="preset-count">{{ presetStore.historyConfigs.length }} 项</span>
        </div>
        <div class="preset-list-content preset-grid">
          <div 
            v-for="preset in presetStore.historyConfigs.slice(0, 10)" 
            :key="preset.id"
            class="preset-card preset-card-history"
            :class="{ selected: selectedPresetId === preset.id }"
            @click="handleSelect(preset)"
          >
            <div class="preset-card-header">
              <span class="preset-name">
                <span class="preset-id">#{{ preset.id }}</span>
                {{ preset.name }}
              </span>
              <Tag severity="warn" value="历史" />
            </div>
            <div class="preset-card-params">
              <code v-if="preset.parameter_string">{{ truncateParams(preset.parameter_string) }}</code>
              <span v-else class="default-params-hint">--batch (使用默认参数)</span>
            </div>
          </div>
          <div v-if="presetStore.historyConfigs.length === 0" class="preset-empty-hint">
            <i class="pi pi-clock"></i>
            <span>暂无历史配置记录</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import { useScanPresetStore } from '@/stores/scanPreset'
import type { ScanPreset } from '@/types/scanPreset'

interface Props {
  presetCategory: 'default' | 'common' | 'history'
  selectedPresetId: number | null
}

defineProps<Props>()

const emit = defineEmits<{
  'update:presetCategory': [category: string]
  select: [preset: ScanPreset]
}>()

const presetStore = useScanPresetStore()

// 预设类型选项
const PRESET_CATEGORY_OPTIONS = [
  { label: '默认配置', value: 'default', icon: 'pi pi-star', color: '#10b981' },
  { label: '常用配置', value: 'common', icon: 'pi pi-bookmark', color: '#6366f1' },
  { label: '历史配置', value: 'history', icon: 'pi pi-history', color: '#f59e0b' }
]

// 方法
function getCategoryOption(value: string) {
  return PRESET_CATEGORY_OPTIONS.find(o => o.value === value)
}

function truncateParams(params: string): string {
  return params.length > 80 ? params.substring(0, 80) + '...' : params
}

function handleSelect(preset: ScanPreset) {
  emit('select', preset)
}
</script>

<style scoped>
.preset-mode-content {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.preset-category-selector {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.preset-category-selector .selector-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-color-secondary);
}

.preset-category-select :deep(.p-select-label) {
  padding: 0.6rem 0.75rem;
}

.preset-category-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.preset-category-item i {
  font-size: 1rem;
}

.preset-list-area {
  min-height: 0;
}

.preset-list-container {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem;
  border-radius: 8px;
}

.preset-list-container.preset-default {
  background: rgba(16, 185, 129, 0.08);
  border: 1px solid rgba(16, 185, 129, 0.3);
}

.preset-list-container.preset-common {
  background: rgba(99, 102, 241, 0.08);
  border: 1px solid rgba(99, 102, 241, 0.3);
}

.preset-list-container.preset-history {
  background: rgba(245, 158, 11, 0.08);
  border: 1px solid rgba(245, 158, 11, 0.3);
}

.preset-list-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
  font-size: 0.9rem;
  color: var(--text-color);
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--surface-border);
  margin-bottom: 0.25rem;
}

.preset-list-header i {
  font-size: 1rem;
}

.preset-default .preset-list-header i { color: #10b981; }
.preset-common .preset-list-header i { color: #6366f1; }
.preset-history .preset-list-header i { color: #f59e0b; }

.preset-count {
  margin-left: auto;
  font-size: 0.75rem;
  font-weight: 400;
  color: var(--text-color-secondary);
  background: var(--surface-200);
  padding: 0.15rem 0.5rem;
  border-radius: 10px;
}

/* 预设卡片多列网格 */
.preset-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 0.75rem;
}

.preset-card {
  padding: 0.75rem;
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  cursor: pointer;
  background: var(--surface-card);
  transition: border-color 0.2s, background 0.2s;
}

.preset-card:hover {
  border-color: var(--p-primary-color);
}

.preset-card-default { border-color: rgba(16, 185, 129, 0.3); }
.preset-card-default:hover { border-color: #10b981; background: rgba(16, 185, 129, 0.05); }
.preset-card-default.selected { border-color: #10b981; background: rgba(16, 185, 129, 0.1); }

.preset-card-common { border-color: rgba(99, 102, 241, 0.3); }
.preset-card-common:hover { border-color: #6366f1; background: rgba(99, 102, 241, 0.05); }
.preset-card-common.selected { border-color: #6366f1; background: rgba(99, 102, 241, 0.1); }

.preset-card-history { border-color: rgba(245, 158, 11, 0.3); }
.preset-card-history:hover { border-color: #f59e0b; background: rgba(245, 158, 11, 0.05); }
.preset-card-history.selected { border-color: #f59e0b; background: rgba(245, 158, 11, 0.1); }

.preset-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.25rem;
}

.preset-name {
  font-weight: 500;
  color: var(--text-color);
  font-size: 0.95rem;
}

.preset-id {
  display: inline-block;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--p-primary-color);
  background: rgba(var(--p-primary-color-rgb, 99, 102, 241), 0.1);
  padding: 1px 6px;
  border-radius: 4px;
  margin-right: 0.5rem;
}

.preset-card-desc {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
  margin-bottom: 0.25rem;
}

.preset-card-params {
  padding: 0.35rem 0.5rem;
  background: #1e1e2e;
  border-radius: 4px;
  margin-top: 0.35rem;
}

.preset-card-params code {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.75rem;
  color: #89b4fa;
}

.preset-card-params .default-params-hint {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.75rem;
  color: #6c7086;
  font-style: italic;
}

.preset-empty-hint {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
  background: var(--surface-100);
  border-radius: 6px;
  border: 1px dashed var(--surface-border);
  grid-column: 1 / -1;
}

.preset-empty-hint i {
  font-size: 1rem;
  opacity: 0.6;
}

.w-full {
  width: 100%;
}

@media (max-width: 900px) {
  .preset-grid {
    grid-template-columns: 1fr;
  }
}
</style>
