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

const configStore = useConfigStore()

function handleRefreshIntervalChange() {
  configStore.updateAutoRefreshInterval(configStore.autoRefreshInterval)
  // 移除弹窗提示，避免拖动时频繁弹窗
}
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.config-page {
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px;
  position: relative;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      radial-gradient(circle at 30% 40%, rgba(139, 92, 246, 0.05) 0%, transparent 50%),
      radial-gradient(circle at 70% 60%, rgba(245, 158, 11, 0.05) 0%, transparent 50%),
      url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23f1f5f9' fill-opacity='0.15'%3E%3Cpath d='M30 30m-20 0a20,20 0 1,0 40,0a20,20 0 1,0 -40,0'/%3E%3C/g%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

.config-section {
  margin-bottom: 40px;
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%);
  border-radius: $border-radius-xl;
  border: 2px solid rgba(255, 255, 255, 0.4);
  box-shadow:
    $shadow-elevated,
    inset 0 2px 4px rgba(255, 255, 255, 0.5);
  padding: 32px;
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
      transparent 0%,
      rgba(255, 255, 255, 0.2) 50%,
      transparent 100%);
    animation: config-shimmer 4s ease-in-out infinite;
  }

  h3 {
    margin-bottom: 24px;
    color: $text-color;
    font-weight: $font-weight-bold;
    font-size: 28px;
    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    background: $gradient-warning;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    position: relative;
    z-index: 2;

    &::after {
      content: '';
      position: absolute;
      bottom: -8px;
      left: 0;
      width: 80px;
      height: 4px;
      background: $gradient-warning;
      border-radius: 2px;
      box-shadow: 0 2px 4px rgba(245, 158, 11, 0.3);
    }
  }
}

@keyframes config-shimmer {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(200%);
    opacity: 1;
  }
}

.field {
  display: flex;
  flex-direction: column;
  gap: 20px;
  max-width: 600px;
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.6) 0%, rgba(248, 250, 252, 0.4) 100%);
  padding: 24px;
  border-radius: $border-radius-lg;
  border: 2px solid rgba(255, 255, 255, 0.3);
  box-shadow: $shadow-raised;
  position: relative;
  z-index: 2;
  transition: $transition-base;

  &:hover {
    transform: translateY(-2px);
    box-shadow: $shadow-elevated;
    background:
      linear-gradient(135deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%);
  }

  label {
    font-weight: $font-weight-semibold;
    color: $text-color;
    font-size: 18px;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    background: $gradient-primary;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }
}

.refresh-slider {
  width: 100%;
  height: 20px;
}

.slider-marks {
  display: flex;
  justify-content: space-between;
  font-size: 14px;
  color: $text-color-secondary;
  font-weight: $font-weight-medium;
  margin-top: 8px;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);

  span {
    padding: 4px 8px;
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.6) 0%, rgba(248, 250, 252, 0.4) 100%);
    border-radius: $border-radius;
    border: 1px solid rgba(255, 255, 255, 0.3);
    box-shadow: $shadow-raised;
    transition: $transition-base;

    &:hover {
      transform: translateY(-1px) scale(1.05);
      box-shadow: $shadow-elevated;
      color: $primary-color;
    }
  }
}

.field-help {
  color: $text-color-secondary;
  line-height: 1.6;
  font-size: 14px;
  font-style: italic;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
  padding: 12px 16px;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.4) 0%, rgba(248, 250, 252, 0.2) 100%);
  border-radius: $border-radius;
  border: 1px solid rgba(255, 255, 255, 0.2);
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.05);
}

// ==================== PrimeVue滑块3D增强 ====================
:deep(.p-slider) {
  background:
    linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
  border-radius: $border-radius-full;
  height: 12px;
  border: 2px solid rgba(99, 102, 241, 0.2);
  box-shadow:
    inset 0 2px 6px rgba(0, 0, 0, 0.1),
    inset 0 0 12px rgba(99, 102, 241, 0.1),
    0 1px 3px rgba(0, 0, 0, 0.1);
  position: relative;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(90deg,
      transparent 0%,
      rgba(255, 255, 255, 0.3) 50%,
      transparent 100%);
    border-radius: inherit;
    animation: slider-glow 3s ease-in-out infinite;
  }

  .p-slider-range {
    background: $gradient-primary;
    border-radius: inherit;
    height: 100%;
    box-shadow:
      inset 0 1px 2px rgba(255, 255, 255, 0.3),
      inset 0 -1px 2px rgba(0, 0, 0, 0.2),
      0 0 10px rgba(99, 102, 241, 0.4);
    position: relative;
    overflow: hidden;

    &::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg,
        transparent 0%,
        rgba(255, 255, 255, 0.4) 50%,
        transparent 100%);
      animation: range-shimmer 2s ease-in-out infinite;
    }
  }

  .p-slider-handle {
    background: $gradient-primary;
    border: 3px solid white;
    border-radius: $border-radius-full;
    width: 28px;
    height: 28px;
    margin-top: -8px;
    box-shadow:
      0 4px 12px rgba(0, 0, 0, 0.2),
      0 8px 24px rgba(99, 102, 241, 0.3),
      inset 0 1px 2px rgba(255, 255, 255, 0.4);
    transition: $transition-base;
    cursor: grab;

    &:hover {
      transform: scale(1.2);
      box-shadow:
        0 6px 16px rgba(0, 0, 0, 0.25),
        0 12px 32px rgba(99, 102, 241, 0.4),
        inset 0 1px 2px rgba(255, 255, 255, 0.5);
    }

    &:active {
      cursor: grabbing;
      transform: scale(1.1);
      box-shadow:
        0 2px 8px rgba(0, 0, 0, 0.3),
        0 4px 16px rgba(99, 102, 241, 0.5),
        inset 0 1px 2px rgba(255, 255, 255, 0.3);
    }

    &:focus {
      outline: none;
      box-shadow:
        0 4px 12px rgba(0, 0, 0, 0.2),
        0 8px 24px rgba(99, 102, 241, 0.3),
        0 0 0 3px rgba(99, 102, 241, 0.3),
        inset 0 1px 2px rgba(255, 255, 255, 0.4);
    }
  }
}

@keyframes slider-glow {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(100%);
    opacity: 1;
  }
}

@keyframes range-shimmer {
  0%, 100% {
    transform: translateX(-100%);
  }
  50% {
    transform: translateX(100%);
  }
}
</style>
