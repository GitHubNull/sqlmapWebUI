<template>
  <div class="config-page">
    <Card>
      <template #title>配置管理</template>
      <template #content>
        <div class="config-section">
          <h3>数据刷新设置</h3>
          <div class="field">
            <label>自动刷新间隔 ({{ configStore.autoRefreshInterval }} 分钟)</label>
            <div class="slider-container">
              <Slider 
                v-model="configStore.autoRefreshInterval" 
                :min="5" 
                :max="60" 
                :step="5"
                @change="handleRefreshIntervalChange"
                class="refresh-slider"
              />
              <!-- 刻度尺标记 -->
              <div class="slider-ruler">
                <div 
                  v-for="n in 12" 
                  :key="n" 
                  class="ruler-mark"
                  :class="{
                    'major': n * 5 === 5 || n * 5 === 15 || n * 5 === 30 || n * 5 === 60,
                    'active': configStore.autoRefreshInterval === n * 5
                  }"
                  :style="{ left: `calc(${((n * 5 - 5) / 55) * 100}% + 14px)` }"
                >
                  <div class="mark-line"></div>
                  <div 
                    v-if="n * 5 === 5 || n * 5 === 15 || n * 5 === 30 || n * 5 === 60" 
                    class="mark-label"
                  >
                    {{ n * 5 }}
                  </div>
                </div>
              </div>
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
  width: 100%;  // 占满主内容区域，不限制最大宽度
  margin: 0;
  padding: 32px 0;  // 只保留上下内边距
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
  max-width: 800px;  // 扩大到800px，适应更多配置项
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.6) 0%, rgba(248, 250, 252, 0.4) 100%);
  padding: 24px;
  border-radius: $border-radius-lg;
  border: 2px solid rgba(255, 255, 255, 0.3);
  box-shadow: $shadow-raised;
  position: relative;
  z-index: 2;
  transition: $transition-base;
  overflow: visible;  // 允许60标签溢出显示

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

.slider-container {
  position: relative;
  width: 100%;  // 恢复为100%
  padding-bottom: 50px;  // 为刻度尺预留空间
  overflow: visible;  // 允许右侧标签溢出显示
}

.refresh-slider {
  width: 100%;  // 恢复为100%
  height: 20px;
  margin-bottom: 8px;
}

// ==================== 刻度尺样式 ====================
.slider-ruler {
  position: relative;
  width: 100%;  // 与滑块宽度一致
  height: 40px;
  margin-top: 12px;
  overflow: visible;  // 允许右侧标签溢出

  .ruler-mark {
    position: absolute;
    transform: translateX(-50%);
    display: flex;
    flex-direction: column;
    align-items: center;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);

    .mark-line {
      width: 2px;
      height: 12px;
      background: linear-gradient(180deg, rgba(148, 163, 184, 0.4) 0%, rgba(148, 163, 184, 0.8) 100%);
      border-radius: 1px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    // 根据位置动态生成颜色
    @for $i from 1 through 12 {
      &:nth-child(#{$i}) .mark-line {
        $percent: ($i - 1) / 11 * 100%;  // 0% 到 100%
        @if $i <= 4 {
          // 5-20分钟: 红色系
          background: linear-gradient(180deg, 
            rgba(239, 68, 68, 0.4) 0%, 
            rgba(239, 68, 68, 0.8) 100%
          );
        } @else if $i <= 7 {
          // 25-35分钟: 黄色系
          background: linear-gradient(180deg, 
            rgba(251, 191, 36, 0.4) 0%, 
            rgba(251, 191, 36, 0.8) 100%
          );
        } @else {
          // 40-60分钟: 绿色系
          background: linear-gradient(180deg, 
            rgba(34, 197, 94, 0.4) 0%, 
            rgba(34, 197, 94, 0.8) 100%
          );
        }
      }
    }

    .mark-label {
      margin-top: 8px;
      font-size: 13px;
      font-weight: 600;
      color: $text-color-secondary;
      text-shadow: 0 1px 2px rgba(255, 255, 255, 0.8);
      padding: 4px 10px;
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.7) 100%);
      border-radius: 6px;
      border: 1px solid rgba(148, 163, 184, 0.2);
      box-shadow: 
        0 2px 4px rgba(0, 0, 0, 0.08),
        inset 0 1px 2px rgba(255, 255, 255, 0.6);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    // 主要刻度（5、15、30、60）
    &.major {
      .mark-line {
        height: 20px;
        width: 3px;
      }

      .mark-label {
        font-size: 14px;
        font-weight: 700;
      }

      // 5分钟 - 红色
      &:nth-child(1) {
        .mark-line {
          background: linear-gradient(180deg, rgba(239, 68, 68, 0.6) 0%, #ef4444 100%);
          box-shadow: 0 2px 4px rgba(239, 68, 68, 0.3), 0 0 8px rgba(239, 68, 68, 0.2);
        }
        .mark-label {
          color: #dc2626;
        }
      }

      // 15分钟 - 橙色
      &:nth-child(3) {
        .mark-line {
          background: linear-gradient(180deg, rgba(245, 158, 11, 0.6) 0%, #f59e0b 100%);
          box-shadow: 0 2px 4px rgba(245, 158, 11, 0.3), 0 0 8px rgba(245, 158, 11, 0.2);
        }
        .mark-label {
          color: #d97706;
        }
      }

      // 30分钟 - 黄绿
      &:nth-child(6) {
        .mark-line {
          background: linear-gradient(180deg, rgba(132, 204, 22, 0.6) 0%, #84cc16 100%);
          box-shadow: 0 2px 4px rgba(132, 204, 22, 0.3), 0 0 8px rgba(132, 204, 22, 0.2);
        }
        .mark-label {
          color: #65a30d;
        }
      }

      // 60分钟 - 绿色
      &:nth-child(12) {
        .mark-line {
          background: linear-gradient(180deg, rgba(34, 197, 94, 0.6) 0%, #22c55e 100%);
          box-shadow: 0 2px 4px rgba(34, 197, 94, 0.3), 0 0 8px rgba(34, 197, 94, 0.2);
        }
        .mark-label {
          color: #16a34a;
        }
      }
    }

    // 激活状态
    &.active {
      .mark-line {
        height: 24px;
        width: 4px;
        background: $gradient-primary;
        box-shadow: 
          0 4px 8px rgba(99, 102, 241, 0.4),
          0 0 16px rgba(99, 102, 241, 0.4),
          inset 0 1px 2px rgba(255, 255, 255, 0.3);
        transform: scaleY(1.1);
      }

      .mark-label {
        background: $gradient-primary;
        color: white;
        transform: translateY(-2px) scale(1.1);
        box-shadow: 
          0 4px 12px rgba(99, 102, 241, 0.4),
          0 0 16px rgba(99, 102, 241, 0.3),
          inset 0 1px 2px rgba(255, 255, 255, 0.3);
        border-color: transparent;
      }
    }

    // hover效果
    &:hover {
      .mark-line {
        transform: scaleY(1.2);
        background: linear-gradient(180deg, rgba(99, 102, 241, 0.6) 0%, rgba(99, 102, 241, 1) 100%);
        box-shadow: 
          0 2px 6px rgba(99, 102, 241, 0.4),
          0 0 12px rgba(99, 102, 241, 0.3);
      }

      .mark-label {
        transform: translateY(-2px) scale(1.05);
        color: $primary-color;
        box-shadow: 
          0 4px 8px rgba(0, 0, 0, 0.12),
          inset 0 1px 2px rgba(255, 255, 255, 0.7);
      }
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

// ==================== PrimeVue滑块3D增强 + 颜色渐变 ====================
:deep(.p-slider) {
  background:
    linear-gradient(90deg, 
      rgba(239, 68, 68, 0.15) 0%,     // 红色（5分钟）
      rgba(251, 191, 36, 0.15) 36%,   // 黄色（25分钟）
      rgba(34, 197, 94, 0.15) 100%    // 绿色（60分钟）
    );
  border-radius: $border-radius-full;
  height: 12px;
  border: 2px solid rgba(148, 163, 184, 0.2);
  box-shadow:
    inset 0 2px 6px rgba(0, 0, 0, 0.1),
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
    background: linear-gradient(90deg, 
      #ef4444 0%,      // 红色（5分钟）- 高频率，资源占用多
      #f59e0b 18%,     // 橙色（15分钟）
      #fbbf24 36%,     // 黄色（25分钟）
      #84cc16 54%,     // 黄绿（35分钟）
      #22c55e 100%     // 绿色（60分钟）- 低频率，资源占用少
    );
    border-radius: inherit;
    height: 100%;
    box-shadow:
      inset 0 1px 2px rgba(255, 255, 255, 0.3),
      inset 0 -1px 2px rgba(0, 0, 0, 0.2),
      0 0 10px rgba(34, 197, 94, 0.3);  // 绿色发光
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
