<template>
  <div class="config-page">
    <Card>
      <template #title>配置管理</template>
      <template #content>
        <!-- Tab导航 -->
        <Tabs v-model:value="activeTab" class="config-tabs">
          <TabList>
            <Tab value="0">
              <i class="pi pi-cog"></i>
              <span>系统配置</span>
            </Tab>
            <Tab value="1">
              <i class="pi pi-sliders-h"></i>
              <span>扫描配置</span>
            </Tab>
            <Tab value="2">
              <i class="pi pi-list"></i>
              <span>Header规则管理</span>
            </Tab>
            <Tab value="3">
              <i class="pi pi-clock"></i>
              <span>会话Header管理</span>
            </Tab>
          </TabList>

          <TabPanels>
            <!-- 系统配置 -->
            <TabPanel value="0">
              <div class="config-section">
              <h3>数据刷新设置</h3>
              <div class="field">
                <label>自动刷新间隔 ({{ configStore.autoRefreshInterval }} 分钟)</label>
                <div class="slider-container" :style="{ '--handle-color': handleColor }">
                  <Slider 
                    v-model="sliderDisplayValue" 
                    :min="1" 
                    :max="60" 
                    :step="1"
                    @slideend="handleSliderEnd"
                    class="refresh-slider"
                    :disabled="isSaving"
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
                      :style="{ left: `calc(${((n * 5 - 5) / 55) * 100}%)` }"
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
                  设置任务列表页面的自动刷新间隔，范围为 1-60 分钟（配置存储在服务端）
                </small>
              </div>
            </div>
            </TabPanel>

            <!-- 扫描配置 -->
            <TabPanel value="1">
              <ScanPresetConfig />
            </TabPanel>

            <!-- Header规则管理 -->
            <TabPanel value="2">
              <HeaderRulesConfig />
            </TabPanel>

            <!-- 会话Header管理 -->
            <TabPanel value="3">
              <SessionHeadersConfig />
            </TabPanel>
          </TabPanels>
        </Tabs>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useConfigStore } from '@/stores/config'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import HeaderRulesConfig from './components/HeaderRulesConfig.vue'
import SessionHeadersConfig from './components/SessionHeadersConfig.vue'
import ScanPresetConfig from './components/ScanPresetConfig.vue'

const configStore = useConfigStore()
const activeTab = ref('0')
const isSaving = ref(false)

// 用于显示的临时滑块值（平滑拖动）
const sliderDisplayValue = ref(configStore.autoRefreshInterval)

// 监听store值变化，同步到显示值
onMounted(() => {
  sliderDisplayValue.value = configStore.autoRefreshInterval
})

watch(() => configStore.autoRefreshInterval, (newVal) => {
  sliderDisplayValue.value = newVal
})

// 滑块释放时吸附到最近的刻度
async function handleSliderEnd() {
  const currentValue = sliderDisplayValue.value
  // 计算最近的刻度值（整数）
  const finalValue = Math.max(1, Math.min(60, Math.round(currentValue)))
  
  // 平滑吸附动画
  sliderDisplayValue.value = finalValue
  
  // 更新store（保存到后端）
  if (finalValue !== configStore.autoRefreshInterval) {
    isSaving.value = true
    try {
      await configStore.updateAutoRefreshInterval(finalValue)
    } finally {
      isSaving.value = false
    }
  }
}

// 根据滑块位置计算游标颜色（红-黄-绿渐变）
const handleColor = computed(() => {
  const value = sliderDisplayValue.value
  const min = 1
  const max = 60
  const percent = (value - min) / (max - min) // 0-1
  
  // 颜色节点: 红(0%) -> 橙(15%) -> 黄(35%) -> 黄绿(55%) -> 绿(100%)
  if (percent <= 0.15) {
    const t = percent / 0.15
    return interpolateColor('#ef4444', '#f97316', t)
  } else if (percent <= 0.35) {
    const t = (percent - 0.15) / 0.20
    return interpolateColor('#f97316', '#fbbf24', t)
  } else if (percent <= 0.55) {
    const t = (percent - 0.35) / 0.20
    return interpolateColor('#fbbf24', '#84cc16', t)
  } else {
    const t = (percent - 0.55) / 0.45
    return interpolateColor('#84cc16', '#22c55e', t)
  }
})

// 颜色插值函数
function interpolateColor(color1: string, color2: string, t: number): string {
  const r1 = parseInt(color1.slice(1, 3), 16)
  const g1 = parseInt(color1.slice(3, 5), 16)
  const b1 = parseInt(color1.slice(5, 7), 16)
  const r2 = parseInt(color2.slice(1, 3), 16)
  const g2 = parseInt(color2.slice(3, 5), 16)
  const b2 = parseInt(color2.slice(5, 7), 16)
  
  const r = Math.round(r1 + (r2 - r1) * t)
  const g = Math.round(g1 + (g2 - g1) * t)
  const b = Math.round(b1 + (b2 - b1) * t)
  
  return `rgb(${r}, ${g}, ${b})`
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

// ==================== Tab样式 ====================
:deep(.config-tabs) {
  .p-tablist {
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.7) 100%);
    border-radius: $border-radius-lg $border-radius-lg 0 0;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-bottom: none;
    padding: 8px 12px 0 12px; // 增加左右内边距
    box-shadow: $shadow-raised;
    gap: 12px; // 增加标签之间的间距
    display: flex;
  }

  .p-tab {
    background: transparent;
    border: none;
    padding: 14px 28px; // 增加内边距
    margin-right: 12px; // 增加右边距
    border-radius: $border-radius $border-radius 0 0;
    transition: $transition-base;
    display: flex;
    align-items: center;
    gap: 10px; // 增加图标和文字之间的间距
    cursor: pointer;

    i {
      font-size: 1.2rem; // 稍微增大图标
      transition: $transition-base;
    }

    span {
      font-weight: 600;
      font-size: 15px;
      white-space: nowrap; // 防止文字换行
    }

    &:hover {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.05) 100%);
      
      i {
        color: $primary-color;
        transform: scale(1.1);
      }
    }
  }

  .p-tab[data-p-active="true"] {
    background: $gradient-primary;
    color: white;
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);

    i {
      color: white;
    }
  }

  .p-tabpanels {
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%);
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-radius: 0 0 $border-radius-lg $border-radius-lg;
    padding: 32px 0; // 只保留上下内边距，左右边界对齐
    box-shadow: $shadow-elevated;
  }
}

.config-section {
  margin-bottom: 40px;
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%);
  border-radius: 0; // 移除圆角，使边框对齐
  border: none; // 移除边框
  border-top: 2px solid rgba(255, 255, 255, 0.4);
  border-bottom: 2px solid rgba(255, 255, 255, 0.4);
  box-shadow:
    $shadow-elevated,
    inset 0 2px 4px rgba(255, 255, 255, 0.5);
  padding: 32px 0; // 只保留上下内边距
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
  max-width: 100%;  // 占满宽度
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.6) 0%, rgba(248, 250, 252, 0.4) 100%);
  padding: 24px 0; // 只保留上下内边距
  border-radius: 0; // 移除圆角
  border: none; // 移除边框
  box-shadow: none; // 移除阴影
  position: relative;
  z-index: 2;
  transition: $transition-base;
  overflow: visible;  // 允许60标签溢出显示

  &:hover {
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
  width: 100%;
  padding: 0 50px 50px 20px;  // 右侧内边距加大，确保最大刻度不超出边界
  box-sizing: border-box;
  overflow: visible;
}

.refresh-slider {
  width: 100%;
  height: 20px;
  margin-bottom: 8px;
}

// ==================== 刻度尺样式 ====================
.slider-ruler {
  position: relative;
  width: 100%;
  height: 40px;
  margin-top: 12px;
  overflow: visible;
  z-index: 1; // 确保刻度尺在滑块下方，不遮挡游标
  pointer-events: none; // 禁止刻度尺拦截鼠标事件

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
      border-radius: 1px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    // 根据位置动态生成颜色 - 始终显示红色到绿色渐变
    // 1=5分钟(红), 6=30分钟(黄), 12=60分钟(绿)
    &:nth-child(1) .mark-line { background: #ef4444; box-shadow: 0 2px 4px rgba(239, 68, 68, 0.4); }
    &:nth-child(2) .mark-line { background: #f97316; box-shadow: 0 2px 4px rgba(249, 115, 22, 0.4); }
    &:nth-child(3) .mark-line { background: #fb923c; box-shadow: 0 2px 4px rgba(251, 146, 60, 0.4); }
    &:nth-child(4) .mark-line { background: #fbbf24; box-shadow: 0 2px 4px rgba(251, 191, 36, 0.4); }
    &:nth-child(5) .mark-line { background: #facc15; box-shadow: 0 2px 4px rgba(250, 204, 21, 0.4); }
    &:nth-child(6) .mark-line { background: #eab308; box-shadow: 0 2px 4px rgba(234, 179, 8, 0.4); }
    &:nth-child(7) .mark-line { background: #a3e635; box-shadow: 0 2px 4px rgba(163, 230, 53, 0.4); }
    &:nth-child(8) .mark-line { background: #84cc16; box-shadow: 0 2px 4px rgba(132, 204, 22, 0.4); }
    &:nth-child(9) .mark-line { background: #65a30d; box-shadow: 0 2px 4px rgba(101, 163, 13, 0.4); }
    &:nth-child(10) .mark-line { background: #4ade80; box-shadow: 0 2px 4px rgba(74, 222, 128, 0.4); }
    &:nth-child(11) .mark-line { background: #34d399; box-shadow: 0 2px 4px rgba(52, 211, 153, 0.4); }
    &:nth-child(12) .mark-line { background: #22c55e; box-shadow: 0 2px 4px rgba(34, 197, 94, 0.4); }

    // 标签颜色也跟随渐变
    &:nth-child(1) .mark-label, &:nth-child(2) .mark-label { color: #dc2626; }
    &:nth-child(3) .mark-label, &:nth-child(4) .mark-label, &:nth-child(5) .mark-label, &:nth-child(6) .mark-label { color: #d97706; }
    &:nth-child(7) .mark-label, &:nth-child(8) .mark-label, &:nth-child(9) .mark-label, &:nth-child(10) .mark-label, &:nth-child(11) .mark-label, &:nth-child(12) .mark-label { color: #16a34a; }

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

    // 主要刻度（5、15、30、60）- 更高更粗
    &.major {
      .mark-line {
        height: 20px;
        width: 4px;
      }

      .mark-label {
        font-size: 14px;
        font-weight: 700;
      }
    }

    // 激活状态 - 保持原有颜色，只增强尺寸和发光
    &.active {
      .mark-line {
        height: 24px;
        width: 5px;
        transform: scaleY(1.1);
        filter: brightness(1.2);
        box-shadow: 
          0 4px 8px currentColor,
          0 0 16px currentColor;
      }

      .mark-label {
        transform: translateY(-2px) scale(1.1);
        font-weight: 800;
        box-shadow: 
          0 4px 12px rgba(0, 0, 0, 0.2);
      }
    }

    // hover效果 - 保持原有颜色，只增加尺寸
    &:hover {
      .mark-line {
        transform: scaleY(1.2);
        filter: brightness(1.1);
      }

      .mark-label {
        transform: translateY(-2px) scale(1.05);
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
  // 整个轨道始终显示完整的红-黄-绿渐变
  background:
    linear-gradient(90deg, 
      #ef4444 0%,      // 红色（5分钟）
      #f97316 15%,     // 橙色
      #fbbf24 35%,     // 黄色
      #84cc16 55%,     // 黄绿
      #22c55e 100%     // 绿色（60分钟）
    );
  border-radius: $border-radius-full;
  height: 12px;
  border: 2px solid rgba(255, 255, 255, 0.4);
  box-shadow:
    inset 0 1px 2px rgba(255, 255, 255, 0.3),
    inset 0 -1px 2px rgba(0, 0, 0, 0.1),
    0 2px 8px rgba(0, 0, 0, 0.15);
  position: relative;
  z-index: 10; // 确保滑块在刻度尺上方

  // 隐藏原有的 range 条
  .p-slider-range {
    display: none;
  }

  .p-slider-handle {
    background: var(--handle-color, #ef4444); // 使用动态颜色
    border: 3px solid white;
    border-radius: $border-radius-full;
    width: 32px;
    height: 32px;
    margin-top: -10px;
    margin-left: -16px;
    box-shadow:
      0 4px 12px rgba(0, 0, 0, 0.25),
      0 4px 16px var(--handle-color, rgba(99, 102, 241, 0.3)),
      inset 0 1px 2px rgba(255, 255, 255, 0.4);
    cursor: grab;
    z-index: 20;
    position: relative;
    transition: box-shadow 0.15s ease, transform 0.15s ease;

    &:hover {
      transform: scale(1.15);
      box-shadow:
        0 6px 16px rgba(0, 0, 0, 0.3),
        0 8px 24px var(--handle-color, rgba(99, 102, 241, 0.4)),
        inset 0 1px 2px rgba(255, 255, 255, 0.5);
    }

    &:active {
      cursor: grabbing;
      transform: scale(1.05);
    }

    &:focus {
      outline: none;
      box-shadow:
        0 4px 12px rgba(0, 0, 0, 0.2),
        0 4px 16px var(--handle-color, rgba(99, 102, 241, 0.3)),
        0 0 0 4px rgba(255, 255, 255, 0.5),
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
