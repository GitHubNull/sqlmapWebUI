<template>
  <div class="dock-layout">
    <!-- 顶部状态栏 -->
    <header class="status-bar">
      <div class="status-bar-left">
        <Avatar icon="pi pi-shield" class="app-logo" shape="circle" size="normal" />
        <span class="app-name">SqlmapWebUI</span>
      </div>
      <div class="status-bar-right">
        <!-- 主题切换 -->

        <div class="theme-switch">
          <i class="pi pi-sun theme-icon" :class="{ active: configStore.theme === 'light' }"></i>
          <ToggleSwitch
            v-model="isDarkMode"
            @change="handleThemeToggle"
            v-tooltip.bottom="isDarkMode ? '切换到亮色主题' : '切换到暗色主题'"
          />
          <i class="pi pi-moon theme-icon" :class="{ active: configStore.theme === 'dark' }"></i>
        </div>
        
        <Badge 
          v-if="authStore.isLocalMode" 
          value="本地模式" 
          severity="success" 
          class="mode-badge"
        />
        <Badge 
          v-else 
          value="远程模式" 
          severity="info" 
          class="mode-badge"
        />
        <span v-if="!authStore.isLocalMode" class="user-name">{{ authStore.userName }}</span>
        <Button 
          v-if="!authStore.isLocalMode" 
          icon="pi pi-sign-out" 
          @click="handleLogout" 
          text 
          rounded 
          severity="secondary"
          v-tooltip.bottom="'登出'"
        />
      </div>
    </header>

    <!-- 主内容区域 -->
    <main class="main-content">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>

    <!-- 底部Dock导航栏 -->
    <nav class="dock-container" role="navigation" aria-label="主导航栏">
      <div class="dock">
        <div 
          v-for="item in dockItems" 
          :key="item.id"
          class="dock-item-wrapper"
          @mouseenter="hoveredItem = item.id"
          @mouseleave="hoveredItem = null"
        >
          <Button
            :class="['dock-item', { active: isActiveRoute(item.route), hovered: hoveredItem === item.id }]"
            @click="navigateTo(item.route)"
            @keydown.enter="navigateTo(item.route)"
            @keydown.space.prevent="navigateTo(item.route)"
            text
            rounded
            :aria-label="item.label + '导航'"
            :aria-current="isActiveRoute(item.route) ? 'page' : undefined"
            v-tooltip.top="getTooltipText(item)"
            :tabindex="0"
          >
            <i :class="['dock-icon', item.icon]"></i>
            <Badge 
              v-if="item.badge !== null && item.badge !== undefined && item.badge > 0" 
              :value="item.badge > 99 ? '99+' : item.badge" 
              :severity="item.badgeVariant || 'danger'"
              class="dock-badge"
              :class="{ pulse: item.badge > 0 }"
            />
          </Button>
          <div v-if="isActiveRoute(item.route)" class="active-indicator"></div>
        </div>
      </div>
    </nav>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useTaskStore } from '@/stores/task'
import { useConfigStore } from '@/stores/config'
import { useRouter, useRoute } from 'vue-router'
import { useSmartPolling } from '@/utils/useSmartPolling'
import ToggleSwitch from 'primevue/toggleswitch'

// Stores
const authStore = useAuthStore()
const taskStore = useTaskStore()
const configStore = useConfigStore()
const router = useRouter()
const route = useRoute()

// 状态
const currentRoute = ref<string>(route.path)
const hoveredItem = ref<string | null>(null)
const isDarkMode = computed({
  get: () => configStore.theme === 'dark',
  set: (value: boolean) => {
    configStore.updateTheme(value ? 'dark' : 'light')
  }
})

// Dock项数据结构
interface DockItem {
  id: string
  label: string
  icon: string
  route: string
  badge?: number | null
  badgeVariant?: string
}

// Dock导航项配置
const dockItems = computed<DockItem[]>(() => [
  {
    id: 'home',
    label: '首页',
    icon: 'pi pi-home',
    route: '/home',
    badge: null,
  },
  {
    id: 'tasks',
    label: '任务',
    icon: 'pi pi-list',
    route: '/tasks',
    badge: runningTaskCount.value,
    badgeVariant: 'danger',
  },
  {
    id: 'config',
    label: '配置',
    icon: 'pi pi-cog',
    route: '/config',
    badge: null,
  },
])

// 计算运行中的任务数量
const runningTaskCount = computed(() => {
  // status: 0-等待中, 1-运行中, 2-完成, 3-失败
  return taskStore.taskList.filter(task => task.status === 1).length
})

// 判断是否为活跃路由
function isActiveRoute(routePath: string): boolean {
  // 对于任务详情页，也应该高亮任务列表项
  if (currentRoute.value.startsWith('/tasks')) {
    return routePath === '/tasks'
  }
  return currentRoute.value === routePath
}

// 路由跳转
function navigateTo(path: string): void {
  if (currentRoute.value !== path) {
    router.push(path)
  }
}

// 获取Tooltip文本
function getTooltipText(item: DockItem): string {
  if (item.badge && item.badge > 0) {
    return `${item.label} - ${item.badge}个运行中`
  }
  return item.label
}

// 登出处理
function handleLogout(): void {
  authStore.logout()
  router.push('/login')
}

// 主题切换处理
function handleThemeToggle(): void {
  configStore.updateTheme(isDarkMode.value ? 'dark' : 'light')
}

// 键盘快捷键处理
function handleKeyboardShortcut(event: KeyboardEvent): void {
  if (event.altKey && !event.ctrlKey && !event.shiftKey) {
    const key = event.key
    const keyMap: Record<string, string> = {
      '1': '/home',
      '2': '/tasks',
      '3': '/config',
    }
    
    if (keyMap[key]) {
      event.preventDefault()
      navigateTo(keyMap[key])
    }
  }
}

// 监听路由变化
watch(
  () => route.path,
  (newPath) => {
    currentRoute.value = newPath
  },
  { immediate: true }
)

// 组件挂载时初始化
onMounted(() => {
  currentRoute.value = route.path
  
  // 使用智能轮询加载任务列表
  useSmartPolling({
    callback: async () => {
      await taskStore.fetchTaskList()
    },
    interval: 5000,              // 页面可见时每5秒一次
    backgroundInterval: 30000,    // 页面隐藏时每30秒一次
    pauseOnUnhealthy: true,       // 后端不健康时暂停轮询
    immediate: true,              // 立即执行一次
  })
  
  // 注册全局键盘快捷键
  window.addEventListener('keydown', handleKeyboardShortcut)
})

// 组件销毁时清理
onUnmounted(() => {
  window.removeEventListener('keydown', handleKeyboardShortcut)
})
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

/* ==================== 全局布局(3D增强) ==================== */
.dock-layout {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
  background:
    radial-gradient(circle at 25% 25%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
    radial-gradient(circle at 75% 75%, rgba(6, 182, 212, 0.1) 0%, transparent 50%),
    linear-gradient(135deg, #f8fafc 0%, #e2e8f0 50%, #f1f5f9 100%);
  position: relative;

  &::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23f1f5f9' fill-opacity='0.3'%3E%3Ccircle cx='30' cy='30' r='1'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

/* ==================== 顶部状态栏(3D增强) ==================== */
.status-bar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 64px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 32px;
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.95) 0%, rgba(248, 250, 252, 0.9) 100%),
    $gradient-primary;
  background-blend-mode: overlay;
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border-bottom: 2px solid rgba(139, 92, 246, 0.2);
  box-shadow:
    $shadow-elevated,
    inset 0 1px 2px rgba(255, 255, 255, 0.4),
    0 0 40px rgba(139, 92, 246, 0.1);
  z-index: 1000;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(90deg,
      transparent 0%,
      rgba(255, 255, 255, 0.1) 50%,
      transparent 100%);
    animation: shimmer-bar 3s ease-in-out infinite;
  }
}

@keyframes shimmer-bar {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(100%);
    opacity: 1;
  }
}

.status-bar-left {
  display: flex;
  align-items: center;
  gap: 16px;
  position: relative;
  z-index: 2;
}

.app-logo {
  background: $gradient-primary;
  color: white;
  box-shadow:
    $shadow-raised,
    inset 0 1px 2px rgba(255, 255, 255, 0.3),
    0 0 20px rgba(99, 102, 241, 0.4);
  border: 2px solid rgba(255, 255, 255, 0.2);
  transform: scale(1.1);
  transition: $transition-base;

  &:hover {
    transform: scale(1.2) rotate(5deg);
    box-shadow:
      $shadow-floating,
      inset 0 1px 2px rgba(255, 255, 255, 0.4),
      0 0 30px rgba(99, 102, 241, 0.6);
  }
}

.app-name {
  font-size: 22px;
  font-weight: $font-weight-bold;
  background: $gradient-primary;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  letter-spacing: -0.02em;
  position: relative;

  &::after {
    content: '';
    position: absolute;
    bottom: -2px;
    left: 0;
    right: 0;
    height: 2px;
    background: $gradient-primary;
    border-radius: 1px;
    transform: scaleX(0);
    transform-origin: center;
    transition: $transition-base;
  }

  &:hover::after {
    transform: scaleX(1);
  }
}

.status-bar-right {
  display: flex;
  align-items: center;
  gap: 20px;
  position: relative;
  z-index: 2;
}

.theme-switch {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 10px 16px;
  height: 44px;
  background:
    linear-gradient(145deg, rgba(255, 255, 255, 0.8) 0%, rgba(248, 250, 252, 0.6) 100%);
  backdrop-filter: blur(10px);
  border-radius: $border-radius-full;
  border: 1px solid rgba(255, 255, 255, 0.3);
  box-shadow:
    $shadow-raised,
    inset 0 1px 2px rgba(255, 255, 255, 0.4);
  transition: $transition-base;

  &:hover {
    transform: translateY(-1px);
    box-shadow:
      $shadow-elevated,
      inset 0 1px 2px rgba(255, 255, 255, 0.5);
  }

  // 确保ToggleSwitch垂直居中
  .p-toggleswitch {
    margin: 0;
    flex-shrink: 0;
  }
}

.theme-icon {
  font-size: 18px;
  color: $text-color-secondary;
  transition: $transition-base;
  filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.1));

  &.active {
    color: $primary-color;
    transform: scale(1.2);
    filter: drop-shadow(0 2px 4px rgba(99, 102, 241, 0.3));
    text-shadow: 0 0 10px rgba(99, 102, 241, 0.5);
  }
}

.mode-badge {
  font-size: 13px;
  font-weight: $font-weight-semibold;
  padding: 6px 12px;
  border-radius: $border-radius-full;
  box-shadow:
    $shadow-raised,
    inset 0 1px 2px rgba(255, 255, 255, 0.2);
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
  transition: $transition-base;

  &:hover {
    transform: translateY(-1px) scale(1.05);
    box-shadow:
      $shadow-elevated,
      inset 0 1px 2px rgba(255, 255, 255, 0.3);
  }
}

.user-name {
  font-size: 16px;
  font-weight: $font-weight-semibold;
  color: $text-color;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  padding: 6px 12px;
  background:
    linear-gradient(145deg, rgba(255, 255, 255, 0.6) 0%, rgba(248, 250, 252, 0.4) 100%);
  border-radius: $border-radius;
  border: 1px solid rgba(255, 255, 255, 0.3);
  box-shadow: $shadow-raised;
  transition: $transition-base;

  &:hover {
    transform: translateY(-1px);
    color: $primary-color;
    box-shadow: $shadow-elevated;
  }
}

/* ==================== 主内容区域(3D增强) ==================== */
.main-content {
  flex: 1;
  margin-top: 64px;
  margin-bottom: 140px;  // 增加底部边距，避免被Dock遮挡
  padding: 16px 4%;  // 左右各占4%，内容占92%
  overflow-y: auto;
  position: relative;

  // 显示简洁的滚动条
  &::-webkit-scrollbar {
    width: 6px;
  }
  &::-webkit-scrollbar-track {
    background: transparent;
  }
  &::-webkit-scrollbar-thumb {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 3px;
    
    &:hover {
      background: rgba(0, 0, 0, 0.3);
    }
  }

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      radial-gradient(circle at 20% 80%, rgba(139, 92, 246, 0.03) 0%, transparent 50%),
      radial-gradient(circle at 80% 20%, rgba(6, 182, 212, 0.03) 0%, transparent 50%);
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

/* ==================== 路由过渡动画(3D增强) ==================== */
.fade-enter-active,
.fade-leave-active {
  transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}

.fade-enter-from {
  opacity: 0;
  transform: translateY(30px) scale(0.9) rotateX(10deg);
  filter: blur(2px);
}

.fade-leave-to {
  opacity: 0;
  transform: translateY(-30px) scale(1.1) rotateX(-10deg);
  filter: blur(2px);
}

/* ==================== 底部Dock栏(3D增强) ==================== */
.dock-container {
  position: fixed;
  bottom: 24px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 1000;

  &::before {
    content: '';
    position: absolute;
    bottom: -20px;
    left: 50%;
    transform: translateX(-50%);
    width: 120%;
    height: 60px;
    background: radial-gradient(ellipse, rgba(0, 0, 0, 0.1) 0%, transparent 70%);
    border-radius: 50%;
    z-index: -1;
  }
}

.dock {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 24px;
  background:
    linear-gradient(145deg, rgba(255, 255, 255, 0.95) 0%, rgba(248, 250, 252, 0.8) 100%),
    radial-gradient(circle at center, rgba(139, 92, 246, 0.1) 0%, transparent 70%);
  backdrop-filter: blur(25px) saturate(180%);
  -webkit-backdrop-filter: blur(25px) saturate(180%);
  border-radius: $border-radius-xl;
  box-shadow:
    $shadow-floating,
    inset 0 2px 4px rgba(255, 255, 255, 0.6),
    inset 0 -1px 2px rgba(0, 0, 0, 0.05),
    0 0 50px rgba(139, 92, 246, 0.15);
  border: 2px solid rgba(255, 255, 255, 0.4);
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    right: -100%;
    height: 100%;
    background: linear-gradient(90deg,
      transparent 0%,
      rgba(255, 255, 255, 0.3) 50%,
      transparent 100%);
    animation: dock-shimmer 4s ease-in-out infinite;
  }

  &:hover {
    transform: translateY(-2px);
    box-shadow:
      0 12px 24px rgba(0, 0, 0, 0.15),
      0 20px 40px rgba(0, 0, 0, 0.1),
      inset 0 2px 4px rgba(255, 255, 255, 0.7),
      0 0 60px rgba(139, 92, 246, 0.2);
  }
}

@keyframes dock-shimmer {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(100%);
    opacity: 1;
  }
}

/* ==================== Dock项(3D增强) ==================== */
.dock-item-wrapper {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  transition: $transition-base;

  &:hover {
    transform: scale(1.05);
  }
}

.dock-item {
  position: relative;
  width: 64px;
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.6) 0%, rgba(248, 250, 252, 0.4) 100%);
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: $border-radius-lg;
  cursor: pointer;
  transition: $transition-base;
  box-shadow:
    $shadow-raised,
    inset 0 1px 2px rgba(255, 255, 255, 0.4);
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: $gradient-primary;
    opacity: 0;
    transition: $transition-base;
  }

  &:hover {
    transform: scale(1.2) translateY(-4px);
    box-shadow:
      $shadow-floating,
      inset 0 1px 2px rgba(255, 255, 255, 0.5),
      0 0 25px rgba(99, 102, 241, 0.4);
    border-color: rgba(99, 102, 241, 0.3);

    &::before {
      opacity: 0.1;
    }
  }

  &.active {
    background: $gradient-primary;
    border-color: rgba(255, 255, 255, 0.4);
    box-shadow:
      $shadow-elevated,
      inset 0 1px 2px rgba(255, 255, 255, 0.3),
      0 0 30px rgba(99, 102, 241, 0.5);

    &::before {
      opacity: 0;
    }
  }

  &:focus-visible {
    outline: 3px solid rgba(99, 102, 241, 0.5);
    outline-offset: 3px;
  }
}

.dock-icon {
  font-size: 28px;
  color: $text-color-secondary;
  transition: $transition-base;
  position: relative;
  z-index: 2;
  filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.1));

  .dock-item:hover & {
    color: $primary-color;
    transform: scale(1.1);
    filter: drop-shadow(0 2px 4px rgba(99, 102, 241, 0.3));
    text-shadow: 0 0 15px rgba(99, 102, 241, 0.5);
  }

  .dock-item.active & {
    color: white;
    transform: scale(1.1);
    filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
    text-shadow: 0 0 10px rgba(255, 255, 255, 0.8);
  }
}

/* ==================== Dock项徽章(3D增强) ==================== */
.dock-badge {
  position: absolute;
  top: -6px;
  right: -6px;
  min-width: 24px;
  height: 24px;
  font-size: 12px;
  font-weight: $font-weight-bold;
  background: $gradient-danger;
  border: 2px solid white;
  border-radius: $border-radius-full;
  box-shadow:
    $shadow-elevated,
    inset 0 1px 2px rgba(255, 255, 255, 0.3);
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
  z-index: 3;

  &.pulse {
    animation: pulse3d-badge 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
}

@keyframes pulse3d-badge {
  0%, 100% {
    transform: scale(1);
    box-shadow:
      $shadow-elevated,
      inset 0 1px 2px rgba(255, 255, 255, 0.3);
  }
  50% {
    transform: scale(1.2);
    box-shadow:
      $shadow-floating,
      inset 0 1px 2px rgba(255, 255, 255, 0.4),
      0 0 20px rgba(239, 68, 68, 0.6);
  }
}

/* ==================== 活跃指示器(3D增强) ==================== */
.active-indicator {
  width: 40px;
  height: 6px;
  background: $gradient-primary;
  border-radius: $border-radius-sm;
  box-shadow:
    $shadow-elevated,
    inset 0 1px 2px rgba(255, 255, 255, 0.3),
    0 0 20px rgba(99, 102, 241, 0.6);
  animation: slideUp3d 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
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
      rgba(255, 255, 255, 0.5) 50%,
      transparent 100%);
    border-radius: inherit;
    animation: indicator-glow 2s ease-in-out infinite;
  }
}

@keyframes slideUp3d {
  0% {
    opacity: 0;
    transform: translateY(10px) scale(0.5);
  }
  50% {
    opacity: 1;
    transform: translateY(-2px) scale(1.1);
  }
  100% {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@keyframes indicator-glow {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(100%);
    opacity: 1;
  }
}

/* ==================== 响应式设计(3D适配) ==================== */
/* 平板 */
@media (max-width: 1024px) {
  .main-content {
    padding: 24px;
  }

  .dock-item {
    width: 60px;
    height: 60px;

    &:hover {
      transform: scale(1.15) translateY(-3px);
    }
  }

  .dock-icon {
    font-size: 26px;
  }
}

/* 移动端 */
@media (max-width: 768px) {
  .status-bar {
    height: 56px;
    padding: 0 20px;

    // 减少3D效果强度
    box-shadow: $shadow-raised;
  }

  .app-name {
    font-size: 18px;
  }

  .user-name {
    display: none;
  }

  .theme-switch {
    padding: 6px 12px;
  }

  .main-content {
    margin-top: 56px;
    margin-bottom: 100px;
    padding: 16px;
    min-height: calc(100vh - 156px);
  }

  .dock-container {
    bottom: 16px;
  }

  .dock {
    padding: 12px 18px;
    gap: 8px;

    // 移动端减少阴影强度
    box-shadow:
      $shadow-elevated,
      inset 0 1px 2px rgba(255, 255, 255, 0.4);

    &:hover {
      transform: translateY(-1px);
    }
  }

  .dock-item {
    width: 52px;
    height: 52px;

    &:hover {
      transform: scale(1.1) translateY(-2px);
    }
  }

  .dock-icon {
    font-size: 22px;
  }

  .active-indicator {
    width: 32px;
    height: 4px;
  }

  .dock-badge {
    top: -4px;
    right: -4px;
    min-width: 20px;
    height: 20px;
    font-size: 11px;
  }
}

/* 小屏手机 */
@media (max-width: 480px) {
  .status-bar {
    padding: 0 16px;
  }

  .status-bar-left {
    gap: 12px;
  }

  .app-logo {
    width: 36px;
    height: 36px;
    transform: scale(1);

    &:hover {
      transform: scale(1.1) rotate(3deg);
    }
  }

  .app-name {
    font-size: 16px;
  }

  .dock {
    padding: 10px 16px;
    gap: 6px;
  }

  .dock-item {
    width: 48px;
    height: 48px;
  }

  .dock-icon {
    font-size: 20px;
  }

  .active-indicator {
    width: 28px;
    height: 3px;
  }
}

/* ==================== 浏览器兼容性(3D降级) ==================== */
/* Safari降级方案 */
@supports not (backdrop-filter: blur(10px)) {
  .status-bar {
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.98) 0%, rgba(248, 250, 252, 0.95) 100%);
    box-shadow: $shadow-elevated;
  }

  .dock {
    background: linear-gradient(145deg, rgba(255, 255, 255, 0.98) 0%, rgba(248, 250, 252, 0.95) 100%);
    box-shadow: $shadow-floating;
  }

  .theme-switch {
    background: linear-gradient(145deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.8) 100%);
  }
}

/* 性能优化：减少不必要的动画 */
@media (prefers-reduced-motion: reduce) {
  .dock::before,
  .status-bar::before,
  .active-indicator::before {
    animation: none;
  }

  .dock-item,
  .dock-icon,
  .app-logo {
    transition: transform 0.2s ease, box-shadow 0.2s ease;
  }
}
</style>
