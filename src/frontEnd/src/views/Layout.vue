<template>
  <div class="dock-layout">
    <!-- 顶部状态栏 -->
    <header class="status-bar">
      <div class="status-bar-left">
        <Avatar icon="pi pi-shield" class="app-logo" shape="circle" size="normal" />
        <span class="app-name">SqlmapWebUI</span>
      </div>
      <div class="status-bar-right">
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
import { useRouter, useRoute } from 'vue-router'
import { useSmartPolling } from '@/utils/useSmartPolling'

// Stores
const authStore = useAuthStore()
const taskStore = useTaskStore()
const router = useRouter()
const route = useRoute()

// 状态
const currentRoute = ref<string>(route.path)
const hoveredItem = ref<string | null>(null)

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
/* ==================== 全局布局 ==================== */
.dock-layout {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
}

/* ==================== 顶部状态栏 ==================== */
.status-bar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 56px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 24px;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border-bottom: 1px solid rgba(0, 0, 0, 0.06);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
  z-index: 1000;
}

.status-bar-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.app-logo {
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  color: white;
}

.app-name {
  font-size: 18px;
  font-weight: 600;
  color: #1f2937;
  letter-spacing: -0.02em;
}

.status-bar-right {
  display: flex;
  align-items: center;
  gap: 16px;
}

.mode-badge {
  font-size: 12px;
  font-weight: 500;
}

.user-name {
  font-size: 14px;
  font-weight: 500;
  color: #4b5563;
}

/* ==================== 主内容区域 ==================== */
.main-content {
  flex: 1;
  margin-top: 56px;
  margin-bottom: 104px;
  padding: 24px;
  min-height: calc(100vh - 160px);
  overflow: auto;
}

/* 路由过渡动画 */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.fade-enter-from {
  opacity: 0;
  transform: translateY(8px);
}

.fade-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

/* ==================== 底部Dock栏 ==================== */
.dock-container {
  position: fixed;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 1000;
}

.dock {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  background: rgba(255, 255, 255, 0.8);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border-radius: 16px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1), 0 2px 8px rgba(0, 0, 0, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.6);
}

/* ==================== Dock项 ==================== */
.dock-item-wrapper {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.dock-item {
  position: relative;
  width: 56px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: 12px;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  
  &:hover {
    background: rgba(255, 255, 255, 0.6);
    transform: scale(1.15);
  }
  
  &.active {
    background: rgba(59, 130, 246, 0.15);
  }
  
  &:focus-visible {
    outline: 2px solid #3b82f6;
    outline-offset: 2px;
  }
}

.dock-icon {
  font-size: 24px;
  color: #6b7280;
  transition: color 0.2s ease;
  
  .dock-item:hover & {
    color: #3b82f6;
  }
  
  .dock-item.active & {
    color: #3b82f6;
  }
}

/* Dock项徽章 */
.dock-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  min-width: 20px;
  height: 20px;
  font-size: 11px;
  font-weight: 600;
  
  &.pulse {
    animation: pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
}

@keyframes pulse {
  0%, 100% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.1);
    opacity: 0.9;
  }
}

/* 活跃指示器 */
.active-indicator {
  width: 32px;
  height: 4px;
  background: #3b82f6;
  border-radius: 2px;
  animation: slideUp 0.3s ease-in-out;
}

@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* ==================== 响应式设计 ==================== */
/* 平板 */
@media (max-width: 1024px) {
  .main-content {
    padding: 16px;
  }
}

/* 移动端 */
@media (max-width: 768px) {
  .status-bar {
    height: 48px;
    padding: 0 16px;
  }
  
  .app-name {
    font-size: 16px;
  }
  
  .user-name {
    display: none;
  }
  
  .main-content {
    margin-top: 48px;
    margin-bottom: 88px;
    padding: 12px;
    min-height: calc(100vh - 136px);
  }
  
  .dock-container {
    bottom: 12px;
  }
  
  .dock {
    padding: 8px 12px;
    gap: 4px;
  }
  
  .dock-item {
    width: 48px;
    height: 48px;
  }
  
  .dock-icon {
    font-size: 20px;
  }
  
  .active-indicator {
    width: 24px;
    height: 3px;
  }
}

/* 小屏手机 */
@media (max-width: 480px) {
  .status-bar-left {
    gap: 8px;
  }
  
  .app-logo {
    width: 32px;
    height: 32px;
  }
  
  .dock {
    gap: 2px;
  }
  
  .dock-item {
    width: 44px;
    height: 44px;
  }
}

/* ==================== 浏览器兼容性 ==================== */
/* Safari降级方案 */
@supports not (backdrop-filter: blur(10px)) {
  .status-bar,
  .dock {
    background: rgba(255, 255, 255, 0.95);
  }
}
</style>
