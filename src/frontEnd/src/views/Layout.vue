<template>
  <div class="layout">
    <!-- 顶部导航栏 -->
    <header class="layout-header">
      <div class="layout-header-left">
        <img src="/favicon.svg" alt="SQLMap WebUI" class="logo" />
        <span class="app-name">SqlmapWebUI</span>
      </div>
      <div class="layout-header-right">
        <Button
          icon="pi pi-question-circle"
          @click="navigateTo('/about')"
          text
          rounded
          severity="secondary"
          v-tooltip.bottom="'帮助/关于'"
        />

        <div class="theme-toggle">
          <i class="pi pi-sun" :class="{ active: configStore.theme === 'light' }"></i>
          <ToggleSwitch
            v-model="isDarkMode"
            @change="handleThemeToggle"
          />
          <i class="pi pi-moon" :class="{ active: configStore.theme === 'dark' }"></i>
        </div>

        <Badge
          v-if="authStore.isLocalMode"
          value="本地模式"
          severity="success"
        />
        <Badge
          v-else
          value="远程模式"
          severity="info"
        />
        <span v-if="!authStore.isLocalMode" class="username">{{ authStore.userName }}</span>
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
    <main class="layout-main">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>

    <!-- 底部导航栏 -->
    <nav class="layout-nav">
      <div class="nav-items">
        <Button
          v-for="item in navItems"
          :key="item.id"
          :class="['nav-item', { active: isActiveRoute(item.route) }]"
          @click="navigateTo(item.route)"
          text
          rounded
          v-tooltip.top="item.label"
        >
          <i :class="item.icon"></i>
          <span>{{ item.label }}</span>
        </Button>
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
import { wsService } from '@/utils/useWebSocket'
import ToggleSwitch from 'primevue/toggleswitch'

const authStore = useAuthStore()
const taskStore = useTaskStore()
const configStore = useConfigStore()
const router = useRouter()
const route = useRoute()

const currentRoute = ref(route.path)

const isDarkMode = computed({
  get: () => configStore.theme === 'dark',
  set: (value: boolean) => {
    configStore.updateTheme(value ? 'dark' : 'light')
  }
})

interface NavItem {
  id: string
  label: string
  icon: string
  route: string
}

const navItems = computed<NavItem[]>(() => [
  { id: 'home', label: '首页', icon: 'pi pi-home', route: '/home' },
  { id: 'tasks', label: '任务', icon: 'pi pi-list', route: '/tasks' },
  { id: 'addTask', label: '添加任务', icon: 'pi pi-plus-circle', route: '/add-task' },
  { id: 'config', label: '配置', icon: 'pi pi-cog', route: '/config' },
])

function isActiveRoute(routePath: string): boolean {
  if (currentRoute.value.startsWith('/tasks')) {
    return routePath === '/tasks'
  }
  return currentRoute.value === routePath
}

function navigateTo(path: string): void {
  if (currentRoute.value !== path) {
    router.push(path).catch(() => {})
  }
}

function handleLogout(): void {
  authStore.logout()
  router.push('/login').catch(() => {})
}

function handleThemeToggle(): void {
  configStore.updateTheme(isDarkMode.value ? 'dark' : 'light')
}

function handleKeyboardShortcut(event: KeyboardEvent): void {
  if (event.altKey && !event.ctrlKey && !event.shiftKey) {
    const keyMap: Record<string, string> = {
      '1': '/home',
      '2': '/tasks',
      '3': '/add-task',
      '4': '/config',
    }
    const key = event.key
    if (key && keyMap[key]) {
      event.preventDefault()
      navigateTo(keyMap[key])
    }
  }
}

watch(() => route.path, (newPath) => {
  currentRoute.value = newPath
}, { immediate: true })

onMounted(async () => {
  await configStore.loadRefreshIntervalFromBackend()
  taskStore.fetchTaskList()
  wsService.connect()
  wsService.onRefresh(() => {
    taskStore.fetchTaskList()
  })
  window.addEventListener('keydown', handleKeyboardShortcut)
})

onUnmounted(() => {
  window.removeEventListener('keydown', handleKeyboardShortcut)
})
</script>

<style scoped>
.layout {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
}

.layout-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1.5rem;
  background: var(--p-surface-card);
  border-bottom: 1px solid var(--p-surface-border);
  flex-shrink: 0;
}

.layout-header-left {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.logo {
  width: 32px;
  height: 32px;
}

.app-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--p-text-color);
}

.layout-header-right {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.theme-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.25rem 0.5rem;
  background: var(--p-surface-section);
  border-radius: 1rem;
}

.theme-toggle i {
  font-size: 1rem;
  color: var(--p-text-secondary-color);
}

.theme-toggle i.active {
  color: var(--p-primary-color);
}

.username {
  font-size: 0.875rem;
  color: var(--p-text-color);
}

.layout-main {
  flex: 1;
  overflow: auto;
  padding: 1rem;
  background: var(--p-surface-ground);
}

.layout-nav {
  flex-shrink: 0;
  padding: 0.75rem;
  background: var(--p-surface-card);
  border-top: 1px solid var(--p-surface-border);
}

.nav-items {
  display: flex;
  justify-content: center;
  gap: 0.5rem;
}

.nav-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.375rem;
  padding: 0.5rem 1rem;
  color: var(--p-text-secondary-color);
  border-radius: 12px;
  position: relative;
  overflow: hidden;
}

.nav-item i {
  font-size: 1.25rem;
}

.nav-item span {
  font-size: 0.75rem;
}

.nav-item:hover {
  color: var(--p-primary-color);
}

/* 科幻蓝选中效果 */
.nav-item.active {
  color: #fff;
  background: linear-gradient(135deg, #0ea5e9 0%, #3b82f6 50%, #6366f1 100%);
  box-shadow:
    0 0 20px rgba(59, 130, 246, 0.5),
    0 0 40px rgba(59, 130, 246, 0.3),
    0 0 60px rgba(59, 130, 246, 0.1),
    inset 0 1px 0 rgba(255, 255, 255, 0.3);
  transform: translateY(-2px);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

/* 跑马灯边框效果 - 从左上角单向射线式 */
.nav-item.active::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 12px;
  padding: 2px;
  background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, #60a5fa 30deg, #a78bfa 60deg, #60a5fa 90deg, transparent 120deg, transparent 360deg);
  animation: borderGlowRay 2s linear infinite;
  -webkit-mask:
    linear-gradient(#fff 0 0) content-box,
    linear-gradient(#fff 0 0);
  mask:
    linear-gradient(#fff 0 0) content-box,
    linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
}

/* 内部光效 */
.nav-item.active::after {
  content: '';
  position: absolute;
  inset: 2px;
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(255,255,255,0.2) 0%, transparent 50%, rgba(255,255,255,0.1) 100%);
  pointer-events: none;
}

@keyframes borderGlowRay {
  0% {
    background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, transparent 360deg);
  }
  10% {
    background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, #60a5fa 10deg, #a78bfa 30deg, #60a5fa 50deg, transparent 70deg, transparent 360deg);
  }
  30% {
    background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, transparent 20deg, #60a5fa 40deg, #a78bfa 70deg, #60a5fa 100deg, transparent 130deg, transparent 360deg);
  }
  50% {
    background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, transparent 50deg, #60a5fa 80deg, #a78bfa 110deg, #60a5fa 140deg, transparent 170deg, transparent 360deg);
  }
  70% {
    background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, transparent 80deg, #60a5fa 110deg, #a78bfa 140deg, #60a5fa 170deg, transparent 200deg, transparent 360deg);
  }
  90% {
    background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, transparent 110deg, #60a5fa 140deg, #a78bfa 170deg, #60a5fa 200deg, transparent 230deg, transparent 360deg);
  }
  100% {
    background: conic-gradient(from 0deg at 0% 0%, transparent 0deg, transparent 360deg);
  }
}

/* 暗色模式科幻效果 */
:deep(.app-dark) .nav-item.active {
  background: linear-gradient(135deg, #0284c7 0%, #2563eb 50%, #4f46e5 100%);
  box-shadow:
    0 0 30px rgba(37, 99, 235, 0.6),
    0 0 60px rgba(37, 99, 235, 0.4),
    0 0 90px rgba(37, 99, 235, 0.2),
    inset 0 1px 0 rgba(255, 255, 255, 0.2);
}

:deep(.app-dark) .nav-item.active::before {
  background: linear-gradient(90deg, transparent, #3b82f6, #8b5cf6, #3b82f6, transparent);
  background-size: 200% 100%;
}

/* 路由过渡动画 */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* 响应式 */
@media (max-width: 768px) {
  .layout-header {
    padding: 0.5rem 1rem;
  }

  .app-name {
    font-size: 1rem;
  }

  .username {
    display: none;
  }

  .nav-item {
    padding: 0.5rem;
  }

  .nav-item span {
    display: none;
  }
}
</style>
