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
    router.push(path)
  }
}

function handleLogout(): void {
  authStore.logout()
  router.push('/login')
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
    if (keyMap[event.key]) {
      event.preventDefault()
      navigateTo(keyMap[event.key])
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
  gap: 0.25rem;
  padding: 0.5rem 1rem;
  color: var(--p-text-secondary-color);
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

.nav-item.active {
  color: var(--p-primary-color);
  background: var(--p-primary-50);
}

:deep(.app-dark) .nav-item.active {
  background: var(--p-primary-900);
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
