<template>
  <div class="layout">
    <div class="layout-header">
      <div class="header-left">
        <h1>SqlmapWebUI</h1>
      </div>
      <div class="header-right">
        <span v-if="authStore.isLocalMode" class="mode-tag">本地模式</span>
        <span v-else class="user-info">{{ authStore.userName }}</span>
        <Button v-if="!authStore.isLocalMode" icon="pi pi-sign-out" @click="handleLogout" text rounded />
      </div>
    </div>
    
    <div class="layout-content">
      <div class="layout-sidebar">
        <Menu :model="menuItems" />
      </div>
      
      <div class="layout-main">
        <router-view />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'

const authStore = useAuthStore()
const router = useRouter()

const menuItems = [
  {
    label: '首页',
    icon: 'pi pi-home',
    command: () => router.push('/home'),
  },
  {
    label: '任务列表',
    icon: 'pi pi-list',
    command: () => router.push('/tasks'),
  },
  {
    label: '配置管理',
    icon: 'pi pi-cog',
    command: () => router.push('/config'),
  },
]

function handleLogout() {
  authStore.logout()
  router.push('/login')
}
</script>

<style scoped lang="scss">
.layout {
  display: flex;
  flex-direction: column;
  height: 100vh;
}

.layout-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 24px;
  height: 64px;
  background: #fff;
  border-bottom: 1px solid #dee2e6;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

.header-left h1 {
  font-size: 20px;
  font-weight: 600;
  color: #3B82F6;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 16px;
}

.mode-tag {
  padding: 4px 12px;
  background: #22C55E;
  color: white;
  border-radius: 12px;
  font-size: 12px;
}

.user-info {
  font-weight: 500;
}

.layout-content {
  display: flex;
  flex: 1;
  overflow: hidden;
}

.layout-sidebar {
  width: 200px;
  background: #fff;
  border-right: 1px solid #dee2e6;
  padding: 16px 0;
}

.layout-main {
  flex: 1;
  overflow: auto;
  padding: 24px;
  background: #f8f9fa;
}
</style>
