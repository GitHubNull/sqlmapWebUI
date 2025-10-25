<template>
  <Transition name="slide-down">
    <div v-if="showBanner" class="offline-banner" role="alert" aria-live="polite">
      <div class="banner-content">
        <i class="pi pi-wifi-slash banner-icon"></i>
        <span class="banner-message">{{ message }}</span>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

// 状态
const isOnline = ref(navigator.onLine)
const showBanner = computed(() => !isOnline.value || !authStore.backendHealthy)

// 消息文本
const message = computed(() => {
  if (!isOnline.value) {
    return '您当前处于离线状态，部分功能不可用'
  }
  if (!authStore.backendHealthy) {
    return '无法连接到后端服务，请检查服务是否已启动'
  }
  return ''
})

/**
 * 网络状态变化处理
 */
function handleNetworkChange(): void {
  isOnline.value = navigator.onLine
  
  // 网络恢复时执行健康检查
  if (isOnline.value) {
    authStore.checkBackendHealth()
  }
}

onMounted(() => {
  window.addEventListener('online', handleNetworkChange)
  window.addEventListener('offline', handleNetworkChange)
  
  // 初始化时检查健康状态
  authStore.checkBackendHealth()
})

onUnmounted(() => {
  window.removeEventListener('online', handleNetworkChange)
  window.removeEventListener('offline', handleNetworkChange)
})
</script>

<style scoped lang="scss">
.offline-banner {
  position: fixed;
  top: 56px;
  left: 0;
  right: 0;
  z-index: 999;
  background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
  color: #78350f;
  padding: 12px 24px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.banner-content {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  max-width: 1200px;
  margin: 0 auto;
}

.banner-icon {
  font-size: 18px;
  font-weight: 600;
}

.banner-message {
  font-size: 14px;
  font-weight: 500;
}

/* 过渡动画 */
.slide-down-enter-active,
.slide-down-leave-active {
  transition: all 0.3s ease;
}

.slide-down-enter-from {
  opacity: 0;
  transform: translateY(-100%);
}

.slide-down-leave-to {
  opacity: 0;
  transform: translateY(-100%);
}

/* 响应式 */
@media (max-width: 768px) {
  .offline-banner {
    top: 48px;
    padding: 10px 16px;
  }
  
  .banner-icon {
    font-size: 16px;
  }
  
  .banner-message {
    font-size: 13px;
  }
}
</style>
