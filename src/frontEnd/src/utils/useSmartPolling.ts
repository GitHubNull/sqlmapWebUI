/**
 * 智能轮询Hook
 * 支持页面可见性监听、网络状态监听和健康检查
 */
import { ref, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/auth'

export interface SmartPollingOptions {
  /** 轮询回调函数 */
  callback: () => Promise<void> | void
  /** 正常轮询间隔（毫秒） */
  interval?: number
  /** 页面隐藏时的轮询间隔（毫秒） */
  backgroundInterval?: number
  /** 是否在后端不健康时暂停轮询 */
  pauseOnUnhealthy?: boolean
  /** 是否立即执行一次 */
  immediate?: boolean
}

export function useSmartPolling(options: SmartPollingOptions) {
  const {
    callback,
    interval = 5000,
    backgroundInterval = 30000,
    pauseOnUnhealthy = true,
    immediate = true,
  } = options

  const authStore = useAuthStore()
  
  // 状态
  const isPolling = ref(false)
  const isPageVisible = ref(!document.hidden)
  const isOnline = ref(navigator.onLine)
  let pollingTimer: ReturnType<typeof setTimeout> | null = null

  /**
   * 获取当前轮询间隔
   */
  function getCurrentInterval(): number {
    // 页面隐藏时使用较长的间隔
    if (!isPageVisible.value) {
      return backgroundInterval
    }
    return interval
  }

  /**
   * 判断是否应该执行轮询
   */
  function shouldPoll(): boolean {
    // 离线时不轮询
    if (!isOnline.value) {
      return false
    }

    // 后端不健康时根据配置决定是否暂停
    if (pauseOnUnhealthy && !authStore.backendHealthy) {
      return false
    }

    return true
  }

  /**
   * 执行轮询
   */
  async function executePoll(): Promise<void> {
    if (!shouldPoll()) {
      console.debug('Polling paused (offline or backend unhealthy)')
      return
    }

    try {
      await callback()
    } catch (error) {
      console.debug('Polling callback error:', error)
      // 错误已在全局拦截器中处理，这里只记录调试信息
    }
  }

  /**
   * 启动轮询
   */
  function startPolling(): void {
    if (isPolling.value) {
      return
    }

    isPolling.value = true

    // 立即执行一次
    if (immediate) {
      executePoll()
    }

    // 设置定时轮询
    const poll = () => {
      if (!isPolling.value) {
        return
      }

      executePoll().finally(() => {
        if (isPolling.value) {
          const currentInterval = getCurrentInterval()
          pollingTimer = setTimeout(poll, currentInterval)
        }
      })
    }

    pollingTimer = setTimeout(poll, getCurrentInterval())
  }

  /**
   * 停止轮询
   */
  function stopPolling(): void {
    isPolling.value = false
    if (pollingTimer) {
      clearTimeout(pollingTimer)
      pollingTimer = null
    }
  }

  /**
   * 重启轮询（重置定时器）
   */
  function restartPolling(): void {
    stopPolling()
    startPolling()
  }

  /**
   * 页面可见性变化处理
   */
  function handleVisibilityChange(): void {
    isPageVisible.value = !document.hidden

    if (isPageVisible.value) {
      console.debug('Page visible, increasing polling frequency')
      // 页面重新可见时，重启轮询并立即执行一次
      restartPolling()
    } else {
      console.debug('Page hidden, decreasing polling frequency')
      // 页面隐藏时，重启轮询以应用新的间隔
      restartPolling()
    }
  }

  /**
   * 网络状态变化处理
   */
  function handleOnlineStatusChange(): void {
    isOnline.value = navigator.onLine

    if (isOnline.value) {
      console.info('Network online, resuming polling')
      // 网络恢复时，执行健康检查
      authStore.checkBackendHealth().then(() => {
        restartPolling()
      })
    } else {
      console.info('Network offline, pausing polling')
      stopPolling()
    }
  }

  /**
   * 初始化
   */
  onMounted(() => {
    // 监听页面可见性
    document.addEventListener('visibilitychange', handleVisibilityChange)

    // 监听网络状态
    window.addEventListener('online', handleOnlineStatusChange)
    window.addEventListener('offline', handleOnlineStatusChange)

    // 启动轮询
    startPolling()
  })

  /**
   * 清理
   */
  onUnmounted(() => {
    stopPolling()
    document.removeEventListener('visibilitychange', handleVisibilityChange)
    window.removeEventListener('online', handleOnlineStatusChange)
    window.removeEventListener('offline', handleOnlineStatusChange)
  })

  return {
    isPolling,
    isPageVisible,
    isOnline,
    startPolling,
    stopPolling,
    restartPolling,
  }
}
