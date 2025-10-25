/**
 * 认证状态管理
 * 支持本地/远程双模式
 */
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { login as loginApi } from '@/api/auth'
import { isLocalAccess, isAuthRequired as checkAuthRequired } from '@/utils/auth'
import { getStorage, setStorage, removeStorage } from '@/utils/storage'
import { request } from '@/api/request'
import type { UserInfo, LoginRequest } from '@/types/common'

// 健康检查响应类型
interface HealthCheckResponse {
  status: string
  timestamp: number
  version?: string
  uptime?: number
}

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const token = ref<string | null>(getStorage<string>('token'))
  const userInfo = ref<UserInfo | null>(getStorage<UserInfo>('userInfo'))
  const isLocalMode = ref<boolean>(isLocalAccess())
  const authRequired = ref<boolean>(checkAuthRequired())
  
  // 健康检查状态
  const backendHealthy = ref<boolean>(true)
  const lastHealthCheck = ref<number>(0)
  const healthCheckInterval = 30000 // 30秒

  // 计算属性
  const isLoggedIn = computed(() => {
    // 本地模式下始终视为已登录
    if (isLocalMode.value) {
      return true
    }
    // 远程模式检查Token
    return !!token.value
  })

  const userName = computed(() => {
    if (isLocalMode.value) {
      return 'Local User'
    }
    return userInfo.value?.username || ''
  })

  const needAuth = computed(() => {
    return !isLocalMode.value && authRequired.value
  })

  // 动作
  async function login(data: LoginRequest): Promise<void> {
    // 本地模式不需要登录
    if (isLocalMode.value) {
      console.log('Local mode: skipping login')
      return
    }

    try {
      const response = await loginApi(data)
      token.value = response.token
      userInfo.value = response.userInfo

      // 持久化
      setStorage('token', response.token)
      setStorage('userInfo', response.userInfo)
    } catch (error) {
      console.error('Login failed:', error)
      throw error
    }
  }

  function logout(): void {
    token.value = null
    userInfo.value = null
    removeStorage('token')
    removeStorage('userInfo')
  }

  function checkAuth(): boolean {
    // 本地模式始终通过
    if (isLocalMode.value) {
      return true
    }
    // 远程模式检查Token
    return !!token.value
  }

  function initAuth(): void {
    // 检测访问模式
    isLocalMode.value = isLocalAccess()
    authRequired.value = checkAuthRequired()

    // 从存储恢复状态
    token.value = getStorage<string>('token')
    userInfo.value = getStorage<UserInfo>('userInfo')
    
    // 初始化时执行一次健康检查
    checkBackendHealth()
  }
  
  /**
   * 检查后端服务健康状态
   */
  async function checkBackendHealth(): Promise<boolean> {
    const now = Date.now()
    
    // 如果距离上次检查时间小于间隔，直接返回缓存结果
    if (now - lastHealthCheck.value < healthCheckInterval) {
      return backendHealthy.value
    }
    
    try {
      const response = await request.get<HealthCheckResponse>('/health', {
        timeout: 5000 // 5秒超时
      })
      
      const healthy = response.status === 'healthy'
      
      // 状态发生变化时记录日志
      if (backendHealthy.value !== healthy) {
        console.info(`Backend health status changed: ${backendHealthy.value} -> ${healthy}`)
      }
      
      backendHealthy.value = healthy
      lastHealthCheck.value = now
      
      return healthy
    } catch (error) {
      console.debug('Backend health check failed:', error)
      
      // 检查失败设置为不健康
      if (backendHealthy.value !== false) {
        console.warn('Backend is unhealthy')
      }
      
      backendHealthy.value = false
      lastHealthCheck.value = now
      
      return false
    }
  }
  
  /**
   * 重置健康检查状态（用于强制重新检查）
   */
  function resetHealthCheck(): void {
    lastHealthCheck.value = 0
  }

  return {
    // 状态
    token,
    userInfo,
    isLocalMode,
    authRequired,
    backendHealthy,
    lastHealthCheck,
    // 计算属性
    isLoggedIn,
    userName,
    needAuth,
    // 动作
    login,
    logout,
    checkAuth,
    initAuth,
    checkBackendHealth,
    resetHealthCheck,
  }
})
