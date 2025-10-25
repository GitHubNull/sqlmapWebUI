/**
 * 认证状态管理
 * 支持本地/远程双模式
 */
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { login as loginApi } from '@/api/auth'
import { isLocalAccess, isAuthRequired as checkAuthRequired } from '@/utils/auth'
import { getStorage, setStorage, removeStorage } from '@/utils/storage'
import type { UserInfo, LoginRequest } from '@/types/common'

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const token = ref<string | null>(getStorage<string>('token'))
  const userInfo = ref<UserInfo | null>(getStorage<UserInfo>('userInfo'))
  const isLocalMode = ref<boolean>(isLocalAccess())
  const authRequired = ref<boolean>(checkAuthRequired())

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
  }

  return {
    // 状态
    token,
    userInfo,
    isLocalMode,
    authRequired,
    // 计算属性
    isLoggedIn,
    userName,
    needAuth,
    // 动作
    login,
    logout,
    checkAuth,
    initAuth,
  }
})
