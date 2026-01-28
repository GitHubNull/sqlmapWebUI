/**
 * 配置状态管理
 */
import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import { getStorage, setStorage } from '@/utils/storage'
import type { PersistentHeaderRule } from '@/types/headerRule'
import { getRefreshIntervalConfig, setRefreshIntervalConfig } from '@/api/system'

export const useConfigStore = defineStore('config', () => {
  // 状态
  const apiBaseUrl = ref<string>(import.meta.env.VITE_API_BASE_URL || '/api')
  const theme = ref<'light' | 'dark'>((getStorage<'light' | 'dark'>('theme') ?? 'light') as 'light' | 'dark')
  const language = ref<string>((getStorage<string>('language') ?? 'zh-CN') as string)
  const headerRules = ref<PersistentHeaderRule[]>([])
  // 自动刷新间隔配置（分钟），默认5分钟
  const autoRefreshInterval = ref<number>(5)
  // 是否正在加载刷新间隔配置
  const isLoadingRefreshInterval = ref<boolean>(false)

  // 动作
  function loadConfig(): void {
    theme.value = (getStorage<'light' | 'dark'>('theme') ?? 'light') as 'light' | 'dark'
    language.value = (getStorage<string>('language') ?? 'zh-CN') as string
  }

  function saveConfig(): void {
    setStorage('theme', theme.value)
    setStorage('language', language.value)
  }

  function updateTheme(newTheme: 'light' | 'dark'): void {
    theme.value = newTheme
    setStorage('theme', newTheme)
    
    // 应用主题到DOM - 使用PrimeVue官方的.app-dark类
    if (newTheme === 'dark') {
      document.documentElement.classList.add('app-dark')
    } else {
      document.documentElement.classList.remove('app-dark')
    }
  }

  function updateLanguage(newLanguage: string): void {
    language.value = newLanguage
    setStorage('language', newLanguage)
  }

  function setHeaderRules(rules: PersistentHeaderRule[]): void {
    headerRules.value = rules
  }

  /**
   * 从后端加载刷新间隔配置
   */
  async function loadRefreshIntervalFromBackend(): Promise<void> {
    try {
      isLoadingRefreshInterval.value = true
      const config = await getRefreshIntervalConfig()
      autoRefreshInterval.value = config.refreshInterval
      console.info(`已从后端加载刷新间隔配置: ${config.refreshInterval} 分钟`)
    } catch (error) {
      console.error('加载刷新间隔配置失败:', error)
      // 保持默认值
    } finally {
      isLoadingRefreshInterval.value = false
    }
  }

  /**
   * 更新刷新间隔配置（保存到后端）
   */
  async function updateAutoRefreshInterval(interval: number): Promise<boolean> {
    // 限制在 1-60 分钟范围内
    const validInterval = Math.max(1, Math.min(60, interval))
    try {
      const config = await setRefreshIntervalConfig(validInterval)
      autoRefreshInterval.value = config.refreshInterval
      console.info(`刷新间隔已更新为: ${config.refreshInterval} 分钟`)
      return true
    } catch (error) {
      console.error('更新刷新间隔配置失败:', error)
      return false
    }
  }

  // 初始化主题
  watch(theme, (newTheme) => {
    if (newTheme === 'dark') {
      document.documentElement.classList.add('app-dark')
    } else {
      document.documentElement.classList.remove('app-dark')
    }
  }, { immediate: true })

  return {
    // 状态
    apiBaseUrl,
    theme,
    language,
    headerRules,
    autoRefreshInterval,
    isLoadingRefreshInterval,
    // 动作
    loadConfig,
    saveConfig,
    updateTheme,
    updateLanguage,
    setHeaderRules,
    loadRefreshIntervalFromBackend,
    updateAutoRefreshInterval,
  }
})
