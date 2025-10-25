/**
 * 配置状态管理
 */
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { getStorage, setStorage } from '@/utils/storage'
import type { PersistentHeaderRule } from '@/types/headerRule'

export const useConfigStore = defineStore('config', () => {
  // 状态
  const apiBaseUrl = ref<string>(import.meta.env.VITE_API_BASE_URL || '/api')
  const theme = ref<'light' | 'dark'>((getStorage<'light' | 'dark'>('theme') ?? 'light') as 'light' | 'dark')
  const language = ref<string>((getStorage<string>('language') ?? 'zh-CN') as string)
  const headerRules = ref<PersistentHeaderRule[]>([])
  // 自动刷新间隔配置（分钟），默认15分钟
  const autoRefreshInterval = ref<number>((getStorage<number>('autoRefreshInterval') ?? 15) as number)

  // 动作
  function loadConfig(): void {
    theme.value = (getStorage<'light' | 'dark'>('theme') ?? 'light') as 'light' | 'dark'
    language.value = (getStorage<string>('language') ?? 'zh-CN') as string
    autoRefreshInterval.value = (getStorage<number>('autoRefreshInterval') ?? 15) as number
  }

  function saveConfig(): void {
    setStorage('theme', theme.value)
    setStorage('language', language.value)
    setStorage('autoRefreshInterval', autoRefreshInterval.value)
  }

  function updateTheme(newTheme: 'light' | 'dark'): void {
    theme.value = newTheme
    setStorage('theme', newTheme)
    
    // 应用主题到DOM
    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark-mode')
    } else {
      document.documentElement.classList.remove('dark-mode')
    }
  }

  function updateLanguage(newLanguage: string): void {
    language.value = newLanguage
    setStorage('language', newLanguage)
  }

  function setHeaderRules(rules: PersistentHeaderRule[]): void {
    headerRules.value = rules
  }

  function updateAutoRefreshInterval(interval: number): void {
    // 限制在5-60分钟范围内
    autoRefreshInterval.value = Math.max(5, Math.min(60, interval))
    setStorage('autoRefreshInterval', autoRefreshInterval.value)
  }

  return {
    // 状态
    apiBaseUrl,
    theme,
    language,
    headerRules,
    autoRefreshInterval,
    // 动作
    loadConfig,
    saveConfig,
    updateTheme,
    updateLanguage,
    setHeaderRules,
    updateAutoRefreshInterval,
  }
})
