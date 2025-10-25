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

  return {
    // 状态
    apiBaseUrl,
    theme,
    language,
    headerRules,
    // 动作
    loadConfig,
    saveConfig,
    updateTheme,
    updateLanguage,
    setHeaderRules,
  }
})
