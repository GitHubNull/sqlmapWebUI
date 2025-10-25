/**
 * 本地存储工具函数
 */

const STORAGE_PREFIX = 'sqlmap_webui_'

/**
 * 设置存储项
 */
export function setStorage(key: string, value: any): void {
  try {
    const serializedValue = JSON.stringify(value)
    localStorage.setItem(STORAGE_PREFIX + key, serializedValue)
  } catch (error) {
    console.error('Error saving to localStorage:', error)
  }
}

/**
 * 获取存储项
 */
export function getStorage<T>(key: string, defaultValue?: T): T {
  try {
    const item = localStorage.getItem(STORAGE_PREFIX + key)
    if (item === null) {
      return defaultValue as T
    }
    return JSON.parse(item) as T
  } catch (error) {
    console.error('Error reading from localStorage:', error)
    return defaultValue as T
  }
}

/**
 * 移除存储项
 */
export function removeStorage(key: string): void {
  try {
    localStorage.removeItem(STORAGE_PREFIX + key)
  } catch (error) {
    console.error('Error removing from localStorage:', error)
  }
}

/**
 * 清空所有存储项
 */
export function clearStorage(): void {
  try {
    const keys = Object.keys(localStorage)
    keys.forEach((key) => {
      if (key.startsWith(STORAGE_PREFIX)) {
        localStorage.removeItem(key)
      }
    })
  } catch (error) {
    console.error('Error clearing localStorage:', error)
  }
}
