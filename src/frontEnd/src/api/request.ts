/**
 * Axios请求封装和拦截器配置
 * 支持本地/远程双模式认证
 */
import axios, { AxiosError } from 'axios'
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import type { BaseResponse } from '@/types/api'
import { isLocalAccess } from '@/utils/auth'
import { getStorage, removeStorage } from '@/utils/storage'
import { useToast } from 'primevue/usetoast'

// 创建Toast实例用于错误提示
let toastInstance: ReturnType<typeof useToast> | null = null

// 初始化Toast实例（在应用启动后调用）
export function initToast() {
  toastInstance = useToast()
}

// 显示错误提示
function showError(message: string, life: number = 5000) {
  if (toastInstance) {
    toastInstance.add({
      severity: 'error',
      summary: '错误',
      detail: message,
      life
    })
  } else {
    console.error(message)
  }
}

// 显示警告提示
function showWarning(message: string, life: number = 4000) {
  if (toastInstance) {
    toastInstance.add({
      severity: 'warn',
      summary: '警告',
      detail: message,
      life
    })
  } else {
    console.warn(message)
  }
}

// 创建axios实例
const instance: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 重试配置
const RETRY_CONFIG = {
  maxRetries: 3,        // 最大重试次数
  initialDelay: 1000,   // 初始延迟（毫秒）
  delayMultiplier: 2,   // 延迟倍数（指数退避）
  maxDelay: 10000,      // 最大延迟（毫秒）
  retryableStatusCodes: [408, 500, 502, 503, 504], // 可重试的HTTP状态码
}

// 判断是否应该重试
function shouldRetry(error: AxiosError, retryCount: number): boolean {
  // 超过最大重试次数
  if (retryCount >= RETRY_CONFIG.maxRetries) {
    return false
  }
  
  // 只重试GET请求（幂等性）
  if (error.config?.method?.toUpperCase() !== 'GET') {
    return false
  }
  
  // 网络错误或超时
  if (!error.response) {
    return true
  }
  
  // 特定的HTTP状态码
  const status = error.response.status
  return RETRY_CONFIG.retryableStatusCodes.includes(status)
}

// 计算重试延迟（指数退避）
function getRetryDelay(retryCount: number): number {
  const delay = RETRY_CONFIG.initialDelay * Math.pow(RETRY_CONFIG.delayMultiplier, retryCount)
  return Math.min(delay, RETRY_CONFIG.maxDelay)
}

// 延迟函数
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// 请求拦截器
instance.interceptors.request.use(
  (config) => {
    // 本地访问模式:不添加Token
    // 远程访问模式:添加认证Token
    if (!isLocalAccess()) {
      const token = getStorage<string>('token')
      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
    }
    
    // 添加通用请求头
    config.headers['X-Requested-With'] = 'XMLHttpRequest'
    
    return config
  },
  (error) => {
    console.error('Request error:', error)
    return Promise.reject(error)
  }
)

// 响应拦截器
instance.interceptors.response.use(
  (response: AxiosResponse<BaseResponse>) => {
    const { data } = response
    
    // 检查业务状态码
    if (data.code === 200 && data.success) {
      // 成功,返回data字段
      return data.data
    } else {
      // 业务错误,显示错误消息
      const errorMessage = data.message || '请求失败'
      showWarning(errorMessage)
      
      return Promise.reject(new Error(errorMessage))
    }
  },
  async (error: AxiosError<BaseResponse>) => {
    const config = error.config as AxiosRequestConfig & { _retryCount?: number }
    
    // 初始化重试计数器
    if (!config._retryCount) {
      config._retryCount = 0
    }
    
    // 判断是否应该重试
    if (shouldRetry(error, config._retryCount)) {
      config._retryCount += 1
      const delay = getRetryDelay(config._retryCount - 1)
      
      console.debug(`Retrying request (${config._retryCount}/${RETRY_CONFIG.maxRetries}) after ${delay}ms...`)
      
      // 等待后重试
      await sleep(delay)
      return instance.request(config)
    }
    
    // HTTP错误处理
    if (error.response) {
      const { status, data } = error.response
      
      // 401未授权处理
      if (status === 401) {
        // 本地模式:忽略401错误
        if (isLocalAccess()) {
          console.warn('Local access mode: ignoring 401 error')
          return Promise.reject(error)
        }
        
        // 远程模式:清除认证信息并提示
        console.warn('Authentication failed, please login again')
        removeStorage('token')
        removeStorage('userInfo')
        
        showError('认证失败，请重新登录', 0) // 0 = 永久显示
        
        return Promise.reject(new Error('认证失败,请重新登录'))
      }
      
      // 其他HTTP错误
      const errorMessage = data?.message || `请求失败(${status})`
      showError(errorMessage)
      
      return Promise.reject(new Error(errorMessage))
    }
    
    // 网络错误或超时
    if (error.code === 'ECONNABORTED') {
      showError('请求超时，请稍后重试')
      return Promise.reject(new Error('请求超时'))
    }
    
    // 连接拒绝错误
    if (error.message.includes('Network Error') || error.code === 'ERR_NETWORK') {
      showError('无法连接到后端服务，请检查服务是否启动')
      return Promise.reject(new Error('网络错误'))
    }
    
    // 其他网络错误
    showError('网络错误，请检查网络连接')
    return Promise.reject(error)
  }
)

// 导出请求方法
export const request = {
  get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return instance.get(url, config)
  },
  
  post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return instance.post(url, data, config)
  },
  
  put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return instance.put(url, data, config)
  },
  
  patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return instance.patch(url, data, config)
  },
  
  delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return instance.delete(url, config)
  },
}

export default instance
