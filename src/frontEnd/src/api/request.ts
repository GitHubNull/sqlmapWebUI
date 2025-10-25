/**
 * Axios请求封装和拦截器配置
 * 支持本地/远程双模式认证
 */
import axios, { AxiosError } from 'axios'
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import type { BaseResponse } from '@/types/api'
import { isLocalAccess } from '@/utils/auth'
import { getStorage, removeStorage } from '@/utils/storage'

// 创建axios实例
const instance: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

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
      console.error('Business error:', errorMessage)
      
      // TODO: 显示错误提示(集成Toast组件后实现)
      // showError(errorMessage)
      
      return Promise.reject(new Error(errorMessage))
    }
  },
  async (error: AxiosError<BaseResponse>) => {
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
        
        // 远程模式:尝试刷新Token或跳转登录
        console.warn('Authentication failed, redirecting to login...')
        removeStorage('token')
        removeStorage('userInfo')
        
        // TODO: 跳转到登录页(集成Router后实现)
        // router.push('/login')
        
        return Promise.reject(new Error('认证失败,请重新登录'))
      }
      
      // 其他错误
      const errorMessage = data?.message || `请求失败(${status})`
      console.error('HTTP error:', errorMessage)
      
      // TODO: 显示错误提示
      // showError(errorMessage)
      
      return Promise.reject(new Error(errorMessage))
    }
    
    // 网络错误或超时
    const networkError = error.code === 'ECONNABORTED' ? '请求超时' : '网络错误'
    console.error('Network error:', networkError)
    
    // TODO: 显示错误提示
    // showError(networkError)
    
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
  
  delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return instance.delete(url, config)
  },
}

export default instance
