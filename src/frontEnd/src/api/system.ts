/**
 * 系统配置 API
 */
import request from './request'

export interface RefreshIntervalConfig {
  refreshInterval: number
  minInterval: number
  maxInterval: number
}

/**
 * 获取刷新间隔配置
 */
export async function getRefreshIntervalConfig(): Promise<RefreshIntervalConfig> {
  // request 已在拦截器中返回 data.data，这里直接返回即可
  return request.get('/config/refresh-interval')
}

/**
 * 设置刷新间隔配置
 */
export async function setRefreshIntervalConfig(interval: number): Promise<RefreshIntervalConfig> {
  // request 已在拦截器中返回 data.data，这里直接返回即可
  return request.post('/config/refresh-interval', { interval })
}
