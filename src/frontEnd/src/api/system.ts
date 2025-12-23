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
  const response = await request.get('/config/refresh-interval')
  return response.data.data
}

/**
 * 设置刷新间隔配置
 */
export async function setRefreshIntervalConfig(interval: number): Promise<RefreshIntervalConfig> {
  const response = await request.post('/config/refresh-interval', { interval })
  return response.data.data
}
