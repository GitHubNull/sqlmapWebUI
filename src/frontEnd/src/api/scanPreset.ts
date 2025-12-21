/**
 * 扫描配置预设相关API
 */
import { request } from './request'
import type { 
  ScanPreset, 
  ScanPresetCreate, 
  ScanPresetUpdate,
  ScanPresetListResponse,
  ConfigOptionsResponse,
  ScanOptions
} from '@/types/scanPreset'

/**
 * 获取所有预设配置列表
 */
export async function getAllPresets(includeInactive = false): Promise<ScanPresetListResponse> {
  const result = await request.get<{
    presets: ScanPreset[]
    total: number
    default_preset: ScanPreset | null
  }>('/scan-preset/list', {
    params: { include_inactive: includeInactive }
  })
  
  return {
    presets: result.presets || [],
    total: result.total || 0,
    default_preset: result.default_preset || undefined
  }
}

/**
 * 获取配置选项（用于下拉菜单）
 */
export async function getConfigOptions(): Promise<ConfigOptionsResponse> {
  const result = await request.get<{
    default: ScanPreset | null
    presets: ScanPreset[]
    history: ScanPreset[]
  }>('/scan-preset/config-options')
  
  return {
    default: result.default,
    presets: result.presets || [],
    history: result.history || []
  }
}

/**
 * 获取默认配置
 */
export async function getDefaultPreset(): Promise<ScanPreset | null> {
  const result = await request.get<ScanPreset | null>('/scan-preset/default')
  return result
}

/**
 * 更新默认配置
 */
export async function updateDefaultPreset(options: ScanOptions): Promise<ScanPreset | null> {
  const result = await request.put<ScanPreset | null>('/scan-preset/default', options)
  return result
}

/**
 * 获取常用配置列表
 */
export async function getPresetConfigs(): Promise<ScanPreset[]> {
  const result = await request.get<{
    presets: ScanPreset[]
    total: number
  }>('/scan-preset/presets')
  
  return result.presets || []
}

/**
 * 获取历史配置列表
 */
export async function getHistoryConfigs(limit = 20): Promise<ScanPreset[]> {
  const result = await request.get<{
    presets: ScanPreset[]
    total: number
  }>('/scan-preset/history', {
    params: { limit }
  })
  
  return result.presets || []
}

/**
 * 根据ID获取预设配置
 */
export async function getPresetById(presetId: number): Promise<ScanPreset | null> {
  const result = await request.get<ScanPreset | null>(`/scan-preset/${presetId}`)
  return result
}

/**
 * 创建新的预设配置
 */
export async function createPreset(data: ScanPresetCreate): Promise<ScanPreset | null> {
  const result = await request.post<ScanPreset | null>('/scan-preset', data)
  return result
}

/**
 * 更新预设配置
 */
export async function updatePreset(presetId: number, data: ScanPresetUpdate): Promise<ScanPreset | null> {
  const result = await request.put<ScanPreset | null>(`/scan-preset/${presetId}`, data)
  return result
}

/**
 * 删除预设配置
 */
export async function deletePreset(presetId: number): Promise<boolean> {
  await request.delete(`/scan-preset/${presetId}`)
  return true
}

/**
 * 添加到历史记录
 */
export async function addToHistory(name: string, options: ScanOptions): Promise<ScanPreset | null> {
  const result = await request.post<ScanPreset | null>('/scan-preset/history', {
    options
  }, {
    params: { name }
  })
  return result
}

/**
 * 应用预设配置
 */
export async function applyPreset(presetId: number, baseOptions?: ScanOptions): Promise<ScanOptions> {
  const result = await request.post<{ options: ScanOptions }>(`/scan-preset/${presetId}/apply`, {
    base_options: baseOptions || {}
  })
  return result.options
}
