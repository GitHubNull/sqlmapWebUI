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
 * 历史配置列表响应
 */
export interface HistoryListResponse {
  presets: ScanPreset[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

/**
 * 获取历史配置列表（带分页和排序）
 */
export async function getHistoryConfigs(
  page: number = 1,
  pageSize: number = 10,
  sortField: string = 'last_used_at',
  sortOrder: string = 'desc'
): Promise<HistoryListResponse> {
  const result = await request.get<{
    presets: ScanPreset[]
    total: number
    page: number
    page_size: number
    total_pages: number
  }>('/scan-preset/history', {
    params: {
      page,
      page_size: pageSize,
      sort_field: sortField,
      sort_order: sortOrder
    }
  })
  
  return {
    presets: result.presets || [],
    total: result.total || 0,
    page: result.page || 1,
    page_size: result.page_size || 10,
    total_pages: result.total_pages || 0
  }
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
