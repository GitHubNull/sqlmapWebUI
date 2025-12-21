/**
 * 扫描配置预设状态管理
 */
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { 
  ScanPreset, 
  ScanPresetCreate, 
  ScanPresetUpdate,
  ScanOptions,
  PresetOption
} from '@/types/scanPreset'
import { DEFAULT_SCAN_OPTIONS } from '@/types/scanPreset'
import * as scanPresetApi from '@/api/scanPreset'

export const useScanPresetStore = defineStore('scanPreset', () => {
  // 状态
  const loading = ref(false)
  const defaultPreset = ref<ScanPreset | null>(null)
  const presetConfigs = ref<ScanPreset[]>([])
  const historyConfigs = ref<ScanPreset[]>([])
  const allPresets = ref<ScanPreset[]>([])
  const currentOptions = ref<ScanOptions>({ ...DEFAULT_SCAN_OPTIONS })
  const selectedPresetId = ref<number | null>(null)
  
  // 计算属性 - 生成下拉菜单选项
  const presetOptions = computed<PresetOption[]>(() => {
    const options: PresetOption[] = []
    
    // 默认配置
    if (defaultPreset.value) {
      options.push({
        label: `【默认】${defaultPreset.value.name}`,
        value: defaultPreset.value.id || 0,
        preset: defaultPreset.value,
        type: 'default'
      })
    }
    
    // 常用配置分隔符
    if (presetConfigs.value.length > 0) {
      options.push({
        label: '── 常用配置 ──',
        value: 'separator',
        type: 'separator',
        disabled: true
      })
      
      // 常用配置
      presetConfigs.value.forEach(preset => {
        options.push({
          label: preset.name,
          value: preset.id || 0,
          preset,
          type: 'preset'
        })
      })
    }
    
    // 历史配置分隔符
    if (historyConfigs.value.length > 0) {
      options.push({
        label: '── 历史配置 ──',
        value: 'separator',
        type: 'separator',
        disabled: true
      })
      
      // 历史配置
      historyConfigs.value.forEach(preset => {
        options.push({
          label: preset.name,
          value: preset.id || 0,
          preset,
          type: 'history'
        })
      })
    }
    
    return options
  })
  
  // 操作
  
  /**
   * 加载配置选项（用于下拉菜单）
   */
  async function loadConfigOptions() {
    loading.value = true
    try {
      const result = await scanPresetApi.getConfigOptions()
      defaultPreset.value = result.default
      presetConfigs.value = result.presets
      historyConfigs.value = result.history
    } catch (error) {
      console.error('Failed to load config options:', error)
    } finally {
      loading.value = false
    }
  }
  
  /**
   * 加载所有预设
   */
  async function loadAllPresets(includeInactive = false) {
    loading.value = true
    try {
      const result = await scanPresetApi.getAllPresets(includeInactive)
      allPresets.value = result.presets
      defaultPreset.value = result.default_preset || null
    } catch (error) {
      console.error('Failed to load all presets:', error)
    } finally {
      loading.value = false
    }
  }
  
  /**
   * 选择预设并应用
   */
  async function selectPreset(presetId: number) {
    try {
      const options = await scanPresetApi.applyPreset(presetId, currentOptions.value)
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...options }
      selectedPresetId.value = presetId
    } catch (error) {
      console.error('Failed to apply preset:', error)
    }
  }
  
  /**
   * 更新当前选项
   */
  function updateOptions(options: Partial<ScanOptions>) {
    currentOptions.value = { ...currentOptions.value, ...options }
  }
  
  /**
   * 重置为默认选项
   */
  function resetOptions() {
    currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
    selectedPresetId.value = null
    
    // 如果有默认预设，应用它
    if (defaultPreset.value) {
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...defaultPreset.value.options }
      selectedPresetId.value = defaultPreset.value.id || null
    }
  }
  
  /**
   * 更新默认配置
   */
  async function updateDefaultPreset(options: ScanOptions): Promise<ScanPreset | null> {
    try {
      const result = await scanPresetApi.updateDefaultPreset(options)
      if (result) {
        defaultPreset.value = result
        currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...result.options }
      }
      return result
    } catch (error) {
      console.error('Failed to update default preset:', error)
      return null
    }
  }
  
  /**
   * 创建新预设
   */
  async function createPreset(data: ScanPresetCreate): Promise<ScanPreset | null> {
    try {
      const result = await scanPresetApi.createPreset(data)
      if (result) {
        // 重新加载列表
        await loadConfigOptions()
      }
      return result
    } catch (error) {
      console.error('Failed to create preset:', error)
      return null
    }
  }
  
  /**
   * 更新预设
   */
  async function updatePreset(presetId: number, data: ScanPresetUpdate): Promise<ScanPreset | null> {
    try {
      const result = await scanPresetApi.updatePreset(presetId, data)
      if (result) {
        await loadConfigOptions()
      }
      return result
    } catch (error) {
      console.error('Failed to update preset:', error)
      return null
    }
  }
  
  /**
   * 删除预设
   */
  async function deletePreset(presetId: number): Promise<boolean> {
    try {
      await scanPresetApi.deletePreset(presetId)
      await loadConfigOptions()
      return true
    } catch (error) {
      console.error('Failed to delete preset:', error)
      return false
    }
  }
  
  /**
   * 保存当前配置为新预设
   */
  async function saveCurrentAsPreset(name: string, description?: string): Promise<ScanPreset | null> {
    return await createPreset({
      name,
      description,
      preset_type: 'preset',
      options: currentOptions.value
    })
  }
  
  /**
   * 添加到历史记录
   */
  async function addToHistory(name: string): Promise<ScanPreset | null> {
    try {
      const result = await scanPresetApi.addToHistory(name, currentOptions.value)
      if (result) {
        await loadConfigOptions()
      }
      return result
    } catch (error) {
      console.error('Failed to add to history:', error)
      return null
    }
  }
  
  /**
   * 获取当前选项的非默认值（用于提交任务）
   */
  function getEffectiveOptions(): ScanOptions {
    const result: ScanOptions = {}
    const defaults = DEFAULT_SCAN_OPTIONS
    
    for (const [key, value] of Object.entries(currentOptions.value)) {
      const defaultValue = (defaults as any)[key]
      if (value !== defaultValue && value !== null && value !== undefined && value !== '') {
        (result as any)[key] = value
      }
    }
    
    // 确保batch选项始终存在
    result.batch = true
    
    return result
  }
  
  return {
    // 状态
    loading,
    defaultPreset,
    presetConfigs,
    historyConfigs,
    allPresets,
    currentOptions,
    selectedPresetId,
    
    // 别名（兼容组件使用）
    presets: presetConfigs,
    history: historyConfigs,
    
    // 计算属性
    presetOptions,
    
    // 操作
    loadConfigOptions,
    loadAllPresets,
    selectPreset,
    updateOptions,
    resetOptions,
    updateDefaultPreset,
    createPreset,
    updatePreset,
    deletePreset,
    saveCurrentAsPreset,
    addToHistory,
    getEffectiveOptions
  }
})
