/**
 * SQLMap 参数分类定义
 */
import type { ParamCategory } from './types'

export const PARAM_CATEGORIES: ParamCategory[] = [
  {
    key: 'target',
    label: 'Target 目标',
    icon: 'pi pi-bullseye',
    description: '定义扫描目标',
    order: 1
  },
  {
    key: 'request',
    label: 'Request 请求',
    icon: 'pi pi-send',
    description: 'HTTP 请求配置',
    order: 2
  },
  {
    key: 'optimization',
    label: 'Optimization 优化',
    icon: 'pi pi-bolt',
    description: '性能优化选项',
    order: 3
  },
  {
    key: 'injection',
    label: 'Injection 注入',
    icon: 'pi pi-code',
    description: '注入测试配置',
    order: 4
  },
  {
    key: 'detection',
    label: 'Detection 检测',
    icon: 'pi pi-search',
    description: '检测配置',
    order: 5
  },
  {
    key: 'techniques',
    label: 'Techniques 技术',
    icon: 'pi pi-wrench',
    description: '注入技术配置',
    order: 6
  },
  {
    key: 'fingerprint',
    label: 'Fingerprint 指纹',
    icon: 'pi pi-id-card',
    description: '数据库指纹识别',
    order: 7
  },
  {
    key: 'enumeration',
    label: 'Enumeration 枚举',
    icon: 'pi pi-database',
    description: '数据枚举选项',
    order: 8
  },
  {
    key: 'bruteForce',
    label: 'Brute Force 暴力破解',
    icon: 'pi pi-key',
    description: '暴力破解选项',
    order: 9
  },
  {
    key: 'udf',
    label: 'UDF 用户函数',
    icon: 'pi pi-box',
    description: '用户自定义函数',
    order: 10
  },
  {
    key: 'fileSystem',
    label: 'File System 文件系统',
    icon: 'pi pi-folder',
    description: '文件系统访问',
    order: 11
  },
  {
    key: 'osTakeover',
    label: 'OS Takeover 系统接管',
    icon: 'pi pi-desktop',
    description: '操作系统接管',
    order: 12
  },
  {
    key: 'windowsRegistry',
    label: 'Windows Registry 注册表',
    icon: 'pi pi-cog',
    description: 'Windows 注册表操作',
    order: 13
  },
  {
    key: 'general',
    label: 'General 通用',
    icon: 'pi pi-sliders-h',
    description: '通用选项',
    order: 14
  },
  {
    key: 'miscellaneous',
    label: 'Miscellaneous 其他',
    icon: 'pi pi-ellipsis-h',
    description: '其他选项',
    order: 15
  }
]

// 获取分类
export function getCategory(key: string): ParamCategory | undefined {
  return PARAM_CATEGORIES.find(c => c.key === key)
}

// 获取排序后的分类列表
export function getSortedCategories(): ParamCategory[] {
  return [...PARAM_CATEGORIES].sort((a, b) => a.order - b.order)
}
