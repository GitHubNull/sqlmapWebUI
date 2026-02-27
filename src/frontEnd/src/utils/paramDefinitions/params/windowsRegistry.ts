/**
 * Windows Registry 注册表参数定义
 */
import type { ParamDefinition } from '../types'

export const WINDOWS_REGISTRY_PARAMS: ParamDefinition[] = [
  {
    key: 'regRead',
    cliName: '--reg-read',
    name: 'Registry Read',
    description: '读取 Windows 注册表键值',
    category: 'windowsRegistry',
    type: 'boolean',
    securityLevel: 'warning',
    securityWarning: '高风险参数：此参数可读取注册表，请谨慎使用！'
  },
  {
    key: 'regAdd',
    cliName: '--reg-add',
    name: 'Registry Add',
    description: '写入 Windows 注册表键值数据',
    category: 'windowsRegistry',
    type: 'boolean',
    securityLevel: 'danger',
    securityWarning: '严重安全风险：此参数可修改注册表，请仅在授权测试环境中使用！'
  },
  {
    key: 'regDel',
    cliName: '--reg-del',
    name: 'Registry Delete',
    description: '删除 Windows 注册表键值',
    category: 'windowsRegistry',
    type: 'boolean',
    securityLevel: 'danger',
    securityWarning: '严重安全风险：此参数可修改注册表，请仅在授权测试环境中使用！'
  },
  {
    key: 'regKey',
    cliName: '--reg-key',
    name: 'Registry Key',
    description: 'Windows 注册表键',
    category: 'windowsRegistry',
    type: 'string',
    placeholder: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\...'
  },
  {
    key: 'regValue',
    cliName: '--reg-value',
    name: 'Registry Value',
    description: 'Windows 注册表键值',
    category: 'windowsRegistry',
    type: 'string'
  },
  {
    key: 'regData',
    cliName: '--reg-data',
    name: 'Registry Data',
    description: 'Windows 注册表键值数据',
    category: 'windowsRegistry',
    type: 'string'
  },
  {
    key: 'regType',
    cliName: '--reg-type',
    name: 'Registry Type',
    description: 'Windows 注册表键值类型',
    category: 'windowsRegistry',
    type: 'string'
  }
]
