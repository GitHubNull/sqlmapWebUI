/**
 * SQLMap 危险参数安全定义
 */
import type { SecurityLevel } from './types'

// 危险参数分类
export const DANGEROUS_PARAMS: Record<SecurityLevel, string[]> = {
  // 严重危险 (红色警告) - 可远程执行系统命令或修改注册表
  danger: [
    'osCmd',      // --os-cmd 远程命令执行
    'osPwn',      // --os-pwn 获取 Meterpreter/VNC
    'osSmb',      // --os-smbrelay SMB 后门
    'osBof',      // --os-bof 缓冲区溢出
    'regAdd',     // --reg-add 添加注册表项
    'regDel'      // --reg-del 删除注册表项
  ],

  // 高危 (橙色警告) - 可访问操作系统或提升权限
  warning: [
    'osShell',    // --os-shell 交互式 OS shell
    'privEsc',    // --priv-esc 权限提升
    'regRead'     // --reg-read 读取注册表
  ],

  // 普通参数
  normal: []
}

// 中危参数（文件系统访问）单独处理
export const FILE_SYSTEM_PARAMS = [
  'fileRead',   // --file-read 读取文件
  'fileWrite',  // --file-write 写入文件
  'fileDest'    // --file-dest 文件目标路径
]

// 安全警告消息
export const SECURITY_WARNINGS: Record<SecurityLevel, string> = {
  danger: '严重安全风险：此参数可执行远程系统命令或修改注册表，请仅在授权测试环境中使用！',
  warning: '高风险参数：此参数可访问操作系统或提升权限，请谨慎使用！',
  normal: ''
}

export const FILE_SYSTEM_WARNING = '中等风险：此参数可访问文件系统，请确保有合法授权！'

// 获取参数的安全等级
export function getParamSecurityLevel(key: string): SecurityLevel {
  if (DANGEROUS_PARAMS.danger.includes(key)) {
    return 'danger'
  }
  if (DANGEROUS_PARAMS.warning.includes(key) || FILE_SYSTEM_PARAMS.includes(key)) {
    return 'warning'
  }
  return 'normal'
}

// 获取参数的安全警告
export function getParamSecurityWarning(key: string): string {
  if (DANGEROUS_PARAMS.danger.includes(key)) {
    return SECURITY_WARNINGS.danger
  }
  if (DANGEROUS_PARAMS.warning.includes(key)) {
    return SECURITY_WARNINGS.warning
  }
  if (FILE_SYSTEM_PARAMS.includes(key)) {
    return FILE_SYSTEM_WARNING
  }
  return ''
}

// 检查是否为危险参数
export function isDangerousParam(key: string): boolean {
  return DANGEROUS_PARAMS.danger.includes(key) ||
         DANGEROUS_PARAMS.warning.includes(key) ||
         FILE_SYSTEM_PARAMS.includes(key)
}

// 禁用的参数（后端不支持或自动处理）
export const DISABLED_PARAMS = {
  // 后端自动添加的参数
  autoAdded: ['api', 'taskid', 'database', 'batch', 'disableColoring', 'eta'],

  // RESTAPI 不支持的参数
  restApiUnsupported: ['sqlShell', 'wizard'],

  // 特殊处理的参数（由后端生成）
  specialHandled: ['requestFile']
}

// 检查参数是否被禁用
export function isParamDisabled(key: string): boolean {
  return DISABLED_PARAMS.autoAdded.includes(key) ||
         DISABLED_PARAMS.restApiUnsupported.includes(key) ||
         DISABLED_PARAMS.specialHandled.includes(key)
}

// 获取参数禁用原因
export function getDisabledReason(key: string): string {
  if (DISABLED_PARAMS.autoAdded.includes(key)) {
    return '此参数由后端自动添加'
  }
  if (DISABLED_PARAMS.restApiUnsupported.includes(key)) {
    return 'SQLMap RESTAPI 不支持此参数'
  }
  if (DISABLED_PARAMS.specialHandled.includes(key)) {
    return '此参数由后端自动处理'
  }
  return ''
}
