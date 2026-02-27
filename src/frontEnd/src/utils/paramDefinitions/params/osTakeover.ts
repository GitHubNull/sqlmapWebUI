/**
 * OS Takeover 操作系统接管参数定义
 */
import type { ParamDefinition } from '../types'

export const OS_TAKEOVER_PARAMS: ParamDefinition[] = [
  {
    key: 'osCmd',
    cliName: '--os-cmd',
    name: 'OS Command',
    description: '执行操作系统命令',
    category: 'osTakeover',
    type: 'string',
    placeholder: 'whoami',
    securityLevel: 'danger',
    securityWarning: '严重安全风险：此参数可执行远程系统命令，请仅在授权测试环境中使用！'
  },
  {
    key: 'osShell',
    cliName: '--os-shell',
    name: 'OS Shell',
    description: '交互式操作系统 shell',
    category: 'osTakeover',
    type: 'boolean',
    securityLevel: 'warning',
    securityWarning: '高风险参数：此参数可访问操作系统，请谨慎使用！'
  },
  {
    key: 'osPwn',
    cliName: '--os-pwn',
    name: 'OS Pwn',
    description: '获取 OOB shell、Meterpreter 或 VNC',
    category: 'osTakeover',
    type: 'boolean',
    securityLevel: 'danger',
    securityWarning: '严重安全风险：此参数可执行远程系统命令，请仅在授权测试环境中使用！'
  },
  {
    key: 'osSmb',
    cliName: '--os-smbrelay',
    name: 'OS SMB Relay',
    description: '一键获取 OOB shell、Meterpreter 或 VNC',
    category: 'osTakeover',
    type: 'boolean',
    securityLevel: 'danger',
    securityWarning: '严重安全风险：此参数可执行远程系统命令，请仅在授权测试环境中使用！'
  },
  {
    key: 'osBof',
    cliName: '--os-bof',
    name: 'OS Buffer Overflow',
    description: '存储过程缓冲区溢出利用',
    category: 'osTakeover',
    type: 'boolean',
    securityLevel: 'danger',
    securityWarning: '严重安全风险：此参数可执行远程系统命令，请仅在授权测试环境中使用！'
  },
  {
    key: 'privEsc',
    cliName: '--priv-esc',
    name: 'Privilege Escalation',
    description: '数据库进程用户权限提升',
    category: 'osTakeover',
    type: 'boolean',
    securityLevel: 'warning',
    securityWarning: '高风险参数：此参数可提升权限，请谨慎使用！'
  },
  {
    key: 'msfPath',
    cliName: '--msf-path',
    name: 'MSF Path',
    description: 'Metasploit Framework 安装路径',
    category: 'osTakeover',
    type: 'string',
    advanced: true
  },
  {
    key: 'tmpPath',
    cliName: '--tmp-path',
    name: 'Temp Path',
    description: '远程临时文件目录的绝对路径',
    category: 'osTakeover',
    type: 'string',
    advanced: true
  }
]
