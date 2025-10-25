/**
 * 认证检测工具函数
 */

/**
 * 获取当前访问的主机名
 */
export function getHostname(): string {
  return window.location.hostname
}

/**
 * 判断当前是否为本地访问
 * 本地访问判断条件:
 * - hostname === 'localhost'
 * - hostname === '127.0.0.1'
 * - hostname === '::1' (IPv6回环地址)
 * - hostname.startsWith('127.') (所有127段地址)
 */
export function isLocalAccess(): boolean {
  const hostname = getHostname()
  
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname.startsWith('127.')
  )
}

/**
 * 是否应该跳过认证
 * 本地访问时跳过认证流程
 */
export function shouldSkipAuth(): boolean {
  return isLocalAccess()
}

/**
 * 检查当前环境是否需要认证
 */
export function isAuthRequired(): boolean {
  return !isLocalAccess()
}
