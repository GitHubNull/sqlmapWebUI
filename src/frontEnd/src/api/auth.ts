/**
 * 认证相关API
 */
import { request } from './request'
import type { LoginRequest, LoginResponse } from '@/types/common'

/**
 * 用户登录
 */
export function login(data: LoginRequest): Promise<LoginResponse> {
  return request.post('/auth/login', data)
}

/**
 * 刷新访问令牌
 */
export function refreshToken(): Promise<{ token: string }> {
  return request.post('/auth/refresh')
}

/**
 * 获取系统版本(无需认证)
 */
export function getVersion(): Promise<{ version: string }> {
  return request.get('/version')
}

/**
 * 检查当前访问是否需要认证
 */
export function checkAuthRequired(): Promise<{ required: boolean }> {
  return request.get('/auth/check-required')
}
