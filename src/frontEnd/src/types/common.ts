// 用户信息
export interface UserInfo {
  username: string
  email?: string
  role?: string
}

// 登录请求
export interface LoginRequest {
  username: string
  password: string
}

// 登录响应
export interface LoginResponse {
  token: string
  userInfo: UserInfo
}

// 通用类型
export type Nullable<T> = T | null
export type Optional<T> = T | undefined
