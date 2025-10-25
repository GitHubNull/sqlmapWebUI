// 后端响应基础结构
export interface BaseResponse<T = any> {
  code: number // 业务状态码
  success: boolean // 操作是否成功
  message: string // 响应消息
  data: T // 响应数据
}

// API响应列表类型
export type ListResponse<T> = BaseResponse<T[]>

// API响应单个项类型
export type ItemResponse<T> = BaseResponse<T>

// 分页参数
export interface PaginationParams {
  page: number
  pageSize: number
}

// 分页响应
export interface PaginatedData<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}
