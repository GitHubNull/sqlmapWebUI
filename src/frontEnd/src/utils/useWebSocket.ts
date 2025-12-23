/**
 * WebSocket 连接管理工具
 * 
 * 提供与后端的实时通信能力，接收刷新通知等消息
 */

import { ref, onMounted, onUnmounted } from 'vue'

export interface WebSocketMessage {
  type: string
  message?: string
  data?: Record<string, any>
  timestamp?: string
}

export interface UseWebSocketOptions {
  /** WebSocket 服务器URL，默认自动检测 */
  url?: string
  /** 是否自动重连 */
  autoReconnect?: boolean
  /** 重连间隔（毫秒） */
  reconnectInterval?: number
  /** 最大重连次数 */
  maxReconnectAttempts?: number
  /** 心跳间隔（毫秒），0表示禁用 */
  heartbeatInterval?: number
  /** 连接成功回调 */
  onConnected?: () => void
  /** 断开连接回调 */
  onDisconnected?: () => void
  /** 收到刷新通知回调 */
  onRefresh?: () => void
  /** 收到消息回调 */
  onMessage?: (message: WebSocketMessage) => void
  /** 错误回调 */
  onError?: (error: Event) => void
}

/**
 * 获取 WebSocket URL
 */
function getWebSocketUrl(): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  
  // 开发环境使用后端端口
  if (import.meta.env.DEV) {
    return `ws://localhost:8775/ws`
  }
  
  return `${protocol}//${host}/ws`
}

/**
 * WebSocket 连接 Hook
 */
export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    url = getWebSocketUrl(),
    autoReconnect = true,
    reconnectInterval = 5000,
    maxReconnectAttempts = 10,
    heartbeatInterval = 30000,
    onConnected,
    onDisconnected,
    onRefresh,
    onMessage,
    onError,
  } = options

  // 状态
  const isConnected = ref(false)
  const reconnectAttempts = ref(0)
  
  // WebSocket 实例
  let ws: WebSocket | null = null
  let heartbeatTimer: ReturnType<typeof setInterval> | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null

  /**
   * 建立连接
   */
  function connect(): void {
    if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
      console.debug('WebSocket 已连接或正在连接中')
      return
    }

    try {
      console.info(`正在连接 WebSocket: ${url}`)
      ws = new WebSocket(url)

      ws.onopen = () => {
        console.info('WebSocket 连接成功')
        isConnected.value = true
        reconnectAttempts.value = 0
        
        // 启动心跳
        startHeartbeat()
        
        onConnected?.()
      }

      ws.onclose = (event) => {
        console.info(`WebSocket 连接关闭: code=${event.code}, reason=${event.reason}`)
        isConnected.value = false
        
        // 停止心跳
        stopHeartbeat()
        
        onDisconnected?.()
        
        // 尝试重连
        if (autoReconnect && reconnectAttempts.value < maxReconnectAttempts) {
          scheduleReconnect()
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket 错误:', error)
        onError?.(error)
      }

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)
          handleMessage(message)
        } catch (e) {
          console.error('解析 WebSocket 消息失败:', e)
        }
      }
    } catch (e) {
      console.error('创建 WebSocket 连接失败:', e)
      if (autoReconnect) {
        scheduleReconnect()
      }
    }
  }

  /**
   * 处理接收到的消息
   */
  function handleMessage(message: WebSocketMessage): void {
    console.debug('收到 WebSocket 消息:', message)
    
    switch (message.type) {
      case 'connected':
        console.info('WebSocket 连接确认:', message.message)
        break
        
      case 'refresh':
        console.info('收到刷新通知')
        onRefresh?.()
        break
        
      case 'pong':
        // 心跳响应，不需要特殊处理
        break
        
      case 'configUpdate':
        console.info('配置已更新:', message.data)
        break
        
      default:
        console.debug('未知消息类型:', message.type)
    }
    
    // 通用消息回调
    onMessage?.(message)
  }

  /**
   * 发送消息
   */
  function send(message: WebSocketMessage): boolean {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      console.warn('WebSocket 未连接，无法发送消息')
      return false
    }
    
    try {
      ws.send(JSON.stringify(message))
      return true
    } catch (e) {
      console.error('发送 WebSocket 消息失败:', e)
      return false
    }
  }

  /**
   * 发送心跳
   */
  function sendHeartbeat(): void {
    send({ type: 'ping' })
  }

  /**
   * 启动心跳
   */
  function startHeartbeat(): void {
    if (heartbeatInterval <= 0) return
    
    stopHeartbeat()
    heartbeatTimer = setInterval(sendHeartbeat, heartbeatInterval)
  }

  /**
   * 停止心跳
   */
  function stopHeartbeat(): void {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }
  }

  /**
   * 安排重连
   */
  function scheduleReconnect(): void {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
    }
    
    reconnectAttempts.value++
    const delay = Math.min(reconnectInterval * reconnectAttempts.value, 60000)
    
    console.info(`将在 ${delay}ms 后尝试第 ${reconnectAttempts.value} 次重连`)
    
    reconnectTimer = setTimeout(() => {
      connect()
    }, delay)
  }

  /**
   * 断开连接
   */
  function disconnect(): void {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    
    stopHeartbeat()
    
    if (ws) {
      ws.close()
      ws = null
    }
    
    isConnected.value = false
  }

  /**
   * 设置刷新间隔
   */
  function setRefreshInterval(interval: number): boolean {
    return send({
      type: 'setRefreshInterval',
      data: { interval }
    })
  }

  // 生命周期
  onMounted(() => {
    connect()
  })

  onUnmounted(() => {
    disconnect()
  })

  return {
    isConnected,
    reconnectAttempts,
    connect,
    disconnect,
    send,
    setRefreshInterval,
  }
}

/**
 * 全局 WebSocket 服务（单例模式）
 */
class WebSocketService {
  private static instance: WebSocketService | null = null
  private ws: WebSocket | null = null
  private isConnected = false
  private reconnectAttempts = 0
  private maxReconnectAttempts = 10
  private reconnectInterval = 5000
  private heartbeatInterval = 30000
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private refreshCallbacks: Set<() => void> = new Set()
  private messageCallbacks: Set<(msg: WebSocketMessage) => void> = new Set()

  private constructor() {}

  static getInstance(): WebSocketService {
    if (!WebSocketService.instance) {
      WebSocketService.instance = new WebSocketService()
    }
    return WebSocketService.instance
  }

  connect(): void {
    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
      return
    }

    const url = getWebSocketUrl()
    console.info(`[WebSocketService] 正在连接: ${url}`)

    try {
      this.ws = new WebSocket(url)

      this.ws.onopen = () => {
        console.info('[WebSocketService] 连接成功')
        this.isConnected = true
        this.reconnectAttempts = 0
        this.startHeartbeat()
      }

      this.ws.onclose = () => {
        console.info('[WebSocketService] 连接关闭')
        this.isConnected = false
        this.stopHeartbeat()
        this.scheduleReconnect()
      }

      this.ws.onerror = (error) => {
        console.error('[WebSocketService] 错误:', error)
      }

      this.ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)
          this.handleMessage(message)
        } catch (e) {
          console.error('[WebSocketService] 解析消息失败:', e)
        }
      }
    } catch (e) {
      console.error('[WebSocketService] 创建连接失败:', e)
      this.scheduleReconnect()
    }
  }

  private handleMessage(message: WebSocketMessage): void {
    if (message.type === 'refresh') {
      console.info('[WebSocketService] 收到刷新通知')
      this.refreshCallbacks.forEach(cb => cb())
    }
    this.messageCallbacks.forEach(cb => cb(message))
  }

  private startHeartbeat(): void {
    this.stopHeartbeat()
    this.heartbeatTimer = setInterval(() => {
      this.send({ type: 'ping' })
    }, this.heartbeatInterval)
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.warn('[WebSocketService] 达到最大重连次数')
      return
    }

    this.reconnectAttempts++
    const delay = Math.min(this.reconnectInterval * this.reconnectAttempts, 60000)

    this.reconnectTimer = setTimeout(() => {
      this.connect()
    }, delay)
  }

  send(message: WebSocketMessage): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return false
    }
    try {
      this.ws.send(JSON.stringify(message))
      return true
    } catch {
      return false
    }
  }

  onRefresh(callback: () => void): () => void {
    this.refreshCallbacks.add(callback)
    return () => this.refreshCallbacks.delete(callback)
  }

  onMessage(callback: (msg: WebSocketMessage) => void): () => void {
    this.messageCallbacks.add(callback)
    return () => this.messageCallbacks.delete(callback)
  }

  setRefreshInterval(interval: number): void {
    this.send({ type: 'setRefreshInterval', data: { interval } })
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
    }
    this.stopHeartbeat()
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.isConnected = false
  }

  getStatus(): { isConnected: boolean; reconnectAttempts: number } {
    return {
      isConnected: this.isConnected,
      reconnectAttempts: this.reconnectAttempts
    }
  }
}

// 导出全局服务实例
export const wsService = WebSocketService.getInstance()
