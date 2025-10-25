/**
 * 路由守卫配置
 * 支持本地/远程双模式认证
 */
import type { NavigationGuardNext, RouteLocationNormalized } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

/**
 * 全局前置守卫
 */
export function setupRouterGuards(router: any) {
  router.beforeEach((
    to: RouteLocationNormalized,
    _from: RouteLocationNormalized,
    next: NavigationGuardNext
  ) => {
    const authStore = useAuthStore()
    
    // 本地访问模式:直接允许访问
    if (authStore.isLocalMode) {
      // 如果是登录页,重定向到首页
      if (to.path === '/login') {
        next({ path: '/' })
        return
      }
      next()
      return
    }
    
    // 远程访问模式:检查认证
    const requiresAuth = to.meta.requiresAuth !== false
    
    if (requiresAuth && !authStore.isLoggedIn) {
      // 需要认证但未登录,跳转到登录页
      next({
        path: '/login',
        query: { redirect: to.fullPath }, // 保存原始路由
      })
    } else if (to.path === '/login' && authStore.isLoggedIn) {
      // 已登录用户访问登录页,重定向到首页
      next({ path: '/' })
    } else {
      next()
    }
  })
}
