/**
 * Vue Router配置
 */
import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { setupRouterGuards } from './guards'

// 路由配置
const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'layout',
    component: () => import('@/views/Layout.vue'),
    redirect: '/home',
    meta: { requiresAuth: true },
    children: [
      {
        path: '/home',
        name: 'home',
        component: () => import('@/views/Home/index.vue'),
        meta: { requiresAuth: true, title: '首页' },
      },
      {
        path: '/tasks',
        name: 'taskList',
        component: () => import('@/views/TaskList/index.vue'),
        meta: { requiresAuth: true, title: '任务列表' },
      },
      {
        path: '/tasks/:id',
        name: 'taskDetail',
        component: () => import('@/views/TaskDetail/index.vue'),
        meta: { requiresAuth: true, title: '任务详情' },
      },
      {
        path: '/config',
        name: 'config',
        component: () => import('@/views/Config/index.vue'),
        meta: { requiresAuth: true, title: '配置管理' },
      },
      {
        path: '/add-task',
        name: 'addTask',
        component: () => import('@/views/AddTask/index.vue'),
        meta: { requiresAuth: true, title: '添加任务' },
      },
      {
        path: '/about',
        name: 'about',
        component: () => import('@/views/About/index.vue'),
        meta: { requiresAuth: true, title: '关于' },
      },
    ],
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/Login/index.vue'),
    meta: { requiresAuth: false, title: '登录' },
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/home',
  },
]

// 创建路由实例
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

// 设置路由守卫
setupRouterGuards(router)

export default router
