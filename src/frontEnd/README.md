# SqlmapWebUI 前端项目

基于Vue 3 + TypeScript + PrimeVue构建的SQL注入安全测试Web管理界面。

## 技术栈

- **框架**: Vue 3.5 (Composition API)
- **构建工具**: Vite 7
- **包管理器**: pnpm
- **语言**: TypeScript 5
- **UI组件库**: PrimeVue 4.4
- **图标库**: PrimeIcons 7.0
- **状态管理**: Pinia 3
- **路由**: Vue Router 4
- **HTTP客户端**: Axios 1.12
- **样式**: SCSS
- **工具库**: lodash-es, dayjs

## 项目特性

### 双模式认证
- **本地访问模式**: localhost/127.0.0.1自动跳过认证
- **远程访问模式**: 需要Token认证

### 核心功能
- 任务管理(创建、查看、停止、删除)
- 请求头规则管理
- 实时状态监控
- 主题切换(亮色/暗色)

### 构建优化
- 代码分割(vendor, primevue, utils)
- 路由懒加载
- 组件自动导入
- Gzip压缩
- 构建输出到后端静态目录

## 开发环境

### 安装依赖
```bash
cd src/frontEnd
pnpm install
```

### 启动开发服务器
```bash
pnpm dev
```
访问: http://localhost:5173

### 构建生产版本
```bash
pnpm build
```
输出目录: `src/backEnd/static`

### 预览生产构建
```bash
pnpm preview
```

## 项目结构

```
src/frontEnd/
├── src/
│   ├── api/              # API接口层
│   ├── assets/           # 静态资源
│   │   └── styles/       # 全局样式
│   ├── components/       # 公共组件
│   ├── composables/      # 组合式函数
│   ├── router/           # 路由配置
│   ├── stores/           # Pinia状态管理
│   ├── types/            # TypeScript类型
│   ├── utils/            # 工具函数
│   ├── views/            # 页面组件
│   ├── App.vue           # 根组件
│   ├── main.ts           # 应用入口
│   └── primevue.ts       # PrimeVue配置
├── public/               # 静态资源
├── .env.development      # 开发环境变量
├── .env.production       # 生产环境变量
├── vite.config.ts        # Vite配置
├── tsconfig.json         # TypeScript配置
└── package.json          # 项目配置
```

## 环境变量

### 开发环境 (.env.development)
- `VITE_API_BASE_URL`: http://localhost:8000/api
- `VITE_APP_TITLE`: SqlmapWebUI - 开发环境

### 生产环境 (.env.production)
- `VITE_API_BASE_URL`: /api
- `VITE_APP_TITLE`: SqlmapWebUI

## API接口

所有API请求通过代理转发到后端服务器:
- 开发环境: `/api` -> `http://localhost:8000/api`
- 生产环境: `/api` (同域部署)

## 部署说明

1. 构建前端项目: `pnpm build`
2. 构建产物自动输出到 `src/backEnd/static`
3. 后端FastAPI托管静态文件服务
4. 访问后端服务地址即可使用完整应用

## 开发指南

### 添加新页面
1. 在 `src/views/` 创建页面组件
2. 在 `src/router/index.ts` 添加路由配置
3. 在Layout侧边栏菜单添加入口

### 添加新API
1. 在 `src/types/` 定义类型
2. 在 `src/api/` 创建API模块
3. 在组件或Store中调用API

### 添加新Store
1. 在 `src/stores/` 创建Store文件
2. 使用Composition API风格定义状态和动作
3. 在 `src/stores/index.ts` 导出

## PrimeVue组件使用

项目已配置自动导入,直接在template中使用即可:
```vue
<template>
  <Button label="点击" icon="pi pi-check" />
  <DataTable :value="data" />
</template>
```

## 主题定制

在 `src/primevue.ts` 中配置PrimeVue主题:
```typescript
import Lara from '@primevue/themes/lara'
```

支持的主题: Lara, Saga, Material, Bootstrap等

## 图标使用

PrimeIcons提供250+图标:
```vue
<i class="pi pi-check"></i>
<Button icon="pi pi-search" />
```

图标列表: https://primevue.org/icons

## 注意事项

1. 本项目使用绝对导入(`@/`)代替相对导入
2. 所有API调用已封装统一的错误处理
3. 本地访问自动跳过认证,远程访问需要Token
4. 构建时会自动生成组件和API类型声明文件

## 许可证

MIT
