# SQLMap WebUI 前端

基于 Vue 3 + TypeScript + PrimeVue 构建的 SQL 注入安全测试 Web 管理界面。

## 技术栈

| 类别 | 技术 | 版本 |
|------|------|------|
| 框架 | Vue | 3.5+ |
| 构建工具 | Vite | 7+ |
| 包管理器 | pnpm | 9+ |
| 语言 | TypeScript | 5+ |
| UI组件库 | PrimeVue | 4.4+ |
| 图标库 | PrimeIcons | 7.0+ |
| 状态管理 | Pinia | 3+ |
| 路由 | Vue Router | 4+ |
| HTTP客户端 | Axios | 1.12+ |
| 样式 | SCSS | - |

## 核心功能

### 任务管理
- 创建/查看/停止/删除扫描任务
- **多维度过滤**: URL关键字、报文关键字、状态、日期范围、注入状态
- **多字段排序**: 任务ID、状态、创建时间
- **批量操作**: 批量停止、批量删除、删除全部
- **汇总统计行**: 实时显示任务统计数据
- **智能轮询**: 根据任务状态自动调整刷新频率

### 扫描配置管理
- **默认配置**: 全局默认扫描参数
- **常用配置**: 保存常用配置组合，支持 CRUD
- **历史配置**: 历史扫描使用的配置记录
- **引导式编辑器**: 可视化配置 SQLMap 参数
- **参数预览**: 实时预览生成的命令行参数

### HTTP 请求解析
- **多格式支持**: cURL/PowerShell/fetch/原始 HTTP
- **智能格式检测**: 自动识别输入格式
- **代码编辑器**: 行号显示、语法高亮、搜索过滤

### 请求头规则管理
- **持久化规则**: 创建/编辑/删除长期有效的请求头规则
- **会话级规则**: 临时请求头，支持 TTL 自动过期
- **作用域配置**: 协议/主机名/端口/路径匹配，支持通配符和正则
- **优先级控制**: 0-100 优先级设置
- **批量导入**: 从文本批量导入请求头

### 双模式认证
- **本地访问模式**: localhost/127.0.0.1 自动跳过认证
- **远程访问模式**: 需要 Token 认证

### 主题系统
- 支持亮色/暗色主题切换
- 使用 PrimeVue 主题系统

### 构建优化
- 代码分割 (vendor, primevue, utils)
- 路由懒加载
- 组件自动导入
- Gzip 压缩
- 构建输出到后端静态目录

## 快速开始

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
│   ├── api/              # API 接口层
│   │   ├── task.ts       # 任务管理 API
│   │   ├── headerRule.ts # 请求头规则 API
│   │   └── ...
│   ├── assets/           # 静态资源
│   │   └── styles/       # 全局样式 (SCSS)
│   ├── components/       # 公共组件
│   │   ├── TaskFilter.vue      # 任务过滤器
│   │   ├── TaskSummary.vue     # 任务汇总统计
│   │   ├── ScopeConfigPanel.vue # 作用域配置面板
│   │   ├── HttpCodeEditor.vue  # 代码编辑器（行号、语法高亮）
│   │   └── GuidedParamEditor.vue # 引导式参数编辑器
│   ├── router/           # 路由配置
│   ├── stores/           # Pinia 状态管理
│   │   ├── task.ts       # 任务状态 (含过滤/排序/统计)
│   │   ├── config.ts     # 配置状态
│   │   └── scanPreset.ts # 扫描配置预设状态
│   ├── types/            # TypeScript 类型定义
│   │   ├── task.ts       # 任务相关类型
│   │   ├── headerRule.ts # 请求头规则类型
│   │   └── scanPreset.ts # 扫描配置预设类型
│   ├── utils/            # 工具函数
│   │   └── httpRequestParser/ # HTTP请求解析器（模块化）
│   │       ├── parsers/   # 格式解析器
│   │       ├── formatters/ # 格式化器
│   │       └── index.ts  # 统一入口
│   ├── views/            # 页面组件
│   │   ├── Home/         # 首页仪表盘
│   │   ├── TaskList/     # 任务列表页
│   │   ├── TaskDetail/   # 任务详情页
│   │   ├── AddTask/      # 添加扫描任务页
│   │   └── Config/       # 配置页面 (Tab 布局)
│   ├── App.vue           # 根组件
│   ├── main.ts           # 应用入口
│   └── primevue.ts       # PrimeVue 配置
├── public/               # 静态资源
├── .env.development      # 开发环境变量
├── .env.production       # 生产环境变量
├── vite.config.ts        # Vite 配置
├── tsconfig.json         # TypeScript 配置
└── package.json          # 项目配置
```

## 页面说明

### 首页仪表盘
- 任务状态统计卡片（总数/运行中/等待中/完成/失败/停止/终止）
- 注入结果统计卡片（可注入/不可注入）
- 点击卡片快速跳转到对应过滤的任务列表

### 任务列表页
- DataTable 展示任务列表
- 过滤面板（多条件组合）
- 排序功能（点击列头）
- 批量操作栏
- 汇总统计行

### 任务详情页
- 基础信息 Tab
- HTTP 请求 Tab
- 扫描配置 Tab
- 扫描结果 Tab
- 实时日志 Tab

### 配置页面
- **系统配置 Tab**: 自动刷新间隔设置
- **Header 规则管理 Tab**: 持久化规则 CRUD
- **会话 Header 管理 Tab**: 临时规则管理
- **扫描配置管理 Tab**: 默认配置/常用配置/历史配置

### 添加扫描任务页
- HTTP 请求输入（支持多格式解析）
- 代码编辑器（行号、语法高亮）
- 扫描配置选择（默认/常用/历史）
- 引导式参数编辑

## 环境变量

### 开发环境 (.env.development)
```
VITE_API_BASE_URL=http://localhost:8775/api
VITE_APP_TITLE=SqlmapWebUI - 开发环境
```

### 生产环境 (.env.production)
```
VITE_API_BASE_URL=/api
VITE_APP_TITLE=SqlmapWebUI
```

## 开发指南

### 添加新页面
1. 在 `src/views/` 创建页面组件
2. 在 `src/router/index.ts` 添加路由配置
3. 在 Layout 侧边栏菜单添加入口

### 添加新 API
1. 在 `src/types/` 定义类型
2. 在 `src/api/` 创建 API 模块
3. 在组件或 Store 中调用 API

### 添加新 Store
1. 在 `src/stores/` 创建 Store 文件
2. 使用 Composition API 风格定义状态和动作
3. 在组件中使用 `useXxxStore()`

## PrimeVue 组件

项目已配置自动导入，直接在 template 中使用即可：
```vue
<template>
  <Button label="点击" icon="pi pi-check" />
  <DataTable :value="data" />
</template>
```

## 部署说明

1. 构建前端项目: `pnpm build`
2. 构建产物自动输出到 `src/backEnd/static`
3. 后端 FastAPI 托管静态文件服务
4. 访问后端服务地址即可使用完整应用

## 许可证

MIT
