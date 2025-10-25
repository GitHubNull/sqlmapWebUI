# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目架构

这是一个基于 FastAPI + Vue 3 的 SQLMap Web UI 应用，为安全研究人员提供 SQL 注入测试的 Web 界面。

### 整体结构
- **后端**: FastAPI 应用，位于 `src/backEnd/`
- **前端**: Vue 3 + TypeScript + PrimeVue 应用，位于 `src/frontEnd/`
- **SQLMap**: 作为第三方库集成在 `src/backEnd/third_lib/sqlmap/` 中
- **静态文件**: 前端构建后的静态文件存放在 `src/backEnd/static/`

### 后端架构 (FastAPI)
- `src/backEnd/main.py` - 主入口文件，配置 SQLMap 导入路径
- `src/backEnd/app.py` - FastAPI 应用核心，包含 CORS 配置、路由挂载
- `src/backEnd/api/` - API 路由模块
  - `chromeExApi/` - Chrome 扩展相关 API
  - `burpSuiteExApi/` - Burp Suite 扩展相关 API
  - `commonApi/` - 通用 API
- `src/backEnd/model/` - 数据模型定义
- `src/backEnd/service/` - 业务逻辑层
- `src/backEnd/utils/` - 工具函数和辅助模块

### 前端架构 (Vue 3)
- 使用 TypeScript + Pinia 状态管理
- PrimeVue UI 组件库
- Vite 构建工具，自动导入 Vue API 和组件
- 构建输出到后端的 `static` 目录

## 开发命令

### 后端开发
```bash
# 进入后端目录
cd src/backEnd

# 使用 uv 安装依赖
uv sync --extra thirdparty

# 启动开发服务器
uv run python main.py
```

### 前端开发
```bash
# 进入前端目录
cd src/frontEnd

# 安装依赖
pnpm install

# 启动开发服务器
pnpm run dev

# 构建生产版本
pnpm run build

# 预览构建结果
pnpm run preview
```

## 重要配置

### 开发环境端口
- 前端开发服务器: http://localhost:5173
- 后端 API 服务器: http://localhost:8775
- 前端代理配置: `/api` 请求会自动代理到后端

### 跨域配置
后端允许来自 `localhost:5173-5176` 和 `localhost:8775` 的跨域请求。

### 构建配置
- 前端构建输出到 `src/backEnd/static/`
- 启用 gzip 压缩
- 手动代码分割: vendor、primevue、utils

## 项目特性

### 导入路径系统
- 使用绝对导入，所有项目模块通过绝对路径导入
- SQLMap 作为第三方库，通过 `third_lib.sqlmap` 前缀访问
- 模块导入优先级在 `main.py` 中配置

### 前端开发便利性
- 自动导入 Vue API、Vue Router、Pinia
- 自动导入 PrimeVue 组件
- TypeScript 类型支持
- 开发时热重载和 API 代理

### 安全考虑
此项目为授权安全测试工具，仅用于:
- 渗透测试授权范围
- CTF 竞赛安全挑战
- 安全研究和教育目的
- 防御性安全评估

## 常见任务

### 添加新的 API 端点
1. 在 `src/backEnd/api/` 对应模块中创建路由
2. 在 `app.py` 中注册路由
3. 前端在 `src/frontEnd/src/api/` 中添加对应请求函数

### 添加新的前端页面
1. 在 `src/frontEnd/src/views/` 中创建页面组件
2. 在路由配置中添加新路由
3. 使用 PrimeVue 组件保持 UI 一致性

### 修改 SQLMap 集成
1. SQLMap 代码位于 `src/backEnd/third_lib/sqlmap/`
2. 注意保持与 SQLMap 主模块的兼容性
3. 通过 `utils/` 模块封装 SQLMap 调用逻辑