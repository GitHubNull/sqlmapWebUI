# SQLMap Web UI

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Vue-3.x-green.svg" alt="Vue">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-red.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

<p align="center">
  <b>中文</b> | <a href="README_EN.md">English</a>
</p>

一个现代化的 SQLMap Web 界面，为安全研究人员提供便捷的 SQL 注入测试平台。

## 功能特性

- **任务管理**: 创建、监控、停止 SQL 注入扫描任务
- **实时日志**: 查看任务执行的实时日志输出
- **扫描结果**: 直观展示注入点和 Payload 信息
- **HTTP 请求查看**: 完整展示原始 HTTP 请求信息
- **批量操作**: 支持批量导入和管理扫描任务
- **扩展集成**: 支持 Chrome 扩展和 Burp Suite 插件集成
- **请求头规则**: 灵活配置自定义请求头规则

## 技术栈

### 后端
- **FastAPI** - 高性能异步 Web 框架
- **SQLMap** - SQL 注入自动化检测工具
- **Python 3.10+** - 运行环境

### 前端
- **Vue 3** - 渐进式 JavaScript 框架
- **TypeScript** - 类型安全的 JavaScript
- **PrimeVue** - 企业级 UI 组件库
- **Pinia** - Vue 状态管理
- **Vite** - 下一代前端构建工具

## 快速开始

### 环境要求

- Python 3.10+
- Node.js 18+
- pnpm 包管理器

### 后端安装

```bash
# 进入后端目录
cd src/backEnd

# 使用 uv 安装依赖
uv sync --extra thirdparty

# 启动服务
uv run python main.py
```

### 前端安装

```bash
# 进入前端目录
cd src/frontEnd

# 安装依赖
pnpm install

# 开发模式
pnpm run dev

# 构建生产版本
pnpm run build
```

### 访问应用

- 前端开发服务器: http://localhost:5173
- 后端 API 服务器: http://localhost:8775

## 项目结构

```
sqlmapWebUI/
├── src/
│   ├── backEnd/                 # 后端代码
│   │   ├── api/                 # API 路由
│   │   │   ├── chromeExApi/     # Chrome 扩展 API
│   │   │   ├── burpSuiteExApi/  # Burp Suite API
│   │   │   └── commonApi/       # 通用 API
│   │   ├── model/               # 数据模型
│   │   ├── service/             # 业务逻辑
│   │   ├── utils/               # 工具函数
│   │   ├── third_lib/sqlmap/    # SQLMap 集成
│   │   ├── app.py               # FastAPI 应用
│   │   └── main.py              # 入口文件
│   └── frontEnd/                # 前端代码
│       ├── src/
│       │   ├── api/             # API 请求
│       │   ├── components/      # 公共组件
│       │   ├── stores/          # Pinia 状态
│       │   ├── types/           # TypeScript 类型
│       │   ├── utils/           # 工具函数
│       │   └── views/           # 页面视图
│       └── vite.config.ts       # Vite 配置
└── doc/                         # 项目文档
```

## 使用说明

### 创建扫描任务

1. 在任务列表页点击「新建任务」
2. 输入目标 URL 或导入 HTTP 请求
3. 配置扫描参数（可选）
4. 点击「开始扫描」

### 查看任务结果

1. 在任务列表中点击目标任务
2. 查看基础信息、HTTP 请求、扫描配置
3. 查看扫描结果和注入 Payload
4. 查看实时任务日志

### 扩展集成

#### Chrome 扩展
通过 Chrome 扩展可以直接将浏览器请求发送到扫描平台。

#### Burp Suite 插件
通过 Burp Suite 插件可以将拦截的请求发送到扫描平台。

## 安全声明

**重要**: 本工具仅供授权安全测试使用。

请在使用前阅读 [免责声明](DISCLAIMER.md)。

## 开源协议

本项目采用 [MIT 协议](LICENSE) 开源。

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 致谢

- [SQLMap](https://github.com/sqlmapproject/sqlmap) - 强大的 SQL 注入自动化工具
- [FastAPI](https://fastapi.tiangolo.com/) - 现代 Python Web 框架
- [Vue.js](https://vuejs.org/) - 渐进式 JavaScript 框架
- [PrimeVue](https://primevue.org/) - Vue UI 组件库
