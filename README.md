# SQLMap Web UI

<p align="center">
  <img src="src/frontEnd/public/logo.svg" alt="SQLMap WebUI Logo" width="120" height="120">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Vue-3.x-green.svg" alt="Vue">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-red.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.8.53-orange.svg" alt="Version">
</p>

<p align="center">
  <b>中文</b> | <a href="README_EN.md">English</a>
</p>

<p align="center">
  <a href="doc/USAGE_GUIDE.md">📖 使用指南</a> | 
  <a href="doc/USAGE_GUIDE_EN.md">📖 English Guide</a> | 
  <a href="#-快速开始">🚀 快速开始</a> | 
  <a href="#-更新日志">📝 更新日志</a>
</p>

一个现代化的 SQLMap Web 界面，为安全研究人员提供便捷的 SQL 注入测试平台。**内置 VulnShop 靶场**，开箱即用。

## 🌟 核心功能

### SQL 注入扫描平台
- **任务管理**: 创建、监控、停止 SQL 注入扫描任务
- **实时日志**: 查看任务执行的实时日志输出
- **扫描结果**: 直观展示注入点和 Payload 信息
- **HTTP 请求查看**: 完整展示原始 HTTP 请求信息
- **任务列表增强**:
  - 多维度过滤（URL/报文关键字、状态、日期范围、注入状态）
  - 多字段排序（任务ID、状态、创建时间）
  - 汇总统计行（实时显示任务统计数据）
  - 智能轮询（根据任务状态自动调整刷新频率）

### 扫描配置管理 🆕
- **默认配置**: 设置全局默认扫描参数
- **常用配置**: 保存常用配置组合，支持 CRUD 操作
- **历史配置**: 查看历史扫描使用过的配置
- **引导式编辑器**: 可视化配置 SQLMap 参数，无需记忆命令行
- **参数预览**: 实时预览生成的命令行参数

### HTTP 请求解析 🆕
- 支持多种请求格式自动解析：
  - cURL (Bash/CMD)
  - PowerShell Invoke-WebRequest
  - JavaScript fetch
  - 原始 HTTP 报文
- **智能格式检测**: 自动识别输入格式
- **代码编辑器**: 行号显示、语法高亮、搜索过滤

### 批量操作
- **批量停止**: 一键停止多个运行中的任务
- **批量删除**: 批量删除已完成或失败的任务
- **批量导入**: 支持批量导入 HTTP 请求创建扫描任务
- **全选/反选**: 便捷的任务选择操作

### 请求头规则管理
- **持久化规则**: 创建长期有效的请求头规则，支持 CRUD 完整操作
- **会话级规则**: 设置临时请求头，支持 TTL 自动过期
- **作用域配置**: 灵活的 URL 匹配规则
  - 协议匹配（http/https）
  - 主机名匹配（支持通配符 `*.example.com`）
  - 端口匹配（支持多端口 `80,443,8080`）
  - 路径匹配（支持通配符 `/api/*`）
  - 正则表达式匹配
- **优先级控制**: 支持 0-100 优先级设置
- **替换策略**: 完全替换、追加、条件替换等多种策略
- **批量导入**: 支持从文本批量导入请求头

### 扩展集成
- **Burp Suite 插件**: 支持 Legacy API 和 Montoya API 两种版本
  - 右键菜单快速发送请求到后端服务器
  - 右键菜单直接执行 SQLMap 扫描（本地终端执行）
  - 可配置扫描参数（Level、Risk、DBMS、Technique）
  - 支持默认配置和常用配置管理
  - 命令预览和复制到剪贴板
  - 终端窗口标题自定义规则
  - 配置导入导出功能
  - 活动日志记录

### VulnShop 漏洞靶场 🎯
内置模拟电商平台，包含 8 种 SQL 注入漏洞类型：

| 漏洞类型 | 接口 | 说明 |
|---------|------|------|
| Error-based | POST /api/user/login | 基于错误的注入 |
| Union-based | GET /api/user/profile | 联合查询注入 |
| Boolean-blind | GET /api/products/search | 布尔盲注 |
| Time-based | GET /api/products/detail | 时间盲注 |
| Stacked Queries | GET /api/orders/query | 堆叠查询注入 |
| 2nd Order | POST /api/user/register | 二次注入 |

**靶场特性**:
- 🎨 现代化 UI，支持亮色/暗色主题切换
- 🛒 完整购物流程：浏览商品、购物车、下单结算
- ⚙️ 3 种难度级别（Easy/Medium/Hard）配合 WAF 防护
- 🔄 一键重置数据库
- 📱 针对 PC 端 Chrome 浏览器优化

## 技术栈

### 后端
- **FastAPI** - 高性能异步 Web 框架
- **SQLMap** - SQL 注入自动化检测工具
- **Python 3.10+** - 运行环境
- **SQLite** - 数据库存储
- **uv** - 现代 Python 包管理器

### 前端
- **Vue 3** - 渐进式 JavaScript 框架
- **TypeScript** - 类型安全的 JavaScript
- **PrimeVue** - 企业级 UI 组件库
- **Pinia** - Vue 状态管理
- **Vite** - 下一代前端构建工具

### 扩展
- **Burp Suite 插件**
  - Montoya API (Java 17+, Burp 2023.1+)
  - Legacy API (Java 11+)

## 🚀 快速开始

### 环境要求

- Python 3.10+
- Node.js 20+
- pnpm 9+
- Java 17+ (Burp Montoya API) 或 Java 11+ (Legacy API)

### 后端安装

#### 方式一：使用启动脚本（推荐）

```batch
# Windows
cd src\backEnd
start.bat

# Linux/macOS
cd src/backEnd && chmod +x start.sh && ./start.sh
```

启动脚本支持配置镜像源、内网环境、离线模式等，详见 `startup.conf`。

#### 方式二：手动启动

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

### 启动 VulnShop 靶场

```bash
# 进入靶场目录
cd src/vulnTestServer

# 安装依赖（如未安装）
pip install flask

# 启动服务
python server.py
```

### 访问应用

| 服务 | 地址 |
|------|------|
| 前端开发服务器 | http://localhost:5173 |
| 后端 API 服务器 | http://localhost:8775 |
| VulnShop 靶场 | http://127.0.0.1:9527 |

## 📁 项目结构

```
sqlmapWebUI/
├── src/
│   ├── backEnd/                 # 后端代码
│   │   ├── api/                 # API 路由
│   │   │   ├── webApi/          # Web 浏览器页面 API
│   │   │   ├── burpSuiteExApi/  # Burp Suite API
│   │   │   └── commonApi/       # 通用 API (认证/请求头规则/配置)
│   │   ├── model/               # 数据模型
│   │   ├── service/             # 业务逻辑
│   │   ├── utils/               # 工具函数
│   │   ├── third_lib/sqlmap/    # SQLMap 集成
│   │   ├── app.py               # FastAPI 应用
│   │   └── main.py              # 入口文件
│   ├── frontEnd/                # 前端代码
│   │   ├── src/
│   │   │   ├── api/             # API 请求
│   │   │   ├── components/      # 公共组件
│   │   │   ├── stores/          # Pinia 状态
│   │   │   ├── types/           # TypeScript 类型
│   │   │   ├── utils/           # 工具函数
│   │   │   └── views/           # 页面视图
│   │   └── vite.config.ts       # Vite 配置
│   ├── burpEx/                  # Burp Suite 扩展
│   │   ├── legacy-api/          # 传统 API (Java 11)
│   │   └── montoya-api/         # Montoya API (Java 17)
│   └── vulnTestServer/          # VulnShop 漏洞靶场
│       ├── static/              # 前端静态资源
│       ├── server.py            # HTTP 服务器
│       ├── database.py          # 数据库管理
│       └── waf.py               # WAF 模块
└── doc/                         # 项目文档
```

## 📖 使用说明

### 创建扫描任务

1. 在任务列表页点击「新建任务」
2. 输入目标 URL 或导入 HTTP 请求
3. 配置扫描参数（可选）
4. 点击「开始扫描」

### 使用 VulnShop 靶场

1. 启动靶场服务 `python server.py`
2. 浏览器访问 http://127.0.0.1:9527
3. 使用测试账户登录（admin/admin123 或 test/test）
4. 根据页面提示测试各种注入类型

### Burp Suite 集成

1. 构建插件: `mvn clean package -DskipTests`
2. 在 Burp Suite 中加载 JAR 文件
3. 配置后端服务器地址
4. 右键请求选择 "Send to SQLMap WebUI"

### 请求头规则配置

1. 进入「配置」→「Header 规则管理」标签页
2. 点击「添加规则」
3. 填写规则信息：
   - 规则名称、Header 名称、Header 值
   - 替换策略、优先级
   - 可选：配置作用域限定生效范围
4. 保存规则

### 系统日志查看器

1. 进入「配置」页面
2. 找到「系统日志查看器」入口
3. 选择日志类型（应用/访问/错误）
4. 设置显示行数并刷新查看

---

**📚 详细使用说明请参阅 [使用指南文档](doc/USAGE_GUIDE.md)**

包含完整的功能说明、操作步骤、配置指南和常见问题解答。

## 🔐 安全声明

**重要**: 本工具仅供授权安全测试使用。

- 仅在获得明确授权的系统上进行测试
- 不要在生产环境或未授权系统上使用
- VulnShop 靶场仅绑定本地地址，禁止暴露到公网

请在使用前阅读 [免责声明](DISCLAIMER.md)。

## 📝 更新日志

> **重要说明**: 完整的版本更新记录已移至独立文档 [CHANGELOG.md](doc/CHANGELOG.md)。
>
> 所有后续版本更新记录均在该文档中维护，本 README 不再重复收录详细变更日志。

**最新版本**: v1.8.54 (2026-04-16)

- 新增优惠券系统，支持 Base64 编码参数的 SQL 注入测试场景
- 新增会员中心、评价中心弹窗功能
- 修复侧边栏菜单项重复显示问题

**查看完整变更日志**: [CHANGELOG.md](doc/CHANGELOG.md) | [English Changelog](doc/CHANGELOG_EN.md)


## 📄 开源协议

本项目采用 [MIT 协议](LICENSE) 开源。

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 🙏 致谢

- [SQLMap](https://github.com/sqlmapproject/sqlmap) - 强大的 SQL 注入自动化工具
- [FastAPI](https://fastapi.tiangolo.com/) - 现代 Python Web 框架
- [Vue.js](https://vuejs.org/) - 渐进式 JavaScript 框架
- [PrimeVue](https://primevue.org/) - Vue UI 组件库
