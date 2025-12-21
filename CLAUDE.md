# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

SQLMap Web UI 是一个完整的 SQL 注入测试平台，包含：
- **主应用**: FastAPI + Vue 3 的 Web 界面
- **VulnShop 靶场**: 内置漏洞测试环境
- **浏览器扩展**: Chrome 扩展和 Burp Suite 插件

## 项目架构

### 整体结构
```
sqlmapWebUI/
├── src/
│   ├── backEnd/           # FastAPI 后端服务
│   ├── frontEnd/          # Vue 3 前端应用
│   ├── burpEx/            # Burp Suite 扩展插件
│   └── vulnTestServer/    # VulnShop 漏洞靶场
└── doc/                   # 项目文档
```

### 后端架构 (src/backEnd/)
- `main.py` - 主入口文件，配置 SQLMap 导入路径
- `app.py` - FastAPI 应用核心，包含 CORS 配置、路由挂载
- `config.py` - 版本号和全局配置
- `api/` - API 路由模块
  - `chromeExApi/` - Chrome 扩展相关 API
  - `burpSuiteExApi/` - Burp Suite 扩展相关 API
  - `commonApi/` - 通用 API
    - `headerController.py` - 请求头规则管理 API
    - `authController.py` - 认证 API
    - `configController.py` - 配置管理 API
- `model/` - 数据模型定义
  - `Task.py` - 任务模型
  - `HeaderScope.py` - 请求头作用域配置
  - `PersistentHeaderRule.py` - 持久化请求头规则
  - `SessionHeader.py` - 会话级请求头
  - `HeaderDatabase.py` - 请求头数据库操作
- `service/` - 业务逻辑层
  - `taskService.py` - 任务管理服务
  - `headerRuleService.py` - 请求头规则服务（单例模式）
- `utils/` - 工具函数
  - `header_processor.py` - 请求头处理器
  - `scope_matcher.py` - 作用域匹配器
  - `task_monitor.py` - 任务监控
- `third_lib/sqlmap/` - SQLMap 第三方库集成

### 前端架构 (src/frontEnd/)
- 使用 TypeScript + Pinia 状态管理
- PrimeVue UI 组件库，支持亮色/暗色主题
- Vite 构建工具，自动导入 Vue API 和组件
- 构建输出到后端的 `static` 目录

主要视图：
- `views/Home/` - 首页仪表盘，显示任务统计
- `views/TaskList/` - 任务列表，支持过滤/排序/批量操作
- `views/TaskDetail/` - 任务详情，显示日志/结果/配置
- `views/AddTask/` - 添加扫描任务页面
- `views/Config/` - 配置页面（Tab 布局）
  - 系统配置
  - Header 规则管理
  - 会话 Header 管理
  - 扫描配置管理（默认配置/常用配置/历史配置）

关键组件：
- `components/TaskFilter.vue` - 任务过滤器
- `components/TaskSummary.vue` - 任务汇总统计
- `components/ScopeConfigPanel.vue` - 作用域配置面板
- `components/HttpCodeEditor.vue` - 代码编辑器（行号、语法高亮）
- `components/GuidedParamEditor.vue` - 引导式参数编辑器

状态管理：
- `stores/task.ts` - 任务状态，包含过滤、排序、统计计算
- `stores/config.ts` - 配置状态
- `stores/scanPreset.ts` - 扫描配置预设状态

### VulnShop 靶场 (src/vulnTestServer/)
独立的漏洞测试环境，包含：
- `server.py` - Python HTTP 服务器，处理所有 API 请求
- `database.py` - SQLite 数据库管理，包含漏洞 SQL 查询
- `waf.py` - WAF 模块，支持 3 种难度级别
- `config.py` - 配置文件（端口、难度等）
- `static/` - 前端静态资源

**支持的漏洞类型**:
- Error-based (POST /api/user/login)
- Union-based (GET /api/user/profile)
- Boolean-blind (GET /api/products/search)
- Time-based (GET /api/products/detail)
- Stacked Queries (GET /api/orders/query)
- Second-order (POST /api/user/register)

### Burp Suite 扩展 (src/burpEx/)
- `legacy-api/` - 传统 Burp API (Java 11)
- `montoya-api/` - Montoya API (Java 17, Burp 2023.1+)

功能：右键菜单发送请求、配置管理、活动日志

## 核心功能

### 任务管理
- 创建/监控/停止 SQL 注入扫描任务
- 实时日志查看
- 批量操作（批量停止、批量删除、清空全部）
- 多维度过滤（URL、报文、状态、日期范围、注入状态）
- 多字段排序
- 汇总统计行
- 智能轮询（根据任务状态调整刷新频率）

### 扫描配置管理
- **默认配置**: 全局默认扫描参数
- **常用配置**: 保存的配置组合，支持 CRUD
- **历史配置**: 历史扫描配置记录
- **引导式编辑器**: 可视化配置 SQLMap 参数
- **参数预览**: 实时预览命令行参数

### HTTP 请求解析
- 多格式解析支持：
  - cURL (Bash/CMD)
  - PowerShell Invoke-WebRequest
  - JavaScript fetch
  - 原始 HTTP 报文
- 智能格式检测
- 代码编辑器（行号、语法高亮、搜索）

### 请求头规则管理
- **持久化规则**: 存储在数据库的长期规则
  - 完整 CRUD 操作
  - 优先级排序 (0-100)
  - 多种替换策略
- **会话级规则**: 带 TTL 的临时规则
- **作用域配置**: 可选的 URL 匹配规则
  - 协议匹配 (http/https)
  - 主机名匹配（支持通配符）
  - 端口匹配（支持多值）
  - 路径匹配（支持通配符）
  - 正则表达式支持
- **批量导入**: 从文本批量导入请求头

## 开发命令

### 后端开发
```bash
cd src/backEnd
uv sync --extra thirdparty
uv run python main.py
```

### 前端开发
```bash
cd src/frontEnd
pnpm install
pnpm run dev      # 开发模式
pnpm run build    # 构建生产版本
```

### VulnShop 靶场
```bash
cd src/vulnTestServer
pip install flask
python server.py
```

### Burp Suite 插件构建
```bash
cd src/burpEx/montoya-api  # 或 legacy-api
mvn clean package -DskipTests
```

## 重要配置

### 服务端口
| 服务 | 端口 | 说明 |
|------|------|------|
| 前端开发服务器 | 5173 | Vite 开发服务器 |
| 后端 API 服务器 | 8775 | FastAPI 服务 |
| VulnShop 靶场 | 9527 | 漏洞测试环境 |

### 跨域配置
后端允许来自 `localhost:5173-5176` 和 `localhost:8775` 的跨域请求。

### 构建配置
- 前端构建输出到 `src/backEnd/static/`
- 启用 gzip 压缩
- 手动代码分割: vendor、primevue、utils

### 数据库
- 任务数据存储在内存（DataStore 单例）
- 请求头规则存储在 SQLite (`header_rules.db`)
- 自动数据库迁移（schema 变更时自动添加新列）

## 主题系统

### 前端 (Vue 3 + PrimeVue)
- 使用 PrimeVue 主题系统
- 支持亮色/暗色模式切换
- 主题配置在 `src/frontEnd/src/primevue.ts`

### VulnShop 靶场
- 使用 CSS 变量实现主题
- 默认亮色主题，支持切换到暗色
- 主题状态保存在 localStorage
- CSS 变量定义在 `:root` 和 `[data-theme="dark"]`

## 常见任务

### 添加新的 API 端点
1. 在 `src/backEnd/api/` 对应模块中创建路由
2. 在 `app.py` 中注册路由
3. 前端在 `src/frontEnd/src/api/` 中添加对应请求函数
4. 更新 TypeScript 类型定义

### 添加新的前端页面
1. 在 `src/frontEnd/src/views/` 中创建页面组件
2. 在路由配置中添加新路由
3. 使用 PrimeVue 组件保持 UI 一致性
4. 在 Pinia store 中添加状态管理

### 添加带作用域的请求头规则
1. 后端：规则包含 scope 字段（可选，null = 全局）
2. 前端：使用 ScopeConfigPanel 组件
3. 作用域支持：协议、主机、端口、路径模式
4. 匹配逻辑：所有配置字段使用 AND 逻辑

### 修改 SQLMap 集成
1. SQLMap 代码位于 `src/backEnd/third_lib/sqlmap/`
2. 注意保持与 SQLMap 主模块的兼容性
3. 通过 `utils/` 模块封装 SQLMap 调用逻辑

### 修改 VulnShop 靶场
1. 后端逻辑在 `server.py` 的路由处理函数中
2. 数据库操作在 `database.py`
3. 前端样式修改 `static/css/style.css`
4. 前端逻辑修改 `static/js/app.js`
5. 添加新主题样式需同时处理亮色和暗色模式

### 构建 Burp Suite 插件
1. 选择对应 API 版本目录
2. 运行 `mvn clean package -DskipTests`
3. 生成的 JAR 文件在 `target/` 目录

## 测试

### 后端测试
```bash
cd src/backEnd
python -m pytest tests/
```

测试文件：
- `test_scope_matcher.py` - 作用域匹配测试
- `test_header_processor_scope.py` - 请求头处理器测试
- `test_api_endpoints.py` - API 端点测试

## 安全考虑

此项目为授权安全测试工具，仅用于:
- 渗透测试授权范围
- CTF 竞赛安全挑战
- 安全研究和教育目的
- 防御性安全评估

VulnShop 靶场仅绑定 127.0.0.1，禁止暴露到公网。

## Git 工作流

- 代码变更需提交至 Git 仓库并打上版本标签
- 使用 `git push origin --tags` 同步标签到远程
- 遵循语义化版本号规范

### 提交信息格式
```
feat: 新功能
fix: 修复 bug
perf: 性能优化
refactor: 代码重构
docs: 文档更新
test: 测试相关
chore: 构建/维护
ci: CI/CD 变更
```

### 发布流程
1. 更新 `config.py` 中的 VERSION
2. 提交代码：`git add . && git commit -m "..."`
3. 创建标签：`git tag release-v1.x.x`
4. 推送：`git push origin master && git push origin --tags`
5. GitHub Actions 自动构建和发布
