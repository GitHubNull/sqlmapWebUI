# SQLMap Web UI 使用指南

本文档详细介绍 SQLMap Web UI 的完整使用方法，包括主应用、VulnShop 靶场和扩展插件。

## 目录

- [1. 系统概述](#1-系统概述)
- [2. 安装部署](#2-安装部署)
- [3. 主应用使用](#3-主应用使用)
- [4. VulnShop 靶场使用](#4-vulnshop-靶场使用)
- [5. 扩展插件使用](#5-扩展插件使用)
- [6. 高级功能](#6-高级功能)
- [7. 常见问题](#7-常见问题)

---

## 1. 系统概述

SQLMap Web UI 是一个完整的 SQL 注入测试平台，包含三个主要组件：

| 组件 | 说明 | 端口 |
|------|------|------|
| Web 应用 | SQL 注入扫描任务管理界面 | 8775 (后端) / 5173 (前端开发) |
| VulnShop 靶场 | 内置漏洞测试环境 | 9527 |
| 扩展插件 | Chrome 扩展 / Burp Suite 插件 | - |

### 系统要求

- **操作系统**: Windows / Linux / macOS
- **Python**: 3.10+
- **Node.js**: 18+ (前端开发)
- **Java**: 11+ (Burp Suite Legacy API) 或 17+ (Montoya API)
- **浏览器**: Chrome (推荐)

---

## 2. 安装部署

### 2.1 后端服务

```bash
# 进入后端目录
cd src/backEnd

# 安装依赖 (使用 uv 包管理器)
uv sync --extra thirdparty

# 启动服务
uv run python main.py
```

服务启动后访问: http://localhost:8775

### 2.2 前端应用

```bash
# 进入前端目录
cd src/frontEnd

# 安装依赖
pnpm install

# 开发模式运行
pnpm run dev

# 或构建生产版本
pnpm run build
```

开发模式访问: http://localhost:5173

### 2.3 VulnShop 靶场

```bash
# 进入靶场目录
cd src/vulnTestServer

# 启动服务
python server.py
```

靶场访问: http://127.0.0.1:9527

---

## 3. 主应用使用

### 3.1 创建扫描任务

1. 进入任务列表页面
2. 点击「新建任务」按钮
3. 填写任务信息：
   - **目标 URL**: 待测试的 URL 地址
   - **HTTP 请求**: 可直接粘贴完整的 HTTP 请求
   - **扫描参数**: Level、Risk、DBMS 等
4. 点击「开始扫描」

### 3.2 查看任务结果

在任务详情页可以查看：

- **基础信息**: 任务状态、创建时间、目标地址
- **HTTP 请求**: 原始请求内容
- **扫描配置**: SQLMap 参数配置
- **扫描结果**: 发现的注入点和 Payload
- **实时日志**: 任务执行日志

### 3.3 批量任务管理

- 支持批量导入 HTTP 请求
- 支持批量启动/停止任务
- 支持任务列表筛选和排序

### 3.4 请求头规则配置

1. 进入「Header 配置」页面
2. 添加请求头规则：
   - **规则名称**: 便于识别的名称
   - **Header 名称**: 如 Authorization、Cookie
   - **Header 值**: 对应的值
   - **作用域**: URL 匹配模式
3. 规则会自动应用到匹配的扫描请求

---

## 4. VulnShop 靶场使用

### 4.1 靶场介绍

VulnShop 是一个模拟电商平台的 SQL 注入靶场，专门设计用于：
- 学习各种 SQL 注入技术
- 测试 SQLMap 等安全工具
- 安全培训和 CTF 练习

### 4.2 测试账户

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| test | test | 普通用户 |
| alice | alice123 | 普通用户 |

### 4.3 漏洞类型

#### Error-based 注入
- **接口**: POST /api/user/login
- **参数**: username, password
- **示例**:
```
username: admin' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
password: x
```

#### Union-based 注入
- **接口**: GET /api/user/profile
- **参数**: id
- **示例**:
```
GET /api/user/profile?id=1 UNION SELECT 1,flag,description,4,5,6 FROM secrets--
```

#### Boolean-blind 注入
- **接口**: GET /api/products/search
- **参数**: keyword
- **示例**:
```
GET /api/products/search?keyword=test' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a'--
```

#### Time-based 注入
- **接口**: GET /api/products/detail
- **参数**: id
- **示例**:
```
GET /api/products/detail?id=1 AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)
```

#### Stacked Queries 注入
- **接口**: GET /api/orders/query
- **参数**: order_no, user_id
- **示例**:
```
GET /api/orders/query?order_no=ORD001'; INSERT INTO users(username,password,email) VALUES('hacker','pwned','h@h.com');--
```

#### Second-order 注入
- **接口**: POST /api/user/register
- **参数**: username, password, email
- **说明**: 注册包含恶意 SQL 的用户名，在其他位置触发

### 4.4 难度级别

| 级别 | WAF 防护 | 绕过方法 |
|------|----------|----------|
| Easy | 无防护 | 直接注入 |
| Medium | 简单过滤 | 大小写混合、URL 编码 |
| Hard | 严格过滤 | 高级绕过技术 |

切换难度：在「系统配置」页面选择难度级别

### 4.5 主题切换

靶场支持亮色和暗色两种主题：
- 点击导航栏右侧的主题切换按钮（☀️/🌙）
- 主题选择会自动保存

### 4.6 数据库重置

如需恢复初始数据：
1. Web 界面：「系统配置」→「重置数据库」
2. 命令行：`python database.py`

---

## 5. 扩展插件使用

### 5.1 Burp Suite 插件

#### 安装步骤

1. 构建插件：
```bash
cd src/burpEx/montoya-api  # Burp 2023.1+ 使用
# 或
cd src/burpEx/legacy-api   # 旧版本 Burp 使用

mvn clean package -DskipTests
```

2. 在 Burp Suite 中加载：
   - 进入 Extender → Extensions
   - 点击 Add 按钮
   - 选择生成的 JAR 文件

#### 使用方法

1. **配置服务器**:
   - 在插件的「服务器配置」标签页
   - 设置后端 URL: http://localhost:8775
   - 点击「测试连接」验证

2. **发送请求**:
   - 在 Burp 中拦截或查看请求
   - 右键选择 "Send to SQLMap WebUI"
   - 或选择 "Send to SQLMap WebUI (选择配置)..." 自定义参数

3. **配置管理**:
   - 「默认配置」: 设置默认扫描参数
   - 「常用配置」: 保存常用配置组合

#### 扫描参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| Level | 检测级别 (1-5) | 1 |
| Risk | 风险级别 (1-3) | 1 |
| DBMS | 数据库类型 | 自动检测 |
| Technique | 注入技术 | BEUSTQ (全部) |

### 5.2 Chrome 扩展

1. 加载扩展到 Chrome
2. 配置后端服务器地址
3. 在目标页面右键选择发送请求

---

## 6. 高级功能

### 6.1 请求头作用域

支持配置请求头规则的作用域：
- **精确匹配**: `https://example.com/api/user`
- **前缀匹配**: `https://example.com/api/*`
- **域名匹配**: `*.example.com`
- **正则匹配**: `regex:https?://.*\.example\.com/.*`

### 6.2 批量导入

支持批量导入 HTTP 请求：
1. 准备请求文件（每个请求以空行分隔）
2. 使用导入功能上传文件
3. 批量创建扫描任务

### 6.3 自定义 SQLMap 参数

在任务创建时可配置所有 SQLMap 参数：
- 检测参数: level, risk, technique
- 目标参数: dbms, os, tamper
- 注入参数: prefix, suffix, string
- 输出参数: dump, dump-all, passwords

---

## 7. 常见问题

### Q: 后端服务启动失败？
A: 检查 Python 版本（需要 3.10+），确保依赖安装完整。

### Q: 前端无法连接后端？
A: 检查跨域配置，确保后端服务正在运行。

### Q: VulnShop 靶场无法访问？
A: 确保端口 9527 未被占用，使用 127.0.0.1 而非 localhost。

### Q: Burp Suite 插件无法发送请求？
A: 检查后端服务器地址配置，确保网络连通。

### Q: 扫描任务一直 Pending？
A: 检查 SQLMap 是否正确集成，查看后端日志获取详细信息。

---

## 技术支持

- **GitHub Issues**: 提交问题和建议
- **文档**: 查看 doc 目录下的详细文档

---

> ⚠️ **安全声明**: 本工具仅供授权安全测试使用，禁止用于非法用途！
