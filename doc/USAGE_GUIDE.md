# SQLMap Web UI 使用指南

<p align="center">
  <img src="../src/frontEnd/public/logo.svg" alt="SQLMap WebUI Logo" width="80" height="80">
</p>

本文档详细介绍 SQLMap Web UI 的完整使用方法，包括主应用、VulnShop 靶场和扩展插件。

## 目录

- [1. 系统概述](#1-系统概述)
- [2. 安装部署](#2-安装部署)
- [3. 主应用使用](#3-主应用使用)
- [4. 扫描配置管理](#4-扫描配置管理)
- [5. 请求头规则配置](#5-请求头规则配置)
- [6. VulnShop 靶场使用](#6-vulnshop-靶场使用)
- [7. 扩展插件使用](#7-扩展插件使用)
- [8. 高级功能](#8-高级功能)
- [9. 常见问题](#9-常见问题)

---

## 1. 系统概述

SQLMap Web UI 是一个完整的 SQL 注入测试平台，包含三个主要组件：

| 组件 | 说明 | 端口 |
|------|------|------|
| Web 应用 | SQL 注入扫描任务管理界面 | 8775 (后端) / 5173 (前端开发) |
| VulnShop 靶场 | 内置漏洞测试环境 | 9527 |
| 扩展插件 | Burp Suite 插件 | - |

### 系统要求

- **操作系统**: Windows / Linux / macOS
- **Python**: 3.13+
- **Node.js**: 20+ (前端开发)
- **Java**: 11+ (Burp Suite Legacy API) 或 17+ (Montoya API)
- **浏览器**: Chrome (推荐)
- **包管理器**: uv (Python), pnpm (Node.js)

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

# 安装依赖
pip install flask

# 启动服务
python server.py
```

靶场访问: http://127.0.0.1:9527

---

## 3. 主应用使用

### 3.1 首页仪表盘

首页显示任务统计信息：
- **任务状态统计**: 总任务数、运行中、等待中、已完成、失败、已停止、已终止
- **注入结果统计**: 可注入任务数、不可注入任务数
- **快捷入口**: 点击统计卡片可快速跳转到对应过滤的任务列表

### 3.2 创建扫描任务

1. 进入任务列表页面
2. 点击「新建任务」按钮
3. 填写任务信息：
   - **目标 URL**: 待测试的 URL 地址
   - **HTTP 请求**: 可直接粘贴完整的 HTTP 请求（支持 cURL/PowerShell/fetch/原始 HTTP）
   - **扫描参数**: Level、Risk、DBMS 等
4. 点击「开始扫描」

#### HTTP 请求格式支持

系统支持以下格式的 HTTP 请求自动解析：

| 格式 | 说明 | 示例 |
|------|------|------|
| cURL (Bash) | Linux/Mac 终端请求 | `curl -X POST 'http://...' -H 'Content-Type: ...'` |
| cURL (CMD) | Windows 命令行 | `curl -X POST "http://..." -H "Content-Type: ..."` |
| PowerShell | Invoke-WebRequest | `Invoke-WebRequest -Uri "http://..." -Method POST` |
| fetch | JavaScript fetch API | `fetch("http://...", { method: "POST", ... })` |
| 原始 HTTP | 标准 HTTP 报文 | `POST /path HTTP/1.1\nHost: example.com\n...` |

系统会自动检测输入格式并转换为标准 HTTP 报文。

### 3.3 任务列表功能

#### 过滤功能
- **URL 关键字搜索**: 支持模糊匹配目标 URL
- **报文关键字搜索**: 搜索 Headers 和 Body 内容
- **状态筛选**: 按任务状态过滤（等待中/运行中/已完成/失败/已停止/已终止）
- **日期范围筛选**: 按创建时间和执行时间范围过滤
- **注入状态筛选**: 存在注入/无注入/未知

#### 排序功能
- 点击列头触发排序
- 支持升序/降序/恢复默认
- 可排序字段: 任务ID、状态、创建时间

#### 批量操作
- **多选**: 表格第一列复选框，支持单选和全选
- **批量停止**: 停止选中的运行中任务
- **批量删除**: 删除选中的任务（运行中任务自动跳过）
- **删除全部**: 清空所有任务（需确认）

#### 汇总统计行
表格底部显示实时统计：
- 总任务数
- 可注入任务数
- 状态分布

### 3.4 查看任务结果

在任务详情页可以查看：

- **基础信息**: 任务状态、创建时间、目标地址、来源IP
- **HTTP 请求**: 原始请求内容（方法、URL、Headers、Body）
- **扫描配置**: SQLMap 参数配置（Level、Risk、Technique 等）
- **扫描结果**: 发现的注入点和 Payload 详情
- **实时日志**: 任务执行日志，支持刷新

### 3.5 智能轮询

系统采用智能轮询策略：
- 当有运行中任务时，自动启动定时刷新
- 无运行中任务时自动停止轮询
- 页面隐藏时暂停轮询，显示时恢复
- 可在配置页面调整刷新间隔

---

## 4. 扫描配置管理

### 4.1 功能概述

扫描配置管理提供三种配置类型：

| 配置类型 | 说明 | 使用场景 |
|----------|------|----------|
| 默认配置 | 全局默认扫描参数 | 大多数扫描任务使用相同参数 |
| 常用配置 | 保存的常用配置组合 | 针对特定场景的配置 |
| 历史配置 | 历史扫描使用过的配置 | 复用之前的扫描配置 |

### 4.2 默认配置

1. 进入「配置」→「扫描配置管理」→「默认配置」Tab
2. 设置全局默认参数：
   - Level: 检测级别 (1-5)
   - Risk: 风险级别 (1-3)
   - DBMS: 数据库类型
   - Technique: 注入技术
   - 其他 SQLMap 参数
3. 点击「保存」

### 4.3 常用配置

#### 创建常用配置

1. 进入「常用配置」Tab
2. 点击「添加配置」或「引导式添加」
3. 填写配置信息：
   - 配置名称：如「MySQL 深度扫描」
   - 配置描述（可选）
   - SQLMap 参数
4. 点击「保存」

#### 引导式编辑器

引导式编辑器提供可视化界面配置 SQLMap 参数：

1. 点击「引导式添加」或「引导式编辑」
2. 在对话框中通过下拉菜单和复选框选择参数
3. 实时预览生成的命令行参数
4. 点击「保存」

### 4.4 历史配置

1. 进入「历史配置」Tab
2. 查看历史扫描使用过的配置
3. 点击「使用」可复用配置
4. 点击「保存为常用」可保存到常用配置

---

## 5. 请求头规则配置

### 5.1 功能概述

配置页面包含3个Tab标签页：

1. **系统配置** - 自动刷新间隔设置
2. **Header规则管理** - 持久化请求头规则配置
3. **会话Header管理** - 临时会话级请求头配置

### 5.2 持久化规则管理

#### 创建全局规则（最常用）

**场景**: 为所有扫描任务添加统一的User-Agent

**步骤**:
1. 点击进入「Header规则管理」Tab
2. 点击「添加规则」按钮
3. 填写表单:
   - 规则名称: `全局User-Agent`
   - Header名称: `User-Agent`
   - Header值: `Mozilla/5.0 SecurityScanner/1.0`
   - 替换策略: `完全替换`
   - 优先级: `50`
   - ✅ 启用规则
   - ❌ 不勾选「配置作用域」（全局生效）
4. 点击「保存」

✅ **结果**: 所有扫描任务都会使用这个User-Agent

#### 创建带作用域的规则

**场景**: 只为特定环境API添加认证Token

**步骤**:
1. 点击「添加规则」
2. 填写表单:
   - 规则名称: `生产环境API认证`
   - Header名称: `Authorization`
   - Header值: `Bearer eyJhbGc...`
   - 优先级: `80` (高优先级)
   - ✅ 启用规则
   - ✅ 勾选「配置作用域」
3. 配置作用域:
   - 协议匹配: `https`
   - 主机名匹配: `api.production.com`
   - 路径匹配: `/v1/*`
   - ❌ 不使用正则表达式
4. 点击「保存」

✅ **结果**: 
- ✅ 只对 `https://api.production.com/v1/*` 的请求添加认证头
- ❌ 其他URL不受影响

#### 规则操作

- **编辑**: 点击编辑按钮修改规则
- **启用/禁用**: 点击眼睛图标切换状态
- **删除**: 点击删除按钮移除规则

### 5.3 作用域配置详解

#### 作用域字段说明

| 字段 | 说明 | 示例 |
|------|------|------|
| 协议匹配 | 匹配http或https | `https` 或 `http,https` |
| 主机名匹配 | 匹配域名(支持通配符*) | `api.example.com` 或 `*.example.com` |
| IP匹配 | 匹配IP地址(支持通配符*) | `192.168.1.100` 或 `192.168.*` |
| 端口匹配 | 匹配端口号(支持多个) | `443` 或 `80,443,8080` |
| 路径匹配 | 匹配URL路径(支持通配符*) | `/api/*` 或 `/v1/users` |
| 使用正则 | 是否使用正则表达式 | ☐ 关键字匹配 ☑ 正则匹配 |

#### 匹配逻辑

- **不填写作用域**: 全局生效，匹配所有URL
- **填写作用域**: 所有配置项都必须匹配才生效(AND逻辑)
- **字段留空**: 该维度不限制(等同于通配符)

#### 作用域示例

**示例1: 只匹配HTTPS**
```json
{
  "protocol_pattern": "https"
}
```
✅ 匹配: `https://任何域名/任何路径`  
❌ 不匹配: `http://...`

**示例2: 匹配example.com的所有子域名**
```json
{
  "host_pattern": "*.example.com"
}
```
✅ 匹配: `api.example.com`, `www.example.com`
❌ 不匹配: `example.com` (主域名)

**示例3: 匹配特定API路径**
```json
{
  "protocol_pattern": "https",
  "host_pattern": "api.production.com",
  "path_pattern": "/v1/*"
}
```
✅ 匹配: `https://api.production.com/v1/users`
❌ 不匹配: `http://api.production.com/v1/users` (协议不匹配)

### 5.4 会话Header管理

#### 批量添加临时Headers

**场景**: 为当前测试会话添加多个临时Headers

**步骤**:
1. 点击进入「会话Header管理」Tab
2. 点击「添加Header」按钮
3. 在文本框中输入多行Headers:
   ```
   Authorization: Bearer temp-token-123
   X-Request-ID: test-request-001
   X-Custom-Header: custom-value
   ```
4. 设置参数:
   - 优先级: `50`
   - 生存时间: `3600` 秒(1小时)
5. 点击「添加」

✅ **结果**: 这些Headers将在接下来的1小时内对所有请求生效

#### 清除会话Headers

点击「清除所有」按钮，确认后立即清除所有会话Headers

### 5.5 优先级设置建议

| 优先级范围 | 建议用途 | Tag颜色 |
|-----------|---------|---------|
| 80-100 | 关键认证/授权Header | 🔴 红色 |
| 50-79 | 重要业务Header | 🟡 黄色 |
| 0-49 | 一般Header | 🔵 蓝色 |

---

## 6. VulnShop 靶场使用

### 6.1 靶场介绍

VulnShop 是一个模拟电商平台的 SQL 注入靶场，专门设计用于：
- 学习各种 SQL 注入技术
- 测试 SQLMap 等安全工具
- 安全培训和 CTF 练习

### 6.2 测试账户

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| test | test | 普通用户 |
| alice | alice123 | 普通用户 |

### 6.3 漏洞类型

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

### 6.4 难度级别

| 级别 | WAF 防护 | 绕过方法 |
|------|----------|----------|
| Easy | 无防护 | 直接注入 |
| Medium | 简单过滤 | 大小写混合、URL 编码 |
| Hard | 严格过滤 | 高级绕过技术 |

切换难度：在「系统配置」页面选择难度级别

### 6.5 主题切换

靶场支持亮色和暗色两种主题：
- 点击导航栏右侧的主题切换按钮（☀️/🌙）
- 主题选择会自动保存

### 6.6 数据库重置

如需恢复初始数据：
1. Web 界面：「系统配置」→「重置数据库」
2. 命令行：`python database.py`

---

## 7. 扩展插件使用

### 7.1 Burp Suite 插件

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

4. **活动日志**:
   - 查看发送历史和结果

#### 扫描参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| Level | 检测级别 (1-5) | 1 |
| Risk | 风险级别 (1-3) | 1 |
| DBMS | 数据库类型 | 自动检测 |
| Technique | 注入技术 | BEUSTQ (全部) |

---

## 8. 高级功能

### 8.1 批量导入HTTP请求

支持批量导入 HTTP 请求：
1. 准备请求文件（每个请求以空行分隔）
2. 使用导入功能上传文件
3. 批量创建扫描任务

### 8.2 自定义 SQLMap 参数

在任务创建时可配置所有 SQLMap 参数：
- 检测参数: level, risk, technique
- 目标参数: dbms, os, tamper
- 注入参数: prefix, suffix, string
- 输出参数: dump, dump-all, passwords

### 8.3 批量请求头导入

在配置页面支持从文本批量导入请求头规则：
1. 进入「Header规则管理」Tab
2. 点击「文本导入」按钮
3. 输入多行格式的请求头
4. 设置优先级和替换策略
5. 确认批量创建

---

## 9. 常见问题

### Q: 后端服务启动失败？
A: 检查 Python 版本（需要 3.13+），确保依赖安装完整。使用 `uv sync --extra thirdparty` 安装依赖。

### Q: 前端无法连接后端？
A: 检查跨域配置，确保后端服务正在运行。后端默认监听 8775 端口。

### Q: VulnShop 靶场无法访问？
A: 确保端口 9527 未被占用，使用 127.0.0.1 而非 localhost。

### Q: Burp Suite 插件无法发送请求？
A: 检查后端服务器地址配置，确保网络连通。使用「测试连接」功能验证。

### Q: 扫描任务一直 Pending？
A: 检查 SQLMap 是否正确集成，查看后端日志获取详细信息。

### Q: 请求头规则不生效？
A: 检查规则是否启用，作用域配置是否正确匹配目标URL。

### Q: 会话Header过期了？
A: 会话Header有TTL限制，过期后需重新添加。可增大TTL或使用持久化规则。

---

## 技术支持

- **GitHub Issues**: 提交问题和建议
- **文档**: 查看 doc 目录下的详细文档

---

> ⚠️ **安全声明**: 本工具仅供授权安全测试使用，禁止用于非法用途！
