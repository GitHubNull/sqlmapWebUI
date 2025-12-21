# SQLMap WebUI - Burp Suite Extensions

Burp Suite 扩展插件，用于将 HTTP 请求发送到 SQLMap WebUI 后端进行 SQL 注入检测。

## 项目结构

```
burpEx/
├── legacy-api/      # 传统 Burp API 插件 (Java 11)
│   ├── src/main/java/com/sqlmapwebui/burp/
│   │   ├── SqlmapWebUIExtension.java    # 插件入口
│   │   ├── ui/                          # UI 组件
│   │   ├── config/                      # 配置管理
│   │   └── http/                        # HTTP 客户端
│   ├── pom.xml
│   └── target/                          # 构建输出
└── montoya-api/     # Montoya API 插件 (Java 17, Burp 2023.1+)
    ├── src/main/java/com/sqlmapwebui/burp/
    │   ├── SqlmapWebUIExtension.java    # 插件入口
    │   ├── ui/                          # UI 组件
    │   ├── config/                      # 配置管理
    │   └── http/                        # HTTP 客户端
    ├── pom.xml
    └── target/                          # 构建输出
```

## 插件功能

### 核心功能

| 功能 | 说明 |
|------|------|
| **提交扫描任务** | 右键菜单发送 HTTP 请求到后端 |
| **默认配置管理** | 设置和保存默认扫描参数 |
| **常用配置管理** | 添加/编辑/删除常用扫描配置 |
| **历史配置记录** | 查看历史扫描使用的配置 |
| **引导式编辑器** | 可视化配置 SQLMap 参数 |
| **配置选择** | 提交时可选择默认配置、常用配置或历史记录配置 |
| **活动日志** | 记录所有操作和发送结果 |

> **注意**: 插件端仅负责发送请求，任务管理和结果查看请使用 Web 前端。

### 右键菜单

- **Send to SQLMap WebUI** - 使用默认配置直接发送
- **Send to SQLMap WebUI (选择配置)...** - 弹出配置选择对话框

### UI 标签页

| 标签页 | 功能 |
|--------|------|
| 服务器配置 | 设置后端 URL、测试连接状态 |
| 默认配置 | 设置 Level、Risk、DBMS、Technique、Batch 等默认参数 |
| 常用配置 | 管理常用配置列表（添加/编辑/删除），支持引导式编辑 |
| 历史配置 | 查看历史扫描使用的配置记录 |
| 活动日志 | 查看操作日志和发送历史 |

## 版本选择

| Burp Suite 版本 | 推荐插件 | Java 要求 |
|-----------------|----------|-----------|
| 2023.1+ | montoya-api | Java 17+ |
| 较老版本 | legacy-api | Java 11+ |

## 构建方式

### Montoya API (推荐)

```bash
cd montoya-api
mvn clean package -DskipTests
```

生成文件: `target/sqlmap-webui-burp-montoya-*.jar`

### Legacy API

```bash
cd legacy-api
mvn clean package -DskipTests
```

生成文件: `target/sqlmap-webui-burp-legacy-*-jar-with-dependencies.jar`

## 安装方式

1. 打开 Burp Suite
2. 进入 **Extender** → **Extensions** 标签页
3. 点击 **Add** 按钮
4. 选择对应版本的 JAR 文件
5. 点击 **Next** 完成安装

## 使用方法

### 1. 配置服务器

1. 进入插件的「服务器配置」标签页
2. 设置后端 URL: `http://localhost:8775`
3. 点击「测试连接」验证连接状态

### 2. 配置默认参数

在「默认配置」标签页设置：
- Level: 检测级别 (1-5)
- Risk: 风险级别 (1-3)
- DBMS: 数据库类型
- Technique: 注入技术
- Batch: 批处理模式

### 3. 发送请求

1. 在 Proxy/Repeater/Target 等位置选中请求
2. 右键选择 "Send to SQLMap WebUI"
3. 或选择 "Send to SQLMap WebUI (选择配置)..." 自定义参数

### 4. 查看结果

发送后在 Web 前端查看扫描任务和结果。

## 扫描参数说明

### 检测级别 (Level)

| 值 | 说明 |
|----|------|
| 1 | 默认，测试 GET/POST 参数 |
| 2 | 同时测试 Cookie |
| 3 | 同时测试 User-Agent/Referer |
| 4 | 更多测试向量 |
| 5 | 最全面的测试 |

### 风险级别 (Risk)

| 值 | 说明 |
|----|------|
| 1 | 默认，安全测试 |
| 2 | 添加基于时间的盲注 |
| 3 | 添加基于 OR 的盲注（可能影响数据）|

### 注入技术代码 (Technique)

| 代码 | 技术 |
|------|------|
| B | 布尔盲注 (Boolean-based blind) |
| E | 报错注入 (Error-based) |
| U | 联合查询注入 (Union query-based) |
| S | 堆叠查询 (Stacked queries) |
| T | 时间盲注 (Time-based blind) |
| Q | 内联查询 (Inline queries) |

默认: `BEUSTQ` (全部技术)

### 数据库类型 (DBMS)

支持: MySQL, PostgreSQL, Oracle, SQLite, Microsoft SQL Server, IBM DB2 等

留空则自动检测。

## 后端接口

插件需要后端提供以下接口：

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/version` | GET | 获取版本信息（用于测试连接） |
| `/api/health` | GET | 健康检查 |
| `/burp/admin/scan` | POST | 提交扫描任务 |

## 依赖项

| 依赖 | 版本 | 用途 |
|------|------|------|
| OkHttp | 4.12.0 | HTTP 客户端 |
| Gson | 2.10.1 | JSON 处理 |
| SLF4J | 2.0.9 | 日志门面 |
| Logback | 1.4.11 | 日志实现 |

## 开发指南

### 项目结构说明

```
src/main/java/com/sqlmapwebui/burp/
├── SqlmapWebUIExtension.java   # 插件入口，注册菜单和UI
├── ui/
│   ├── MainPanel.java          # 主面板（Tab容器）
│   ├── ServerConfigPanel.java  # 服务器配置面板
│   ├── DefaultConfigPanel.java # 默认配置面板
│   ├── PresetConfigPanel.java  # 常用配置面板
│   ├── HistoryConfigPanel.java # 历史配置面板
│   ├── GuidedParamEditorDialog.java # 引导式参数编辑器
│   └── ActivityLogPanel.java   # 活动日志面板
├── config/
│   ├── ConfigManager.java      # 配置管理器
│   └── ScanConfig.java         # 扫描配置模型
└── http/
    └── ApiClient.java          # API 客户端
```

### 添加新配置项

1. 在 `ScanConfig` 中添加字段
2. 在 `DefaultConfigPanel` 中添加 UI 控件
3. 在 `ConfigManager` 中添加持久化逻辑

### 调试方法

1. 在 Burp Suite 中加载插件
2. 查看 Extender → Output 标签页的日志
3. 使用活动日志面板查看操作记录

## 常见问题

### Q: 插件加载失败？
A: 检查 Java 版本是否满足要求（Montoya 需要 Java 17+，Legacy 需要 Java 11+）

### Q: 连接测试失败？
A: 检查后端服务是否运行，URL 是否正确（默认 http://localhost:8775）

### Q: 发送请求后看不到任务？
A: 在 Web 前端查看任务列表，插件只负责发送，不显示任务

### Q: 如何查看详细错误？
A: 查看 Burp Suite 的 Extender → Output 标签页

## 许可证

MIT License
