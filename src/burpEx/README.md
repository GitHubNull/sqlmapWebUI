# SQLMap WebUI - Burp Suite Extensions

Burp Suite 扩展插件，用于将 HTTP 请求发送到 SQLMap WebUI 后端进行 SQL 注入检测。

## 项目结构

```
src/burpEx/
├── legacy-api/          # 传统 Burp API 插件 (Java 11)
│   ├── src/main/java/com/sqlmapwebui/burp/
│   │   ├── BurpExtender.java              # 插件入口
│   │   ├── ConfigManager.java             # 配置管理
│   │   ├── SqlmapApiClient.java           # API客户端
│   │   ├── SqlmapUITab.java               # 主UI标签页
│   │   ├── panels/                        # UI面板组件
│   │   ├── dialogs/                       # 对话框组件
│   │   └── ... (共34个文件)
│   └── pom.xml
│
└── montoya-api/         # Montoya API 插件 (Java 17+, Burp 2023.1+)
    ├── src/main/java/com/sqlmapwebui/burp/
    │   ├── SqlmapWebUIExtension.java      # 插件入口
    │   ├── SqlmapContextMenuProvider.java # 右键菜单
    │   ├── HttpRequestUtils.java          # UTF-8工具
    │   ├── ConfigManager.java             # 配置管理
    │   ├── SqlmapApiClient.java           # API客户端
    │   ├── SqlmapUITab.java               # 主UI标签页
    │   ├── panels/                        # UI面板组件
    │   ├── dialogs/                       # 对话框组件
    │   └── ... (共37个文件)
    └── pom.xml
```

## 双 API 架构

本项目同时支持 Burp Suite 的两种 API：

| 模块 | API 类型 | Java 版本 | 兼容 Burp Suite |
|------|----------|-----------|----------------|
| `legacy-api` | Legacy API | Java 11+ | 所有版本 |
| `montoya-api` | Montoya API | Java 17+ | 2023.1+ |

**重要说明**: 两个模块使用**不同的 Burp API**，因此代码**不能共享**：
- Legacy API: `import burp.IBurpExtenderCallbacks`
- Montoya API: `import burp.api.montoya.MontoyaApi`

虽然业务逻辑完全相同，但必须独立维护两套代码。

详细说明请查看 [ARCHITECTURE.md](./ARCHITECTURE.md)

## 插件功能

### 核心功能

| 功能 | 说明 |
|------|------|
| **提交扫描任务** | 右键菜单发送 HTTP 请求到后端 |
| **默认配置管理** | 设置和保存默认扫描参数 |
| **常用配置管理** | 添加/编辑/删除常用扫描配置 (SQLite存储) |
| **历史配置记录** | 查看历史扫描使用的配置 |
| **引导式编辑器** | 可视化配置 SQLMap 215个参数 |
| **配置选择** | 提交时可选择默认配置、常用配置或历史记录配置 |
| **活动日志** | 记录所有操作和发送结果 |
| **请求过滤** | 自动过滤二进制内容请求 |
| **请求去重** | 自动去重相同 URL 的请求 |
| **注入点标记** | 手动标记注入点位置 |
| **会话Header** | 提交临时会话Header |
| **Header规则** | 提交持久化Header规则 |

> **注意**: 插件端仅负责发送请求，任务管理和结果查看请使用 Web 前端。

### 右键菜单

- **Send to SQLMap WebUI** - 使用选中的配置直接发送
- **标记注入点并扫描 (*)** - 标记注入点后发送
- **Send to SQLMap WebUI (配置扫描)...** - 弹出高级配置对话框
- **提交会话Header** - 提交临时会话Header (单选时显示)
- **提交Header规则** - 提交持久化Header规则 (单选时显示)

### UI 标签页

| 标签页 | 功能 |
|--------|------|
| **后端配置** | 设置后端 URL 和连接状态 |
| **默认配置** | 设置默认扫描参数 |
| **常用配置** | 管理常用配置 (CRUD操作) |
| **历史记录** | 查看历史使用过的配置 |
| **活动日志** | 查看操作记录和发送结果 |

## 构建说明

### 环境要求

- **Legacy API**: JDK 11+
- **Montoya API**: JDK 17+
- Maven 3.6+

### 编译命令

```bash
# 编译 Legacy API (兼容 Java 11)
cd src/burpEx/legacy-api
mvn clean package -DskipTests

# 编译 Montoya API (需要 Java 17+)
cd src/burpEx/montoya-api
mvn clean package -DskipTests
```

### 输出文件

- Legacy: `target/sqlmap-webui-burp-legacy-1.8.16-jar-with-dependencies.jar`
- Montoya: `target/sqlmap-webui-burp-montoya-1.8.16.jar`

## 安装使用

1. 编译生成 JAR 文件
2. 打开 Burp Suite -> Extensions -> Add
3. 选择编译好的 JAR 文件
4. 确保 SQLMap WebUI 后端已启动（默认 http://localhost:8775）

## 配置说明

### 后端 URL

默认后端地址: `http://localhost:8775`

在 "后端配置" 标签页中修改后端 URL，插件会自动测试连接。

### 扫描配置

支持 215 个 SQLMap 参数，包括但不限于：
- **目标选项**: URL、日志文件、批量文件等
- **请求选项**: 方法、数据、Cookie、代理、认证等
- **优化选项**: 线程、预测输出等
- **注入选项**: 测试参数、DBMS、Tamper脚本等
- **检测选项**: Level、Risk、字符串匹配等
- **技术选项**: 注入技术、时间盲注等
- **枚举选项**: Banner、表、列、数据导出等
- **操作系统接管**: 命令执行、Shell等 (高危)
- **文件系统**: 文件读写 (高危)

## 开发说明

### 修改代码

由于两个 API 不兼容，需要**分别修改**：

1. 先在 `legacy-api` 中修改（使用 Legacy API）
2. 参考修改内容，在 `montoya-api` 中做对应修改（使用 Montoya API）
3. 分别编译验证

### 为什么不能共享代码？

尝试过提取共享模块，但发现：
1. UI 组件依赖 Burp API
2. ConfigManager 需要适配不同 API
3. Import 语句完全不同
4. 需要修改 100+ 个文件
5. 风险高，容易引入 bug

**结论**: 当前独立维护的方式虽然重复代码多，但是最稳定和可维护的方案。

## 版本信息

- **版本**: 1.8.16
- **更新日期**: 2026-02-10
- **兼容 SQLMap**: 1.9.11.3+

## 相关链接

- [架构说明](./ARCHITECTURE.md)
- [SQLMap 官方文档](https://sqlmap.org/)
- [Burp Suite 扩展开发](https://portswigger.net/burp/documentation/desktop/extensions)

## License

MIT License
