# SQLMap WebUI - Burp Suite Extensions

Burp Suite 扩展插件，用于将 HTTP 请求发送到 SQLMap WebUI 后端进行 SQL 注入检测。

## 项目结构

```
burpEx/
├── legacy-api/          # 传统 Burp API 插件 (Java 11)
│   ├── src/main/java/com/sqlmapwebui/burp/
│   │   ├── BurpExtender.java              # 插件入口 (Legacy API)
│   │   ├── SqlmapUITab.java               # 主UI标签页
│   │   ├── panels/                        # UI面板组件
│   │   ├── dialogs/                       # 对话框组件
│   │   └── [共享代码文件...]
│   └── pom.xml
│
├── montoya-api/         # Montoya API 插件 (Java 17+, Burp 2023.1+)
│   ├── src/main/java/com/sqlmapwebui/burp/
│   │   ├── SqlmapWebUIExtension.java      # 插件入口 (Montoya API)
│   │   ├── SqlmapContextMenuProvider.java # 右键菜单提供者
│   │   ├── HttpRequestUtils.java          # UTF-8请求处理
│   │   ├── util/                          # 工具类
│   │   ├── SqlmapUITab.java               # 主UI标签页 (与Legacy共享)
│   │   ├── panels/                        # UI面板组件 (与Legacy共享)
│   │   ├── dialogs/                       # 对话框组件 (与Legacy共享)
│   │   └── [共享代码文件...]
│   └── pom.xml
│
├── sync-shared.bat      # Windows 同步脚本
├── sync-shared.sh       # Linux/Mac 同步脚本
└── SHARED_FILES.md      # 共享文件文档
```

## 双 API 架构

本项目同时支持 Burp Suite 的两种 API：

| 模块 | API 类型 | Java 版本 | 兼容 Burp Suite |
|------|----------|-----------|----------------|
| `legacy-api` | Legacy API | Java 11+ | 所有版本 |
| `montoya-api` | Montoya API | Java 17+ | 2023.1+ |

**共享代码策略：**
- 两个模块共享 90% 的代码（模型、工具类、UI组件）
- 使用同步脚本 `sync-shared.bat/sh` 保持代码一致
- 仅入口点和 API 特定代码独立维护

## 同步脚本使用

当修改 `legacy-api` 中的共享代码后，需要同步到 `montoya-api`：

### Windows
```batch
cd src/burpEx
sync-shared.bat
```

### Linux/Mac
```bash
cd src/burpEx
chmod +x sync-shared.sh
./sync-shared.sh
```

详细说明请查看 [SHARED_FILES.md](./SHARED_FILES.md)

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

### 修改共享代码

1. 在 `legacy-api` 中修改文件（保持 Java 11 兼容性）
2. 运行 `sync-shared.bat` 或 `sync-shared.sh`
3. 分别编译两个模块验证

### 添加新功能

- 如果是通用功能：在 `legacy-api` 中实现，然后同步
- 如果是 API 特定：只在对应模块中实现

## 注意事项

1. **同步方向**: 始终以 `legacy-api` 为源，`montoya-api` 为目标
2. **兼容性**: 确保共享代码兼容 Java 11
3. **编译验证**: 每次同步后都应该编译验证
4. **备份**: 同步脚本会自动创建备份

## 版本信息

- **版本**: 1.8.16
- **更新日期**: 2026-02-10
- **兼容 SQLMap**: 1.9.11.3+

## 相关链接

- [共享文件说明](./SHARED_FILES.md)
- [SQLMap 官方文档](https://sqlmap.org/)
- [Burp Suite 扩展开发](https://portswigger.net/burp/documentation/desktop/extensions)

## License

MIT License
