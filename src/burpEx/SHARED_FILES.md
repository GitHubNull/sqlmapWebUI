# SQLMap WebUI Burp Extension - Shared Files Documentation

## 概述

本项目采用双 API 架构，同时支持 Burp Suite 的 Legacy API (Java 11) 和 Montoya API (Java 17+)。
为了保持代码一致性，两个模块共享大部分代码文件，通过同步脚本维护。

## 目录结构

```
src/burpEx/
├── legacy-api/          # Legacy API 实现 (Java 11)
│   └── src/main/java/com/sqlmapwebui/burp/
│       ├── BurpExtender.java              # 入口点 (API特定)
│       ├── ApiClient.java                 # 共享
│       ├── SqlmapApiClient.java           # 共享
│       ├── ConfigManager.java             # 共享
│       ├── ScanConfig.java                # 共享
│       ├── PresetConfig.java              # 共享
│       ├── PresetConfigDatabase.java      # 共享
│       ├── ScanConfigParser.java          # 共享
│       ├── BinaryContentDetector.java     # 共享
│       ├── RequestDeduplicator.java       # 共享
│       ├── SqlmapUITab.java               # 共享
│       ├── ParseResult.java               # 共享
│       ├── ParamMeta.java                 # 共享
│       ├── panels/                        # 共享目录
│       │   ├── BaseConfigPanel.java
│       │   ├── ServerConfigPanel.java
│       │   ├── DefaultConfigPanel.java
│       │   ├── PresetConfigPanel.java
│       │   ├── PresetConfigDialog.java
│       │   ├── HistoryConfigPanel.java
│       │   ├── GuidedParamEditor.java
│       │   ├── GuidedParamEditorDialog.java
│       │   ├── LogPanel.java
│       │   ├── HtmlMessageDialog.java
│       │   └── ConfigImportExportHelper.java
│       └── dialogs/                       # 共享目录
│           ├── AdvancedScanConfigDialog.java
│           ├── BatchInjectionMarkDialog.java
│           ├── ConfigSelectionDialog.java
│           ├── InjectionPointDialog.java
│           ├── HeaderRuleDialog.java
│           ├── SessionHeaderDialog.java
│           ├── AboutDialog.java
│           ├── TextLineNumber.java
│           ├── HeaderConstants.java
│           └── JsonUtils.java
│
├── montoya-api/         # Montoya API 实现 (Java 17+)
│   └── src/main/java/com/sqlmapwebui/burp/
│       ├── SqlmapWebUIExtension.java      # 入口点 (API特定)
│       ├── SqlmapContextMenuProvider.java # 菜单提供者 (API特定)
│       ├── HttpRequestUtils.java          # UTF-8工具 (API特定)
│       ├── util/                          # 工具包 (API特定)
│       │   ├── PayloadBuilder.java
│       │   └── LoggerUtil.java
│       └── [所有共享文件与legacy-api相同]
│
└── sync-shared.bat/sh   # 同步脚本
```

## 文件分类

### 共享文件 (Shared)
这些文件在 legacy-api 和 montoya-api 之间保持同步：

**模型类:**
- `ScanConfig.java` - 扫描配置模型 (215个SQLMap参数)
- `PresetConfig.java` - 预设配置模型
- `ParseResult.java` - 解析结果包装类
- `ParamMeta.java` - 参数元数据

**工具类:**
- `ApiClient.java` - HTTP客户端
- `SqlmapApiClient.java` - SQLMap API客户端
- `ConfigManager.java` - 配置管理器
- `PresetConfigDatabase.java` - SQLite数据库操作
- `ScanConfigParser.java` - 命令行参数解析器
- `BinaryContentDetector.java` - 二进制内容检测
- `RequestDeduplicator.java` - 请求去重

**UI组件:**
- `SqlmapUITab.java` - 主UI标签页
- `panels/*.java` - 所有面板组件
- `dialogs/*.java` - 所有对话框组件

### API特定文件 (API-Specific)
这些文件因API差异而保持独立：

**Legacy API (Java 11):**
- `BurpExtender.java` - 插件入口点，实现 `IBurpExtender`

**Montoya API (Java 17+):**
- `SqlmapWebUIExtension.java` - 插件入口点，实现 `BurpExtension`
- `SqlmapContextMenuProvider.java` - 右键菜单提供者
- `HttpRequestUtils.java` - UTF-8请求处理工具
- `util/PayloadBuilder.java` - JSON Payload构建器
- `util/LoggerUtil.java` - 日志工具

## 同步脚本使用

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

### 同步流程
1. 以 `legacy-api` 为基准源
2. 创建 `montoya-api` 的备份
3. 同步所有共享文件
4. 跳过 API 特定文件

## 开发工作流程

### 修改共享代码
1. 在 `legacy-api` 中修改文件
2. 运行同步脚本更新 `montoya-api`
3. 编译两个模块验证

### 修改 API 特定代码
直接在对应模块中修改，无需同步。

### 添加新功能
1. 如果功能在两个 API 中都适用：
   - 在 `legacy-api` 中实现
   - 运行同步脚本
2. 如果功能是 API 特定的：
   - 只在对应模块中实现

## 编译验证

同步后，应该分别编译两个模块：

```bash
# Compile Legacy API
cd src/burpEx/legacy-api
mvn clean package -DskipTests

# Compile Montoya API
cd src/burpEx/montoya-api
mvn clean package -DskipTests
```

两个模块都应该编译成功，无警告、无错误。

## 注意事项

1. **不要直接修改 montoya-api 中的共享文件**，应该在 legacy-api 中修改后同步
2. **同步前确保代码兼容 Java 11**，因为 legacy-api 需要 Java 11 兼容性
3. **定期运行同步脚本**以保持两个模块一致
4. **编译验证**每次同步后都应该编译验证

## 版本历史

- v1.8.16 - 初始实现双 API 支持
- 后续版本 - 保持同步脚本更新
