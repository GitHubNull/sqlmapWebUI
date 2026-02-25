# SQLMap WebUI Burp Extension - Architecture Notes

## 重要说明

经过实际测试发现，**legacy-api 和 montoya-api 不能直接同步文件**。

### 原因

两个模块使用**不同的 Burp Suite API**：

**Legacy API (Java 11):**
```java
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
```

**Montoya API (Java 17+):**
```java
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
```

### 影响

虽然两个模块的业务逻辑**完全相同**，但：
1. **Import 语句不同** - 无法直接复制文件
2. **API 调用方式不同** - 类名和方法签名不同
3. **必须独立维护** - 每个修改需要在两个地方手动更新

### 当前架构

```
src/burpEx/
├── legacy-api/          # 完全独立的代码 (Java 11)
│   ├── BurpExtender.java
│   ├── ConfigManager.java      # 使用 IBurpExtenderCallbacks
│   ├── SqlmapApiClient.java
│   ├── SqlmapUITab.java
│   ├── panels/
│   ├── dialogs/
│   └── ... (共34个文件)
│
└── montoya-api/         # 完全独立的代码 (Java 17)
    ├── SqlmapWebUIExtension.java
    ├── ConfigManager.java        # 使用 MontoyaApi
    ├── SqlmapApiClient.java
    ├── SqlmapUITab.java
    ├── panels/
    ├── dialogs/
    └── ... (共37个文件)
```

### 开发建议

1. **修改逻辑时**: 需要在两个模块中分别修改
2. **先改 legacy-api**: 因为它使用更简单的 Legacy API
3. **再改 montoya-api**: 参考 legacy-api 的修改，适配 Montoya API
4. **分别编译验证**: 确保两个模块都能编译通过

### 编译验证

```bash
# 编译 Legacy API (Java 11)
cd src/burpEx/legacy-api
mvn clean package -DskipTests

# 编译 Montoya API (Java 17)
cd src/burpEx/montoya-api
mvn clean package -DskipTests
```

两个模块都能独立编译成功，无警告、无错误。

### 为什么不创建 shared 模块？

尝试过创建 shared 模块，但发现：
1. UI 组件深度依赖 Burp API
2. ConfigManager 需要适配不同 API
3. 抽象层会增加复杂度
4. 需要修改 100+ 个文件的 import 语句
5. 风险高，容易引入 bug

**结论**: 当前独立维护的方式虽然重复代码多，但是最稳定和可维护的方案。

## 版本信息

- **版本**: 1.8.16
- **更新日期**: 2026-02-10
- **状态**: 两个模块独立维护，各自编译成功
