# SQLMap WebUI - Burp Suite Extensions

Burp Suite扩展插件，用于将HTTP请求发送到SQLMap WebUI后端进行SQL注入检测。

## 项目结构

```
burpEx/
├── legacy-api/      # 传统Burp API插件 (Java 11)
└── montoya-api/     # Montoya API插件 (Java 17, Burp 2023.1+)
```

## 插件功能

插件端**仅支持**以下功能：

1. **提交扫描任务** - 右键菜单发送HTTP请求到后端
2. **默认配置管理** - 设置和保存默认扫描参数
3. **常用配置管理** - 添加/编辑/删除常用扫描配置
4. **配置选择** - 提交时可选择默认配置、常用配置或历史记录配置

> **注意**: 插件端不能管理扫描任务，也不能查看扫描任务记录。任务管理请使用Web前端。

## 右键菜单

- **Send to SQLMap WebUI** - 使用默认配置直接发送
- **Send to SQLMap WebUI (选择配置)...** - 弹出配置选择对话框

## UI标签页

| 标签页 | 功能 |
|--------|------|
| 服务器配置 | 设置后端URL、测试连接 |
| 默认配置 | 设置Level、Risk、DBMS、Technique、Batch等 |
| 常用配置 | 管理常用配置列表 |
| 活动日志 | 查看操作日志 |

## 构建方式

### Legacy API (Java 11)

```bash
cd legacy-api
mvn clean package -DskipTests
```

生成文件: `target/sqlmap-webui-burp-legacy-1.0.0-jar-with-dependencies.jar`

### Montoya API (Java 17)

```bash
cd montoya-api
mvn clean package -DskipTests
```

生成文件: `target/sqlmap-webui-burp-montoya-1.0.0.jar`

## 安装方式

1. 打开Burp Suite
2. 进入 **Extender** → **Extensions** 标签页
3. 点击 **Add** 按钮
4. 选择对应版本的JAR文件
5. 点击 **Next** 完成安装

## 版本选择

| Burp Suite版本 | 推荐插件 |
|----------------|----------|
| 2023.1+ | montoya-api |
| 较老版本 | legacy-api |

## 配置说明

### 扫描参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| Level | 检测级别 (1-5) | 1 |
| Risk | 风险级别 (1-3) | 1 |
| DBMS | 数据库类型 | 自动检测 |
| Technique | 注入技术 (BEUSTQ) | 全部 |
| Batch | 批处理模式 | 启用 |

### 注入技术代码

- **B** - 布尔盲注 (Boolean-based blind)
- **E** - 报错注入 (Error-based)
- **U** - 联合查询注入 (Union query-based)
- **S** - 堆叠查询 (Stacked queries)
- **T** - 时间盲注 (Time-based blind)
- **Q** - 内联查询 (Inline queries)

## 后端接口

插件需要后端提供以下接口：

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/version` | GET | 获取版本信息 |
| `/burp/admin/scan` | POST | 提交扫描任务 |

## 依赖项

- OkHttp 4.12.0 - HTTP客户端
- Gson 2.10.1 - JSON处理
- SLF4J + Logback - 日志

## 许可证

MIT License
