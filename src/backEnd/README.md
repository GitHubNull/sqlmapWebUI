# SQLMap WebUI 后端

基于 FastAPI 构建的 SQL 注入扫描任务管理后端服务。

## 技术栈

| 类别 | 技术 | 版本 |
|------|------|------|
| 框架 | FastAPI | 0.100+ |
| 运行时 | Python | 3.13+ |
| 包管理器 | uv | latest |
| 数据库 | SQLite | 3+ |
| SQL注入引擎 | SQLMap | latest |
| ASGI服务器 | Uvicorn | 0.30+ |

## 核心功能

### 任务管理
- 创建/查询/停止/删除扫描任务
- 任务状态监控
- 实时日志获取
- 扫描结果查询
- 批量任务操作

### 请求头规则管理
- **持久化规则**: 存储在 SQLite 数据库
  - CRUD 完整操作
  - 优先级排序 (0-100)
  - 多种替换策略 (REPLACE, APPEND, PREPEND, SKIP)
- **会话级规则**: 基于客户端 IP 的临时规则
  - TTL 自动过期
  - 内存存储
- **作用域匹配**: 灵活的 URL 匹配规则
  - 协议匹配 (http/https)
  - 主机名匹配 (支持通配符)
  - 端口匹配 (支持多值)
  - 路径匹配 (支持通配符)
  - 正则表达式支持

### 扩展集成
- Chrome 扩展 API
- Burp Suite 插件 API
- 统一的认证机制

## 快速开始

### 环境要求

- Python 3.13+
- uv 包管理器

### 安装依赖

```bash
cd src/backEnd
uv sync --extra thirdparty
```

### 启动服务

```bash
uv run python main.py
```

服务将在 http://localhost:8775 启动。

### 访问 API 文档

- Swagger UI: http://localhost:8775/docs
- ReDoc: http://localhost:8775/redoc

## 项目结构

```
src/backEnd/
├── api/                      # API 路由模块
│   ├── chromeExApi/          # Chrome 扩展 API
│   │   └── admin.py          # 任务管理接口
│   ├── burpSuiteExApi/       # Burp Suite 插件 API
│   │   └── admin.py          # 扫描提交接口
│   └── commonApi/            # 通用 API
│       ├── headerController.py   # 请求头规则管理
│       ├── authController.py     # 认证接口
│       └── configController.py   # 配置管理
├── model/                    # 数据模型
│   ├── Task.py               # 任务模型
│   ├── TaskStatus.py         # 任务状态枚举
│   ├── DataStore.py          # 内存数据存储（单例）
│   ├── Database.py           # 数据库连接
│   ├── HeaderScope.py        # 请求头作用域配置
│   ├── PersistentHeaderRule.py  # 持久化请求头规则
│   ├── SessionHeader.py      # 会话级请求头
│   ├── HeaderDatabase.py     # 请求头数据库操作
│   ├── HeaderBatch.py        # 批量请求头操作
│   ├── BaseResponseMsg.py    # 统一响应格式
│   └── requestModel/         # 请求 DTO
│       └── TaskRequest.py    # 任务请求模型
├── service/                  # 业务逻辑层
│   ├── taskService.py        # 任务管理服务
│   └── headerRuleService.py  # 请求头规则服务（单例）
├── utils/                    # 工具函数
│   ├── header_processor.py   # 请求头处理器
│   ├── scope_matcher.py      # 作用域匹配器
│   ├── header_parser.py      # 请求头解析器
│   ├── session_header_manager.py  # 会话请求头管理
│   ├── task_monitor.py       # 任务监控
│   ├── auth.py               # 认证工具
│   └── content_type_helper.py # Content-Type 处理
├── third_lib/                # 第三方库
│   └── sqlmap/               # SQLMap 集成 (git submodule)
├── tests/                    # 测试文件
│   ├── test_scope_matcher.py
│   ├── test_header_processor_scope.py
│   └── test_api_endpoints.py
├── static/                   # 前端静态资源（构建输出）
├── temp/                     # 临时文件
│   └── http_requests/        # HTTP 请求缓存
├── app.py                    # FastAPI 应用核心
├── main.py                   # 入口文件
├── config.py                 # 配置文件
├── pyproject.toml            # 项目配置
└── uvicorn_config.json       # Uvicorn 配置
```

## API 端点

### 任务管理 API

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/chrome/admin/task/list` | 获取任务列表 |
| POST | `/chrome/admin/task/add` | 创建任务 |
| PUT | `/chrome/admin/task/stop` | 停止任务 |
| DELETE | `/chrome/admin/task/delete` | 删除任务 |
| PATCH | `/chrome/admin/task/flush` | 清空所有任务 |
| GET | `/chrome/admin/task/logs/getLogsByTaskId` | 获取任务日志 |
| GET | `/chrome/admin/task/getTaskScanOptionsByTaskId` | 获取扫描配置 |
| GET | `/chrome/admin/task/getScanDataByTaskId` | 获取扫描结果 |

### 请求头规则 API

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/commonApi/header/persistent-header-rules` | 获取规则列表 |
| GET | `/commonApi/header/persistent-header-rules/{id}` | 获取单个规则 |
| POST | `/commonApi/header/persistent-header-rules` | 创建规则 |
| PUT | `/commonApi/header/persistent-header-rules/{id}` | 更新规则 |
| DELETE | `/commonApi/header/persistent-header-rules/{id}` | 删除规则 |
| POST | `/commonApi/header/session-headers` | 设置会话请求头 |
| GET | `/commonApi/header/session-headers` | 获取会话请求头 |
| DELETE | `/commonApi/header/session-headers` | 清除会话请求头 |
| POST | `/commonApi/header/header-processing/preview` | 预览请求头处理 |
| POST | `/commonApi/header/parse-headers-batch` | 批量解析请求头 |
| POST | `/commonApi/header/create-persistent-rules-batch` | 批量创建规则 |

### Burp Suite API

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/burp/admin/scan` | 提交扫描任务 |

### 通用 API

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/version` | 获取版本信息 |
| GET | `/api/health` | 健康检查 |

## 配置说明

### config.py

```python
# 最大并发任务数
MAX_TASKS_COUNT = 3

# 版本号
VERSION = "1.6.0"
```

### 环境变量

可通过 `.env` 文件配置：
- 认证密钥
- 日志级别
- 其他敏感配置

## 数据存储

### 内存存储
- 任务数据存储在 `DataStore` 单例中
- 会话请求头存储在 `SessionHeaderManager` 中

### SQLite 数据库
- 持久化请求头规则存储在 `header_rules.db`
- 自动数据库迁移（新字段自动添加）

## 开发指南

### 添加新 API 端点

1. 在 `api/` 对应模块创建路由函数
2. 在 `app.py` 中注册路由
3. 如需要，在 `service/` 添加业务逻辑
4. 在 `model/` 添加数据模型

### 添加新服务

1. 在 `service/` 创建服务类
2. 使用单例模式（参考 `headerRuleService.py`）
3. 在 API 层调用服务

### 运行测试

```bash
cd src/backEnd
python -m pytest tests/ -v
```

## 跨域配置

允许以下来源的跨域请求：
- `localhost:5173-5176` (前端开发)
- `localhost:8775` (后端)

配置在 `app.py` 中：
```python
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):(517[3-6]|8775)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
```

## SQLMap 集成

SQLMap 作为 git submodule 集成在 `third_lib/sqlmap/`：

```bash
# 更新 SQLMap
git submodule update --remote
```

`main.py` 在启动时配置 SQLMap 导入路径。

## 部署说明

### 开发环境

```bash
uv run python main.py
```

### 生产环境

```bash
uv run uvicorn app:app --host 0.0.0.0 --port 8775
```

或使用配置文件：

```bash
uv run uvicorn app:app --config uvicorn_config.json
```

## 许可证

MIT
