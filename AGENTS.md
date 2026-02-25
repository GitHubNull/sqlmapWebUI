# AGENTS.md

This file provides guidance to AI coding assistants when working with this repository.

## Project Overview

SQLMap Web UI is a comprehensive SQL injection testing platform that includes:
- **Main Application**: FastAPI backend + Vue 3 frontend web interface
- **VulnShop Lab**: Built-in vulnerability testing environment
- **Browser Extensions**: Burp Suite plugins

## Project Structure

```
sqlmapWebUI/
├── src/
│   ├── backEnd/           # FastAPI backend service (Python 3.10+)
│   │   ├── api/           # API routes
│   │   │   ├── webApi/           # Web browser page API
│   │   │   ├── burpSuiteExApi/   # Burp Suite plugin API
│   │   │   └── commonApi/        # Common APIs (auth, headers, config)
│   │   ├── model/         # Data models
│   │   │   ├── requestModel/     # Request DTOs
│   │   │   ├── Task.py           # Task model
│   │   │   ├── ScanPreset.py     # Scan configuration presets
│   │   │   ├── ScanPresetDatabase.py  # Preset database operations
│   │   │   ├── HeaderScope.py    # Header scope configuration
│   │   │   ├── PersistentHeaderRule.py  # Persistent header rules
│   │   │   ├── SessionHeader.py  # Session-level headers
│   │   │   └── ...
│   │   ├── service/       # Business logic layer
│   │   │   ├── taskService.py    # Task management
│   │   │   ├── headerRuleService.py  # Header rules management
│   │   │   └── scanPresetService.py  # Scan preset management
│   │   ├── utils/         # Utility functions
│   │   │   ├── header_processor.py   # Header processing
│   │   │   ├── scope_matcher.py      # Scope matching logic
│   │   │   └── task_monitor.py       # Task monitoring
│   │   ├── third_lib/sqlmap/     # SQLMap integration (git submodule)
│   │   ├── app.py         # FastAPI application core
│   │   └── main.py        # Entry point
│   ├── frontEnd/          # Vue 3 frontend (TypeScript + Vite)
│   │   └── src/
│   │       ├── api/       # API request functions
│   │       ├── components/# Shared components
│   │       │   ├── TaskFilter.vue    # Task filtering component
│   │       │   ├── TaskSummary.vue   # Task statistics summary
│   │       │   ├── ScopeConfigPanel.vue  # Scope configuration UI
│   │       │   ├── HttpCodeEditor.vue    # Code editor with syntax highlighting
│   │       │   └── GuidedParamEditor.vue # Guided SQLMap parameter editor
│   │       ├── stores/    # Pinia state management
│   │       │   ├── task.ts          # Task state store
│   │       │   ├── config.ts        # Config state store
│   │       │   └── scanPreset.ts    # Scan preset state store
│   │       ├── types/     # TypeScript type definitions
│   │       ├── utils/     # Utility functions
│   │       └── views/     # Page views
│   │           ├── Home/            # Dashboard
│   │           ├── TaskList/        # Task list page
│   │           ├── TaskDetail/      # Task detail page
│   │           ├── AddTask/         # Add scan task page
│   │           └── Config/          # Configuration page
│   ├── burpEx/            # Burp Suite extensions
│   │   ├── legacy-api/    # Legacy Burp API (Java 11)
│   │   └── montoya-api/   # Montoya API (Java 17, Burp 2023.1+)
│   └── vulnTestServer/    # VulnShop vulnerability lab
│       ├── server.py      # HTTP server with vulnerable endpoints
│       ├── database.py    # SQLite database with vulnerable queries
│       ├── waf.py         # WAF module (3 difficulty levels)
│       └── static/        # Frontend static assets
├── .github/workflows/     # GitHub Actions CI/CD
└── doc/                   # Project documentation
```

## Technology Stack

| Component | Technologies |
|-----------|-------------|
| Backend | Python 3.10+, FastAPI, SQLMap, SQLite, uv |
| Frontend | Vue 3, TypeScript, PrimeVue, Pinia, Vite |
| Burp Plugins | Java 11 (Legacy), Java 17 (Montoya) |
| Package Managers | uv (Python), pnpm (Node.js), Maven (Java) |

## Core Features

### Task Management
- Create/monitor/stop SQL injection scan tasks
- Real-time log viewing
- Batch operations (batch stop, batch delete, flush all)
- Multi-dimensional filtering (URL, message, status, date range, injection status)
- Sorting by multiple fields
- Summary statistics row in task list
- Smart polling (adjusts refresh rate based on task status)
- WebSocket real-time notifications for task status changes
- Confirmation dialogs for delete/stop operations

### Scan Configuration Management
- **Default Configuration**: Global default scan parameters
- **Preset Configurations**: Saved scan parameter combinations with CRUD
- **History Configurations**: Past scan configurations record
- **Guided Parameter Editor**: Visual SQLMap parameter configuration
- **Parameter Preview**: Real-time command line parameter preview

### HTTP Request Parsing
- Multi-format request parsing:
  - cURL (Bash/CMD)
  - PowerShell Invoke-WebRequest
  - JavaScript fetch
  - Raw HTTP message
- Smart format detection
- Code editor with line numbers and syntax highlighting

### Header Rules Management
- **Persistent Rules**: Long-term header rules stored in database
  - Full CRUD operations
  - Priority-based ordering (0-100)
  - Multiple replace strategies (REPLACE, APPEND, PREPEND, etc.)
- **Session Headers**: Temporary headers with TTL expiration
- **Scope Configuration**: URL matching for targeted header application
  - Protocol pattern (http/https)
  - Hostname pattern (supports wildcards)
  - Port pattern (supports multiple values)
  - Path pattern (supports wildcards)
  - Regex support for complex matching
   - **Batch Import**: Import multiple headers from text
   - **Batch Import**: Import multiple headers from text
   
   ### 完整 SQLMap 参数支持
   
   本项目支持 SQLMap 的 **215 个参数**（除 `-r` 外），完全兼容 SQLMap 1.9.11.3+。
   
   #### 参数分类总览
   
   | 分类 | 参数数量 | 说明 |
   |------|---------|------|
   | Target | 8 | 目标定义（URL、日志、批量文件等）|
   | Request | 51 | HTTP 请求配置（认证、代理、CSRF 等）|
   | Optimization | 5 | 性能优化（线程、连接等）|
   | Injection | 17 | 注入测试配置（测试参数、注入技术等）|
   | Detection | 8 | 检测配置（level、risk、匹配规则等）|
   | Techniques | 9 | 注入技术配置（UNION、DNS 外泄等）|
   | Fingerprint | 1 | 数据库指纹识别 |
   | Enumeration | 36 | 数据枚举（表、列、用户等）|
   | Brute Force | 3 | 暴力破解（常见表、列、文件）|
   | UDF | 2 | 用户自定义函数注入 |
   | File System | 3 | 文件系统访问（读、写文件）|
   | OS Takeover | 8 | 操作系统接管（命令执行、shell 等）|
   | Windows Registry | 6 | Windows 注册表操作 |
   | General | 38 | 通用选项（输出格式、会话管理等）|
   | Miscellaneous | 17 | 其他选项（工具、调试等）|
   
   #### 完整参数列表
   
   详见 `doc/SQLMap参数支持进度.md` 获取所有 215 个参数的详细列表和分类。
   
   #### 重点参数说明
   
   **--answers 参数（预定义答案）**:
   ```bash
   --answers="quit=N,follow=N,extending=N"
   ```
   用于在非交互式扫描中预定义 SQLMap 询问的答案，实现自动化扫描。
   
   **常见参数组合**:
   
   - **基础扫描**:
     ```bash
     --batch --level=1 --risk=1
     ```
   
   - **深度扫描**:
     ```bash
     --batch --level=5 --risk=3 --technique=BEUSTQ
     ```
   
   - **高级请求配置**:
     ```bash
     --method=POST --data="id=1" --cookie="session=abc123"
     --headers="X-Custom-Header: value" --random-agent
     ```
   
   - **代理和认证**:
     ```bash
     --proxy="http://127.0.0.1:8080" --auth-type=Basic
     --auth-cred="user:pass"
     ```
   
   - **枚举数据**:
     ```bash
     --batch --dbs --tables --columns --dump
     -D=testdb -T=users -C=id,password
     ```
   
   - **导出配置**:
     ```bash
     --dump-format=CSV --csv-del=";" --output-dir="/tmp/scan_results"
     ```
   
   #### 限制说明
   
   **已排除的参数**:
   - `-r` (`--requestFile`): 由 Web UI 通过 HTTP 请求文件功能处理，不通过命令行参数传递
   
   **SQLMap RESTAPI 限制**:
   以下参数由 SQLMap RESTAPI 限制，在 Burp 插件中会显示为置灰不可用：
   - `sqlShell` (`--sql-shell`): 交互式 SQL shell
   - `wizard` (`--wizard`): 向导模式
   
   **安全警告**:
   以下参数会在 UI 中显示明显的安全警告标识（⚠️）：
   
   - **严重** (🚫 红色): 可远程执行系统命令或修改注册表，风险极高
     - `osCmd`, `osPwn`, `osSmb`, `osBof`, `regRead`, `regAdd`, `regDel`
   
   - **高危** (⚠️ 橙色): 可访问操作系统或提升权限
     - `osShell`, `privEsc`
   
   - **中危** (⚠️ 橙色): 可访问文件系统
     - `fileRead`, `fileWrite`, `fileDest`
   
   **使用建议**:
   - 仅在授权的测试环境中使用危险参数
   - 了解潜在的安全风险和法律法规要求
   - 建议先在隔离环境中测试
   
   #### 常见问题解答
   
   **Q: 为什么某些参数显示为置灰不可用？**
   A: 这些参数由 SQLMap RESTAPI 限制，无法通过 API 调用。如需使用这些参数，请使用命令行版本的 SQLMap。
   
   **Q: 如何使用 --answers 参数？**
   A: --answers 参数用于预定义 SQLMap 在扫描过程中的答案，实现非交互式自动化扫描。
   
   **Q: 如何配置代理？**
   A: 使用 --proxy 参数指定代理服务器，支持 HTTP/HTTPS/SOCKS 代理。
   
   **Q: 危险参数有风险吗？**
   A: 危险参数（如 os-cmd）允许远程执行系统命令，请确保：1. 仅在授权测试环境中使用；2. 了解潜在的安全风险；3. 遵守相关法律法规。
   
   ### VulnShop Lab
- 8 SQL injection vulnerability types
- 3 WAF difficulty levels (Easy/Medium/Hard)
- Light/Dark theme support
- One-click database reset

## Development Commands

### Backend
```bash
cd src/backEnd
uv sync --extra thirdparty    # Install dependencies
uv run python main.py         # Start server (port 8775)
```

### Frontend
```bash
cd src/frontEnd
pnpm install                  # Install dependencies
pnpm run dev                  # Development mode (port 5173)
pnpm run build                # Build to backend static directory
```

### VulnShop Lab
```bash
cd src/vulnTestServer
pip install flask
python server.py              # Start server (port 9527)
```

### Burp Suite Plugins
```bash
cd src/burpEx/montoya-api     # or legacy-api
mvn clean package -DskipTests
# Output: target/*.jar
```

## Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Frontend Dev | 5173 | Vite development server |
| Backend API | 8775 | FastAPI service |
| VulnShop Lab | 9527 | Vulnerability testing environment |

## Coding Standards

### Python (Backend)
- Use type hints for all function parameters and returns
- Follow PEP 8 style guidelines
- Use async/await for I/O operations in FastAPI
- Models use Pydantic for validation
- Service classes are singletons

### TypeScript (Frontend)
- Strict TypeScript mode enabled
- Use Composition API with `<script setup>`
- State management through Pinia stores
- PrimeVue components for UI consistency
- Use computed properties for derived data

### Java (Burp Plugins)
- Legacy API: Java 11 compatibility
- Montoya API: Java 17+ required
- Use Maven Shade/Assembly for fat JAR packaging

## API Design Patterns

### Backend Routes Structure
```python
# Route registration in app.py
app.include_router(router, prefix="/api/xxx", tags=["Module Name"])

# Response format
class BaseResponseMsg:
    code: int      # 0 = success, non-zero = error
    msg: str       # Message description
    data: Any      # Response payload
```

### Frontend API Calls
```typescript
// API functions in src/api/*.ts
export const fetchData = async (params: RequestParams): Promise<ResponseType> => {
  const response = await axios.get('/api/endpoint', { params })
  return response.data
}
```

### Header Rules API Endpoints
```
GET    /commonApi/header/persistent-header-rules     # List all rules
GET    /commonApi/header/persistent-header-rules/:id # Get single rule
POST   /commonApi/header/persistent-header-rules     # Create rule
PUT    /commonApi/header/persistent-header-rules/:id # Update rule
DELETE /commonApi/header/persistent-header-rules/:id # Delete rule
POST   /commonApi/header/session-headers             # Set session headers
GET    /commonApi/header/session-headers             # Get session headers
DELETE /commonApi/header/session-headers             # Clear session headers
POST   /commonApi/header/header-processing/preview   # Preview header processing
```

### Scan Preset API Endpoints
```
GET    /commonApi/scanPreset/list          # List all presets
GET    /commonApi/scanPreset/:id           # Get single preset
POST   /commonApi/scanPreset               # Create preset
PUT    /commonApi/scanPreset/:id           # Update preset
DELETE /commonApi/scanPreset/:id           # Delete preset
GET    /commonApi/scanPreset/default       # Get default config
PUT    /commonApi/scanPreset/default       # Update default config
```

## Git Workflow

### Commit Message Format (Conventional Commits)
```
feat: add new feature
fix: fix a bug
perf: performance improvement
refactor: code refactoring
docs: documentation update
test: add tests
chore: maintenance tasks
ci: CI/CD changes
```

### Release Process
1. Create version tag: `git tag v1.x.x`
2. Push code: `git push origin master`
3. Push tags: `git push origin --tags`
4. For automated release: `git tag release-v1.x.x && git push origin release-v1.x.x`

### GitHub Actions
Automatic build and release is triggered when pushing tags matching:
- `release-v[0-9]+.[0-9]+.[0-9]+*`
- `v[0-9]+.[0-9]+.[0-9]+-release*`
- `release/v[0-9]+.[0-9]+.[0-9]+*`

Release artifacts:
- `sqlmapwebui-{version}.zip` - Backend with integrated frontend
- `sqlmap-webui-burp-montoya-{version}.jar` - Burp Montoya plugin
- `sqlmap-webui-burp-legacy-{version}.jar` - Burp Legacy plugin
- `vulnTestServer-{version}.zip` - Vulnerability lab

## Common Tasks

### Adding a New API Endpoint
1. Create route handler in `src/backEnd/api/` module
2. Register router in `app.py`
3. Add frontend API function in `src/frontEnd/src/api/`
4. Update TypeScript types if needed

### Adding a New Frontend Page
1. Create component in `src/frontEnd/src/views/`
2. Add route in router configuration
3. Use PrimeVue components for consistent UI
4. Add state management in Pinia store if needed

### Adding Header Rule with Scope
1. Backend: Rule with scope field (optional, null = global)
2. Frontend: Use ScopeConfigPanel component
3. Scope supports: protocol, host, port, path patterns
4. Scope matching uses AND logic for all configured fields

### Modifying VulnShop Lab
1. Backend logic in `server.py` route handlers
2. Database operations in `database.py`
3. WAF rules in `waf.py`
4. Frontend in `static/` directory
5. Support both light and dark themes

## Important Notes

### Security Considerations
- This tool is for authorized security testing only
- VulnShop binds to 127.0.0.1 only - never expose to public network
- Do not use SNAPSHOT versions in releases

### Build Configuration
- Frontend builds to `src/backEnd/static/`
- Gzip compression enabled
- Code splitting: vendor, primevue, utils chunks

### Cross-Origin Configuration
Backend allows CORS from:
- `localhost:5173-5176` (frontend dev)
- `localhost:8775` (backend)

### Database
- Task data stored in memory (DataStore singleton)
- Header rules stored in SQLite (`header_rules.db`)
- Automatic database migration for schema changes

### Thread Safety (Important)
- `DataStore.tasks_lock` is a `threading.Lock` (synchronous)
- In async functions, use `run_in_executor` with `ThreadPoolExecutor` to avoid blocking event loop
- Never use `with tasks_lock:` directly in async functions
- Task operations use thread pool pattern for safe concurrent access

## File Dependencies

### Backend Entry Point
`main.py` → configures SQLMap import paths → imports `app.py`

### Frontend Build Output
`src/frontEnd/dist/` → copied to `src/backEnd/static/`

### SQLMap Integration
`src/backEnd/third_lib/sqlmap/` is a git submodule - update with:
```bash
git submodule update --remote
```

## Testing

### Backend Tests
```bash
cd src/backEnd
python -m pytest tests/
```

Test files:
- `test_scope_matcher.py` - Scope matching logic tests
- `test_header_processor_scope.py` - Header processor tests
- `test_api_endpoints.py` - API endpoint tests

### Frontend Development
```bash
cd src/frontEnd
pnpm run dev      # Start with hot reload
pnpm run lint     # Run linter
pnpm run build    # Build production
```
