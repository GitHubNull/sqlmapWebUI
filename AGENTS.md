# AGENTS.md

This file provides guidance to AI coding assistants when working with this repository.

## Project Overview

SQLMap Web UI is a comprehensive SQL injection testing platform that includes:
- **Main Application**: FastAPI backend + Vue 3 frontend web interface
- **VulnShop Lab**: Built-in vulnerability testing environment
- **Browser Extensions**: Chrome extension and Burp Suite plugins

## Project Structure

```
sqlmapWebUI/
├── src/
│   ├── backEnd/           # FastAPI backend service (Python 3.13+)
│   │   ├── api/           # API routes
│   │   │   ├── chromeExApi/      # Chrome extension API
│   │   │   ├── burpSuiteExApi/   # Burp Suite plugin API
│   │   │   └── commonApi/        # Common APIs (auth, headers)
│   │   ├── model/         # Data models
│   │   ├── service/       # Business logic layer
│   │   ├── utils/         # Utility functions
│   │   ├── third_lib/sqlmap/     # SQLMap integration (git submodule)
│   │   ├── app.py         # FastAPI application core
│   │   └── main.py        # Entry point
│   ├── frontEnd/          # Vue 3 frontend (TypeScript + Vite)
│   │   └── src/
│   │       ├── api/       # API request functions
│   │       ├── components/# Shared components
│   │       ├── stores/    # Pinia state management
│   │       ├── types/     # TypeScript type definitions
│   │       ├── utils/     # Utility functions
│   │       └── views/     # Page views
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
| Backend | Python 3.13+, FastAPI, SQLMap, SQLite |
| Frontend | Vue 3, TypeScript, PrimeVue, Pinia, Vite |
| Burp Plugins | Java 11 (Legacy), Java 17 (Montoya) |
| Package Managers | uv (Python), pnpm (Node.js), Maven (Java) |

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

### TypeScript (Frontend)
- Strict TypeScript mode enabled
- Use Composition API with `<script setup>`
- State management through Pinia stores
- PrimeVue components for UI consistency

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
