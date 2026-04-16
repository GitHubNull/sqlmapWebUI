# SQLMap Web UI

<p align="center">
  <img src="src/frontEnd/public/logo.svg" alt="SQLMap WebUI Logo" width="120" height="120">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Vue-3.x-green.svg" alt="Vue">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-red.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.8.53-orange.svg" alt="Version">
</p>

<p align="center">
  <a href="README.md">中文</a> | <b>English</b>
</p>

<p align="center">
  <a href="doc/USAGE_GUIDE_EN.md">📖 User Guide</a> | 
  <a href="doc/USAGE_GUIDE.md">📖 中文指南</a> | 
  <a href="#-quick-start">🚀 Quick Start</a> | 
  <a href="#-changelog">📝 Changelog</a>
</p>

A modern SQLMap web interface that provides a convenient SQL injection testing platform for security researchers. **Built-in VulnShop Lab** for hands-on practice.

## 🌟 Core Features

### SQL Injection Scanning Platform
- **Task Management**: Create, monitor, and stop SQL injection scanning tasks
- **Real-time Logs**: View real-time log output during task execution
- **Scan Results**: Intuitive display of injection points and payload information
- **HTTP Request Viewer**: Complete display of raw HTTP request information
- **Enhanced Task List**:
  - Multi-dimensional filtering (URL/message keywords, status, date range, injection status)
  - Multi-field sorting (Task ID, status, creation time)
  - Summary statistics row (real-time task statistics display)
  - Smart polling (automatically adjusts refresh frequency based on task status)

### Scan Configuration Management 🆕
- **Default Configuration**: Set global default scan parameters
- **Preset Configurations**: Save commonly used configuration combinations with full CRUD support
- **History Configurations**: View configurations used in past scans
- **Guided Editor**: Visually configure SQLMap parameters without memorizing command line
- **Parameter Preview**: Real-time preview of generated command line parameters

### HTTP Request Parsing 🆕
- Support for automatic parsing of multiple request formats:
  - cURL (Bash/CMD)
  - PowerShell Invoke-WebRequest
  - JavaScript fetch
  - Raw HTTP message
- **Smart Format Detection**: Automatically identify input format
- **Code Editor**: Line numbers, syntax highlighting, search filter

### Batch Operations
- **Batch Stop**: Stop multiple running tasks at once
- **Batch Delete**: Delete completed or failed tasks in bulk
- **Batch Import**: Support batch import of HTTP requests to create scan tasks
- **Select All/Deselect**: Convenient task selection operations

### Header Rules Management
- **Persistent Rules**: Create long-term header rules with full CRUD support
- **Session-level Rules**: Set temporary headers with TTL auto-expiration
- **Scope Configuration**: Flexible URL matching rules
  - Protocol matching (http/https)
  - Hostname matching (supports wildcards `*.example.com`)
  - Port matching (supports multiple ports `80,443,8080`)
  - Path matching (supports wildcards `/api/*`)
  - Regular expression matching
- **Priority Control**: Support 0-100 priority settings
- **Replace Strategies**: Full replace, append, conditional replace, and more
- **Batch Import**: Support importing headers from text in bulk

### Extension Integration
- **Burp Suite Plugin**: Supports both Legacy API and Montoya API versions
  - Right-click menu to send requests to backend server
  - Right-click menu to execute SQLMap scan directly (local terminal execution)
  - Configurable scan parameters (Level, Risk, DBMS, Technique)
  - Default configuration and saved presets management
  - Command preview and copy to clipboard
  - Terminal window title customization rules
  - Configuration import/export functionality
  - Activity logging

### VulnShop Vulnerability Lab 🎯
Built-in e-commerce platform simulation with 8 types of SQL injection vulnerabilities:

| Vulnerability Type | Endpoint | Description |
|-------------------|----------|-------------|
| Error-based | POST /api/user/login | Error-based injection |
| Union-based | GET /api/user/profile | Union query injection |
| Boolean-blind | GET /api/products/search | Boolean blind injection |
| Time-based | GET /api/products/detail | Time-based blind injection |
| Stacked Queries | GET /api/orders/query | Stacked queries injection |
| 2nd Order | POST /api/user/register | Second-order injection |

**Lab Features**:
- 🎨 Modern UI with light/dark theme toggle
- 🛒 Complete shopping flow: browse products, cart, checkout
- ⚙️ 3 difficulty levels (Easy/Medium/Hard) with WAF protection
- 🔄 One-click database reset
- 📱 Optimized for Chrome browser on PC

## Tech Stack

### Backend
- **FastAPI** - High-performance asynchronous web framework
- **SQLMap** - Automatic SQL injection detection tool
- **Python 3.10+** - Runtime environment
- **SQLite** - Database storage
- **uv** - Modern Python package manager

### Frontend
- **Vue 3** - Progressive JavaScript framework
- **TypeScript** - Type-safe JavaScript
- **PrimeVue** - Enterprise-grade UI component library
- **Pinia** - Vue state management
- **Vite** - Next-generation frontend build tool

### Extensions
- **Burp Suite Plugin**
  - Montoya API (Java 17+, Burp 2023.1+)
  - Legacy API (Java 11+)

## 🚀 Quick Start

### Requirements

- Python 3.10+
- Node.js 20+
- pnpm 9+
- Java 17+ (Burp Montoya API) or Java 11+ (Legacy API)

### Backend Installation

#### Method 1: Using Startup Script (Recommended)

```batch
# Windows
cd src\backEnd
start.bat

# Linux/macOS
cd src/backEnd && chmod +x start.sh && ./start.sh
```

The startup script supports configuring mirror sources, intranet environment, offline mode, etc. See `startup.conf` for details.

#### Method 2: Manual Startup

```bash
# Enter backend directory
cd src/backEnd

# Install dependencies using uv
uv sync --extra thirdparty

# Start service
uv run python main.py
```

### Frontend Installation

```bash
# Enter frontend directory
cd src/frontEnd

# Install dependencies
pnpm install

# Development mode
pnpm run dev

# Build production version
pnpm run build
```

### Start VulnShop Lab

```bash
# Enter lab directory
cd src/vulnTestServer

# Install dependencies (if not installed)
pip install flask

# Start server
python server.py
```

### Access Application

| Service | Address |
|---------|---------|
| Frontend Dev Server | http://localhost:5173 |
| Backend API Server | http://localhost:8775 |
| VulnShop Lab | http://127.0.0.1:9527 |

## 📁 Project Structure

```
sqlmapWebUI/
├── src/
│   ├── backEnd/                 # Backend code
│   │   ├── api/                 # API routes
│   │   │   ├── webApi/          # Web browser page API
│   │   │   ├── burpSuiteExApi/  # Burp Suite API
│   │   │   └── commonApi/       # Common API (auth/header rules/config)
│   │   ├── model/               # Data models
│   │   ├── service/             # Business logic
│   │   ├── utils/               # Utility functions
│   │   ├── third_lib/sqlmap/    # SQLMap integration
│   │   ├── app.py               # FastAPI application
│   │   └── main.py              # Entry point
│   ├── frontEnd/                # Frontend code
│   │   ├── src/
│   │   │   ├── api/             # API requests
│   │   │   ├── components/      # Common components
│   │   │   ├── stores/          # Pinia stores
│   │   │   ├── types/           # TypeScript types
│   │   │   ├── utils/           # Utility functions
│   │   │   └── views/           # Page views
│   │   └── vite.config.ts       # Vite configuration
│   ├── burpEx/                  # Burp Suite extensions
│   │   ├── legacy-api/          # Legacy API (Java 11)
│   │   └── montoya-api/         # Montoya API (Java 17)
│   └── vulnTestServer/          # VulnShop vulnerability lab
│       ├── static/              # Frontend static assets
│       ├── server.py            # HTTP server
│       ├── database.py          # Database management
│       └── waf.py               # WAF module
└── doc/                         # Project documentation
```

## 📖 Usage Guide

### Create Scan Task

1. Click "New Task" on the task list page
2. Enter target URL or import HTTP request
3. Configure scan parameters (optional)
4. Click "Start Scan"

### Using VulnShop Lab

1. Start lab server: `python server.py`
2. Visit http://127.0.0.1:9527 in your browser
3. Login with test accounts (admin/admin123 or test/test)
4. Follow page prompts to test various injection types

### Burp Suite Integration

1. Build plugin: `mvn clean package -DskipTests`
2. Load JAR file in Burp Suite
3. Configure backend server address
4. Right-click request and select "Send to SQLMap WebUI"

### Header Rules Configuration

1. Go to "Config" → "Header Rules Management" tab
2. Click "Add Rule"
3. Fill in rule information:
   - Rule name, Header name, Header value
   - Replace strategy, Priority
   - Optional: Configure scope to limit effective range
4. Save the rule

### System Log Viewer

1. Go to "Config" page
2. Find "System Log Viewer" entry
3. Select log type (Application/Access/Error)
4. Set display lines and refresh to view

---

**📚 For detailed usage, please refer to [User Guide](doc/USAGE_GUIDE_EN.md)**

Includes complete feature descriptions, operation steps, configuration guides, and FAQ.

## 🔐 Security Notice

**Important**: This tool is for authorized security testing only.

- Only test on systems with explicit authorization
- Do not use on production or unauthorized systems
- VulnShop Lab binds to localhost only - never expose to public network

Please read the [Disclaimer](DISCLAIMER.md) before use.

## 📝 Changelog

> **Important**: The complete version history has been moved to a standalone document [CHANGELOG_EN.md](doc/CHANGELOG_EN.md).
>
> All future version updates will be maintained in that document. This README no longer includes detailed changelog.

**Latest Version**: v1.8.53 (2026-04-16)

- Reorganized Burp plugin architecture with layered structure
- Pure code reorganization, no functional changes, improved maintainability

**View Full Changelog**: [CHANGELOG_EN.md](doc/CHANGELOG_EN.md) | [中文更新日志](doc/CHANGELOG.md)


## 📄 License

This project is open sourced under the [MIT License](LICENSE).

## 🤝 Contributing

Issues and Pull Requests are welcome!

1. Fork this repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Submit Pull Request

## 🙏 Acknowledgments

- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Powerful SQL injection automation tool
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Vue.js](https://vuejs.org/) - Progressive JavaScript framework
- [PrimeVue](https://primevue.org/) - Vue UI component library
