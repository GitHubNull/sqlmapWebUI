# SQLMap Web UI

<p align="center">
  <img src="src/frontEnd/public/logo.svg" alt="SQLMap WebUI Logo" width="120" height="120">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Vue-3.x-green.svg" alt="Vue">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-red.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.8.51-orange.svg" alt="Version">
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

### v1.8.51 (2026-04-16)

**Fixes (Burp Plugin)**
- Fixed SQLMap `-r` mode incorrectly treating GET as POST due to trailing newlines in HTTP request files generated by Burp plugins
- Added defensive trailing newline cleanup logic in both Montoya API and Legacy API plugins

### v1.8.49 (2026-03-27)

**Documentation**
- Comprehensive update of project documentation to reflect latest features
- Updated README version numbers and changelogs in both Chinese and English
- Updated user guide with Burp plugin command execution configuration details
- Updated frontend About page version number
- Updated Burp plugin help documentation

### v1.8.48 (2026-03-27)

**Fixes (CI/CD)**
- Fixed GitHub Actions build Burp Legacy plugin `maven-clean-plugin:3.2.0` download 403 Forbidden error
- Explicitly declared `maven-clean-plugin:3.4.0` in both Burp plugin pom.xml files

**New Features (Burp Plugin)**
- Added command execution configuration, support direct SQLMap scan execution in terminal
- Added terminal window title rule configuration, support custom title extraction rules
- Added command preview dialog, real-time preview of generated SQLMap commands
- Added configuration import/export functionality for easy backup and sharing

### v1.8.47 (2026-03-26)

**Fixes (Scan Tasks)**
- Fixed proxy connection timeout issue when submitting scans via Burp plugin
- Root cause: `apply_header_rules()` wrote all request headers to sqlmap config file's `headers` option, conflicting with request file (`-r`) headers
- Now headers are only passed through request file, consistent with command line execution behavior

### v1.8.46 (2026-03-26)

**Fixes (Scan Tasks)**
- Fixed XML body truncation issue (Windows line endings causing Content-Length mismatch)
- Removed Content-Length header, allowing sqlmap to auto-calculate based on actual body
- Use binary mode to write request files, avoiding Windows automatic line ending conversion
- Normalized body line endings to standard HTTP line endings

**Improvements (Burp Plugin)**
- Replaced manual JSON string concatenation with Gson/PayloadBuilder
- Eliminated risks of incomplete escaping for special characters (e.g., XML content)

### v1.8.45 (2026-03-26)

**New Features (VulnShop Lab)**
- Added logistics management module, support order shipping and tracking
- Added shipping_handlers for logistics-related requests
- Updated database structure, added logistics information table
- Updated frontend interface, added logistics management page and styles

**Fixes**
- Fixed task_monitor.py related issues
- Removed deprecated req.txt file

### v1.8.44 (2026-03-26)

**New Features (Burp Plugin)**
- Added command execution configuration, support custom SQLMap command execution methods
- Added command execution configuration panel with visual configuration interface
- Added command execution help dialog with detailed configuration instructions
- Added request title extraction, support extracting custom titles from requests
- Added title rule management, support creating, editing, deleting title extraction rules
- Added title rule test dialog, support real-time testing of rule effects
- Added command preview dialog, support previewing generated SQLMap commands
- Added direct execution configuration panel, support one-click scan execution

**Refactoring (Burp Plugin)**
- Removed deprecated clipboard configuration panel, replaced with more flexible command execution configuration
- Refactored command executor to support configurable command execution
- Refactored SQL command builder to enhance command building capabilities
- Refactored title extractor to support multiple title source types and regex matching

**Improvements (Burp Plugin)**
- Optimized context menu integration, providing richer scan options
- Improved configuration manager to support more configuration types
- Optimized preset configuration database to support title rule storage

### v1.8.41 (2026-02-28)

**Documentation**
- Fully refactored frontend help page with modular design (8 components, <700 lines per file)
- Added complete bilingual user guide (Chinese/English)
- Updated Burp Suite plugin help documentation
- Optimized README document structure and navigation links

### v1.8.40 (2026-02-28)

**New Features**
- VulnShop frontend page visual design fully improved
- Added system log viewer function, supporting Application/Access/Error log switching
- Log viewer supports custom display line count (50/100/200/500 lines)

**Fixes**
- Fixed "View Logs" function not responding when clicked
- Optimized log display interface and interaction experience

### v1.8.39 (2026-02-28)

**Fixes**
- Fixed scanPresetService return value unpacking issue

### v1.8.38 (2026-02-27)

**New Features**
- History config table added sorting function (support sorting by ID, command line params, last used time, usage count)
- History config table added pagination function (support selecting items per page)
- History config cards display ID identifier

### v1.8.37 (2026-02-27)

**Fixes**
- Burp plugin auto-refreshes history config table after task creation

### v1.8.36 (2026-02-27)

**New Features**
- Burp plugin auto-saves to history config after creating tasks

**Improvements**
- Improved history config deduplication logic, only updates usage time when same name and params

### v1.8.35 (2026-02-27)

**Fixes**
- Fixed frontend build failure caused by TypeScript unused variable warnings (TS6133)

### v1.8.34 (2026-02-27)

**Refactoring**
- GuidedParamEditor component refactored to modular architecture
- CustomModePanel optimized, added scanOptionsConverter utility

### v1.8.33 (2026-02-26)

**New Features**
- Command line preview component adopts GitHub Dark theme style, added terminal window style

**Improvements**
- Burp plugins (Montoya & Legacy) version synchronized to 1.8.33

### v1.8.32 (2026-02-26)

**Fixes**
- Fixed randomAgent parameter not taking effect

### v1.8.30 (2026-02-26)

**New Features**
- Added tick marks to auto-refresh interval slider in config page (major ticks every 5 minutes, minor ticks every 1 minute)

### v1.8.29 (2026-02-26)

**Fixes**
- Fixed dark theme adaptation issue for config trigger bar in AddTask page

### v1.8.28 (2026-02-26)

**Fixes**
- Fixed HTTP Host header non-default port being incorrectly removed

### v1.8.27 (2026-02-26)

**Refactoring**
- AddTask page split into modular components (ConfigTriggerBar, CustomModePanel, PresetModePanel, etc.)

### v1.8.19-v1.8.26 (2026-02)

**New Features**
- Support parsing all SQLMap command line parameters (215 params)
- Frontend refactored to PrimeVue 4 clean theme
- Session Header management component modularized

**Improvements**
- Optimized frontend styles and component layouts
- Unified homepage and config page background panel width
- Fixed task list dropdown text truncation issue

**Fixes**
- Fixed white background issues on multiple pages in dark mode
- Fixed Burp plugin parameter parsing and backend parameter display issues
- Fixed Burp plugin JSON requests being misjudged as binary

### v1.8.13-v1.8.18 (2025-12)

**New Features**
- Added file sync script supporting dual API architecture
- Added architecture documentation explaining dual API design

**Fixes**
- Fixed guided parameter editor parameter display and loading issues
- Fixed TypeScript type errors and SCSS variables

### v1.8.12 (2025-12-24)

**Fixes**
- Fixed cURL (Windows CMD) parsing not removing escape character `^` before Chinese characters
- Fixed HTTP message editor long lines stretching container, added soft wrap support

### v1.8.11 (2025-12-24)

**Fixes**
- Fixed Burp plugin (Legacy/Montoya) Chinese garbled text, forced UTF-8 encoding for HTTP requests

### v1.8.10 (2025-12-24)

**Fixes**
- Fixed task log area unable to scroll to display all logs

### v1.8.9 (2025-12-23)

**Fixes**
- Fixed Burp plugin right-click menu scan config source selection not taking effect

### v1.8.8 (2025-12-23)

**Fixes**
- Fixed session Header and Body field configuration not taking effect

### v1.8.7 (2025-12-22)

**Fixes**
- URL parsing excludes port from host field for cross-platform consistency

**Improvements**
- Optimized homepage statistic card sizes

### v1.8.1-v1.8.6 (2025-12)

**New Features**
- Added session Body field dynamic replacement function
- VulnShop lab added logging system
- VulnShop lab modular refactoring and security enhancement

**Improvements**
- Improved VulnShop lab robustness, prevents crashes during SQLMap scanning
- Adjusted task list empty data area height
- API prefix renamed (/chrome/admin → /web/admin)

### v1.8.0 (2025-12)

**New Features**
- Added backend service startup scripts (Windows/Linux/macOS)
- Support automatic creation and reuse of virtual environments
- Support configuring PyPI mirrors (Tsinghua/Aliyun/USTC, etc.)
- Support intranet private mirror configuration
- Support fully offline environment deployment
- Added WebSocket real-time notification mechanism, backend can actively push task status changes
- Added confirmation dialogs for delete and stop operations on task list page

**Improvements**
- Optimized task operation thread safety, moved sync lock operations to thread pool to avoid blocking event loop
- Optimized scan config preset selection UI
- Improved submit button disabled logic and prompt messages
- Python minimum version requirement adjusted to 3.10+

**Fixes**
- Solved Windows/Linux command line Chinese garbled text issues
- Fixed refresh interval API response data structure handling error
- Added backend service disclaimer document

### v1.7.9 (2025-12)
- Added project Logo design (shield + injection needle concept)
- Web: Updated favicon, status bar, about page Logo
- BurpSuite plugin: Added help/about dialog (includes usage help, open source license, disclaimer)
- BurpSuite plugin: About page uses Java2D to draw custom Logo
- Fixed PrimeVue 4 component deprecation warnings (TabView → Tabs)
- Fixed BurpSuite plugin JLabel HTML rendering issues
- Updated project documentation adding Logo display

### v1.7.7 (2025-12)
- Updated all project documents to reflect latest features
- Improved AGENTS.md and CLAUDE.md AI programming guides
- Optimized user usage guide documentation

### v1.7.6 (2025-12)
- Added scan config preset management (default/preset/history configs)
- Added guided parameter editor
- Added HTTP request parser (supports cURL/PowerShell/fetch/raw HTTP)
- Added code editor component (line numbers, syntax highlighting, search)
- Frontend code modular refactoring
- Fixed fetch parser escaped quote handling issues

### v1.6.0 (2025-12)
- Added header rules scope configuration function
- Added session-level header management
- Added batch header rules import function
- Added summary statistics row to task list
- Enhanced task filters (date range, injection status)
- Optimized smart polling strategy
- Updated project documentation

### v1.5.1 (2025-12)
- Updated project documentation
- Improved Burp Suite plugin integration
- Fixed backend configuration issues

### v1.5.0 (2025-12)
- Added VulnShop SQL injection testing lab
- Support 8 types of SQL injection vulnerabilities
- Modern UI with light/dark theme
- Complete shopping flow simulation
- 3 difficulty levels and WAF protection

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
