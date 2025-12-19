# SQLMap Web UI

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Vue-3.x-green.svg" alt="Vue">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-red.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

<p align="center">
  <a href="README.md">中文</a> | <b>English</b>
</p>

A modern SQLMap web interface that provides a convenient SQL injection testing platform for security researchers.

## Features

- **Task Management**: Create, monitor, and stop SQL injection scanning tasks
- **Real-time Logs**: View real-time log output during task execution
- **Scan Results**: Intuitive display of injection points and payload information
- **HTTP Request Viewer**: Complete display of raw HTTP request information
- **Batch Operations**: Support batch import and management of scanning tasks
- **Extension Integration**: Support Chrome extension and Burp Suite plugin integration
- **Header Rules**: Flexible configuration of custom request header rules

## Tech Stack

### Backend
- **FastAPI** - High-performance asynchronous web framework
- **SQLMap** - Automatic SQL injection detection tool
- **Python 3.10+** - Runtime environment

### Frontend
- **Vue 3** - Progressive JavaScript framework
- **TypeScript** - Type-safe JavaScript
- **PrimeVue** - Enterprise-grade UI component library
- **Pinia** - Vue state management
- **Vite** - Next-generation frontend build tool

## Quick Start

### Requirements

- Python 3.10+
- Node.js 18+
- pnpm package manager

### Backend Installation

```bash
# Enter backend directory
cd src/backEnd

# Install dependencies with uv
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

# Build for production
pnpm run build
```

### Access Application

- Frontend dev server: http://localhost:5173
- Backend API server: http://localhost:8775

## Project Structure

```
sqlmapWebUI/
├── src/
│   ├── backEnd/                 # Backend code
│   │   ├── api/                 # API routes
│   │   │   ├── chromeExApi/     # Chrome extension API
│   │   │   ├── burpSuiteExApi/  # Burp Suite API
│   │   │   └── commonApi/       # Common API
│   │   ├── model/               # Data models
│   │   ├── service/             # Business logic
│   │   ├── utils/               # Utility functions
│   │   ├── third_lib/sqlmap/    # SQLMap integration
│   │   ├── app.py               # FastAPI application
│   │   └── main.py              # Entry point
│   └── frontEnd/                # Frontend code
│       ├── src/
│       │   ├── api/             # API requests
│       │   ├── components/      # Common components
│       │   ├── stores/          # Pinia stores
│       │   ├── types/           # TypeScript types
│       │   ├── utils/           # Utility functions
│       │   └── views/           # Page views
│       └── vite.config.ts       # Vite configuration
└── doc/                         # Documentation
```

## Usage Guide

### Create Scan Task

1. Click "New Task" on the task list page
2. Enter target URL or import HTTP request
3. Configure scan parameters (optional)
4. Click "Start Scan"

### View Task Results

1. Click the target task in the task list
2. View basic info, HTTP request, scan configuration
3. View scan results and injection payloads
4. View real-time task logs

### Extension Integration

#### Chrome Extension
Send browser requests directly to the scanning platform via Chrome extension.

#### Burp Suite Plugin
Send intercepted requests to the scanning platform via Burp Suite plugin.

## Security Notice

**Important**: This tool is for authorized security testing only.

Please read the [Disclaimer](DISCLAIMER.md) before use.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Issues and Pull Requests are welcome!

1. Fork this repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Submit Pull Request

## Acknowledgments

- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Powerful SQL injection automation tool
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Vue.js](https://vuejs.org/) - Progressive JavaScript framework
- [PrimeVue](https://primevue.org/) - Vue UI component library
