@echo off
REM ============================================================
REM SQLMap Web UI 后端服务启动脚本 (Windows)
REM Backend Service Startup Script (Windows)
REM ============================================================

setlocal EnableDelayedExpansion

REM 切换到脚本所在目录
cd /d "%~dp0"

REM ============================================================
REM 编码设置 - 解决中文乱码问题
REM ============================================================
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

REM ============================================================
REM 颜色定义（使用 ANSI 转义序列）
REM ============================================================
for /F %%a in ('echo prompt $E^| cmd') do set "ESC=%%a"
set "GREEN=%ESC%[32m"
set "YELLOW=%ESC%[33m"
set "RED=%ESC%[31m"
set "CYAN=%ESC%[36m"
set "RESET=%ESC%[0m"

REM ============================================================
REM 默认配置
REM ============================================================
set "NETWORK_MODE=online"
set "PYPI_MIRROR=tsinghua"
set "PRIVATE_MIRROR_URL="
set "PRIVATE_MIRROR_AUTH="
set "PRIVATE_MIRROR_TRUSTED_HOSTS="
set "PYTHON_PATH="
set "VENV_DIR=.venv"
set "HOST=127.0.0.1"
set "PORT=8775"
set "ADMIN_USERNAME=admin"
set "ADMIN_PASSWORD=admin"
set "CONSOLE_ENCODING="
set "FORCE_UTF8=true"
set "DEBUG=false"
set "LOG_LEVEL=INFO"
set "SKIP_DEPS_CHECK=false"

REM ============================================================
REM 加载配置文件
REM ============================================================
if exist "startup.conf" (
    echo %CYAN%[INFO]%RESET% Loading configuration from startup.conf...
    for /f "usebackq tokens=1,* delims==" %%a in ("startup.conf") do (
        set "line=%%a"
        if not "!line:~0,1!"=="#" (
            if not "%%b"=="" (
                set "%%a=%%b"
            )
        )
    )
)

REM ============================================================
REM PyPI 镜像 URL 映射
REM ============================================================
set "MIRROR_URL="
if /i "%PYPI_MIRROR%"=="tsinghua" set "MIRROR_URL=https://pypi.tuna.tsinghua.edu.cn/simple"
if /i "%PYPI_MIRROR%"=="aliyun" set "MIRROR_URL=https://mirrors.aliyun.com/pypi/simple/"
if /i "%PYPI_MIRROR%"=="ustc" set "MIRROR_URL=https://pypi.mirrors.ustc.edu.cn/simple/"
if /i "%PYPI_MIRROR%"=="douban" set "MIRROR_URL=https://pypi.doubanio.com/simple/"
if /i "%PYPI_MIRROR%"=="huawei" set "MIRROR_URL=https://mirrors.huaweicloud.com/repository/pypi/simple/"
if /i "%PYPI_MIRROR%"=="tencent" set "MIRROR_URL=https://mirrors.cloud.tencent.com/pypi/simple/"
if /i "%PYPI_MIRROR%"=="pypi" set "MIRROR_URL=https://pypi.org/simple/"

REM ============================================================
REM 显示启动信息
REM ============================================================
echo.
echo %CYAN%============================================================%RESET%
echo %CYAN%  SQLMap Web UI - Backend Service%RESET%
echo %CYAN%============================================================%RESET%
echo.
echo %GREEN%[CONFIG]%RESET% Network Mode: %NETWORK_MODE%
if /i "%NETWORK_MODE%"=="online" (
    echo %GREEN%[CONFIG]%RESET% PyPI Mirror: %PYPI_MIRROR% ^(%MIRROR_URL%^)
)
if /i "%NETWORK_MODE%"=="intranet" (
    echo %GREEN%[CONFIG]%RESET% Private Mirror: %PRIVATE_MIRROR_URL%
)
if /i "%NETWORK_MODE%"=="offline" (
    echo %YELLOW%[CONFIG]%RESET% Offline Mode - Using local cache only
)
echo.

REM ============================================================
REM 检测 Python 可执行文件
REM ============================================================
set "PYTHON_CMD="

if not "%PYTHON_PATH%"=="" (
    if exist "%PYTHON_PATH%" (
        set "PYTHON_CMD=%PYTHON_PATH%"
        echo %GREEN%[INFO]%RESET% Using configured Python: %PYTHON_PATH%
    ) else (
        echo %RED%[ERROR]%RESET% Configured Python not found: %PYTHON_PATH%
        goto :check_system_python
    )
) else (
    :check_system_python
    REM 尝试使用 py launcher (Windows)
    py --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_CMD=py"
        echo %GREEN%[INFO]%RESET% Using Python Launcher ^(py^)
    ) else (
        REM 尝试使用 python3
        python3 --version >nul 2>&1
        if !errorlevel! equ 0 (
            set "PYTHON_CMD=python3"
            echo %GREEN%[INFO]%RESET% Using python3
        ) else (
            REM 尝试使用 python
            python --version >nul 2>&1
            if !errorlevel! equ 0 (
                set "PYTHON_CMD=python"
                echo %GREEN%[INFO]%RESET% Using python
            ) else (
                echo %RED%[ERROR]%RESET% Python not found! Please install Python 3.10+
                echo %YELLOW%[HINT]%RESET% Download from: https://www.python.org/downloads/
                pause
                exit /b 1
            )
        )
    )
)

REM 验证 Python 版本
for /f "tokens=2 delims= " %%v in ('%PYTHON_CMD% --version 2^>^&1') do set "PY_VERSION=%%v"
echo %GREEN%[INFO]%RESET% Python version: %PY_VERSION%

REM ============================================================
REM 检测 uv 包管理器
REM ============================================================
set "UV_AVAILABLE=false"
uv --version >nul 2>&1
if %errorlevel% equ 0 (
    set "UV_AVAILABLE=true"
    echo %GREEN%[INFO]%RESET% uv package manager detected
)

REM ============================================================
REM 创建/激活虚拟环境
REM ============================================================
echo.
echo %CYAN%[STEP 1]%RESET% Setting up virtual environment...

if not exist "%VENV_DIR%" (
    echo %YELLOW%[INFO]%RESET% Creating virtual environment: %VENV_DIR%
    
    if "%UV_AVAILABLE%"=="true" (
        uv venv "%VENV_DIR%"
    ) else (
        %PYTHON_CMD% -m venv "%VENV_DIR%"
    )
    
    if !errorlevel! neq 0 (
        echo %RED%[ERROR]%RESET% Failed to create virtual environment
        pause
        exit /b 1
    )
    echo %GREEN%[OK]%RESET% Virtual environment created
) else (
    echo %GREEN%[OK]%RESET% Virtual environment exists: %VENV_DIR%
)

REM 激活虚拟环境
echo %CYAN%[INFO]%RESET% Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Failed to activate virtual environment
    pause
    exit /b 1
)
echo %GREEN%[OK]%RESET% Virtual environment activated

REM ============================================================
REM 安装依赖
REM ============================================================
echo.
echo %CYAN%[STEP 2]%RESET% Installing dependencies...

REM 检查是否跳过依赖安装
if /i "%SKIP_DEPS_CHECK%"=="true" (
    echo %YELLOW%[INFO]%RESET% Skipping dependency check ^(SKIP_DEPS_CHECK=true^)
    goto :start_service
)

if /i "%NETWORK_MODE%"=="offline" (
    echo %YELLOW%[INFO]%RESET% Offline mode - Skipping dependency installation
    echo %YELLOW%[HINT]%RESET% Make sure dependencies are pre-installed in the virtual environment
    goto :start_service
)

REM 构建 pip/uv 参数
set "EXTRA_ARGS="

if /i "%NETWORK_MODE%"=="online" (
    if not "%MIRROR_URL%"=="" (
        if "%UV_AVAILABLE%"=="true" (
            set "EXTRA_ARGS=--index-url %MIRROR_URL%"
        ) else (
            set "EXTRA_ARGS=-i %MIRROR_URL% --trusted-host !MIRROR_URL:~8,-7!"
        )
    )
)

if /i "%NETWORK_MODE%"=="intranet" (
    if not "%PRIVATE_MIRROR_URL%"=="" (
        if "%UV_AVAILABLE%"=="true" (
            set "EXTRA_ARGS=--index-url %PRIVATE_MIRROR_URL%"
        ) else (
            set "EXTRA_ARGS=-i %PRIVATE_MIRROR_URL%"
            if not "%PRIVATE_MIRROR_TRUSTED_HOSTS%"=="" (
                for %%h in (%PRIVATE_MIRROR_TRUSTED_HOSTS:,= %) do (
                    set "EXTRA_ARGS=!EXTRA_ARGS! --trusted-host %%h"
                )
            )
        )
    ) else (
        echo %RED%[ERROR]%RESET% Intranet mode requires PRIVATE_MIRROR_URL configuration
        pause
        exit /b 1
    )
)

REM 安装依赖
if "%UV_AVAILABLE%"=="true" (
    echo %CYAN%[INFO]%RESET% Installing with uv...
    uv sync --extra thirdparty %EXTRA_ARGS%
) else (
    echo %CYAN%[INFO]%RESET% Installing with pip...
    python -m pip install --upgrade pip %EXTRA_ARGS% >nul 2>&1
    
    REM 安装 pyproject.toml 中的依赖
    if exist "pyproject.toml" (
        python -m pip install -e ".[thirdparty]" %EXTRA_ARGS%
    ) else (
        echo %YELLOW%[WARN]%RESET% pyproject.toml not found, installing basic dependencies...
        python -m pip install fastapi[standard] apscheduler psutil %EXTRA_ARGS%
    )
)

if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Failed to install dependencies
    echo.
    echo %YELLOW%[POSSIBLE CAUSES]%RESET%
    echo   1. File locked by another process ^(IDE, previous service instance^)
    echo   2. Network connection issues
    echo   3. Mirror server unavailable
    echo.
    echo %YELLOW%[SOLUTIONS]%RESET%
    echo   - Close all Python processes and IDEs, then retry
    echo   - If dependencies are already installed, set SKIP_DEPS_CHECK=true in startup.conf
    if /i "%NETWORK_MODE%"=="online" (
        echo   - Try changing PYPI_MIRROR in startup.conf
    )
    if /i "%NETWORK_MODE%"=="intranet" (
        echo   - Check PRIVATE_MIRROR_URL configuration
    )
    pause
    exit /b 1
)
echo %GREEN%[OK]%RESET% Dependencies installed

REM ============================================================
REM 启动服务
REM ============================================================
:start_service
echo.
echo %CYAN%[STEP 3]%RESET% Starting SQLMap Web UI Backend Service...
echo.
echo %GREEN%============================================================%RESET%
echo %GREEN%  Service URL: http://%HOST%:%PORT%%RESET%
echo %GREEN%  Admin User:  %ADMIN_USERNAME%%RESET%
echo %GREEN%============================================================%RESET%
echo.
echo %YELLOW%[INFO]%RESET% Press Ctrl+C to stop the service
echo.

REM 设置环境变量
set "SQLMAP_WEBUI_HOST=%HOST%"
set "SQLMAP_WEBUI_PORT=%PORT%"
set "SQLMAP_WEBUI_USERNAME=%ADMIN_USERNAME%"
set "SQLMAP_WEBUI_PASSWORD=%ADMIN_PASSWORD%"

REM 启动服务
python main.py

REM ============================================================
REM 退出处理
REM ============================================================
echo.
echo %YELLOW%[INFO]%RESET% Service stopped
pause
