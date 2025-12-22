@echo off
REM ============================================================
REM SQLMap Web UI 离线依赖准备脚本 (Windows)
REM Offline Dependencies Preparation Script (Windows)
REM ============================================================
REM 在有网络的环境下运行此脚本，准备离线依赖包
REM 然后将整个 backEnd 目录复制到离线环境使用
REM ============================================================

setlocal EnableDelayedExpansion

REM 切换到脚本所在目录
cd /d "%~dp0"

REM 编码设置
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8

REM 颜色定义
for /F %%a in ('echo prompt $E^| cmd') do set "ESC=%%a"
set "GREEN=%ESC%[32m"
set "YELLOW=%ESC%[33m"
set "RED=%ESC%[31m"
set "CYAN=%ESC%[36m"
set "RESET=%ESC%[0m"

echo.
echo %CYAN%============================================================%RESET%
echo %CYAN%  SQLMap Web UI - Offline Dependencies Preparation%RESET%
echo %CYAN%============================================================%RESET%
echo.

REM 默认配置
set "VENV_DIR=.venv"
set "OFFLINE_DIR=offline_packages"
set "PYPI_MIRROR=tsinghua"

REM 加载配置
if exist "startup.conf" (
    for /f "usebackq tokens=1,* delims==" %%a in ("startup.conf") do (
        set "line=%%a"
        if not "!line:~0,1!"=="#" (
            if not "%%b"=="" (
                set "%%a=%%b"
            )
        )
    )
)

REM 镜像 URL
set "MIRROR_URL="
if /i "%PYPI_MIRROR%"=="tsinghua" set "MIRROR_URL=https://pypi.tuna.tsinghua.edu.cn/simple"
if /i "%PYPI_MIRROR%"=="aliyun" set "MIRROR_URL=https://mirrors.aliyun.com/pypi/simple/"
if "%MIRROR_URL%"=="" set "MIRROR_URL=https://pypi.org/simple/"

REM 检测 Python
set "PYTHON_CMD="
py --version >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_CMD=py"
) else (
    python --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_CMD=python"
    ) else (
        echo %RED%[ERROR]%RESET% Python not found!
        pause
        exit /b 1
    )
)

echo %GREEN%[INFO]%RESET% Using Python: %PYTHON_CMD%
echo %GREEN%[INFO]%RESET% Mirror: %MIRROR_URL%
echo.

REM ============================================================
REM 步骤 1: 创建虚拟环境
REM ============================================================
echo %CYAN%[STEP 1]%RESET% Creating virtual environment...

if not exist "%VENV_DIR%" (
    %PYTHON_CMD% -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo %RED%[ERROR]%RESET% Failed to create virtual environment
        pause
        exit /b 1
    )
)
call "%VENV_DIR%\Scripts\activate.bat"
echo %GREEN%[OK]%RESET% Virtual environment ready

REM ============================================================
REM 步骤 2: 安装依赖到虚拟环境
REM ============================================================
echo.
echo %CYAN%[STEP 2]%RESET% Installing dependencies to virtual environment...

python -m pip install --upgrade pip -i %MIRROR_URL% --trusted-host pypi.tuna.tsinghua.edu.cn >nul 2>&1

if exist "pyproject.toml" (
    python -m pip install -e ".[thirdparty]" -i %MIRROR_URL% --trusted-host pypi.tuna.tsinghua.edu.cn
) else (
    python -m pip install fastapi[standard] apscheduler psutil -i %MIRROR_URL% --trusted-host pypi.tuna.tsinghua.edu.cn
)

if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Failed to install dependencies
    pause
    exit /b 1
)
echo %GREEN%[OK]%RESET% Dependencies installed

REM ============================================================
REM 步骤 3: 下载离线包（可选）
REM ============================================================
echo.
echo %CYAN%[STEP 3]%RESET% Downloading offline packages...

if not exist "%OFFLINE_DIR%" mkdir "%OFFLINE_DIR%"

python -m pip download -d "%OFFLINE_DIR%" fastapi[standard] apscheduler psutil -i %MIRROR_URL% --trusted-host pypi.tuna.tsinghua.edu.cn

if %errorlevel% neq 0 (
    echo %YELLOW%[WARN]%RESET% Some packages may not have been downloaded
) else (
    echo %GREEN%[OK]%RESET% Offline packages downloaded to: %OFFLINE_DIR%
)

REM ============================================================
REM 完成
REM ============================================================
echo.
echo %GREEN%============================================================%RESET%
echo %GREEN%  Offline preparation complete!%RESET%
echo %GREEN%============================================================%RESET%
echo.
echo %CYAN%[USAGE]%RESET% To use in offline environment:
echo.
echo   1. Copy the entire backEnd directory to the offline machine
echo   2. Edit startup.conf and set: NETWORK_MODE=offline
echo   3. Run start.bat to start the service
echo.
echo %YELLOW%[NOTE]%RESET% The virtual environment contains all dependencies.
echo        No internet connection required for offline startup.
echo.

pause
