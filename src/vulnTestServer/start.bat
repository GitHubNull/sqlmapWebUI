@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

:: ========================================
:: VulnShop 漏洞靶场 - Windows 启动脚本
:: ========================================

title VulnShop - SQL Injection Test Lab

echo.
echo ========================================
echo   VulnShop - SQL Injection Test Lab
echo   仅供安全测试和教育目的使用
echo ========================================
echo.

:: 切换到脚本所在目录
cd /d "%~dp0"

:: 检查 Python 是否安装
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python，请先安装 Python 3.10+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: 检查 Python 版本
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [信息] 检测到 Python %PYTHON_VERSION%

:: 检查依赖
python -c "import flask" >nul 2>&1
if %errorlevel% neq 0 (
    echo [信息] 正在安装 Flask 依赖...
    pip install flask -q
)

:: 启动服务器
echo.
echo [信息] 正在启动 VulnShop 靶场服务...
echo [信息] 服务地址: http://127.0.0.1:9527
echo [信息] 按 Ctrl+C 停止服务
echo.

python server.py

:: 如果服务异常退出
if %errorlevel% neq 0 (
    echo.
    echo [错误] 服务异常退出，错误代码: %errorlevel%
    pause
)
