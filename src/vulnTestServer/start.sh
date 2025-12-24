#!/bin/bash

# ========================================
# VulnShop 漏洞靶场 - Linux/macOS 启动脚本
# ========================================

echo ""
echo "========================================"
echo "  VulnShop - SQL Injection Test Lab"
echo "  仅供安全测试和教育目的使用"
echo "========================================"
echo ""

# 切换到脚本所在目录
cd "$(dirname "$0")"

# 检查 Python 是否安装
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未找到 Python3，请先安装 Python 3.10+"
    echo "Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "macOS: brew install python3"
    exit 1
fi

# 检查 Python 版本
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "[信息] 检测到 Python $PYTHON_VERSION"

# 检查依赖
if ! python3 -c "import flask" &> /dev/null; then
    echo "[信息] 正在安装 Flask 依赖..."
    pip3 install flask -q 2>/dev/null || pip install flask -q
fi

# 启动服务器
echo ""
echo "[信息] 正在启动 VulnShop 靶场服务..."
echo "[信息] 服务地址: http://127.0.0.1:9527"
echo "[信息] 按 Ctrl+C 停止服务"
echo ""

python3 server.py

# 如果服务异常退出
if [ $? -ne 0 ]; then
    echo ""
    echo "[错误] 服务异常退出"
    read -p "按回车键退出..."
fi
