#!/bin/bash
# ============================================================
# SQLMap Web UI 后端服务启动脚本 (Linux/macOS)
# Backend Service Startup Script (Linux/macOS)
# ============================================================

set -e

# 切换到脚本所在目录
cd "$(dirname "$0")"

# ============================================================
# 编码设置 - 解决乱码问题
# ============================================================
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1
export LC_ALL=en_US.UTF-8 2>/dev/null || export LC_ALL=C.UTF-8 2>/dev/null || true
export LANG=en_US.UTF-8 2>/dev/null || export LANG=C.UTF-8 2>/dev/null || true

# ============================================================
# 颜色定义
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# 默认配置
# ============================================================
NETWORK_MODE="online"
PYPI_MIRROR="tsinghua"
PRIVATE_MIRROR_URL=""
PRIVATE_MIRROR_AUTH=""
PRIVATE_MIRROR_TRUSTED_HOSTS=""
PYTHON_PATH=""
VENV_DIR=".venv"
HOST="127.0.0.1"
PORT="8775"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="admin"
CONSOLE_ENCODING=""
FORCE_UTF8="true"
DEBUG="false"
LOG_LEVEL="INFO"
SKIP_DEPS_CHECK="false"

# ============================================================
# 加载配置文件
# ============================================================
if [ -f "startup.conf" ]; then
    echo -e "${CYAN}[INFO]${NC} Loading configuration from startup.conf..."
    while IFS='=' read -r key value; do
        # 跳过注释和空行
        [[ "$key" =~ ^#.*$ ]] && continue
        [[ -z "$key" ]] && continue
        # 去除空格
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        # 设置变量
        if [ -n "$key" ] && [ -n "$value" ]; then
            declare "$key=$value"
        fi
    done < "startup.conf"
fi

# ============================================================
# PyPI 镜像 URL 映射
# ============================================================
get_mirror_url() {
    case "${PYPI_MIRROR,,}" in
        tsinghua)
            echo "https://pypi.tuna.tsinghua.edu.cn/simple"
            ;;
        aliyun)
            echo "https://mirrors.aliyun.com/pypi/simple/"
            ;;
        ustc)
            echo "https://pypi.mirrors.ustc.edu.cn/simple/"
            ;;
        douban)
            echo "https://pypi.doubanio.com/simple/"
            ;;
        huawei)
            echo "https://mirrors.huaweicloud.com/repository/pypi/simple/"
            ;;
        tencent)
            echo "https://mirrors.cloud.tencent.com/pypi/simple/"
            ;;
        pypi|*)
            echo "https://pypi.org/simple/"
            ;;
    esac
}

MIRROR_URL=$(get_mirror_url)

# ============================================================
# 显示启动信息
# ============================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  SQLMap Web UI - Backend Service${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "${GREEN}[CONFIG]${NC} Network Mode: ${NETWORK_MODE}"
if [ "${NETWORK_MODE,,}" == "online" ]; then
    echo -e "${GREEN}[CONFIG]${NC} PyPI Mirror: ${PYPI_MIRROR} (${MIRROR_URL})"
fi
if [ "${NETWORK_MODE,,}" == "intranet" ]; then
    echo -e "${GREEN}[CONFIG]${NC} Private Mirror: ${PRIVATE_MIRROR_URL}"
fi
if [ "${NETWORK_MODE,,}" == "offline" ]; then
    echo -e "${YELLOW}[CONFIG]${NC} Offline Mode - Using local cache only"
fi
echo ""

# ============================================================
# 检测 Python 可执行文件
# ============================================================
detect_python() {
    if [ -n "$PYTHON_PATH" ] && [ -x "$PYTHON_PATH" ]; then
        echo "$PYTHON_PATH"
        return 0
    fi
    
    # 按优先级尝试不同的 Python 命令
    for cmd in python3.13 python3.12 python3.11 python3 python; do
        if command -v "$cmd" &> /dev/null; then
            # 检查版本是否 >= 3.10
            version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
            if [ -n "$version" ]; then
                major=$(echo "$version" | cut -d. -f1)
                minor=$(echo "$version" | cut -d. -f2)
                if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                    echo "$cmd"
                    return 0
                fi
            fi
        fi
    done
    
    return 1
}

PYTHON_CMD=$(detect_python)
if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[ERROR]${NC} Python 3.10+ not found!"
    echo -e "${YELLOW}[HINT]${NC} Please install Python 3.10 or later"
    exit 1
fi

PY_VERSION=$("$PYTHON_CMD" --version 2>&1 | cut -d' ' -f2)
echo -e "${GREEN}[INFO]${NC} Using Python: $PYTHON_CMD (version $PY_VERSION)"

# ============================================================
# 检测 uv 包管理器
# ============================================================
UV_AVAILABLE="false"
if command -v uv &> /dev/null; then
    UV_AVAILABLE="true"
    echo -e "${GREEN}[INFO]${NC} uv package manager detected"
fi

# ============================================================
# 创建/激活虚拟环境
# ============================================================
echo ""
echo -e "${CYAN}[STEP 1]${NC} Setting up virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[INFO]${NC} Creating virtual environment: ${VENV_DIR}"
    
    if [ "$UV_AVAILABLE" == "true" ]; then
        uv venv "$VENV_DIR"
    else
        "$PYTHON_CMD" -m venv "$VENV_DIR"
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Failed to create virtual environment"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Virtual environment created"
else
    echo -e "${GREEN}[OK]${NC} Virtual environment exists: ${VENV_DIR}"
fi

# 激活虚拟环境
echo -e "${CYAN}[INFO]${NC} Activating virtual environment..."
source "$VENV_DIR/bin/activate"
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Failed to activate virtual environment"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Virtual environment activated"

# ============================================================
# 安装依赖
# ============================================================
echo ""
echo -e "${CYAN}[STEP 2]${NC} Installing dependencies..."

# 检查是否跳过依赖安装
if [ "${SKIP_DEPS_CHECK,,}" == "true" ]; then
    echo -e "${YELLOW}[INFO]${NC} Skipping dependency check (SKIP_DEPS_CHECK=true)"
else

if [ "${NETWORK_MODE,,}" == "offline" ]; then
    echo -e "${YELLOW}[INFO]${NC} Offline mode - Skipping dependency installation"
    echo -e "${YELLOW}[HINT]${NC} Make sure dependencies are pre-installed in the virtual environment"
else
    # 构建安装参数
    EXTRA_ARGS=""
    
    if [ "${NETWORK_MODE,,}" == "online" ]; then
        if [ -n "$MIRROR_URL" ]; then
            if [ "$UV_AVAILABLE" == "true" ]; then
                EXTRA_ARGS="--index-url $MIRROR_URL"
            else
                # 提取主机名用于 trusted-host
                MIRROR_HOST=$(echo "$MIRROR_URL" | sed -E 's|https?://([^/]+).*|\1|')
                EXTRA_ARGS="-i $MIRROR_URL --trusted-host $MIRROR_HOST"
            fi
        fi
    fi
    
    if [ "${NETWORK_MODE,,}" == "intranet" ]; then
        if [ -n "$PRIVATE_MIRROR_URL" ]; then
            if [ "$UV_AVAILABLE" == "true" ]; then
                EXTRA_ARGS="--index-url $PRIVATE_MIRROR_URL"
            else
                EXTRA_ARGS="-i $PRIVATE_MIRROR_URL"
                if [ -n "$PRIVATE_MIRROR_TRUSTED_HOSTS" ]; then
                    IFS=',' read -ra HOSTS <<< "$PRIVATE_MIRROR_TRUSTED_HOSTS"
                    for host in "${HOSTS[@]}"; do
                        EXTRA_ARGS="$EXTRA_ARGS --trusted-host $(echo "$host" | xargs)"
                    done
                fi
            fi
        else
            echo -e "${RED}[ERROR]${NC} Intranet mode requires PRIVATE_MIRROR_URL configuration"
            exit 1
        fi
    fi
    
    # 安装依赖
    if [ "$UV_AVAILABLE" == "true" ]; then
        echo -e "${CYAN}[INFO]${NC} Installing with uv..."
        uv sync --extra thirdparty $EXTRA_ARGS
    else
        echo -e "${CYAN}[INFO]${NC} Installing with pip..."
        python -m pip install --upgrade pip $EXTRA_ARGS > /dev/null 2>&1 || true
        
        if [ -f "pyproject.toml" ]; then
            python -m pip install -e ".[thirdparty]" $EXTRA_ARGS
        else
            echo -e "${YELLOW}[WARN]${NC} pyproject.toml not found, installing basic dependencies..."
            python -m pip install fastapi[standard] apscheduler psutil $EXTRA_ARGS
        fi
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Failed to install dependencies"
        if [ "${NETWORK_MODE,,}" == "online" ]; then
            echo -e "${YELLOW}[HINT]${NC} Try changing PYPI_MIRROR in startup.conf"
        fi
        if [ "${NETWORK_MODE,,}" == "intranet" ]; then
            echo -e "${YELLOW}[HINT]${NC} Check PRIVATE_MIRROR_URL configuration"
        fi
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Dependencies installed"
fi

fi  # end SKIP_DEPS_CHECK

# ============================================================
# 启动服务
# ============================================================
echo ""
echo -e "${CYAN}[STEP 3]${NC} Starting SQLMap Web UI Backend Service..."
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Service URL: http://${HOST}:${PORT}${NC}"
echo -e "${GREEN}  Admin User:  ${ADMIN_USERNAME}${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "${YELLOW}[INFO]${NC} Press Ctrl+C to stop the service"
echo ""

# 设置环境变量
export SQLMAP_WEBUI_HOST="$HOST"
export SQLMAP_WEBUI_PORT="$PORT"
export SQLMAP_WEBUI_USERNAME="$ADMIN_USERNAME"
export SQLMAP_WEBUI_PASSWORD="$ADMIN_PASSWORD"

# 捕获 SIGINT 信号
trap 'echo ""; echo -e "${YELLOW}[INFO]${NC} Service stopped"; exit 0' SIGINT SIGTERM

# 启动服务
python main.py

# ============================================================
# 退出处理
# ============================================================
echo ""
echo -e "${YELLOW}[INFO]${NC} Service stopped"
