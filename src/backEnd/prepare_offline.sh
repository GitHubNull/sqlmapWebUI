#!/bin/bash
# ============================================================
# SQLMap Web UI 离线依赖准备脚本 (Linux/macOS)
# Offline Dependencies Preparation Script (Linux/macOS)
# ============================================================
# 在有网络的环境下运行此脚本，准备离线依赖包
# 然后将整个 backEnd 目录复制到离线环境使用
# ============================================================

set -e

# 切换到脚本所在目录
cd "$(dirname "$0")"

# 编码设置
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  SQLMap Web UI - Offline Dependencies Preparation${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# 默认配置
VENV_DIR=".venv"
OFFLINE_DIR="offline_packages"
PYPI_MIRROR="tsinghua"

# 加载配置
if [ -f "startup.conf" ]; then
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^#.*$ ]] && continue
        [[ -z "$key" ]] && continue
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        if [ -n "$key" ] && [ -n "$value" ]; then
            declare "$key=$value"
        fi
    done < "startup.conf"
fi

# 镜像 URL
get_mirror_url() {
    case "${PYPI_MIRROR,,}" in
        tsinghua)
            echo "https://pypi.tuna.tsinghua.edu.cn/simple"
            ;;
        aliyun)
            echo "https://mirrors.aliyun.com/pypi/simple/"
            ;;
        *)
            echo "https://pypi.org/simple/"
            ;;
    esac
}

MIRROR_URL=$(get_mirror_url)

# 检测 Python
detect_python() {
    for cmd in python3.13 python3.12 python3.11 python3 python; do
        if command -v "$cmd" &> /dev/null; then
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
    exit 1
fi

echo -e "${GREEN}[INFO]${NC} Using Python: $PYTHON_CMD"
echo -e "${GREEN}[INFO]${NC} Mirror: $MIRROR_URL"
echo ""

# ============================================================
# 步骤 1: 创建虚拟环境
# ============================================================
echo -e "${CYAN}[STEP 1]${NC} Creating virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON_CMD" -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
echo -e "${GREEN}[OK]${NC} Virtual environment ready"

# ============================================================
# 步骤 2: 安装依赖到虚拟环境
# ============================================================
echo ""
echo -e "${CYAN}[STEP 2]${NC} Installing dependencies to virtual environment..."

MIRROR_HOST=$(echo "$MIRROR_URL" | sed -E 's|https?://([^/]+).*|\1|')
python -m pip install --upgrade pip -i "$MIRROR_URL" --trusted-host "$MIRROR_HOST" > /dev/null 2>&1 || true

if [ -f "pyproject.toml" ]; then
    python -m pip install -e ".[thirdparty]" -i "$MIRROR_URL" --trusted-host "$MIRROR_HOST"
else
    python -m pip install fastapi[standard] apscheduler psutil -i "$MIRROR_URL" --trusted-host "$MIRROR_HOST"
fi

echo -e "${GREEN}[OK]${NC} Dependencies installed"

# ============================================================
# 步骤 3: 下载离线包（可选）
# ============================================================
echo ""
echo -e "${CYAN}[STEP 3]${NC} Downloading offline packages..."

mkdir -p "$OFFLINE_DIR"

python -m pip download -d "$OFFLINE_DIR" fastapi[standard] apscheduler psutil -i "$MIRROR_URL" --trusted-host "$MIRROR_HOST" || {
    echo -e "${YELLOW}[WARN]${NC} Some packages may not have been downloaded"
}

echo -e "${GREEN}[OK]${NC} Offline packages downloaded to: $OFFLINE_DIR"

# ============================================================
# 完成
# ============================================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Offline preparation complete!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "${CYAN}[USAGE]${NC} To use in offline environment:"
echo ""
echo "   1. Copy the entire backEnd directory to the offline machine"
echo "   2. Edit startup.conf and set: NETWORK_MODE=offline"
echo "   3. Run ./start.sh to start the service"
echo ""
echo -e "${YELLOW}[NOTE]${NC} The virtual environment contains all dependencies."
echo "       No internet connection required for offline startup."
echo ""
