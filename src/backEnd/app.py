import logging
import time
import os
from typing import Union
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from api.chromeExApi.admin import router as chrome_admin_router
from api.burpSuiteExApi.admin import router as burp_admin_router
from api.commonApi.headerController import router as header_router
from api.commonApi.authController import router as auth_router
from api.commonApi.configController import router as config_router
from api.commonApi.scanPreset import router as scan_preset_router
from api.commonApi.webTaskController import router as web_task_router
from config import VERSION

logger = logging.getLogger(__name__)
app = FastAPI()

# 记录服务启动时间
START_TIME = time.time()

# 静态文件目录
STATIC_DIR = "static"

# 将编译好的 Vue 项目静态文件夹（如dist）放置在FastAPI项目中的static文件夹下
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
# 挂载 /assets 路径到 static/assets 目录（前端构建后资源的访问路径）
app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")
# 允许所有来源的跨域请求
app.add_middleware(
    CORSMiddleware,
    # 允许开发环境下的localhost所有端口，以及后端端口
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):(517[3-6]|8775)",
    allow_credentials=True,  # 允许携带身份凭证，如cookies
    allow_methods=["*"],   # 允许所有HTTP方法
    allow_headers=["*"]    # 允许所有请求头
)

app.include_router(chrome_admin_router, prefix="/api", tags=["chrome"])
app.include_router(burp_admin_router, prefix="/api", tags=["burp"])
app.include_router(header_router, prefix="/api", tags=["header"])
app.include_router(auth_router, prefix="/api", tags=["auth"])
app.include_router(config_router, prefix="/api", tags=["config"])
app.include_router(scan_preset_router, prefix="/api", tags=["scan-preset"])
app.include_router(web_task_router, prefix="/api", tags=["web-task"])

@app.get("/api/version")
def get_version():
    """获取系统版本信息"""
    return {
        "code": 200,
        "success": True,
        "message": "success",
        "data": {
            "version": VERSION
        }
    }

@app.get("/api/health")
def health_check():
    """健康检查端点
    
    返回服务健康状态信息，用于前端监控后端服务可用性
    """
    current_time = time.time()
    uptime = int(current_time - START_TIME)
    
    return {
        "code": 200,
        "success": True,
        "message": "success",
        "data": {
            "status": "healthy",
            "timestamp": int(current_time * 1000),  # 毫秒时间戳
            "version": VERSION,
            "uptime": uptime  # 运行时长（秒）
        }
    }

# 返回 index.html 文件
@app.get("/")
async def read_root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

# 处理根路径的静态文件请求和 SPA 前端路由（通配符路由放在最后）
@app.get("/{filename:path}")
async def serve_static_file(filename: str):
    """处理 SPA 前端路由和根路径静态文件
    
    1. 如果请求的是存在于 static 目录中的文件，返回该文件
    2. 否则返回 index.html（用于 SPA 前端路由）
    """
    # 检查是否是静态文件请求（带有文件扩展名）
    file_path = os.path.join(STATIC_DIR, filename)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    
    # 对于 SPA 前端路由，返回 index.html
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))