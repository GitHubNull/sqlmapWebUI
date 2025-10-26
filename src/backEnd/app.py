import logging
import time
from typing import Union
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from api.chromeExApi.admin import router as chrome_admin_router
from api.burpSuiteExApi.admin import router as burp_admin_router
from api.commonApi.headerController import router as header_router
from config import VERSION

logger = logging.getLogger(__name__)
app = FastAPI()

# 记录服务启动时间
START_TIME = time.time()
# 将编译好的 Vue 项目静态文件夹（如dist）放置在FastAPI项目中的static文件夹下
app.mount("/static", StaticFiles(directory="static"), name="static")
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

# 返回 index.html 文件
@app.get("/")
async def read_root():
    return FileResponse("static/index.html")

@app.get("/version")
def get_version():
    logger.debug("root")
    return {
        "version": VERSION
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