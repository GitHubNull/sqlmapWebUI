# 认证相关API
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from model.BaseResponseMsg import BaseResponseMsg
from config import VERSION

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth")


# ==================== 请求/响应模型 ====================

class LoginRequest(BaseModel):
    """登录请求"""
    username: str = Field(..., min_length=1, max_length=50, description="用户名")
    password: str = Field(..., min_length=1, max_length=100, description="密码")


class LoginResponse(BaseModel):
    """登录响应"""
    token: str = Field(..., description="访问令牌")
    expires_in: int = Field(..., description="过期时间（秒）")
    user: dict = Field(..., description="用户信息")


class TokenRefreshResponse(BaseModel):
    """令牌刷新响应"""
    token: str = Field(..., description="新的访问令牌")
    expires_in: int = Field(..., description="过期时间（秒）")


# ==================== API接口 ====================

@router.post('/login')
async def login(request: LoginRequest):
    """
    用户登录接口
    
    注意：当前为本地单机模式，不需要真正的认证。
    此接口主要用于远程访问模式下的用户验证。
    """
    try:
        # TODO: 实现真正的用户认证逻辑
        # 当前为演示模式，接受任意用户名密码
        
        # 生成模拟token（实际应使用JWT）
        mock_token = f"local_token_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        response_data = {
            "token": mock_token,
            "userInfo": {
                "username": request.username,
                "email": f"{request.username}@local",
                "role": "admin"
            }
        }
        
        return BaseResponseMsg(
            data=response_data,
            msg="登录成功",
            success=True,
            code=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Login failed: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"登录失败: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.post('/refresh')
async def refresh_token():
    """
    刷新访问令牌
    
    注意：当前为本地单机模式，直接返回新的模拟token。
    """
    try:
        # 生成新的模拟token
        new_token = f"local_token_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        response_data = {
            "token": new_token,
            "expires_in": 86400  # 24小时
        }
        
        return BaseResponseMsg(
            data=response_data,
            msg="令牌刷新成功",
            success=True,
            code=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"令牌刷新失败: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.get('/check-required')
async def check_auth_required():
    """
    检查当前访问是否需要认证
    
    返回值说明：
    - required=False: 本地访问模式，不需要认证
    - required=True: 远程访问模式，需要认证
    
    当前实现：始终返回 False（本地单机模式）
    """
    try:
        # TODO: 根据实际配置决定是否需要认证
        # 当前为本地单机模式，不需要认证
        
        response_data = {
            "required": False,
            "mode": "local",
            "version": VERSION
        }
        
        return BaseResponseMsg(
            data=response_data,
            msg="检查成功",
            success=True,
            code=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Auth check failed: {e}")
        return BaseResponseMsg(
            data=None,
            msg=f"检查失败: {str(e)}",
            success=False,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
