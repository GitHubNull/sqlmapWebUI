#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop API处理器模块

按功能划分的处理器：
- user_handlers: 用户相关（登录、注册、更新、资料）
- product_handlers: 商品相关（列表、搜索、详情）
- order_handlers: 订单相关（创建、查询、取消）
- cart_handlers: 购物车相关（添加、更新）
- system_handlers: 系统相关（配置、重置、API信息、反馈）
"""

from .user_handlers import UserHandlerMixin
from .product_handlers import ProductHandlerMixin
from .order_handlers import OrderHandlerMixin
from .cart_handlers import CartHandlerMixin
from .system_handlers import SystemHandlerMixin

__all__ = [
    'UserHandlerMixin',
    'ProductHandlerMixin',
    'OrderHandlerMixin',
    'CartHandlerMixin',
    'SystemHandlerMixin',
]
