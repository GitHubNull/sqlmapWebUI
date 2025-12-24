#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入测试靶场 - 主服务器

███████╗ ██████╗ ██╗         ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
██╔════╝██╔═══██╗██║         ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
███████╗██║   ██║██║         ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
╚════██║██║▄▄ ██║██║         ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
███████║╚██████╔╝███████╗    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
╚══════╝ ╚══▀▀═╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

VulnShop - SQL Injection Test Lab
仅供安全测试和教育目的使用！禁止用于非法用途！

模块化结构:
- handlers/base.py: 基础处理器（响应发送、请求解析等公共方法）
- handlers/user_handlers.py: 用户相关处理器（登录、注册、更新）
- handlers/product_handlers.py: 商品相关处理器（列表、搜索、详情）
- handlers/order_handlers.py: 订单相关处理器（创建、查询、取消）
- handlers/cart_handlers.py: 购物车相关处理器（添加、更新）
- handlers/system_handlers.py: 系统相关处理器（配置、重置、API信息、反馈）
"""

import os
import sys
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import HOST, PORT, DEBUG, DIFFICULTY, VERSION
from database import init_database
from waf import WAFBlockedException
from logger import logger, access_logger, error_logger

# 导入处理器模块
from handlers.base import BaseHandlerMixin
from handlers.user_handlers import UserHandlerMixin
from handlers.product_handlers import ProductHandlerMixin
from handlers.order_handlers import OrderHandlerMixin
from handlers.cart_handlers import CartHandlerMixin
from handlers.system_handlers import SystemHandlerMixin


class VulnShopHandler(
    BaseHandlerMixin,
    UserHandlerMixin,
    ProductHandlerMixin,
    OrderHandlerMixin,
    CartHandlerMixin,
    SystemHandlerMixin,
    BaseHTTPRequestHandler
):
    """
    漏洞商店HTTP请求处理器
    
    使用Mixin模式组合各个功能模块，实现模块化设计
    """
    
    def log_message(self, format, *args):
        """重写日志方法，使用自定义日志器"""
        access_logger.info("%s - %s", self.client_address[0], format % args)
    
    def do_OPTIONS(self):
        """处理CORS预检请求"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_GET(self):
        """处理GET请求"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        # 将单值参数展开
        params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        
        try:
            # 路由分发
            if path == '/' or path == '/index.html':
                self.send_static_file('index.html')
            elif path.startswith('/static/'):
                filepath = path[8:]  # 移除 /static/
                self.send_static_file(filepath)
            elif path.startswith('/css/') or path.startswith('/js/') or path.startswith('/img/'):
                filepath = path[1:]  # 移除开头的 /
                self.send_static_file(filepath)
            elif path == '/api/info':
                self.handle_api_info()
            elif path == '/api/products':
                self.handle_products_list(params)
            elif path == '/api/products/search':
                self.handle_products_search(params)
            elif path == '/api/products/detail':
                self.handle_product_detail(params)
            elif path == '/api/user/profile':
                self.handle_user_profile(params)
            elif path == '/api/orders/query':
                self.handle_orders_query(params)
            elif path == '/api/config':
                self.handle_get_config()
            else:
                self.send_error(404, 'Not Found')
        except WAFBlockedException as e:
            access_logger.warning("%s - WAF Blocked: %s", self.client_address[0], e.reason)
            self.send_error_response(f'WAF Blocked: {e.reason}', 403)
        except Exception as e:
            error_logger.exception("Error processing GET %s: %s", path, str(e))
            self.send_error_response(str(e), 500, sql_error=e)
    
    def do_POST(self):
        """处理POST请求"""
        parsed = urlparse(self.path)
        path = parsed.path
        data = self.get_post_data()
        
        try:
            if path == '/api/user/login':
                self.handle_user_login(data)
            elif path == '/api/user/register':
                self.handle_user_register(data)
            elif path == '/api/user/update':
                self.handle_user_update(data)  # XML格式
            elif path == '/api/cart/add':
                self.handle_cart_add(data)  # URL-encoded格式
            elif path == '/api/cart/update':
                self.handle_cart_update(data)  # URL-encoded格式
            elif path == '/api/orders/create':
                self.handle_order_create(data)  # JSON格式
            elif path == '/api/orders/cancel':
                self.handle_order_cancel(data)  # XML格式
            elif path == '/api/feedback':
                self.handle_feedback(data)  # JSON格式
            elif path == '/api/config':
                self.handle_set_config(data)
            elif path == '/api/database/reset':
                self.handle_database_reset()
            else:
                self.send_error(404, 'Not Found')
        except WAFBlockedException as e:
            access_logger.warning("%s - WAF Blocked: %s", self.client_address[0], e.reason)
            self.send_error_response(f'WAF Blocked: {e.reason}', 403)
        except Exception as e:
            error_logger.exception("Error processing POST %s: %s", path, str(e))
            self.send_error_response(str(e), 500, sql_error=e)


def run_server():
    """启动服务器"""
    # 初始化数据库
    init_database()
    logger.info("Database initialized")
    
    # 创建服务器
    server = HTTPServer((HOST, PORT), VulnShopHandler)
    logger.info("Server created on %s:%d", HOST, PORT)
    
    print(f"""
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                       ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗                ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║  ██║██╔═══██╗██╔══██╗               ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗███████║██║   ██║██████╔╝               ║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██╔══██║██║   ██║██╔═══╝                ║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║██║  ██║╚██████╔╝██║                  ║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝                  ║
║                                                                                       ║
║           SQL Injection Test Lab - For Educational Use Only                           ║
║                                                                                       ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  Version: {VERSION:<10}                                                                ║
║  Difficulty: {DIFFICULTY:<7}                                                              ║
║  Server: http://{HOST}:{PORT}                                                           ║
║                                                                                       ║
║  ⚠️  WARNING: This server contains intentional vulnerabilities!                      ║
║  ⚠️  Only use on localhost for testing purposes!                                     ║
║                                                                                       ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  Vulnerability Distribution:                                                          ║
║  • 只读SELECT查询接口: 保留SQL注入漏洞 (用于测试)                                     ║
║  • 数据修改INSERT/UPDATE接口: 使用参数化查询保护 (防止数据污染)                      ║
║                                                                                       ║
║  [存在SQL注入的接口 - 可用于测试]                                                     ║
║  • POST /api/user/login       - Error-based SQLi (只读)                                ║
║  • GET  /api/user/profile     - Union-based SQLi (只读)                                ║
║  • GET  /api/products/search  - Boolean-based Blind SQLi (只读)                        ║
║  • GET  /api/products/detail  - Time-based Blind SQLi (只读)                           ║
║  • GET  /api/orders/query     - SQL注入 (只读)                                          ║
║                                                                                       ║
║  [安全接口 - 参数化查询保护]                                                           ║
║  • POST /api/user/register    - 安全 (session_id, captcha_token)                       ║
║  • POST /api/user/update      - 安全 XML (session_id, token, device_id)                ║
║  • POST /api/cart/add         - 安全 Form (session_id, csrf_token)                     ║
║  • POST /api/cart/update      - 安全 Form (session_id, csrf_token)                     ║
║  • POST /api/orders/create    - 安全 JSON (session_id, token, user_agent)              ║
║  • POST /api/orders/cancel    - 安全 XML (session_id, auth_token)                      ║
║  • POST /api/feedback         - 安全 JSON (session_id, token, timestamp)               ║
║                                                                                       ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  Test Accounts:                                                                       ║
║  • admin / admin123  (Administrator)                                                  ║
║  • test  / test      (Regular User)                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        logger.info("Server starting...")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        server.shutdown()


if __name__ == '__main__':
    run_server()
