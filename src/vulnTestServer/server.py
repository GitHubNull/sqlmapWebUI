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

"""

import json
import os
import sys
import time
import sqlite3
import hashlib
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import HOST, PORT, DEBUG, DIFFICULTY, VERSION, APP_NAME, LOG_REQUESTS, LOG_FILE
from database import get_db_connection, init_database, hash_password
from waf import get_waf, WAFBlockedException, set_difficulty


class VulnShopHandler(BaseHTTPRequestHandler):
    """漏洞商店HTTP请求处理器"""
    
    # 静态文件MIME类型
    MIME_TYPES = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json; charset=utf-8',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.ico': 'image/x-icon',
        '.svg': 'image/svg+xml',
    }
    
    def log_message(self, format, *args):
        """自定义日志格式"""
        if LOG_REQUESTS:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            message = f"[{timestamp}] {self.address_string()} - {format % args}"
            print(message)
            try:
                os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(message + '\n')
            except:
                pass
    
    def send_json_response(self, data, status=200):
        """发送JSON响应"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        response = json.dumps(data, ensure_ascii=False)
        self.wfile.write(response.encode('utf-8'))
    
    def send_error_response(self, message, status=400, sql_error=None):
        """发送错误响应（可能包含SQL错误信息用于演示）"""
        data = {
            'success': False,
            'message': message,
            'timestamp': int(time.time() * 1000)
        }
        if sql_error and DEBUG:
            data['debug'] = {
                'sql_error': str(sql_error),
                'difficulty': DIFFICULTY
            }
        self.send_json_response(data, status)
    
    def send_static_file(self, filepath):
        """发送静态文件"""
        static_dir = os.path.join(os.path.dirname(__file__), 'static')
        full_path = os.path.normpath(os.path.join(static_dir, filepath))
        
        # 防止目录遍历
        if not full_path.startswith(static_dir):
            self.send_error(403, 'Forbidden')
            return
        
        if not os.path.exists(full_path):
            self.send_error(404, 'File Not Found')
            return
        
        ext = os.path.splitext(filepath)[1].lower()
        mime_type = self.MIME_TYPES.get(ext, 'application/octet-stream')
        
        try:
            with open(full_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, str(e))
    
    def get_post_data(self):
        """获取POST请求数据"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        
        post_data = self.rfile.read(content_length).decode('utf-8')
        content_type = self.headers.get('Content-Type', '')
        
        if 'application/json' in content_type:
            try:
                return json.loads(post_data)
            except:
                return {}
        else:
            # application/x-www-form-urlencoded
            result = {}
            for pair in post_data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    result[unquote(key)] = unquote(value)
            return result
    
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
                # /static/css/style.css -> css/style.css
                filepath = path[8:]  # 移除 /static/
                self.send_static_file(filepath)
            elif path.startswith('/css/') or path.startswith('/js/') or path.startswith('/img/'):
                # /css/style.css -> css/style.css
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
            self.send_error_response(f'WAF Blocked: {e.reason}', 403)
        except Exception as e:
            if DEBUG:
                traceback.print_exc()
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
            elif path == '/api/config':
                self.handle_set_config(data)
            elif path == '/api/database/reset':
                self.handle_database_reset()
            else:
                self.send_error(404, 'Not Found')
        except WAFBlockedException as e:
            self.send_error_response(f'WAF Blocked: {e.reason}', 403)
        except Exception as e:
            if DEBUG:
                traceback.print_exc()
            self.send_error_response(str(e), 500, sql_error=e)
    
    # ==================== API处理器 ====================
    
    def handle_api_info(self):
        """API信息"""
        self.send_json_response({
            'success': True,
            'data': {
                'name': APP_NAME,
                'version': VERSION,
                'difficulty': DIFFICULTY,
                'endpoints': [
                    {'method': 'POST', 'path': '/api/user/login', 'vuln_type': 'Error-based SQLi'},
                    {'method': 'GET', 'path': '/api/user/profile', 'vuln_type': 'Union-based SQLi'},
                    {'method': 'GET', 'path': '/api/products/search', 'vuln_type': 'Boolean-based Blind SQLi'},
                    {'method': 'GET', 'path': '/api/products/detail', 'vuln_type': 'Time-based Blind SQLi'},
                    {'method': 'GET', 'path': '/api/orders/query', 'vuln_type': 'Stacked Queries SQLi'},
                    {'method': 'POST', 'path': '/api/user/register', 'vuln_type': 'Second-order SQLi'},
                ]
            }
        })
    
    def handle_user_login(self, data):
        """
        用户登录 - 基于错误的SQL注入
        
        漏洞点：直接拼接用户输入到SQL语句
        测试payload: admin' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
        SQLite payload: admin' AND 1=1--
        """
        waf = get_waf()
        username = waf.filter_input(data.get('username', ''))
        password = data.get('password', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在SQL注入漏洞）
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
        
        if DEBUG:
            print(f"[SQL] {sql}")
        
        try:
            cursor.execute(sql)
            user = cursor.fetchone()
            
            if user:
                self.send_json_response({
                    'success': True,
                    'message': 'Login successful',
                    'data': {
                        'id': user['id'],
                        'username': user['username'],
                        'email': user['email'],
                        'is_admin': bool(user['is_admin'])
                    }
                })
            else:
                self.send_error_response('Invalid username or password', 401)
        except sqlite3.Error as e:
            # 故意返回详细错误信息（基于错误的注入）
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_user_profile(self, params):
        """
        用户资料 - 联合查询SQL注入
        
        漏洞点：用户ID直接拼接
        测试payload: 1 UNION SELECT 1,username,password,email,phone,address,balance,is_admin,created_at FROM users--
        """
        waf = get_waf()
        user_id = waf.filter_input(params.get('id', '1'))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在SQL注入漏洞）
        sql = f"SELECT id, username, email, phone, address, balance FROM users WHERE id = {user_id}"
        
        if DEBUG:
            print(f"[SQL] {sql}")
        
        try:
            cursor.execute(sql)
            users = cursor.fetchall()
            
            if users:
                result = []
                for user in users:
                    result.append({
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'phone': user[3],
                        'address': user[4],
                        'balance': user[5]
                    })
                self.send_json_response({
                    'success': True,
                    'data': result[0] if len(result) == 1 else result
                })
            else:
                self.send_error_response('User not found', 404)
        except sqlite3.Error as e:
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_products_search(self, params):
        """
        商品搜索 - 布尔盲注
        
        漏洞点：搜索关键词直接拼接
        测试payload: test' AND (SELECT SUBSTR(username,1,1) FROM users WHERE is_admin=1)='a'--
        """
        waf = get_waf()
        keyword = waf.filter_input(params.get('keyword', ''))
        category = waf.filter_input(params.get('category', ''))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL
        sql = f"SELECT id, name, price, category FROM products WHERE name LIKE '%{keyword}%'"
        if category:
            sql += f" AND category = '{category}'"
        sql += " AND is_active = 1"
        
        if DEBUG:
            print(f"[SQL] {sql}")
        
        try:
            cursor.execute(sql)
            products = cursor.fetchall()
            
            # 布尔盲注：只返回是否有结果，不返回详细信息
            if products:
                result = []
                for p in products:
                    result.append({
                        'id': p[0],
                        'name': p[1],
                        'price': p[2],
                        'category': p[3]
                    })
                self.send_json_response({
                    'success': True,
                    'count': len(result),
                    'data': result
                })
            else:
                self.send_json_response({
                    'success': True,
                    'count': 0,
                    'data': [],
                    'message': 'No products found'
                })
        except sqlite3.Error as e:
            # 不返回详细错误（盲注特点）
            self.send_json_response({
                'success': True,
                'count': 0,
                'data': [],
                'message': 'No products found'
            })
        finally:
            conn.close()
    
    def handle_product_detail(self, params):
        """
        商品详情 - 时间盲注
        
        漏洞点：商品ID直接拼接
        测试payload: 1 AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)
        或者使用自定义sleep: 1; SELECT CASE WHEN (1=1) THEN randomblob(500000000) END--
        """
        waf = get_waf()
        product_id = waf.filter_input(params.get('id', '1'))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在SQL注入漏洞）
        sql = f"SELECT * FROM products WHERE id = {product_id}"
        
        if DEBUG:
            print(f"[SQL] {sql}")
        
        try:
            start_time = time.time()
            cursor.execute(sql)
            product = cursor.fetchone()
            elapsed = time.time() - start_time
            
            if product:
                self.send_json_response({
                    'success': True,
                    'data': {
                        'id': product['id'],
                        'name': product['name'],
                        'description': product['description'],
                        'price': product['price'],
                        'stock': product['stock'],
                        'category': product['category'],
                        'image': product['image']
                    },
                    '_debug_time': round(elapsed, 3) if DEBUG else None
                })
            else:
                self.send_json_response({
                    'success': True,
                    'data': None,
                    'message': 'Product not found'
                })
        except sqlite3.Error as e:
            # 时间盲注不返回错误详情
            self.send_json_response({
                'success': True,
                'data': None,
                'message': 'Product not found'
            })
        finally:
            conn.close()
    
    def handle_orders_query(self, params):
        """
        订单查询 - 堆叠查询注入
        
        漏洞点：订单号直接拼接，SQLite支持有限的堆叠查询
        测试payload: ORD20231201001'; INSERT INTO users(username,password,email) VALUES('hacker','hacked','h@h.com');--
        """
        waf = get_waf()
        order_no = waf.filter_input(params.get('order_no', ''))
        user_id = waf.filter_input(params.get('user_id', ''))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL
        if order_no:
            sql = f"SELECT * FROM orders WHERE order_no = '{order_no}'"
        elif user_id:
            sql = f"SELECT * FROM orders WHERE user_id = {user_id}"
        else:
            self.send_error_response('Please provide order_no or user_id', 400)
            return
        
        if DEBUG:
            print(f"[SQL] {sql}")
        
        try:
            # 使用executescript支持堆叠查询
            if ';' in sql:
                cursor.executescript(sql)
                conn.commit()
                self.send_json_response({
                    'success': True,
                    'message': 'Query executed',
                    'data': []
                })
            else:
                cursor.execute(sql)
                orders = cursor.fetchall()
                
                result = []
                for order in orders:
                    result.append({
                        'id': order['id'],
                        'order_no': order['order_no'],
                        'product_id': order['product_id'],
                        'quantity': order['quantity'],
                        'total_price': order['total_price'],
                        'status': order['status'],
                        'created_at': order['created_at']
                    })
                
                self.send_json_response({
                    'success': True,
                    'data': result
                })
        except sqlite3.Error as e:
            self.send_error_response(f'Query error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_user_register(self, data):
        """
        用户注册 - 二次注入
        
        漏洞点：用户名存储后在其他查询中被使用
        测试：先注册用户名为 admin'-- ，然后登录或查询时触发
        """
        waf = get_waf()
        username = waf.filter_input(data.get('username', ''))
        password = data.get('password', '')
        email = data.get('email', '')
        
        if not username or not password:
            self.send_error_response('Username and password are required', 400)
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 第一步：安全地存储用户（使用参数化查询）
            # 但恶意内容会被存入数据库，在后续操作中触发
            cursor.execute('''
                INSERT INTO pending_users (username, password, email, status)
                VALUES (?, ?, ?, 'pending')
            ''', (username, hash_password(password), email))
            
            pending_id = cursor.lastrowid
            conn.commit()
            
            # 模拟审核通过后的处理（存在二次注入）
            # 这里从pending_users读取用户名并直接拼接
            cursor.execute(f"SELECT username FROM pending_users WHERE id = {pending_id}")
            pending_user = cursor.fetchone()
            
            if pending_user:
                stored_username = pending_user[0]
                # 二次注入：存储的恶意用户名在此被执行
                check_sql = f"SELECT COUNT(*) FROM users WHERE username = '{stored_username}'"
                
                if DEBUG:
                    print(f"[SQL] {check_sql}")
                
                cursor.execute(check_sql)
            
            self.send_json_response({
                'success': True,
                'message': 'Registration submitted, pending approval',
                'data': {'pending_id': pending_id}
            })
            
        except sqlite3.Error as e:
            self.send_error_response(f'Registration failed: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_products_list(self, params):
        """商品列表"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT id, name, price, category, stock FROM products WHERE is_active = 1")
            products = cursor.fetchall()
            
            result = []
            for p in products:
                result.append({
                    'id': p[0],
                    'name': p[1],
                    'price': p[2],
                    'category': p[3],
                    'stock': p[4]
                })
            
            self.send_json_response({
                'success': True,
                'data': result
            })
        except sqlite3.Error as e:
            self.send_error_response(str(e), 500)
        finally:
            conn.close()
    
    def handle_get_config(self):
        """获取当前配置"""
        self.send_json_response({
            'success': True,
            'data': {
                'difficulty': DIFFICULTY,
                'debug': DEBUG,
                'version': VERSION
            }
        })
    
    def handle_set_config(self, data):
        """设置配置（仅限本地）"""
        if self.client_address[0] not in ['127.0.0.1', '::1']:
            self.send_error_response('Only localhost can change config', 403)
            return
        
        difficulty = data.get('difficulty')
        if difficulty:
            if set_difficulty(difficulty):
                self.send_json_response({
                    'success': True,
                    'message': f'Difficulty set to {difficulty}'
                })
            else:
                self.send_error_response('Invalid difficulty level', 400)
        else:
            self.send_error_response('No config provided', 400)
    
    def handle_database_reset(self):
        """重置数据库"""
        if self.client_address[0] not in ['127.0.0.1', '::1']:
            self.send_error_response('Only localhost can reset database', 403)
            return
        
        from database import reset_database
        reset_database()
        self.send_json_response({
            'success': True,
            'message': 'Database reset completed'
        })


def run_server():
    """启动服务器"""
    # 初始化数据库
    init_database()
    
    # 创建服务器
    server = HTTPServer((HOST, PORT), VulnShopHandler)
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗  ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║  ██║██╔═══██╗██╔══██╗ ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗███████║██║   ██║██████╔╝ ║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██╔══██║██║   ██║██╔═══╝  ║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║██║  ██║╚██████╔╝██║      ║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ║
║                                                                      ║
║           SQL Injection Test Lab - For Educational Use Only          ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Version: {VERSION:<10}                                                ║
║  Difficulty: {DIFFICULTY:<7}                                              ║
║  Server: http://{HOST}:{PORT}                                         ║
║                                                                      ║
║  ⚠️  WARNING: This server contains intentional vulnerabilities!      ║
║  ⚠️  Only use on localhost for testing purposes!                     ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Available Endpoints:                                                ║
║  • POST /api/user/login      - Error-based SQL Injection             ║
║  • GET  /api/user/profile    - Union-based SQL Injection             ║
║  • GET  /api/products/search - Boolean-based Blind SQL Injection     ║
║  • GET  /api/products/detail - Time-based Blind SQL Injection        ║
║  • GET  /api/orders/query    - Stacked Queries SQL Injection         ║
║  • POST /api/user/register   - Second-order SQL Injection            ║
╠══════════════════════════════════════════════════════════════════════╣
║  Test Accounts:                                                      ║
║  • admin / admin123  (Administrator)                                 ║
║  • test  / test      (Regular User)                                  ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        server.shutdown()


if __name__ == '__main__':
    run_server()
