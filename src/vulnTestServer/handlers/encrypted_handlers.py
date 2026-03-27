#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 加密参数处理器 - 嵌套加密参数 SQL 注入演示

模拟场景：
- 外层 JSON 包含 req_id 和加密后的 content 字段
- content 使用 Base64 编码（模拟加密）
- content 内部是 JSON，包含实际的业务参数
- 内部参数存在 SQL 注入漏洞

用于测试 SQLMap 处理嵌套加密参数的能力
"""

import json
import base64
import sqlite3

from config import DEBUG
from database import get_db_connection
from waf import get_waf
from logger import sql_logger, logger


class EncryptedHandlerMixin:
    """加密参数处理器Mixin - 嵌套加密参数 SQL 注入演示"""

    def _decode_content(self, encoded_content):
        """
        解码 content 字段（Base64 模拟加密）
        
        Args:
            encoded_content: Base64 编码的字符串
            
        Returns:
            dict: 解码后的 JSON 对象
            
        Raises:
            ValueError: 解码失败时抛出
        """
        try:
            # Base64 解码
            decoded_bytes = base64.b64decode(encoded_content)
            decoded_str = decoded_bytes.decode('utf-8')
            # 解析内部 JSON
            return json.loads(decoded_str)
        except Exception as e:
            raise ValueError(f"Failed to decode content: {str(e)}")

    def _encode_content(self, data):
        """
        编码 content 字段（Base64 模拟加密）
        
        Args:
            data: 要编码的字典
            
        Returns:
            str: Base64 编码的字符串
        """
        json_str = json.dumps(data, ensure_ascii=False)
        encoded_bytes = base64.b64encode(json_str.encode('utf-8'))
        return encoded_bytes.decode('utf-8')

    def handle_encrypted_user_query(self, data):
        """
        加密参数用户查询 - 基于错误的 SQL 注入
        
        请求体示例 (application/json):
        {
            "req_id": "REQ123456",
            "content": "eyJuYW1lIjogIkFsaWNlIiwgImFnZSI6IDE4fQ=="
        }
        
        content 解码后:
        {
            "name": "Alice",
            "age": 18
        }
        
        漏洞点：name 参数直接拼接到 SQL 语句
        
        SQLMap 测试方案：
        1. 使用 --eval 参数实时编码 payload
        2. 使用 tamper 脚本自动处理编码
        
        测试 payload (原始):
        Alice' AND 1=1--
        
        测试 payload (编码后):
        QWxpY2UnIEFORCAxPTEtLQ==
        """
        waf = get_waf()
        req_id = data.get('req_id', '')
        encoded_content = data.get('content', '')
        
        if not encoded_content:
            self.send_json_response({
                'success': False,
                'message': 'content field is required'
            }, 400)
            return
        
        # 解码 content
        try:
            inner_data = self._decode_content(encoded_content)
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)
            return
        
        # 获取内部参数（存在 SQL 注入漏洞）
        name = waf.filter_input(inner_data.get('name', ''))
        age = inner_data.get('age', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在 SQL 注入漏洞）
        # 查询 users 表中 username 匹配的记录
        sql = f"SELECT id, username, email, phone, address, balance FROM users WHERE username = '{name}'"
        
        if DEBUG:
            sql_logger.debug("[Encrypted SQL] %s", sql)
            logger.debug("[Encrypted Query] req_id=%s, inner_data=%s", req_id, inner_data)
        
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
                
                # 重新编码响应内容
                response_content = {
                    'users': result,
                    'query_name': name,
                    'query_age': age
                }
                
                self.send_json_response({
                    'success': True,
                    'req_id': req_id,
                    'content': self._encode_content(response_content)
                })
            else:
                # 重新编码空结果
                response_content = {
                    'users': [],
                    'message': 'No users found',
                    'query_name': name
                }
                
                self.send_json_response({
                    'success': True,
                    'req_id': req_id,
                    'content': self._encode_content(response_content)
                })
        except sqlite3.Error as e:
            # 故意返回详细错误信息（基于错误的注入）
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()

    def handle_encrypted_product_search(self, data):
        """
        加密参数商品搜索 - 布尔盲注 SQL 注入
        
        请求体示例 (application/json):
        {
            "req_id": "REQ789012",
            "content": "eyJrZXl3b3JkIjogImlQaG9uZSIsICJjYXRlZ29yeSI6ICJlbGVjdHJvbmljcyJ9"
        }
        
        content 解码后:
        {
            "keyword": "iPhone",
            "category": "electronics"
        }
        
        漏洞点：keyword 参数直接拼接到 SQL 语句的 LIKE 条件
        
        SQLMap 测试方案：
        使用 --eval 参数实时编码 payload
        
        测试 payload (原始):
        iPhone%' AND (SELECT COUNT(*) FROM users) > 0--
        
        测试 payload (编码后):
        aVBob25lJScgQU5EIChTRUxFQ1QgQ09VTlQoKikgRlJPTSB1c2VycykgPiAwLS0=
        """
        waf = get_waf()
        req_id = data.get('req_id', '')
        encoded_content = data.get('content', '')
        
        if not encoded_content:
            self.send_json_response({
                'success': False,
                'message': 'content field is required'
            }, 400)
            return
        
        # 解码 content
        try:
            inner_data = self._decode_content(encoded_content)
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)
            return
        
        # 获取内部参数（存在 SQL 注入漏洞）
        keyword = waf.filter_input(inner_data.get('keyword', ''))
        category = inner_data.get('category', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的 SQL
        if category:
            sql = f"SELECT id, name, description, price, stock, category FROM products WHERE name LIKE '%{keyword}%' AND category = '{category}'"
        else:
            sql = f"SELECT id, name, description, price, stock, category FROM products WHERE name LIKE '%{keyword}%'"
        
        if DEBUG:
            sql_logger.debug("[Encrypted SQL] %s", sql)
            logger.debug("[Encrypted Product Search] req_id=%s, keyword=%s", req_id, keyword)
        
        try:
            cursor.execute(sql)
            products = cursor.fetchall()
            
            result = []
            for product in products:
                result.append({
                    'id': product[0],
                    'name': product[1],
                    'description': product[2],
                    'price': product[3],
                    'stock': product[4],
                    'category': product[5]
                })
            
            # 重新编码响应内容
            response_content = {
                'products': result,
                'count': len(result),
                'keyword': keyword
            }
            
            self.send_json_response({
                'success': True,
                'req_id': req_id,
                'content': self._encode_content(response_content)
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()

    def handle_encrypted_order_query(self, data):
        """
        加密参数订单查询 - 时间盲注 SQL 注入
        
        请求体示例 (application/json):
        {
            "req_id": "REQ345678",
            "content": "eyJvcmRlcl9ubyI6ICJPUkQyMDIzMTIwMTAwMSIsICJ1c2VyX2lkIjogMn0="
        }
        
        content 解码后:
        {
            "order_no": "ORD20231201001",
            "user_id": 2
        }
        
        漏洞点：order_no 参数直接拼接到 SQL 语句
        
        SQLMap 测试方案：
        使用 --eval 参数实时编码 payload
        
        测试 payload (原始):
        ORD20231201001' AND (SELECT CASE WHEN (1=1) THEN randomblob(1000000000) ELSE 0 END)--
        
        测试 payload (编码后):
        T1JEMjAyMzEyMDEwMDEnIEFORCAoU0VMRUNUIENBU0UgV0hFTiAoMT0xKSBUSEVOIHJhbmRvbWJsb2IoMTAwMDAwMDAwMCkgRUxTRSAwIEVORCktLQ==
        """
        waf = get_waf()
        req_id = data.get('req_id', '')
        encoded_content = data.get('content', '')
        
        if not encoded_content:
            self.send_json_response({
                'success': False,
                'message': 'content field is required'
            }, 400)
            return
        
        # 解码 content
        try:
            inner_data = self._decode_content(encoded_content)
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)
            return
        
        # 获取内部参数（存在 SQL 注入漏洞）
        order_no = waf.filter_input(inner_data.get('order_no', ''))
        user_id = inner_data.get('user_id', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在 SQL 注入漏洞）
        sql = f"""
            SELECT o.id, o.order_no, o.user_id, u.username, o.total_price, o.status, o.shipping_address 
            FROM orders o 
            JOIN users u ON o.user_id = u.id 
            WHERE o.order_no = '{order_no}'
        """
        
        if DEBUG:
            sql_logger.debug("[Encrypted SQL] %s", sql)
            logger.debug("[Encrypted Order Query] req_id=%s, order_no=%s", req_id, order_no)
        
        try:
            cursor.execute(sql)
            orders = cursor.fetchall()
            
            result = []
            for order in orders:
                result.append({
                    'id': order[0],
                    'order_no': order[1],
                    'user_id': order[2],
                    'username': order[3],
                    'total_price': order[4],
                    'status': order[5],
                    'shipping_address': order[6]
                })
            
            # 重新编码响应内容
            response_content = {
                'orders': result,
                'count': len(result)
            }
            
            self.send_json_response({
                'success': True,
                'req_id': req_id,
                'content': self._encode_content(response_content)
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()

    def handle_encrypted_debug_decode(self, data):
        """
        调试接口：解码 content 字段（用于测试）
        
        请求体示例 (application/json):
        {
            "content": "eyJuYW1lIjogIkFsaWNlIiwgImFnZSI6IDE4fQ=="
        }
        
        响应:
        {
            "success": true,
            "decoded": {
                "name": "Alice",
                "age": 18
            }
        }
        """
        encoded_content = data.get('content', '')
        
        if not encoded_content:
            self.send_json_response({
                'success': False,
                'message': 'content field is required'
            }, 400)
            return
        
        try:
            decoded = self._decode_content(encoded_content)
            self.send_json_response({
                'success': True,
                'decoded': decoded,
                'original_content': encoded_content
            })
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)

    def handle_encrypted_debug_encode(self, data):
        """
        调试接口：编码 content 字段（用于测试）
        
        请求体示例 (application/json):
        {
            "data": {
                "name": "Alice",
                "age": 18
            }
        }
        
        响应:
        {
            "success": true,
            "encoded": "eyJuYW1lIjogIkFsaWNlIiwgImFnZSI6IDE4fQ=="
        }
        """
        inner_data = data.get('data', {})
        
        if not inner_data:
            self.send_json_response({
                'success': False,
                'message': 'data field is required'
            }, 400)
            return
        
        try:
            encoded = self._encode_content(inner_data)
            self.send_json_response({
                'success': True,
                'encoded': encoded,
                'original_data': inner_data
            })
        except Exception as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 500)
