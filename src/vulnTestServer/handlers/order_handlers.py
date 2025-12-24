#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 订单处理器 - 订单相关API

包含：订单创建、订单查询、订单取消

注意：
- 订单查询保留SQL注入漏洞（只读操作）
- 订单创建/取消使用参数化查询保护（数据修改操作）
"""

import sqlite3
import uuid
from datetime import datetime

from config import DEBUG
from database import get_db_connection
from waf import get_waf
from logger import sql_logger, logger


class OrderHandlerMixin:
    """订单相关处理器Mixin"""
    
    def handle_order_create(self, data):
        """
        创建订单 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "user_id": 1,
            "product_id": 2,
            "quantity": 1,
            "shipping_address": "123 Main St",
            "session_id": "abc123",
            "token": "xyz789",
            "user_agent": "Mozilla/5.0..."
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        user_id = data.get('user_id', '')
        product_id = data.get('product_id', '')
        quantity = data.get('quantity', 1)
        shipping_address = data.get('shipping_address', '')
        session_id = data.get('session_id', '')  # 会话ID
        token = data.get('token', '')  # token
        user_agent = data.get('user_agent', '')  # User-Agent
        
        if not user_id or not product_id:
            self.send_json_response({'success': False, 'message': 'user_id and product_id are required'}, 400)
            return
        
        # 验证参数是否为有效数字
        try:
            user_id_int = int(user_id)
            product_id_int = int(product_id)
            quantity_int = int(quantity)
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid numeric parameters'}, 400)
            return
        
        if DEBUG:
            logger.debug("[OrderCreate] session_id=%s, token=%s, user_agent=%s", session_id, token, user_agent)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询查询商品价格
            cursor.execute('SELECT price FROM products WHERE id = ?', (product_id_int,))
            product = cursor.fetchone()
            
            if not product:
                self.send_json_response({'success': False, 'message': 'Product not found'}, 404)
                conn.close()
                return
            
            total_price = product['price'] * quantity_int
            order_no = f"ORD{datetime.now().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:6].upper()}"
            
            # 使用参数化查询插入订单
            cursor.execute('''
                INSERT INTO orders (user_id, product_id, quantity, total_price, status, shipping_address, order_no)
                VALUES (?, ?, ?, ?, 'pending', ?, ?)
            ''', (user_id_int, product_id_int, quantity_int, total_price, shipping_address, order_no))
            conn.commit()
            order_id = cursor.lastrowid
            
            self.send_json_response({
                'success': True,
                'message': 'Order created successfully',
                'data': {
                    'order_id': order_id,
                    'order_no': order_no,
                    'total_price': total_price,
                    'status': 'pending',
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to create order: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_orders_query(self, params):
        """
        订单查询 - 保留SQL注入漏洞（只读查询）
            
        漏洞点：订单号或用户ID直接拼接到SQL语句
        测试payload: order_no=' OR '1'='1
            
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询（避免数据修改）
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
            sql_logger.debug("[SQL] %s", sql)
            
        try:
            # 不使用executescript，避免堆叠查询修改数据
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
    
    def handle_order_cancel(self, data):
        """
        取消订单 - XML格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/xml):
        <?xml version="1.0" encoding="UTF-8"?>
        <request>
            <order_id>1</order_id>
            <reason>不想要了</reason>
            <session_id>abc123</session_id>
            <auth_token>xyz789</auth_token>
        </request>
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        order_id = data.get('order_id', '')
        reason = data.get('reason', '')
        session_id = data.get('session_id', '')  # 会话ID
        auth_token = data.get('auth_token', '')  # 认证token
        
        if not order_id:
            self.send_xml_response({'success': 'false', 'message': 'order_id is required'}, 400)
            return
        
        # 验证order_id是否为有效数字
        try:
            order_id_int = int(order_id)
        except ValueError:
            self.send_xml_response({'success': 'false', 'message': 'Invalid order ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[OrderCancel] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询，安全更新数据
            cursor.execute('UPDATE orders SET status = ? WHERE id = ?', ('cancelled', order_id_int))
            conn.commit()
            
            self.send_xml_response({
                'success': 'true',
                'message': 'Order cancelled successfully',
                'data': {
                    'order_id': order_id,
                    'reason': reason,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_xml_response({'success': 'false', 'message': f'Failed to cancel order: {str(e)}'}, 500)
        finally:
            conn.close()
