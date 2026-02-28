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
    
    def handle_order_update_status(self, data):
        """
        更新订单状态 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "order_id": 1,
            "status": "shipped",
            "tracking_number": "TRACK123456",
            "session_id": "abc123",
            "auth_token": "xyz789"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        order_id = data.get('order_id', '')
        status = data.get('status', '')
        tracking_number = data.get('tracking_number', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
        if not order_id or not status:
            self.send_json_response({
                'success': False,
                'message': 'order_id and status are required'
            }, 400)
            return
        
        # 验证order_id是否为有效数字
        try:
            order_id_int = int(order_id)
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid order ID'}, 400)
            return
        
        # 验证状态值
        valid_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded']
        if status not in valid_statuses:
            self.send_json_response({
                'success': False,
                'message': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
            }, 400)
            return
        
        if DEBUG:
            logger.debug("[OrderUpdateStatus] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询更新订单状态
            cursor.execute('''
                UPDATE orders SET status = ? WHERE id = ?
            ''', (status, order_id_int))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_json_response({
                    'success': True,
                    'message': 'Order status updated successfully',
                    'data': {
                        'order_id': order_id,
                        'status': status,
                        'tracking_number': tracking_number,
                        'session_id': session_id
                    }
                })
            else:
                self.send_json_response({
                    'success': False,
                    'message': 'Order not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to update order status: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_order_delete(self, data):
        """
        删除订单 - XML格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/xml):
        <?xml version="1.0" encoding="UTF-8"?>
        <request>
            <order_id>1</order_id>
            <reason>Customer request</reason>
            <session_id>abc123</session_id>
            <auth_token>xyz789</auth_token>
        </request>
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        order_id = data.get('order_id', '')
        reason = data.get('reason', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
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
            logger.debug("[OrderDelete] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询删除订单
            cursor.execute('DELETE FROM orders WHERE id = ?', (order_id_int,))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_xml_response({
                    'success': 'true',
                    'message': 'Order deleted successfully',
                    'data': {
                        'order_id': order_id,
                        'reason': reason,
                        'session_id': session_id
                    }
                })
            else:
                self.send_xml_response({
                    'success': 'false',
                    'message': 'Order not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_xml_response({'success': 'false', 'message': f'Failed to delete order: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_orders_stats(self, data):
        """
        订单统计查询 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：分组字段直接拼接到SQL语句
        测试payload: group_by=status' UNION SELECT * FROM secrets--
        
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询
        """
        waf = get_waf()
        group_by = waf.filter_input(data.get('group_by', 'status'))
        status_filter = waf.filter_input(data.get('status', ''))
        session_id = data.get('session_id', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        if status_filter:
            sql = f"SELECT {group_by}, COUNT(*) as count, SUM(total_price) as total FROM orders WHERE status = '{status_filter}' GROUP BY {group_by}"
        else:
            sql = f"SELECT {group_by}, COUNT(*) as count, SUM(total_price) as total FROM orders GROUP BY {group_by}"
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[OrdersStats] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
            stats = cursor.fetchall()
            
            result = []
            for row in stats:
                result.append({
                    'group_value': row[0],
                    'count': row[1],
                    'total': row[2] if row[2] else 0
                })
            
            self.send_json_response({
                'success': True,
                'data': result,
                'count': len(result),
                'session_id': session_id
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Query error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_orders_advanced_search(self, data):
        """
        订单高级搜索 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：搜索条件直接拼接到SQL语句
        测试payload: status=pending' OR '1'='1
        
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询
        """
        waf = get_waf()
        user_id = waf.filter_input(data.get('user_id', ''))
        status = waf.filter_input(data.get('status', ''))
        min_price = waf.filter_input(data.get('min_price', ''))
        max_price = waf.filter_input(data.get('max_price', ''))
        date_from = waf.filter_input(data.get('date_from', ''))
        date_to = waf.filter_input(data.get('date_to', ''))
        session_id = data.get('session_id', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        conditions = []
        
        if user_id:
            conditions.append(f"user_id = {user_id}")
        if status:
            conditions.append(f"status = '{status}'")
        if min_price:
            conditions.append(f"total_price >= {min_price}")
        if max_price:
            conditions.append(f"total_price <= {max_price}")
        if date_from:
            conditions.append(f"created_at >= '{date_from}'")
        if date_to:
            conditions.append(f"created_at <= '{date_to}'")
        
        if conditions:
            sql = f"SELECT * FROM orders WHERE {' AND '.join(conditions)} ORDER BY created_at DESC"
        else:
            sql = "SELECT * FROM orders ORDER BY created_at DESC LIMIT 50"
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[OrdersAdvancedSearch] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
            orders = cursor.fetchall()
            
            result = []
            for order in orders:
                result.append({
                    'id': order['id'],
                    'order_no': order['order_no'],
                    'user_id': order['user_id'],
                    'product_id': order['product_id'],
                    'quantity': order['quantity'],
                    'total_price': order['total_price'],
                    'status': order['status'],
                    'created_at': order['created_at']
                })
            
            self.send_json_response({
                'success': True,
                'data': result,
                'count': len(result),
                'session_id': session_id
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Query error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
