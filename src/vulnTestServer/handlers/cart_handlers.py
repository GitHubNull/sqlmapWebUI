#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 购物车处理器 - 购物车相关API

包含：添加购物车、更新购物车

注意：购物车操作涉及数据修改，使用参数化查询保护，避免SQL注入导致数据污染
"""

import sqlite3

from config import DEBUG
from database import get_db_connection
from logger import logger


class CartHandlerMixin:
    """购物车相关处理器Mixin"""
    
    def handle_cart_add(self, data):
        """
        添加购物车 - URL-encoded格式 - 安全接口
        
        请求体示例 (application/x-www-form-urlencoded):
        user_id=1&product_id=2&quantity=1&session_id=abc123&csrf_token=xyz789
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        user_id = data.get('user_id', '')
        product_id = data.get('product_id', '')
        quantity = data.get('quantity', '1')
        session_id = data.get('session_id', '')  # 会话ID
        csrf_token = data.get('csrf_token', '')  # CSRF token
        
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
            logger.debug("[CartAdd] session_id=%s, csrf_token=%s", session_id, csrf_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询，安全插入数据
            cursor.execute('''
                INSERT INTO cart (user_id, product_id, quantity, session_id)
                VALUES (?, ?, ?, ?)
            ''', (user_id_int, product_id_int, quantity_int, session_id))
            conn.commit()
            cart_id = cursor.lastrowid
            
            self.send_json_response({
                'success': True,
                'message': 'Added to cart',
                'data': {
                    'cart_id': cart_id,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to add to cart: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_cart_update(self, data):
        """
        更新购物车 - URL-encoded格式 - 安全接口
        
        请求体示例 (application/x-www-form-urlencoded):
        cart_id=1&quantity=3&session_id=abc123&csrf_token=xyz789
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        cart_id = data.get('cart_id', '')
        quantity = data.get('quantity', '')
        session_id = data.get('session_id', '')  # 会话ID
        csrf_token = data.get('csrf_token', '')  # CSRF token
        
        if not cart_id:
            self.send_json_response({'success': False, 'message': 'cart_id is required'}, 400)
            return
        
        # 验证参数是否为有效数字
        try:
            cart_id_int = int(cart_id)
            quantity_int = int(quantity) if quantity else 1
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid numeric parameters'}, 400)
            return
        
        if DEBUG:
            logger.debug("[CartUpdate] session_id=%s, csrf_token=%s", session_id, csrf_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询，安全更新数据
            cursor.execute('UPDATE cart SET quantity = ? WHERE id = ?', (quantity_int, cart_id_int))
            conn.commit()
            
            self.send_json_response({
                'success': True,
                'message': 'Cart updated',
                'data': {
                    'cart_id': cart_id,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to update cart: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_cart_delete(self, data):
        """
        删除购物车项 - XML格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/xml):
        <?xml version="1.0" encoding="UTF-8"?>
        <request>
            <cart_id>1</cart_id>
            <reason>Removed by user</reason>
            <session_id>abc123</session_id>
            <csrf_token>xyz789</csrf_token>
        </request>
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        cart_id = data.get('cart_id', '')
        reason = data.get('reason', '')
        session_id = data.get('session_id', '')
        csrf_token = data.get('csrf_token', '')
        
        if not cart_id:
            self.send_xml_response({'success': 'false', 'message': 'cart_id is required'}, 400)
            return
        
        # 验证cart_id是否为有效数字
        try:
            cart_id_int = int(cart_id)
        except ValueError:
            self.send_xml_response({'success': 'false', 'message': 'Invalid cart ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[CartDelete] session_id=%s, csrf_token=%s", session_id, csrf_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询删除购物车项
            cursor.execute('DELETE FROM cart WHERE id = ?', (cart_id_int,))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_xml_response({
                    'success': 'true',
                    'message': 'Cart item deleted successfully',
                    'data': {
                        'cart_id': cart_id,
                        'reason': reason,
                        'session_id': session_id
                    }
                })
            else:
                self.send_xml_response({
                    'success': 'false',
                    'message': 'Cart item not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_xml_response({'success': 'false', 'message': f'Failed to delete cart item: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_cart_clear(self, data):
        """
        清空购物车 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "user_id": 1,
            "session_id": "abc123",
            "csrf_token": "xyz789"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        user_id = data.get('user_id', '')
        session_id = data.get('session_id', '')
        csrf_token = data.get('csrf_token', '')
        
        if not user_id:
            self.send_json_response({'success': False, 'message': 'user_id is required'}, 400)
            return
        
        # 验证user_id是否为有效数字
        try:
            user_id_int = int(user_id)
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid user ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[CartClear] session_id=%s, csrf_token=%s", session_id, csrf_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询清空用户购物车
            cursor.execute('DELETE FROM cart WHERE user_id = ?', (user_id_int,))
            deleted_count = cursor.rowcount
            conn.commit()
            
            self.send_json_response({
                'success': True,
                'message': 'Cart cleared successfully',
                'data': {
                    'user_id': user_id,
                    'deleted_count': deleted_count,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to clear cart: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_cart_query(self, data):
        """
        购物车查询 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：用户ID直接拼接到SQL语句
        测试payload: user_id=1' OR '1'='1
        
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询
        """
        waf = get_waf()
        user_id = waf.filter_input(data.get('user_id', ''))
        session_id = waf.filter_input(data.get('session_id', ''))
        
        if not user_id:
            self.send_json_response({'success': False, 'message': 'user_id is required'}, 400)
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        sql = f"""SELECT c.id, c.user_id, c.product_id, c.quantity, c.session_id, 
                         p.name as product_name, p.price as product_price
                  FROM cart c 
                  JOIN products p ON c.product_id = p.id 
                  WHERE c.user_id = {user_id}"""
        
        if session_id:
            sql += f" AND c.session_id = '{session_id}'"
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
        
        try:
            cursor.execute(sql)
            items = cursor.fetchall()
            
            result = []
            total = 0
            for item in items:
                subtotal = item[3] * item[6]  # quantity * price
                total += subtotal
                result.append({
                    'cart_id': item[0],
                    'user_id': item[1],
                    'product_id': item[2],
                    'quantity': item[3],
                    'session_id': item[4],
                    'product_name': item[5],
                    'product_price': item[6],
                    'subtotal': subtotal
                })
            
            self.send_json_response({
                'success': True,
                'data': result,
                'count': len(result),
                'total': total
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Query error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
