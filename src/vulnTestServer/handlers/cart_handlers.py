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
