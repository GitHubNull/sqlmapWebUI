#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 商品处理器 - 商品相关API

包含：商品列表、商品搜索、商品详情
"""

import sqlite3
import time

from config import DEBUG
from database import get_db_connection
from waf import get_waf
from logger import sql_logger


class ProductHandlerMixin:
    """商品相关处理器Mixin"""
    
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
            sql_logger.debug("[SQL] %s", sql)
        
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
            sql_logger.debug("[SQL] %s", sql)
        
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
    
    def handle_product_create(self, data):
        """
        创建商品 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "name": "New Product",
            "description": "Product description",
            "price": 99.99,
            "stock": 100,
            "category": "electronics",
            "image": "product.jpg",
            "session_id": "abc123",
            "auth_token": "xyz789"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        name = data.get('name', '')
        description = data.get('description', '')
        price = data.get('price', 0)
        stock = data.get('stock', 0)
        category = data.get('category', '')
        image = data.get('image', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
        if not name or not price:
            self.send_json_response({
                'success': False,
                'message': 'name and price are required'
            }, 400)
            return
        
        # 验证数值参数
        try:
            price_float = float(price)
            stock_int = int(stock)
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid numeric parameters'}, 400)
            return
        
        if DEBUG:
            logger.debug("[ProductCreate] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询插入商品
            cursor.execute('''
                INSERT INTO products (name, description, price, stock, category, image)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, description, price_float, stock_int, category, image))
            conn.commit()
            product_id = cursor.lastrowid
            
            self.send_json_response({
                'success': True,
                'message': 'Product created successfully',
                'data': {
                    'product_id': product_id,
                    'name': name,
                    'price': price_float,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to create product: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_product_update(self, data):
        """
        更新商品 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "product_id": 1,
            "name": "Updated Product",
            "description": "Updated description",
            "price": 129.99,
            "stock": 50,
            "category": "electronics",
            "session_id": "abc123",
            "auth_token": "xyz789"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        product_id = data.get('product_id', '')
        name = data.get('name', '')
        description = data.get('description', '')
        price = data.get('price', '')
        stock = data.get('stock', '')
        category = data.get('category', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
        if not product_id:
            self.send_json_response({'success': False, 'message': 'product_id is required'}, 400)
            return
        
        # 验证product_id是否为有效数字
        try:
            product_id_int = int(product_id)
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid product ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[ProductUpdate] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 构建动态更新SQL（仅更新提供的字段）
            update_fields = []
            params = []
            
            if name:
                update_fields.append('name = ?')
                params.append(name)
            if description:
                update_fields.append('description = ?')
                params.append(description)
            if price:
                try:
                    update_fields.append('price = ?')
                    params.append(float(price))
                except ValueError:
                    pass
            if stock:
                try:
                    update_fields.append('stock = ?')
                    params.append(int(stock))
                except ValueError:
                    pass
            if category:
                update_fields.append('category = ?')
                params.append(category)
            
            if not update_fields:
                self.send_json_response({'success': False, 'message': 'No fields to update'}, 400)
                conn.close()
                return
            
            params.append(product_id_int)
            sql = f"UPDATE products SET {', '.join(update_fields)} WHERE id = ?"
            
            # 使用参数化查询更新商品
            cursor.execute(sql, tuple(params))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_json_response({
                    'success': True,
                    'message': 'Product updated successfully',
                    'data': {
                        'product_id': product_id,
                        'session_id': session_id
                    }
                })
            else:
                self.send_json_response({
                    'success': False,
                    'message': 'Product not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to update product: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_product_delete(self, data):
        """
        删除商品 - XML格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/xml):
        <?xml version="1.0" encoding="UTF-8"?>
        <request>
            <product_id>1</product_id>
            <reason>Discontinued</reason>
            <session_id>abc123</session_id>
            <auth_token>xyz789</auth_token>
        </request>
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        product_id = data.get('product_id', '')
        reason = data.get('reason', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
        if not product_id:
            self.send_xml_response({'success': 'false', 'message': 'product_id is required'}, 400)
            return
        
        # 验证product_id是否为有效数字
        try:
            product_id_int = int(product_id)
        except ValueError:
            self.send_xml_response({'success': 'false', 'message': 'Invalid product ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[ProductDelete] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询删除商品
            cursor.execute('DELETE FROM products WHERE id = ?', (product_id_int,))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_xml_response({
                    'success': 'true',
                    'message': 'Product deleted successfully',
                    'data': {
                        'product_id': product_id,
                        'reason': reason,
                        'session_id': session_id
                    }
                })
            else:
                self.send_xml_response({
                    'success': 'false',
                    'message': 'Product not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_xml_response({'success': 'false', 'message': f'Failed to delete product: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_products_by_category(self, data):
        """
        按分类查询商品 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：分类参数直接拼接到SQL语句
        测试payload: category=electronics' UNION SELECT * FROM secrets--
        
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询
        """
        waf = get_waf()
        category = waf.filter_input(data.get('category', ''))
        sort_by = waf.filter_input(data.get('sort_by', 'id'))
        order = waf.filter_input(data.get('order', 'ASC'))
        session_id = data.get('session_id', '')
        
        if not category:
            self.send_json_response({'success': False, 'message': 'category is required'}, 400)
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        sql = f"SELECT id, name, price, category, stock FROM products WHERE category = '{category}' AND is_active = 1 ORDER BY {sort_by} {order}"
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[ProductsByCategory] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
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
                'data': result,
                'count': len(result),
                'session_id': session_id
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Query error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_products_by_price_range(self, data):
        """
        按价格范围查询商品 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：价格参数直接拼接到SQL语句
        测试payload: min_price=0' OR '1'='1
        
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询
        """
        waf = get_waf()
        min_price = waf.filter_input(data.get('min_price', '0'))
        max_price = waf.filter_input(data.get('max_price', '999999'))
        category = waf.filter_input(data.get('category', ''))
        session_id = data.get('session_id', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        if category:
            sql = f"SELECT id, name, price, category, stock FROM products WHERE price >= {min_price} AND price <= {max_price} AND category = '{category}' AND is_active = 1"
        else:
            sql = f"SELECT id, name, price, category, stock FROM products WHERE price >= {min_price} AND price <= {max_price} AND is_active = 1"
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[ProductsByPriceRange] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
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
                'data': result,
                'count': len(result),
                'session_id': session_id
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Query error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
