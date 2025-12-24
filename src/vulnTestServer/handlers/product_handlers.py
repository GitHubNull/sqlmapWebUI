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
