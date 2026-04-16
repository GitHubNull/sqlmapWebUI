#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 优惠券处理器 - Base64 加密参数 SQL 注入演示

模拟场景：
- 外层 JSON 包含 req_id 和加密后的 data 字段
- data 使用 Base64 编码（模拟加密传输）
- data 内部是 JSON，包含实际的业务参数
- 内部参数存在 SQL 注入漏洞

用于测试 SQLMap 处理加密传输参数的能力
"""

import json
import base64
import sqlite3

from config import DEBUG
from database import get_db_connection
from waf import get_waf
from logger import sql_logger, logger


class CouponHandlerMixin:
    """优惠券处理器Mixin - Base64 加密参数 SQL 注入演示"""

    def _decode_data(self, encoded_data):
        """
        解码 data 字段（Base64 模拟加密传输）
        
        Args:
            encoded_data: Base64 编码的字符串
            
        Returns:
            dict: 解码后的 JSON 对象
            
        Raises:
            ValueError: 解码失败时抛出
        """
        try:
            # Base64 解码
            decoded_bytes = base64.b64decode(encoded_data)
            decoded_str = decoded_bytes.decode('utf-8')
            # 解析内部 JSON
            return json.loads(decoded_str)
        except Exception as e:
            raise ValueError(f"Failed to decode data: {str(e)}")

    def _encode_data(self, data):
        """
        编码 data 字段（Base64 模拟加密传输）
        
        Args:
            data: 要编码的字典
            
        Returns:
            str: Base64 编码的字符串
        """
        json_str = json.dumps(data, ensure_ascii=False)
        encoded_bytes = base64.b64encode(json_str.encode('utf-8'))
        return encoded_bytes.decode('utf-8')

    def handle_coupon_query(self, data):
        """
        优惠券查询 - 基于错误的 SQL 注入
        
        请求体示例 (application/json):
        {
            "req_id": "REQ123456",
            "data": "eyJjb3Vwb25fY29kZSI6ICJTVkVPMTAifQ=="
        }
        
        data 解码后:
        {
            "coupon_code": "SAVE10"
        }
        
        漏洞点：coupon_code 参数直接拼接到 SQL 语句
        
        SQLMap 测试方案：
        1. 使用 --eval 参数实时编码 payload
        2. 使用 tamper 脚本自动处理编码
        
        测试 payload (原始):
        SAVE10' UNION SELECT 1,flag,description,4,5,6,7,8,9,10,11,12 FROM secrets--
        
        测试 payload (编码后):
        U0FWRTEwJyBVTklPTiBTRUxFQ1QgMSxmbGFnLGRlc2NyaXB0aW9uLDQsNSw2LDcsOCw5LDEwLDExLDEyIEZST00gc2VjcmV0cy0t
        """
        waf = get_waf()
        req_id = data.get('req_id', '')
        encoded_data = data.get('data', '')
        
        if not encoded_data:
            self.send_json_response({
                'success': False,
                'message': 'data field is required'
            }, 400)
            return
        
        # 解码 data
        try:
            inner_data = self._decode_data(encoded_data)
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)
            return
        
        # 获取内部参数（存在 SQL 注入漏洞）
        coupon_code = waf.filter_input(inner_data.get('coupon_code', ''))
        category = inner_data.get('category', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在 SQL 注入漏洞）
        if category:
            sql = f"SELECT id, coupon_code, discount_type, discount_value, min_purchase, max_discount, category, status FROM coupons WHERE coupon_code = '{coupon_code}' AND category = '{category}'"
        else:
            sql = f"SELECT id, coupon_code, discount_type, discount_value, min_purchase, max_discount, category, status FROM coupons WHERE coupon_code = '{coupon_code}'"
        
        if DEBUG:
            sql_logger.debug("[Coupon SQL] %s", sql)
            logger.debug("[Coupon Query] req_id=%s, inner_data=%s", req_id, inner_data)
        
        try:
            cursor.execute(sql)
            coupons = cursor.fetchall()
            
            if coupons:
                result = []
                for coupon in coupons:
                    result.append({
                        'id': coupon[0],
                        'coupon_code': coupon[1],
                        'discount_type': coupon[2],
                        'discount_value': coupon[3],
                        'min_purchase': coupon[4],
                        'max_discount': coupon[5],
                        'category': coupon[6],
                        'status': coupon[7]
                    })
                
                # 重新编码响应内容
                response_data = {
                    'coupons': result,
                    'query_code': coupon_code,
                    'message': f'找到 {len(result)} 张优惠券'
                }
                
                self.send_json_response({
                    'success': True,
                    'req_id': req_id,
                    'data': self._encode_data(response_data)
                })
            else:
                # 重新编码空结果
                response_data = {
                    'coupons': [],
                    'message': '未找到匹配的优惠券',
                    'query_code': coupon_code
                }
                
                self.send_json_response({
                    'success': True,
                    'req_id': req_id,
                    'data': self._encode_data(response_data)
                })
        except sqlite3.Error as e:
            # 故意返回详细错误信息（基于错误的注入）
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()

    def handle_coupon_search(self, data):
        """
        优惠券搜索 - 布尔盲注 SQL 注入
        
        请求体示例 (application/json):
        {
            "req_id": "REQ789012",
            "data": "eyJrZXl3b3JkIjogIlNBVkUiLCAiY2F0ZWdvcnkiOiAiZWxlY3Ryb25pY3MifQ=="
        }
        
        data 解码后:
        {
            "keyword": "SAVE",
            "category": "electronics"
        }
        
        漏洞点：keyword 参数直接拼接到 SQL 语句的 LIKE 条件
        """
        waf = get_waf()
        req_id = data.get('req_id', '')
        encoded_data = data.get('data', '')
        
        if not encoded_data:
            self.send_json_response({
                'success': False,
                'message': 'data field is required'
            }, 400)
            return
        
        # 解码 data
        try:
            inner_data = self._decode_data(encoded_data)
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)
            return
        
        # 获取内部参数（存在 SQL 注入漏洞）
        keyword = waf.filter_input(inner_data.get('keyword', ''))
        category = inner_data.get('category', '')
        status = inner_data.get('status', 'active')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的 SQL
        sql = f"SELECT id, coupon_code, discount_type, discount_value, min_purchase, max_discount, category, status FROM coupons WHERE coupon_code LIKE '%{keyword}%' AND status = '{status}'"
        if category:
            sql += f" AND category = '{category}'"
        
        if DEBUG:
            sql_logger.debug("[Coupon Search SQL] %s", sql)
            logger.debug("[Coupon Search] req_id=%s, keyword=%s", req_id, keyword)
        
        try:
            cursor.execute(sql)
            coupons = cursor.fetchall()
            
            result = []
            for coupon in coupons:
                result.append({
                    'id': coupon[0],
                    'coupon_code': coupon[1],
                    'discount_type': coupon[2],
                    'discount_value': coupon[3],
                    'min_purchase': coupon[4],
                    'max_discount': coupon[5],
                    'category': coupon[6],
                    'status': coupon[7]
                })
            
            # 重新编码响应内容
            response_data = {
                'coupons': result,
                'count': len(result),
                'keyword': keyword
            }
            
            self.send_json_response({
                'success': True,
                'req_id': req_id,
                'data': self._encode_data(response_data)
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()

    def handle_coupon_by_category(self, data):
        """
        按分类查询优惠券 - 时间盲注 SQL 注入
        
        请求体示例 (application/json):
        {
            "req_id": "REQ345678",
            "data": "eyJjYXRlZ29yeSI6ICJlbGVjdHJvbmljcyIsICJtaW5fZGlzY291bnQiOiAifQ=="
        }
        
        data 解码后:
        {
            "category": "electronics",
            "min_discount": ""
        }
        
        漏洞点：category 参数直接拼接到 SQL 语句
        """
        waf = get_waf()
        req_id = data.get('req_id', '')
        encoded_data = data.get('data', '')
        
        if not encoded_data:
            self.send_json_response({
                'success': False,
                'message': 'data field is required'
            }, 400)
            return
        
        # 解码 data
        try:
            inner_data = self._decode_data(encoded_data)
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)
            return
        
        # 获取内部参数（存在 SQL 注入漏洞）
        category = waf.filter_input(inner_data.get('category', ''))
        min_discount = inner_data.get('min_discount', '0')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在 SQL 注入漏洞）
        sql = f"SELECT id, coupon_code, discount_type, discount_value, min_purchase, max_discount, category, status FROM coupons WHERE category = '{category}' AND discount_value >= {min_discount} AND status = 'active'"
        
        if DEBUG:
            sql_logger.debug("[Coupon Category SQL] %s", sql)
            logger.debug("[Coupon Category] req_id=%s, category=%s", req_id, category)
        
        try:
            cursor.execute(sql)
            coupons = cursor.fetchall()
            
            result = []
            for coupon in coupons:
                result.append({
                    'id': coupon[0],
                    'coupon_code': coupon[1],
                    'discount_type': coupon[2],
                    'discount_value': coupon[3],
                    'min_purchase': coupon[4],
                    'max_discount': coupon[5],
                    'category': coupon[6],
                    'status': coupon[7]
                })
            
            # 重新编码响应内容
            response_data = {
                'coupons': result,
                'count': len(result),
                'category': category
            }
            
            self.send_json_response({
                'success': True,
                'req_id': req_id,
                'data': self._encode_data(response_data)
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()

    def handle_coupon_debug_decode(self, data):
        """
        调试接口：解码 data 字段（用于测试）
        
        请求体示例 (application/json):
        {
            "data": "eyJjb3Vwb25fY29kZSI6ICJTVkVPMTAifQ=="
        }
        
        响应:
        {
            "success": true,
            "decoded": {
                "coupon_code": "SAVE10"
            }
        }
        """
        encoded_data = data.get('data', '')
        
        if not encoded_data:
            self.send_json_response({
                'success': False,
                'message': 'data field is required'
            }, 400)
            return
        
        try:
            decoded = self._decode_data(encoded_data)
            self.send_json_response({
                'success': True,
                'decoded': decoded,
                'original_data': encoded_data
            })
        except ValueError as e:
            self.send_json_response({
                'success': False,
                'message': str(e)
            }, 400)

    def handle_coupon_debug_encode(self, data):
        """
        调试接口：编码 data 字段（用于测试）
        
        请求体示例 (application/json):
        {
            "data": {
                "coupon_code": "SAVE10"
            }
        }
        
        响应:
        {
            "success": true,
            "encoded": "eyJjb3Vwb25fY29kZSI6ICJTVkVPMTAifQ=="
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
            encoded = self._encode_data(inner_data)
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
