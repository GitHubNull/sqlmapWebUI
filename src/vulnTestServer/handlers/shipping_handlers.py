#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 物流查询处理器 - XML SQL 注入演示

包含：物流查询接口

注意：
- 物流查询保留SQL注入漏洞（只读操作）
- 支持 Error-based 和 Boolean-blind 双模式检测
- 支持 CDATA 包装和 XML 实体编码绕过
"""

import sqlite3
import time

from config import DEBUG
from database import get_db_connection
from waf import get_waf
from logger import sql_logger, logger


class ShippingHandlerMixin:
    """物流查询相关处理器Mixin"""

    def handle_shipping_query(self, data):
        """
        物流查询 - XML格式 - Error-based + Boolean-blind SQL注入

        漏洞点：trackingNumber 参数直接拼接到SQL语句

        支持的检测方式：
        1. Error-based: 注入导致SQL错误，错误信息在响应中返回
           Payload: TRK' AND 1=CAST((SELECT flag FROM secrets LIMIT 1) AS INT)--

        2. Boolean-blind: 通过查询结果有无判断条件真假
           Payload: TRK' AND (SELECT SUBSTR(flag,1,1) FROM secrets)='F'--
           - 条件为真：返回物流信息
           - 条件为假：返回空结果

        3. CDATA绕过（针对WAF）:
           <trackingNumber><![CDATA[TRK' OR '1'='1']]></trackingNumber>

        4. XML实体编码绕过:
           <trackingNumber>&#84;&#82;&#75;' OR '1'='1'</trackingNumber>

        XML请求示例 (30个参数):
        <?xml version="1.0" encoding="UTF-8"?>
        <shippingQuery>
            <version>1.0</version>
            <requestId>req_001</requestId>
            <timestamp>1710489600000</timestamp>
            <clientId>web_client_001</clientId>
            <apiKey>ak_live_xxxxx</apiKey>
            <trackingNumber>TRK202403150001</trackingNumber>
            <carrierCode>SF</carrierCode>
            <queryType>realtime</queryType>
            <senderProvince>广东省</senderProvince>
            <senderCity>深圳市</senderCity>
            <senderDistrict>南山区</senderDistrict>
            <receiverProvince>北京市</receiverProvince>
            <receiverCity>北京市</receiverCity>
            <receiverDistrict>朝阳区</receiverDistrict>
            <userId>10001</userId>
            <userName>张三</userName>
            <userPhone>138****8888</userPhone>
            <userEmail>test@example.com</userEmail>
            <orderNo>ORD202403150001</orderNo>
            <orderId>100001</orderId>
            <shopId>SHOP001</shopId>
            <deliveryMethod>standard</deliveryMethod>
            <priority>normal</priority>
            <signature>required</signature>
            <insurance>true</insurance>
            <sessionId>sess_abc123</sessionId>
            <deviceFingerprint>fp_win_chrome_123</deviceFingerprint>
            <userAgent>Mozilla/5.0</userAgent>
            <clientIp>127.0.0.1</clientIp>
            <extraData><![CDATA[{"source":"web"}]]></extraData>
        </shippingQuery>

        注意：此接口保留SQL注入以供测试，但不支持堆叠查询（避免数据修改）
        """
        waf = get_waf()

        # 提取所有参数（约30个）
        version = data.get('version', '')
        request_id = data.get('requestId', '')
        timestamp = data.get('timestamp', '')
        client_id = data.get('clientId', '')
        api_key = data.get('apiKey', '')

        # trackingNumber 是注入点
        tracking_number = data.get('trackingNumber', '')

        carrier_code = data.get('carrierCode', '')
        query_type = data.get('queryType', '')

        sender_province = data.get('senderProvince', '')
        sender_city = data.get('senderCity', '')
        sender_district = data.get('senderDistrict', '')
        receiver_province = data.get('receiverProvince', '')
        receiver_city = data.get('receiverCity', '')
        receiver_district = data.get('receiverDistrict', '')

        user_id = data.get('userId', '')
        user_name = data.get('userName', '')
        user_phone = data.get('userPhone', '')
        user_email = data.get('userEmail', '')

        order_no = data.get('orderNo', '')
        order_id = data.get('orderId', '')
        shop_id = data.get('shopId', '')

        delivery_method = data.get('deliveryMethod', '')
        priority = data.get('priority', '')
        signature = data.get('signature', '')
        insurance = data.get('insurance', '')

        session_id = data.get('sessionId', '')
        device_fingerprint = data.get('deviceFingerprint', '')
        user_agent = data.get('userAgent', '')
        client_ip = data.get('clientIp', '')
        extra_data = data.get('extraData', '')

        if not tracking_number:
            self.send_json_response({
                'success': False,
                'message': 'trackingNumber is required',
                'params_received': len(data)
            }, 400)
            return

        # WAF 检查
        blocked, reason = waf.check(tracking_number)
        if blocked:
            self.send_json_response({
                'success': False,
                'message': f'WAF Blocked: {reason}',
                'tracking_number': tracking_number[:20] + '...' if len(tracking_number) > 20 else tracking_number
            }, 403)
            return

        if DEBUG:
            logger.debug(
                "[ShippingQuery] version=%s, requestId=%s, clientId=%s, "
                "trackingNumber=%s, carrierCode=%s, userId=%s, sessionId=%s",
                version, request_id, client_id, tracking_number, carrier_code, user_id, session_id
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        # 构建存在漏洞的SQL（字符串拼接）- trackingNumber 是注入点
        sql = f"SELECT * FROM shipping_logs WHERE tracking_number = '{tracking_number}'"

        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)

        try:
            start_time = time.time()
            cursor.execute(sql)
            results = cursor.fetchall()
            elapsed_time = time.time() - start_time

            # 构建响应
            shipping_info = []
            for row in results:
                shipping_info.append({
                    'id': row['id'],
                    'tracking_number': row['tracking_number'],
                    'carrier_code': row['carrier_code'],
                    'status': row['status'],
                    'location': row['location'],
                    'weight': row['weight'],
                    'notes': row['notes'],
                    'update_time': row['update_time']
                })

            # 返回响应，包含所有接收到的参数信息（用于演示）
            response_data = {
                'success': True,
                'data': shipping_info[0] if shipping_info else None,
                'count': len(shipping_info),
                'query_time_ms': round(elapsed_time * 1000, 2),
                'request_info': {
                    'request_id': request_id,
                    'client_id': client_id,
                    'timestamp': timestamp,
                    'params_count': len(data)
                }
            }

            # 如果没有结果，返回提示信息（用于 Boolean-blind 检测）
            if not shipping_info:
                response_data['message'] = 'No shipping information found for the given tracking number'

            self.send_json_response(response_data)

        except sqlite3.Error as e:
            # Error-based 检测：返回详细的 SQL 错误信息
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
