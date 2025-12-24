#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 系统处理器 - 系统相关API

包含：API信息、配置管理、数据库重置、反馈

注意：
- 数据修改操作（反馈）使用参数化查询保护
"""

import sqlite3
import uuid

from config import DEBUG, VERSION, DIFFICULTY, APP_NAME
from database import get_db_connection
from waf import get_waf, set_difficulty
from logger import logger


class SystemHandlerMixin:
    """系统相关处理器Mixin"""
    
    def handle_api_info(self):
        """API信息 - 包含漏洞说明"""
        self.send_json_response({
            'success': True,
            'data': {
                'name': APP_NAME,
                'version': VERSION,
                'difficulty': DIFFICULTY,
                'notes': '数据修改操作(INSERT/UPDATE)使用参数化查询保护，只有只读查询(SELECT)存在SQL注入漏洞',
                'endpoints': [
                    {'method': 'POST', 'path': '/api/user/login', 'vuln_type': 'Error-based SQLi (只读)', 'body_type': 'JSON', 'session_fields': ['session_id', 'device_id']},
                    {'method': 'GET', 'path': '/api/user/profile', 'vuln_type': 'Union-based SQLi (只读)'},
                    {'method': 'POST', 'path': '/api/user/update', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'token', 'device_id']},
                    {'method': 'GET', 'path': '/api/products/search', 'vuln_type': 'Boolean-based Blind SQLi (只读)'},
                    {'method': 'GET', 'path': '/api/products/detail', 'vuln_type': 'Time-based Blind SQLi (只读)'},
                    {'method': 'POST', 'path': '/api/cart/add', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'URL-encoded', 'session_fields': ['session_id', 'csrf_token']},
                    {'method': 'POST', 'path': '/api/cart/update', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'URL-encoded', 'session_fields': ['session_id', 'csrf_token']},
                    {'method': 'POST', 'path': '/api/orders/create', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'token', 'user_agent']},
                    {'method': 'POST', 'path': '/api/orders/cancel', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'GET', 'path': '/api/orders/query', 'vuln_type': 'SQL注入 (只读)'},
                    {'method': 'POST', 'path': '/api/user/register', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'captcha_token']},
                    {'method': 'POST', 'path': '/api/feedback', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'token', 'timestamp']},
                ]
            }
        })
    
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
    
    def handle_feedback(self, data):
        """
        提交反馈 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "user_id": 1,
            "title": "反馈标题",
            "content": "反馈内容",
            "rating": 5,
            "session_id": "abc123",
            "token": "xyz789",
            "timestamp": "1703404800000"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        user_id = data.get('user_id', '')
        title = data.get('title', '')
        content = data.get('content', '')
        rating = data.get('rating', 5)
        session_id = data.get('session_id', '')  # 会话ID
        token = data.get('token', '')  # token
        timestamp = data.get('timestamp', '')  # 时间戳
        
        if not title or not content:
            self.send_json_response({'success': False, 'message': 'title and content are required'}, 400)
            return
        
        # 验证参数
        try:
            user_id_int = int(user_id) if user_id else None
            rating_int = int(rating) if rating else 5
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid numeric parameters'}, 400)
            return
        
        if DEBUG:
            logger.debug("[Feedback] session_id=%s, token=%s, timestamp=%s", session_id, token, timestamp)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询，安全插入数据
            cursor.execute('''
                INSERT INTO feedback (user_id, session_id, title, content, rating)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id_int, session_id, title, content, rating_int))
            conn.commit()
            feedback_id = cursor.lastrowid
            
            self.send_json_response({
                'success': True,
                'message': 'Feedback submitted successfully',
                'data': {
                    'feedback_id': feedback_id,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to submit feedback: {str(e)}'}, 500)
        finally:
            conn.close()
