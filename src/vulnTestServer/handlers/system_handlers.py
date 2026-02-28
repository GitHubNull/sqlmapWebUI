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
from logger import logger, LOG_DIR, sql_logger


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
                    # 原有接口
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
                    
                    # 用户模块扩展接口
                    {'method': 'POST', 'path': '/api/user/delete', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/user/change-password', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/user/list', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    {'method': 'POST', 'path': '/api/user/search', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    
                    # 商品模块扩展接口
                    {'method': 'POST', 'path': '/api/products/create', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/products/update', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/products/delete', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/products/category', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    {'method': 'POST', 'path': '/api/products/price-range', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    
                    # 订单模块扩展接口
                    {'method': 'POST', 'path': '/api/orders/update-status', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/orders/delete', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/orders/stats', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    {'method': 'POST', 'path': '/api/orders/advanced-search', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    
                    # 购物车模块扩展接口
                    {'method': 'POST', 'path': '/api/cart/delete', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'csrf_token']},
                    {'method': 'POST', 'path': '/api/cart/clear', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'csrf_token']},
                    {'method': 'POST', 'path': '/api/cart/query', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    
                    # 反馈模块扩展接口
                    {'method': 'POST', 'path': '/api/feedback/update', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'token']},
                    {'method': 'POST', 'path': '/api/feedback/delete', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'token']},
                    {'method': 'POST', 'path': '/api/feedback/list', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    {'method': 'POST', 'path': '/api/feedback/search', 'vuln_type': 'SQL注入 (只读)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    
                    # 敏感信息模块接口
                    {'method': 'POST', 'path': '/api/secrets/create', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/secrets/update', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'JSON', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/secrets/delete', 'vuln_type': '安全接口 (参数化查询)', 'body_type': 'XML', 'session_fields': ['session_id', 'auth_token']},
                    {'method': 'POST', 'path': '/api/secrets/query', 'vuln_type': 'SQL注入 (只读 - 可获取Flag)', 'body_type': 'JSON', 'session_fields': ['session_id']},
                    {'method': 'POST', 'path': '/api/secrets/search', 'vuln_type': 'SQL注入 (只读 - 可搜索Flag)', 'body_type': 'JSON', 'session_fields': ['session_id']},
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
    
    def handle_feedback_update(self, data):
        """
        更新反馈 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "feedback_id": 1,
            "title": "Updated Title",
            "content": "Updated content",
            "rating": 4,
            "session_id": "abc123",
            "token": "xyz789"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        feedback_id = data.get('feedback_id', '')
        title = data.get('title', '')
        content = data.get('content', '')
        rating = data.get('rating', '')
        session_id = data.get('session_id', '')
        token = data.get('token', '')
        
        if not feedback_id:
            self.send_json_response({'success': False, 'message': 'feedback_id is required'}, 400)
            return
        
        # 验证feedback_id是否为有效数字
        try:
            feedback_id_int = int(feedback_id)
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid feedback ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[FeedbackUpdate] session_id=%s, token=%s", session_id, token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 构建动态更新SQL（仅更新提供的字段）
            update_fields = []
            params = []
            
            if title:
                update_fields.append('title = ?')
                params.append(title)
            if content:
                update_fields.append('content = ?')
                params.append(content)
            if rating:
                try:
                    rating_int = int(rating)
                    if 1 <= rating_int <= 5:
                        update_fields.append('rating = ?')
                        params.append(rating_int)
                except ValueError:
                    pass
            
            if not update_fields:
                self.send_json_response({'success': False, 'message': 'No fields to update'}, 400)
                conn.close()
                return
            
            params.append(feedback_id_int)
            sql = f"UPDATE feedback SET {', '.join(update_fields)} WHERE id = ?"
            
            # 使用参数化查询更新反馈
            cursor.execute(sql, tuple(params))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_json_response({
                    'success': True,
                    'message': 'Feedback updated successfully',
                    'data': {
                        'feedback_id': feedback_id,
                        'session_id': session_id
                    }
                })
            else:
                self.send_json_response({
                    'success': False,
                    'message': 'Feedback not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to update feedback: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_feedback_delete(self, data):
        """
        删除反馈 - XML格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/xml):
        <?xml version="1.0" encoding="UTF-8"?>
        <request>
            <feedback_id>1</feedback_id>
            <reason>Duplicate feedback</reason>
            <session_id>abc123</session_id>
            <token>xyz789</token>
        </request>
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        feedback_id = data.get('feedback_id', '')
        reason = data.get('reason', '')
        session_id = data.get('session_id', '')
        token = data.get('token', '')
        
        if not feedback_id:
            self.send_xml_response({'success': 'false', 'message': 'feedback_id is required'}, 400)
            return
        
        # 验证feedback_id是否为有效数字
        try:
            feedback_id_int = int(feedback_id)
        except ValueError:
            self.send_xml_response({'success': 'false', 'message': 'Invalid feedback ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[FeedbackDelete] session_id=%s, token=%s", session_id, token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询删除反馈
            cursor.execute('DELETE FROM feedback WHERE id = ?', (feedback_id_int,))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_xml_response({
                    'success': 'true',
                    'message': 'Feedback deleted successfully',
                    'data': {
                        'feedback_id': feedback_id,
                        'reason': reason,
                        'session_id': session_id
                    }
                })
            else:
                self.send_xml_response({
                    'success': 'false',
                    'message': 'Feedback not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_xml_response({'success': 'false', 'message': f'Failed to delete feedback: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_feedback_list(self, data):
        """
        反馈列表查询 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：排序字段和限制直接拼接到SQL语句
        测试payload: sort_by=id' UNION SELECT * FROM secrets--
        
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询
        """
        waf = get_waf()
        sort_by = waf.filter_input(data.get('sort_by', 'created_at'))
        order = waf.filter_input(data.get('order', 'DESC'))
        limit = data.get('limit', '10')
        session_id = data.get('session_id', '')
        
        # 验证limit为数字
        try:
            limit_int = int(limit)
            if limit_int > 100:
                limit_int = 100
        except ValueError:
            limit_int = 10
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        sql = f"""SELECT f.id, f.user_id, f.session_id, f.title, f.content, f.rating, f.created_at,
                         u.username as user_name
                  FROM feedback f
                  LEFT JOIN users u ON f.user_id = u.id
                  ORDER BY f.{sort_by} {order}
                  LIMIT {limit_int}"""
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[FeedbackList] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
            feedbacks = cursor.fetchall()
            
            result = []
            for f in feedbacks:
                result.append({
                    'id': f[0],
                    'user_id': f[1],
                    'session_id': f[2],
                    'title': f[3],
                    'content': f[4],
                    'rating': f[5],
                    'created_at': f[6],
                    'user_name': f[7]
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
    
    def handle_feedback_search(self, data):
        """
        反馈搜索 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：搜索关键词直接拼接到SQL语句
        测试payload: keyword=test' OR '1'='1
        
        注意：此接口保留SQL注入以供测试，但不支持堆叠查询
        """
        waf = get_waf()
        keyword = waf.filter_input(data.get('keyword', ''))
        search_in = waf.filter_input(data.get('search_in', 'title'))
        min_rating = waf.filter_input(data.get('min_rating', '1'))
        session_id = data.get('session_id', '')
        
        if not keyword:
            self.send_json_response({'success': False, 'message': 'keyword is required'}, 400)
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        sql = f"""SELECT f.id, f.user_id, f.session_id, f.title, f.content, f.rating, f.created_at,
                         u.username as user_name
                  FROM feedback f
                  LEFT JOIN users u ON f.user_id = u.id
                  WHERE f.{search_in} LIKE '%{keyword}%'
                  AND f.rating >= {min_rating}
                  ORDER BY f.created_at DESC"""
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[FeedbackSearch] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
            feedbacks = cursor.fetchall()
            
            result = []
            for f in feedbacks:
                result.append({
                    'id': f[0],
                    'user_id': f[1],
                    'session_id': f[2],
                    'title': f[3],
                    'content': f[4],
                    'rating': f[5],
                    'created_at': f[6],
                    'user_name': f[7]
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
    
    def handle_get_logs(self, params):
        """
        获取日志文件内容 - 仅限本地访问
        
        安全考虑：只允许localhost访问日志，防止信息泄露
        """
        if self.client_address[0] not in ['127.0.0.1', '::1']:
            self.send_error_response('Only localhost can view logs', 403)
            return
        
        log_type = params.get('type', 'vulnshop')
        lines = params.get('lines', '100')
        
        # 验证lines参数
        try:
            lines_int = int(lines)
            if lines_int > 1000:
                lines_int = 1000
            elif lines_int < 10:
                lines_int = 10
        except ValueError:
            lines_int = 100
        
        # 安全的日志文件映射
        log_files = {
            'vulnshop': 'vulnshop.log',
            'access': 'access.log',
            'error': 'error.log'
        }
        
        if log_type not in log_files:
            self.send_error_response('Invalid log type', 400)
            return
        
        log_file = LOG_DIR / log_files[log_type]
        
        try:
            if not log_file.exists():
                self.send_json_response({
                    'success': True,
                    'data': {
                        'type': log_type,
                        'lines': 0,
                        'content': 'Log file is empty or does not exist yet.'
                    }
                })
                return
            
            # 读取日志文件的最后N行
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
                last_lines = all_lines[-lines_int:] if len(all_lines) > lines_int else all_lines
            
            self.send_json_response({
                'success': True,
                'data': {
                    'type': log_type,
                    'lines': len(last_lines),
                    'total_lines': len(all_lines),
                    'content': ''.join(last_lines)
                }
            })
        except Exception as e:
            self.send_error_response(f'Failed to read log file: {str(e)}', 500)
