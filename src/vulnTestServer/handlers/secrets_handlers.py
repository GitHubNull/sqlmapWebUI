#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 敏感信息处理器 - 敏感信息相关API

包含：敏感信息创建、查询、更新、删除

注意：
- 敏感信息查询保留SQL注入漏洞（只读操作，用于获取Flag）
- 敏感信息创建/更新/删除使用参数化查询保护（数据修改操作）
"""

import sqlite3

from config import DEBUG
from database import get_db_connection
from waf import get_waf
from logger import sql_logger, logger


class SecretsHandlerMixin:
    """敏感信息相关处理器Mixin"""
    
    def handle_secrets_create(self, data):
        """
        创建敏感信息 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "flag": "FLAG{new_secret_flag}",
            "description": "Secret description",
            "session_id": "abc123",
            "auth_token": "xyz789"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        flag = data.get('flag', '')
        description = data.get('description', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
        if not flag:
            self.send_json_response({
                'success': False,
                'message': 'flag is required'
            }, 400)
            return
        
        if DEBUG:
            logger.debug("[SecretsCreate] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询插入敏感信息
            cursor.execute('''
                INSERT INTO secrets (flag, description)
                VALUES (?, ?)
            ''', (flag, description))
            conn.commit()
            secret_id = cursor.lastrowid
            
            self.send_json_response({
                'success': True,
                'message': 'Secret created successfully',
                'data': {
                    'secret_id': secret_id,
                    'flag': flag,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to create secret: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_secrets_update(self, data):
        """
        更新敏感信息 - JSON格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/json):
        {
            "secret_id": 1,
            "flag": "FLAG{updated_flag}",
            "description": "Updated description",
            "session_id": "abc123",
            "auth_token": "xyz789"
        }
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        secret_id = data.get('secret_id', '')
        flag = data.get('flag', '')
        description = data.get('description', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
        if not secret_id:
            self.send_json_response({'success': False, 'message': 'secret_id is required'}, 400)
            return
        
        # 验证secret_id是否为有效数字
        try:
            secret_id_int = int(secret_id)
        except ValueError:
            self.send_json_response({'success': False, 'message': 'Invalid secret ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[SecretsUpdate] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 构建动态更新SQL（仅更新提供的字段）
            update_fields = []
            params = []
            
            if flag:
                update_fields.append('flag = ?')
                params.append(flag)
            if description:
                update_fields.append('description = ?')
                params.append(description)
            
            if not update_fields:
                self.send_json_response({'success': False, 'message': 'No fields to update'}, 400)
                conn.close()
                return
            
            params.append(secret_id_int)
            sql = f"UPDATE secrets SET {', '.join(update_fields)} WHERE id = ?"
            
            # 使用参数化查询更新敏感信息
            cursor.execute(sql, tuple(params))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_json_response({
                    'success': True,
                    'message': 'Secret updated successfully',
                    'data': {
                        'secret_id': secret_id,
                        'session_id': session_id
                    }
                })
            else:
                self.send_json_response({
                    'success': False,
                    'message': 'Secret not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_json_response({'success': False, 'message': f'Failed to update secret: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_secrets_delete(self, data):
        """
        删除敏感信息 - XML格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/xml):
        <?xml version="1.0" encoding="UTF-8"?>
        <request>
            <secret_id>1</secret_id>
            <reason>Expired flag</reason>
            <session_id>abc123</session_id>
            <auth_token>xyz789</auth_token>
        </request>
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        secret_id = data.get('secret_id', '')
        reason = data.get('reason', '')
        session_id = data.get('session_id', '')
        auth_token = data.get('auth_token', '')
        
        if not secret_id:
            self.send_xml_response({'success': 'false', 'message': 'secret_id is required'}, 400)
            return
        
        # 验证secret_id是否为有效数字
        try:
            secret_id_int = int(secret_id)
        except ValueError:
            self.send_xml_response({'success': 'false', 'message': 'Invalid secret ID'}, 400)
            return
        
        if DEBUG:
            logger.debug("[SecretsDelete] session_id=%s, auth_token=%s", session_id, auth_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询删除敏感信息
            cursor.execute('DELETE FROM secrets WHERE id = ?', (secret_id_int,))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.send_xml_response({
                    'success': 'true',
                    'message': 'Secret deleted successfully',
                    'data': {
                        'secret_id': secret_id,
                        'reason': reason,
                        'session_id': session_id
                    }
                })
            else:
                self.send_xml_response({
                    'success': 'false',
                    'message': 'Secret not found'
                }, 404)
        except sqlite3.Error as e:
            self.send_xml_response({'success': 'false', 'message': f'Failed to delete secret: {str(e)}'}, 500)
        finally:
            conn.close()
    
    def handle_secrets_query(self, data):
        """
        敏感信息查询 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：ID直接拼接到SQL语句
        测试payload: id=1' UNION SELECT * FROM users--
        
        注意：此接口保留SQL注入以供测试，可获取Flag
        但不支持堆叠查询（避免数据修改）
        """
        waf = get_waf()
        secret_id = waf.filter_input(data.get('id', ''))
        session_id = data.get('session_id', '')
        
        if not secret_id:
            self.send_json_response({'success': False, 'message': 'id is required'}, 400)
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        sql = f"SELECT id, flag, description, created_at FROM secrets WHERE id = {secret_id}"
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[SecretsQuery] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
            secrets = cursor.fetchall()
            
            result = []
            for s in secrets:
                result.append({
                    'id': s[0],
                    'flag': s[1],
                    'description': s[2],
                    'created_at': s[3]
                })
            
            self.send_json_response({
                'success': True,
                'data': result[0] if len(result) == 1 else result,
                'count': len(result),
                'session_id': session_id
            })
        except sqlite3.Error as e:
            self.send_error_response(f'Query error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_secrets_search(self, data):
        """
        敏感信息搜索 - JSON格式 - 保留SQL注入漏洞（只读查询）
        
        漏洞点：搜索关键词直接拼接到SQL语句
        测试payload: keyword=FLAG{sql' OR '1'='1
        
        注意：此接口保留SQL注入以供测试，可搜索Flag
        但不支持堆叠查询（避免数据修改）
        """
        waf = get_waf()
        keyword = waf.filter_input(data.get('keyword', ''))
        search_in = waf.filter_input(data.get('search_in', 'flag'))
        limit = data.get('limit', '10')
        session_id = data.get('session_id', '')
        
        if not keyword:
            self.send_json_response({'success': False, 'message': 'keyword is required'}, 400)
            return
        
        # 验证limit为数字
        try:
            limit_int = int(limit)
            if limit_int > 50:
                limit_int = 50
        except ValueError:
            limit_int = 10
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 构建存在漏洞的SQL（字符串拼接）
        sql = f"SELECT id, flag, description, created_at FROM secrets WHERE {search_in} LIKE '%{keyword}%' LIMIT {limit_int}"
        
        if DEBUG:
            sql_logger.debug("[SQL] %s", sql)
            logger.debug("[SecretsSearch] session_id=%s", session_id)
        
        try:
            cursor.execute(sql)
            secrets = cursor.fetchall()
            
            result = []
            for s in secrets:
                result.append({
                    'id': s[0],
                    'flag': s[1],
                    'description': s[2],
                    'created_at': s[3]
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
