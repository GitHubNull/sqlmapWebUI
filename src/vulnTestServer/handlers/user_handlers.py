#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 用户处理器 - 用户相关API

包含：登录、注册、资料查询、信息更新
"""

import sqlite3
import uuid

from config import DEBUG
from database import get_db_connection, hash_password
from waf import get_waf


class UserHandlerMixin:
    """用户相关处理器Mixin"""
    
    def handle_user_login(self, data):
        """
        用户登录 - 基于错误的SQL注入 (JSON格式)
        
        请求体字段:
        - username: 用户名
        - password: 密码
        - session_id: 会话ID (用于测试Body会话字段替换)
        - device_id: 设备ID (用于测试Body会话字段替换)
        
        漏洞点：直接拼接用户输入到SQL语句
        测试payload: admin' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
        SQLite payload: admin' AND 1=1--
        """
        waf = get_waf()
        username = waf.filter_input(data.get('username', ''))
        password = data.get('password', '')
        session_id = data.get('session_id', '')  # 会话ID字段
        device_id = data.get('device_id', '')  # 设备ID字段
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在SQL注入漏洞）
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
        
        if DEBUG:
            print(f"[SQL] {sql}")
            print(f"[Session] session_id={session_id}, device_id={device_id}")
        
        try:
            cursor.execute(sql)
            user = cursor.fetchone()
            
            if user:
                # 生成新的会话token
                new_token = str(uuid.uuid4())
                new_session_id = session_id or str(uuid.uuid4())
                
                self.send_json_response({
                    'success': True,
                    'message': 'Login successful',
                    'data': {
                        'id': user['id'],
                        'username': user['username'],
                        'email': user['email'],
                        'is_admin': bool(user['is_admin']),
                        'session_id': new_session_id,
                        'token': new_token
                    }
                })
            else:
                self.send_error_response('Invalid username or password', 401)
        except sqlite3.Error as e:
            # 故意返回详细错误信息（基于错误的注入）
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_user_register(self, data):
        """
        用户注册 (JSON格式) - 安全接口，使用参数化查询
        
        请求体字段:
        - username: 用户名
        - password: 密码
        - email: 邮箱
        - session_id: 会话ID (用于测试Body会话字段替换)
        - captcha_token: 验证码token (用于测试Body会话字段替换)
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        username = data.get('username', '')
        password = data.get('password', '')
        email = data.get('email', '')
        session_id = data.get('session_id', '')  # 会话ID字段
        captcha_token = data.get('captcha_token', '')  # 验证码token字段
        
        if not username or not password:
            self.send_error_response('Username and password are required', 400)
            return
        
        if DEBUG:
            print(f"[Register] session_id={session_id}, captcha_token={captcha_token}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询，安全插入数据
            cursor.execute('''
                INSERT INTO pending_users (username, password, email, status)
                VALUES (?, ?, ?, 'pending')
            ''', (username, hash_password(password), email))
            
            pending_id = cursor.lastrowid
            conn.commit()
            
            self.send_json_response({
                'success': True,
                'message': 'Registration submitted, pending approval',
                'data': {
                    'pending_id': pending_id,
                    'session_id': session_id or str(uuid.uuid4())
                }
            })
            
        except sqlite3.Error as e:
            self.send_error_response(f'Registration failed: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_user_profile(self, params):
        """
        用户资料 - 联合查询SQL注入
        
        漏洞点：用户ID直接拼接
        测试payload: 1 UNION SELECT 1,username,password,email,phone,address,balance,is_admin,created_at FROM users--
        """
        waf = get_waf()
        user_id = waf.filter_input(params.get('id', '1'))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 故意使用字符串拼接（存在SQL注入漏洞）
        sql = f"SELECT id, username, email, phone, address, balance FROM users WHERE id = {user_id}"
        
        if DEBUG:
            print(f"[SQL] {sql}")
        
        try:
            cursor.execute(sql)
            users = cursor.fetchall()
            
            if users:
                result = []
                for user in users:
                    result.append({
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'phone': user[3],
                        'address': user[4],
                        'balance': user[5]
                    })
                self.send_json_response({
                    'success': True,
                    'data': result[0] if len(result) == 1 else result
                })
            else:
                self.send_error_response('User not found', 404)
        except sqlite3.Error as e:
            self.send_error_response(f'Database error: {str(e)}', 500, sql_error=e)
        finally:
            conn.close()
    
    def handle_user_update(self, data):
        """
        更新用户信息 - XML格式 - 安全接口，使用参数化查询
        
        请求体示例 (application/xml):
        <?xml version="1.0" encoding="UTF-8"?>
        <request>
            <user_id>1</user_id>
            <email>new@email.com</email>
            <phone>13800000001</phone>
            <address>New Address</address>
            <session_id>abc123</session_id>
            <token>xyz789</token>
            <device_id>device001</device_id>
        </request>
        
        注意：此接口使用参数化查询，不存在SQL注入漏洞
        （数据修改操作需保护，避免测试数据污染）
        """
        user_id = data.get('user_id', '')
        email = data.get('email', '')
        phone = data.get('phone', '')
        address = data.get('address', '')
        session_id = data.get('session_id', '')  # 会话ID
        token = data.get('token', '')  # token
        device_id = data.get('device_id', '')  # 设备ID
        
        if not user_id:
            self.send_xml_response({'success': 'false', 'message': 'User ID is required'}, 400)
            return
        
        # 验证user_id是否为有效数字
        try:
            user_id_int = int(user_id)
        except ValueError:
            self.send_xml_response({'success': 'false', 'message': 'Invalid user ID'}, 400)
            return
        
        if DEBUG:
            print(f"[UserUpdate] session_id={session_id}, token={token}, device_id={device_id}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 使用参数化查询，安全更新数据
            cursor.execute('''
                UPDATE users SET email = ?, phone = ?, address = ? WHERE id = ?
            ''', (email, phone, address, user_id_int))
            conn.commit()
            
            self.send_xml_response({
                'success': 'true',
                'message': 'User updated successfully',
                'data': {
                    'user_id': user_id,
                    'session_id': session_id
                }
            })
        except sqlite3.Error as e:
            self.send_xml_response({'success': 'false', 'message': f'Update failed: {str(e)}'}, 500)
        finally:
            conn.close()
