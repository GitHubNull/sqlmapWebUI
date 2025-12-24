#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 基础处理器 - 公共方法和工具函数

提供所有处理器共享的响应发送、请求解析等公共功能
"""

import json
import os
import time
import xml.etree.ElementTree as ET
from urllib.parse import unquote

# 导入日志模块
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logger import logger, sql_logger, error_logger


class BaseHandlerMixin:
    """基础处理器Mixin - 提供公共方法"""
    
    # 静态文件MIME类型
    MIME_TYPES = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json; charset=utf-8',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.ico': 'image/x-icon',
        '.svg': 'image/svg+xml',
    }
    
    def send_json_response(self, data, status=200):
        """发送JSON响应"""
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            self.end_headers()
            response = json.dumps(data, ensure_ascii=False)
            self.wfile.write(response.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # 客户端断开连接，静默处理
            pass
        except Exception as e:
            error_logger.debug("Error sending JSON response: %s", str(e))
    
    def send_error_response(self, message, status=400, sql_error=None):
        """发送错误响应（可能包含SQL错误信息用于演示）"""
        from config import DEBUG, DIFFICULTY
        data = {
            'success': False,
            'message': message,
            'timestamp': int(time.time() * 1000)
        }
        if sql_error and DEBUG:
            data['debug'] = {
                'sql_error': str(sql_error),
                'difficulty': DIFFICULTY
            }
        self.send_json_response(data, status)
    
    def send_xml_response(self, data, status=200):
        """发送XML响应"""
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/xml; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Id, X-Token')
            self.end_headers()
            
            # 将dict转换为XML
            def dict_to_xml(d, root_name='response'):
                root = ET.Element(root_name)
                for key, value in d.items():
                    child = ET.SubElement(root, key)
                    if isinstance(value, dict):
                        for k, v in value.items():
                            sub = ET.SubElement(child, k)
                            sub.text = str(v) if v is not None else ''
                    elif isinstance(value, list):
                        for item in value:
                            item_el = ET.SubElement(child, 'item')
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    sub = ET.SubElement(item_el, k)
                                    sub.text = str(v) if v is not None else ''
                            else:
                                item_el.text = str(item)
                    else:
                        child.text = str(value) if value is not None else ''
                return ET.tostring(root, encoding='unicode')
            
            xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + dict_to_xml(data)
            self.wfile.write(xml_str.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # 客户端断开连接，静默处理
            pass
        except Exception as e:
            error_logger.debug("Error sending XML response: %s", str(e))
    
    def send_static_file(self, filepath):
        """发送静态文件"""
        static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static')
        full_path = os.path.normpath(os.path.join(static_dir, filepath))
        
        # 防止目录遍历
        if not full_path.startswith(static_dir):
            self.send_error(403, 'Forbidden')
            return
        
        if not os.path.exists(full_path):
            self.send_error(404, 'File Not Found')
            return
        
        ext = os.path.splitext(filepath)[1].lower()
        mime_type = self.MIME_TYPES.get(ext, 'application/octet-stream')
        
        try:
            with open(full_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # 客户端断开连接，静默处理
            pass
        except FileNotFoundError:
            self.send_error(404, 'File Not Found')
        except Exception as e:
            error_logger.debug("Error serving static file %s: %s", filepath, str(e))
            try:
                self.send_error(500, 'Internal Server Error')
            except:
                pass
    
    def get_post_data(self):
        """获取POST请求数据，支持JSON、URL-encoded和XML格式"""
        try:
            content_length_str = self.headers.get('Content-Length', '0')
            try:
                content_length = int(content_length_str)
            except (ValueError, TypeError):
                content_length = 0
            
            if content_length <= 0:
                return {}
            
            # 限制最大读取长度，防止内存攻击
            max_length = 10 * 1024 * 1024  # 10MB
            if content_length > max_length:
                content_length = max_length
            
            raw_data = self.rfile.read(content_length)
            try:
                post_data = raw_data.decode('utf-8')
            except UnicodeDecodeError:
                # 尝试其他编码
                try:
                    post_data = raw_data.decode('latin-1')
                except:
                    return {}
            
            content_type = self.headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                try:
                    return json.loads(post_data)
                except:
                    return {}
            elif 'application/xml' in content_type or 'text/xml' in content_type:
                # XML解析
                try:
                    root = ET.fromstring(post_data)
                    result = {}
                    for child in root:
                        result[child.tag] = child.text or ''
                    return result
                except:
                    return {}
            else:
                # application/x-www-form-urlencoded
                result = {}
                for pair in post_data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        try:
                            result[unquote(key)] = unquote(value)
                        except:
                            pass
                return result
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return {}
        except Exception as e:
            error_logger.debug("Error reading POST data: %s", str(e))
            return {}
    
    def get_content_type(self):
        """获取请求的Content-Type类型"""
        content_type = self.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            return 'json'
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            return 'xml'
        else:
            return 'form'
