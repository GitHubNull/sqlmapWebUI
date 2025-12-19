#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入测试靶场 - WAF模拟模块

仅供安全测试和教育目的使用！
"""

import re
import urllib.parse
from config import DIFFICULTY, WAF_RULES


class WAFFilter:
    """模拟WAF过滤器"""
    
    def __init__(self, difficulty=None):
        self.difficulty = difficulty or DIFFICULTY
        self.rules = WAF_RULES.get(self.difficulty, {})
    
    def check(self, value):
        """
        检查输入是否包含恶意内容
        
        Returns:
            tuple: (is_blocked, reason)
        """
        if self.difficulty == "easy":
            return False, None
        
        if not value:
            return False, None
        
        # 检查长度限制（hard模式）
        if self.difficulty == "hard":
            max_length = self.rules.get("max_length", 100)
            if len(value) > max_length:
                return True, f"Input too long (max {max_length} chars)"
        
        keywords = self.rules.get("keywords", [])
        bypass_allowed = self.rules.get("bypass_allowed", True)
        
        # 标准化输入进行检查
        check_value = value.lower() if not bypass_allowed else value
        
        # URL解码（多次解码防止双重编码绕过）
        decoded_value = value
        for _ in range(3):
            try:
                new_decoded = urllib.parse.unquote(decoded_value)
                if new_decoded == decoded_value:
                    break
                decoded_value = new_decoded
            except:
                break
        
        if not bypass_allowed:
            decoded_value = decoded_value.lower()
        
        # 检查关键字
        for keyword in keywords:
            check_keyword = keyword if bypass_allowed else keyword.lower()
            
            if bypass_allowed:
                # Medium模式：只检查原始输入中的小写匹配
                if keyword.lower() in value.lower():
                    # 但允许大小写变形绕过
                    if keyword in value:
                        return True, f"Blocked keyword detected: {keyword}"
            else:
                # Hard模式：检查所有变形
                if check_keyword in check_value or check_keyword in decoded_value.lower():
                    return True, f"Blocked keyword detected: {keyword}"
        
        # Hard模式额外检查
        if self.difficulty == "hard":
            # 检查十六进制编码
            if re.search(r'0x[0-9a-fA-F]+', value):
                return True, "Hex encoding detected"
            
            # 检查注释符号
            if re.search(r'/\*.*?\*/', value, re.DOTALL):
                return True, "SQL comment detected"
            
            # 检查特殊字符组合
            if re.search(r'[\'"]\s*[oO][rR]\s*[\'"1]', value):
                return True, "SQL OR pattern detected"
        
        return False, None
    
    def filter_input(self, value):
        """
        过滤输入（返回过滤后的值或抛出异常）
        """
        is_blocked, reason = self.check(value)
        if is_blocked:
            raise WAFBlockedException(reason)
        return value


class WAFBlockedException(Exception):
    """WAF拦截异常"""
    def __init__(self, reason):
        self.reason = reason
        super().__init__(f"WAF Blocked: {reason}")


def get_waf():
    """获取当前难度的WAF实例"""
    return WAFFilter()


def set_difficulty(difficulty):
    """动态设置难度"""
    global DIFFICULTY
    if difficulty in ["easy", "medium", "hard"]:
        import config
        config.DIFFICULTY = difficulty
        return True
    return False
