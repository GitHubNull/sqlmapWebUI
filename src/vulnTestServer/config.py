#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入测试靶场 - 配置文件

仅供安全测试和教育目的使用！
"""

import os

# 服务器配置
HOST = "127.0.0.1"  # 仅允许本地访问
PORT = 9527
DEBUG = True

# 数据库配置
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "shop.db")

# 难度配置
# easy: 无任何防护，所有注入类型都可用
# medium: 简单过滤（过滤部分关键字如 UNION, SELECT 等，但可绕过）
# hard: WAF模拟（更严格的过滤，需要高级绕过技术）
DIFFICULTY = "easy"

# 各接口的SQL注入类型配置
# 可选类型: error, union, boolean, time, stacked, second_order
INJECTION_TYPES = {
    "/api/user/login": "error",           # 基于错误的注入
    "/api/user/profile": "union",         # 联合查询注入
    "/api/products/search": "boolean",    # 布尔盲注
    "/api/products/detail": "time",       # 时间盲注
    "/api/orders/query": "stacked",       # 堆叠查询
    "/api/user/register": "second_order", # 二次注入
}

# WAF过滤规则（仅在 medium/hard 难度下生效）
WAF_RULES = {
    "medium": {
        "keywords": ["union", "select", "insert", "update", "delete", "drop", "--", "#"],
        "bypass_allowed": True,  # 允许大小写、编码等绕过
    },
    "hard": {
        "keywords": ["union", "select", "insert", "update", "delete", "drop", 
                     "--", "#", "/*", "*/", "or", "and", "xor", "sleep", "benchmark",
                     "waitfor", "delay", "0x", "char(", "concat(", "group_concat("],
        "bypass_allowed": False,  # 不允许简单绕过
        "max_length": 100,  # 参数最大长度限制
    }
}

# 日志配置
LOG_REQUESTS = True
LOG_FILE = os.path.join(os.path.dirname(__file__), "data", "access.log")

# 版本信息
VERSION = "1.0.0"
APP_NAME = "VulnShop - SQL Injection Test Lab"
