#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入测试靶场 - 数据库管理模块

仅供安全测试和教育目的使用！
"""

import sqlite3
import os
import hashlib
from config import DB_PATH


def get_db_connection():
    """获取数据库连接（不使用参数化查询，故意存在漏洞）"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """初始化数据库，创建表和测试数据"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 创建用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            balance REAL DEFAULT 1000.00,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建商品表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 100,
            category TEXT,
            image TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建订单表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER DEFAULT 1,
            total_price REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            shipping_address TEXT,
            order_no TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')
    
    # 创建敏感信息表（用于演示数据泄露）
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flag TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建二次注入暂存表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 插入测试用户
    test_users = [
        ('admin', hash_password('admin123'), 'admin@vulnshop.local', '13800000001', 'Admin Office', 99999.99, 1),
        ('alice', hash_password('alice123'), 'alice@vulnshop.local', '13800000002', '123 Main St', 500.00, 0),
        ('bob', hash_password('bob456'), 'bob@vulnshop.local', '13800000003', '456 Oak Ave', 750.50, 0),
        ('charlie', hash_password('charlie789'), 'charlie@vulnshop.local', '13800000004', '789 Pine Rd', 1200.00, 0),
        ('test', hash_password('test'), 'test@vulnshop.local', '13800000005', 'Test Address', 100.00, 0),
    ]
    
    for user in test_users:
        try:
            cursor.execute('''
                INSERT INTO users (username, password, email, phone, address, balance, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', user)
        except sqlite3.IntegrityError:
            pass  # 用户已存在
    
    # 插入测试商品
    test_products = [
        ('iPhone 15 Pro', 'Apple最新旗舰手机，A17 Pro芯片', 8999.00, 50, 'electronics', 'iphone.jpg'),
        ('MacBook Pro 14', 'M3 Pro芯片，专业级笔记本电脑', 16999.00, 30, 'electronics', 'macbook.jpg'),
        ('AirPods Pro 2', '主动降噪无线耳机', 1899.00, 100, 'electronics', 'airpods.jpg'),
        ('Nike Air Max', '经典运动鞋款', 999.00, 200, 'fashion', 'nike.jpg'),
        ('Levi\'s 501 牛仔裤', '经典直筒牛仔裤', 599.00, 150, 'fashion', 'levis.jpg'),
        ('Python编程从入门到精通', '畅销编程书籍', 79.00, 500, 'books', 'python_book.jpg'),
        ('黑客与画家', '硅谷创业之父Paul Graham文集', 59.00, 300, 'books', 'hackers.jpg'),
        ('机械键盘 Cherry MX', '办公游戏两用机械键盘', 499.00, 80, 'electronics', 'keyboard.jpg'),
        ('4K显示器 27寸', '专业设计师显示器', 2999.00, 40, 'electronics', 'monitor.jpg'),
        ('咖啡机全自动', '意式浓缩咖啡机', 1599.00, 60, 'home', 'coffee.jpg'),
    ]
    
    for product in test_products:
        try:
            cursor.execute('''
                INSERT INTO products (name, description, price, stock, category, image)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', product)
        except sqlite3.IntegrityError:
            pass
    
    # 插入测试订单
    test_orders = [
        (2, 1, 1, 8999.00, 'completed', '123 Main St', 'ORD20231201001'),
        (2, 3, 2, 3798.00, 'shipped', '123 Main St', 'ORD20231202002'),
        (3, 2, 1, 16999.00, 'pending', '456 Oak Ave', 'ORD20231203003'),
        (4, 5, 1, 599.00, 'completed', '789 Pine Rd', 'ORD20231204004'),
        (3, 6, 3, 237.00, 'delivered', '456 Oak Ave', 'ORD20231205005'),
    ]
    
    for order in test_orders:
        try:
            cursor.execute('''
                INSERT INTO orders (user_id, product_id, quantity, total_price, status, shipping_address, order_no)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', order)
        except sqlite3.IntegrityError:
            pass
    
    # 插入敏感信息（Flag）
    secrets = [
        ('FLAG{sql_injection_master}', '恭喜你发现了隐藏的Flag！'),
        ('FLAG{error_based_injection_success}', '错误注入成功获取'),
        ('FLAG{union_based_extraction}', '联合查询提取成功'),
        ('FLAG{blind_injection_expert}', '盲注专家认证'),
        ('FLAG{admin_password_leaked}', '管理员密码已泄露'),
    ]
    
    for secret in secrets:
        try:
            cursor.execute('''
                INSERT INTO secrets (flag, description) VALUES (?, ?)
            ''', secret)
        except:
            pass
    
    conn.commit()
    conn.close()
    print("[*] Database initialized with test data")


def hash_password(password):
    """简单的密码哈希（故意使用弱哈希，便于演示）"""
    return hashlib.md5(password.encode()).hexdigest()


def reset_database():
    """重置数据库"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_database()
    print("[*] Database reset completed")


if __name__ == "__main__":
    init_database()
