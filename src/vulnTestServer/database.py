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
    
    # 创建购物车表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER DEFAULT 1,
            session_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')
    
    # 创建用户反馈表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_id TEXT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            rating INTEGER DEFAULT 5,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建用户会话表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT NOT NULL UNIQUE,
            token TEXT NOT NULL,
            device_info TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # 创建物流日志表（用于 XML SQL 注入演示）
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shipping_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_number TEXT NOT NULL,
            carrier_code TEXT,
            status TEXT DEFAULT 'in_transit',
            location TEXT,
            update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            estimated_delivery TIMESTAMP,
            weight REAL,
            notes TEXT
        )
    ''')

    # 创建优惠券表（用于 Base64 加密参数 SQL 注入演示）
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            coupon_code TEXT NOT NULL UNIQUE,
            discount_type TEXT DEFAULT 'percent',
            discount_value REAL NOT NULL,
            min_purchase REAL DEFAULT 0,
            max_discount REAL,
            category TEXT,
            status TEXT DEFAULT 'active',
            valid_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            valid_until TIMESTAMP,
            usage_limit INTEGER DEFAULT 100,
            used_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 创建用户评价表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            order_id INTEGER,
            rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
            title TEXT,
            content TEXT,
            is_anonymous INTEGER DEFAULT 0,
            helpful_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (order_id) REFERENCES orders(id)
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

    # 插入物流测试数据（用于 XML SQL 注入演示）
    test_shipping = [
        ('TRK202403150001', 'SF', 'in_transit', '深圳转运中心', 1.5, '预计3天内送达'),
        ('TRK202403150002', 'YT', 'delivered', '北京朝阳区派送站', 0.8, '已签收'),
        ('TRK202403150003', 'ZT', 'pending', '等待揽收', 2.0, '等待快递员上门'),
        ('TRK202403150004', 'JD', 'in_transit', '上海分拨中心', 1.2, '运输中'),
        ('TRK202403150005', 'EMS', 'customs', '海关清关中', 3.5, '国际包裹清关'),
    ]

    for shipping in test_shipping:
        try:
            cursor.execute('''
                INSERT INTO shipping_logs (tracking_number, carrier_code, status, location, weight, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', shipping)
        except:
            pass

    # 插入优惠券测试数据（用于 Base64 加密参数 SQL 注入演示）
    test_coupons = [
        ('SAVE10', 'percent', 10.0, 100.0, 50.0, 'electronics', 'active'),
        ('NEWUSER20', 'percent', 20.0, 0, 100.0, None, 'active'),
        ('FLASH50', 'fixed', 50.0, 200.0, 50.0, 'fashion', 'active'),
        ('VIP30', 'percent', 30.0, 500.0, 200.0, None, 'active'),
        ('BOOKS15', 'percent', 15.0, 50.0, 30.0, 'books', 'active'),
        ('EXPIRED99', 'percent', 99.0, 0, 999.0, None, 'expired'),
    ]

    for coupon in test_coupons:
        try:
            cursor.execute('''
                INSERT INTO coupons (coupon_code, discount_type, discount_value, min_purchase, max_discount, category, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', coupon)
        except:
            pass

    # 插入评价测试数据
    test_reviews = [
        (2, 1, 1, 5, '非常满意', 'iPhone 15 Pro 手感超级好，性能强劲！', 0, 15),
        (3, 2, 3, 4, '工作利器', 'MacBook Pro 屏幕素质极佳，适合设计工作', 0, 8),
        (4, 5, 4, 5, '经典之作', 'Levi\'s 质量一如既往的好', 0, 23),
        (2, 3, 2, 5, '降噪效果好', 'AirPods Pro 降噪效果超出预期', 0, 45),
        (3, 6, 5, 4, '入门必读', 'Python书籍内容详实，适合初学者', 0, 12),
    ]

    for review in test_reviews:
        try:
            cursor.execute('''
                INSERT INTO reviews (user_id, product_id, order_id, rating, title, content, is_anonymous, helpful_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', review)
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
