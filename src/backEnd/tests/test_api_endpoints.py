"""
API端点实际测试脚本 - 演示scope字段CRUD操作

这个脚本演示了如何通过HTTP API进行scope字段的CRUD操作。
注意：需要后端服务运行在 http://localhost:8000
"""

import requests
import json


BASE_URL = "http://localhost:8000"
API_PREFIX = "/commonApi/header"


def print_response(title, response):
    """打印响应信息"""
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")
    print(f"状态码: {response.status_code}")
    try:
        data = response.json()
        print(f"响应数据:\n{json.dumps(data, indent=2, ensure_ascii=False)}")
    except:
        print(f"响应内容: {response.text}")


def test_create_global_rule():
    """测试1: 创建全局规则（不带scope）"""
    url = f"{BASE_URL}{API_PREFIX}/persistent-header-rules"
    payload = {
        "name": "测试全局User-Agent",
        "header_name": "User-Agent",
        "header_value": "TestScanner/1.0",
        "replace_strategy": "REPLACE",
        "priority": 50,
        "is_active": True
        # 注意：不包含scope字段，默认全局生效
    }
    
    response = requests.post(url, json=payload)
    print_response("测试1: 创建全局规则（不带scope）", response)
    
    if response.status_code == 201:
        data = response.json()
        if data.get('success'):
            rule_id = data['data']['id']
            print(f"\n✓ 规则ID: {rule_id}")
            print(f"✓ Scope字段: {data['data'].get('scope')}")
            return rule_id
    return None


def test_create_scoped_rule():
    """测试2: 创建带scope的规则"""
    url = f"{BASE_URL}{API_PREFIX}/persistent-header-rules"
    payload = {
        "name": "测试API认证头",
        "header_name": "Authorization",
        "header_value": "Bearer test-token-123",
        "replace_strategy": "REPLACE",
        "priority": 80,
        "is_active": True,
        "scope": {
            "protocol_pattern": "https",
            "host_pattern": "api.example.com",
            "port_pattern": "443",
            "path_pattern": "/v1/*",
            "use_regex": False
        }
    }
    
    response = requests.post(url, json=payload)
    print_response("测试2: 创建带scope的规则", response)
    
    if response.status_code == 201:
        data = response.json()
        if data.get('success'):
            rule_id = data['data']['id']
            print(f"\n✓ 规则ID: {rule_id}")
            print(f"✓ Scope配置: {json.dumps(data['data'].get('scope'), indent=2, ensure_ascii=False)}")
            return rule_id
    return None


def test_get_rules_list():
    """测试3: 获取规则列表"""
    url = f"{BASE_URL}{API_PREFIX}/persistent-header-rules?active_only=false"
    
    response = requests.get(url)
    print_response("测试3: 获取规则列表", response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            rules = data['data']['rules']
            print(f"\n✓ 共有 {len(rules)} 个规则")
            for rule in rules:
                scope_info = "全局" if rule.get('scope') is None else "有作用域"
                print(f"  - [{rule['id']}] {rule['name']}: {scope_info}")


def test_get_rule_by_id(rule_id):
    """测试4: 根据ID获取规则"""
    url = f"{BASE_URL}{API_PREFIX}/persistent-header-rules/{rule_id}"
    
    response = requests.get(url)
    print_response(f"测试4: 根据ID获取规则 (ID={rule_id})", response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            rule_data = data['data']
            print(f"\n✓ 规则名称: {rule_data['name']}")
            print(f"✓ Scope字段存在: {'scope' in rule_data}")
            if rule_data.get('scope'):
                print(f"✓ Scope内容: {json.dumps(rule_data['scope'], indent=2, ensure_ascii=False)}")
            else:
                print(f"✓ Scope为None（全局生效）")


def test_update_rule_scope(rule_id):
    """测试5: 更新规则的scope"""
    url = f"{BASE_URL}{API_PREFIX}/persistent-header-rules/{rule_id}"
    payload = {
        "scope": {
            "protocol_pattern": "http,https",
            "host_pattern": "*.test.com",
            "use_regex": False
        }
    }
    
    response = requests.put(url, json=payload)
    print_response(f"测试5: 更新规则的scope (ID={rule_id})", response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            print(f"\n✓ 更新成功")
            # 重新获取验证
            test_get_rule_by_id(rule_id)


def test_preview_with_target_url():
    """测试6: 预览功能（带target_url）"""
    url = f"{BASE_URL}{API_PREFIX}/header-processing/preview"
    payload = {
        "headers": [
            "Content-Type: application/json",
            "Accept: application/json"
        ],
        "target_url": "https://api.example.com:443/v1/users"
    }
    
    response = requests.post(url, json=payload)
    print_response("测试6: 预览功能（带target_url）", response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            preview_data = data['data']
            print(f"\n✓ 原始请求头数量: {len(preview_data.get('original_headers', []))}")
            print(f"✓ 处理后请求头数量: {len(preview_data.get('processed_headers', []))}")
            print(f"✓ 应用的规则数量: {len(preview_data.get('applied_rules', []))}")


def test_preview_without_target_url():
    """测试7: 预览功能（不带target_url，应用所有规则）"""
    url = f"{BASE_URL}{API_PREFIX}/header-processing/preview"
    payload = {
        "headers": [
            "Content-Type: application/json"
        ]
        # 不包含target_url，应该应用所有活跃规则
    }
    
    response = requests.post(url, json=payload)
    print_response("测试7: 预览功能（不带target_url）", response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            preview_data = data['data']
            print(f"\n✓ 应用的规则数量: {len(preview_data.get('applied_rules', []))}")
            print("✓ 说明：不带target_url时，应用所有活跃规则")


def test_delete_rule(rule_id):
    """清理: 删除测试规则"""
    url = f"{BASE_URL}{API_PREFIX}/persistent-header-rules/{rule_id}"
    
    response = requests.delete(url)
    print_response(f"清理: 删除规则 (ID={rule_id})", response)


def main():
    """主测试流程"""
    print("=" * 70)
    print("API端点实际测试 - Scope字段CRUD功能演示")
    print("=" * 70)
    print("\n注意：需要后端服务运行在 http://localhost:8000")
    print("\n按Enter键开始测试...")
    input()
    
    created_rule_ids = []
    
    try:
        # 测试创建
        global_rule_id = test_create_global_rule()
        if global_rule_id:
            created_rule_ids.append(global_rule_id)
        
        scoped_rule_id = test_create_scoped_rule()
        if scoped_rule_id:
            created_rule_ids.append(scoped_rule_id)
        
        # 测试读取
        test_get_rules_list()
        
        if scoped_rule_id:
            test_get_rule_by_id(scoped_rule_id)
        
        # 测试更新
        if global_rule_id:
            test_update_rule_scope(global_rule_id)
        
        # 测试预览
        test_preview_with_target_url()
        test_preview_without_target_url()
        
        print("\n" + "=" * 70)
        print("✓ 所有API测试完成！")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ 测试出错: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # 清理测试数据
        if created_rule_ids:
            print("\n" + "=" * 70)
            print("清理测试数据")
            print("=" * 70)
            for rule_id in created_rule_ids:
                test_delete_rule(rule_id)


if __name__ == "__main__":
    main()
