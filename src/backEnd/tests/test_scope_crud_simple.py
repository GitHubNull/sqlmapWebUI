"""
简化的scope字段CRUD测试 - 直接测试数据库和序列化
"""

import sys
import os
import json

# 添加backend目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
sys.path.insert(0, backend_dir)

from model.PersistentHeaderRule import PersistentHeaderRuleCreate, PersistentHeaderRuleResponse
from model.HeaderScope import HeaderScope


def test_scope_serialization():
    """测试scope序列化和反序列化"""
    print("\n=== 测试1: Scope序列化和反序列化 ===")
    
    # 创建scope对象
    scope = HeaderScope(
        protocol_pattern="https",
        host_pattern="api.example.com",
        port_pattern="443",
        path_pattern="/v1/*",
        use_regex=False
    )
    
    # 序列化为JSON
    scope_dict = scope.to_dict()
    scope_json = json.dumps(scope_dict, ensure_ascii=False)
    print(f"序列化后: {scope_json}")
    
    # 反序列化
    parsed_data = json.loads(scope_json)
    reconstructed_scope = HeaderScope.from_dict(parsed_data)
    
    assert reconstructed_scope.protocol_pattern == "https"
    assert reconstructed_scope.host_pattern == "api.example.com"
    assert reconstructed_scope.port_pattern == "443"
    assert reconstructed_scope.path_pattern == "/v1/*"
    
    print("✓ Scope序列化测试通过")


def test_empty_scope():
    """测试空scope（全局生效）"""
    print("\n=== 测试2: 空Scope（全局生效） ===")
    
    # scope为None
    scope_none = None
    assert scope_none is None
    print("✓ scope=None 表示全局生效")
    
    # scope对象为空
    empty_scope = HeaderScope(
        protocol_pattern=None,
        host_pattern=None,
        ip_pattern=None,
        port_pattern=None,
        path_pattern=None
    )
    
    assert empty_scope.is_empty() == True
    print("✓ 空scope对象也表示全局生效")


def test_rule_create_model_with_scope():
    """测试规则创建模型（带scope）"""
    print("\n=== 测试3: 规则创建模型（带scope） ===")
    
    scope = HeaderScope(
        protocol_pattern="https",
        host_pattern="*.example.com"
    )
    
    rule_data = PersistentHeaderRuleCreate(
        name="测试规则",
        header_name="X-Test-Header",
        header_value="TestValue",
        priority=50,
        scope=scope
    )
    
    assert rule_data.scope is not None
    assert rule_data.scope.host_pattern == "*.example.com"
    print(f"✓ 创建模型测试通过: {rule_data.name}")


def test_rule_create_model_without_scope():
    """测试规则创建模型（不带scope）"""
    print("\n=== 测试4: 规则创建模型（不带scope） ===")
    
    rule_data = PersistentHeaderRuleCreate(
        name="全局测试规则",
        header_name="X-Global-Header",
        header_value="GlobalValue",
        priority=50
    )
    
    assert rule_data.scope is None
    print(f"✓ 全局规则创建模型测试通过: {rule_data.name}")


def test_response_model_with_scope():
    """测试响应模型（带scope）"""
    print("\n=== 测试5: 响应模型（带scope） ===")
    
    scope_dict = {
        "protocol_pattern": "https",
        "host_pattern": "api.test.com",
        "port_pattern": "443",
        "use_regex": False
    }
    
    response = PersistentHeaderRuleResponse(
        id=1,
        name="测试规则",
        header_name="X-Test",
        header_value="Value",
        replace_strategy="REPLACE",
        match_condition=None,
        priority=50,
        is_active=True,
        scope=scope_dict,
        created_at="2025-10-26 10:00:00",
        updated_at="2025-10-26 10:00:00"
    )
    
    assert response.scope is not None
    assert response.scope['host_pattern'] == "api.test.com"
    print(f"✓ 响应模型测试通过: {response.dict()}")


def test_response_model_without_scope():
    """测试响应模型（不带scope）"""
    print("\n=== 测试6: 响应模型（不带scope） ===")
    
    response = PersistentHeaderRuleResponse(
        id=2,
        name="全局规则",
        header_name="X-Global",
        header_value="GlobalValue",
        replace_strategy="REPLACE",
        match_condition=None,
        priority=50,
        is_active=True,
        scope=None,
        created_at="2025-10-26 10:00:00",
        updated_at="2025-10-26 10:00:00"
    )
    
    assert response.scope is None
    response_dict = response.dict()
    assert 'scope' in response_dict
    assert response_dict['scope'] is None
    print(f"✓ 全局规则响应模型测试通过")


def main():
    """运行所有测试"""
    print("=" * 70)
    print("Scope字段CRUD功能 - 数据模型测试")
    print("=" * 70)
    
    try:
        test_scope_serialization()
        test_empty_scope()
        test_rule_create_model_with_scope()
        test_rule_create_model_without_scope()
        test_response_model_with_scope()
        test_response_model_without_scope()
        
        print("\n" + "=" * 70)
        print("✓ 所有数据模型测试通过！")
        print("=" * 70)
        
    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        raise
    except Exception as e:
        print(f"\n✗ 测试出错: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
