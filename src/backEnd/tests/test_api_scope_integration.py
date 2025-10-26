"""
API集成测试 - 验证scope字段的CRUD功能

测试覆盖：
1. 创建持久化规则（带/不带scope）
2. 获取规则列表（验证scope字段返回）
3. 获取单个规则（验证scope字段返回）
4. 更新规则（更新scope字段）
5. 预览功能（验证target_url参数）
"""

import sys
import os

# 设置正确的路径
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
sys.path.insert(0, backend_dir)

# 添加third_lib/sqlmap到路径
sqlmap_path = os.path.join(backend_dir, 'third_lib', 'sqlmap')
if os.path.exists(sqlmap_path):
    sys.path.insert(0, sqlmap_path)

import asyncio
import json
import sqlite3

from model.PersistentHeaderRule import PersistentHeaderRuleCreate, PersistentHeaderRuleUpdate
from model.HeaderScope import HeaderScope


async def test_create_rule_without_scope():
    """测试创建不带scope的全局规则"""
    print("\n=== 测试1: 创建不带scope的全局规则 ===")
    service = HeaderRuleService()
    
    rule_data = PersistentHeaderRuleCreate(
        name="全局测试规则",
        header_name="X-Global-Header",
        header_value="GlobalValue",
        priority=50
    )
    
    result = await service.create_persistent_rule(rule_data)
    assert result.success, f"创建失败: {result.msg}"
    assert result.data is not None
    assert result.data.get('scope') is None, "全局规则的scope应该为None"
    print(f"✓ 创建成功: {result.data}")
    return result.data['id']


async def test_create_rule_with_scope():
    """测试创建带scope的规则"""
    print("\n=== 测试2: 创建带scope的规则 ===")
    service = HeaderRuleService()
    
    scope = HeaderScope(
        protocol_pattern="https",
        host_pattern="api.example.com",
        port_pattern="443",
        path_pattern="/v1/*",
        use_regex=False
    )
    
    rule_data = PersistentHeaderRuleCreate(
        name="API测试规则",
        header_name="X-API-Header",
        header_value="APIValue",
        priority=60,
        scope=scope
    )
    
    result = await service.create_persistent_rule(rule_data)
    assert result.success, f"创建失败: {result.msg}"
    assert result.data is not None
    assert result.data.get('scope') is not None, "带scope的规则应该返回scope"
    assert result.data['scope']['protocol_pattern'] == "https"
    assert result.data['scope']['host_pattern'] == "api.example.com"
    print(f"✓ 创建成功: {result.data}")
    return result.data['id']


async def test_get_rules_list():
    """测试获取规则列表（验证scope字段）"""
    print("\n=== 测试3: 获取规则列表 ===")
    service = HeaderRuleService()
    
    result = await service.get_persistent_rules(active_only=False)
    assert result.success, f"获取失败: {result.msg}"
    assert result.data is not None
    assert 'rules' in result.data
    
    rules = result.data['rules']
    print(f"✓ 获取到 {len(rules)} 个规则")
    
    # 验证每个规则是否正确包含scope字段
    for rule in rules:
        print(f"  - {rule['name']}: scope={rule.get('scope')}")
        # scope字段应该存在（可以是None或dict）
        assert 'scope' in rule, f"规则 {rule['name']} 缺少scope字段"


async def test_get_rule_by_id(rule_id):
    """测试根据ID获取规则（验证scope字段）"""
    print(f"\n=== 测试4: 根据ID获取规则 (ID={rule_id}) ===")
    service = HeaderRuleService()
    
    result = await service.get_persistent_rule_by_id(rule_id)
    assert result.success, f"获取失败: {result.msg}"
    assert result.data is not None
    assert 'scope' in result.data, "返回数据应该包含scope字段"
    print(f"✓ 获取成功: {result.data}")


async def test_update_rule_scope(rule_id):
    """测试更新规则的scope字段"""
    print(f"\n=== 测试5: 更新规则的scope字段 (ID={rule_id}) ===")
    service = HeaderRuleService()
    
    # 更新scope
    new_scope = HeaderScope(
        protocol_pattern="http,https",
        host_pattern="*.test.com",
        use_regex=False
    )
    
    update_data = PersistentHeaderRuleUpdate(
        scope=new_scope
    )
    
    result = await service.update_persistent_rule(rule_id, update_data)
    assert result.success, f"更新失败: {result.msg}"
    
    # 验证更新后的scope
    get_result = await service.get_persistent_rule_by_id(rule_id)
    assert get_result.success
    assert get_result.data['scope'] is not None
    assert get_result.data['scope']['host_pattern'] == "*.test.com"
    print(f"✓ 更新成功: {get_result.data}")


async def test_preview_with_target_url():
    """测试预览功能（传递target_url）"""
    print("\n=== 测试6: 预览功能（带target_url） ===")
    service = HeaderRuleService()
    
    headers = ["Content-Type: application/json"]
    client_ip = "127.0.0.1"
    target_url = "https://api.test.com/v1/users"
    
    result = await service.preview_header_processing(headers, client_ip, target_url)
    assert result.success, f"预览失败: {result.msg}"
    print(f"✓ 预览成功: {result.data}")


async def cleanup_test_rules():
    """清理测试数据"""
    print("\n=== 清理测试数据 ===")
    service = HeaderRuleService()
    
    # 获取所有规则
    result = await service.get_persistent_rules(active_only=False)
    if result.success and result.data:
        rules = result.data['rules']
        for rule in rules:
            if rule['name'].startswith(('全局测试规则', 'API测试规则')):
                await service.delete_persistent_rule(rule['id'])
                print(f"✓ 删除规则: {rule['name']}")


async def main():
    """主测试流程"""
    print("=" * 70)
    print("API集成测试 - scope字段CRUD功能验证")
    print("=" * 70)
    
    # 初始化数据库
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_headers.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    
    header_db = HeaderDatabase(db_path)
    header_db.init()
    DataStore.header_db = header_db
    
    try:
        # 清理旧的测试数据
        await cleanup_test_rules()
        
        # 运行测试
        global_rule_id = await test_create_rule_without_scope()
        scoped_rule_id = await test_create_rule_with_scope()
        await test_get_rules_list()
        await test_get_rule_by_id(scoped_rule_id)
        await test_update_rule_scope(global_rule_id)
        await test_preview_with_target_url()
        
        # 清理测试数据
        await cleanup_test_rules()
        
        print("\n" + "=" * 70)
        print("✓ 所有测试通过！")
        print("=" * 70)
        
    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        raise
    except Exception as e:
        print(f"\n✗ 测试出错: {e}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        # 清理测试数据库
        if os.path.exists(db_path):
            os.remove(db_path)


if __name__ == "__main__":
    asyncio.run(main())
