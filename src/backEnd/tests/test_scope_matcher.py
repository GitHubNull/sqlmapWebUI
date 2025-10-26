"""
ScopeMatcher单元测试

测试作用域匹配器的各种匹配场景
"""

import unittest
from model.HeaderScope import HeaderScope
from utils.scope_matcher import ScopeMatcher


class TestScopeMatcher(unittest.TestCase):
    """作用域匹配器测试类"""
    
    def setUp(self):
        """测试初始化"""
        # 清空缓存
        ScopeMatcher.clear_cache()
    
    def test_null_scope_matches_all(self):
        """测试空scope匹配所有URL"""
        result = ScopeMatcher.match_scope(None, "https://example.com/path")
        self.assertTrue(result, "空scope应该匹配所有URL")
    
    def test_empty_scope_matches_all(self):
        """测试空配置的scope匹配所有URL"""
        scope = HeaderScope()
        result = ScopeMatcher.match_scope(scope, "https://example.com/path")
        self.assertTrue(result, "空配置的scope应该匹配所有URL")
    
    def test_protocol_exact_match(self):
        """测试协议精确匹配"""
        scope = HeaderScope(protocol_pattern="https")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com"),
            "应该匹配https协议"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "http://example.com"),
            "不应该匹配http协议"
        )
    
    def test_protocol_multiple_match(self):
        """测试协议多值匹配"""
        scope = HeaderScope(protocol_pattern="http,https")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "http://example.com"),
            "应该匹配http协议"
        )
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com"),
            "应该匹配https协议"
        )
    
    def test_host_exact_match(self):
        """测试主机名精确匹配"""
        scope = HeaderScope(host_pattern="example.com")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com/path"),
            "应该匹配example.com"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://api.example.com/path"),
            "不应该匹配api.example.com"
        )
    
    def test_host_wildcard_match(self):
        """测试主机名通配符匹配"""
        scope = HeaderScope(host_pattern="*.example.com")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://api.example.com/path"),
            "应该匹配api.example.com"
        )
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://www.example.com/path"),
            "应该匹配www.example.com"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://example.com/path"),
            "不应该匹配example.com（*.不匹配空前缀）"
        )
    
    def test_port_exact_match(self):
        """测试端口精确匹配"""
        scope = HeaderScope(port_pattern="8080")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "http://example.com:8080/path"),
            "应该匹配端口8080"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "http://example.com:80/path"),
            "不应该匹配端口80"
        )
    
    def test_port_multiple_match(self):
        """测试端口多值匹配"""
        scope = HeaderScope(port_pattern="80,443,8080")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "http://example.com:80/path"),
            "应该匹配端口80"
        )
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com:443/path"),
            "应该匹配端口443"
        )
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "http://example.com:8080/path"),
            "应该匹配端口8080"
        )
    
    def test_path_exact_match(self):
        """测试路径精确匹配"""
        scope = HeaderScope(path_pattern="/api/users")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com/api/users"),
            "应该匹配路径/api/users"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://example.com/api/products"),
            "不应该匹配路径/api/products"
        )
    
    def test_path_wildcard_match(self):
        """测试路径通配符匹配"""
        scope = HeaderScope(path_pattern="/api/*")
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com/api/users"),
            "应该匹配路径/api/users"
        )
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com/api/products"),
            "应该匹配路径/api/products"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://example.com/admin/panel"),
            "不应该匹配路径/admin/panel"
        )
    
    def test_combined_scope_match(self):
        """测试组合条件匹配（AND逻辑）"""
        scope = HeaderScope(
            protocol_pattern="https",
            host_pattern="api.example.com",
            port_pattern="443",
            path_pattern="/v1/*"
        )
        
        # 全部匹配
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://api.example.com:443/v1/users"),
            "所有维度都匹配应该返回True"
        )
        
        # 协议不匹配
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "http://api.example.com:443/v1/users"),
            "协议不匹配应该返回False"
        )
        
        # 主机名不匹配
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://www.example.com:443/v1/users"),
            "主机名不匹配应该返回False"
        )
        
        # 端口不匹配
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://api.example.com:8443/v1/users"),
            "端口不匹配应该返回False"
        )
        
        # 路径不匹配
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://api.example.com:443/v2/users"),
            "路径不匹配应该返回False"
        )
    
    def test_regex_protocol_match(self):
        """测试正则表达式协议匹配"""
        scope = HeaderScope(protocol_pattern="^https$", use_regex=True)
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com"),
            "应该匹配https协议"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "http://example.com"),
            "不应该匹配http协议"
        )
    
    def test_regex_host_match(self):
        """测试正则表达式主机名匹配"""
        scope = HeaderScope(host_pattern=r"^api\..*\.com$", use_regex=True)
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://api.example.com/path"),
            "应该匹配api.example.com"
        )
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://api.test.com/path"),
            "应该匹配api.test.com"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://api.test.org/path"),
            "不应该匹配api.test.org"
        )
    
    def test_regex_path_match(self):
        """测试正则表达式路径匹配"""
        scope = HeaderScope(path_pattern=r"^/api/v[0-9]+/.*", use_regex=True)
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com/api/v1/users"),
            "应该匹配/api/v1/users"
        )
        
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com/api/v2/products"),
            "应该匹配/api/v2/products"
        )
        
        self.assertFalse(
            ScopeMatcher.match_scope(scope, "https://example.com/api/users"),
            "不应该匹配/api/users"
        )
    
    def test_default_port_handling(self):
        """测试默认端口处理"""
        scope = HeaderScope(port_pattern="80")
        
        # HTTP默认端口80
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "http://example.com/path"),
            "应该匹配HTTP默认端口80"
        )
        
        scope_https = HeaderScope(port_pattern="443")
        
        # HTTPS默认端口443
        self.assertTrue(
            ScopeMatcher.match_scope(scope_https, "https://example.com/path"),
            "应该匹配HTTPS默认端口443"
        )
    
    def test_url_parsing_edge_cases(self):
        """测试URL解析边界情况"""
        scope = HeaderScope(path_pattern="/")
        
        # 无路径的URL
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com"),
            "应该匹配根路径"
        )
        
        # 带查询参数的URL
        self.assertTrue(
            ScopeMatcher.match_scope(scope, "https://example.com/?query=test"),
            "应该匹配带查询参数的根路径"
        )


if __name__ == '__main__':
    unittest.main()
