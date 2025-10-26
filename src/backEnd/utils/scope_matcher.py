"""
ScopeMatcher作用域匹配器

负责执行作用域匹配逻辑，判断请求头规则是否应用于特定的目标URL。
支持关键字匹配和正则表达式匹配两种模式。
"""

from typing import Optional, Dict
from urllib.parse import urlparse
import re
import socket
import logging

from model.HeaderScope import HeaderScope

logger = logging.getLogger(__name__)


class ScopeMatcher:
    """
    作用域匹配器
    
    负责判断HeaderScope是否匹配目标URL。
    支持协议、主机名、IP、端口、路径五个维度的匹配。
    """
    
    # 正则表达式编译缓存
    _regex_cache: Dict[str, re.Pattern] = {}
    _cache_max_size = 100  # 限制缓存大小
    
    # URL解析缓存
    _url_cache: Dict[str, Dict] = {}
    _url_cache_max_size = 50
    
    @classmethod
    def match_scope(cls, scope: Optional[HeaderScope], target_url: str) -> bool:
        """
        判断作用域是否匹配目标URL
        
        参数:
            scope: HeaderScope对象，可以为None
            target_url: 目标URL字符串
        
        返回:
            True表示匹配成功，False表示不匹配
        
        匹配逻辑:
            - scope为None时，表示全局生效，返回True
            - scope.is_empty()为True时，表示全局生效，返回True
            - 所有配置的维度必须同时匹配（AND逻辑）
        """
        # scope为None或为空，表示全局生效
        if scope is None:
            logger.debug(f"作用域为None，全局生效，目标URL: {target_url}")
            return True
        
        if scope.is_empty():
            logger.debug(f"作用域为空配置，全局生效，目标URL: {target_url}")
            return True
        
        # 解析目标URL
        try:
            url_parts = cls.parse_target_url(target_url)
        except Exception as e:
            logger.warning(f"URL解析失败: {target_url}, 错误: {e}，视为匹配失败")
            return False
        
        # 检查各个维度的匹配
        # 协议匹配
        if scope.protocol_pattern:
            if not cls._match_dimension(
                url_parts['protocol'],
                scope.protocol_pattern,
                scope.use_regex,
                "协议"
            ):
                logger.debug(
                    f"协议不匹配: URL协议={url_parts['protocol']}, "
                    f"模式={scope.protocol_pattern}, URL={target_url}"
                )
                return False
        
        # 主机名匹配
        if scope.host_pattern:
            if not cls._match_dimension(
                url_parts['host'],
                scope.host_pattern,
                scope.use_regex,
                "主机名"
            ):
                logger.debug(
                    f"主机名不匹配: URL主机={url_parts['host']}, "
                    f"模式={scope.host_pattern}, URL={target_url}"
                )
                return False
        
        # IP地址匹配
        if scope.ip_pattern:
            if not cls._match_dimension(
                url_parts['ip'],
                scope.ip_pattern,
                scope.use_regex,
                "IP"
            ):
                logger.debug(
                    f"IP不匹配: URL_IP={url_parts['ip']}, "
                    f"模式={scope.ip_pattern}, URL={target_url}"
                )
                return False
        
        # 端口匹配
        if scope.port_pattern:
            if not cls._match_dimension(
                str(url_parts['port']),
                scope.port_pattern,
                scope.use_regex,
                "端口"
            ):
                logger.debug(
                    f"端口不匹配: URL端口={url_parts['port']}, "
                    f"模式={scope.port_pattern}, URL={target_url}"
                )
                return False
        
        # 路径匹配
        if scope.path_pattern:
            if not cls._match_dimension(
                url_parts['path'],
                scope.path_pattern,
                scope.use_regex,
                "路径"
            ):
                logger.debug(
                    f"路径不匹配: URL路径={url_parts['path']}, "
                    f"模式={scope.path_pattern}, URL={target_url}"
                )
                return False
        
        # 所有配置的维度都匹配
        logger.debug(f"作用域匹配成功，目标URL: {target_url}")
        return True
    
    @classmethod
    def parse_target_url(cls, url: str) -> Dict:
        """
        解析目标URL为各个组成部分
        
        参数:
            url: URL字符串
        
        返回:
            字典，包含protocol、host、ip、port、path
        """
        # 检查缓存
        if url in cls._url_cache:
            return cls._url_cache[url]
        
        parsed = urlparse(url)
        
        # 提取基本信息
        protocol = parsed.scheme or 'http'
        host = parsed.hostname or parsed.netloc.split(':')[0] if parsed.netloc else ''
        path = parsed.path or '/'
        
        # 确定端口
        if parsed.port:
            port = parsed.port
        else:
            # 默认端口
            port = 443 if protocol == 'https' else 80
        
        # 尝试解析IP地址
        ip = cls._resolve_ip(host)
        
        result = {
            'protocol': protocol,
            'host': host,
            'ip': ip,
            'port': port,
            'path': path
        }
        
        # 缓存结果
        if len(cls._url_cache) >= cls._url_cache_max_size:
            # 清空一半缓存
            keys_to_remove = list(cls._url_cache.keys())[:cls._url_cache_max_size // 2]
            for key in keys_to_remove:
                del cls._url_cache[key]
        
        cls._url_cache[url] = result
        return result
    
    @classmethod
    def _resolve_ip(cls, host: str) -> str:
        """
        解析主机名为IP地址
        
        参数:
            host: 主机名
        
        返回:
            IP地址字符串，解析失败返回空字符串
        """
        # 如果host已经是IP地址格式
        if cls._is_ip_address(host):
            return host
        
        # 尝试DNS解析
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.error:
            logger.debug(f"无法解析主机名到IP: {host}")
            return ""
    
    @classmethod
    def _is_ip_address(cls, value: str) -> bool:
        """判断字符串是否为IP地址格式"""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    @classmethod
    def _match_dimension(
        cls,
        value: str,
        pattern: str,
        use_regex: bool,
        dimension_name: str
    ) -> bool:
        """
        执行单个维度的匹配
        
        参数:
            value: 实际值
            pattern: 匹配模式
            use_regex: 是否使用正则表达式
            dimension_name: 维度名称（用于日志）
        
        返回:
            True表示匹配，False表示不匹配
        """
        if not value:
            value = ""
        
        if use_regex:
            return cls._match_regex(value, pattern, dimension_name)
        else:
            return cls._match_keyword(value, pattern)
    
    @classmethod
    def _match_regex(cls, value: str, pattern: str, dimension_name: str) -> bool:
        """
        正则表达式匹配
        
        参数:
            value: 实际值
            pattern: 正则表达式模式
            dimension_name: 维度名称
        
        返回:
            True表示匹配
        """
        try:
            # 从缓存获取或编译正则表达式
            if pattern not in cls._regex_cache:
                # 限制缓存大小
                if len(cls._regex_cache) >= cls._cache_max_size:
                    # 清空一半缓存
                    keys_to_remove = list(cls._regex_cache.keys())[:cls._cache_max_size // 2]
                    for key in keys_to_remove:
                        del cls._regex_cache[key]
                
                # 编译正则，设置超时保护（Python 3.11+）
                cls._regex_cache[pattern] = re.compile(pattern)
            
            regex = cls._regex_cache[pattern]
            
            # 执行匹配
            match = regex.search(value) is not None
            return match
            
        except re.error as e:
            logger.error(f"正则表达式错误 [{dimension_name}]: 模式={pattern}, 错误={e}")
            return False
        except Exception as e:
            logger.error(f"正则匹配异常 [{dimension_name}]: {e}")
            return False
    
    @classmethod
    def _match_keyword(cls, value: str, pattern: str) -> bool:
        """
        关键字匹配（支持通配符和逗号分隔）
        
        参数:
            value: 实际值
            pattern: 匹配模式
        
        返回:
            True表示匹配
        
        支持格式:
            - 精确匹配: "example.com"
            - 通配符: "*.example.com", "192.168.*"
            - 逗号分隔: "http,https", "80,443,8080"
        """
        # 支持逗号分隔的多个模式（OR逻辑）
        patterns = [p.strip() for p in pattern.split(',')]
        
        for p in patterns:
            if not p:
                continue
            
            # 将通配符模式转换为正则表达式
            if '*' in p:
                # 转义特殊字符，但保留*
                escaped = re.escape(p)
                # 将\*转换为.*
                regex_pattern = escaped.replace(r'\*', '.*')
                # 完整匹配
                regex_pattern = f'^{regex_pattern}$'
                
                try:
                    if re.match(regex_pattern, value):
                        return True
                except re.error:
                    logger.warning(f"通配符模式转换失败: {p}")
                    continue
            else:
                # 精确匹配（不区分大小写）
                if value.lower() == p.lower():
                    return True
        
        return False
    
    @classmethod
    def clear_cache(cls):
        """清空所有缓存"""
        cls._regex_cache.clear()
        cls._url_cache.clear()
        logger.debug("作用域匹配器缓存已清空")
