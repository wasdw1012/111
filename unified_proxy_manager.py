#!/usr/bin/env python3
"""
Unified Proxy Manager - 统一代理管理器

解决各模块代理调用不一致的问题，提供统一的代理接口
"""

import asyncio
import socket
import ssl
import httpx
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse
import logging

# 尝试导入各种代理库
try:
    from python_socks.async_.asyncio import Proxy
    from python_socks import ProxyType
    PYTHON_SOCKS_AVAILABLE = True
except ImportError:
    PYTHON_SOCKS_AVAILABLE = False

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector
    AIOHTTP_SOCKS_AVAILABLE = True
except ImportError:
    AIOHTTP_SOCKS_AVAILABLE = False

logger = logging.getLogger(__name__)


class UnifiedProxyManager:
    """统一的代理管理器，为所有模块提供一致的代理接口"""
    
    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url
        self.enabled = bool(proxy_url)
        self._parse_proxy_url()
        
    def _parse_proxy_url(self):
        """解析代理URL"""
        if not self.proxy_url:
            self.proxy_type = None
            self.proxy_host = None
            self.proxy_port = None
            self.proxy_username = None
            self.proxy_password = None
            return
            
        parsed = urlparse(self.proxy_url)
        self.proxy_type = parsed.scheme.lower()
        self.proxy_host = parsed.hostname
        self.proxy_port = parsed.port
        self.proxy_username = parsed.username
        self.proxy_password = parsed.password
        
    async def create_tcp_connection(self, host: str, port: int, ssl_context: Optional[ssl.SSLContext] = None) -> Tuple[Any, Any]:
        """创建TCP连接（支持代理）"""
        if not self.enabled:
            # 直接连接
            return await asyncio.open_connection(host, port, ssl=ssl_context)
            
        if PYTHON_SOCKS_AVAILABLE:
            # 使用 python-socks
            proxy = Proxy.from_url(self.proxy_url)
            sock = await proxy.connect(host, port)
            
            if ssl_context:
                # 如果需要SSL，包装socket
                reader, writer = await asyncio.open_connection(
                    sock=sock, 
                    ssl=ssl_context,
                    server_hostname=host
                )
                return reader, writer
            else:
                # 创建 reader/writer
                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await asyncio.get_event_loop().create_connection(
                    lambda: protocol, sock=sock
                )
                writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_event_loop())
                return reader, writer
        else:
            raise RuntimeError("No proxy library available. Install python-socks: pip install python-socks")
            
    def create_httpx_client(self, **kwargs) -> httpx.AsyncClient:
        """创建支持代理的httpx客户端"""
        if self.enabled:
            kwargs['proxies'] = {
                'http://': self.proxy_url,
                'https://': self.proxy_url
            }
        return httpx.AsyncClient(**kwargs)
        
    def create_aiohttp_session(self, **kwargs) -> 'aiohttp.ClientSession':
        """创建支持代理的aiohttp会话"""
        if not AIOHTTP_SOCKS_AVAILABLE:
            raise RuntimeError("aiohttp-socks not available. Install: pip install aiohttp aiohttp-socks")
            
        if self.enabled:
            connector = ProxyConnector.from_url(self.proxy_url)
            kwargs['connector'] = connector
            
        return aiohttp.ClientSession(**kwargs)
        
    def get_socket_proxy(self) -> Optional['Proxy']:
        """获取python-socks的Proxy对象"""
        if not self.enabled:
            return None
            
        if not PYTHON_SOCKS_AVAILABLE:
            raise RuntimeError("python-socks not available")
            
        return Proxy.from_url(self.proxy_url)
        
    def get_proxy_dict(self) -> Dict[str, str]:
        """获取标准的代理字典（用于requests等）"""
        if not self.enabled:
            return {}
            
        return {
            'http': self.proxy_url,
            'https': self.proxy_url
        }
        
    def update_module_proxy(self, module_name: str, module: Any) -> None:
        """更新特定模块的代理设置"""
        if not self.enabled:
            return
            
        # 常见的代理配置属性名
        proxy_attrs = [
            'PROXY_URL', 'proxy_url', 'proxy',
            'PROXY_ENABLED', 'proxy_enabled',
            'PROXY_CONFIG', 'proxy_config'
        ]
        
        for attr in proxy_attrs:
            if hasattr(module, attr):
                if 'enabled' in attr.lower():
                    setattr(module, attr, True)
                elif 'config' in attr.lower():
                    setattr(module, attr, {
                        'url': self.proxy_url,
                        'enabled': True,
                        'type': self.proxy_type,
                        'host': self.proxy_host,
                        'port': self.proxy_port
                    })
                else:
                    setattr(module, attr, self.proxy_url)
                    
        # 特殊处理某些模块
        if hasattr(module, 'PROXY_ENABLED'):
            module.PROXY_ENABLED = True
            
        logger.info(f"Updated proxy settings for module: {module_name}")
        
    async def test_proxy(self, test_url: str = "https://httpbin.org/ip") -> Dict[str, Any]:
        """测试代理是否工作正常"""
        try:
            async with self.create_httpx_client(timeout=10) as client:
                response = await client.get(test_url)
                data = response.json()
                return {
                    'success': True,
                    'ip': data.get('origin', 'unknown'),
                    'response_time': response.elapsed.total_seconds()
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def __str__(self) -> str:
        if not self.enabled:
            return "UnifiedProxyManager(disabled)"
        return f"UnifiedProxyManager({self.proxy_type}://{self.proxy_host}:{self.proxy_port})"
        

# 全局代理管理器实例
_global_proxy_manager: Optional[UnifiedProxyManager] = None


def init_global_proxy(proxy_url: Optional[str] = None) -> UnifiedProxyManager:
    """初始化全局代理管理器"""
    global _global_proxy_manager
    _global_proxy_manager = UnifiedProxyManager(proxy_url)
    return _global_proxy_manager
    

def get_proxy_manager() -> Optional[UnifiedProxyManager]:
    """获取全局代理管理器"""
    return _global_proxy_manager
    

def apply_proxy_to_module(module: Any, module_name: str = "") -> None:
    """将代理设置应用到指定模块"""
    if _global_proxy_manager:
        _global_proxy_manager.update_module_proxy(module_name or module.__name__, module)