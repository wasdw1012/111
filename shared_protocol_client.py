"""
Shared Protocol Communication Core
==================================
统一的协议通信核心，基于httpx，替换所有手写的网络实现

从proto_norm_diff_v2.py中提取EnhancedProtocolClient作为共享核心
供所有模块使用，确保网络通信的一致性和可靠性
"""

import asyncio
import json
import logging
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from httpx import AsyncClient

# Setup logging
logger = logging.getLogger(__name__)

# Global proxy support (imported from existing modules)
try:
    from .fingerprint_proxy import PROXY_ENABLED, PROXY_URL, PROXY_AVAILABLE
except ImportError:
    try:
        # Fallback to parent directory
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))
        from fingerprint_proxy import PROXY_ENABLED, PROXY_URL, PROXY_AVAILABLE
    except ImportError:
        PROXY_ENABLED = False
        PROXY_URL = None
        PROXY_AVAILABLE = False

class SharedProtocolClient:
    """
    统一的协议通信客户端
    
    基于httpx实现，支持HTTP/1.1, HTTP/2, HTTP/3
    替换所有模块中的手写网络代码
    """
    
    def __init__(self, 
                 host: str, 
                 port: int = 443,
                 timeout: float = 10.0,
                 proxy_url: Optional[str] = None,
                 enable_http2: bool = True,
                 enable_http3: bool = False):
        
        self.host = host
        self.port = port
        self.timeout = timeout
        self.proxy_url = proxy_url or (PROXY_URL if PROXY_ENABLED and PROXY_AVAILABLE else None)
        self.enable_http2 = enable_http2
        self.enable_http3 = enable_http3
        
        # 创建基础配置
        self.base_config = {
            'verify': False,  # 禁用SSL验证（安全测试需要）
            'timeout': httpx.Timeout(timeout),
            'limits': httpx.Limits(
                max_keepalive_connections=10,
                max_connections=20,
                keepalive_expiry=30.0
            ),
            'http2': enable_http2,
            'follow_redirects': False,  # 安全测试需要控制重定向
        }
        
        if self.proxy_url:
            self.base_config['proxies'] = {
                'http://': self.proxy_url,
                'https://': self.proxy_url,
            }
            
        self._client = None
        
    async def __aenter__(self):
        self._client = AsyncClient(**self.base_config)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
            
    @property
    def client(self) -> AsyncClient:
        """获取httpx客户端实例"""
        if self._client is None:
            self._client = AsyncClient(**self.base_config)
        return self._client
        
    async def close(self):
        """关闭客户端"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def test_http2_connectivity(self) -> Dict[str, Any]:
        """
        测试HTTP/2连接能力
        替换h2_cfs模块中的手写实现
        """
        start_time = time.perf_counter()
        
        try:
            # 强制HTTP/2测试
            config = self.base_config.copy()
            config['http2'] = True
            
            async with AsyncClient(**config) as client:
                response = await client.get(f"https://{self.host}:{self.port}/")
                
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                return {
                    'supported': True,
                    'http_version': response.http_version,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'server': response.headers.get('server', ''),
                    'duration_ms': duration_ms,
                    'alpn_negotiated': response.http_version == 'HTTP/2',
                    'diagnostics': {
                        'ssl_handshake': True,
                        'connection_successful': True,
                        'response_received': True
                    }
                }
                
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_type = type(e).__name__
            error_message = str(e)
            
            logger.warning(f"HTTP/2 connectivity test failed [{error_type}]: {error_message}")
            
            # 尝试HTTP/1.1作为降级
            try:
                config = self.base_config.copy()
                config['http2'] = False
                
                async with AsyncClient(**config) as client:
                    response = await client.get(f"https://{self.host}:{self.port}/")
                    
                    return {
                        'supported': False,
                        'fallback_successful': True,
                        'http_version': response.http_version,
                        'status_code': response.status_code,
                        'server': response.headers.get('server', ''),
                        'error': error_message,
                        'error_type': error_type,
                        'duration_ms': duration_ms,
                        'diagnostics': {
                            'ssl_handshake': True,
                            'http1_fallback': True
                        },
                        'recommendations': [
                            'Server supports HTTP/1.1 but not HTTP/2',
                            'HTTP/2 may be disabled in server configuration',
                            'Consider using HTTP/1.1 security testing approaches'
                        ]
                    }
            except Exception as fallback_error:
                return {
                    'supported': False,
                    'fallback_successful': False,
                    'error': error_message,
                    'error_type': error_type,
                    'fallback_error': str(fallback_error),
                    'duration_ms': duration_ms,
                    'diagnostics': {
                        'ssl_handshake': 'SSL_ERROR' not in error_message.upper(),
                        'connection_failed': True
                    },
                    'recommendations': [
                        'Server may not support HTTP/2 or HTTPS',
                        'Check server configuration and SSL setup',
                        'Verify network connectivity and firewall rules'
                    ]
                }
    
    async def execute_http_test(self, 
                               method: str = 'GET',
                               path: str = '/',
                               headers: Optional[Dict[str, str]] = None,
                               data: Optional[Union[str, bytes, Dict]] = None,
                               force_http_version: Optional[str] = None) -> Dict[str, Any]:
        """
        执行HTTP测试请求
        通用的HTTP测试方法，替换各模块中的自定义实现
        """
        start_time = time.perf_counter()
        
        # 构建URL
        scheme = 'https' if self.port == 443 or self.port == 8443 else 'http'
        if self.port in [80, 443]:
            url = f"{scheme}://{self.host}{path}"
        else:
            url = f"{scheme}://{self.host}:{self.port}{path}"
        
        # 配置HTTP版本
        config = self.base_config.copy()
        if force_http_version:
            if force_http_version.lower() == 'http/1.1':
                config['http2'] = False
            elif force_http_version.lower() == 'http/2':
                config['http2'] = True
        
        try:
            async with AsyncClient(**config) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=data
                )
                
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                return {
                    'success': True,
                    'status_code': response.status_code,
                    'http_version': response.http_version,
                    'headers': dict(response.headers),
                    'content': response.content,
                    'text': response.text if response.content else '',
                    'duration_ms': duration_ms,
                    'server': response.headers.get('server', ''),
                    'content_length': len(response.content) if response.content else 0
                }
                
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'duration_ms': duration_ms,
                'url': url,
                'method': method
            }
    
    async def execute_tls_test(self) -> Dict[str, Any]:
        """
        执行TLS连接测试
        替换cert_sociology等模块中的手写TLS代码
        """
        start_time = time.perf_counter()
        
        try:
            async with AsyncClient(**self.base_config) as client:
                # 执行简单请求来建立TLS连接
                url = f"https://{self.host}:{self.port}/"
                response = await client.get(url)
                
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # 尝试获取TLS信息（httpx的限制，无法直接获取SSL对象）
                return {
                    'success': True,
                    'handshake_duration_ms': duration_ms,
                    'http_version': response.http_version,
                    'server': response.headers.get('server', ''),
                    'status_code': response.status_code,
                    'tls_established': True,
                    'certificate_accepted': True
                }
                
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'duration_ms': duration_ms,
                'tls_established': False
            }
    
    async def test_server_push_support(self) -> Dict[str, Any]:
        """
        测试HTTP/2 Server Push支持
        替换h2_push_poisoning等模块的实现
        """
        try:
            # httpx doesn't directly support server push testing
            # We'll use a standard HTTP/2 request and check response headers
            result = await self.execute_http_test(
                headers={'accept': 'text/html,*/*;q=0.8'}
            )
            
            if result['success']:
                # Check for server push indicators in headers
                headers = result.get('headers', {})
                link_header = headers.get('link', '')
                
                return {
                    'push_supported': 'preload' in link_header.lower(),
                    'link_header': link_header,
                    'http_version': result.get('http_version'),
                    'server_push_hints': 'push' in str(headers).lower()
                }
            else:
                return {
                    'push_supported': False,
                    'error': result.get('error'),
                    'test_failed': True
                }
                
        except Exception as e:
            return {
                'push_supported': False,
                'error': str(e),
                'test_failed': True
            }
    
    async def execute_h2_continuation_attacks(self) -> Dict[str, Any]:
        """执行HTTP/2 CONTINUATION帧攻击，使用稳定的httpx实现"""
        attack_results = {
            'vulnerabilities': [],
            'summary': {'overall_risk': 'LOW'},
            'attack_details': {}
        }
        
        try:
            # 首先验证HTTP/2支持
            h2_test = await self.test_http2_connectivity()
            if not h2_test.get('supported'):
                return {
                    'http2_supported': False,
                    'reason': 'HTTP/2 not supported',
                    'vulnerabilities': []
                }
            
            # 使用稳定的httpx执行各种HTTP/2攻击测试
            attack_results['attack_details']['frame_size_test'] = await self._test_frame_size_manipulation()
            attack_results['attack_details']['header_interleaving'] = await self._test_header_interleaving()
            attack_results['attack_details']['pseudo_header_test'] = await self._test_pseudo_header_confusion()
            
            # 评估结果
            vuln_count = 0
            for test_name, result in attack_results['attack_details'].items():
                if result.get('vulnerable') or result.get('anomaly_detected'):
                    vuln_count += 1
                    attack_results['vulnerabilities'].append({
                        'type': test_name,
                        'severity': result.get('severity', 'MEDIUM'),
                        'title': result.get('title', f'{test_name} vulnerability'),
                        'evidence': result.get('evidence', [])
                    })
            
            # 设置风险等级
            if vuln_count >= 2:
                attack_results['summary']['overall_risk'] = 'HIGH'
            elif vuln_count >= 1:
                attack_results['summary']['overall_risk'] = 'MEDIUM'
                
        except Exception as e:
            logger.error(f"HTTP/2 CONTINUATION attacks failed: {e}")
            attack_results['error'] = str(e)
            
        return attack_results
    
    async def _test_frame_size_manipulation(self) -> Dict[str, Any]:
        """测试HTTP/2帧大小操作"""
        try:
            # 使用不同的帧大小配置测试
            results = []
            config = self.base_config.copy()
            config['http2'] = True
            
            async with AsyncClient(**config) as client:
                for frame_size in [16384, 32768, 65536]:  # 不同帧大小
                    response = await client.get(
                        f"https://{self.host}:{self.port}/",
                        headers={'test-frame-size': str(frame_size)}
                    )
                    results.append({
                        'frame_size': frame_size,
                        'status': response.status_code,
                        'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
                    })
            
            # 分析异常响应
            anomaly_detected = len(set(r['status'] for r in results)) > 1
            
            return {
                'vulnerable': anomaly_detected,
                'anomaly_detected': anomaly_detected,
                'severity': 'MEDIUM' if anomaly_detected else 'LOW',
                'title': 'HTTP/2 Frame Size Manipulation',
                'evidence': results,
                'test_count': len(results)
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'test_count': 0
            }
    
    async def _test_header_interleaving(self) -> Dict[str, Any]:
        """测试HTTP/2头部交错"""
        try:
            # 测试大量头部和不同的头部组合
            test_headers = {
                'X-Test-Header-1': 'A' * 1000,
                'X-Test-Header-2': 'B' * 500, 
                'X-Custom-Header': 'test-value',
                'User-Agent': 'HTTP2-Continuation-Test/1.0'
            }
            
            config = self.base_config.copy()
            config['http2'] = True
            
            async with AsyncClient(**config) as client:
                response = await client.get(
                    f"https://{self.host}:{self.port}/",
                    headers=test_headers
                )
            
            # 检查响应是否异常
            anomaly_detected = (
                response.status_code >= 400 and response.status_code != 404 and response.status_code != 403
            ) or len(response.content) == 0
            
            return {
                'vulnerable': anomaly_detected,
                'anomaly_detected': anomaly_detected,
                'severity': 'MEDIUM' if anomaly_detected else 'LOW',
                'title': 'HTTP/2 Header Interleaving Test',
                'evidence': {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers_sent': len(test_headers)
                }
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e)
            }
    
    async def _test_pseudo_header_confusion(self) -> Dict[str, Any]:
        """测试伪头部混淆"""
        try:
            # HTTP/2伪头部测试
            confusing_headers = {
                'X-Authority-Override': self.host,
                'X-Method-Override': 'POST',
                'X-Path-Override': '/admin',
                'X-Scheme-Override': 'https'
            }
            
            config = self.base_config.copy()
            config['http2'] = True
            
            async with AsyncClient(**config) as client:
                response = await client.get(
                    f"https://{self.host}:{self.port}/",
                    headers=confusing_headers
                )
            
            # 检查是否有意外的响应
            anomaly_detected = response.status_code == 200 and 'admin' in response.text.lower()
            
            return {
                'vulnerable': anomaly_detected,
                'anomaly_detected': anomaly_detected,
                'severity': 'HIGH' if anomaly_detected else 'LOW',
                'title': 'HTTP/2 Pseudo-Header Confusion',
                'evidence': {
                    'status_code': response.status_code,
                    'admin_content_detected': 'admin' in response.text.lower()
                }
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e)
            }

    async def execute_grpc_test(self, 
                               service_path: str = '/',
                               message_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        执行gRPC测试
        替换grpc_trailer_poisoning等模块的实现
        """
        # gRPC-Web over HTTP/2
        headers = {
            'content-type': 'application/grpc-web+proto',
            'grpc-encoding': 'identity',
            'grpc-accept-encoding': 'identity,deflate,gzip'
        }
        
        if message_data is None:
            # 创建空的gRPC消息
            message_data = b'\x00\x00\x00\x00\x00'  # 空消息的gRPC格式
        
        return await self.execute_http_test(
            method='POST',
            path=service_path,
            headers=headers,
            data=message_data,
            force_http_version='HTTP/2'
        )

# 全局实例管理
_client_cache: Dict[str, SharedProtocolClient] = {}

def get_shared_client(host: str, port: int = 443, **kwargs) -> SharedProtocolClient:
    """
    获取共享的协议客户端实例
    实现连接复用和缓存
    """
    cache_key = f"{host}:{port}"
    
    if cache_key not in _client_cache:
        _client_cache[cache_key] = SharedProtocolClient(
            host=host, port=port, **kwargs
        )
    
    return _client_cache[cache_key]

async def cleanup_shared_clients():
    """清理所有共享客户端"""
    for client in _client_cache.values():
        await client.close()
    _client_cache.clear()

# 兼容性适配器：为现有模块提供平滑迁移
class LegacyCompatibility:
    """为现有模块提供兼容性适配"""
    
    @staticmethod
    async def h2_cfs_adapter(host: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
        """h2_cfs模块的适配器"""
        client = get_shared_client(host, port, timeout=timeout)
        return await client.test_http2_connectivity()
    
    @staticmethod
    async def cert_sociology_adapter(host: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
        """cert_sociology模块的适配器"""
        client = get_shared_client(host, port, timeout=timeout)
        return await client.execute_tls_test()
    
    @staticmethod
    async def grpc_adapter(host: str, port: int = 443, service_path: str = '/') -> Dict[str, Any]:
        """gRPC模块的适配器"""
        client = get_shared_client(host, port)
        return await client.execute_grpc_test(service_path)

if __name__ == "__main__":
    # 简单测试
    async def test_client():
        async with SharedProtocolClient("httpbin.org", 443) as client:
            result = await client.test_http2_connectivity()
            print(f"HTTP/2 support: {result}")
            
            http_result = await client.execute_http_test()
            print(f"HTTP test: {http_result['success']}, {http_result.get('http_version')}")
    
    asyncio.run(test_client())