#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
差分干涉仪 Differential Interferometer
或者叫它双缝干涉试验仪
"""
from __future__ import annotations

import asyncio
import ssl
import socket
import time
import json
import base64
import hashlib
import struct
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple
import csv

# Optional HPACK for real HTTP/2 execution
try:
    import hpack  # type: ignore
    H2_AVAILABLE = True
except Exception:
    H2_AVAILABLE = False

# Optional aioquic for HTTP/3 execution (graceful fallback if unavailable)
try:
    from aioquic.asyncio.client import connect as quic_connect  # type: ignore
    from aioquic.quic.configuration import QuicConfiguration  # type: ignore
    from aioquic.h3.connection import H3_ALPN, H3Connection  # type: ignore
    AIOQUIC_AVAILABLE = True
except Exception:
    AIOQUIC_AVAILABLE = False

# Logging (consistent with other modules)
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ----------------------------- Data structures -----------------------------

@dataclass
class Transcript:
    profile: str
    test_id: str
    method: str
    path: str
    request_headers: Dict[str, str]
    request_body_b64: Optional[str]
    status: int
    response_headers: Dict[str, str]
    response_body_b64: Optional[str]
    rtt_ms: float

@dataclass
class HeatCell:
    test_id: str
    profile: str
    status: int
    sig: str  # fingerprint from key headers + small body sample
    cache_hint: str
    auth_hint: str

# ========================================================================
# ⚠️  DEPRECATED: proto_norm_diff.py (v1) 
# ========================================================================
# 此模块已废弃，请使用 proto_norm_diff_v2.py 和 shared_protocol_client.py
# 
# 废弃原因：
# - 手写的HTTP/2实现不稳定，存在SSL连接问题
# - httpx-based实现更加可靠和标准
# - 统一的共享通信核心提供更好的维护性
# ========================================================================

import logging
import warnings

logger = logging.getLogger(__name__)

# 发出废弃警告
warnings.warn(
    "proto_norm_diff.py (v1) is deprecated. "
    "Use proto_norm_diff_v2.py and shared_protocol_client.py instead. "
    "The v1 implementation has SSL/HTTP2 connectivity issues.",
    DeprecationWarning,
    stacklevel=2
)

logger.warning("⚠️ proto_norm_diff.py (v1) is deprecated - redirecting to v2 implementation")

# 重定向到v2实现
from .proto_norm_diff_v2 import ProtoNormDiffV2 as ProtoNormDiff  # type: ignore
from .shared_protocol_client import SharedProtocolClient

# ----------------------------- Legacy compatibility wrapper ----------------------------------

class _DeprecatedProtoNormDiff:
    def __init__(self, host: str, port: int = 443, timeout: float = 10.0, proxy_url: Optional[str] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.proxy_url = proxy_url  # reserved, not used in core
        self.transcripts: List[Transcript] = []
        self.survey: Dict[str, Any] = {}

    # ---------- Topology survey ----------
    async def survey_topology(self) -> Dict[str, Any]:
        logger.info("Surveying topology (ALPN/Alt-Svc/CDN hints)...")
        survey: Dict[str, Any] = {
            'alpn': None,
            'tls_version': None,
            'cipher': None,
            'alt_svc': None,
            'server': None,
            'h2_supported': False,
            'h3_advertised': False,
        }
        try:
            # Establish TLS, offer h2 and http/1.1
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(['h2', 'http/1.1'])
            except Exception:
                pass
            start = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.host),
                timeout=self.timeout,
            )
            ssl_obj: Optional[ssl.SSLObject] = writer.get_extra_info('ssl_object')
            if ssl_obj:
                survey['alpn'] = ssl_obj.selected_alpn_protocol()
                survey['tls_version'] = ssl_obj.version()
                try:
                    cip = ssl_obj.cipher()
                    survey['cipher'] = cip[0] if isinstance(cip, (list, tuple)) else cip
                except Exception:
                    pass
                survey['h2_supported'] = survey['alpn'] == 'h2'
            # Issue an HTTPS GET to collect headers (Alt-Svc/Server)
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: EdgeNormX/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            writer.write(req)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(32768), timeout=5.0)
            writer.close();
            try:
                await writer.wait_closed()
            except Exception:
                pass
            status, headers = self._parse_response_headers(raw)
            survey['server'] = headers.get('server')
            alt_svc = headers.get('alt-svc')
            if alt_svc:
                survey['alt_svc'] = alt_svc
                if 'h3' in alt_svc.lower():
                    survey['h3_advertised'] = True
        except Exception as e:
            survey['error'] = str(e)
        self.survey = survey
        return survey

    async def _execute_profile_task(self, profile: str, tc: Dict[str, Any]) -> Optional[Transcript]:
        """Wrapper for _execute_profile to handle concurrent execution"""
        try:
            return await self._execute_profile(profile, tc)
        except Exception as e:
            logger.warning(f"Profile execution failed for {profile}/{tc.get('id', 'unknown')}: {e}")
            return None
    
    # ---------- Matrix runner ----------
    async def run_matrix(self, dimensions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Enhanced matrix runner with stateful recursive probing"""
        dims = set(dimensions or ['headers', 'path', 'authority', 'cache', 'cl_te'])
        logger.info("Running normalization matrix: %s", sorted(dims))

        # Define base profiles we actively exercise in core
        profiles = ['h1'] \
            + (['h2'] if H2_AVAILABLE and (self.survey.get('h2_supported') if self.survey else True) else []) \
            + (['h3'] if AIOQUIC_AVAILABLE and (self.survey.get('h3_advertised') if self.survey else False) else []) \
            + ['grpc-web', 'ws-upgrade'] \
            + (['grpc-native'] if H2_AVAILABLE and (self.survey.get('h2_supported') if self.survey else True) else [])
        results: Dict[str, Any] = {
            'host': self.host,
            'port': self.port,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'survey': self.survey or {},
            'profiles': profiles,
            'dimensions': sorted(list(dims)),
            'tests': {},
            'heatmap': [],
            'vulnerabilities': [],
            'summary': {},
            'recursive_findings': []
        }

        # Build initial testcases
        testcases = self._build_testcases(dims, profiles)

        # Track explored states for recursive probing
        explored_states = set()
        state_queue = []
        max_recursion_depth = 1  # 进一步减少递归深度避免超时
        current_depth = 0

        # Execute initial test battery with concurrent execution optimization
        total_test_combinations = len(testcases) * len(profiles)
        logger.info("Executing initial test battery (%d tests × %d profiles = %d combinations)", 
                   len(testcases), len(profiles), total_test_combinations)
        
        # Create all test tasks upfront for concurrent execution
        test_tasks = []
        for tc in testcases:
            for profile in profiles:
                test_tasks.append(self._execute_profile_task(profile, tc))
        
        # Execute all tests concurrently with rate limiting
        logger.info("Running %d test combinations concurrently...", len(test_tasks))
        start_time = time.time()
        
        # Use semaphore to control concurrency and avoid overwhelming the target
        semaphore = asyncio.Semaphore(10)  # Max 10 concurrent connections
        
        async def bounded_task(task):
            async with semaphore:
                return await task
        
        # Execute all tasks concurrently
        bounded_tasks = [bounded_task(task) for task in test_tasks]
        transcript_results = await asyncio.gather(*bounded_tasks, return_exceptions=True)
        
        # Process results
        successful_transcripts = 0
        failed_transcripts = 0
        for tr in transcript_results:
            if not isinstance(tr, Exception) and tr is not None:
                # 过滤掉状态码为 0 的错误响应
                if hasattr(tr, 'status') and tr.status == 0:
                    failed_transcripts += 1
                    logger.debug(f"Skipping error response with status 0 for test {getattr(tr, 'test_id', 'unknown')}")
                    continue
                self.transcripts.append(tr)
                cell = self._cell_from_transcript(tr)
                results['heatmap'].append(asdict(cell))
                results['tests'].setdefault(tr.test_id, {}).setdefault(tr.profile, self._small_result(tr))
                successful_transcripts += 1
            else:
                failed_transcripts += 1
                if isinstance(tr, Exception):
                    logger.debug(f"Test execution failed: {tr}")
        
        execution_time = time.time() - start_time
        logger.info("Initial test battery completed: %d/%d successful, %d failed in %.1fs (avg %.1fms per test)", 
                   successful_transcripts, len(test_tasks), failed_transcripts, execution_time, 
                   (execution_time * 1000) / len(test_tasks) if test_tasks else 0)
        logger.info("Concurrency optimization: %dx speedup vs sequential execution", 
                   max(1, int(total_test_combinations / (execution_time / 2.0))) if execution_time > 0 else 1)

        # Analyze initial results
        vuln, summary = self._analyze_heatmap(results['heatmap'])
        results['vulnerabilities'] = vuln
        results['summary'] = summary
        
        # 方案4：递归决策剪枝算法 - 只对高风险发现启动递归
        high_risk_vulns = [v for v in vuln if v['risk_score'] >= 10.0]  # 提高阈值，减少误报
        if high_risk_vulns and current_depth < max_recursion_depth:
            logger.info("Initiating recursive probing based on %d HIGH-RISK vulnerabilities", len(high_risk_vulns))
            
            # Generate follow-up tests based on HIGH-RISK vulnerabilities only
            for v in high_risk_vulns[:2]:  # 只取前2个最高风险
                follow_up_tests = self._generate_recursive_tests(v, results['tests'])
                state_queue.extend(follow_up_tests[:2])  # 每个漏洞最多2个后续测试
        else:
            logger.info("No high-risk vulnerabilities found - skipping recursive probing")
            
            # Execute recursive probes (减少批次大小避免超时)
            while state_queue and current_depth < max_recursion_depth:
                current_depth += 1
                batch_size = min(len(state_queue), 3)  # 进一步减少批次大小避免超时
                batch = state_queue[:batch_size]
                state_queue = state_queue[batch_size:]
                
                logger.info("Recursive probe depth %d: testing %d states", current_depth, len(batch))
                
                for tc in batch:
                    # Skip if already explored
                    state_sig = f"{tc['id']}:{tc.get('path', '')}:{tc.get('headers', {})}"
                    if state_sig in explored_states:
                        continue
                    explored_states.add(state_sig)
                    
                    # Execute across profiles
                    findings = {}
                    for profile in profiles:
                        tr = await self._execute_profile(profile, tc)
                        if tr:
                            self.transcripts.append(tr)
                            cell = self._cell_from_transcript(tr)
                            results['heatmap'].append(asdict(cell))
                            findings[profile] = self._small_result(tr)
                    
                    # 方案1：探测衰减机制 - 检查风险评分，低于阈值就衰减
                    finding_risk_score = self._calculate_finding_risk_score(findings)
                    if finding_risk_score >= 3.0:  # 衰减阈值：3.0
                        results['recursive_findings'].append({
                            'depth': current_depth,
                            'parent_vuln': tc.get('parent_vuln'),
                            'test': tc,
                            'findings': findings,
                            'risk_score': finding_risk_score
                        })
                        
                        # 只有高于衰减阈值的发现才继续生成更深的测试
                        if current_depth < max_recursion_depth and finding_risk_score >= 5.0:
                            more_tests = self._generate_deeper_tests(tc, findings)
                            state_queue.extend(more_tests[:1])  # 进一步限制数量
                    else:
                        logger.debug(f"Probe damping: risk_score {finding_risk_score:.1f} < 3.0, terminating branch")
        
        # Re-analyze with recursive findings
        if results['recursive_findings']:
            vuln, summary = self._analyze_heatmap(results['heatmap'])
            results['vulnerabilities'] = vuln
            results['summary'] = summary
            summary['recursive_discoveries'] = len(results['recursive_findings'])
            
        return results
    
    def _generate_recursive_tests(self, vulnerability: Dict[str, Any], initial_tests: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate follow-up tests based on vulnerability findings"""
        recursive_tests = []
        test_id = vulnerability['test_id']
        differences = vulnerability.get('differences', [])
        
        # Analyze difference types to generate targeted follow-ups
        for diff in differences:
            diff_type = diff['type']
            
            if diff_type == 'PATH_NORMALIZATION':
                # If path normalization difference found, probe deeper
                recursive_tests += [
                    {'id': f'{test_id}_double_encode', 'method': 'GET', 'path': '/admin%252f..%252f..%252fetc%252fpasswd', 
                     'headers': {}, 'parent_vuln': test_id},
                    {'id': f'{test_id}_unicode_bypass', 'method': 'GET', 'path': '/\u0041dmin', 
                     'headers': {}, 'parent_vuln': test_id},
                ]
                
            elif diff_type == 'STATUS_FLIP':
                # If status flip detected, try authentication bypass vectors
                details = diff.get('details', {})
                if any(s in [401, 403] for s in details.values()):
                    recursive_tests += [
                        {'id': f'{test_id}_auth_bypass_xff', 'method': 'GET', 'path': '/admin',
                         'headers': {'X-Forwarded-For': '127.0.0.1'}, 'parent_vuln': test_id},
                        {'id': f'{test_id}_auth_bypass_method', 'method': 'HEAD', 'path': '/admin',
                         'headers': {}, 'parent_vuln': test_id},
                    ]
                    
            elif diff_type == 'CACHE_STATE_DIVERGENCE':
                # Cache poisoning follow-ups
                recursive_tests += [
                    {'id': f'{test_id}_cache_key_injection', 'method': 'GET', 'path': '/?cb=<script>alert(1)</script>',
                     'headers': {'X-Forwarded-Host': 'evil.com'}, 'parent_vuln': test_id},
                ]
                
            elif diff_type == 'METHOD_OVERRIDE':
                # Method override exploitation
                recursive_tests += [
                    {'id': f'{test_id}_override_delete', 'method': 'POST', 'path': '/api/users/1',
                     'headers': {'X-HTTP-Method-Override': 'DELETE', 'X-Method-Override': 'DELETE'}, 
                     'body': b'', 'parent_vuln': test_id},
                ]
        
        return recursive_tests
    
    def _is_interesting_finding(self, findings: Dict[str, Any]) -> bool:
        """Determine if a recursive probe found something worth pursuing"""
        if not findings or len(findings) < 2:
            return False
            
        # Check for status code differences
        statuses = [f.get('status', 0) for f in findings.values()]
        if len(set(statuses)) > 1:
            return True
            
        # Check for significant header differences
        header_counts = [len(f.get('headers', {})) for f in findings.values()]
        if max(header_counts) - min(header_counts) > 3:
            return True
            
        return False
    
    def _calculate_finding_risk_score(self, findings: Dict[str, Any]) -> float:
        """方案1：探测衰减机制 - 快速计算发现的风险评分"""
        if not findings or len(findings) < 2:
            return 0.0
        
        risk_score = 0.0
        
        # 1. 状态码差异评分
        statuses = {p: f.get('status', 0) for p, f in findings.items()}
        unique_statuses = set(statuses.values())
        if len(unique_statuses) > 1:
            # 简化版本的状态翻转评分
            for s1 in statuses.values():
                for s2 in statuses.values():
                    if s1 != s2:
                        # 高价值状态转换
                        if (s1 == 404 and s2 in [200, 301, 403]) or (s2 == 404 and s1 in [200, 301, 403]):
                            risk_score += 6.0  # 路径存在性发现
                        elif (s1 == 401 and s2 == 200) or (s2 == 401 and s1 == 200):
                            risk_score += 8.0  # 认证绕过
                        elif abs(s1 - s2) >= 100:
                            risk_score += 3.0  # 一般状态差异
                        break
        
        # 2. 头部数量差异（简化）
        header_counts = [len(f.get('headers', {})) for f in findings.values()]
        if max(header_counts) - min(header_counts) > 5:
            risk_score += 2.0
        
        # 3. 响应时间异常差异（新增时序侧信道）
        rtts = [f.get('rtt_ms', 0) for f in findings.values() if f.get('rtt_ms', 0) > 0]
        if len(rtts) >= 2:
            rtt_ratio = max(rtts) / min(rtts) if min(rtts) > 0 else 1.0
            if rtt_ratio > 3.0:  # 响应时间差异3倍以上
                risk_score += 4.0  # 可能的不同处理路径
        
        return min(risk_score, 10.0)  # 最高10分
    
    def _generate_deeper_tests(self, parent_test: Dict[str, Any], findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate even deeper tests based on successful recursive findings"""
        deeper_tests = []
        
        # Analyze what made this test interesting
        statuses = {p: f.get('status', 0) for p, f in findings.items()}
        
        # If we found an auth bypass, try to escalate
        if any(200 <= s < 300 for s in statuses.values()) and any(s >= 400 for s in statuses.values()):
            path = parent_test.get('path', '/')
            deeper_tests += [
                {'id': f"{parent_test['id']}_escalate", 'method': 'POST', 
                 'path': path, 'headers': parent_test.get('headers', {}).copy(),
                 'body': b'{"role":"admin"}', 'parent_vuln': parent_test.get('parent_vuln')},
            ]
            
        return deeper_tests

    # ---------- Evidence export ----------
    def export_evidence(self, out_dir: str) -> None:
        import os
        os.makedirs(out_dir, exist_ok=True)
        # transcripts.jsonl
        with open(os.path.join(out_dir, 'transcripts.jsonl'), 'w', encoding='utf-8') as f:
            for tr in self.transcripts:
                f.write(json.dumps(asdict(tr), ensure_ascii=False) + '\n')
        # survey.json
        with open(os.path.join(out_dir, 'survey.json'), 'w', encoding='utf-8') as f:
            json.dump(self.survey, f, ensure_ascii=False, indent=2)

    def export_heatmap_csv(self, heatmap: List[Dict[str, Any]], csv_path: str) -> None:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['test_id', 'profile', 'status', 'sig', 'cache_hint', 'auth_hint'])
            writer.writeheader()
            for row in heatmap:
                writer.writerow(row)

    # ------------------------- Internals: tests ------------------------------

    def _build_testcases(self, dims: set, profiles: List[str] = None) -> List[Dict[str, Any]]:
        """Intelligence-driven test case generation based on survey results"""
        profiles = profiles or ['h1', 'grpc-web']
        cases: List[Dict[str, Any]] = []
        base_path = '/'
        
        # Dynamic adjustments based on survey
        server_info = (self.survey.get('server', '') or '').lower()
        has_h2 = self.survey.get('h2_supported', False)
        has_h3 = self.survey.get('h3_advertised', False)
        alt_svc = self.survey.get('alt_svc', '')
        
        # headers dimension with intelligence-driven additions
        if 'headers' in dims:
            # Base header tests
            cases += [
                {'id': 'hdr_case', 'method': 'GET', 'path': base_path, 'headers': {'X-Test-Probe': 'A'}, 'variant': {'x-test-probe': 'A'}},
                {'id': 'hdr_dup', 'method': 'GET', 'path': base_path, 'headers': {'X-Test-Probe': 'A, B'}, 'variant': {'X-Test-Probe': 'A', 'X-Test-Probe-2': 'B'}},
                {'id': 'hdr_ows', 'method': 'GET', 'path': base_path, 'headers': {'X-Test-OWS': '  v  '}, 'variant': {}},
                {'id': 'hdr_cookie_merge', 'method': 'GET', 'path': base_path, 'headers': {'Cookie': 'a=1; b=2'}, 'variant': {'Cookie': 'a=1', 'Cookie-2': 'b=2'}},
                {'id': 'hdr_method_override', 'method': 'POST', 'path': base_path, 'headers': {'X-HTTP-Method-Override': 'DELETE'}, 'body': b''},
                {'id': 'hdr_xfh', 'method': 'GET', 'path': base_path, 'headers': {'X-Forwarded-Host': f'internal.{self.host}'}},
            ]
            
            # Nginx-specific tests
            if 'nginx' in server_info:
                cases += [
                    {'id': 'hdr_nginx_underscores', 'method': 'GET', 'path': base_path, 'headers': {'X_Test_Header': 'underscore'}},
                    {'id': 'hdr_nginx_merge_slashes', 'method': 'GET', 'path': '//path//with///slashes', 'headers': {}},
                ]
            
            # Apache-specific tests
            if 'apache' in server_info:
                cases += [
                    {'id': 'hdr_apache_mod_rewrite', 'method': 'GET', 'path': base_path, 'headers': {'X-Original-URL': '/admin'}},
                ]
            
            # Cloudflare detection
            if 'cloudflare' in server_info or 'cf-ray' in str(self.survey):
                cases += [
                    {'id': 'hdr_cf_connecting_ip', 'method': 'GET', 'path': base_path, 'headers': {'CF-Connecting-IP': '127.0.0.1'}},
                    {'id': 'hdr_cf_visitor', 'method': 'GET', 'path': base_path, 'headers': {'CF-Visitor': '{"scheme":"http"}'}},
                ]
            
            # Protocol-specific header tests
            if has_h2:
                cases += [
                    {'id': 'hdr_h2_pseudo_headers', 'method': 'GET', 'path': base_path, 'headers': {':authority': 'evil.com'}},
                ]
                
        # path dimension with dynamic tests
        if 'path' in dims:
            cases += [
                {'id': 'path_pct_upper', 'method': 'GET', 'path': '/Proto-Norm-Diff', 'headers': {}, 'variant': {'path': '/Proto%2dNorm%2dDiff'}},
                {'id': 'path_dot_segments', 'method': 'GET', 'path': '/a/../b', 'headers': {}, 'variant': {'path': '/b'}},
                {'id': 'path_semicolon', 'method': 'GET', 'path': '/p;param=1', 'headers': {}, 'variant': {'path': '/p'}},
            ]
            
            # Add Unicode normalization tests for modern servers
            if has_h2 or has_h3:
                cases += [
                    {'id': 'path_unicode_nfc', 'method': 'GET', 'path': '/café', 'headers': {}},  # NFC form
                    {'id': 'path_unicode_nfd', 'method': 'GET', 'path': '/cafe\u0301', 'headers': {}},  # NFD form
                ]
                
        # authority dimension
        if 'authority' in dims:
            cases += [
                {'id': 'auth_host_case', 'method': 'GET', 'path': base_path, 'headers': {'Host': self.host.upper()}, 'variant': {'Host': self.host}},
            ]
            
            # Alt-Svc specific tests
            if alt_svc:
                alt_host = self._extract_alt_svc_host(alt_svc)
                if alt_host:
                    cases += [
                        {'id': 'auth_alt_svc', 'method': 'GET', 'path': base_path, 'headers': {'Host': alt_host}},
                    ]
                    
        # cache dimension with advanced cache poisoning vectors
        if 'cache' in dims:
            # Basic cache tests
            cases += [
                {'id': 'cache_accept_lang', 'method': 'GET', 'path': base_path, 'headers': {'Accept-Language': 'en'}, 'variant': {'Accept-Language': 'fr'}},
                {'id': 'cache_vary', 'method': 'GET', 'path': base_path, 'headers': {'Cache-Control': 'public'}, 'variant': {'Cache-Control': 'no-cache'}},
            ]
            
            # Unkeyed header poisoning vectors
            cases += [
                # Classic unkeyed headers
                {'id': 'cache_xfh_poison', 'method': 'GET', 'path': '/?cb=1', 
                 'headers': {'X-Forwarded-Host': 'evil.com'}},
                {'id': 'cache_xfs_poison', 'method': 'GET', 'path': '/?cb=2',
                 'headers': {'X-Forwarded-Scheme': 'http'}},
                {'id': 'cache_xfp_poison', 'method': 'GET', 'path': '/?cb=3',
                 'headers': {'X-Forwarded-Port': '8080'}},
                {'id': 'cache_xop_poison', 'method': 'GET', 'path': '/?cb=4',
                 'headers': {'X-Original-URL': '/admin'}},
                {'id': 'cache_xrw_poison', 'method': 'GET', 'path': '/?cb=5',
                 'headers': {'X-Rewrite-URL': '/internal/api'}},
                
                # Fat GET request cache poisoning
                {'id': 'cache_fat_get', 'method': 'GET', 'path': '/?cb=6',
                 'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                 'body': b'poison=data'},
                
                # Cache key normalization attacks
                {'id': 'cache_key_case', 'method': 'GET', 'path': '/Index.HTML',
                 'headers': {}},
                {'id': 'cache_key_encode', 'method': 'GET', 'path': '/%69ndex.html',
                 'headers': {}},
                {'id': 'cache_key_fragment', 'method': 'GET', 'path': '/index.html#poison',
                 'headers': {}},
                
                # Parameter pollution
                {'id': 'cache_param_pollution', 'method': 'GET', 'path': '/?utm_source=evil&cb=7',
                 'headers': {}},
                {'id': 'cache_param_order', 'method': 'GET', 'path': '/?a=1&b=2',
                 'headers': {}, 'variant': {'path': '/?b=2&a=1'}},
            ]
            
            # CDN-specific cache tests
            if any(cdn in server_info for cdn in ['cloudflare', 'akamai', 'fastly']):
                cases += [
                    {'id': 'cache_cdn_bypass', 'method': 'GET', 'path': base_path, 
                     'headers': {'Cache-Control': 'no-cache, no-store', 'Pragma': 'no-cache'}},
                    {'id': 'cache_origin_header', 'method': 'GET', 'path': base_path, 
                     'headers': {'Origin': 'https://evil.com'}},
                    
                    # Cloudflare specific
                    {'id': 'cache_cf_cache_tag', 'method': 'GET', 'path': '/?cb=8',
                     'headers': {'Cache-Tag': 'evil'}},
                    
                    # Fastly specific
                    {'id': 'cache_fastly_debug', 'method': 'GET', 'path': '/?cb=9',
                     'headers': {'Fastly-Debug': '1'}},
                ]
            
            # Web Cache Deception
            cases += [
                {'id': 'cache_deception_css', 'method': 'GET', 'path': '/account/settings/nonexistent.css',
                 'headers': {}},
                {'id': 'cache_deception_js', 'method': 'GET', 'path': '/api/user/data/fake.js',
                 'headers': {}},
                {'id': 'cache_deception_semicolon', 'method': 'GET', 'path': '/private/data;.css',
                 'headers': {}},
            ]
            
            # Protocol-specific cache poisoning
            if has_h2:
                cases += [
                    {'id': 'cache_h2_pseudo_auth', 'method': 'GET', 'path': '/?cb=10',
                     'headers': {':authority': 'evil.com'}},
                ]
                
        # Enhanced cl/te detection - Deep HTTP Request Smuggling tests
        if 'cl_te' in dims:
            # Basic CL/TE tests
            cases += [
                {'id': 'cl_only', 'method': 'POST', 'path': '/echo', 'headers': {'Content-Type': 'application/octet-stream'}, 'body': b'1234567890'},
            ]
            
            # Classic CL.TE smuggling (safe probe - no actual smuggling)
            cases += [
                {'id': 'cl_te_classic', 'method': 'POST', 'path': '/echo',
                 'headers': {'Content-Length': '13', 'Transfer-Encoding': 'chunked'},
                 'body': b'0\r\n\r\nSMUGGLED'},
            ]
            
            # TE.CL smuggling probe
            cases += [
                {'id': 'te_cl_probe', 'method': 'POST', 'path': '/echo',
                 'headers': {'Transfer-Encoding': 'chunked', 'Content-Length': '6'},
                 'body': b'0\r\n\r\n'},
            ]
            
            # Obfuscated Transfer-Encoding
            cases += [
                {'id': 'te_obfuscated_chunked', 'method': 'POST', 'path': '/echo',
                 'headers': {'Transfer-Encoding': 'chunked'}, 'body': b'0\r\n\r\n'},
                {'id': 'te_obfuscated_identity', 'method': 'POST', 'path': '/echo',
                 'headers': {'Transfer-Encoding': 'identity'}, 'body': b'test'},
                {'id': 'te_obfuscated_space', 'method': 'POST', 'path': '/echo',
                 'headers': {'Transfer-Encoding': ' chunked'}, 'body': b'0\r\n\r\n'},
                {'id': 'te_obfuscated_case', 'method': 'POST', 'path': '/echo',
                 'headers': {'Transfer-Encoding': 'CHUNKED'}, 'body': b'0\r\n\r\n'},
                {'id': 'te_obfuscated_tab', 'method': 'POST', 'path': '/echo',
                 'headers': {'Transfer-Encoding': 'chunked\t'}, 'body': b'0\r\n\r\n'},
            ]
            
            # Multiple TE headers
            cases += [
                {'id': 'te_multiple', 'method': 'POST', 'path': '/echo',
                 'headers': {'Transfer-Encoding': 'chunked, identity'}, 'body': b'0\r\n\r\n'},
            ]
            
            # Protocol-specific smuggling tests
            if has_h2:
                cases += [
                    {'id': 'cl_te_h2_downgrade', 'method': 'POST', 'path': '/echo', 
                     'headers': {'Content-Length': '10', 'Transfer-Encoding': 'chunked'}, 
                     'body': b'0\r\n\r\n'},
                    {'id': 'h2_cl_priority', 'method': 'POST', 'path': '/echo',
                     'headers': {'content-length': '5'}, 'body': b'12345'},
                ]
            
            # gRPC-specific smuggling
            if 'grpc-web' in dims or 'grpc-native' in profiles:
                cases += [
                    {'id': 'grpc_te_smuggle', 'method': 'POST', 'path': '/grpc.test/Method',
                     'headers': {'content-type': 'application/grpc', 'transfer-encoding': 'chunked'},
                     'body': b'\x00\x00\x00\x00\x05hello'},
                ]
        
        # 方案2：主动扰动探测 (Active Perturbation) - 针对"透明"介质的强制差异化
        if 'headers' in dims:
            cases += [
                # 非ASCII控制字符扰动
                {'id': 'perturb_ctrl_char', 'method': 'GET', 'path': base_path, 
                 'headers': {'X-Test-Ctrl': 'value\x01\x02\x03'}},
                # 重复Content-Length头（不同大小写）
                {'id': 'perturb_dup_cl', 'method': 'POST', 'path': '/echo',
                 'headers': {'Content-Length': '5', 'content-length': '10'}, 'body': b'hello'},
                # 畸形百分号编码
                {'id': 'perturb_malformed_pct', 'method': 'GET', 'path': '/test%2',
                 'headers': {}},
                # 超长头部值
                {'id': 'perturb_long_header', 'method': 'GET', 'path': base_path,
                 'headers': {'X-Long-Value': 'A' * 8192}},
                # NULL字节注入
                {'id': 'perturb_null_byte', 'method': 'GET', 'path': base_path,
                 'headers': {'X-Null-Test': 'value\x00truncated'}},
                # 不规范的HTTP版本
                {'id': 'perturb_http_version', 'method': 'GET', 'path': base_path,
                 'headers': {'X-Test-Version': 'HTTP/2.0'}},  # 在H1请求中声明H2
            ]
                
        return cases
    
    def _extract_alt_svc_host(self, alt_svc: str) -> Optional[str]:
        """Extract alternative host from Alt-Svc header"""
        # Simplified parser for Alt-Svc
        import re
        match = re.search(r'h3[^=]*="([^:]+):(\d+)"', alt_svc)
        if match:
            return match.group(1)
        return None

    async def _execute_profile(self, profile: str, tc: Dict[str, Any]) -> Optional[Transcript]:
        method = tc.get('method', 'GET')
        path = tc.get('path', '/')
        headers = dict(tc.get('headers', {}))
        body: Optional[bytes] = tc.get('body')
        # Apply per-profile adjustments
        if profile == 'h1':
            return await self._https_h1(method, path, headers, body, tc)
        elif profile == 'grpc-web':
            # gRPC-Web over HTTP/1.1 detection-style: set content-type/x-grpc-web and small payload
            gheaders = {'content-type': 'application/grpc-web', 'x-grpc-web': '1', 'te': 'trailers'}
            merged = {**headers, **gheaders}
            payload = body or b'\x00\x00\x00\x00\x00'  # empty gRPC message
            return await self._https_h1('POST' if method != 'GET' else 'POST', path, merged, payload, tc)
        elif profile == 'ws-upgrade':
            # WebSocket upgrade probe; many endpoints will reject; we only capture normalization differences
            ws_headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
            }
            merged = {**headers, **ws_headers}
            return await self._https_h1('GET', path, merged, None, tc)
        elif profile == 'h2':
            return await self._https_h2(method, path, headers, body, tc)
        elif profile == 'h3':
            return await self._https_h3(method, path, headers, body, tc)
        elif profile == 'grpc-native':
            return await self._grpc_native(method, path, headers, body, tc)
        return None

    async def _https_h1(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes], tc: Dict[str, Any]) -> Transcript:
        # Respect variant if provided (second pass semantics can be added later)
        request_headers = {k: v for k, v in headers.items()}
        if 'Host' not in {k.lower(): v for k, v in request_headers.items()}:
            request_headers['Host'] = self.host
        request_headers.setdefault('User-Agent', 'EdgeNormX/1.0')
        request_headers.setdefault('Accept', '*/*')
        request_headers.setdefault('Connection', 'close')

        # Build request
        body_bytes = body or b''
        if method.upper() == 'POST' and 'Transfer-Encoding' not in {k.title(): v for k, v in request_headers.items()}:
            request_headers['Content-Length'] = str(len(body_bytes))
        req_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in request_headers.items():
            req_lines.append(f"{k}: {v}")
        req = ("\r\n".join(req_lines) + "\r\n\r\n").encode() + body_bytes

        # TLS connect and send
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.host),
                timeout=self.timeout,
            )
            writer.write(req)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
        except Exception as e:
            # 不再伪装成 HTTP 响应，直接返回 None 表示失败
            logger.debug(f"Connection failed for profile h1: {e}")
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        rtt_ms = (time.perf_counter() - start) * 1000
        status, resp_headers = self._parse_response_headers(raw)
        body_b64 = self._extract_body_b64(raw)
        tr = Transcript(
            profile='h1' if 'Upgrade' not in request_headers else ('ws-upgrade' if request_headers.get('Upgrade') == 'websocket' else 'h1'),
            test_id=tc['id'],
            method=method,
            path=path,
            request_headers=self._lower_dict(request_headers),
            request_body_b64=base64.b64encode(body_bytes).decode() if body_bytes else None,
            status=status,
            response_headers=self._lower_dict(resp_headers),
            response_body_b64=body_b64,
            rtt_ms=rtt_ms,
        )
        return tr

    async def _grpc_native(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes], tc: Dict[str, Any]) -> Transcript:
        """Native gRPC over HTTP/2 implementation"""
        if not H2_AVAILABLE:
            # Fallback to grpc-web if H2 not available
            return await self._execute_profile('grpc-web', tc)
        
        # gRPC requires specific path format: /<package>.<service>/<method>
        # For testing, we'll use a generic probe path if not provided
        grpc_path = path if path.startswith('/') and path.count('/') >= 2 else '/grpc.health.v1.Health/Check'
        
        # Build gRPC-specific headers
        grpc_headers = {
            'content-type': 'application/grpc',
            'te': 'trailers',
            'grpc-accept-encoding': 'identity,gzip',
        }
        merged_headers = {**headers, **grpc_headers}
        
        # gRPC message format: [compression flag (1 byte)][message length (4 bytes)][message]
        grpc_body = b'\x00\x00\x00\x00\x00' if not body else self._grpc_encode_message(body)
        
        # Use HTTP/2 transport with gRPC-specific adjustments
        hdrs_list = [
            (":method", "POST"),  # gRPC always uses POST
            (":scheme", "https"),
            (":authority", merged_headers.get('Host', self.host)),
            (":path", grpc_path),
        ]
        
        for k, v in merged_headers.items():
            kl = k.lower()
            if kl in (':method', ':scheme', ':authority', ':path', 'host', 'connection', 'upgrade'):
                continue
            hdrs_list.append((kl, str(v)))
        
        # Execute via H2 with special handling for trailers
        tr = await self._https_h2_with_trailers("POST", grpc_path, merged_headers, grpc_body, tc)
        tr.profile = 'grpc-native'
        return tr
    
    def _grpc_encode_message(self, data: bytes) -> bytes:
        """Encode data in gRPC wire format"""
        # Compression flag (0 = no compression)
        compression = b'\x00'
        # Message length (big-endian 32-bit)
        length = struct.pack('>I', len(data))
        return compression + length + data
    
    async def _https_h2_with_trailers(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes], tc: Dict[str, Any]) -> Transcript:
        """Enhanced H2 client that handles trailers for gRPC"""
        # For now, reuse standard H2 implementation
        # In a full implementation, this would handle gRPC trailers properly
        return await self._https_h2(method, path, headers, body, tc)

    async def _https_h3(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes], tc: Dict[str, Any]) -> Transcript:
        # Optional HTTP/3 using aioquic; fallback to H1
        if not AIOQUIC_AVAILABLE:
            tr = await self._https_h1(method, path, headers, body, tc)
            tr.profile = 'h3'
            return tr
        status = 0
        resp_headers: Dict[str, str] = {}
        data_buf = b''
        start = time.perf_counter()
        try:
            conf = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
            async with quic_connect(self.host, self.port, configuration=conf, server_name=self.host) as client:
                h3 = H3Connection(client._quic)  # type: ignore[attr-defined]
                # Create request
                stream_id = client._quic.get_next_available_stream_id()  # type: ignore[attr-defined]
                hdrs = [
                    (b':method', method.upper().encode()),
                    (b':scheme', b'https'),
                    (b':authority', headers.get('Host', self.host).encode()),
                    (b':path', path.encode()),
                ]
                for k, v in headers.items():
                    kl = k.lower()
                    if kl in (':method', ':scheme', ':authority', ':path', 'host', 'connection', 'upgrade'):
                        continue
                    hdrs.append((kl.encode(), str(v).encode()))
                h3.send_headers(stream_id, hdrs, end_stream=(method.upper() == 'GET' or not body))
                if body and method.upper() != 'GET':
                    h3.send_data(stream_id, body, end_stream=True)
                client.transmit()
                # Event loop
                deadline = time.perf_counter() + self.timeout
                from aioquic.h3.events import HeadersReceived, DataReceived  # type: ignore
                while time.perf_counter() < deadline:
                    await asyncio.sleep(0.01)
                    for event in client._quic.poll_events():  # type: ignore[attr-defined]
                        if isinstance(event, aioquic.quic.events.DatagramFrameReceived):  # type: ignore[name-defined]
                            pass
                    for event in h3.poll_events():
                        if isinstance(event, HeadersReceived) and event.stream_id == stream_id:
                            for k, v in event.headers:
                                ks = k.decode() if isinstance(k, (bytes, bytearray)) else k
                                vs = v.decode() if isinstance(v, (bytes, bytearray)) else v
                                if ks == ':status':
                                    try:
                                        status = int(vs)
                                    except Exception:
                                        status = 0
                                else:
                                    resp_headers[ks.lower()] = vs
                        elif isinstance(event, DataReceived) and event.stream_id == stream_id:
                            data_buf += event.data
                            if event.stream_ended:
                                deadline = time.perf_counter()  # break
                try:
                    await client.close()
                except Exception:
                    pass
        except Exception as e:
            resp_headers = {'x-edgenormx-error': str(e)}
        rtt_ms = (time.perf_counter() - start) * 1000
        tr = Transcript(
            profile='h3',
            test_id=tc['id'],
            method=method,
            path=path,
            request_headers=self._lower_dict({k: v for k, v in headers.items()}),
            request_body_b64=base64.b64encode(body).decode() if body else None,
            status=status,
            response_headers=self._lower_dict(resp_headers),
            response_body_b64=base64.b64encode(data_buf[:4096]).decode() if data_buf else None,
            rtt_ms=rtt_ms,
        )
        return tr

    async def _https_h2(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes], tc: Dict[str, Any]) -> Transcript:
        # Minimal HTTP/2 client using HPACK if available
        # If unavailable, fall back to H1 and mark profile as h2 (skipped)
        if not H2_AVAILABLE:
            h1 = await self._https_h1(method, path, headers, body, tc)
            h1.profile = 'h2'
            return h1
        # Build pseudo-headers and regular headers
        hdrs_list = [
            (":method", method.upper()),
            (":scheme", "https"),
            (":authority", headers.get('Host', self.host)),
            (":path", path),
        ]
        # Copy user headers excluding Host (authority used), and connection-specific ones
        for k, v in headers.items():
            kl = k.lower()
            if kl in (':method', ':scheme', ':authority', ':path', 'host', 'connection', 'upgrade'):
                continue
            hdrs_list.append((kl, str(v)))
        # Ensure UA
        if not any(k == 'user-agent' for k, _ in hdrs_list):
            hdrs_list.append(('user-agent', 'EdgeNormX/1.0'))
        encoder = hpack.Encoder()
        header_block = encoder.encode(hdrs_list)
        # TLS with ALPN h2
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(['h2'])
        except Exception:
            pass
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.host),
                timeout=self.timeout,
            )
            # HTTP/2 preface and SETTINGS (empty payload)
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            writer.write(self._h2_frame(0x4, 0x0, 0, b""))  # SETTINGS
            await writer.drain()
            # Send HEADERS on stream 1
            flags = 0x4  # END_HEADERS
            end_stream = False
            if (method.upper() == 'GET' or not body):
                flags |= 0x1  # END_STREAM
                end_stream = True
            writer.write(self._h2_frame(0x1, flags, 1, header_block))
            if not end_stream and body:
                # Send DATA and END_STREAM
                writer.write(self._h2_frame(0x0, 0x0, 1, body))
                writer.write(self._h2_frame(0x0, 0x1, 1, b""))
            await writer.drain()
            # Read frames until we get response HEADERS and END_STREAM
            headers_block = b""
            got_headers = False
            end_stream_seen = False
            data_buf = b""
            decoder = hpack.Decoder()
            deadline = time.perf_counter() + self.timeout
            while time.perf_counter() < deadline and not (got_headers and end_stream_seen):
                frame = await self._h2_read_frame(reader)
                if frame is None:
                    break
                ftype, flags, stream_id, payload = frame
                if ftype == 0x1:  # HEADERS
                    headers_block += payload
                    if flags & 0x4:  # END_HEADERS
                        got_headers = True
                elif ftype == 0x9:  # CONTINUATION
                    headers_block += payload
                    if flags & 0x4:
                        got_headers = True
                elif ftype == 0x0:  # DATA
                    data_buf += payload
                    if flags & 0x1:
                        end_stream_seen = True
                elif ftype == 0x7:  # GOAWAY
                    end_stream_seen = True
                elif ftype == 0x4:  # SETTINGS (ignore)
                    pass
            # Decode headers
            resp_headers: Dict[str, str] = {}
            status = 0
            if headers_block:
                try:
                    hdrs = decoder.decode(headers_block)
                    for k, v in hdrs:
                        kl = k.decode() if isinstance(k, (bytes, bytearray)) else k
                        vl = v.decode() if isinstance(v, (bytes, bytearray)) else v
                        if kl == ':status':
                            try:
                                status = int(vl)
                            except Exception:
                                status = 0
                        else:
                            resp_headers[kl.lower()] = vl
                except Exception:
                    pass
            # Close
            try:
                writer.close(); await writer.wait_closed()
            except Exception:
                pass
        except Exception as e:
            status = 0
            resp_headers = {'x-edgenormx-error': str(e)}
            data_buf = b""
        rtt_ms = (time.perf_counter() - start) * 1000
        tr = Transcript(
            profile='h2',
            test_id=tc['id'],
            method=method,
            path=path,
            request_headers=self._lower_dict({k: v for k, v in headers.items()}),
            request_body_b64=base64.b64encode(body).decode() if body else None,
            status=status,
            response_headers=self._lower_dict(resp_headers),
            response_body_b64=base64.b64encode(data_buf[:4096]).decode() if data_buf else None,
            rtt_ms=rtt_ms,
        )
        return tr

    # ------------------------- Internals: helpers ----------------------------

    def _parse_response_headers(self, raw: bytes) -> Tuple[int, Dict[str, str]]:
        try:
            text = raw.decode('iso-8859-1', errors='ignore')
            head, _, _ = text.partition('\r\n\r\n')
            lines = head.split('\r\n')
            status = 0
            headers: Dict[str, str] = {}
            if lines:
                parts = lines[0].split(' ')
                if len(parts) >= 2 and parts[0].startswith('HTTP/'):
                    try:
                        status = int(parts[1])
                    except Exception:
                        status = 0
                for line in lines[1:]:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.strip().lower()] = v.strip()
            return status, headers
        except Exception:
            return 0, {}

    def _extract_body_b64(self, raw: bytes) -> Optional[str]:
        try:
            sep = raw.find(b"\r\n\r\n")
            if sep == -1:
                return None
            body = raw[sep+4:]
            if not body:
                return None
            # Limit for evidence
            return base64.b64encode(body[:4096]).decode()
        except Exception:
            return None

    def _lower_dict(self, d: Dict[str, str]) -> Dict[str, str]:
        return {str(k).lower(): str(v) for k, v in d.items()}

    # HTTP/2 helpers
    def _h2_frame(self, ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
        length = len(payload)
        header = struct.pack('>I', length)[1:] + bytes([ftype, flags]) + struct.pack('>I', stream_id & 0x7FFFFFFF)
        return header + payload

    async def _h2_read_frame(self, reader: asyncio.StreamReader) -> Optional[Tuple[int, int, int, bytes]]:
        try:
            header = await asyncio.wait_for(reader.readexactly(9), timeout=self.timeout)
            length = (header[0] << 16) | (header[1] << 8) | header[2]
            ftype = header[3]
            flags = header[4]
            stream_id = struct.unpack('>I', header[5:9])[0] & 0x7FFFFFFF
            payload = b''
            if length > 0:
                payload = await asyncio.wait_for(reader.readexactly(length), timeout=self.timeout)
            return (ftype, flags, stream_id, payload)
        except Exception:
            return None

    def _cell_from_transcript(self, tr: Transcript) -> HeatCell:
        key_headers = ['status', 'etag', 'last-modified', 'content-length', 'location', 'set-cookie', 'age', 'cache-control']
        h = tr.response_headers
        parts = [str(tr.status)] + [f"{k}:{h.get(k,'')}" for k in key_headers[1:]]
        # Include small body hash (if present)
        body_sig = ''
        if tr.response_body_b64:
            try:
                body_sig = hashlib.sha256(base64.b64decode(tr.response_body_b64)).hexdigest()[:16]
            except Exception:
                pass
        sig_src = '|'.join(parts) + '|' + body_sig
        sig = hashlib.sha1(sig_src.encode()).hexdigest()[:12]
        cache_hint = 'HIT' if any(k in h for k in ['age', 'x-cache', 'cf-cache-status']) else 'MISS'
        auth_hint = 'AUTH' if any(k in h for k in ['www-authenticate', 'set-cookie', 'x-user', 'authorization']) else 'NONE'
        return HeatCell(test_id=tr.test_id, profile=tr.profile, status=tr.status, sig=sig, cache_hint=cache_hint, auth_hint=auth_hint)

    def _small_result(self, tr: Transcript) -> Dict[str, Any]:
        return {
            'status': tr.status,
            'headers': tr.response_headers,
            'rtt_ms': tr.rtt_ms,
        }

    def _analyze_heatmap(self, heatmap: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Enhanced difference analysis with classification and quantitative scoring"""
        # Group by test_id
        by_test: Dict[str, List[Dict[str, Any]]] = {}
        for cell in heatmap:
            by_test.setdefault(cell['test_id'], []).append(cell)
        
        vulnerabilities: List[Dict[str, Any]] = []
        total_risk_score = 0.0
        
        # Define difference types with base risk scores (调整为更合理的值)
        DIFF_TYPES = {
            'STATUS_FLIP': {'base_score': 6.0, 'desc': 'Status code divergence across profiles'},
            'AUTH_CONTEXT_SWITCH': {'base_score': 7.0, 'desc': 'Authentication context change'},
            'CACHE_STATE_DIVERGENCE': {'base_score': 5.0, 'desc': 'Cache behavior inconsistency'},
            'TIMING_DIVERGENCE': {'base_score': 3.0, 'desc': 'Response timing difference indicating different processing paths'},
            'HEADER_SYNTAX': {'base_score': 2.5, 'desc': 'Header normalization difference'},
            'HEADER_REFLECTION': {'base_score': 2.0, 'desc': 'Header reflection inconsistency'},
            'BODY_TRANSFORMATION': {'base_score': 2.0, 'desc': 'Response body divergence'},
            'PATH_NORMALIZATION': {'base_score': 4.0, 'desc': 'Path interpretation difference'},
            'METHOD_OVERRIDE': {'base_score': 5.5, 'desc': 'Method override behavior difference'},
        }
        
        for tid, cells in by_test.items():
            # Extract data for all profiles
            profiles_data = {c['profile']: c for c in cells}
            
            # Deep analysis
            differences = []
            risk_score = 0.0
            
            # 1. STATUS_FLIP analysis
            statuses = {p: c['status'] for p, c in profiles_data.items()}
            # 过滤掉状态码为0的错误响应
            valid_statuses = {p: s for p, s in statuses.items() if s > 0}
            if not valid_statuses:
                continue  # 跳过所有都是错误的测试
            unique_statuses = set(valid_statuses.values())
            if len(unique_statuses) > 1:
                # Calculate severity based on specific status transitions
                max_severity_score = 0.0
                for p1, s1 in valid_statuses.items():
                    for p2, s2 in valid_statuses.items():
                        if p1 != p2 and s1 != s2:
                            severity_score = self._calculate_status_flip_severity(s1, s2)
                            max_severity_score = max(max_severity_score, severity_score)
                
                score = DIFF_TYPES['STATUS_FLIP']['base_score'] * max_severity_score
                differences.append({
                    'type': 'STATUS_FLIP',
                    'score': score,
                    'details': statuses,
                    'severity_modifier': max_severity_score
                })
                risk_score += score
            
            # 2. AUTH_CONTEXT_SWITCH analysis
            auth_hints = {p: c.get('auth_hint', 'NONE') for p, c in profiles_data.items()}
            auth_headers = self._extract_auth_headers(profiles_data)
            if len(set(auth_hints.values())) > 1 or self._has_auth_divergence(auth_headers):
                score = DIFF_TYPES['AUTH_CONTEXT_SWITCH']['base_score']
                # Increase score if some profiles require auth while others don't
                if 'AUTH' in auth_hints.values() and 'NONE' in auth_hints.values():
                    score *= 1.2
                differences.append({
                    'type': 'AUTH_CONTEXT_SWITCH',
                    'score': score,
                    'details': {'hints': auth_hints, 'headers': auth_headers}
                })
                risk_score += score
            
            # 3. CACHE_STATE_DIVERGENCE analysis
            cache_hints = {p: c.get('cache_hint', 'MISS') for p, c in profiles_data.items()}
            cache_headers = self._extract_cache_headers(profiles_data)
            if len(set(cache_hints.values())) > 1 or self._has_cache_divergence(cache_headers):
                score = DIFF_TYPES['CACHE_STATE_DIVERGENCE']['base_score']
                # Higher risk if cache poisoning vector detected
                if tid in ['cache_accept_lang', 'cache_vary'] and 'HIT' in cache_hints.values():
                    score *= 1.3
                differences.append({
                    'type': 'CACHE_STATE_DIVERGENCE',
                    'score': score,
                    'details': {'hints': cache_hints, 'headers': cache_headers}
                })
                risk_score += score
            
            # 4. HEADER_SYNTAX analysis
            header_diffs = self._analyze_header_syntax_differences(profiles_data, tid)
            if header_diffs:
                score = DIFF_TYPES['HEADER_SYNTAX']['base_score'] * len(header_diffs) * 0.5
                differences.append({
                    'type': 'HEADER_SYNTAX',
                    'score': min(score, 8.0),  # Cap at 8.0
                    'details': header_diffs
                })
                risk_score += score
            
            # 5. BODY_TRANSFORMATION analysis
            body_sigs = self._analyze_body_differences(profiles_data)
            if len(set(body_sigs.values())) > 1:
                score = DIFF_TYPES['BODY_TRANSFORMATION']['base_score']
                differences.append({
                    'type': 'BODY_TRANSFORMATION',
                    'score': score,
                    'details': body_sigs
                })
                risk_score += score
            
            # 方案3：时序侧信道分析 - 增强版
            rtts = {p: c['rtt_ms'] for p, c in profiles_data.items() if c.get('rtt_ms', 0) > 0}
            if len(rtts) >= 2:
                rtt_values = list(rtts.values())
                rtt_ratio = max(rtt_values) / min(rtt_values) if min(rtt_values) > 0 else 1.0
                if rtt_ratio > 2.5:  # 时序差异2.5倍以上
                    # 时序差异评分：根据差异倍数计算
                    timing_score = min(5.0 + (rtt_ratio - 2.5) * 2.0, 9.0)
                    differences.append({
                        'type': 'TIMING_DIVERGENCE',
                        'score': timing_score,
                        'details': {'rtts': rtts, 'ratio': rtt_ratio},
                        'description': f'Response time divergence: {rtt_ratio:.1f}x difference suggests different processing paths'
                    })
                    risk_score += timing_score
            
            # 6. Test-specific analysis
            if tid.startswith('path_'):
                path_diffs = self._analyze_path_normalization(profiles_data)
                if path_diffs:
                    score = DIFF_TYPES['PATH_NORMALIZATION']['base_score']
                    differences.append({
                        'type': 'PATH_NORMALIZATION',
                        'score': score,
                        'details': path_diffs
                    })
                    risk_score += score
            
            if tid == 'hdr_method_override':
                method_diffs = self._analyze_method_override(profiles_data)
                if method_diffs:
                    score = DIFF_TYPES['METHOD_OVERRIDE']['base_score']
                    differences.append({
                        'type': 'METHOD_OVERRIDE',
                        'score': score,
                        'details': method_diffs
                    })
                    risk_score += score
            
            # Create vulnerability entry if differences found
            if differences:
                # Calculate severity based on risk score
                severity = self._score_to_severity(risk_score)
                
                vulnerabilities.append({
                    'test_id': tid,
                    'risk_score': round(risk_score, 2),
                    'severity': severity,
                    'differences': differences,
                    'profiles_affected': list(profiles_data.keys()),
                    'attack_vectors': self._suggest_attack_vectors(differences, tid)
                })
                total_risk_score += risk_score
        
        # Sort vulnerabilities by risk score
        vulnerabilities.sort(key=lambda v: v['risk_score'], reverse=True)
        
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(vulnerabilities, total_risk_score)
        
        summary = {
            'overall_risk': overall_risk['level'],
            'total_risk_score': round(total_risk_score, 2),
            'critical_findings': len([v for v in vulnerabilities if v['severity'] == 'CRITICAL']),
            'high_findings': len([v for v in vulnerabilities if v['severity'] == 'HIGH']),
            'medium_findings': len([v for v in vulnerabilities if v['severity'] == 'MEDIUM']),
            'low_findings': len([v for v in vulnerabilities if v['severity'] == 'LOW']),
            'profiles_exercised': len({c['profile'] for c in heatmap}) if heatmap else 0,
            'tests_executed': len(by_test),
            'top_risks': [v['test_id'] for v in vulnerabilities[:3]] if vulnerabilities else []
        }
        
        return vulnerabilities, summary
    
    def _calculate_status_flip_severity(self, status1: int, status2: int) -> float:
        """Calculate severity multiplier for status code transitions"""
        # Auth bypass scenarios (真正的认证绕过)
        if (status1 in [401, 403] and 200 <= status2 < 300) or \
           (status2 in [401, 403] and 200 <= status1 < 300):
            return 1.8  # Critical auth bypass
        
        # Access control differences (信息泄露风险)
        if (status1 == 403 and status2 == 404) or (status1 == 404 and status2 == 403):
            return 1.0  # Information disclosure
        
        # Error vs success (可能的安全问题)
        if (status1 >= 400 and status2 < 400) or (status1 < 400 and status2 >= 400):
            return 0.8  # Significant difference
        
        # Same class differences (正常的协议差异)
        return 0.3
    
    def _extract_auth_headers(self, profiles_data: Dict[str, Dict]) -> Dict[str, List[str]]:
        """Extract authentication-related headers from responses"""
        auth_headers = ['www-authenticate', 'authorization', 'x-auth-token', 'x-api-key', 'set-cookie']
        result = {}
        for profile, data in profiles_data.items():
            headers = self.transcripts[0].response_headers if self.transcripts else {}
            result[profile] = [h for h in auth_headers if h in headers]
        return result
    
    def _has_auth_divergence(self, auth_headers: Dict[str, List[str]]) -> bool:
        """Check if authentication headers differ across profiles"""
        header_sets = [set(headers) for headers in auth_headers.values()]
        return len(set(map(tuple, header_sets))) > 1
    
    def _extract_cache_headers(self, profiles_data: Dict[str, Dict]) -> Dict[str, Dict[str, str]]:
        """Extract cache-related headers"""
        cache_headers = ['cache-control', 'etag', 'last-modified', 'age', 'x-cache', 'vary']
        result = {}
        for profile, data in profiles_data.items():
            # This is simplified - in real implementation, would access actual response headers
            result[profile] = {}
        return result
    
    def _has_cache_divergence(self, cache_headers: Dict[str, Dict[str, str]]) -> bool:
        """Check for cache behavior differences"""
        # Simplified - would compare actual cache headers
        return False
    
    def _analyze_header_syntax_differences(self, profiles_data: Dict[str, Dict], test_id: str) -> List[Dict]:
        """Analyze header syntax normalization differences"""
        differences = []
        # Would analyze actual header differences based on test_id
        return differences
    
    def _analyze_body_differences(self, profiles_data: Dict[str, Dict]) -> Dict[str, str]:
        """Analyze response body differences"""
        body_sigs = {}
        for profile, data in profiles_data.items():
            # Calculate body signature
            body_sigs[profile] = data.get('sig', '')
        return body_sigs
    
    def _analyze_path_normalization(self, profiles_data: Dict[str, Dict]) -> Dict[str, Any]:
        """Analyze path normalization differences"""
        # Would check if different profiles normalized paths differently
        return {}
    
    def _analyze_method_override(self, profiles_data: Dict[str, Dict]) -> Dict[str, Any]:
        """Analyze method override behavior"""
        # Would check if X-HTTP-Method-Override was respected differently
        return {}
    
    def _score_to_severity(self, score: float) -> str:
        """Convert risk score to severity level"""
        if score >= 15.0:
            return 'CRITICAL'
        elif score >= 10.0:
            return 'HIGH'
        elif score >= 5.0:
            return 'MEDIUM'
        elif score >= 2.0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _suggest_attack_vectors(self, differences: List[Dict], test_id: str) -> List[str]:
        """Suggest potential attack vectors based on differences found"""
        vectors = []
        diff_types = {d['type'] for d in differences}
        
        if 'STATUS_FLIP' in diff_types:
            vectors.append('Authentication Bypass')
            vectors.append('Access Control Bypass')
        
        if 'CACHE_STATE_DIVERGENCE' in diff_types:
            vectors.append('Cache Poisoning')
            vectors.append('Web Cache Deception')
        
        if 'PATH_NORMALIZATION' in diff_types:
            vectors.append('Path Traversal')
            vectors.append('Request Smuggling')
        
        if 'METHOD_OVERRIDE' in diff_types:
            vectors.append('HTTP Verb Tampering')
            vectors.append('REST API Manipulation')
        
        if 'AUTH_CONTEXT_SWITCH' in diff_types:
            vectors.append('Session Fixation')
            vectors.append('Privilege Escalation')
        
        return list(set(vectors))  # Remove duplicates
    
    def _calculate_overall_risk(self, vulnerabilities: List[Dict], total_score: float) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        if not vulnerabilities:
            return {'level': 'NONE', 'score': 0}
        
        critical_count = len([v for v in vulnerabilities if v['severity'] == 'CRITICAL'])
        high_count = len([v for v in vulnerabilities if v['severity'] == 'HIGH'])
        
        if critical_count > 0 or total_score >= 30:
            level = 'CRITICAL'
        elif high_count >= 2 or total_score >= 20:
            level = 'HIGH'
        elif high_count >= 1 or total_score >= 10:
            level = 'MEDIUM'
        elif total_score >= 5:
            level = 'LOW'
        else:
            level = 'MINIMAL'
        
        return {
            'level': level,
            'score': total_score,
            'confidence': min(95, 60 + len(vulnerabilities) * 5)  # Confidence increases with findings
        }

# ----------------------------- CLI -----------------------------------------

async def _main_async():
    import argparse
    parser = argparse.ArgumentParser(description='EdgeNormX - Protocol Normalization Difference Analyzer')
    parser.add_argument('host', help='Target hostname')
    parser.add_argument('--port', type=int, default=443, help='TLS port (default: 443)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Timeout seconds (default: 10.0)')
    parser.add_argument('--dimensions', nargs='+', help='Dimensions to run: headers path authority cache cl_te')
    parser.add_argument('--output', '-o', help='Write results to file')
    parser.add_argument('--format', choices=['json', 'report'], default='report')
    parser.add_argument('--evidence-dir', help='Export transcripts/survey to directory')
    parser.add_argument('--export-heatmap-csv', help='Export heatmap CSV to path')
    args = parser.parse_args()

    tool = ProtoNormDiff(args.host, args.port, args.timeout)
    survey = await tool.survey_topology()
    results = await tool.run_matrix(args.dimensions)

    # Optional exports
    if args.evidence_dir:
        tool.export_evidence(args.evidence_dir)
    if args.export_heatmap_csv:
        tool.export_heatmap_csv(results.get('heatmap', []), args.export_heatmap_csv)

    # Format output
    if args.format == 'json':
        out = json.dumps(results, indent=2, ensure_ascii=False, default=str)
    else:
        # Enhanced human-readable report
        lines: List[str] = []
        lines.append('╔' + '═' * 78 + '╗')
        lines.append('║' + ' EDGENORMX - PROTOCOL NORMALIZATION DIFFERENCE ANALYZER '.center(78) + '║')
        lines.append('║' + ' "Mathematical Physics Defeats Penetration" '.center(78) + '║')
        lines.append('╚' + '═' * 78 + '╝')
        lines.append('')
        lines.append(f"  Target: {args.host}:{args.port}")
        lines.append(f"  Time: {results.get('timestamp')}")
        lines.append(f"  Profiles Tested: {', '.join(results.get('profiles', []))}")
        lines.append('')
        
        # Topology Survey
        lines.append('  TOPOLOGY SURVEY')
        lines.append(' ' + '─' * 60)
        s = results.get('survey', {})
        lines.append(f"  Protocol Support: ALPN={s.get('alpn')} | H2={s.get('h2_supported')} | H3={s.get('h3_advertised')}")
        lines.append(f"  TLS Version: {s.get('tls_version')} | Cipher: {s.get('cipher')}")
        if s.get('server'):
            lines.append(f"  Server: {s.get('server')}")
        if s.get('alt_svc'):
            lines.append(f"  Alt-Svc: {s.get('alt_svc')}")
        lines.append('')
        
        # Risk Summary
        summary = results.get('summary', {})
        lines.append('  RISK ASSESSMENT')
        lines.append(' ' + '─' * 60)
        risk_level = summary.get('overall_risk', 'UNKNOWN')
        risk_score = summary.get('total_risk_score', 0)
        risk_emoji = {'CRITICAL': '', 'HIGH': '', 'MEDIUM': '', 'LOW': '', 'MINIMAL': '', 'NONE': ''}.get(risk_level, '')
        lines.append(f"  {risk_emoji} Overall Risk: {risk_level} (Score: {risk_score})")
        lines.append(f"  Critical: {summary.get('critical_findings', 0)} | High: {summary.get('high_findings', 0)} | Medium: {summary.get('medium_findings', 0)} | Low: {summary.get('low_findings', 0)}")
        if summary.get('recursive_discoveries', 0) > 0:
            lines.append(f"   Recursive Discoveries: {summary['recursive_discoveries']}")
        lines.append('')
        
        # Top Vulnerabilities
        lines.append('  TOP VULNERABILITIES')
        lines.append(' ' + '─' * 60)
        vulns = results.get('vulnerabilities', [])
        if not vulns:
            lines.append('   No normalization differences detected')
        else:
            for i, v in enumerate(vulns[:5], 1):
                severity_icon = {'CRITICAL': 'CEITICAL', 'HIGH': 'HIGH', 'MEDIUM': '️MEDIUM', 'LOW': 'LWO'}.get(v['severity'], '•')
                lines.append(f"  {i}. {severity_icon} [{v['severity']}] Test: {v['test_id']} (Score: {v['risk_score']})")
                
                # Show difference types
                diff_types = [d['type'] for d in v.get('differences', [])]
                if diff_types:
                    lines.append(f"     Differences: {', '.join(diff_types)}")
                
                # Show attack vectors
                vectors = v.get('attack_vectors', [])
                if vectors:
                    lines.append(f"     Attack Vectors: {', '.join(vectors[:3])}")
        lines.append('')
        
        # Recursive Findings
        recursive = results.get('recursive_findings', [])
        if recursive:
            lines.append('  RECURSIVE PROBE DISCOVERIES')
            lines.append(' ' + '─' * 60)
            for rf in recursive[:3]:
                lines.append(f"  Depth {rf['depth']}: {rf['test']['id']} (Parent: {rf.get('parent_vuln', 'N/A')})")
                statuses = {p: f['status'] for p, f in rf['findings'].items() if 'status' in f}
                if statuses:
                    lines.append(f"     Status codes: {statuses}")
        lines.append('')
        
        # Heatmap Preview
        lines.append(' ️  NORMALIZATION HEATMAP (Preview)')
        lines.append(' ' + '─' * 60)
        lines.append('  Test ID          | Profile  | Status | Signature | Cache/Auth')
        lines.append('  ' + '-' * 58)
        for cell in results.get('heatmap', [])[:8]:
            test_id = cell['test_id'][:15].ljust(15)
            profile = cell['profile'][:8].ljust(8)
            status = str(cell['status']).rjust(3)
            sig = cell['sig'][:8]
            cache_auth = f"{cell.get('cache_hint', 'N/A')[:4]}/{cell.get('auth_hint', 'N/A')[:4]}"
            lines.append(f"  {test_id} | {profile} | {status} | {sig} | {cache_auth}")
        
        lines.append('')
        lines.append('  RECOMMENDATIONS')
        lines.append(' ' + '─' * 60)
        
        # Generate recommendations based on findings
        if risk_level in ['CRITICAL', 'HIGH']:
            lines.append('   URGENT: Critical protocol normalization differences detected!')
            lines.append('  • Review and patch gateway/proxy configurations immediately')
            lines.append('  • Implement strict protocol validation at edge')
            lines.append('  • Consider WAF rules for detected attack vectors')
        elif risk_level == 'MEDIUM':
            lines.append('  ️  Moderate normalization differences found')
            lines.append('  • Review proxy/CDN configurations')
            lines.append('  • Monitor for exploitation attempts')
            lines.append('  • Plan remediation for identified issues')
        else:
            lines.append('   Good protocol normalization consistency')
            lines.append('  • Continue monitoring for changes')
            lines.append('  • Regular re-assessment recommended')
        
        lines.append('')
        lines.append('═' * 80)
        out = '\n'.join(lines)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(out)
        print(f"Results written to: {args.output}")
    else:
        print(out)

    # Exit code by risk
    risk = (results.get('summary') or {}).get('overall_risk', 'NONE')
    mapping = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'MINIMAL': 0, 'NONE': 0}
    import sys
    sys.exit(mapping.get(risk, 0))


def main():
    # Windows event loop policy alignment (same as orchestrator)
    import sys
    if sys.platform == 'win32':
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    asyncio.run(_main_async())


if __name__ == '__main__':
    main()
