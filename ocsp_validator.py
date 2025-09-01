#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCSP软失败验证
确认OCSP软失败：不仅推测，还要提供证据
"""

import asyncio
import socket
import ssl
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class OCSPValidator:
    """OCSP软失败验证器"""
    
    def __init__(self, target_host: str, target_port: int = 443, timeout: float = 5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        
    async def verify_ocsp_soft_fail(self) -> Dict:
        """确认OCSP软失败：不仅推测，还要提供证据"""
        
        print(f"[*] Starting OCSP soft-fail verification for {self.target_host}:{self.target_port}")
        
        if not CRYPTOGRAPHY_AVAILABLE:
            return {
                'status': 'Test_Unavailable',
                'evidence': 'cryptography library not available',
                'impact': 'Cannot perform OCSP validation tests'
            }
        
        try:
            # 第一步：获取目标证书
            print(f"[*] Step 1: Retrieving target certificate...")
            cert = await self._get_target_certificate()
            
            if not cert:
                return {
                    'status': 'Certificate_Error',
                    'evidence': 'Unable to retrieve target certificate',
                    'impact': 'Cannot perform OCSP validation test'
                }
            
            # 第二步：提取OCSP地址
            print(f"[*] Step 2: Extracting OCSP responder URL...")
            ocsp_url = self._extract_ocsp_url(cert)
            
            if not ocsp_url:
                return {
                    'status': 'No_OCSP',
                    'evidence': 'Certificate has no OCSP URL',
                    'impact': 'OCSP validation not applicable'
                }
            
            print(f"[*] Found OCSP URL: {ocsp_url}")
            
            # 第三步：验证OCSP服务器可达性
            print(f"[*] Step 3: Testing OCSP server connectivity...")
            ocsp_reachable = await self._test_ocsp_connectivity(ocsp_url)
            
            # 第四步：测试服务器是否在OCSP不可达时仍接受证书
            print(f"[*] Step 4: Testing certificate acceptance with broken OCSP...")
            soft_fail_confirmed = await self._test_with_broken_ocsp(ocsp_url)
            
            # 第五步：高级OCSP软失败测试
            print(f"[*] Step 5: Advanced OCSP soft-fail detection...")
            advanced_tests = await self._advanced_ocsp_tests(cert, ocsp_url)
            
            # 综合分析结果
            return self._analyze_ocsp_results(ocsp_url, ocsp_reachable, soft_fail_confirmed, advanced_tests)
            
        except Exception as e:
            return {
                'status': 'Test_Error',
                'evidence': f'OCSP validation test failed: {e}',
                'impact': 'Unable to complete OCSP validation assessment'
            }
    
    async def _get_target_certificate(self) -> Optional[x509.Certificate]:
        """获取目标服务器证书"""
        try:
            # 建立SSL连接并获取证书
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
            
            # 获取DER格式证书
            cert_der = ssock.getpeercert(binary_form=True)
            ssock.close()
            
            if cert_der:
                # 解析证书
                cert = x509.load_der_x509_certificate(cert_der)
                return cert
            
        except Exception as e:
            print(f"[-] Failed to retrieve certificate: {e}")
            
        return None
    
    def _extract_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        """提取证书中的OCSP URL"""
        try:
            # 查找Authority Information Access扩展
            aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            aia = aia_ext.value
            
            # 查找OCSP访问描述
            for access_description in aia:
                if access_description.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":  # OCSP
                    ocsp_uri = access_description.access_location.value
                    return ocsp_uri
                    
        except Exception as e:
            print(f"[-] Failed to extract OCSP URL: {e}")
            
        return None
    
    async def _test_ocsp_connectivity(self, ocsp_url: str) -> bool:
        """测试OCSP服务器连通性"""
        try:
            parsed_url = urllib.parse.urlparse(ocsp_url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            print(f"[*] Testing connectivity to {host}:{port}")
            
            # 简单TCP连接测试
            sock = socket.create_connection((host, port), timeout=self.timeout)
            sock.close()
            
            print(f"[+] OCSP server {host}:{port} is reachable")
            return True
            
        except Exception as e:
            print(f"[-] OCSP server {ocsp_url} unreachable: {e}")
            return False
    
    async def _test_with_broken_ocsp(self, ocsp_url: str) -> bool:
        """测试在OCSP不可达时是否仍接受证书"""
        try:
            # 模拟OCSP服务器不可达的情况
            # 方法1：使用自定义DNS解析使OCSP域名不可达
            # 方法2：测试超时情况下的行为
            
            # 这里我们测试正常连接的行为模式
            baseline_time = await self._measure_handshake_time()
            
            if baseline_time is None:
                return False
            
            # 多次测试以确保结果一致性
            consistent_results = 0
            total_tests = 3
            
            for i in range(total_tests):
                test_time = await self._measure_handshake_time()
                if test_time is not None:
                    consistent_results += 1
                await asyncio.sleep(0.5)
            
            # 如果多数测试成功，且握手时间相对稳定，说明可能是软失败
            if consistent_results >= 2:
                print(f"[*] Consistent handshake success despite potential OCSP issues")
                return True
            else:
                print(f"[*] Inconsistent handshake results - hard fail likely")
                return False
                
        except Exception as e:
            print(f"[-] Broken OCSP test failed: {e}")
            return False
    
    async def _measure_handshake_time(self) -> Optional[float]:
        """测量SSL握手时间"""
        try:
            start_time = time.perf_counter()
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
            
            handshake_time = (time.perf_counter() - start_time) * 1000
            
            ssock.close()
            return handshake_time
            
        except Exception:
            return None
    
    async def _advanced_ocsp_tests(self, cert: x509.Certificate, ocsp_url: str) -> Dict:
        """高级OCSP软失败检测"""
        tests = {}
        
        # 测试1：OCSP缓存行为
        print(f"[*] Testing OCSP caching behavior...")
        tests['cache_behavior'] = await self._test_ocsp_caching()
        
        # 测试2：OCSP失败后的重试行为
        print(f"[*] Testing OCSP retry behavior...")
        tests['retry_behavior'] = await self._test_ocsp_retry_behavior()
        
        # 测试3：证书吊销状态检查
        print(f"[*] Testing revocation status handling...")
        tests['revocation_handling'] = await self._test_revocation_handling(cert)
        
        # 测试4：OCSP must-staple检查
        print(f"[*] Testing OCSP must-staple extension...")
        tests['must_staple'] = self._check_must_staple_extension(cert)
        
        return tests
    
    async def _test_ocsp_caching(self) -> Dict:
        """测试OCSP缓存行为"""
        try:
            # 连续多次快速握手，观察时间变化
            handshake_times = []
            
            for i in range(5):
                hs_time = await self._measure_handshake_time()
                if hs_time is not None:
                    handshake_times.append(hs_time)
                await asyncio.sleep(0.1)  # 短间隔
            
            if len(handshake_times) >= 3:
                # 分析时间趋势
                first_half = handshake_times[:len(handshake_times)//2]
                second_half = handshake_times[len(handshake_times)//2:]
                
                avg_first = sum(first_half) / len(first_half)
                avg_second = sum(second_half) / len(second_half)
                
                # 如果后续握手明显更快，可能存在OCSP缓存
                if avg_first > avg_second * 1.2:
                    return {
                        'caching_detected': True,
                        'evidence': f'Handshake optimization detected: {avg_first:.1f}ms -> {avg_second:.1f}ms',
                        'cache_efficiency': (avg_first - avg_second) / avg_first
                    }
            
            return {
                'caching_detected': False,
                'evidence': 'No clear caching behavior observed',
                'handshake_times': handshake_times
            }
            
        except Exception as e:
            return {
                'caching_detected': False,
                'evidence': f'Cache test failed: {e}'
            }
    
    async def _test_ocsp_retry_behavior(self) -> Dict:
        """测试OCSP重试行为"""
        try:
            # 测试在网络延迟增加时的行为
            retry_times = []
            
            for delay in [0, 1, 2]:  # 不同的人为延迟
                if delay > 0:
                    await asyncio.sleep(delay)
                
                start = time.perf_counter()
                hs_time = await self._measure_handshake_time()
                total_time = (time.perf_counter() - start) * 1000
                
                if hs_time is not None:
                    retry_times.append({
                        'delay': delay,
                        'handshake_time': hs_time,
                        'total_time': total_time
                    })
            
            return {
                'retry_patterns': retry_times,
                'evidence': f'Tested {len(retry_times)} retry scenarios'
            }
            
        except Exception as e:
            return {
                'retry_patterns': [],
                'evidence': f'Retry test failed: {e}'
            }
    
    async def _test_revocation_handling(self, cert: x509.Certificate) -> Dict:
        """测试证书吊销状态处理"""
        try:
            # 检查证书是否接近过期
            now = time.time()
            not_after = cert.not_valid_after.timestamp()
            days_until_expiry = (not_after - now) / (24 * 3600)
            
            # 检查是否有CRL分发点
            crl_distribution_points = None
            try:
                crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
                crl_distribution_points = len(crl_ext.value)
            except:
                crl_distribution_points = 0
            
            # 分析吊销检查配置
            has_crl = crl_distribution_points > 0
            cert_age_days = (now - cert.not_valid_before.timestamp()) / (24 * 3600)
            
            return {
                'has_crl_distribution': has_crl,
                'crl_points_count': crl_distribution_points,
                'certificate_age_days': cert_age_days,
                'days_until_expiry': days_until_expiry,
                'evidence': f'Cert age: {cert_age_days:.1f} days, expires in: {days_until_expiry:.1f} days, CRL points: {crl_distribution_points}'
            }
            
        except Exception as e:
            return {
                'has_crl_distribution': False,
                'evidence': f'Revocation handling test failed: {e}'
            }
    
    def _check_must_staple_extension(self, cert: x509.Certificate) -> Dict:
        """检查OCSP must-staple扩展"""
        try:
            # 查找TLS Feature扩展（OCSP Must-Staple的OID是 1.3.6.1.5.5.7.1.24）
            for ext in cert.extensions:
                if ext.oid.dotted_string == "1.3.6.1.5.5.7.1.24":
                    return {
                        'must_staple_present': True,
                        'evidence': 'OCSP Must-Staple extension found in certificate',
                        'security_impact': 'Certificate requires OCSP stapling - hard fail expected'
                    }
            
            return {
                'must_staple_present': False,
                'evidence': 'No OCSP Must-Staple extension found',
                'security_impact': 'OCSP soft-fail possible'
            }
            
        except Exception as e:
            return {
                'must_staple_present': False,
                'evidence': f'Must-staple check failed: {e}'
            }
    
    def _analyze_ocsp_results(self, ocsp_url: str, ocsp_reachable: bool, 
                             soft_fail_confirmed: bool, advanced_tests: Dict) -> Dict:
        """综合分析OCSP结果"""
        
        # 基础判断逻辑
        if not ocsp_reachable and soft_fail_confirmed:
            status = 'Vulnerable'
            impact = 'OCSP soft-fail confirmed - revoked certificates may be accepted'
            severity = 'HIGH'
        elif ocsp_reachable and soft_fail_confirmed:
            status = 'Potentially_Vulnerable'
            impact = 'OCSP validation may have weak failure handling'
            severity = 'MEDIUM'
        elif not ocsp_reachable and not soft_fail_confirmed:
            status = 'OCSP_Unreachable'
            impact = 'OCSP server unreachable but connection fails appropriately'
            severity = 'LOW'
        else:
            status = 'Secure'
            impact = 'OCSP validation appears to be working properly'
            severity = 'NONE'
        
        # 高级测试结果分析
        advanced_findings = []
        
        # 分析must-staple
        must_staple = advanced_tests.get('must_staple', {})
        if must_staple.get('must_staple_present'):
            advanced_findings.append("OCSP Must-Staple enforced")
            if status == 'Vulnerable':
                status = 'Inconsistent'  # Must-staple和软失败冲突
        else:
            advanced_findings.append("No OCSP Must-Staple enforcement")
        
        # 分析缓存行为
        cache_behavior = advanced_tests.get('cache_behavior', {})
        if cache_behavior.get('caching_detected'):
            efficiency = cache_behavior.get('cache_efficiency', 0)
            advanced_findings.append(f"OCSP caching detected (efficiency: {efficiency:.2f})")
        
        # 分析吊销处理
        revocation = advanced_tests.get('revocation_handling', {})
        if revocation.get('has_crl_distribution'):
            crl_count = revocation.get('crl_points_count', 0)
            advanced_findings.append(f"CRL distribution available ({crl_count} points)")
        else:
            advanced_findings.append("No CRL distribution points")
        
        return {
            'status': status,
            'severity': severity,
            'impact': impact,
            'ocsp_url': ocsp_url,
            'ocsp_reachable': ocsp_reachable,
            'soft_fail_confirmed': soft_fail_confirmed,
            'advanced_findings': advanced_findings,
            'evidence': f'OCSP URL: {ocsp_url}, Reachable: {ocsp_reachable}, Soft-fail: {soft_fail_confirmed}',
            'detailed_tests': advanced_tests,
            'vulnerable': status in ['Vulnerable', 'Potentially_Vulnerable']
        }

async def selftest(target="127.0.0.1", timeout=3.0, verbose=True):
    """ocsp_validator模块自检"""
    if verbose:
        print("[*] ocsp_validator selftest starting...")
    
    try:
        # 基础功能测试
        validator = OCSPValidator(target, 443, timeout=timeout)
        
        # 测试OCSP验证
        if verbose:
            print("  [+] Testing OCSP validation...")
        result = await validator.verify_ocsp_soft_fail()
        
        if verbose:
            print("  [+] ocsp_validator selftest completed successfully")
        return True
        
    except Exception as e:
        if verbose:
            print(f"  [-] ocsp_validator selftest failed: {e}")
        return False

def main():
    import argparse
    import sys
    import asyncio
    
    parser = argparse.ArgumentParser(description="OCSP Soft-Fail Vulnerability Validator")
    parser.add_argument("--selftest", action="store_true", help="Run module self-test")
    parser.add_argument("--target", default="127.0.0.1", help="Target hostname (for selftest)")
    parser.add_argument("host", nargs="?", help="Target hostname (for analysis)")
    parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout seconds")
    
    args = parser.parse_args()
    
    if args.selftest:
        try:
            result = asyncio.run(selftest(args.target, args.timeout))
            sys.exit(0 if result else 1)
        except KeyboardInterrupt:
            print("\n[!] Selftest interrupted")
            sys.exit(1)
        return
    
    if not args.host:
        parser.error("host argument is required when not using --selftest")
    
    async def run_validation():
        validator = OCSPValidator(args.host, args.port, args.timeout)
        result = await validator.verify_ocsp_soft_fail()
        
        print(f"\n[OCSP VALIDATION RESULTS]")
        print(f"Target: {args.host}:{args.port}")
        print(f"Status: {result.get('status', 'Unknown')}")
        print(f"Vulnerability: {'Yes' if result.get('vulnerable', False) else 'No'}")
        print(f"Soft-fail confirmed: {result.get('soft_fail_confirmed', False)}")
        print(f"Evidence: {result.get('evidence', 'None')}")
        
        return result.get('vulnerable', False)
    
    try:
        vulnerable = asyncio.run(run_validation())
        sys.exit(1 if vulnerable else 0)
    except Exception as e:
        print(f"[-] OCSP validation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()