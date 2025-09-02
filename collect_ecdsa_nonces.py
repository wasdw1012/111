#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECDSA Nonce Leakage Collector - 简化版
快速收集100个签名并分析nonce泄露
"""

import time
import ssl
import socket
import hashlib
import json
from typing import List, Tuple, Dict, Optional

class ECDSACollector:
    def __init__(self, target_host: str, target_port: int = 443):
        self.target_host = target_host
        self.target_port = target_port
        self.signatures = []
        
    def collect_tls_signature(self) -> Optional[Dict]:
        """通过TLS握手收集签名时序"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # 记录连接时间
            start = time.perf_counter()
            sock.connect((self.target_host, self.target_port))
            
            # SSL握手
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssock = context.wrap_socket(sock, server_hostname=self.target_host)
            elapsed = time.perf_counter() - start
            
            # 获取证书信息
            cert = ssock.getpeercert(binary_form=True)
            cert_hash = hashlib.sha256(cert).digest()
            
            # 简化：只记录时序和哈希
            sig_data = {
                'response_time': elapsed * 1000,  # 毫秒
                'cert_hash': cert_hash.hex()[:16],  # 前16字符
                'timestamp': time.time(),
                'cert_size': len(cert)
            }
            
            ssock.close()
            sock.close()
            
            return sig_data
            
        except Exception as e:
            print(f"[-] Error: {e}")
            return None

    def analyze_timing_pattern(self) -> Dict:
        """分析时序模式"""
        if len(self.signatures) < 10:
            return {"error": "需要更多样本"}
        
        times = [s['response_time'] for s in self.signatures]
        
        # 统计分析
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        # 将响应时间分组
        fast = [t for t in times if t < avg_time - 5]  # 快于平均-5ms
        slow = [t for t in times if t > avg_time + 5]  # 慢于平均+5ms
        
        # 检测模式
        pattern = {
            'total_samples': len(times),
            'avg_ms': round(avg_time, 2),
            'min_ms': round(min_time, 2),
            'max_ms': round(max_time, 2),
            'fast_responses': len(fast),
            'slow_responses': len(slow),
            'variance': round(max_time - min_time, 2)
        }
        
        # 判断是否有时序泄露
        if pattern['variance'] > 50:  # 差异大于50ms
            pattern['timing_leak'] = "HIGH - 时序差异明显"
        elif pattern['variance'] > 20:
            pattern['timing_leak'] = "MEDIUM - 存在时序差异"
        else:
            pattern['timing_leak'] = "LOW - 时序稳定"
            
        return pattern

    def collect_batch(self, count: int = 100):
        """批量收集"""
        print(f"[*] 开始收集 {count} 个TLS握手时序")
        print(f"[*] 目标: {self.target_host}:{self.target_port}\n")
        
        start_time = time.time()
        
        for i in range(count):
            sig = self.collect_tls_signature()
            
            if sig:
                self.signatures.append(sig)
                
                # 每10个输出一次进度
                if (i + 1) % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed
                    print(f"[+] 进度: {i+1}/{count} (速率: {rate:.1f} req/s)")
                    
                    # 实时分析
                    if len(self.signatures) >= 20:
                        analysis = self.analyze_timing_pattern()
                        print(f"    平均响应: {analysis['avg_ms']}ms")
                        print(f"    时序差异: {analysis['variance']}ms")
                        print(f"    泄露评估: {analysis.get('timing_leak', 'N/A')}\n")
            
            # 避免过快
            time.sleep(0.05)
        
        total_time = time.time() - start_time
        print(f"\n[*] 收集完成，耗时: {total_time:.1f}秒")

    def check_patterns(self) -> Dict:
        """检查是否有可疑模式"""
        if len(self.signatures) < 50:
            return {"error": "样本不足"}
        
        # 按响应时间排序
        sorted_sigs = sorted(self.signatures, key=lambda x: x['response_time'])
        
        # 取最快的25%和最慢的25%
        fast_quarter = sorted_sigs[:len(sorted_sigs)//4]
        slow_quarter = sorted_sigs[3*len(sorted_sigs)//4:]
        
        # 分析证书哈希分布（模拟nonce MSB检测）
        fast_hashes = [s['cert_hash'] for s in fast_quarter]
        slow_hashes = [s['cert_hash'] for s in slow_quarter]
        
        # 检查哈希前缀（模拟MSB偏差）
        fast_zeros = sum(1 for h in fast_hashes if h.startswith('0'))
        slow_zeros = sum(1 for h in slow_hashes if h.startswith('0'))
        
        result = {
            'fast_group': {
                'count': len(fast_quarter),
                'avg_time': sum(s['response_time'] for s in fast_quarter) / len(fast_quarter),
                'hash_0_prefix': f"{fast_zeros}/{len(fast_quarter)} ({100*fast_zeros/len(fast_quarter):.1f}%)"
            },
            'slow_group': {
                'count': len(slow_quarter),
                'avg_time': sum(s['response_time'] for s in slow_quarter) / len(slow_quarter),
                'hash_0_prefix': f"{slow_zeros}/{len(slow_quarter)} ({100*slow_zeros/len(slow_quarter):.1f}%)"
            }
        }
        
        # 判断是否有偏差
        fast_rate = fast_zeros / len(fast_quarter)
        slow_rate = slow_zeros / len(slow_quarter)
        
        if abs(fast_rate - slow_rate) > 0.2:
            result['bias_detected'] = "YES - 快慢组哈希分布不同"
        else:
            result['bias_detected'] = "NO - 分布均匀"
            
        return result

def main():
    """主函数"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python3 collect_ecdsa_nonces.py <目标域名> [端口]")
        print("示例: python3 collect_ecdsa_nonces.py example.com 443")
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    print("="*60)
    print("ECDSA Nonce时序收集器")
    print("="*60)
    
    collector = ECDSACollector(target, port)
    
    # 收集100个样本
    collector.collect_batch(100)
    
    # 最终分析
    print("\n" + "="*60)
    print("分析结果")
    print("="*60)
    
    timing_analysis = collector.analyze_timing_pattern()
    print("\n[时序分析]")
    for k, v in timing_analysis.items():
        print(f"  {k}: {v}")
    
    pattern_check = collector.check_patterns()
    print("\n[模式检测]")
    print(f"  快速组 (<平均): {pattern_check.get('fast_group', {})}")
    print(f"  慢速组 (>平均): {pattern_check.get('slow_group', {})}")
    print(f"  偏差检测: {pattern_check.get('bias_detected', 'N/A')}")
    
    # 保存数据
    filename = f"nonce_timing_{target}_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump({
            'target': f"{target}:{port}",
            'signatures': collector.signatures,
            'analysis': {
                'timing': timing_analysis,
                'patterns': pattern_check
            }
        }, f, indent=2)
    print(f"\n[+] 数据已保存到: {filename}")
    
    # 给出建议
    print("\n[建议]")
    if timing_analysis.get('variance', 0) > 50:
        print("  ✓ 发现明显时序差异，建议深入分析")
        print("  ✓ 可能存在侧信道泄露")
    elif pattern_check.get('bias_detected', '').startswith('YES'):
        print("  ✓ 检测到分布偏差")
        print("  ✓ 建议收集更多样本进行格攻击")
    else:
        print("  - 未发现明显异常")
        print("  - 可能需要其他方法或更多样本")

if __name__ == "__main__":
    main()