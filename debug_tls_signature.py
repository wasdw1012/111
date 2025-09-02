#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS签名调试工具
诊断为什么无法提取签名
"""

import socket
import ssl
import struct
import binascii
import sys

def analyze_tls_connection(host: str, port: int = 443):
    """分析TLS连接，找出问题"""
    print(f"[*] 连接到 {host}:{port}")
    print("="*60)
    
    # 方法1：使用标准SSL库获取信息
    print("\n[1] 使用SSL库分析")
    print("-"*40)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssock = context.wrap_socket(sock, server_hostname=host)
        
        # 获取协商信息
        cipher = ssock.cipher()
        version = ssock.version()
        
        print(f"✓ TLS版本: {version}")
        print(f"✓ 密码套件: {cipher[0] if cipher else 'Unknown'}")
        print(f"✓ 密码强度: {cipher[2] if cipher and len(cipher) > 2 else 'Unknown'} bits")
        
        # 获取证书
        cert = ssock.getpeercert()
        cert_bin = ssock.getpeercert(binary_form=True)
        
        if cert:
            # 检查签名算法
            sig_alg = cert.get('signatureAlgorithm', 'Unknown')
            print(f"✓ 证书签名算法: {sig_alg}")
            
            # 检查公钥类型
            if 'subject' in cert:
                print(f"✓ 证书主题: {cert['subject']}")
        
        print(f"✓ 证书大小: {len(cert_bin)} bytes")
        
        # 检查是否是ECDSA
        if b'ecdsa' in str(cipher).lower().encode() or b'ecdsa' in cert_bin.lower():
            print("✓ 检测到ECDSA!")
        elif b'rsa' in str(cipher).lower().encode() or b'rsa' in cert_bin.lower():
            print("⚠ 检测到RSA (不是ECDSA)")
        
        ssock.close()
        sock.close()
        
    except Exception as e:
        print(f"✗ SSL分析失败: {e}")
    
    # 方法2：原始TLS握手分析
    print("\n[2] 原始TLS握手分析")
    print("-"*40)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # 构造ClientHello
        client_hello = build_client_hello(host)
        sock.send(client_hello)
        
        # 接收响应
        response = b''
        for _ in range(10):  # 最多读10次
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            
            # 检查是否收到足够的数据
            if b'\x0e\x00\x00\x00' in response:  # ServerHelloDone
                break
        
        sock.close()
        
        print(f"✓ 收到响应: {len(response)} bytes")
        
        # 分析响应
        analyze_server_response(response)
        
    except Exception as e:
        print(f"✗ 原始握手失败: {e}")
    
    # 方法3：使用openssl命令行（如果可用）
    print("\n[3] 密码套件枚举")
    print("-"*40)
    
    # 测试不同的密码套件
    test_ciphers = [
        ('ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDSA with P-256'),
        ('ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDSA with P-384'),
        ('ECDHE-RSA-AES128-GCM-SHA256', 'RSA'),
        ('ECDHE-RSA-AES256-GCM-SHA384', 'RSA'),
    ]
    
    for cipher_name, desc in test_ciphers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            try:
                context.set_ciphers(cipher_name)
                ssock = context.wrap_socket(sock, server_hostname=host)
                print(f"✓ 支持 {cipher_name} ({desc})")
                ssock.close()
            except:
                print(f"✗ 不支持 {cipher_name}")
            
            sock.close()
            
        except:
            pass

def build_client_hello(hostname: str) -> bytes:
    """构造ClientHello"""
    import os
    
    # TLS 1.2
    version = struct.pack('>H', 0x0303)
    
    # 客户端随机数
    client_random = os.urandom(32)
    
    # Session ID
    session_id = b'\x00'
    
    # 密码套件 - 包括ECDSA和RSA
    cipher_suites = struct.pack('>H', 8)  # 4个套件
    cipher_suites += struct.pack('>H', 0xc02b)  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    cipher_suites += struct.pack('>H', 0xc02c)  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    cipher_suites += struct.pack('>H', 0xc02f)  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    cipher_suites += struct.pack('>H', 0xc030)  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    
    # 压缩方法
    compression = b'\x01\x00'
    
    # 扩展
    extensions = b''
    
    # SNI
    hostname_bytes = hostname.encode('ascii')
    sni_content = struct.pack('>BH', 0x00, len(hostname_bytes)) + hostname_bytes
    sni_list = struct.pack('>H', len(sni_content)) + sni_content
    extensions += struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    
    # 支持的曲线
    curves = struct.pack('>H', 6)  # 3个曲线
    curves += struct.pack('>H', 0x0017)  # secp256r1
    curves += struct.pack('>H', 0x0018)  # secp384r1
    curves += struct.pack('>H', 0x0019)  # secp521r1
    extensions += struct.pack('>HH', 0x000a, len(curves)) + curves
    
    # EC点格式
    ec_points = b'\x01\x00'  # uncompressed
    extensions += struct.pack('>HHB', 0x000b, 1, 0) + b'\x00'
    
    # 签名算法
    sig_algs = struct.pack('>HHH', 0x000d, 8, 4)
    sig_algs += struct.pack('>H', 0x0403)  # ECDSA-SHA256
    sig_algs += struct.pack('>H', 0x0401)  # RSA-SHA256
    extensions += sig_algs
    
    extensions_length = struct.pack('>H', len(extensions))
    
    # 组装
    client_hello = version + client_random + session_id
    client_hello += cipher_suites + compression
    client_hello += extensions_length + extensions
    
    # Handshake头
    handshake = struct.pack('>B', 0x01)  # ClientHello
    handshake += struct.pack('>I', len(client_hello))[1:]
    handshake += client_hello
    
    # TLS记录
    record = struct.pack('>B', 0x16)  # Handshake
    record += struct.pack('>H', 0x0301)  # TLS 1.0
    record += struct.pack('>H', len(handshake))
    record += handshake
    
    return record

def analyze_server_response(data: bytes):
    """分析服务器响应"""
    offset = 0
    
    # 消息类型统计
    messages = {
        0x02: 'ServerHello',
        0x0b: 'Certificate',
        0x0c: 'ServerKeyExchange',
        0x0d: 'CertificateRequest',
        0x0e: 'ServerHelloDone'
    }
    
    found_messages = []
    has_ske = False
    cipher_suite = None
    
    while offset < len(data) - 5:
        # TLS记录头
        record_type = data[offset]
        
        if record_type != 0x16:  # 不是Handshake
            offset += 1
            continue
        
        # 跳过版本和长度
        record_len = struct.unpack('>H', data[offset+3:offset+5])[0]
        
        if offset + 5 + record_len > len(data):
            break
        
        # 解析握手消息
        hs_offset = offset + 5
        
        while hs_offset < offset + 5 + record_len:
            if hs_offset + 4 > len(data):
                break
            
            msg_type = data[hs_offset]
            msg_len = struct.unpack('>I', b'\x00' + data[hs_offset+1:hs_offset+4])[0]
            
            if msg_type in messages:
                found_messages.append(messages[msg_type])
                
                if msg_type == 0x0c:  # ServerKeyExchange
                    has_ske = True
                    print(f"✓ 发现ServerKeyExchange! 位置: {hs_offset}, 长度: {msg_len}")
                    
                    # 分析SKE内容
                    if hs_offset + 4 + msg_len <= len(data):
                        ske_data = data[hs_offset+4:hs_offset+4+msg_len]
                        print(f"  SKE前32字节: {binascii.hexlify(ske_data[:32]).decode()}")
                        
                        # 检查是否是ECDHE
                        if ske_data[0] == 0x03:  # Named curve
                            curve_id = struct.unpack('>H', ske_data[1:3])[0]
                            print(f"  ECDHE曲线ID: 0x{curve_id:04x}")
                            
                            # 检查签名
                            pubkey_len = ske_data[3]
                            sig_offset = 4 + pubkey_len
                            
                            if sig_offset + 2 <= len(ske_data):
                                sig_algo = struct.unpack('>H', ske_data[sig_offset:sig_offset+2])[0]
                                print(f"  签名算法: 0x{sig_algo:04x}")
                                
                                if sig_algo & 0xFF == 0x03:
                                    print("  ✓ ECDSA签名!")
                                elif sig_algo & 0xFF == 0x01:
                                    print("  ⚠ RSA签名")
                
                elif msg_type == 0x02:  # ServerHello
                    if hs_offset + 4 + 35 <= len(data):
                        # 获取密码套件
                        session_id_len = data[hs_offset + 4 + 34]
                        cs_offset = hs_offset + 4 + 35 + session_id_len
                        if cs_offset + 2 <= len(data):
                            cipher_suite = struct.unpack('>H', data[cs_offset:cs_offset+2])[0]
                            print(f"✓ 协商的密码套件: 0x{cipher_suite:04x}")
                            
                            # 解释密码套件
                            if cipher_suite == 0xc02b:
                                print("  = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
                            elif cipher_suite == 0xc02f:
                                print("  = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
                            elif cipher_suite in [0x009c, 0x009d]:
                                print("  = RSA with AES")
            
            hs_offset += 4 + msg_len
        
        offset += 5 + record_len
    
    print(f"\n发现的消息: {', '.join(found_messages)}")
    
    if not has_ske:
        print("\n⚠ 未发现ServerKeyExchange消息!")
        print("可能原因:")
        print("  1. 服务器使用RSA密钥交换（不是ECDHE）")
        print("  2. 服务器使用静态DH")
        print("  3. 响应不完整")

def main():
    """主函数"""
    if len(sys.argv) < 2:
        host = "125.212.254.149"
    else:
        host = sys.argv[1]
    
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    print("="*60)
    print("TLS签名提取诊断工具")
    print("="*60)
    
    analyze_tls_connection(host, port)
    
    print("\n" + "="*60)
    print("诊断建议")
    print("="*60)
    print("""
如果看到RSA而不是ECDSA：
  → 目标不使用ECDSA证书
  → 时序泄露可能与其他因素相关

如果没有ServerKeyExchange：
  → 可能使用RSA密钥交换
  → 需要其他方法获取签名

如果有ECDSA但提取失败：
  → 可能需要调整解析逻辑
  → 检查DER格式是否特殊
""")

if __name__ == "__main__":
    main()