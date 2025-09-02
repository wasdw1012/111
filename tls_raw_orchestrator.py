import socket
import struct
import secrets
from typing import Optional, Tuple, Dict, Any

# Reuse enums and builders from TLS13PSKCrossBind
from ..tls13_psk_crossbind import (
    TLS13MessageBuilder,
    TLSRecord,
    TLSContentType,
    TLSVersion,
    TLSHandshakeType,
)


def _send(host: str, port: int, data: bytes, timeout: float = 10.0) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(data)
        try:
            return s.recv(8192)
        except socket.timeout:
            return b""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _build_client_hello(sni: str, include_key_share: bool = True) -> bytes:
    # Build CH similar to TLS13MessageBuilder.build_client_hello but optionally omit key_share
    # legacy version
    ch = struct.pack('>H', TLSVersion.TLS_1_2)
    ch += secrets.token_bytes(32)  # random
    ch += struct.pack('>B', 0)  # empty session id
    # cipher suites (one)
    ch += struct.pack('>HH', 2, 0x1301)
    # compression
    ch += struct.pack('>BB', 1, 0)

    # extensions
    exts = b''
    sni_data = TLS13MessageBuilder._build_sni_extension(sni)
    exts += struct.pack('>HH', 0, len(sni_data)) + sni_data
    versions = struct.pack('>BH', 2, TLSVersion.TLS_1_3)
    exts += struct.pack('>HH', 43, len(versions)) + versions
    if include_key_share:
        ks = TLS13MessageBuilder._build_key_share_extension()
        exts += struct.pack('>HH', 51, len(ks)) + ks

    ch += struct.pack('>H', len(exts)) + exts
    hs = struct.pack('>BI', TLSHandshakeType.CLIENT_HELLO, len(ch)) + ch
    rec = TLSRecord(TLSContentType.HANDSHAKE, TLSVersion.TLS_1_2, len(hs), hs)
    return bytes(rec)


def duplicate_client_hello(host: str, port: int, sni: str, timeout: float = 10.0) -> Dict[str, Any]:
    ch = _build_client_hello(sni)
    # Send two ClientHello back-to-back without waiting
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(ch + ch)
        try:
            resp = s.recv(8192)
        except socket.timeout:
            resp = b''
        detected = bool(resp) and resp[0] == TLSContentType.ALERT
        return {"detected": detected, "response_len": len(resp), "alert": resp[:20].hex() if resp else ""}
    finally:
        try:
            s.close()
        except Exception:
            pass


def reorder_client_hello(host: str, port: int, sni: str, timeout: float = 10.0) -> Dict[str, Any]:
    # Send a CH missing key_share to provoke HRR, then immediately send another normal CH
    ch_no_ks = _build_client_hello(sni, include_key_share=False)
    ch = _build_client_hello(sni, include_key_share=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(ch_no_ks + ch)
        try:
            resp = s.recv(8192)
        except socket.timeout:
            resp = b''
        # If server accepts HRR path, it may respond with HRR (handshake type 6), otherwise alert
        hrr = bool(resp) and resp[0] == TLSContentType.HANDSHAKE and len(resp) >= 6 and resp[5] == TLSHandshakeType.HELLO_RETRY_REQUEST
        alert = bool(resp) and resp[0] == TLSContentType.ALERT
        return {"detected": alert or hrr, "hrr": hrr, "alert": alert, "response_len": len(resp)}
    finally:
        try:
            s.close()
        except Exception:
            pass


def splice_across_connections(host: str, port: int, sni: str, timeout: float = 10.0) -> Dict[str, Any]:
    # Connection A: send CH, read some bytes from server
    ch = _build_client_hello(sni)
    a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.settimeout(timeout)
    try:
        a.connect((host, port))
        a.sendall(ch)
        try:
            resp_a = a.recv(8192)
        except socket.timeout:
            resp_a = b''
    finally:
        try:
            a.close()
        except Exception:
            pass

    # Connection B: send CH, then inject bytes captured from A (nonsense for server)
    b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    b.settimeout(timeout)
    try:
        b.connect((host, port))
        b.sendall(ch + resp_a)
        try:
            resp_b = b.recv(8192)
        except socket.timeout:
            resp_b = b''
        alert = bool(resp_b) and resp_b[0] == TLSContentType.ALERT
        return {"rejected": alert or len(resp_b) == 0, "response_len": len(resp_b), "alert": alert}
    finally:
        try:
            b.close()
        except Exception:
            pass


def malformed_client_hello(host: str, port: int, sni: str, timeout: float = 10.0) -> Dict[str, Any]:
    # Build a CH then corrupt the handshake length field (set too small)
    ch = _build_client_hello(sni)
    # TLS record header is 5 bytes; handshake header 4 bytes (type + 3-byte len in TLS13? Here we used 1+4)
    # Our TLS builder uses 1 byte type + 4 byte length (BI pack) = 5 bytes after record header
    # Corrupt the 4-byte length to be len-10
    if len(ch) < 10:
        return {"detected": False, "error": "short_client_hello"}
    malformed = bytearray(ch)
    # Record header at 0..4, handshake header starts at 5; length at 6..9 (big-endian 32-bit from struct '>BI')
    hs_len = struct.unpack('>I', bytes(malformed[6:10]))[0]
    new_len = max(0, hs_len - 10)
    malformed[6:10] = struct.pack('>I', new_len)

    resp = _send(host, port, bytes(malformed), timeout)
    alert = bool(resp) and resp[0] == TLSContentType.ALERT
    return {"detected": alert or len(resp) == 0, "response_len": len(resp), "alert": alert}


def keyupdate_plaintext_probe(host: str, port: int, sni: str, timeout: float = 10.0) -> Dict[str, Any]:
    # Send a plaintext KeyUpdate record (should be rejected if handshake progressed)
    ch = _build_client_hello(sni)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(ch)
        try:
            _ = s.recv(4096)  # likely ServerHello/alert
        except socket.timeout:
            pass
        # Build plaintext KeyUpdate handshake record (unencrypted -> invalid)
        ku_hs = struct.pack('>BI', TLSHandshakeType.KEY_UPDATE, 1) + b'\x01'  # update_requested
        rec = TLSRecord(TLSContentType.HANDSHAKE, TLSVersion.TLS_1_2, len(ku_hs), ku_hs)
        s.sendall(bytes(rec))
        try:
            resp = s.recv(8192)
        except socket.timeout:
            resp = b''
        alert = bool(resp) and resp[0] == TLSContentType.ALERT
        return {"explicit_fail": alert or len(resp) == 0, "response_len": len(resp), "alert": alert}
    finally:
        try:
            s.close()
        except Exception:
            pass


def invalid_appdata_probe(host: str, port: int, sni: str, timeout: float = 10.0) -> Dict[str, Any]:
    # Send a bogus ApplicationData record (unencrypted); server should fail fast.
    ch = _build_client_hello(sni)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(ch)
        try:
            _ = s.recv(4096)
        except socket.timeout:
            pass
        # Application Data record carrying plaintext (invalid under TLS1.3)
        payload = b'\x00' * 32
        rec = TLSRecord(TLSContentType.APPLICATION_DATA, TLSVersion.TLS_1_2, len(payload), payload)
        s.sendall(bytes(rec))
        try:
            resp = s.recv(8192)
        except socket.timeout:
            resp = b''
        alert = bool(resp) and resp[0] == TLSContentType.ALERT
        return {"aead_detected": alert or len(resp) == 0, "response_len": len(resp), "alert": alert}
    finally:
        try:
            s.close()
        except Exception:
            pass
