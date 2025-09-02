import socket
import ssl
from typing import Optional, Tuple


def _mk_ctx_tls13() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Prefer TLS 1.3; allow fallback if not supported
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        pass
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _connect(host: str, port: int, server_hostname: Optional[str]) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port), timeout=10)
    ctx = _mk_ctx_tls13()
    tls = ctx.wrap_socket(sock, server_hostname=server_hostname)
    return tls


def export_key_material(host: str, port: int, sni: Optional[str], label: str, length: int = 32, context: bytes = b"") -> Tuple[bytes, str]:
    """Perform a real TLS handshake then export keying material via RFC 5705/8446 exporter.

    Returns: (ekm_bytes, negotiated_alpn)
    """
    tls = _connect(host, port, sni or host)
    try:
        alpn = tls.selected_alpn_protocol() or ""
        # Python's ssl exposes exporter on SSLSocket in modern versions
        if hasattr(tls, "export_keying_material"):
            ekm: bytes = tls.export_keying_material(label=label, length=length, context=context)
            return ekm, alpn
        # If exporter not available, raise
        raise RuntimeError("export_keying_material not supported by this Python/OpenSSL build")
    finally:
        try:
            tls.close()
        except Exception:
            pass


def compare_exporter_across_sni(host: str, port: int, sni_a: str, sni_b: str, label: str, context: bytes = b"") -> bool:
    """Return True if exported key differs across different SNI handshakes (expected)."""
    ekm_a, _ = export_key_material(host, port, sni_a, label, 32, context)
    ekm_b, _ = export_key_material(host, port, sni_b, label, 32, context)
    return ekm_a != ekm_b


def label_collision_check(host: str, port: int, sni: Optional[str], label_a: str, label_b: str, context: bytes = b"") -> bool:
    """Return True if different labels produce different exporters (expected)."""
    ekm_a, _ = export_key_material(host, port, sni, label_a, 32, context)
    ekm_b, _ = export_key_material(host, port, sni, label_b, 32, context)
    return ekm_a != ekm_b
