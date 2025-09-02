import asyncio
import os
import socket
import struct
from typing import Any, Dict, List, Optional

from .types import AlgorithmBackend, KemKeypair, EncapsResult


class TLSPSKBackend(AlgorithmBackend):
    """Backend that leverages TLS13PSKCrossBind and real TLS exporter for tests.

    Configuration sources:
    - Environment variables (highest priority):
      SCANCORE_TARGET_HOST, SCANCORE_TARGET_PORT, SCANCORE_SNI_LIST (comma-separated)
    - Constructor parameters (fallback): host, port, sni_list
    """

    def __init__(self, host: Optional[str] = None, port: int = 443, sni_list: Optional[List[str]] = None, timeout: float = 15.0) -> None:
        self._host = os.getenv("SCANCORE_TARGET_HOST", host or "").strip()
        port_env = os.getenv("SCANCORE_TARGET_PORT")
        if port_env:
            try:
                port = int(port_env)
            except ValueError:
                pass
        self._port = port
        sni_env = os.getenv("SCANCORE_SNI_LIST")
        if sni_env:
            sni_list = [s.strip() for s in sni_env.split(",") if s.strip()]
        self._snis = sni_list or ([self._host] if self._host else [])
        self._timeout = timeout

        # Lazy assessment cache
        self._assessment: Optional[Dict[str, Any]] = None

        if not self._host:
            raise SystemExit("TLSPSKBackend requires target host. Set --host or SCANCORE_TARGET_HOST.")

    # ---- AlgorithmBackend protocol minimal stubs (not used for TLS backend) ----
    def name(self) -> str:
        return f"TLS-PSK({self._host}:{self._port})"

    def supports_deterministic_encaps(self) -> bool:
        return False

    def keygen(self) -> KemKeypair:  # pragma: no cover - not applicable
        raise NotImplementedError("KEM operations are not supported by TLSPSKBackend")

    def encaps(self, public_key: bytes, coins: Optional[bytes] = None) -> EncapsResult:  # pragma: no cover
        raise NotImplementedError("KEM operations are not supported by TLSPSKBackend")

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:  # pragma: no cover
        raise NotImplementedError("KEM operations are not supported by TLSPSKBackend")

    # ---- Real handshake test hooks consumed by variants.py ----
    def _ensure_assessment(self) -> Dict[str, Any]:
        if self._assessment is not None:
            return self._assessment
        # Deferred import to avoid heavy deps at import time
        from ..tls13_psk_crossbind import TLS13PSKCrossBind  # type: ignore

        async def _run():
            attacker = TLS13PSKCrossBind(self._host, self._port, timeout=self._timeout)
            snis = self._snis or [self._host]
            return await attacker.run_comprehensive_assessment(snis)

        # Ensure a loop exists (Windows compatibility handled by orchestrator elsewhere)
        try:
            self._assessment = asyncio.run(_run())
        except RuntimeError:
            # In case we're already inside an event loop (unlikely here), create nested loop
            self._assessment = asyncio.get_event_loop().run_until_complete(_run())  # type: ignore
        return self._assessment

    # Negotiation / downgrade
    def negotiate_suites(self, suites: List[str], prefer: str = "X25519") -> Dict[str, Any]:
        res = self._ensure_assessment()
        adv = (res.get("attacks") or {}).get("advanced_attacks") or {}
        # Our TLS tool specifically tests PSK mode downgrade
        by_sni = (adv.get("downgrade_tests") or adv.get("results") or {}).get("downgrade_tests", {})
        downgraded = False
        evidence: List[str] = []
        for sni, d in by_sni.items():
            if isinstance(d, dict) and d.get("downgrade_successful"):
                downgraded = True
                ev = d.get("evidence") or d.get("reason") or d.get("error")
                if ev:
                    evidence.append(f"{sni}: {ev}")
        return {
            "bound": not downgraded,
            "final": "ML-KEM+PSK" if not downgraded else prefer,
            "downgraded": downgraded,
            "evidence": evidence,
        }

    # HelloRetry detection using crafted ClientHello without key_share
    def hello_retry(self, change_params: bool = True) -> Dict[str, Any]:
        from ..tls13_psk_crossbind import TLS13MessageBuilder, TLSRecord, TLSContentType, TLSVersion, TLSHandshakeType  # type: ignore

        # Build ClientHello without KEY_SHARE to try inducing HRR
        try:
            # Minimal ClientHello: legacy_version, random, empty session, one cipher, no compression, only SNI+versions
            import secrets
            client_hello = struct.pack('>H', TLSVersion.TLS_1_2)
            client_hello += secrets.token_bytes(32)
            client_hello += struct.pack('>B', 0)  # empty session id
            # one cipher suite
            client_hello += struct.pack('>HH', 2, 0x1301)
            client_hello += struct.pack('>BB', 1, 0)
            # extensions: SNI + supported_versions
            sni_data = TLS13MessageBuilder._build_sni_extension(self._snis[0] if self._snis else self._host)
            exts = struct.pack('>HH', 0, len(sni_data)) + sni_data  # type 0 = SNI
            versions = struct.pack('>BH', 2, TLSVersion.TLS_1_3)
            exts += struct.pack('>HH', 43, len(versions)) + versions  # supported_versions
            client_hello += struct.pack('>H', len(exts)) + exts
            hs = struct.pack('>BI', TLSHandshakeType.CLIENT_HELLO, len(client_hello)) + client_hello
            record = TLSRecord(TLSContentType.HANDSHAKE, TLSVersion.TLS_1_2, len(hs), hs)

            # Send and receive
            response = self._send_raw_tls(bytes(record))
            # Parse first handshake type if any
            hrr = False
            if response and len(response) >= 6 and response[0] == TLSContentType.HANDSHAKE:
                # skip record header (5), handshake byte at 5
                hrr = response[5] == TLSHandshakeType.HELLO_RETRY_REQUEST
            return {"binder_changed": hrr, "old_path_valid": not hrr, "hrr": hrr}
        except Exception as e:
            return {"binder_changed": False, "old_path_valid": False, "error": str(e)}

    def _send_raw_tls(self, data: bytes) -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((self._host, self._port))
            s.sendall(data)
            return s.recv(8192)
        finally:
            try:
                s.close()
            except Exception:
                pass

    # Auth/binding tests from cross-SNI evidence
    def auth_bindings(self, miscover: bool = True) -> Dict[str, Any]:
        res = self._ensure_assessment()
        cross = (res.get("attacks") or {}).get("cross_sni_binding") or {}
        vulns = cross.get("vulnerabilities", [])
        rejected = len(vulns) == 0
        return {"rejected": rejected, "vulns": vulns}

    def exporter_test(self, misbind: bool = True) -> Dict[str, Any]:
        # Use real TLS exporter across two SNIs to check binding
        if len(self._snis) < 2:
            return {"changed": False, "supported": False, "reason": "need >=2 SNI"}
        from .tls_exporter import compare_exporter_across_sni
        label = "EXPORTER-Context-Binding-Test"
        try:
            changed = compare_exporter_across_sni(self._host, self._port, self._snis[0], self._snis[1], label)
            return {"changed": changed, "supported": True, "sni": [self._snis[0], self._snis[1]]}
        except Exception as e:
            return {"changed": False, "supported": False, "error": str(e)}

    # 0-RTT / tickets / PSK binding
    def zero_rtt(self, replay: bool = True) -> Dict[str, Any]:
        res = self._ensure_assessment()
        zr = (res.get("attacks") or {}).get("zero_rtt_attacks") or {}
        vulns = zr.get("vulnerabilities") or []
        replay_rejected = len(vulns) == 0
        return {"replay_rejected": replay_rejected, "details": zr}

    def ticket_reuse(self, cross_client: bool = True) -> Dict[str, Any]:
        res = self._ensure_assessment()
        rep = (res.get("attacks") or {}).get("replay_attacks") or {}
        vulns = rep.get("vulnerabilities") or []
        rejected = len(vulns) == 0
        return {"rejected": rejected, "details": rep}

    def psk_mismatch(self) -> Dict[str, Any]:
        res = self._ensure_assessment()
        cross = (res.get("attacks") or {}).get("cross_sni_binding") or {}
        vulns = cross.get("vulnerabilities") or []
        binder_invalid = len(vulns) > 0
        return {"binder_invalid": binder_invalid, "details": cross}

    # Rekey/rollover and message choreography not implemented by current tools
    def rekey_test(self, reuse_nonce: bool = False) -> Dict[str, Any]:
        from .tls_raw_orchestrator import invalid_appdata_probe
        sni = self._snis[0] if self._snis else self._host
        try:
            res = invalid_appdata_probe(self._host, self._port, sni, self._timeout)
            return {"aead_detected": bool(res.get("aead_detected")), "details": res, "supported": True}
        except Exception as e:
            return {"aead_detected": False, "supported": True, "error": str(e)}

    def key_rollover(self, one_side_only: bool = True) -> Dict[str, Any]:
        from .tls_raw_orchestrator import keyupdate_plaintext_probe
        sni = self._snis[0] if self._snis else self._host
        try:
            res = keyupdate_plaintext_probe(self._host, self._port, sni, self._timeout)
            return {"explicit_fail": bool(res.get("explicit_fail")), "details": res, "supported": True}
        except Exception as e:
            return {"explicit_fail": True, "supported": True, "error": str(e)}

    def message_sequence_test(self, mode: str = "duplicate_drop_reorder") -> Dict[str, Any]:
        from .tls_raw_orchestrator import duplicate_client_hello, reorder_client_hello
        sni = self._snis[0] if self._snis else self._host
        try:
            if mode == "duplicate_drop_reorder":
                dup = duplicate_client_hello(self._host, self._port, sni, self._timeout)
                reo = reorder_client_hello(self._host, self._port, sni, self._timeout)
                detected = bool(dup.get("detected") and reo.get("detected"))
                return {"detected": detected, "details": {"duplicate": dup, "reorder": reo}, "supported": True}
            else:
                return {"detected": False, "supported": True, "details": {"mode": mode}}
        except Exception as e:
            return {"detected": False, "supported": True, "error": str(e)}

    def splice_test(self) -> Dict[str, Any]:
        from .tls_raw_orchestrator import splice_across_connections
        sni = self._snis[0] if self._snis else self._host
        try:
            res = splice_across_connections(self._host, self._port, sni, self._timeout)
            return {"rejected": bool(res.get("rejected")), "details": res, "supported": True}
        except Exception as e:
            return {"rejected": True, "supported": True, "error": str(e)}

    def hybrid_mismatch(self) -> Dict[str, Any]:
        return {"keys_diverged": True, "supported": False}

    def identity_hiding(self, order: str = "kem_then_auth") -> Dict[str, Any]:
        return {"policy_consistent": True, "supported": False}

    def encoding_test(self, anomaly: str = "leading_zero") -> Dict[str, Any]:
        from .tls_raw_orchestrator import malformed_client_hello
        sni = self._snis[0] if self._snis else self._host
        try:
            res = malformed_client_hello(self._host, self._port, sni, self._timeout)
            return {"detected": bool(res.get("detected")), "details": res, "supported": True}
        except Exception as e:
            return {"detected": False, "supported": True, "error": str(e)}

    def context_label_test(self) -> Dict[str, Any]:
        # Use exporter with different labels to ensure separation
        from .tls_exporter import label_collision_check
        sni = self._snis[0] if self._snis else None
        try:
            ok = label_collision_check(self._host, self._port, sni, "EXPORTER-A", "EXPORTER-B")
            return {"exporter_changed": ok, "supported": True}
        except Exception as e:
            return {"exporter_changed": False, "supported": False, "error": str(e)}
