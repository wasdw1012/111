import inspect
import os
import sys
from typing import Optional, Tuple, Dict

from .types import AlgorithmBackend, KemKeypair, EncapsResult
from .events import hit


def _maybe_add_repo_path_from_env() -> None:
    repo_path = os.getenv("SCANCORE_PY_ACVP_PQC_PATH")
    if repo_path and os.path.isdir(repo_path) and repo_path not in sys.path:
        sys.path.insert(0, repo_path)


class _LazyFIPS203:
    def __init__(self) -> None:
        _maybe_add_repo_path_from_env()
        self._mod = None
        self._funcs: Optional[Tuple[str, str, str]] = None

    def _load(self):
        if self._mod is not None:
            return
        try:
            import fips203  # type: ignore

            self._mod = fips203
        except Exception as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "fips203 module not found. Set SCANCORE_PY_ACVP_PQC_PATH or add repo to sys.path"
            ) from exc

    def _resolve_funcs(self) -> Tuple[str, str, str]:
        if self._funcs is not None:
            return self._funcs
        self._load()
        assert self._mod is not None
        candidates = [
            ("keygen", "encaps", "decaps"),
            ("ml_kem_keygen", "ml_kem_encaps", "ml_kem_decaps"),
            ("KeyGen", "Encaps", "Decaps"),
        ]
        for kg, en, de in candidates:
            if all(hasattr(self._mod, n) for n in (kg, en, de)):
                self._funcs = (kg, en, de)
                return self._funcs
        raise AttributeError("Could not find keygen/encaps/decaps in fips203 module")

    @property
    def mod(self):
        self._load()
        return self._mod

    def funcs(self) -> Tuple[str, str, str]:
        return self._resolve_funcs()


class MLKEMPythonBackend(AlgorithmBackend):
    """Adapter over py-acvp-pqc fips203.py functions.

    This backend supports deterministic encaps if the underlying function
    exposes a 'coins' (or similar) parameter.
    """

    def __init__(self) -> None:
        self._fips = _LazyFIPS203()
        kg_name, en_name, de_name = self._fips.funcs()
        mod = self._fips.mod
        self._kg = getattr(mod, kg_name)
        self._en = getattr(mod, en_name)
        self._de = getattr(mod, de_name)

        # Detect whether encaps supports caller-supplied randomness
        try:
            sig = inspect.signature(self._en)
            self._encaps_accepts_coins = any(
                p.name in {"coins", "seed", "random_bytes"}
                for p in sig.parameters.values()
            )
        except (TypeError, ValueError):  # builtins or C-accelerated
            self._encaps_accepts_coins = False

        # Known ciphertext to secret mapping for rare-event probes
        self._known_ct_to_ss: Dict[bytes, bytes] = {}
        self._max_known = 128
        # Optional expectations set by higher-level variants for next decaps
        self._expected_ct_to_ss: Dict[bytes, Tuple[bytes, str]] = {}

    def name(self) -> str:
        return "MLKEM-Python(fips203)"

    def supports_deterministic_encaps(self) -> bool:
        return self._encaps_accepts_coins

    def keygen(self) -> KemKeypair:
        pk, sk = self._kg()
        if not isinstance(pk, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray)):
            # Some implementations return lists; make bytes
            pk = bytes(pk)
            sk = bytes(sk)
        return KemKeypair(public_key=bytes(pk), secret_key=bytes(sk))

    def encaps(self, public_key: bytes, coins: Optional[bytes] = None) -> EncapsResult:
        deterministic = coins is not None and self._encaps_accepts_coins
        if deterministic:
            res = self._en(public_key, coins=coins)
        else:
            res = self._en(public_key)
        ct, ss = res
        ct_b = bytes(ct)
        ss_b = bytes(ss)
        # Record mapping and emit events
        if deterministic:
            hit("kem.encaps.deterministic")
        hit("kem.encaps.generated")
        if len(self._known_ct_to_ss) >= self._max_known:
            # Remove an arbitrary item (FIFO not guaranteed). For simplicity, pop first key.
            try:
                first_key = next(iter(self._known_ct_to_ss.keys()))
                self._known_ct_to_ss.pop(first_key, None)
            except StopIteration:
                pass
        self._known_ct_to_ss[ct_b] = ss_b
        return EncapsResult(ciphertext=ct_b, shared_secret=ss_b)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        ct_b = bytes(ciphertext)
        is_known = ct_b in self._known_ct_to_ss
        if is_known:
            hit("kem.decaps.on_known_ct")
        else:
            hit("kem.decaps.on_unknown_ct")
        ss = self._de(secret_key, ct_b)
        ss_b = bytes(ss)
        # Compare with known mapping (if any)
        if is_known:
            expected = self._known_ct_to_ss.get(ct_b)
            if expected == ss_b:
                hit("kem.decaps.equal_known")
            else:
                hit("kem.decaps.diff_known")
        else:
            # If unknown ct produces a secret equal to any known secret, suspicious acceptance
            if ss_b in self._known_ct_to_ss.values():
                hit("kem.decaps.equal_on_unseen_ct")
        # Check explicit expectations from variants (e.g., mutated ct should NOT equal original ss)
        exp = self._expected_ct_to_ss.pop(ct_b, None)
        if exp is not None:
            expected_ss, tag = exp
            if ss_b == expected_ss:
                hit(f"kem.decaps.equal_expected.{tag}")
            else:
                hit(f"kem.decaps.diff_expected.{tag}")
        return ss_b

    # Optional hook for variants to register expectations for next decaps call on given ciphertext
    def expect_secret_for_ct(self, ciphertext: bytes, expected_ss: bytes, tag: str = "") -> None:
        self._expected_ct_to_ss[bytes(ciphertext)] = (bytes(expected_ss), tag)
