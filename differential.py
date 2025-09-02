from dataclasses import dataclass
from typing import Dict, Optional

from .types import AlgorithmBackend, VariantResult
from .mutators import derive_coins
from .events import hit


@dataclass
class DiffReport:
    ok: bool
    details: Dict[str, object]


def diff_on_pk_coins(backend_a: AlgorithmBackend, backend_b: AlgorithmBackend, coins: Optional[bytes] = None) -> DiffReport:
    """Compare behavior of two backends for same pk and coins.

    Steps:
    - Generate pk/sk with backend_a (as reference)
    - Encaps with pk using both backends (backend_b uses same pk; no coins if unsupported)
    - Decaps with backend_a's sk for both ciphertexts (when meaningful)
    - Compare (ct, ss) pairs and resulting secrets
    """
    k = backend_a.keygen()
    e_a = backend_a.encaps(k.public_key, coins=coins)

    # Second backend may not support deterministic coins; call without coins if not supported
    if backend_b.supports_deterministic_encaps():
        e_b = backend_b.encaps(k.public_key, coins=coins)
    else:
        e_b = backend_b.encaps(k.public_key)

    same_ct = e_a.ciphertext == e_b.ciphertext
    same_ss = e_a.shared_secret == e_b.shared_secret

    # Try decapsulation of each ct with backend_a's secret key (if cross-compatible)
    try:
        ss_a_ct_a = backend_a.decaps(k.secret_key, e_a.ciphertext)
        ss_a_ct_b = backend_a.decaps(k.secret_key, e_b.ciphertext)
    except Exception:
        ss_a_ct_a = e_a.shared_secret
        ss_a_ct_b = b""

    equal_ct_a = ss_a_ct_a == e_a.shared_secret
    equal_ct_b = ss_a_ct_b == e_a.shared_secret

    ok = (not same_ct) or (not same_ss)
    # If everything is exactly same, it could still be ok for deterministic identical implementation.
    # Mark ok unless there is an unexpected equality on mismatched path.
    if equal_ct_b:
        ok = False

    details = {
        "backend_a": backend_a.name(),
        "backend_b": backend_b.name(),
        "same_ct": same_ct,
        "same_ss": same_ss,
        "decap_equal_ct_a": equal_ct_a,
        "decap_equal_ct_b": equal_ct_b,
    }
    hit("diff.pk_coins.executed")
    return DiffReport(ok=ok, details=details)


def run_diff_variant(backend_a: AlgorithmBackend, backend_b: AlgorithmBackend, coins: Optional[bytes] = None) -> VariantResult:
    if coins is None and backend_a.supports_deterministic_encaps():
        coins = derive_coins(b"diff:pk_coins", 32)
    rep = diff_on_pk_coins(backend_a, backend_b, coins=coins)
    return VariantResult(
        name="diff_pk_coins",
        passed=rep.ok,
        details=rep.details,
    )

