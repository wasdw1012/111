from typing import Optional

from .events import hit
from .mutators import common_ciphertext_mutations, derive_coins
from .types import AlgorithmBackend, VariantResult


def _skipped(name: str, reason: str, backend: AlgorithmBackend) -> VariantResult:
    hit(f"variant.{name}.skipped")
    return VariantResult(
        name=name,
        passed=True,
        details={"skipped": True, "reason": reason, "backend": backend.name()},
    )


def ct_reuse_cross_session(backend: AlgorithmBackend) -> VariantResult:
    """Use ciphertext from session A against keypair B. Expected: different secret.

    Signals correctness of transcript/key binding and decapsulation failure path.
    """
    a = backend.keygen()
    # Prefer deterministic encaps when supported for reproducibility
    if backend.supports_deterministic_encaps():
        coins = derive_coins(b"variant:ct_reuse_cross_session", 32)
        enc_a = backend.encaps(a.public_key, coins=coins)
    else:
        enc_a = backend.encaps(a.public_key)

    b = backend.keygen()
    ss_b = backend.decaps(b.secret_key, enc_a.ciphertext)

    passed = ss_b != enc_a.shared_secret
    hit("variant.ct_reuse_cross_session.executed")
    hit("variant.ct_reuse_cross_session.rejected" if passed else "variant.ct_reuse_cross_session.accepted")
    return VariantResult(
        name="ct_reuse_cross_session",
        passed=passed,
        details={
            "secret_equal": ss_b == enc_a.shared_secret,
            "backend": backend.name(),
        },
    )


def coins_reuse_same_pk(backend: AlgorithmBackend, coins: Optional[bytes] = None) -> VariantResult:
    """Encaps twice to same pk with identical coins if supported.

    Expected: identical (ct, ss). If backend doesn't support deterministic encaps, mark skipped.
    """
    if not backend.supports_deterministic_encaps():
        return _skipped("coins_reuse_same_pk", "backend_no_deterministic_encaps", backend)

    k = backend.keygen()
    if coins is None:
        coins = derive_coins(b"variant:coins_reuse_same_pk", 32)

    e1 = backend.encaps(k.public_key, coins=coins)
    e2 = backend.encaps(k.public_key, coins=coins)

    same_ct = e1.ciphertext == e2.ciphertext
    same_ss = e1.shared_secret == e2.shared_secret
    passed = same_ct and same_ss
    hit("variant.coins_reuse.executed")
    hit("variant.coins_reuse.identical" if passed else "variant.coins_reuse.diverged")
    return VariantResult(
        name="coins_reuse_same_pk",
        passed=passed,
        details={
            "same_ct": same_ct,
            "same_ss": same_ss,
            "backend": backend.name(),
        },
    )


def coins_reuse_cross_pk(backend: AlgorithmBackend, coins: Optional[bytes] = None) -> VariantResult:
    """Encaps to two different pks with identical coins.

    Expected: results should differ; identical results indicate weak binding/random isolation issues.
    Skips if backend doesn't support deterministic encaps.
    """
    if not backend.supports_deterministic_encaps():
        return _skipped("coins_reuse_cross_pk", "backend_no_deterministic_encaps", backend)

    k1 = backend.keygen()
    k2 = backend.keygen()
    if coins is None:
        coins = derive_coins(b"variant:coins_reuse_cross_pk", 32)

    e1 = backend.encaps(k1.public_key, coins=coins)
    e2 = backend.encaps(k2.public_key, coins=coins)

    same_ct = e1.ciphertext == e2.ciphertext
    same_ss = e1.shared_secret == e2.shared_secret
    passed = (not same_ct) and (not same_ss)
    hit("variant.coins_reuse_cross_pk.executed")
    hit("variant.coins_reuse_cross_pk.diverged" if passed else "variant.coins_reuse_cross_pk.collision")
    return VariantResult(
        name="coins_reuse_cross_pk",
        passed=passed,
        details={
            "same_ct": same_ct,
            "same_ss": same_ss,
            "backend": backend.name(),
        },
    )


def corrupt_ciphertext_fail_path(backend: AlgorithmBackend) -> VariantResult:
    """Apply structured ciphertext mutations; decapsulation should not yield original secret.

    Expected: new secret differs (or an error path handled). If identical, failure.
    """
    k = backend.keygen()
    # Deterministic encaps if supported for stable baseline
    if backend.supports_deterministic_encaps():
        e = backend.encaps(k.public_key, coins=derive_coins(b"variant:corrupt_ct", 32))
    else:
        e = backend.encaps(k.public_key)
    muts = common_ciphertext_mutations(e.ciphertext)
    all_ok = True
    details = {"backend": backend.name(), "mutations": []}
    for tag, mutated in muts:
        try:
            # If backend exposes expectation hook, register baseline to detect unexpected acceptance
            if hasattr(backend, "expect_secret_for_ct"):
                try:
                    backend.expect_secret_for_ct(mutated, e.shared_secret, tag)  # type: ignore[attr-defined]
                except Exception:
                    pass
            ss_corrupt = backend.decaps(k.secret_key, mutated)
            ok = ss_corrupt != e.shared_secret
        except Exception:
            ok = True
        details["mutations"].append({"tag": tag, "ok": ok})
        all_ok = all_ok and ok
    hit("variant.corrupt_ct.executed")
    hit("variant.corrupt_ct.rejected" if all_ok else "variant.corrupt_ct.accepted")
    return VariantResult(
        name="corrupt_ciphertext_fail_path",
        passed=all_ok,
        details=details,
    )


def order_mismatch_pairing(backend: AlgorithmBackend) -> VariantResult:
    """Generate two encapsulations then decapsulate mismatched order.

    Expected: secrets mismatch against the originally paired secrets.
    """
    k = backend.keygen()
    if backend.supports_deterministic_encaps():
        base = b"variant:order_mismatch_pairing"
        e1 = backend.encaps(k.public_key, coins=derive_coins(base + b":1", 32))
        e2 = backend.encaps(k.public_key, coins=derive_coins(base + b":2", 32))
    else:
        e1 = backend.encaps(k.public_key)
        e2 = backend.encaps(k.public_key)

    # Wrong pairing: compare e1.secret vs decaps(e2.ct)
    ss_wrong = backend.decaps(k.secret_key, e2.ciphertext)
    passed = ss_wrong != e1.shared_secret
    hit("variant.order_mismatch.executed")
    hit("variant.order_mismatch.mismatch" if passed else "variant.order_mismatch.match")
    return VariantResult(
        name="order_mismatch_pairing",
        passed=passed,
        details={"backend": backend.name()},
    )


# Placeholders for higher-layer handshake variants; mark skipped unless backend provides hooks.

def algorithm_downgrade_attempt(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "negotiate_suites"):
        return _skipped("algorithm_downgrade_attempt", "no_negotiation_api", backend)
    # If provided, a backend can override this by implementing negotiate_suites
    try:
        res = backend.negotiate_suites(["ML-KEM", "X25519"], prefer="X25519")  # type: ignore[attr-defined]
        passed = res.get("bound", False) and res.get("final") != "X25519"
        hit("variant.downgrade.executed")
        return VariantResult("algorithm_downgrade_attempt", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("algorithm_downgrade_attempt", passed=False, details={"error": str(e)})


def helloretry_parameter_change(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "hello_retry"):
        return _skipped("helloretry_parameter_change", "no_helloretry_api", backend)
    try:
        res = backend.hello_retry(change_params=True)  # type: ignore[attr-defined]
        passed = res.get("binder_changed", False) and res.get("old_path_valid") is False
        hit("variant.helloretry.executed")
        return VariantResult("helloretry_parameter_change", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("helloretry_parameter_change", passed=False, details={"error": str(e)})


def auth_transcript_mismatch(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "auth_bindings"):
        return _skipped("auth_transcript_mismatch", "no_auth_binding_api", backend)
    try:
        res = backend.auth_bindings(miscover=True)  # type: ignore[attr-defined]
        passed = res.get("rejected", False)
        hit("variant.auth_transcript.executed")
        return VariantResult("auth_transcript_mismatch", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("auth_transcript_mismatch", passed=False, details={"error": str(e)})


def exporter_binding_mismatch(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "exporter_test"):
        return _skipped("exporter_binding_mismatch", "no_exporter_api", backend)
    try:
        res = backend.exporter_test(misbind=True)  # type: ignore[attr-defined]
        passed = res.get("changed", False)
        hit("variant.exporter.executed")
        return VariantResult("exporter_binding_mismatch", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("exporter_binding_mismatch", passed=False, details={"error": str(e)})


def zero_rtt_replay(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "zero_rtt"):
        return _skipped("zero_rtt_replay", "no_0rtt_api", backend)
    try:
        res = backend.zero_rtt(replay=True)  # type: ignore[attr-defined]
        passed = res.get("replay_rejected", False)
        hit("variant.zero_rtt.executed")
        return VariantResult("zero_rtt_replay", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("zero_rtt_replay", passed=False, details={"error": str(e)})


def session_ticket_reuse(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "ticket_reuse"):
        return _skipped("session_ticket_reuse", "no_ticket_api", backend)
    try:
        res = backend.ticket_reuse(cross_client=True)  # type: ignore[attr-defined]
        passed = res.get("rejected", False)
        hit("variant.ticket.executed")
        return VariantResult("session_ticket_reuse", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("session_ticket_reuse", passed=False, details={"error": str(e)})


def psk_context_mismatch(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "psk_mismatch"):
        return _skipped("psk_context_mismatch", "no_psk_api", backend)
    try:
        res = backend.psk_mismatch()  # type: ignore[attr-defined]
        passed = res.get("binder_invalid", False)
        hit("variant.psk.executed")
        return VariantResult("psk_context_mismatch", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("psk_context_mismatch", passed=False, details={"error": str(e)})


def midstream_rekey_nonce_reuse(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "rekey_test"):
        return _skipped("midstream_rekey_nonce_reuse", "no_rekey_api", backend)
    try:
        res = backend.rekey_test(reuse_nonce=True)  # type: ignore[attr-defined]
        passed = res.get("aead_detected", False)
        hit("variant.rekey.executed")
        return VariantResult("midstream_rekey_nonce_reuse", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("midstream_rekey_nonce_reuse", passed=False, details={"error": str(e)})


def key_rollover_inconsistency(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "key_rollover"):
        return _skipped("key_rollover_inconsistency", "no_rollover_api", backend)
    try:
        res = backend.key_rollover(one_side_only=True)  # type: ignore[attr-defined]
        passed = res.get("explicit_fail", False)
        hit("variant.rollover.executed")
        return VariantResult("key_rollover_inconsistency", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("key_rollover_inconsistency", passed=False, details={"error": str(e)})


def duplicate_drop_reorder_detection(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "message_sequence_test"):
        return _skipped("duplicate_drop_reorder_detection", "no_sequence_api", backend)
    try:
        res = backend.message_sequence_test(mode="duplicate_drop_reorder")  # type: ignore[attr-defined]
        passed = res.get("detected", False)
        hit("variant.sequence.executed")
        return VariantResult("duplicate_drop_reorder_detection", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("duplicate_drop_reorder_detection", passed=False, details={"error": str(e)})


def cross_connection_splicing(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "splice_test"):
        return _skipped("cross_connection_splicing", "no_splice_api", backend)
    try:
        res = backend.splice_test()  # type: ignore[attr-defined]
        passed = res.get("rejected", False)
        hit("variant.splice.executed")
        return VariantResult("cross_connection_splicing", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("cross_connection_splicing", passed=False, details={"error": str(e)})


def hybrid_kex_mismatch(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "hybrid_mismatch"):
        return _skipped("hybrid_kex_mismatch", "no_hybrid_api", backend)
    try:
        res = backend.hybrid_mismatch()  # type: ignore[attr-defined]
        passed = res.get("keys_diverged", False)
        hit("variant.hybrid.executed")
        return VariantResult("hybrid_kex_mismatch", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("hybrid_kex_mismatch", passed=False, details={"error": str(e)})


def identity_hiding_timing(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "identity_hiding"):
        return _skipped("identity_hiding_timing", "no_identity_hiding_api", backend)
    try:
        res = backend.identity_hiding(order="kem_then_auth")  # type: ignore[attr-defined]
        passed = res.get("policy_consistent", False)
        hit("variant.identity_hiding.executed")
        return VariantResult("identity_hiding_timing", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("identity_hiding_timing", passed=False, details={"error": str(e)})


def length_leading_zero_anomaly(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "encoding_test"):
        return _skipped("length_leading_zero_anomaly", "no_encoding_api", backend)
    try:
        res = backend.encoding_test(anomaly="leading_zero")  # type: ignore[attr-defined]
        passed = res.get("detected", False)
        hit("variant.encoding.executed")
        return VariantResult("length_leading_zero_anomaly", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("length_leading_zero_anomaly", passed=False, details={"error": str(e)})


def context_string_collision(backend: AlgorithmBackend) -> VariantResult:
    if not hasattr(backend, "context_label_test"):
        return _skipped("context_string_collision", "no_context_api", backend)
    try:
        res = backend.context_label_test()  # type: ignore[attr-defined]
        passed = res.get("exporter_changed", False)
        hit("variant.context_label.executed")
        return VariantResult("context_string_collision", passed=passed, details=res)
    except Exception as e:  # pragma: no cover
        return VariantResult("context_string_collision", passed=False, details={"error": str(e)})

