import argparse
import json
import sys
from typing import List

from .events import snapshot, reset_events
from .types import AlgorithmBackend, VariantResult
from .mutators import derive_coins
from .backends_mlkem_py import MLKEMPythonBackend
from . import variants


def _select_variants(names: List[str]):
    mapping = {
        # KEM-focused checks
        "ct_reuse_cross_session": variants.ct_reuse_cross_session,
        "coins_reuse_same_pk": variants.coins_reuse_same_pk,
        "coins_reuse_cross_pk": variants.coins_reuse_cross_pk,
        "order_mismatch_pairing": variants.order_mismatch_pairing,
        "corrupt_ciphertext_fail_path": variants.corrupt_ciphertext_fail_path,
        # Negotiation / downgrade
        "algorithm_downgrade_attempt": variants.algorithm_downgrade_attempt,
        "helloretry_parameter_change": variants.helloretry_parameter_change,
        # Identity & binding
        "auth_transcript_mismatch": variants.auth_transcript_mismatch,
        "exporter_binding_mismatch": variants.exporter_binding_mismatch,
        # Replay / 0-RTT / session reuse
        "zero_rtt_replay": variants.zero_rtt_replay,
        "session_ticket_reuse": variants.session_ticket_reuse,
        "psk_context_mismatch": variants.psk_context_mismatch,
        # Rekey / renewal
        "midstream_rekey_nonce_reuse": variants.midstream_rekey_nonce_reuse,
        "key_rollover_inconsistency": variants.key_rollover_inconsistency,
        # Message choreography
        "duplicate_drop_reorder_detection": variants.duplicate_drop_reorder_detection,
        "cross_connection_splicing": variants.cross_connection_splicing,
        # Hybrid & identity hiding
        "hybrid_kex_mismatch": variants.hybrid_kex_mismatch,
        "identity_hiding_timing": variants.identity_hiding_timing,
        # Encoding / length / context
        "length_leading_zero_anomaly": variants.length_leading_zero_anomaly,
        "context_string_collision": variants.context_string_collision,
    }
    if not names or names == ["all"]:
        return list(mapping.values())
    funcs = []
    for n in names:
        if n not in mapping:
            raise SystemExit(f"Unknown variant: {n}")
        funcs.append(mapping[n])
    return funcs


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description="Handshake variant runner")
    parser.add_argument("--backend", default="mlkem_py", help="Backend name: mlkem_py | tls_psk")
    parser.add_argument("--host", help="Target host for TLS backends")
    parser.add_argument("--port", type=int, default=443, help="Target port for TLS backends (default: 443)")
    parser.add_argument("--sni", nargs="*", help="SNI list for TLS backends")
    parser.add_argument(
        "--variants",
        nargs="*",
        default=["all"],
        help="Variant names or 'all'",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON results")
    parser.add_argument("--diff-backend", help="Enable differential mode with given backend (e.g., mlkem_gv)")
    parser.add_argument("--coins-seed", help="Derive deterministic coins from this ASCII seed for supported variants")
    args = parser.parse_args(argv)

    backend: AlgorithmBackend
    default_variants: List[str] = []

    if args.backend.lower() in {"mlkem_py", "mlkem", "fips203"}:
        backend = MLKEMPythonBackend()
        default_variants = [
            "ct_reuse_cross_session",
            "coins_reuse_same_pk",
            "coins_reuse_cross_pk",
            "order_mismatch_pairing",
            "corrupt_ciphertext_fail_path",
        ]
    elif args.backend.lower() in {"tls_psk", "tls"}:
        from .backends_tls_psk import TLSPSKBackend
        backend = TLSPSKBackend(host=args.host, port=args.port, sni_list=args.sni)
        default_variants = [
            "algorithm_downgrade_attempt",
            "helloretry_parameter_change",
            "exporter_binding_mismatch",
            "context_string_collision",
            "zero_rtt_replay",
            "session_ticket_reuse",
            "psk_context_mismatch",
        ]
    else:
        raise SystemExit(f"Unknown backend: {args.backend}")

    # Select variants
    if not args.variants or args.variants == ["all"]:
        funcs = _select_variants(default_variants)
    else:
        funcs = _select_variants(args.variants)

    results: List[VariantResult] = []
    reset_events()

    for f in funcs:
        # If variant supports coins parameter, pass derived coins when requested
        if args.coins_seed and f.__name__ in {"coins_reuse_same_pk", "coins_reuse_cross_pk"}:
            coins = derive_coins(args.coins_seed.encode("utf-8"), 32)
            res = f(backend, coins=coins)  # type: ignore[misc]
        else:
            res = f(backend)
        results.append(res)

    # Differential mode
    diff_info = None
    if args.diff_backend:
        if args.diff_backend.lower() in {"mlkem_gv", "gv", ".net"}:
            from .backends_mlkem_gv import MLKEMGenValsBackend
            from .differential import run_diff_variant

            try:
                backend_b: AlgorithmBackend = MLKEMGenValsBackend()
                coins = derive_coins(args.coins_seed.encode("utf-8"), 32) if args.coins_seed else None
                diff_res = run_diff_variant(backend, backend_b, coins=coins)
                results.append(diff_res)
                diff_info = diff_res.details
            except Exception as e:
                results.append(VariantResult(name="diff_pk_coins", passed=False, details={"error": str(e)}))
        else:
            results.append(VariantResult(name="diff_pk_coins", passed=False, details={"error": f"Unknown diff backend: {args.diff_backend}"}))

    events = snapshot()
    out = {
        "backend": backend.name(),
        "results": [
            {"name": r.name, "passed": r.passed, "details": r.details} for r in results
        ],
        "events": events,
    }

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(f"Backend: {out['backend']}")
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"- {r.name}: {status}")
        if events:
            print("Events:")
            for k, v in sorted(events.items()):
                print(f"  {k}: {v}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
