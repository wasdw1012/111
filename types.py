from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol


@dataclass
class KemKeypair:
    public_key: bytes
    secret_key: bytes


@dataclass
class EncapsResult:
    ciphertext: bytes
    shared_secret: bytes


@dataclass
class VariantResult:
    name: str
    passed: bool
    details: Dict[str, Any]


class AlgorithmBackend(Protocol):
    """Protocol for KEM-capable backends used by handshake variants."""

    def name(self) -> str:
        ...

    def supports_deterministic_encaps(self) -> bool:
        """Whether encaps can accept caller-supplied randomness/coins for determinism."""
        ...

    def keygen(self) -> KemKeypair:
        ...

    def encaps(self, public_key: bytes, coins: Optional[bytes] = None) -> EncapsResult:
        ...

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Return shared secret from decapsulation."""
        ...
