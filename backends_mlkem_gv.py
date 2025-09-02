import os
from typing import Optional

from .types import AlgorithmBackend, KemKeypair, EncapsResult


class MLKEMGenValsBackend(AlgorithmBackend):
    """ML-KEM backend that bridges NIST Gen/Vals C# via pythonnet.

    Requirements:
    - pythonnet installed (pip install pythonnet)
    - Environment variables pointing to built DLLs from ACVP-Server:
      SCANCORE_DOTNET_DLL_DIR (directory containing the crypto DLLs)

    This adapter intentionally keeps the API minimal; deterministic 'coins' is not supported.
    """

    def __init__(self) -> None:
        try:
            import clr  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "pythonnet (clr) not available. Install pythonnet to use MLKEMGenValsBackend."
            ) from exc

        dll_dir = os.getenv("SCANCORE_DOTNET_DLL_DIR")
        if not dll_dir or not os.path.isdir(dll_dir):
            raise SystemExit(
                "Set SCANCORE_DOTNET_DLL_DIR to the directory containing NIST ACVP-Server crypto DLLs"
            )

        import sys
        if dll_dir not in sys.path:
            sys.path.append(dll_dir)

        # Load required assemblies. Names are indicative; user should ensure correct names.
        import clr  # type: ignore

        # The exact DLL names may vary by build; allow user to reference via env var if needed.
        kyber_dll = os.getenv("SCANCORE_KYBER_DLL", "NIST.CVP.ACVTS.Libraries.Crypto.Kyber.dll")
        try:
            clr.AddReference(kyber_dll)  # type: ignore[attr-defined]
        except Exception:
            # Try loading by path
            clr.AddReference(os.path.join(dll_dir, kyber_dll))  # type: ignore[attr-defined]

        # After loading the Kyber assembly, import the namespaces/classes
        # Namespace names depend on ACVP-Server repo structure; we use a thin reflection-based approach.
        try:
            from NIST.CVP.ACVTS.Libraries.Crypto.Kyber import Kyber  # type: ignore
        except Exception as exc:
            raise SystemExit(
                "Could not import Kyber from loaded assembly. Verify ACVP-Server build and DLL paths."
            ) from exc

        self._kyber = Kyber

    def name(self) -> str:
        return "MLKEM-GenVals(.NET)"

    def supports_deterministic_encaps(self) -> bool:
        return False

    def keygen(self) -> KemKeypair:
        # Assuming Kyber exposes static methods KeyGen/Encaps/Decaps returning byte arrays
        pk, sk = self._kyber.KeyGen()  # type: ignore[attr-defined]
        return KemKeypair(public_key=bytes(pk), secret_key=bytes(sk))

    def encaps(self, public_key: bytes, coins: Optional[bytes] = None) -> EncapsResult:
        ct, ss = self._kyber.Encaps(public_key)  # type: ignore[attr-defined]
        return EncapsResult(ciphertext=bytes(ct), shared_secret=bytes(ss))

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        ss = self._kyber.Decaps(secret_key, ciphertext)  # type: ignore[attr-defined]
        return bytes(ss)

