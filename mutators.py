import hashlib
import hmac
import random
from typing import Iterable, List, Tuple


def derive_coins(seed: bytes, length: int = 32, tweak: bytes = b"") -> bytes:
    """Derive deterministic coins from seed using HKDF-like extract+expand (HMAC-SHA256)."""
    prk = hmac.new(b"scan-core-hkdf", seed + tweak, hashlib.sha256).digest()
    out = b""
    counter = 1
    while len(out) < length:
        out = out + hmac.new(prk, out + bytes([counter]), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def flip_bits_at_positions(data: bytes, positions: Iterable[int]) -> bytes:
    b = bytearray(data)
    n = len(b)
    for pos in positions:
        if pos < 0 or pos >= n * 8:
            continue
        byte_index = pos // 8
        bit_index = pos % 8
        b[byte_index] ^= 1 << bit_index
    return bytes(b)


def flip_bits_random(data: bytes, count: int, seed: int = 0) -> bytes:
    if count <= 0 or not data:
        return data
    rng = random.Random(seed)
    nbits = len(data) * 8
    picks = {rng.randrange(0, nbits) for _ in range(count)}
    return flip_bits_at_positions(data, picks)


def truncate_bytes(data: bytes, new_len: int) -> bytes:
    new_len = max(0, min(len(data), new_len))
    return data[:new_len]


def pad_bytes(data: bytes, total_len: int, pad_byte: int = 0) -> bytes:
    if total_len <= len(data):
        return data
    pad = bytes([pad_byte & 0xFF]) * (total_len - len(data))
    return data + pad


def add_leading_zeroes(data: bytes, count: int) -> bytes:
    if count <= 0:
        return data
    return b"\x00" * count + data


def shuffle_segments(data: bytes, segments: int = 4, seed: int = 0) -> bytes:
    if segments <= 1 or len(data) < segments:
        return data
    seg_len = len(data) // segments
    chunks: List[bytes] = [data[i * seg_len : (i + 1) * seg_len] for i in range(segments - 1)]
    chunks.append(data[(segments - 1) * seg_len :])
    rng = random.Random(seed)
    rng.shuffle(chunks)
    return b"".join(chunks)


def corrupt_length_field_big_endian(data: bytes, offset: int, width: int, delta: int) -> bytes:
    """Corrupt a big-endian integer field at offset by adding delta, keeping width bytes.

    If bounds invalid, returns original data.
    """
    if offset < 0 or width <= 0 or offset + width > len(data):
        return data
    val = int.from_bytes(data[offset : offset + width], "big")
    new_val = (val + delta) & ((1 << (8 * width)) - 1)
    b = bytearray(data)
    b[offset : offset + width] = new_val.to_bytes(width, "big")
    return bytes(b)


def common_ciphertext_mutations(ct: bytes) -> List[Tuple[str, bytes]]:
    muts: List[Tuple[str, bytes]] = []
    if ct:
        mid = len(ct) // 2
        muts.append(("flip_mid_bit", flip_bits_at_positions(ct, [mid * 8])))
        muts.append(("flip_8_random_bits", flip_bits_random(ct, 8, seed=123)))
        muts.append(("truncate_minus_1", truncate_bytes(ct, max(0, len(ct) - 1))))
        muts.append(("pad_plus_1_00", pad_bytes(ct, len(ct) + 1, 0x00)))
        muts.append(("pad_plus_1_ff", pad_bytes(ct, len(ct) + 1, 0xFF)))
        muts.append(("leading_zero_1", add_leading_zeroes(ct, 1)))
        muts.append(("shuffle_segments", shuffle_segments(ct, segments=4, seed=7)))
    return muts
