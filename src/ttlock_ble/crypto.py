"""AES-128-CBC, table-driven CRC-8, and the libLockCore.so codec_decode XOR.

All three primitives were reverse-engineered from `libLockCore.so` (the
JNI library shipped inside the DLock-XP 1.6.0 APK) and validated against
captured byte fixtures from a real cloud sync.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if TYPE_CHECKING:
    from collections.abc import Callable

_AES_BLOCK_BITS = 128
_AES_KEY_LEN = 16

_DECODE_TABLE = bytes.fromhex(
    "005ebce2613fdd83c29c7e20a3fd1f419dc3217ffca2401e5f01e3bd3e6082dc"
    "23079fc1421cfea0e1bf5d0380de3c62bee0025cdf81633d7c22c09e1d43a1ff"
    "4618faa427799bc584da3866e5bb5907db856739bae406581947a5fb7826c49a"
    "653bd987045ab8e6a7f91b45c6987a24f8a6441a99c7257b3a6486d85b05e7b9"
    "8cd2306eedb3510f4e10f2ac2f7193cd114fadf3702ecc92d38d6f31b2ec0e50"
    "aff1134dce90722c6d33d18f0c52b0ee326c8ed0530defb1f0ae4c1291cf2d73"
    "ca947628abf517490856b4ea6937d58b5709ebb536688ad495cb2977f4aa4816"
    "e9b7550b88d6346a2b7597c94a14f6a8742ac896154ba9f7b6e80a54d7896b35"
)


def _check_key(key: bytes) -> None:
    if key is None or len(key) != _AES_KEY_LEN:
        raise ValueError(f"AES key must be {_AES_KEY_LEN} bytes, got {len(key) if key else 0}")


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128-CBC encrypt with `key` used as both key and IV (TTLock convention)."""
    _check_key(key)
    padder = padding.PKCS7(_AES_BLOCK_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128-CBC decrypt with `key` used as both key and IV (TTLock convention)."""
    _check_key(key)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(_AES_BLOCK_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _table_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = _DECODE_TABLE[(byte ^ crc) & 0xFF]
    return crc & 0xFF


_crc_func: Callable[[bytes], int] = _table_crc


def crc_compute(data: bytes) -> int:
    """CRC-8 used by libLockCore.so, table-driven against `_DECODE_TABLE`."""
    return _crc_func(data)


def set_crc_func(fn: Callable[[bytes], int]) -> None:
    """Override the CRC implementation (only useful for protocol experiments)."""
    global _crc_func  # noqa: PLW0603  -- module-level swap is the public contract
    _crc_func = fn


def codec_decode(encoded: bytes) -> bytes:
    """Reverse of `CodecUtils.encode` in libLockCore.so.

    The native lib XORs every byte of the payload with a per-call constant
    derived from the LAST byte and a fixed 256-entry substitution table:

        xor_const = TABLE[(len - 1) % 256] XOR encoded[-1]
        decoded   = [b XOR xor_const for b in encoded[:-1]]

    The last byte is consumed (not part of the result) — it carries the
    information needed to recover the constant and is dropped on decode.
    """
    if len(encoded) < 2:
        return encoded
    xor_const = _DECODE_TABLE[(len(encoded) - 1) % 256] ^ encoded[-1]
    return bytes(b ^ xor_const for b in encoded[:-1])


def decode_password(field: str) -> str:
    """Decode a `lockKey` / `adminPwd` / `noKeyPwd` field from the cloud sync.

    The cloud serialises these as base64( "n1,n2,n3,..." ) where each n_i is
    the decimal byte value of the *encoded* payload. We base64-decode, parse
    the CSV into bytes, then run `codec_decode` and return the resulting
    ASCII numeric string ready for `int(...)`.

    Short fields (10 chars or fewer) are passed through verbatim — mirroring
    `CommandUtil.U_checkUserTime`'s `unlockKey.length() > 10` guard.
    """
    if not field or len(field) <= 10:
        return field
    csv = base64.b64decode(field).decode("ascii")
    raw = bytes(int(x) & 0xFF for x in csv.split(",") if x)
    return codec_decode(raw).decode("latin1")


def hex_key_to_bytes(hex_str: str) -> bytes:
    """Convert the cloud's `aesKeyStr` to raw bytes.

    Accepts the comma-separated hex form the cloud uses
    (`"2c,3d,23,..."`, mirrors `DigitUtil.convertAesKeyStrToBytes`),
    a dot-separated equivalent, or a 32-char continuous hex string.
    """
    s = hex_str.strip()
    if not s:
        raise ValueError("aesKeyStr is empty")
    if "," in s or "." in s:
        sep = "," if "," in s else "."
        parts = [int(x.strip(), 16) & 0xFF for x in s.split(sep) if x.strip()]
        if len(parts) != _AES_KEY_LEN:
            raise ValueError(f"AES key has {len(parts)} parts, expected {_AES_KEY_LEN}")
        return bytes(parts)
    if len(s) == _AES_KEY_LEN * 2 and all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    raise ValueError(f"Unrecognised AES key format: {s!r}")
