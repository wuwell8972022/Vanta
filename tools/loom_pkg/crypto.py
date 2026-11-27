"""Vanta primitive cryptography.

Self-contained reference implementation used by the packer.  The loader
re-implements exactly these primitives in freestanding C++ (no CRT, no
external crypto library), so this module is the normative specification.

Primitives
----------
* SHA-256 / HMAC-SHA256 / PBKDF2-HMAC-SHA256  (hashlib/hmac)
* ChaCha20 (RFC 8439) and HChaCha20
* Poly1305 (RFC 8439)
* XChaCha20-Poly1305 AEAD
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

MASK32 = 0xFFFFFFFF

try:  # optional acceleration; the pure implementations below stay normative
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - depends on the host
    Cipher = algorithms = ChaCha20Poly1305 = None
    _HAS_CRYPTOGRAPHY = False

_USE_ACCEL = _HAS_CRYPTOGRAPHY and os.environ.get("VANTA_PURE") != "1"


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & MASK32


def _qr(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]
    s[d] = _rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]
    s[b] = _rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]
    s[d] = _rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]
    s[b] = _rotl32(s[b], 7)


_CONST = b"expand 32-byte k"


def _init_state(key: bytes, counter: int, nonce12: bytes) -> list[int]:
    if len(key) != 32:
        raise ValueError("chacha20 key must be 32 bytes")
    if len(nonce12) != 12:
        raise ValueError("chacha20 nonce must be 12 bytes")
    return (
        list(struct.unpack("<4I", _CONST))
        + list(struct.unpack("<8I", key))
        + [counter & MASK32]
        + list(struct.unpack("<3I", nonce12))
    )


def _rounds(s: list[int]) -> None:
    for _ in range(10):
        _qr(s, 0, 4, 8, 12)
        _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14)
        _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15)
        _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13)
        _qr(s, 3, 4, 9, 14)


def chacha20_block(key: bytes, counter: int, nonce12: bytes) -> bytes:
    initial = _init_state(key, counter, nonce12)
    working = initial[:]
    _rounds(working)
    out = [(working[i] + initial[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    if len(nonce16) != 16:
        raise ValueError("hchacha20 nonce must be 16 bytes")
    s = (
        list(struct.unpack("<4I", _CONST))
        + list(struct.unpack("<8I", key))
        + list(struct.unpack("<4I", nonce16))
    )
    _rounds(s)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def chacha20_xor(key: bytes, nonce12: bytes, data: bytes, counter: int = 1) -> bytes:
    if _USE_ACCEL:
        nonce16 = struct.pack("<I", counter & MASK32) + nonce12
        cipher = Cipher(algorithms.ChaCha20(key, nonce16), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()
    out = bytearray(len(data))
    pos = 0
    ctr = counter
    while pos < len(data):
        ks = chacha20_block(key, ctr, nonce12)
        chunk = data[pos : pos + 64]
        for i, b in enumerate(chunk):
            out[pos + i] = b ^ ks[i]
        pos += len(chunk)
        ctr = (ctr + 1) & MASK32
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        block = msg[i : i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _pad16(n: int) -> bytes:
    rem = n % 16
    return b"\x00" * (16 - rem) if rem else b""


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    if len(nonce24) != 24:
        raise ValueError("xchacha20 nonce must be 24 bytes")
    subkey = hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    if _USE_ACCEL:
        combined = ChaCha20Poly1305(subkey).encrypt(nonce12, plaintext, aad)
        return combined[:-16], combined[-16:]
    otk = chacha20_block(subkey, 0, nonce12)[:32]
    ct = chacha20_xor(subkey, nonce12, plaintext, counter=1)
    mac_data = (
        aad
        + _pad16(len(aad))
        + ct
        + _pad16(len(ct))
        + struct.pack("<QQ", len(aad), len(ct))
    )
    tag = poly1305(otk, mac_data)
    return ct, tag


def xchacha20poly1305_decrypt(key: bytes, nonce24: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> bytes:
    if len(nonce24) != 24:
        raise ValueError("xchacha20 nonce must be 24 bytes")
    if len(tag) != 16:
        raise ValueError("poly1305 tag must be 16 bytes")
    subkey = hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    if _USE_ACCEL:
        try:
            return ChaCha20Poly1305(subkey).decrypt(nonce12, ciphertext + tag, aad)
        except Exception as exc:  # InvalidTag and friends
            raise ValueError("authentication tag mismatch") from exc
    otk = chacha20_block(subkey, 0, nonce12)[:32]
    mac_data = (
        aad
        + _pad16(len(aad))
        + ciphertext
        + _pad16(len(ciphertext))
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    expected = poly1305(otk, mac_data)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication tag mismatch")
    return chacha20_xor(subkey, nonce12, ciphertext, counter=1)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def pbkdf2_sha256(password: bytes, salt: bytes, rounds: int, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, rounds, length)


def kdf_outer(passphrase: bytes) -> bytes:
    return hmac_sha256(passphrase, b"vanta/outer/v1")


def kdf_master(passphrase: bytes, salt: bytes, rounds: int) -> bytes:
    return pbkdf2_sha256(passphrase, salt, rounds, 32)


def kdf_subkey(master: bytes, label: bytes) -> bytes:
    return hmac_sha256(master, b"vanta/" + label + b"/v1")
