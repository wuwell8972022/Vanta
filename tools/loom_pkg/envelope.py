"""Vanta envelope (VENV/1).

On-disk layout::

    +----------------+-----------------------------------------------+
    | outer nonce(8) |  masked[ header(128) | body(body_len) ]        |
    +----------------+-----------------------------------------------+

Masking is ChaCha20 with a key derived from the passphrase only, so the
header can be recovered before the per-file salt is known.  Every inner
layer is keyed from PBKDF2(passphrase, salt) and separated with HMAC labels.

Layers, applied in this order when packing:
  1. optional LZSS compression
  2. zero-free padding to a 64 byte multiple
  3. keyed whole-block permutation
  4. ChaCha20 stream mask
  5. XChaCha20-Poly1305 AEAD (header authenticated as AAD)
  6. outer ChaCha20 mask over header and body
"""

from __future__ import annotations

import array
import os
import struct
import zlib

from . import crypto, lzss

MAGIC = b"NYX1"
VERSION = 1
HEADER_LEN = 128
OUTER_NONCE_LEN = 8
FLAG_COMPRESSED = 0x01
FLAG_PE_IMAGE = 0x02

_HEADER = struct.Struct("<4sBBHQQQII16s24s16s16s16s")
assert _HEADER.size == HEADER_LEN


def _padding(length: int) -> int:
    return 64 - (length % 64) if length % 64 else 64


def _worth_compressing(payload: bytes) -> bool:
    """Cheap zlib probe on three samples; avoids 20 s LZSS walks on random data."""
    if len(payload) < 4096:
        return True
    chunk = min(16384, len(payload) // 3 or len(payload))
    starts = [0, max(0, len(payload) // 2 - chunk // 2), max(0, len(payload) - chunk)]
    raw = b""
    packed = b""
    for start in starts:
        sample = payload[start : start + chunk]
        raw += sample
        packed += zlib.compress(sample, 1)
    return len(packed) < int(len(raw) * 0.92)


def _u32_stream(key: bytes, nonce12: bytes, counter: int = 1):
    while True:
        block = crypto.chacha20_block(key, counter, nonce12)
        for i in range(16):
            yield struct.unpack_from("<I", block, i * 4)[0]
        counter = (counter + 1) & 0xFFFFFFFF


def _permutation(count: int, key: bytes, nonce12: bytes) -> array.array:
    order = array.array("I", range(count))
    gen = _u32_stream(key, nonce12, 1)
    for i in range(count - 1, 0, -1):
        j = next(gen) % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def _block_permute(data: bytes, key: bytes, nonce12: bytes) -> bytes:
    count = len(data) // 64
    if count <= 1:
        return data
    order = _permutation(count, key, nonce12)
    out = bytearray(len(data))
    for i in range(count):
        src = order[i] * 64
        out[i * 64 : (i + 1) * 64] = data[src : src + 64]
    return bytes(out)


def _block_unpermute(data: bytes, key: bytes, nonce12: bytes) -> bytes:
    count = len(data) // 64
    if count <= 1:
        return data
    order = _permutation(count, key, nonce12)
    out = bytearray(len(data))
    for i in range(count):
        dst = order[i] * 64
        out[dst : dst + 64] = data[i * 64 : (i + 1) * 64]
    return bytes(out)


def _aad(header: bytes) -> bytes:
    return header[:80] + b"\x00" * 16 + header[96:]


def pack(
    payload: bytes,
    passphrase: bytes,
    *,
    compress: bool = True,
    pe_image: bool | None = None,
    rounds: int = 120_000,
    salt: bytes | None = None,
    nonce: bytes | None = None,
    outer_nonce: bytes | None = None,
) -> bytes:
    if not payload:
        raise ValueError("payload is empty")
    if pe_image is None:
        pe_image = payload[:2] == b"MZ"
    if salt is None:
        salt = os.urandom(16)
    if len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    if nonce is None:
        nonce = os.urandom(24)
    if len(nonce) != 24:
        raise ValueError("nonce must be 24 bytes")
    if outer_nonce is None:
        outer_nonce = os.urandom(OUTER_NONCE_LEN)
    if len(outer_nonce) != OUTER_NONCE_LEN:
        raise ValueError("outer nonce must be 8 bytes")

    flags = FLAG_PE_IMAGE if pe_image else 0
    data = payload
    if compress and _worth_compressing(payload):
        squeezed = lzss.compress(payload)
        if len(squeezed) < len(payload):
            data = squeezed
            flags |= FLAG_COMPRESSED

    body_len = len(data) + _padding(len(data))
    body = bytearray(data)
    body.extend(os.urandom(body_len - len(data)))

    master = crypto.kdf_master(passphrase, salt, rounds)
    k_perm = crypto.kdf_subkey(master, b"perm")
    k_mask = crypto.kdf_subkey(master, b"mask")
    k_aead = crypto.kdf_subkey(master, b"aead")

    permuted = _block_permute(bytes(body), k_perm, nonce[0:12])
    masked = crypto.chacha20_xor(k_mask, nonce[12:24], permuted, 1)

    header = bytearray(
        _HEADER.pack(
            MAGIC,
            VERSION,
            flags,
            HEADER_LEN,
            len(payload),
            len(data),
            body_len,
            rounds,
            0,
            salt,
            nonce,
            b"\x00" * 16,
            crypto.sha256(payload)[:16],
            b"\x00" * 16,
        )
    )
    ciphertext, tag = crypto.xchacha20poly1305_encrypt(k_aead, nonce, masked, _aad(bytes(header)))
    header[80:96] = tag

    plain = bytes(header) + ciphertext
    outer_key = crypto.kdf_outer(passphrase)
    outer_nonce12 = outer_nonce + b"\x00\x00\x00\x00"
    return outer_nonce + crypto.chacha20_xor(outer_key, outer_nonce12, plain, 1)


def unpack(blob: bytes, passphrase: bytes, *, verify_digest: bool = True) -> tuple[bytes, dict]:
    if len(blob) < OUTER_NONCE_LEN + HEADER_LEN:
        raise ValueError("envelope is truncated")
    outer_nonce = blob[:OUTER_NONCE_LEN]
    outer_key = crypto.kdf_outer(passphrase)
    outer_nonce12 = outer_nonce + b"\x00\x00\x00\x00"
    plain = crypto.chacha20_xor(outer_key, outer_nonce12, blob[OUTER_NONCE_LEN:], 1)
    header = plain[:HEADER_LEN]
    body = plain[HEADER_LEN:]

    magic, version, flags, hlen, payload_len, data_len, body_len, rounds, reserved, salt, nonce, tag, digest, _ = _HEADER.unpack(header)
    if magic != MAGIC:
        raise ValueError("bad envelope magic (wrong passphrase?)")
    if version != VERSION:
        raise ValueError(f"unsupported envelope version {version}")
    if hlen != HEADER_LEN:
        raise ValueError("bad header length")
    if len(body) != body_len:
        raise ValueError("body length mismatch")
    if body_len % 64 or data_len > body_len or payload_len > (1 << 34):
        raise ValueError("implausible header lengths")

    master = crypto.kdf_master(passphrase, salt, rounds)
    k_perm = crypto.kdf_subkey(master, b"perm")
    k_mask = crypto.kdf_subkey(master, b"mask")
    k_aead = crypto.kdf_subkey(master, b"aead")

    masked = crypto.xchacha20poly1305_decrypt(k_aead, nonce, body, _aad(header), tag)
    permuted = crypto.chacha20_xor(k_mask, nonce[12:24], masked, 1)
    padded = _block_unpermute(permuted, k_perm, nonce[0:12])
    data = padded[:data_len]

    if flags & FLAG_COMPRESSED:
        payload = lzss.decompress(data, payload_len)
    else:
        payload = data
        if len(payload) != payload_len:
            raise ValueError("payload length mismatch")
    if verify_digest and crypto.sha256(payload)[:16] != digest:
        raise ValueError("payload digest mismatch")

    meta = {
        "version": version,
        "flags": flags,
        "compressed": bool(flags & FLAG_COMPRESSED),
        "pe_image": bool(flags & FLAG_PE_IMAGE),
        "payload_len": payload_len,
        "data_len": data_len,
        "body_len": body_len,
        "rounds": rounds,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
    }
    return payload, meta
