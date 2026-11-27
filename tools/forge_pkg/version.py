"""VS_VERSIONINFO builder.

Produces a structurally valid RT_VERSION payload with randomized strings and
version numbers, replacing the image's version resource.  Windows'
GetFileVersionInfo and Explorer read this tree directly.
"""

from __future__ import annotations

import random
import struct

LANG_EN_US = 0x409
CODEPAGE_UNICODE = 0x4B0


def _pad4(data: bytes) -> bytes:
    return data + b"\0" * ((4 - len(data) % 4) % 4)


def _node(key: str, value: bytes = b"", value_len: int = 0, wtype: int = 1, children: bytes = b"") -> bytes:
    key_bytes = key.encode("utf-16le") + b"\0\0"
    header = struct.pack("<HHH", 0, value_len, wtype) + key_bytes
    header_padded = _pad4(header)
    body = _pad4(value)
    payload = header_padded + body + children
    length = len(payload)
    return struct.pack("<HHH", length, value_len, wtype) + key_bytes + header_padded[6 + len(key_bytes):] + body + children


def _string_node(key: str, text: str) -> bytes:
    encoded = text.encode("utf-16le") + b"\0\0"
    return _node(key, encoded, len(text) + 1, 1)


def _rand_text(rng: random.Random, minimum: int = 18, maximum: int = 40) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(minimum, maximum)))


def _fixed_file_info(rng: random.Random) -> tuple[bytes, dict]:
    major = rng.randint(1, 9)
    minor = rng.randint(0, 9)
    build = rng.randint(0, 999)
    revision = rng.randint(0, 999)
    product_major = rng.randint(1, 9)
    product_minor = rng.randint(0, 9)
    file_ms = (major << 16) | minor
    file_ls = (build << 16) | revision
    product_ms = (product_major << 16) | product_minor
    product_ls = (rng.randint(0, 999) << 16) | rng.randint(0, 999)
    value = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        file_ms,
        file_ls,
        product_ms,
        product_ls,
        0x3F,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    )
    return value, {
        "FileVersion": f"{major}.{minor}.{build}.{revision}",
        "ProductVersion": f"{product_major}.{product_minor}",
    }


def build_version_info(rng: random.Random) -> tuple[bytes, dict]:
    fixed, numbers = _fixed_file_info(rng)
    marketing = _rand_text(rng, 10, 24)
    strings = {
        "CompanyName": _rand_text(rng, 20, 36),
        "FileDescription": _rand_text(rng, 24, 48),
        "FileVersion": numbers["FileVersion"],
        "InternalName": _rand_text(rng, 8, 16),
        "LegalCopyright": "(C) " + _rand_text(rng, 16, 30),
        "OriginalFilename": _rand_text(rng, 8, 16) + ".exe",
        "ProductName": marketing,
        "ProductVersion": numbers["ProductVersion"],
    }
    string_children = b"".join(_string_node(k, v) for k, v in strings.items())
    string_table = _node("040904B0", children=string_children)
    string_file_info = _node("StringFileInfo", children=string_table)
    translation = _node(
        "Translation",
        struct.pack("<HH", LANG_EN_US, CODEPAGE_UNICODE),
        4,
        0,
    )
    var_file_info = _node("VarFileInfo", children=translation)
    root = _node(
        "VS_VERSION_INFO",
        fixed,
        52,
        0,
        string_file_info + var_file_info,
    )
    return root, {"strings": strings, "numbers": numbers}
