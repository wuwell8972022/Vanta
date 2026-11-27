"""LZSS codec matching the loader's freestanding decoder.

Token format (classic 12/4 split):
  control byte: bit i == 1 -> literal, bit i == 0 -> match (bits consumed LSB first)
  literal: 1 byte
  match:   2 bytes little endian -> pos = (b0 | ((b1 & 0x0F) << 8)) + 1
                                    len = (b1 >> 4) + 3
  window:  4096 bytes, initially zeroed, output is written as it is produced.

The encoder is intentionally conservative (bounded hash chains) so that
multi-megabyte payloads pack in reasonable time.
"""

from __future__ import annotations

WINDOW = 4096
MIN_MATCH = 3
MAX_MATCH = 18
CHAIN = 48


def compress(data: bytes) -> bytes:
    n = len(data)
    table: dict[bytes, list[int]] = {}
    tokens: list[tuple] = []
    i = 0
    while i < n:
        best_len = 0
        best_off = 0
        if i + MIN_MATCH <= n:
            key = data[i : i + 3]
            chain = table.get(key)
            if chain:
                for pos in chain[-CHAIN:]:
                    off = i - pos
                    if off <= 0 or off > WINDOW:
                        continue
                    limit = min(MAX_MATCH, n - i)
                    length = 0
                    while length < limit and data[pos + length] == data[i + length]:
                        length += 1
                    if length > best_len:
                        best_len = length
                        best_off = off
                        if length == limit:
                            break
        if best_len >= MIN_MATCH:
            tokens.append((best_off, best_len))
            end = min(i + best_len, n - 2)
            for k in range(i, end):
                key = data[k : k + 3]
                bucket = table.get(key)
                if bucket is None:
                    table[key] = [k]
                else:
                    bucket.append(k)
                    if len(bucket) > 64:
                        del bucket[: len(bucket) - 64]
            i += best_len
        else:
            tokens.append((0, data[i]))
            if i + MIN_MATCH <= n:
                key = data[i : i + 3]
                bucket = table.get(key)
                if bucket is None:
                    table[key] = [i]
                else:
                    bucket.append(i)
                    if len(bucket) > 64:
                        del bucket[: len(bucket) - 64]
            i += 1

    out = bytearray()
    group: list[int] = []
    ctrl = 0

    def flush() -> None:
        nonlocal group, ctrl
        if group:
            out.append(ctrl)
            out.extend(group)
        group = []
        ctrl = 0

    bit = 0
    for tok in tokens:
        if tok[0] == 0:
            ctrl |= 1 << bit
            group.append(tok[1] & 0xFF)
        else:
            off, length = tok
            packed = (off - 1) | ((length - MIN_MATCH) << 12)
            group.append(packed & 0xFF)
            group.append((packed >> 8) & 0xFF)
        bit += 1
        if bit == 8:
            flush()
            bit = 0
    flush()
    return bytes(out)


def decompress(data: bytes, expected: int) -> bytes:
    out = bytearray()
    window = bytearray(WINDOW)
    wpos = 0
    p = 0
    n = len(data)
    while len(out) < expected:
        if p >= n:
            raise ValueError("truncated LZSS stream")
        ctrl = data[p]
        p += 1
        for bit in range(8):
            if len(out) >= expected:
                break
            if ctrl & (1 << bit):
                if p >= n:
                    raise ValueError("truncated literal")
                b = data[p]
                p += 1
                out.append(b)
                window[wpos] = b
                wpos = (wpos + 1) & (WINDOW - 1)
            else:
                if p + 1 >= n:
                    raise ValueError("truncated match")
                b0 = data[p]
                b1 = data[p + 1]
                p += 2
                off = (b0 | ((b1 & 0x0F) << 8)) + 1
                length = (b1 >> 4) + MIN_MATCH
                for _ in range(length):
                    if len(out) >= expected:
                        break
                    b = window[(wpos - off) & (WINDOW - 1)]
                    out.append(b)
                    window[wpos] = b
                    wpos = (wpos + 1) & (WINDOW - 1)
    return bytes(out)
