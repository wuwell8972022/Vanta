"""Decoy icon generation for the forge.

The original QVM250 workflow used ResourceHacker to append random icon groups
under random names.  Vanta creates the same structural decoys directly:
valid ICO images become RT_ICON entries, plus a matching RT_GROUP_ICON under a
random string name.  The executable's primary icon is untouched.
"""

from __future__ import annotations

import io
import random
import struct

from .resources import RT_GROUP_ICON, RT_ICON, RT_VERSION, Blob, Tree


def _random_icon_png(rng: random.Random) -> bytes:
    from PIL import Image, ImageDraw

    size = 64
    background = (rng.randrange(256), rng.randrange(256), rng.randrange(256), 255)
    image = Image.new("RGBA", (size, size), background)
    draw = ImageDraw.Draw(image)
    for _ in range(rng.randint(4, 10)):
        x0 = rng.randrange(size)
        y0 = rng.randrange(size)
        x1 = rng.randrange(size)
        y1 = rng.randrange(size)
        color = (rng.randrange(256), rng.randrange(256), rng.randrange(256), rng.randrange(120, 255))
        if rng.random() < 0.5:
            draw.rectangle([min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)], fill=color)
        else:
            draw.ellipse([min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)], fill=color)
    buffer = io.BytesIO()
    image.save(buffer, format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    return buffer.getvalue()


def _parse_ico(ico: bytes) -> list[tuple[int, int, int, int, int, int, bytes]]:
    if len(ico) < 6:
        raise ValueError("short ICO")
    reserved, kind, count = struct.unpack_from("<HHH", ico, 0)
    if reserved != 0 or kind != 1:
        raise ValueError("not an ICO")
    entries = []
    for i in range(count):
        pos = 6 + i * 16
        width, height, colors, _, planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", ico, pos)
        if offset + size > len(ico):
            raise ValueError("ICO entry out of range")
        entries.append((width, height, colors, planes, bpp, size, ico[offset : offset + size]))
    return entries


def add_icon_group(tree: Tree, rng: random.Random, next_id: int) -> tuple[str, int]:
    ico = _parse_ico(_random_icon_png(rng))
    if not ico:
        raise ValueError("empty icon")

    icon_type = tree.setdefault(RT_ICON, {})
    group_type = tree.setdefault(RT_GROUP_ICON, {})
    if not isinstance(icon_type, dict) or not isinstance(group_type, dict):
        raise ValueError("icon resource type is malformed")

    group_entries = []
    used_ids = []
    for width, height, colors, planes, bpp, size, image in ico:
        icon_id = next_id
        next_id += 1
        if icon_id > 0xFFFF:
            raise ValueError("icon id space exhausted")
        used_ids.append(icon_id)
        icon_type[icon_id] = {0x409: Blob(image, 0)}
        group_entries.append(
            struct.pack(
                "<BBBBHHIH",
                width,
                height,
                colors,
                0,
                planes or 1,
                bpp or 32,
                len(image),
                icon_id,
            )
        )

    while True:
        name = rng.choice("abcdefghijklmnopqrstuvwxyz") + "".join(
            rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            for _ in range(15)
        )
        if name not in group_type:
            break

    group = struct.pack("<HHH", 0, 1, len(group_entries)) + b"".join(group_entries)
    group_type[name] = {0x409: Blob(group, 0)}
    return name, next_id


def add_decoys(tree: Tree, rng: random.Random, count: int, start_id: int) -> list[str]:
    names = []
    next_id = start_id
    for _ in range(max(0, count)):
        name, next_id = add_icon_group(tree, rng, next_id)
        names.append(name)
    return names


__all__ = ["add_decoys", "add_icon_group", "RT_ICON", "RT_GROUP_ICON", "RT_VERSION"]
