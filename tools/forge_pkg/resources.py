"""PE resource directory parser/builder.

The forge never edits the existing resource directory in place: it parses the
old tree, merges new entries, serializes a fresh tree and appends it as a new
section.  Named entries are sorted case-insensitively, IDs ascending, exactly
as the Windows loader expects for binary search.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .pe import PEImage, align_up

RT_ICON = 3
RT_RCDATA = 10
RT_GROUP_ICON = 14
RT_VERSION = 16
LANG_EN_US = 0x409


@dataclass
class Blob:
    data: bytes
    code_page: int = 0


Tree = dict  # keys are int | str, values are Tree | Blob


def _parse_name(data: bytes, base: int, offset: int) -> str:
    pos = base + offset
    length = struct.unpack_from("<H", data, pos)[0]
    raw = data[pos + 2 : pos + 2 + length * 2]
    return raw.decode("utf-16le", errors="replace")


def parse_resources(image: PEImage) -> Tree:
    rva, size = image.resource_dir()
    if not rva or not size:
        return {}
    base = image.rva_to_offset(rva)

    def parse_dir(offset: int, depth: int) -> Tree:
        if depth > 4:
            raise ValueError("resource tree too deep")
        pos = base + offset
        characteristics, timestamp, major, minor, named, ids = struct.unpack_from(
            "<IIHHHH", image.data, pos
        )
        del characteristics, timestamp, major, minor
        node: Tree = {}
        cursor = pos + 16
        for _ in range(named + ids):
            name_field, data_field = struct.unpack_from("<II", image.data, cursor)
            cursor += 8
            key = _parse_name(image.data, base, name_field & 0x7FFFFFFF) if name_field & 0x80000000 else name_field
            if data_field & 0x80000000:
                child = parse_dir(data_field & 0x7FFFFFFF, depth + 1)
            else:
                entry_pos = base + (data_field & 0x7FFFFFFF)
                data_rva, data_size, code_page, _ = struct.unpack_from("<IIII", image.data, entry_pos)
                file_off = image.rva_to_offset(data_rva)
                child = Blob(bytes(image.data[file_off : file_off + data_size]), code_page)
            node[key] = child
        return node

    return parse_dir(0, 0)


def sorted_items(node: Tree) -> list[tuple[object, object]]:
    named = sorted(((k, v) for k, v in node.items() if isinstance(k, str)), key=lambda kv: kv[0].lower())
    numeric = sorted(((k, v) for k, v in node.items() if not isinstance(k, str)), key=lambda kv: int(kv[0]))
    return named + numeric


def _walk_dirs(node: Tree):
    yield node
    for _, child in sorted_items(node):
        if isinstance(child, dict):
            yield from _walk_dirs(child)


def _walk_blobs(node: Tree):
    for _, child in sorted_items(node):
        if isinstance(child, dict):
            yield from _walk_blobs(child)
        else:
            yield child


def build_resources(tree: Tree, rva: int) -> bytes:
    dir_offsets: dict[int, int] = {}
    blob_entry_offsets: dict[int, int] = {}
    blob_data_offsets: dict[int, int] = {}
    cursor = 0

    for directory in _walk_dirs(tree):
        dir_offsets[id(directory)] = cursor
        cursor += 16 + 8 * len(directory)

    for blob in _walk_blobs(tree):
        blob_entry_offsets[id(blob)] = cursor
        cursor += 16

    names = sorted({k for d in _walk_dirs(tree) for k in d if isinstance(k, str)}, key=str.lower)
    name_offsets: dict[str, int] = {}
    for name in names:
        name_offsets[name] = cursor
        cursor += align_up(2 + 2 * len(name) + 2, 4)

    cursor = align_up(cursor, 8)
    for blob in _walk_blobs(tree):
        blob_data_offsets[id(blob)] = cursor
        cursor += align_up(len(blob.data), 8)

    out = bytearray(cursor)
    base_data_rva = rva

    for directory in _walk_dirs(tree):
        pos = dir_offsets[id(directory)]
        items = sorted_items(directory)
        named_count = sum(1 for k, _ in items if isinstance(k, str))
        id_count = len(items) - named_count
        struct.pack_into("<IIHHHH", out, pos, 0, 0, 0, 0, named_count, id_count)
        entry_pos = pos + 16
        for key, child in items:
            if isinstance(key, str):
                name_field = 0x80000000 | name_offsets[key]
            else:
                name_field = int(key) & 0xFFFFFFFF
            if isinstance(child, dict):
                data_field = 0x80000000 | dir_offsets[id(child)]
            else:
                data_field = blob_entry_offsets[id(child)]
            struct.pack_into("<II", out, entry_pos, name_field, data_field)
            entry_pos += 8

    for name in names:
        pos = name_offsets[name]
        struct.pack_into("<H", out, pos, len(name))
        out[pos + 2 : pos + 2 + len(name) * 2] = name.encode("utf-16le")
        struct.pack_into("<H", out, pos + 2 + len(name) * 2, 0)

    for blob in _walk_blobs(tree):
        entry_pos = blob_entry_offsets[id(blob)]
        data_pos = blob_data_offsets[id(blob)]
        struct.pack_into(
            "<IIII",
            out,
            entry_pos,
            base_data_rva + data_pos,
            len(blob.data),
            blob.code_page,
            0,
        )
        out[data_pos : data_pos + len(blob.data)] = blob.data

    return bytes(out)


def set_resource(tree: Tree, type_id: int, name: int | str, lang: int, blob: Blob) -> None:
    type_node = tree.setdefault(type_id, {})
    if not isinstance(type_node, dict):
        raise ValueError("resource type node is not a directory")
    name_node = type_node.get(name)
    if not isinstance(name_node, dict):
        name_node = {}
        type_node[name] = name_node
    name_node[lang] = blob


def replace_resource(tree: Tree, type_id: int, name: int | str, lang: int, blob: Blob) -> None:
    type_node = tree.setdefault(type_id, {})
    type_node[name] = {lang: blob}


def count_resources(tree: Tree) -> int:
    total = 0
    for directory in _walk_dirs(tree):
        total += sum(1 for _, child in directory.items() if not isinstance(child, dict))
    return total


def max_icon_id(tree: Tree) -> int:
    icons = tree.get(RT_ICON, {})
    if not isinstance(icons, dict):
        return 0
    ids = [int(k) for k in icons if not isinstance(k, str)]
    return max(ids, default=0)
