"""Minimal PE32+ editor used by the Vanta forge tool.

Only what the forge needs:
  * parse headers and section table
  * translate RVA <-> file offset
  * append (or replace) a resource section
  * update the resource data directory, SizeOfImage, timestamp, checksum
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass
class Section:
    name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int
    header_offset: int


class PEImage:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("not a PE image")
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if self.e_lfanew + 24 > len(data) or data[self.e_lfanew : self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("bad NT header")
        self.file_header_off = self.e_lfanew + 4
        self.optional_off = self.e_lfanew + 24
        if struct.unpack_from("<H", data, self.optional_off)[0] != 0x20B:
            raise ValueError("not PE32+")
        self.num_sections = struct.unpack_from("<H", data, self.file_header_off + 2)[0]
        self.size_of_optional = struct.unpack_from("<H", data, self.file_header_off + 16)[0]
        self.section_table_off = self.optional_off + self.size_of_optional
        self.section_alignment = struct.unpack_from("<I", data, self.optional_off + 32)[0]
        self.file_alignment = struct.unpack_from("<I", data, self.optional_off + 36)[0]
        if self.section_alignment < 0x200 or self.file_alignment < 0x200:
            raise ValueError("unsupported alignment")
        self.size_of_image_off = self.optional_off + 56
        self.size_of_headers_off = self.optional_off + 60
        self.checksum_off = self.optional_off + 64
        self.size_of_init_off = self.optional_off + 8
        self.data_dir_off = self.optional_off + 112
        self.num_dirs = struct.unpack_from("<I", data, self.optional_off + 108)[0]
        if self.num_dirs < 16:
            raise ValueError("too few data directories")
        self.sections: list[Section] = []
        for i in range(self.num_sections):
            off = self.section_table_off + i * 40
            if off + 40 > len(data):
                raise ValueError("truncated section table")
            name = data[off : off + 8].rstrip(b"\0")
            vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append(Section(name, vsize, vaddr, raw_size, raw_off, chars, off))
        self.size_of_headers = struct.unpack_from("<I", data, self.size_of_headers_off)[0]

    def resource_dir(self) -> tuple[int, int]:
        rva, size = struct.unpack_from("<II", self.data, self.data_dir_off + 2 * 8)
        return rva, size

    def rva_to_offset(self, rva: int) -> int:
        if rva < self.size_of_headers:
            return rva
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    raise ValueError("RVA points into uninitialized section data")
                return section.raw_offset + delta
        raise ValueError(f"RVA 0x{rva:x} is not mapped")

    def section_containing_offset(self, offset: int) -> Section | None:
        for section in self.sections:
            if section.raw_offset <= offset < section.raw_offset + section.raw_size:
                return section
        return None

    def plan_resource_section(self, blob_len: int) -> tuple[int, int, int]:
        """Return (virtual_address, raw_offset, raw_size) for a new section."""
        end_va = 0
        end_raw = 0
        for section in self.sections:
            end_va = max(end_va, section.virtual_address + max(section.virtual_size, section.raw_size))
            end_raw = max(end_raw, section.raw_offset + section.raw_size)
        new_va = align_up(end_va, self.section_alignment)
        raw_off = align_up(max(end_raw, len(self.data)), self.file_alignment)
        raw_size = align_up(blob_len, self.file_alignment)
        return new_va, raw_off, raw_size

    def append_section(self, name: bytes, blob: bytes) -> tuple[int, int]:
        if len(name) > 8:
            raise ValueError("section name too long")
        new_va, raw_off, raw_size = self.plan_resource_section(len(blob))
        header_off = self.section_table_off + self.num_sections * 40
        first_raw = min((s.raw_offset for s in self.sections if s.raw_offset), default=self.size_of_headers)
        if header_off + 40 > first_raw:
            raise ValueError("no room in the PE header for another section")

        # Rename an existing .rsrc section so the image has one canonical one.
        for section in self.sections:
            if section.name == b".rsrc":
                struct.pack_into("<8s", self.data, section.header_offset, b".rsold\0\0")

        header = struct.pack(
            "<8sIIIIIIHHI",
            name.ljust(8, b"\0"),
            len(blob),
            new_va,
            raw_size,
            raw_off,
            0,
            0,
            0,
            0,
            0x40000040,
        )
        if len(self.data) < header_off + 40:
            self.data.extend(b"\0" * (header_off + 40 - len(self.data)))
        self.data[header_off : header_off + 40] = header

        if len(self.data) < raw_off:
            self.data.extend(b"\0" * (raw_off - len(self.data)))
        self.data.extend(blob)
        if len(self.data) < raw_off + raw_size:
            self.data.extend(b"\0" * (raw_off + raw_size - len(self.data)))

        struct.pack_into("<H", self.data, self.file_header_off + 2, self.num_sections + 1)
        struct.pack_into(
            "<I", self.data, self.size_of_image_off,
            align_up(new_va + max(len(blob), 1), self.section_alignment),
        )
        struct.pack_into("<I", self.data, self.checksum_off, 0)
        old_init = struct.unpack_from("<I", self.data, self.size_of_init_off)[0]
        struct.pack_into("<I", self.data, self.size_of_init_off, old_init + raw_size)
        struct.pack_into("<II", self.data, self.data_dir_off + 2 * 8, new_va, len(blob))
        self.num_sections += 1
        return new_va, raw_off

    def set_timestamp(self, value: int) -> None:
        struct.pack_into("<I", self.data, self.file_header_off + 4, value & 0xFFFFFFFF)

    def to_bytes(self) -> bytes:
        return bytes(self.data)
