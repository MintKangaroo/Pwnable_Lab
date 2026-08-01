"""테스트용 ELF 합성 헬퍼."""

from __future__ import annotations

import struct

from pwnable_lab.challenge.base import POP_RDI_RET, RET, XOR_EAX_RET, sub_rsp
from pwnable_lab.elf.builder import ElfBuilder, Symbol


def sample_elf(**overrides) -> bytes:
    """가젯·심볼·문자열을 갖춘 대표 ELF 를 만든다."""
    text = sub_rsp(0x20) + POP_RDI_RET + RET + XOR_EAX_RET
    kwargs = dict(
        text=text,
        rodata=b"FLAG{test}\x00/bin/sh\x00",
        symbols=[
            Symbol("main", ".text", 0, len(text)),
            Symbol("win", ".text", len(sub_rsp(0x20)), 2),
            Symbol("gets", ".text", 0, 0),
        ],
        pie=False,
        nx=True,
        relro="partial",
        canary=False,
    )
    kwargs.update(overrides)
    return ElfBuilder(**kwargs).build()


def sample_pe() -> bytes:
    """Create a small PE32+ image with one import and one base relocation."""

    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    optional_size = 0xF0
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x8664,
        2,
        0x65000000,
        0,
        0,
        optional_size,
        0x0022,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", data, optional + 68, 3, 0x4160)
    struct.pack_into("<I", data, optional + 108, 16)
    # Import and base-relocation directories.
    struct.pack_into("<II", data, optional + 112 + 8, 0x2000, 0x40)
    struct.pack_into("<II", data, optional + 112 + 5 * 8, 0x2100, 12)

    section_table = optional + optional_size
    data[section_table : section_table + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIII",
        data,
        section_table + 8,
        0x20,
        0x1000,
        0x200,
        0x200,
    )
    struct.pack_into("<I", data, section_table + 36, 0x60000020)
    second = section_table + 40
    data[second : second + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", data, second + 8, 0x400, 0x2000, 0x400, 0x400)
    struct.pack_into("<I", data, second + 36, 0x40000040)

    data[0x200:0x203] = b"\x90\x90\xc3"
    struct.pack_into("<IIIII", data, 0x400, 0x2050, 0, 0, 0x2080, 0x2070)
    struct.pack_into("<Q", data, 0x450, 0x2090)
    data[0x480:0x48D] = b"KERNEL32.dll\x00"
    struct.pack_into("<H", data, 0x490, 0)
    data[0x492:0x4A1] = b"CreateProcessA\x00"
    struct.pack_into("<IIHH", data, 0x500, 0x1000, 12, 0xA010, 0)
    return bytes(data)


def sample_raw() -> bytes:
    """Raw x86-like bytes with no executable container header."""

    return b"\x90" * 16 + b"HELLO\x00" + b"\x48\x31\xc0\xc3"
