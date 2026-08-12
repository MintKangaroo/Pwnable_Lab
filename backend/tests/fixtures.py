"""테스트용 ELF 합성 헬퍼."""

from __future__ import annotations

import struct

from pwnable_lab.challenge.base import POP_RDI_RET, RET, XOR_EAX_RET, sub_rsp
from pwnable_lab.elf.builder import ElfBuilder, Symbol
from pwnable_lab.payload.cyclic import cyclic


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


def sample_control_flow_elf() -> bytes:
    """ELF with one conditional branch and a direct call to a second function."""

    main = (
        b"\x48\x85\xff"  # test rdi, rdi
        b"\x74\x06"  # je main+0xb
        b"\xe8\x06\x00\x00\x00"  # call helper at .text+0x10
        b"\xc3"  # ret
        b"\x31\xc0"  # xor eax, eax
        b"\xc3"  # ret
    )
    padding = b"\x90\x90"
    helper = b"\x55\x48\x89\xe5\xc3"  # push rbp ; mov rbp, rsp ; ret
    return ElfBuilder(
        text=main + padding + helper,
        symbols=[
            Symbol("main", ".text", 0, len(main)),
            Symbol("helper", ".text", len(main) + len(padding), len(helper)),
        ],
        pie=False,
        nx=True,
        relro="partial",
    ).build()


def sample_gadget_elf(*, pie: bool = False) -> bytes:
    """ELF containing deterministic gadget-semantic fixtures."""

    text = b"".join(
        [
            b"\x5f\xc3",  # pop rdi ; ret
            b"\x5e\x41\x5f\xc3",  # pop rsi ; pop r15 ; ret
            b"\xc9\xc3",  # leave ; ret
            b"\x48\x89\x07\xc3",  # mov [rdi], rax ; ret
            b"\x48\x83\xc4\x10\xc3",  # add rsp, 0x10 ; ret
            b"\x48\x83\xec\x10\xc3",  # sub rsp, 0x10 ; ret
            b"\x50\xc3",  # push rax ; ret
            b"\x9d\xc3",  # popfq ; ret
            b"\xff\xd0\xc3",  # call rax ; ret
            b"\x48\x89\xc4\xc3",  # mov rsp, rax ; ret
            b"\x48\x94\xc3",  # xchg rsp, rax ; ret
            b"\x0f\x05",  # syscall
            b"\xcd\x80",  # int 0x80
            b"\xc2\x10\x00",  # ret 0x10
        ]
    )
    return ElfBuilder(
        text=text,
        symbols=[Symbol("gadget_bank", ".text", 0, len(text))],
        pie=pie,
        nx=True,
        relro="partial",
    ).build()


def sample_x86_64_core() -> bytes:
    """Build a compact Linux ELF64 core with notes, code, stack, and frame chain."""

    register_names = (
        "r15",
        "r14",
        "r13",
        "r12",
        "rbp",
        "rbx",
        "r11",
        "r10",
        "r9",
        "r8",
        "rax",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "orig_rax",
        "rip",
        "cs",
        "eflags",
        "rsp",
        "ss",
        "fs_base",
        "gs_base",
        "ds",
        "es",
        "fs",
        "gs",
    )
    code_address = 0x400000
    stack_address = 0x7FFFFFFFD000

    prstatus = bytearray(336)
    struct.pack_into("<H", prstatus, 12, 11)
    struct.pack_into("<I", prstatus, 32, 4242)
    registers = {name: 0 for name in register_names}
    registers.update(
        {
            "rbp": stack_address + 0x40,
            "rip": code_address,
            "cs": 0x33,
            "eflags": 0x10202,
            "rsp": stack_address,
            "ss": 0x2B,
        }
    )
    for index, name in enumerate(register_names):
        struct.pack_into("<Q", prstatus, 112 + index * 8, registers[name])

    siginfo = bytearray(128)
    struct.pack_into("<iii", siginfo, 0, 11, 0, 1)
    struct.pack_into("<Q", siginfo, 16, 8)

    prpsinfo = bytearray(136)
    prpsinfo[40:47] = b"target\x00"
    prpsinfo[56:72] = b"./target input\x00"

    paths = b"/tmp/target\x00[stack]\x00"
    nt_file = bytearray(16 + 2 * 24 + len(paths))
    struct.pack_into("<QQ", nt_file, 0, 2, 4096)
    struct.pack_into("<QQQ", nt_file, 16, code_address, code_address + 0x100, 0)
    struct.pack_into("<QQQ", nt_file, 40, stack_address, stack_address + 0x100, 0)
    nt_file[64:] = paths

    def note(note_type: int, description: bytes) -> bytes:
        name = b"CORE\x00"
        value = bytearray(struct.pack("<III", len(name), len(description), note_type))
        value.extend(name)
        value.extend(b"\x00" * ((-len(value)) % 4))
        value.extend(description)
        value.extend(b"\x00" * ((-len(value)) % 4))
        return bytes(value)

    notes = b"".join(
        (
            note(1, prstatus),
            note(0x53494749, siginfo),
            note(3, prpsinfo),
            note(0x46494C45, nt_file),
        )
    )
    note_offset = 0x200
    code_offset = 0x600
    stack_offset = 0x700
    data = bytearray(stack_offset + 0x100)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        4,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        3,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ", data, 64, 4, 4, note_offset, 0, 0, len(notes), len(notes), 4
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        120,
        1,
        5,
        code_offset,
        code_address,
        0,
        0x100,
        0x100,
        0x1000,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        176,
        1,
        6,
        stack_offset,
        stack_address,
        0,
        0x100,
        0x100,
        0x1000,
    )
    data[note_offset : note_offset + len(notes)] = notes
    data[code_offset : code_offset + 0x100] = b"\xc3" + b"\x90" * 0xFF
    pattern = cyclic(160, n=8)[64:72]
    data[stack_offset : stack_offset + 8] = pattern
    struct.pack_into(
        "<QQ", data, stack_offset + 0x40, stack_address + 0x60, code_address + 0x10
    )
    struct.pack_into("<QQ", data, stack_offset + 0x60, 0, code_address + 0x20)
    return bytes(data)


def sample_x86_core() -> bytes:
    """Build a compact Linux ELF32 core for the supported i386 note layout."""

    register_names = (
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "ebp",
        "eax",
        "xds",
        "xes",
        "xfs",
        "xgs",
        "orig_eax",
        "eip",
        "xcs",
        "eflags",
        "esp",
        "xss",
    )
    code_address = 0x08048000
    stack_address = 0xFFFFD000

    prstatus = bytearray(144)
    struct.pack_into("<H", prstatus, 12, 11)
    struct.pack_into("<I", prstatus, 24, 31337)
    registers = {name: 0 for name in register_names}
    registers.update(
        {
            "ebp": stack_address + 0x20,
            "eip": code_address,
            "xcs": 0x23,
            "eflags": 0x10202,
            "esp": stack_address,
            "xss": 0x2B,
        }
    )
    for index, name in enumerate(register_names):
        struct.pack_into("<I", prstatus, 72 + index * 4, registers[name])

    siginfo = bytearray(128)
    struct.pack_into("<iiiI", siginfo, 0, 11, 0, 1, 0x10)
    prpsinfo = bytearray(124)
    prpsinfo[28:35] = b"target\x00"
    prpsinfo[44:60] = b"./target input\x00"
    paths = b"/tmp/target\x00[stack]\x00"
    nt_file = bytearray(8 + 2 * 12 + len(paths))
    struct.pack_into("<II", nt_file, 0, 2, 4096)
    struct.pack_into("<III", nt_file, 8, code_address, code_address + 0x80, 0)
    struct.pack_into("<III", nt_file, 20, stack_address, stack_address + 0x80, 0)
    nt_file[32:] = paths

    def note(note_type: int, description: bytes) -> bytes:
        name = b"CORE\x00"
        value = bytearray(struct.pack("<III", len(name), len(description), note_type))
        value.extend(name)
        value.extend(b"\x00" * ((-len(value)) % 4))
        value.extend(description)
        value.extend(b"\x00" * ((-len(value)) % 4))
        return bytes(value)

    notes = b"".join(
        (
            note(1, prstatus),
            note(0x53494749, siginfo),
            note(3, prpsinfo),
            note(0x46494C45, nt_file),
        )
    )
    note_offset = 0x100
    code_offset = 0x400
    stack_offset = 0x500
    data = bytearray(stack_offset + 0x80)
    data[:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        data,
        16,
        4,
        3,
        1,
        0,
        52,
        0,
        0,
        52,
        32,
        3,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIIIIIII", data, 52, 4, note_offset, 0, 0, len(notes), len(notes), 4, 4
    )
    struct.pack_into(
        "<IIIIIIII",
        data,
        84,
        1,
        code_offset,
        code_address,
        0,
        0x80,
        0x80,
        5,
        0x1000,
    )
    struct.pack_into(
        "<IIIIIIII",
        data,
        116,
        1,
        stack_offset,
        stack_address,
        0,
        0x80,
        0x80,
        6,
        0x1000,
    )
    data[note_offset : note_offset + len(notes)] = notes
    data[code_offset : code_offset + 0x80] = b"\xc3" + b"\x90" * 0x7F
    data[stack_offset : stack_offset + 4] = cyclic(120, n=4)[40:44]
    struct.pack_into(
        "<II", data, stack_offset + 0x20, stack_address + 0x30, code_address + 0x10
    )
    struct.pack_into("<II", data, stack_offset + 0x30, 0, code_address + 0x20)
    return bytes(data)
