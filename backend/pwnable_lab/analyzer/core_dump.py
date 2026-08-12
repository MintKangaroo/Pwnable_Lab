"""Bounded, non-executing Linux ELF core-dump analysis for x86 and x86-64."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Literal

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    Cs,
    CsError,
)

from pwnable_lab.errors import ParseError, UnsupportedFormatError
from pwnable_lab.payload.cyclic import cyclic

ANALYZER_NAME = "linux_elf_core"
ANALYZER_VERSION = "1.0.0"

_PT_LOAD = 1
_PT_NOTE = 4
_ET_CORE = 4
_EM_386 = 3
_EM_X86_64 = 62
_NT_PRSTATUS = 1
_NT_PRPSINFO = 3
_NT_AUXV = 6
_NT_SIGINFO = 0x53494749
_NT_FILE = 0x46494C45

_SIGNALS = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}

_REGISTERS_64 = (
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
_REGISTERS_32 = (
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

ByteOrder = Literal["little", "big"]


@dataclass(frozen=True)
class CoreLimits:
    max_program_headers: int = 4096
    max_notes: int = 4096
    max_note_bytes: int = 8 * 1024 * 1024
    max_file_mappings: int = 8192
    max_stack_entries: int = 4096
    max_backtrace_frames: int = 64


@dataclass(frozen=True)
class LoadSegment:
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int


@dataclass(frozen=True)
class NoteSegment:
    offset: int
    size: int


def analyze_core_dump(
    data: bytes, *, limits: CoreLimits | None = None
) -> dict[str, Any]:
    limits = limits or CoreLimits()
    header = _parse_header(data, limits)
    bits = header["bits"]
    endian = header["endian"]
    loads, note_segments = _parse_program_headers(data, header, limits)
    notes = _parse_notes(data, note_segments, endian=endian, limits=limits)

    threads = [
        parsed
        for note in notes
        if note["type_id"] == _NT_PRSTATUS
        and (parsed := _parse_prstatus(note["description"], bits, endian)) is not None
    ]
    if not threads:
        raise ParseError("ELF core에 유효한 NT_PRSTATUS register note가 없습니다.")
    crashing_thread = next(
        (thread for thread in threads if thread["signal_number"]), threads[0]
    )
    registers: dict[str, int] = crashing_thread["register_values"]
    ip_name, sp_name, bp_name = (
        ("rip", "rsp", "rbp") if bits == 64 else ("eip", "esp", "ebp")
    )
    ip = registers[ip_name]
    sp = registers[sp_name]
    bp = registers[bp_name]

    file_mappings: list[dict[str, Any]] = []
    siginfo: dict[str, int] | None = None
    process: dict[str, Any] | None = None
    for note in notes:
        if note["type_id"] == _NT_FILE:
            parsed_mappings = _parse_nt_file(note["description"], bits, endian, limits)
            if len(file_mappings) + len(parsed_mappings) > limits.max_file_mappings:
                raise ParseError(
                    "ELF core의 전체 NT_FILE mapping 수가 상한을 초과했습니다."
                )
            file_mappings.extend(parsed_mappings)
        elif note["type_id"] == _NT_SIGINFO and siginfo is None:
            siginfo = _parse_siginfo(note["description"], bits, endian)
        elif note["type_id"] == _NT_PRPSINFO and process is None:
            process = _parse_prpsinfo(note["description"], bits, endian)

    mappings = _build_mappings(loads, file_mappings, stack_pointer=sp)
    stack = _parse_stack(
        data,
        loads,
        mappings,
        stack_pointer=sp,
        bits=bits,
        endian=endian,
        limit=limits.max_stack_entries,
    )
    register_items = [
        {
            "name": name,
            "value": value,
            "value_hex": hex(value),
            "classification": _classify_pointer(value, mappings),
            "verification": "verified",
            "confidence": 1.0,
            "evidence": [
                f"Read from NT_PRSTATUS for thread {crashing_thread['thread_id']}"
            ],
        }
        for name, value in registers.items()
    ]
    signal_number = (
        siginfo["signal_number"]
        if siginfo and siginfo["signal_number"]
        else crashing_thread["signal_number"]
    )
    signal_name = _SIGNALS.get(signal_number, f"SIG{signal_number}")
    fault_address = siginfo.get("fault_address") if siginfo else None
    crash_instruction = _decode_instruction(data, loads, ip, bits)
    cyclic_match = _find_cyclic(registers, stack, bits)
    root_cause = _infer_root_cause(
        signal_name,
        fault_address,
        cyclic_match,
        crash_instruction.get("instruction"),
    )
    backtrace = _walk_frame_chain(
        data,
        loads,
        mappings,
        instruction_pointer=ip,
        base_pointer=bp,
        bits=bits,
        endian=endian,
        limit=limits.max_backtrace_frames,
    )

    note_summary = [
        {
            "name": note["name"],
            "type": _note_name(note["type_id"]),
            "type_id": note["type_id"],
            "description_size": len(note["description"]),
            "verification": "verified",
        }
        for note in notes
    ]
    return {
        "analyzer_name": ANALYZER_NAME,
        "analyzer_version": ANALYZER_VERSION,
        "status": "completed",
        "error": None,
        "confidence": 0.97,
        "evidence": [
            "ELF magic, ET_CORE type, program headers, and file-backed ranges validated",
            f"Parsed {len(notes)} bounded ELF notes without executing the target",
        ],
        "source": {"kind": "core_dump", "dialect": "linux-elf-core"},
        "architecture": {
            "value": "x86_64" if bits == 64 else "x86",
            "bits": bits,
            "endian": endian,
            "verification": "verified",
            "confidence": 1.0,
            "evidence": ["ELF class, data encoding, and e_machine"],
        },
        "signal": {
            "value": signal_name,
            "number": signal_number,
            "verification": "verified",
            "confidence": 1.0,
            "evidence": ["NT_SIGINFO or NT_PRSTATUS current signal"],
        },
        "fault_address": _observed_address(
            fault_address,
            "NT_SIGINFO siginfo_t fault address",
        ),
        "instruction_pointer": _register_pointer(ip_name, ip, crashing_thread),
        "stack_pointer": _register_pointer(sp_name, sp, crashing_thread),
        "base_pointer": _register_pointer(bp_name, bp, crashing_thread),
        "crash_instruction": crash_instruction,
        "registers": register_items,
        "stack": stack,
        "mappings": mappings,
        "backtrace": backtrace,
        "threads": [
            {
                "thread_id": thread["thread_id"],
                "signal_number": thread["signal_number"],
                "instruction_pointer": hex(thread["register_values"][ip_name]),
                "stack_pointer": hex(thread["register_values"][sp_name]),
                "verification": "verified",
            }
            for thread in threads
        ],
        "process": process,
        "notes": note_summary,
        "probable_overflow_pattern": cyclic_match,
        "probable_root_cause": root_cause,
        "warnings": [],
        "limitations": [
            "Only Linux x86/x86-64 ELF core layouts are supported in this increment.",
            "Frame-pointer backtraces are inferred and may be incomplete for optimized or corrupted frames.",
            "Core memory reflects the captured process, but symbol names require separate module analysis.",
            "Canary and return-address labels are heuristic candidates, never confirmed values.",
        ],
    }


def _parse_header(data: bytes, limits: CoreLimits) -> dict[str, Any]:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise UnsupportedFormatError("Linux ELF core magic이 아닙니다.")
    elf_class = data[4]
    encoding = data[5]
    if elf_class not in {1, 2} or encoding not in {1, 2}:
        raise ParseError("유효하지 않은 ELF class 또는 data encoding입니다.")
    bits = 64 if elf_class == 2 else 32
    endian = "little" if encoding == 1 else "big"
    prefix = "<" if endian == "little" else ">"
    minimum = 64 if bits == 64 else 52
    if len(data) < minimum:
        raise ParseError("ELF core header가 잘렸습니다.")
    e_type, machine = struct.unpack_from(f"{prefix}HH", data, 16)
    if e_type != _ET_CORE:
        raise UnsupportedFormatError("ELF 파일이지만 ET_CORE 타입이 아닙니다.")
    if machine not in {_EM_386, _EM_X86_64}:
        raise UnsupportedFormatError(
            f"현재 core analyzer는 x86/x86-64만 지원합니다: e_machine={machine}"
        )
    if (machine == _EM_X86_64) != (bits == 64) or endian != "little":
        raise UnsupportedFormatError("지원하지 않는 x86 ELF class/data 조합입니다.")
    if bits == 64:
        phoff = struct.unpack_from(f"{prefix}Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(f"{prefix}HH", data, 54)
        expected_phentsize = 56
    else:
        phoff = struct.unpack_from(f"{prefix}I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(f"{prefix}HH", data, 42)
        expected_phentsize = 32
    if phnum == 0xFFFF:
        raise UnsupportedFormatError(
            "extended program-header count는 아직 지원하지 않습니다."
        )
    if phnum == 0 or phnum > limits.max_program_headers:
        raise ParseError(f"program-header count가 허용 범위를 벗어났습니다: {phnum}")
    if phentsize < expected_phentsize:
        raise ParseError("ELF program-header entry가 너무 작습니다.")
    if phoff > len(data) or phnum * phentsize > len(data) - phoff:
        raise ParseError("ELF program-header table이 파일 범위를 벗어납니다.")
    return {
        "bits": bits,
        "endian": endian,
        "prefix": prefix,
        "machine": machine,
        "phoff": phoff,
        "phentsize": phentsize,
        "phnum": phnum,
    }


def _parse_program_headers(
    data: bytes, header: dict[str, Any], limits: CoreLimits
) -> tuple[list[LoadSegment], list[NoteSegment]]:
    del limits
    loads: list[LoadSegment] = []
    notes: list[NoteSegment] = []
    prefix = header["prefix"]
    for index in range(header["phnum"]):
        offset = header["phoff"] + index * header["phentsize"]
        if header["bits"] == 64:
            values = struct.unpack_from(f"{prefix}IIQQQQQQ", data, offset)
            ptype, flags, file_offset, vaddr, _paddr, filesz, memsz, _align = values
        else:
            values = struct.unpack_from(f"{prefix}IIIIIIII", data, offset)
            ptype, file_offset, vaddr, _paddr, filesz, memsz, flags, _align = values
        if filesz > len(data) or file_offset > len(data) - filesz:
            raise ParseError(
                f"program header {index} file range가 core 범위를 벗어납니다."
            )
        if ptype == _PT_LOAD:
            if memsz < filesz:
                raise ParseError(f"PT_LOAD {index}의 memsz가 filesz보다 작습니다.")
            loads.append(LoadSegment(file_offset, vaddr, filesz, memsz, flags))
        elif ptype == _PT_NOTE:
            notes.append(NoteSegment(file_offset, filesz))
    if not loads:
        raise ParseError("ELF core에 PT_LOAD memory segment가 없습니다.")
    if not notes:
        raise ParseError("ELF core에 PT_NOTE segment가 없습니다.")
    return loads, notes


def _parse_notes(
    data: bytes,
    segments: list[NoteSegment],
    *,
    endian: ByteOrder,
    limits: CoreLimits,
) -> list[dict[str, Any]]:
    prefix = "<" if endian == "little" else ">"
    notes: list[dict[str, Any]] = []
    for segment in segments:
        cursor = segment.offset
        end = segment.offset + segment.size
        while cursor + 12 <= end:
            namesz, descsz, note_type = struct.unpack_from(f"{prefix}III", data, cursor)
            if namesz == 0 and descsz == 0 and note_type == 0:
                break
            if len(notes) >= limits.max_notes:
                raise ParseError(
                    f"ELF note count가 상한 {limits.max_notes}을 초과했습니다."
                )
            if namesz > 4096 or descsz > limits.max_note_bytes:
                raise ParseError(
                    "ELF note name/description이 허용 크기를 초과했습니다."
                )
            name_start = cursor + 12
            desc_start = _align4(name_start + namesz)
            next_note = _align4(desc_start + descsz)
            if desc_start > end or next_note > end:
                raise ParseError("ELF note가 PT_NOTE file range를 벗어납니다.")
            raw_name = data[name_start : name_start + namesz].split(b"\x00", 1)[0]
            name = raw_name.decode("utf-8", errors="replace")
            name = "".join(char for char in name if char.isprintable())[:128]
            notes.append(
                {
                    "name": name or None,
                    "type_id": note_type,
                    "description": data[desc_start : desc_start + descsz],
                }
            )
            cursor = next_note
    return notes


def _parse_prstatus(
    description: bytes, bits: int, endian: ByteOrder
) -> dict[str, Any] | None:
    prefix = "<" if endian == "little" else ">"
    names: tuple[str, ...]
    if bits == 64:
        register_offset, thread_offset, width, names = 112, 32, 8, _REGISTERS_64
    else:
        register_offset, thread_offset, width, names = 72, 24, 4, _REGISTERS_32
    required = register_offset + width * len(names)
    if len(description) < required:
        return None
    signal_number = struct.unpack_from(f"{prefix}H", description, 12)[0]
    thread_id = struct.unpack_from(f"{prefix}I", description, thread_offset)[0]
    registers = {
        name: int.from_bytes(
            description[
                register_offset + index * width : register_offset + (index + 1) * width
            ],
            endian,
        )
        for index, name in enumerate(names)
    }
    return {
        "thread_id": thread_id,
        "signal_number": signal_number,
        "register_values": registers,
    }


def _parse_siginfo(
    description: bytes, bits: int, endian: ByteOrder
) -> dict[str, int] | None:
    address_offset = 16 if bits == 64 else 12
    width = bits // 8
    if len(description) < address_offset + width:
        return None
    prefix = "<" if endian == "little" else ">"
    signal_number, error_number, signal_code = struct.unpack_from(
        f"{prefix}iii", description, 0
    )
    fault_address = int.from_bytes(
        description[address_offset : address_offset + width], endian
    )
    return {
        "signal_number": signal_number,
        "error_number": error_number,
        "signal_code": signal_code,
        "fault_address": fault_address,
    }


def _parse_prpsinfo(
    description: bytes, bits: int, endian: ByteOrder
) -> dict[str, Any] | None:
    del endian
    name_offset = 40 if bits == 64 else 28
    args_offset = name_offset + 16
    if len(description) < args_offset:
        return None
    name = _bounded_cstring(description[name_offset : name_offset + 16])
    arguments = _bounded_cstring(description[args_offset : args_offset + 80])
    return {
        "name": name or None,
        "arguments": arguments or None,
        "verification": "verified",
        "evidence": ["NT_PRPSINFO fixed-size process fields"],
    }


def _parse_nt_file(
    description: bytes, bits: int, endian: ByteOrder, limits: CoreLimits
) -> list[dict[str, Any]]:
    width = bits // 8
    if len(description) < width * 2:
        return []
    count = int.from_bytes(description[:width], endian)
    page_size = int.from_bytes(description[width : width * 2], endian)
    if count > limits.max_file_mappings:
        raise ParseError(f"NT_FILE mapping count가 상한을 초과했습니다: {count}")
    entries_start = width * 2
    names_start = entries_start + count * width * 3
    if names_start > len(description):
        raise ParseError("NT_FILE entry array가 note 범위를 벗어납니다.")
    names = description[names_start:].split(b"\x00")
    mappings: list[dict[str, Any]] = []
    for index in range(count):
        cursor = entries_start + index * width * 3
        start = int.from_bytes(description[cursor : cursor + width], endian)
        end = int.from_bytes(description[cursor + width : cursor + width * 2], endian)
        page_offset = int.from_bytes(
            description[cursor + width * 2 : cursor + width * 3], endian
        )
        if end <= start:
            continue
        raw_name = names[index] if index < len(names) else b""
        path = _bounded_cstring(raw_name[:4096])
        mappings.append(
            {
                "start": start,
                "end": end,
                "file_offset": page_offset * page_size,
                "path": path or None,
            }
        )
    return mappings


def _build_mappings(
    loads: list[LoadSegment],
    file_mappings: list[dict[str, Any]],
    *,
    stack_pointer: int,
) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for load in sorted(loads, key=lambda segment: segment.vaddr):
        end = load.vaddr + load.memsz
        file_mapping = next(
            (
                item
                for item in file_mappings
                if item["start"] < end and item["end"] > load.vaddr
            ),
            None,
        )
        path = file_mapping["path"] if file_mapping else None
        permissions = "".join(
            (
                "r" if load.flags & 4 else "-",
                "w" if load.flags & 2 else "-",
                "x" if load.flags & 1 else "-",
                "p",
            )
        )
        kind = _mapping_kind(path, permissions)
        if load.vaddr <= stack_pointer < end:
            kind = "stack"
            path = path or "[stack]"
        mappings.append(
            {
                "start": load.vaddr,
                "end": end,
                "start_hex": hex(load.vaddr),
                "end_hex": hex(end),
                "size": load.memsz,
                "file_size": load.filesz,
                "core_offset": load.offset,
                "offset": file_mapping["file_offset"] if file_mapping else 0,
                "permissions": permissions,
                "path": path,
                "kind": kind,
                "verification": "verified",
                "confidence": 1.0,
                "evidence": [
                    "Address and permissions from PT_LOAD"
                    + ("; path and file offset from NT_FILE" if file_mapping else "")
                ],
            }
        )
    return mappings


def _mapping_kind(path: str | None, permissions: str) -> str:
    lowered = (path or "").lower()
    if "[stack" in lowered:
        return "stack"
    if lowered == "[heap]":
        return "heap"
    if "libc" in lowered:
        return "libc"
    if "ld-linux" in lowered or "ld-musl" in lowered or "/ld-" in lowered:
        return "loader"
    if "x" in permissions:
        return "executable"
    if path:
        return "mapped_file"
    return "anonymous"


def _parse_stack(
    data: bytes,
    loads: list[LoadSegment],
    mappings: list[dict[str, Any]],
    *,
    stack_pointer: int,
    bits: int,
    endian: ByteOrder,
    limit: int,
) -> list[dict[str, Any]]:
    width = bits // 8
    entries: list[dict[str, Any]] = []
    for index in range(limit):
        address = stack_pointer + index * width
        raw = _read_memory(data, loads, address, width)
        if raw is None:
            break
        value = int.from_bytes(raw, endian)
        classification = _classify_pointer(value, mappings)
        labels: list[str] = []
        confidence = 1.0
        if classification["kind"] in {"executable", "libc", "loader"} and "x" in str(
            classification.get("permissions", "")
        ):
            labels.append("return_address_candidate")
            confidence = 0.55
        if _is_canary_candidate(value, bits, address, stack_pointer, classification):
            labels.append("canary_candidate")
            confidence = min(confidence, 0.35)
        entries.append(
            {
                "address": address,
                "address_hex": hex(address),
                "value": value,
                "value_hex": hex(value),
                "offset_from_sp": index * width,
                "ascii": "".join(
                    chr(byte) if 32 <= byte < 127 else "." for byte in raw
                ),
                "classification": classification,
                "labels": labels,
                "verification": "verified",
                "interpretation_verification": (
                    "inferred"
                    if labels or classification["kind"] != "unmapped"
                    else "unknown"
                ),
                "confidence": confidence,
                "evidence": [
                    "Pointer-sized bytes read from file-backed PT_LOAD memory"
                ],
            }
        )
    return entries


def _read_memory(
    data: bytes, loads: list[LoadSegment], address: int, size: int
) -> bytes | None:
    for load in loads:
        if load.vaddr <= address and address + size <= load.vaddr + load.filesz:
            offset = load.offset + address - load.vaddr
            return data[offset : offset + size]
    return None


def _read_memory_prefix(
    data: bytes, loads: list[LoadSegment], address: int, max_size: int
) -> bytes | None:
    """Read available file-backed bytes without requiring the full requested window."""

    for load in loads:
        file_end = load.vaddr + load.filesz
        if load.vaddr <= address < file_end:
            size = min(max_size, file_end - address)
            offset = load.offset + address - load.vaddr
            return data[offset : offset + size]
    return None


def _classify_pointer(value: int, mappings: list[dict[str, Any]]) -> dict[str, Any]:
    if value == 0:
        return {
            "kind": "null",
            "mapping": None,
            "permissions": None,
            "verification": "inferred",
            "confidence": 1.0,
        }
    for mapping in mappings:
        if mapping["start"] <= value < mapping["end"]:
            return {
                "kind": mapping["kind"],
                "mapping": mapping["path"],
                "permissions": mapping["permissions"],
                "offset": value - mapping["start"],
                "verification": "inferred",
                "confidence": 0.98,
            }
    return {
        "kind": "unmapped",
        "mapping": None,
        "permissions": None,
        "verification": "unknown",
        "confidence": 0.2,
    }


def _is_canary_candidate(
    value: int,
    bits: int,
    address: int,
    stack_pointer: int,
    classification: dict[str, Any],
) -> bool:
    return (
        bits == 64
        and value != 0
        and value & 0xFF == 0
        and classification["kind"] == "unmapped"
        and 0 <= address - stack_pointer <= 0x400
        and value.bit_length() >= 40
    )


def _decode_instruction(
    data: bytes, loads: list[LoadSegment], instruction_pointer: int, bits: int
) -> dict[str, Any]:
    raw = _read_memory_prefix(data, loads, instruction_pointer, 16)
    if raw is None:
        return {
            "address": instruction_pointer,
            "address_hex": hex(instruction_pointer),
            "symbol": None,
            "instruction": None,
            "bytes_hex": None,
            "verification": "unknown",
            "confidence": 0.0,
            "evidence": ["Instruction pointer is not in file-backed PT_LOAD bytes"],
        }
    try:
        decoder = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
        instruction = next(decoder.disasm(raw, instruction_pointer, count=1), None)
    except CsError:
        instruction = None
    if instruction is None:
        return {
            "address": instruction_pointer,
            "address_hex": hex(instruction_pointer),
            "symbol": None,
            "instruction": None,
            "bytes_hex": raw.hex(),
            "verification": "unknown",
            "confidence": 0.0,
            "evidence": [
                "Core bytes were present but Capstone did not decode an instruction"
            ],
        }
    text = f"{instruction.mnemonic} {instruction.op_str}".strip()
    return {
        "address": instruction_pointer,
        "address_hex": hex(instruction_pointer),
        "symbol": None,
        "instruction": text,
        "bytes_hex": bytes(instruction.bytes).hex(),
        "verification": "verified",
        "confidence": 1.0,
        "evidence": ["Capstone decoded file-backed PT_LOAD bytes at the verified IP"],
    }


def _walk_frame_chain(
    data: bytes,
    loads: list[LoadSegment],
    mappings: list[dict[str, Any]],
    *,
    instruction_pointer: int,
    base_pointer: int,
    bits: int,
    endian: ByteOrder,
    limit: int,
) -> list[dict[str, Any]]:
    frames = [
        {
            "index": 0,
            "address": instruction_pointer,
            "address_hex": hex(instruction_pointer),
            "frame_pointer": hex(base_pointer),
            "verification": "verified",
            "confidence": 1.0,
            "evidence": ["Current IP and BP from NT_PRSTATUS"],
        }
    ]
    width = bits // 8
    current = base_pointer
    for index in range(1, limit):
        raw = _read_memory(data, loads, current, width * 2)
        if raw is None:
            break
        next_frame = int.from_bytes(raw[:width], endian)
        return_address = int.from_bytes(raw[width:], endian)
        classification = _classify_pointer(return_address, mappings)
        if classification["kind"] not in {"executable", "libc", "loader"}:
            break
        frames.append(
            {
                "index": index,
                "address": return_address,
                "address_hex": hex(return_address),
                "frame_pointer": hex(current),
                "verification": "inferred",
                "confidence": 0.72,
                "evidence": [
                    "Return address read from a monotonic frame-pointer chain and mapped executable memory"
                ],
            }
        )
        if (
            next_frame <= current
            or next_frame - current > 1024 * 1024
            or next_frame % width
            or _classify_pointer(next_frame, mappings)["kind"] != "stack"
        ):
            break
        current = next_frame
    return frames


def _find_cyclic(
    registers: dict[str, int], stack: list[dict[str, Any]], bits: int
) -> dict[str, Any]:
    sources: list[tuple[str, int]] = []
    for name in ("rip", "eip", "rbp", "ebp"):
        if name in registers:
            sources.append((name, registers[name]))
    sources.extend(
        (f"stack:{item['address_hex']}", item["value"]) for item in stack[:256]
    )
    width = bits // 8
    # Prefer the full pointer-width match. The first four bytes of an n=8 pattern can
    # also appear in the n=4 pattern at a different offset, which would otherwise
    # produce a misleading but superficially valid offset.
    patterns = [(8, cyclic(65_536, n=8))] if width == 8 else []
    patterns.append((4, cyclic(65_536, n=4)))
    for source, value in sources:
        raw = (value & ((1 << bits) - 1)).to_bytes(width, "little")
        for pattern_width, pattern in patterns:
            offset = pattern.find(raw[:pattern_width])
            if offset >= 0:
                return {
                    "status": "likely",
                    "offset": offset,
                    "subsequence_hex": raw[:pattern_width].hex(),
                    "pattern_width": pattern_width,
                    "source": source,
                    "verification": "verified",
                    "confidence": 0.99,
                    "evidence": [
                        f"Core bytes from {source} match the bounded De Bruijn pattern at offset {offset}"
                    ],
                    "constraints": [
                        "The offset is valid only if the crashing input used the same alphabet and subsequence width."
                    ],
                }
    return {
        "status": "unknown",
        "offset": None,
        "subsequence_hex": None,
        "pattern_width": None,
        "source": None,
        "verification": "unknown",
        "confidence": 0.0,
        "evidence": [],
        "constraints": [],
    }


def _infer_root_cause(
    signal: str,
    fault_address: int | None,
    cyclic_match: dict[str, Any],
    instruction: str | None,
) -> dict[str, Any]:
    if cyclic_match["offset"] is not None and cyclic_match["source"] in {"rip", "eip"}:
        return {
            "type": "instruction_pointer_overwrite",
            "status": "likely",
            "summary": "A cyclic input pattern appears in the core instruction pointer.",
            "verification": "inferred",
            "confidence": 0.97,
            "evidence": cyclic_match["evidence"],
            "recommended_next_steps": [
                "Confirm the pattern alphabet and width used for the crashing input.",
                "Inspect the stack frame and attached binary around the overwrite site.",
            ],
        }
    if signal == "SIGSEGV" and fault_address is not None and fault_address < 0x1000:
        return {
            "type": "null_pointer_access",
            "status": "possible",
            "summary": "SIGSEGV recorded a low fault address in NT_SIGINFO.",
            "verification": "inferred",
            "confidence": 0.68,
            "evidence": [f"Verified core fault address {hex(fault_address)}"],
            "recommended_next_steps": [
                "Inspect the decoded instruction and its memory operand."
            ],
        }
    if signal == "SIGSEGV" and instruction and instruction.startswith("ret"):
        return {
            "type": "corrupted_return_address",
            "status": "possible",
            "summary": "The process faulted at a return instruction, but overwrite control is not proven.",
            "verification": "inferred",
            "confidence": 0.58,
            "evidence": [f"Verified crash instruction: {instruction}"],
            "recommended_next_steps": [
                "Inspect stack return-address candidates and compare them with the original binary."
            ],
        }
    return {
        "type": "invalid_memory_access" if signal == "SIGSEGV" else "process_signal",
        "status": "possible",
        "summary": f"The core records {signal}; available evidence does not prove the root cause.",
        "verification": "inferred",
        "confidence": 0.42,
        "evidence": [f"Verified core signal {signal}"],
        "recommended_next_steps": [
            "Inspect the fault address, current instruction, mappings, and inferred frame chain."
        ],
    }


def _observed_address(value: int | None, evidence: str) -> dict[str, Any]:
    return {
        "value": value,
        "value_hex": hex(value) if value is not None else None,
        "verification": "verified" if value is not None else "unknown",
        "confidence": 1.0 if value is not None else 0.0,
        "evidence": [evidence] if value is not None else [],
    }


def _register_pointer(name: str, value: int, thread: dict[str, Any]) -> dict[str, Any]:
    return {
        "register": name,
        "value": value,
        "value_hex": hex(value),
        "verification": "verified",
        "confidence": 1.0,
        "evidence": [f"NT_PRSTATUS register for thread {thread['thread_id']}"],
    }


def _note_name(note_type: int) -> str:
    return {
        _NT_PRSTATUS: "NT_PRSTATUS",
        _NT_PRPSINFO: "NT_PRPSINFO",
        _NT_AUXV: "NT_AUXV",
        _NT_SIGINFO: "NT_SIGINFO",
        _NT_FILE: "NT_FILE",
    }.get(note_type, f"UNKNOWN_{hex(note_type)}")


def _bounded_cstring(value: bytes) -> str:
    decoded = value.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return "".join(char for char in decoded if char.isprintable())


def _align4(value: int) -> int:
    return (value + 3) & ~3
