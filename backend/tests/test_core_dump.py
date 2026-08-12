from __future__ import annotations

import struct

import pytest

from pwnable_lab.analyzer.core_dump import CoreLimits, analyze_core_dump
from pwnable_lab.errors import ParseError, UnsupportedFormatError
from tests.fixtures import sample_x86_64_core, sample_x86_core


def test_core_extracts_verified_notes_registers_memory_and_signal() -> None:
    result = analyze_core_dump(sample_x86_64_core())

    assert result["source"] == {
        "kind": "core_dump",
        "dialect": "linux-elf-core",
    }
    assert result["architecture"]["value"] == "x86_64"
    assert result["signal"]["value"] == "SIGSEGV"
    assert result["fault_address"]["value"] == 8
    assert result["instruction_pointer"]["value"] == 0x400000
    assert result["crash_instruction"]["instruction"] == "ret"
    assert result["process"]["name"] == "target"
    assert result["threads"][0]["thread_id"] == 4242
    assert {item["type"] for item in result["notes"]} == {
        "NT_PRSTATUS",
        "NT_SIGINFO",
        "NT_PRPSINFO",
        "NT_FILE",
    }


def test_core_stack_mapping_cyclic_match_and_frame_chain_are_bounded() -> None:
    result = analyze_core_dump(
        sample_x86_64_core(),
        limits=CoreLimits(max_stack_entries=4, max_backtrace_frames=8),
    )

    assert len(result["stack"]) == 4
    assert result["stack"][0]["classification"]["kind"] == "unmapped"
    assert result["mappings"][0]["kind"] == "executable"
    assert result["mappings"][1]["kind"] == "stack"
    assert result["probable_overflow_pattern"]["offset"] == 64
    assert result["probable_overflow_pattern"]["source"].startswith("stack:")
    assert [frame["address"] for frame in result["backtrace"]] == [
        0x400000,
        0x400010,
        0x400020,
    ]
    assert result["backtrace"][1]["verification"] == "inferred"
    assert result["probable_root_cause"]["type"] == "null_pointer_access"


def test_core_rejects_wrong_type_truncation_and_note_limit() -> None:
    with pytest.raises(UnsupportedFormatError):
        analyze_core_dump(b"not an elf")

    executable = bytearray(sample_x86_64_core())
    struct.pack_into("<H", executable, 16, 2)
    with pytest.raises(UnsupportedFormatError):
        analyze_core_dump(bytes(executable))

    with pytest.raises(ParseError):
        analyze_core_dump(sample_x86_64_core()[:-1])

    with pytest.raises(ParseError, match="note count"):
        analyze_core_dump(sample_x86_64_core(), limits=CoreLimits(max_notes=2))


def test_i386_core_uses_32_bit_register_note_and_pointer_width() -> None:
    result = analyze_core_dump(sample_x86_core())

    assert result["architecture"]["value"] == "x86"
    assert result["architecture"]["bits"] == 32
    assert result["instruction_pointer"]["register"] == "eip"
    assert result["stack_pointer"]["register"] == "esp"
    assert result["threads"][0]["thread_id"] == 31337
    assert result["fault_address"]["value"] == 0x10
    assert result["probable_overflow_pattern"]["offset"] == 40
    assert result["probable_overflow_pattern"]["pattern_width"] == 4
    assert len(result["backtrace"]) == 3


def test_instruction_at_end_of_file_backed_load_uses_available_bytes() -> None:
    core = bytearray(sample_x86_64_core())
    rip_register_offset = 0x200 + 20 + 112 + 16 * 8
    struct.pack_into("<Q", core, rip_register_offset, 0x4000FF)
    core[0x600 + 0xFF] = 0xC3

    result = analyze_core_dump(bytes(core))

    assert result["instruction_pointer"]["value"] == 0x4000FF
    assert result["crash_instruction"]["instruction"] == "ret"
    assert result["crash_instruction"]["bytes_hex"] == "c3"


def test_executable_load_and_frame_chain_do_not_require_nt_file_paths() -> None:
    core = bytearray(sample_x86_64_core())
    nt_file_type_offset = 0x200 + 356 + 148 + 156 + 8
    struct.pack_into("<I", core, nt_file_type_offset, 0xDEADBEEF)

    result = analyze_core_dump(bytes(core))

    assert result["mappings"][0]["path"] is None
    assert result["mappings"][0]["kind"] == "executable"
    assert result["mappings"][1]["kind"] == "stack"
    assert len(result["backtrace"]) == 3


def test_total_nt_file_mapping_limit_is_enforced_across_notes() -> None:
    core = bytearray(sample_x86_64_core())
    original_note_size = struct.unpack_from("<Q", core, 64 + 32)[0]
    original_notes = bytes(core[0x200 : 0x200 + original_note_size])
    nt_file_note = original_notes[356 + 148 + 156 :]
    insertion = 0x200 + original_note_size
    core[insertion : insertion + len(nt_file_note)] = nt_file_note
    new_note_size = original_note_size + len(nt_file_note)
    struct.pack_into("<Q", core, 64 + 32, new_note_size)
    struct.pack_into("<Q", core, 64 + 40, new_note_size)

    with pytest.raises(ParseError, match="전체 NT_FILE mapping"):
        analyze_core_dump(bytes(core), limits=CoreLimits(max_file_mappings=3))
