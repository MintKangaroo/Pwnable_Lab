from __future__ import annotations

from pwnable_lab.analyzer.crash_log import Limits, analyze_crash_log
from pwnable_lab.payload.cyclic import cyclic


def _gdb_log() -> str:
    pattern_value = int.from_bytes(cyclic(200)[72:80], "little")
    return f"""GNU gdb
(gdb) run
Program received signal SIGSEGV, Segmentation fault.
rax 0x0 0
rbp 0x4242424242424242 0x4242424242424242
rsp 0x7fffffffe000 0x7fffffffe000
rip {pattern_value:#x} {pattern_value:#x}
eflags 0x10206
=> 0x4011a2 <vuln+44>: ret
0x7fffffffe000: {pattern_value:#x} 0x40123a
0x7fffffffe010: 0x7ffff7e1a490 0x123456789abcde00
0x00400000 0x00402000 0x2000 0x0 r-xp /tmp/target
0x7ffff7dc0000 0x7ffff7fa0000 0x1e0000 0x0 r-xp /lib/libc.so.6
0x7ffffffde000 0x7ffffffff000 0x21000 0x0 rw-p [stack]
"""


def test_gdb_log_extracts_verified_state_and_inferred_root_cause() -> None:
    result = analyze_crash_log(_gdb_log())

    assert result["source"]["dialect"] == "gdb"
    assert result["architecture"] == {
        "value": "x86_64",
        "bits": 64,
        "verification": "inferred",
        "confidence": 0.95,
        "evidence": ["Register names in the supplied log"],
    }
    assert result["signal"]["value"] == "SIGSEGV"
    assert result["signal"]["verification"] == "verified"
    assert result["instruction_pointer"]["register"] == "rip"
    assert result["crash_instruction"]["symbol"] == "vuln+44"
    assert result["probable_overflow_pattern"]["offset"] == 72
    assert result["probable_overflow_pattern"]["verification"] == "verified"
    assert result["probable_root_cause"]["status"] == "likely"
    assert result["probable_root_cause"]["verification"] == "inferred"


def test_stack_pointer_mapping_and_canary_labels_remain_inferred() -> None:
    result = analyze_crash_log(_gdb_log())
    stack = result["stack"]

    assert stack[1]["classification"]["kind"] == "executable"
    assert stack[1]["labels"] == ["return_address_candidate"]
    assert stack[1]["interpretation_verification"] == "inferred"
    assert stack[2]["classification"]["kind"] == "libc"
    assert stack[3]["labels"] == ["canary_candidate"]
    assert stack[3]["confidence"] < 0.5


def test_proc_maps_and_low_fault_address() -> None:
    result = analyze_crash_log("""Program received signal SIGSEGV
eip 0x8048123
esp 0xffffd000
si_addr = 0x8
08048000-08049000 r-xp 00000000 08:01 123 /tmp/x
ffffd000-ffffe000 rw-p 00000000 00:00 0 [stack]
""")

    assert result["architecture"]["value"] == "x86"
    assert result["fault_address"]["value"] == 8
    assert result["mappings"][0]["kind"] == "executable"
    assert result["probable_root_cause"]["type"] == "null_pointer_access"
    assert result["probable_root_cause"]["status"] == "possible"


def test_incomplete_log_does_not_invent_crash_facts() -> None:
    result = analyze_crash_log("application stopped\nno register dump available")

    assert result["status"] == "partially_completed"
    assert result["signal"]["verification"] == "unknown"
    assert result["instruction_pointer"]["value"] is None
    assert result["probable_overflow_pattern"]["status"] == "unknown"
    assert result["probable_root_cause"]["type"] == "unknown"


def test_parser_bounds_lines_and_removes_ansi_sequences() -> None:
    result = analyze_crash_log(
        "\x1b[31mProgram received signal SIGSEGV\x1b[0m\nrip 0x401000\nextra",
        limits=Limits(max_lines=2, max_line_length=100, max_stack_entries=8),
    )

    assert result["signal"]["value"] == "SIGSEGV"
    assert result["instruction_pointer"]["value"] == 0x401000
    assert result["warnings"] == ["Only the first 2 lines were analyzed."]


def test_oversized_register_and_stack_values_do_not_crash_parser() -> None:
    huge = "f" * 128
    result = analyze_crash_log(
        f"Program terminated with signal SIGSEGV\nrip 0x{huge}\nrsp 0x1000\n"
        f"0x1000: 0x{huge}\n"
    )

    assert result["signal"]["value"] == "SIGSEGV"
    assert result["instruction_pointer"]["value_hex"] == f"0x{huge}"
    assert result["stack"][0]["ascii"] == "........"
    assert result["probable_overflow_pattern"]["status"] == "unknown"
