"""JOP/COP 간접 분기 가젯 종단(F-CRIT-2 회귀) 단위 테스트.

capstone 만으로 결정적으로 검증하므로 gcc/ELF 가 필요 없다.
"""

from __future__ import annotations

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from pwnable_lab.analyzer.gadgets import _indirect_terminals, _is_terminal


def _engine() -> Cs:
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    return engine


def _decode_one(engine: Cs, code: bytes):
    return next(iter(engine.disasm(code, 0)))


def test_is_terminal_accepts_indirect_branches():
    engine = _engine()
    assert _is_terminal(_decode_one(engine, b"\xff\xe0"))  # jmp rax
    assert _is_terminal(_decode_one(engine, b"\xff\xd0"))  # call rax
    assert _is_terminal(_decode_one(engine, b"\xff\x20"))  # jmp qword [rax]
    assert _is_terminal(_decode_one(engine, b"\xff\x10"))  # call qword [rax]


def test_is_terminal_rejects_relative_branches():
    engine = _engine()
    # 상대 분기는 제어를 뺏기지 않으므로 종단 아님.
    assert not _is_terminal(_decode_one(engine, b"\xeb\xfe"))  # jmp .-2 (rel8)
    assert not _is_terminal(_decode_one(engine, b"\xe9\x00\x00\x00\x00"))  # jmp rel32
    assert not _is_terminal(_decode_one(engine, b"\xe8\x00\x00\x00\x00"))  # call rel32


def test_indirect_terminals_finds_jmp_and_call_reg():
    engine = _engine()
    # pop rdi (5f) ; jmp rax (ff e0)  →  종단은 인덱스 1..3
    blob = b"\x5f\xff\xe0"
    terminals = list(_indirect_terminals(engine, blob))
    assert (1, 3) in terminals  # jmp rax at index 1, size 2

    # call rax (ff d0) 단독
    assert list(_indirect_terminals(engine, b"\xff\xd0")) == [(0, 2)]


def test_indirect_terminals_handles_rex_prefixed_branch():
    engine = _engine()
    # jmp r8 = 41 ff e0 : REX.B(0x41) + ff e0
    blob = b"\x41\xff\xe0"
    terminals = list(_indirect_terminals(engine, blob))
    assert (0, 3) in terminals


def test_indirect_terminals_ignores_non_branch_ff():
    engine = _engine()
    # inc dword [rax] = ff 00 : ModRM reg 필드 0 → call/jmp 아님.
    assert list(_indirect_terminals(engine, b"\xff\x00")) == []
