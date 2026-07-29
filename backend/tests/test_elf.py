"""ELF 빌더·파서 라운드트립 테스트."""

from __future__ import annotations

import pytest

from pwnable_lab.elf.builder import ElfBuilder, Symbol
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.errors import UnsupportedFormatError
from tests.fixtures import sample_elf


def test_roundtrip_header_and_symbols():
    img = parse_elf(sample_elf())
    assert img.bits == 64
    assert img.machine == "EM_X86_64"
    assert img.e_type == "ET_EXEC"
    assert img.symbol("win") is not None
    assert img.symbol("main").addr == img.entry


def test_rodata_bytes_recovered():
    img = parse_elf(sample_elf())
    assert b"FLAG{test}" in img.section_bytes(".rodata")


def test_pie_produces_dyn():
    img = parse_elf(sample_elf(pie=True))
    assert img.e_type == "ET_DYN"


def test_nx_toggle_via_gnu_stack():
    nx_off = parse_elf(sample_elf(nx=False))
    stack = [s for s in nx_off.segments if s.ptype == "PT_GNU_STACK"][0]
    assert stack.executable is True

    nx_on = parse_elf(sample_elf(nx=True))
    stack = [s for s in nx_on.segments if s.ptype == "PT_GNU_STACK"][0]
    assert stack.executable is False


def test_reject_non_elf():
    with pytest.raises(UnsupportedFormatError):
        parse_elf(b"not an elf at all")


def test_symbol_ordering_local_before_global():
    data = ElfBuilder(
        text=b"\xc3",
        symbols=[
            Symbol("g", ".text", 0, 1, binding=1),
            Symbol("l", ".text", 0, 1, binding=0),
        ],
    ).build()
    img = parse_elf(data)
    assert img.symbol("g").addr == img.symbol("l").addr
