"""분석기 테스트: checksec, vuln scan, gadgets, disasm, strings, got."""

from __future__ import annotations

from pwnable_lab.analyzer.checksec import run_checksec
from pwnable_lab.analyzer.disasm import disassemble
from pwnable_lab.analyzer.gadgets import find_gadgets, search_gadgets
from pwnable_lab.analyzer.got_plt import analyze_got_plt
from pwnable_lab.analyzer.strings import extract_strings
from pwnable_lab.analyzer.vuln_scan import scan_vulns
from pwnable_lab.elf.builder import ElfBuilder, Symbol
from pwnable_lab.elf.parser import parse_elf
from tests.fixtures import sample_elf


def test_checksec_all_on():
    cs = run_checksec(
        parse_elf(sample_elf(nx=True, pie=True, relro="full", canary=True))
    )
    assert cs.nx is True
    assert cs.pie == "PIE"
    assert cs.relro == "Full"
    assert cs.canary is True


def test_checksec_all_off():
    cs = run_checksec(
        parse_elf(sample_elf(nx=False, pie=False, relro="none", canary=False))
    )
    assert cs.nx is False
    assert cs.pie == "No PIE"
    assert cs.relro == "No"
    assert cs.canary is False


def test_vuln_scan_detects_and_ranks():
    data = ElfBuilder(
        text=b"\xc3",
        symbols=[
            Symbol("gets", ".text", 0, 0),
            Symbol("printf", ".text", 0, 0),
            Symbol("system", ".text", 0, 0),
        ],
    ).build()
    findings = scan_vulns(parse_elf(data))
    names = [f.symbol for f in findings]
    assert "gets" in names and "system" in names and "printf" in names
    # critical 이 먼저
    assert findings[0].severity == "critical"


def test_gadget_finder_finds_pop_rdi():
    img = parse_elf(sample_elf())
    gadgets = find_gadgets(img)
    hits = [
        g
        for g in search_gadgets(gadgets, "pop rdi ; ret")
        if g.instructions == ["pop rdi", "ret"]
    ]
    assert hits, "pop rdi ; ret 가젯을 찾지 못함"


def test_gadget_max_gadgets_limit():
    img = parse_elf(sample_elf())
    gadgets = find_gadgets(img, max_gadgets=1)
    assert len(gadgets) <= 1


def test_disassemble_from_entry():
    img = parse_elf(sample_elf())
    insns = disassemble(img, count=5)
    assert insns[0].mnemonic == "sub"  # sub rsp, 0x20


def test_strings_ascii_and_utf16():
    data = b"hello world\x00" + "안".encode("utf-16le") + b"A\x00B\x00C\x00D\x00\x00"
    strings = extract_strings(data, min_length=4)
    values = [s.value for s in strings]
    assert "hello world" in values
    assert any(s.encoding == "utf-16le" for s in strings)


def test_got_plt_graceful_empty():
    report = analyze_got_plt(parse_elf(sample_elf()))
    assert report.sections == []  # 정적 학습 바이너리에는 GOT/PLT 없음
