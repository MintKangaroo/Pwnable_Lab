"""one_gadget 정적 탐지: libc 안의 원샷 execve("/bin/sh") 가젯 찾기."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # type: ignore[import-untyped]

from pwnable_lab.analyzer.one_gadget import (
    OneGadget,
    _constraints,
    _scan_execve,
    find_one_gadgets,
)
from pwnable_lab.analyzer.strategy import find_string
from pwnable_lab.elf.parser import parse_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None
_LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
_HAVE_LIBC = os.path.exists(_LIBC)


def test_constraints_helper():
    assert _constraints(True, True) == ["추가 제약 없음(rsi/rdx 가 NULL 로 설정됨)."]
    c = _constraints(False, True)
    assert any("rsi" in x for x in c)
    c2 = _constraints(True, False)
    assert any("rdx" in x for x in c2)


def test_one_gadget_dataclass_serializes():
    g = OneGadget(offset=0xEBC48, execve_via="call", constraints=["x"])
    d = g.as_dict()
    assert d["offset"] == 0xEBC48
    assert d["offset_hex"] == "0xebc48"
    assert d["execve_via"] == "call"


def _insns(code: bytes):
    return list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, 0x1000))


def test_scan_execve_syscall_path_no_constraints():
    # lea rdi,[rip+0]; xor esi,esi; xor edx,edx; mov eax,0x3b; syscall
    code = bytes.fromhex("488d3d00000000" "31f6" "31d2" "b83b000000" "0f05")
    g = _scan_execve(_insns(code), 0, set())
    assert g is not None and g.execve_via == "syscall"
    assert "추가 제약 없음" in g.constraints[0]


def test_scan_execve_call_path_with_mov_null():
    # lea rdi; mov esi,0; mov edx,0; call rel32=0
    code = bytes.fromhex("488d3d00000000" "be00000000" "ba00000000" "e800000000")
    insns = _insns(code)
    call = next(i for i in insns if i.mnemonic == "call")
    g = _scan_execve(insns, 0, {int(call.op_str, 16)})
    assert g is not None and g.execve_via == "call"
    assert "추가 제약 없음" in g.constraints[0]


def test_scan_execve_stops_on_ret():
    # lea rdi; ret → 흐름이 갈라져 후보 아님.
    code = bytes.fromhex("488d3d00000000" "c3")
    assert _scan_execve(_insns(code), 0, set()) is None


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_no_binsh_binary_has_no_one_gadget(tmp_path):
    csrc = tmp_path / "n.c"
    csrc.write_text("int main(void){ return 0; }\n")
    out = tmp_path / "n"
    subprocess.run(
        ["gcc", "-no-pie", "-o", str(out), str(csrc)], check=True, capture_output=True
    )
    assert find_one_gadgets(parse_elf(out.read_bytes())) == []


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_LIBC), reason="시스템 libc 필요")
def test_finds_one_gadget_in_real_libc():
    data = open(_LIBC, "rb").read()
    image = parse_elf(data)
    gadgets = find_one_gadgets(image)
    assert gadgets, "실 libc 에서 one_gadget 을 찾지 못함"

    binsh = find_string(image, b"/bin/sh\x00")
    text = image.section(".text")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for g in gadgets:
        assert g.execve_via in {"call", "syscall"}
        assert g.constraints
        # 구조 검증: 오프셋의 명령이 실제로 "/bin/sh" 를 rdi 에 싣는 lea 여야 한다.
        blob = data[text.offset + (g.offset - text.addr) :][:16]
        insn = next(md.disasm(blob, g.offset))
        assert insn.mnemonic == "lea" and insn.op_str.startswith("rdi")
        m = re.search(r"rip ([+-]) (0x[0-9a-fA-F]+)", insn.op_str)
        disp = int(m.group(2), 16)
        target = insn.address + insn.size + (disp if m.group(1) == "+" else -disp)
        assert target == binsh
