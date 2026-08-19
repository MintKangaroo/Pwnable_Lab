"""골든 코퍼스 회귀 하네스 — 실 gcc 바이너리로 정확성을 오라클 대조·고정.

합성 ``ElfBuilder`` 픽스처는 실컴파일러 관용구를 재현하지 못해(F-CRIT-1 이 테스트를
통과했던 원인) 값 정확성 회귀를 놓친다. 이 하네스는 실제 gcc 바이너리를 컴파일하고:

* **오프셋**: 동적 확정(`confirm_return_offset`, 실행으로 검증된 ground truth)을
  오라클로 삼아, 정적 추론(`analyze_strategy` ret2win 스켈레톤의 ``offset = N``)이
  일치하는지 관용구(gets/read/fgets)·버퍼크기 전반에서 고정한다.
* **checksec**: 컴파일 플래그를 오라클로 canary/executable_stack/pie 를 대조.
* **가젯**: 인라인 asm 으로 심은 알려진 가젯(pop rdi;ret, syscall;ret, jmp rax)을
  ``scan_gadgets`` 가 정확한 주소·명령으로 찾는지 nm 을 오라클로 대조.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.checksec import run_checksec
from pwnable_lab.analyzer.gadgets import scan_gadgets
from pwnable_lab.analyzer.strategy import analyze_strategy
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox.runner import confirm_return_offset

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None
_HAVE_NM = shutil.which("nm") is not None

pytestmark = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실 컴파일 코퍼스)"
)

_HEADER = (
    "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
    'void win(void){ system("/bin/sh"); }\n'
)


def _compile(tmp_path, name, body, *flags):
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(_HEADER + body + "int main(void){ vuln(); return 0; }\n")
    out = tmp_path / name
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", *flags, "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


def _static_offset(binary_bytes):
    report = analyze_strategy(parse_elf(binary_bytes))
    path = next((p for p in report["paths"] if p["id"] == "ret2win"), None)
    if path is None:
        return None
    match = re.search(r"offset = (\d+)", path["pwntools"])
    return int(match.group(1)) if match else None


# (name, vuln body, cyclic pattern length) — 다양한 오버플로 관용구.
_OFFSET_CORPUS = [
    ("gets64", "void vuln(void){ char buf[64]; gets(buf); }", 400),
    ("gets128", "void vuln(void){ char buf[128]; gets(buf); }", 400),
    ("read64", "void vuln(void){ char buf[64]; read(0, buf, 256); }", 200),
    ("read96", "void vuln(void){ char buf[96]; read(0, buf, 256); }", 200),
    ("fgets64", "void vuln(void){ char buf[64]; fgets(buf, 200, stdin); }", 150),
    ("scanf64", 'void vuln(void){ char buf[64]; scanf("%s", buf); }', 300),
]


@pytest.mark.parametrize("name,body,pattern_length", _OFFSET_CORPUS)
def test_static_offset_matches_dynamic_oracle(tmp_path, name, body, pattern_length):
    """정적 오프셋 추론이 실행으로 확정한 오프셋(오라클)과 일치해야 한다."""
    binary = _compile(tmp_path, name, body)
    dynamic = confirm_return_offset(str(binary), pattern_length=pattern_length)
    assert dynamic.confirmed, f"{name}: 동적 확정 실패"

    static = _static_offset(binary.read_bytes())
    assert static is not None, f"{name}: ret2win 스켈레톤에 offset 없음"
    # 핵심 회귀 락: 정적 추론 == 실행 검증 오프셋(관용구/버퍼크기 무관).
    assert (
        static == dynamic.offset
    ), f"{name}: static={static} != dynamic(oracle)={dynamic.offset}"


def test_glibc_scanf_alias_is_detected(tmp_path):
    """glibc 의 __isoc99_scanf 별칭도 scanf 취약점으로 인식돼야 한다."""
    from pwnable_lab.analyzer.vuln_scan import scan_vulns

    binary = _compile(
        tmp_path, "scanfdet", 'void vuln(void){ char buf[64]; scanf("%s", buf); }'
    )
    findings = scan_vulns(parse_elf(binary.read_bytes()))
    assert any(f.symbol == "scanf" for f in findings), "scanf(__isoc99_scanf) 미탐지"


def test_checksec_matches_compile_flags(tmp_path):
    """checksec 필드가 컴파일 플래그(오라클)와 일치해야 한다."""
    body = "void vuln(void){ char buf[64]; gets(buf); }"

    no_canary = run_checksec(parse_elf(_compile(tmp_path, "nc", body).read_bytes()))
    canary = run_checksec(
        parse_elf(_compile(tmp_path, "c", body, "-fstack-protector-all").read_bytes())
    )
    assert no_canary.canary is False
    assert canary.canary is True

    execstack = run_checksec(
        parse_elf(_compile(tmp_path, "xs", body, "-z", "execstack").read_bytes())
    )
    assert no_canary.executable_stack in (False, None)
    assert execstack.executable_stack is True

    pie = run_checksec(
        parse_elf(_compile(tmp_path, "pie", body, "-pie", "-fPIE").read_bytes())
    )
    # 비 PIE 와 PIE 는 e_type 이 달라 checksec.pie 표현이 달라야 한다.
    assert no_canary.pie != pie.pie


@pytest.mark.skipif(not _HAVE_NM, reason="nm 필요(가젯 주소 오라클)")
def test_planted_gadgets_are_found(tmp_path):
    """인라인 asm 으로 심은 가젯을 scan_gadgets 가 정확한 주소로 찾아야 한다."""
    body = (
        '__asm__(".global g_pop_rdi\\ng_pop_rdi: pop %rdi\\n ret");\n'
        '__asm__(".global g_syscall\\ng_syscall: syscall\\n ret");\n'
        '__asm__(".global g_jmp_rax\\ng_jmp_rax: jmp *%rax");\n'
        "void vuln(void){ char buf[64]; gets(buf); }\n"
    )
    binary = _compile(tmp_path, "gadgets", body)
    nm = subprocess.run(["nm", str(binary)], capture_output=True, text=True, check=True)
    addr = {
        line.split()[2]: int(line.split()[0], 16)
        for line in nm.stdout.splitlines()
        if " T g_" in line
    }
    gadgets = scan_gadgets(parse_elf(binary.read_bytes())).gadgets
    by_addr = {g.address: [i.strip().lower() for i in g.instructions] for g in gadgets}

    def _ends_with(addr_val, first, last):
        body = by_addr.get(addr_val)
        return body is not None and body[0] == first and body[-1].startswith(last)

    assert _ends_with(addr["g_pop_rdi"], "pop rdi", "ret")
    assert _ends_with(addr["g_syscall"], "syscall", "syscall") or _ends_with(
        addr["g_syscall"], "syscall", "ret"
    )
    # JOP 종단(F-CRIT-2): jmp rax 가 종단으로 인식돼야 한다.
    jmp = by_addr.get(addr["g_jmp_rax"])
    assert jmp is not None and jmp[-1].replace(" ", "") == "jmprax"
