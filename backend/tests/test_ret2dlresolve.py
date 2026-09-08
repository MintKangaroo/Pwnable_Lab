"""ret2dlresolve 위조 구조체 빌더/plan: 구조적 정확성 검증.

glibc 2.34+ 는 심볼 버전 검사로 고전 ret2dlresolve 를 하드닝하므로 실제 셸 획득은
libc 버전에 따라 성립하지 않는다. 여기서는 **위조 구조체가 정확한지**(정렬·필드·
reloc_arg/sym_index 수학)를 검증한다(pwntools Ret2dlresolvePayload 와 동형).
"""

from __future__ import annotations

import platform
import shutil
import struct
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import ret2dlresolve_plan
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.ret2dlresolve import build_ret2dlresolve
from tests.fixtures import sample_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None


def test_builder_alignment_and_fields():
    jmprel, dynsym, dynstr, buf = 0x400530, 0x4003A0, 0x400448, 0x403360
    r = build_ret2dlresolve(jmprel=jmprel, dynsym=dynsym, dynstr=dynstr, buf=buf)

    # 정렬: reloc_arg/sym_index 가 정수(주소가 24 정렬)여야 한다.
    rela_addr = jmprel + r.reloc_arg * 24
    assert (rela_addr - jmprel) % 24 == 0
    sym_addr = dynsym + r.sym_index * 24
    assert (sym_addr - dynsym) % 24 == 0

    # Rela: r_info 의 심볼 인덱스·타입(JUMP_SLOT=7).
    off = rela_addr - buf
    r_offset, r_info, r_addend = struct.unpack_from("<QQQ", r.blob, off)
    assert r_info >> 32 == r.sym_index
    assert r_info & 0xFFFFFFFF == 7
    assert r_addend == 0

    # Sym: st_name 이 func 문자열의 dynstr 상대 오프셋, st_info=STB_GLOBAL|STT_FUNC.
    soff = sym_addr - buf
    st_name, st_info = struct.unpack_from("<IB", r.blob, soff)
    assert dynstr + st_name == r.func_str_addr
    assert st_info == 0x12

    # 문자열 내용.
    fo = r.func_str_addr - buf
    assert r.blob[fo : fo + 7] == b"system\x00"
    bo = r.binsh_addr - buf
    assert r.blob[bo : bo + 8] == b"/bin/sh\x00"


def test_builder_custom_symbol():
    r = build_ret2dlresolve(
        jmprel=0x1000, dynsym=0x800, dynstr=0x900, buf=0x5000, func=b"execve"
    )
    fo = r.func_str_addr - 0x5000
    assert r.blob[fo : fo + 7] == b"execve\x00"


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_plan_and_service_on_lazy_binary(tmp_path):
    csrc = tmp_path / "dl.c"
    csrc.write_text(
        "#include <stdio.h>\n#include <unistd.h>\n"
        '__asm__(".global g_pr\\ng_pr: pop %rdi\\n ret\\n");\n'
        "char bss_buf[512];\n"
        "void vuln(void){ char b[64]; read(0,b,0x400); }\n"
        'int main(void){ puts("hi"); vuln(); return 0; }\n'
    )
    out = tmp_path / "dl"
    subprocess.run(
        [
            "gcc",
            "-fno-stack-protector",
            "-no-pie",
            "-Wl,-z,norelro",
            "-o",
            str(out),
            str(csrc),
        ],
        check=True,
        capture_output=True,
    )
    img = parse_elf(out.read_bytes())
    plan = ret2dlresolve_plan(img)
    assert plan is not None
    for key in ("plt0", "jmprel", "dynsym", "dynstr", "buf", "pop_rdi"):
        assert plan[key] > 0

    result = AnalysisService(Settings()).ret2dlresolve(out.read_bytes())
    assert result["available"] is True
    assert result["reloc_arg"] >= 0
    assert result["blob_hex"]
    assert "glibc" in result["note"]


def test_service_ret2dlresolve_non_elf_and_no_plan():
    service = AnalysisService(Settings())
    assert service.ret2dlresolve(b"MZ not elf")["available"] is False
    # sample_elf 은 지연바인딩 PLT/버퍼 재료가 없어 no-plan.
    r = service.ret2dlresolve(sample_elf())
    assert r["available"] is False
