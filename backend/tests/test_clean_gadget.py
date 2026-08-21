"""체인용 가젯 선택은 부작용 없는 **클린** 가젯만 골라야 한다.

정적 glibc 등에는 ``pop rdx ; adc ... ; ret 0x349`` 처럼 종단이 ``ret imm`` 이거나
중간에 부작용이 있는 가젯이 흔하다. 이를 걸러내지 않으면 rsp 가 어긋나 조용히
깨진 ROP 체인을 만든다(ret2system/ret2libc/leak/PIE 체인 전부 영향).
"""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.gadgets import scan_gadgets
from pwnable_lab.analyzer.strategy import _is_clean_ret, find_clean_pop
from pwnable_lab.elf.parser import parse_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None


def test_is_clean_ret_truth_table():
    assert _is_clean_ret("ret") is True
    assert _is_clean_ret("ret 0") is True
    assert _is_clean_ret("ret 0x0") is True
    # ret <nonzero imm> 은 rsp 를 어긋나게 하므로 배제.
    assert _is_clean_ret("ret 0x349") is False
    assert _is_clean_ret("ret 0xffff") is False
    assert _is_clean_ret("ret 8") is False
    # 근접 명령을 ret 로 오인하지 않는다.
    assert _is_clean_ret("retf") is False
    assert _is_clean_ret("pop rdi") is False


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_find_clean_pop_returns_only_clean_gadgets(tmp_path):
    """정적 바이너리에서 clean pop 선택이 항상 부작용 없는 2명령 가젯이어야 한다."""
    csrc = tmp_path / "s.c"
    csrc.write_text(
        "#include <stdio.h>\n"
        'char shstr[] = "/bin/sh";\n'
        "void vuln(void){ char buf[64]; gets(buf); }\n"
        "int main(void){ vuln(); return 0; }\n"
    )
    out = tmp_path / "s"
    subprocess.run(
        [
            "gcc",
            "-fno-stack-protector",
            "-no-pie",
            "-static",
            "-o",
            str(out),
            str(csrc),
        ],
        check=True,
        capture_output=True,
    )
    image = parse_elf(out.read_bytes())
    gadgets = {g.address: g for g in scan_gadgets(image).gadgets}

    addr = find_clean_pop(image, "rdi")
    assert addr is not None, "정적 바이너리엔 clean pop rdi 가 반드시 있다"
    body = [i.strip().lower() for i in gadgets[addr].instructions]
    # 반환된 가젯은 정확히 2명령 pop rdi ; (clean) ret 여야 한다.
    assert len(body) == 2
    assert body[0] == "pop rdi"
    assert _is_clean_ret(body[1])

    # 이 정적 바이너리는 clean 한 pop rdx ; ret 가 없다(오염 가젯만 존재) →
    # 조용히 깨진 체인을 만드느니 None 을 반환해야 한다.
    rdx = find_clean_pop(image, "rdx")
    if rdx is not None:
        # 혹시 반환하더라도 반드시 clean 2명령이어야 한다(오염 가젯 금지).
        rbody = [i.strip().lower() for i in gadgets[rdx].instructions]
        assert len(rbody) == 2 and rbody[0] == "pop rdx" and _is_clean_ret(rbody[1])
