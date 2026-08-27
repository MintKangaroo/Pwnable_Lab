"""Ghidra 디컴파일 → vuln_scan/strategy 피드백.

핵심 로직(overflow_insights)은 Ghidra 실행 없이 합성 결과 dict 로 검증한다. 실제
바이너리 대조는 Ghidra 설치 + 컴파일러가 있을 때만(느림) 수행한다.
"""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.ghidra import ghidra_available
from pwnable_lab.analyzer.ghidra_insights import (
    best_overflow_offset,
    ghidra_offset_for_function,
    overflow_insights,
)
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings

_SUPPORTED = platform.system() == "Linux"
_HAVE_GHIDRA = ghidra_available()


def _res(functions):
    return {"program": "t", "language": "x86:LE:64:default", "functions": functions}


def test_read_overflow_confirmed_with_offset():
    r = _res(
        [
            {
                "name": "vuln",
                "return_addr_offset": 0,
                "c": "void vuln(void){ char buf[64]; read(0,buf,300); }",
                "stack_vars": [{"name": "buf", "offset": -72, "size": 64}],
            }
        ]
    )
    ins = overflow_insights(r)
    assert len(ins) == 1
    assert ins[0].confirmed is True
    assert ins[0].offset == 72  # return_addr_offset(0) - stack_offset(-72)
    assert ins[0].buffer_size == 64
    assert ghidra_offset_for_function(ins, "vuln") == 72
    assert best_overflow_offset(ins) == 72


def test_bounded_read_within_buffer_is_safe():
    r = _res(
        [
            {
                "name": "safe",
                "return_addr_offset": 0,
                "c": "void safe(void){ char s[128]; read(0,s,64); }",
                "stack_vars": [{"name": "s", "offset": -136, "size": 128}],
            }
        ]
    )
    ins = overflow_insights(r)
    assert ins[0].confirmed is False
    assert best_overflow_offset(ins) is None


def test_gets_is_unbounded_overflow():
    r = _res(
        [
            {
                "name": "g",
                "return_addr_offset": 0,
                "c": "void g(void){ char b[32]; gets(b); }",
                "stack_vars": [{"name": "b", "offset": -40, "size": 32}],
            }
        ]
    )
    ins = overflow_insights(r)
    assert ins[0].confirmed is True
    assert ins[0].unbounded is True
    assert ins[0].offset == 40


def test_buffer_size_from_c_declaration_when_stack_length_is_one():
    """스트립 바이너리는 스택 length==1(undefined1) — 배열 크기는 C 선언에서 온다."""
    r = _res(
        [
            {
                "name": "FUN_1",
                "return_addr_offset": 0,
                # 스택 length 1 이지만 C 선언은 [64]/[128]
                "c": (
                    "void FUN_1(void){ undefined1 small [64]; undefined1 big [128];"
                    " read(0,big,100); read(0,small,300); }"
                ),
                "stack_vars": [
                    {"name": "small", "offset": -200, "size": 1},
                    {"name": "big", "offset": -136, "size": 1},
                ],
            }
        ]
    )
    ins = overflow_insights(r)
    by = {i.buffer_name: i for i in ins}
    # big[128] read 100 → 안전, small[64] read 300 → 오버플로 offset 200
    assert by["big"].confirmed is False
    assert by["small"].confirmed is True
    assert by["small"].offset == 200
    assert best_overflow_offset(ins) == 200


def test_multiple_functions_pick_farthest_confirmed():
    r = _res(
        [
            {
                "name": "a",
                "return_addr_offset": 0,
                "c": "void a(void){ char x[16]; gets(x); }",
                "stack_vars": [{"name": "x", "offset": -24, "size": 16}],
            },
            {
                "name": "b",
                "return_addr_offset": 0,
                "c": "void b(void){ char y[256]; read(0,y,999); }",
                "stack_vars": [{"name": "y", "offset": -264, "size": 256}],
            },
        ]
    )
    ins = overflow_insights(r)
    assert best_overflow_offset(ins) == 264  # b 가 더 먼 오프셋
    assert ghidra_offset_for_function(ins, "a") == 24


# ---- 실제 Ghidra 경유 서비스 통합(설치+컴파일러 필요, 느림) --------------------

_SRC = """
#include <stdio.h>
#include <unistd.h>
void vuln(void){ char buf[64]; read(0, buf, 300); }
int main(void){ setvbuf(stdout, 0, 2, 0); vuln(); return 0; }
"""


def _cc():
    if shutil.which("gcc"):
        return ["gcc"]
    if shutil.which("zig"):
        return ["zig", "cc", "-target", "x86_64-linux-gnu"]
    return None


def _compile(tmp_path):
    cc = _cc()
    if cc is None:
        return None
    csrc = tmp_path / "g.c"
    csrc.write_text(_SRC)
    out = tmp_path / "g"
    try:
        subprocess.run(
            [*cc, "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    return out


def test_analyze_ghidra_disabled_signals_fallback():
    service = AnalysisService(Settings(ghidra_enabled=False))
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (0x3E).to_bytes(2, "little")
    result = service.analyze_ghidra(bytes(header))
    assert result["available"] is False


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GHIDRA), reason="Ghidra 설치 필요(느림)")
def test_analyze_ghidra_feeds_vuln_scan_and_strategy(tmp_path):
    out = _compile(tmp_path)
    if out is None:
        pytest.skip("컴파일러 없음")
    service = AnalysisService(Settings(ghidra_enabled=True))
    result = service.analyze_ghidra(out.read_bytes())
    assert result["available"] is True
    # vuln_scan 피드백: read finding 이 Ghidra 로 확정 승격.
    assert result["best_overflow_offset"] == 72
    read_finding = next(
        (v for v in result["vulnerabilities"] if v["symbol"] == "read"), None
    )
    assert read_finding is not None
    assert read_finding.get("ghidra_confirmed") is True
    assert read_finding.get("ghidra_offset") == 72
    assert read_finding["status"] == "confirmed"
    # strategy 피드백: 오프셋 주입 + 정직한 라벨.
    strat = result["strategy"]
    assert strat["confirmed_offset"] == 72
    assert strat["offset_source"] == "ghidra-static"
    assert strat["offset_verification"] == "static-ghidra"
