"""Ghidra headless 디컴파일 백엔드.

Ghidra 는 바이너리를 실행하지 않고 정적 분석만 한다. 설치가 없거나 비활성이면
서비스는 규칙 기반 pseudo-C 로 폴백하라는 신호(``available: False``)를 준다.
실제 디컴파일 테스트는 Ghidra 설치 + 컴파일러가 있을 때만 수행(느림, ~수십 초).
"""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.ghidra import (
    GhidraError,
    decompile_with_ghidra,
    ghidra_available,
    locate_ghidra,
)
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings

_SUPPORTED = platform.system() == "Linux"
_HAVE_GHIDRA = ghidra_available()

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


def test_decompile_ghidra_disabled_signals_fallback():
    """비활성이면 서비스가 available=False 를 줘 UI 가 pseudo-C 로 폴백하게 한다."""
    # ELF 최소 헤더(포맷 가드 통과용)는 실제 분석 전에 available 체크로 걸러진다.
    service = AnalysisService(Settings(ghidra_enabled=False))
    # 형식 가드를 통과하도록 최소 ELF 매직 + 헤더가 필요하지만, disabled 는 그 전에
    # ghidra_available 로 판단하지 않고 포맷 확인 후 곧바로 반환한다.
    data = _minimal_elf()
    result = service.decompile_ghidra(data)
    assert result["available"] is False
    assert result["reason"] == "ghidra-disabled"


def test_ghidra_available_matches_locate():
    assert ghidra_available() == (locate_ghidra() is not None)


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GHIDRA), reason="Ghidra 설치 필요(느림)")
def test_decompile_with_ghidra_produces_c(tmp_path):
    out = _compile(tmp_path)
    if out is None:
        pytest.skip("컴파일러 없음")
    result = decompile_with_ghidra(
        out.read_bytes(), max_functions=60, timeout_seconds=300
    )
    assert result["backend"] == "ghidra"
    assert result["function_count"] > 0
    vuln = next((f for f in result["functions"] if f["name"] == "vuln"), None)
    assert vuln is not None
    # 진짜 디컴파일러라 버퍼 read 호출을 C 로 복원한다.
    assert vuln["c"] is not None
    assert "read" in vuln["c"]


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GHIDRA), reason="Ghidra 설치 필요(느림)")
def test_service_decompile_ghidra_enabled(tmp_path):
    out = _compile(tmp_path)
    if out is None:
        pytest.skip("컴파일러 없음")
    service = AnalysisService(Settings(ghidra_enabled=True))
    result = service.decompile_ghidra(out.read_bytes())
    assert result["available"] is True
    assert result["succeeded"] is True
    assert any(f["name"] == "vuln" for f in result["functions"])


def test_decompile_with_ghidra_raises_when_absent(monkeypatch):
    """설치를 못 찾으면 GhidraError 로 명시적으로 실패한다."""
    monkeypatch.setattr(
        "pwnable_lab.analyzer.ghidra.locate_ghidra", lambda *a, **k: None
    )
    with pytest.raises(GhidraError):
        decompile_with_ghidra(b"\x7fELF", max_functions=1)


def _minimal_elf() -> bytes:
    # 64-bit ELF 헤더(포맷 감지 통과용). 분석은 하지 않는다(disabled 경로).
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    header[6] = 1  # version
    header[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
    header[18:20] = (0x3E).to_bytes(2, "little")  # x86-64
    return bytes(header)
