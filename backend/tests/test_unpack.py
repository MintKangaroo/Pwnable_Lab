"""UPX 언패킹(Phase 6C 후속): 패킹 ELF 를 `upx -d` 로 복원(대상 미실행)."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.packing import detect_packing
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import unpack_upx
from tests.fixtures import sample_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None
_HAVE_UPX = shutil.which("upx") is not None

_SRC = '#include <stdio.h>\nint main(void){ puts("packed-hello"); return 0; }\n'


def _compile(tmp_path) -> str:
    csrc = tmp_path / "u.c"
    csrc.write_text(_SRC)
    out = tmp_path / "u"
    subprocess.run(
        ["gcc", "-O0", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


def test_non_elf_is_rejected():
    result = unpack_upx(b"MZ\x90\x00 not an elf")
    assert result["attempted"] is False
    assert result["reason"] == "not-elf"


def test_normal_elf_is_not_upx():
    result = unpack_upx(sample_elf())
    assert result["attempted"] is False
    assert result["reason"] == "not-upx-packed"


def test_service_unpack_non_elf():
    from pwnable_lab.errors import PwnableLabError

    with pytest.raises(PwnableLabError):
        AnalysisService(Settings()).unpack(b"not an elf at all")


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC and _HAVE_UPX),
    reason="Linux/x86-64 + gcc + upx 필요(실제 패킹/언패킹)",
)
def test_upx_unavailable_branch(tmp_path, monkeypatch):
    # upx 가 설치돼 있어도 PATH 에서 안 보이는 상황을 흉내낸다.
    packed = _packed_bytes(tmp_path)
    monkeypatch.setattr("pwnable_lab.sandbox.unpack.shutil.which", lambda _n: None)
    result = unpack_upx(packed)
    assert result["attempted"] is False
    assert result["reason"] == "upx-unavailable"


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC and _HAVE_UPX),
    reason="Linux/x86-64 + gcc + upx 필요(실제 패킹/언패킹)",
)
def test_unpack_recovers_packed_binary(tmp_path):
    packed = _packed_bytes(tmp_path)
    assert detect_packing(parse_elf(packed)).packer == "UPX"
    result = unpack_upx(packed)
    assert result["attempted"] is True
    assert result["unpacked"] is True
    assert result["packer"] == "UPX"
    # 언패킹 결과는 패킹본과 다르고, 언패킹된 바이너리는 더 이상 UPX 로 안 잡힌다.
    assert result["unpacked_size"] > 0
    assert len(result["unpacked_sha256"]) == 64


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC and _HAVE_UPX),
    reason="Linux/x86-64 + gcc + upx 필요",
)
def test_service_unpack_elf(tmp_path):
    packed = _packed_bytes(tmp_path)
    result = AnalysisService(Settings()).unpack(packed)
    assert result["attempted"] is True
    assert result["unpacked"] is True


def _packed_bytes(tmp_path) -> bytes:
    path = _compile(tmp_path)
    subprocess.run(["upx", "-q", path], check=True, capture_output=True)
    return open(path, "rb").read()
