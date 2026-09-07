"""패커/난독화 정적 탐지(Phase 6C): UPX 서명·엔트로피·섹션·임포트·오버레이."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.packing import detect_packing
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import (
    ElfImage,
    SectionInfo,
    SegmentInfo,
    SymbolInfo,
    parse_elf,
)
from tests.fixtures import sample_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None
_HAVE_UPX = shutil.which("upx") is not None

_SRC = '#include <stdio.h>\nint main(void){ puts("hi"); return 0; }\n'


def _compile(tmp_path) -> str:
    csrc = tmp_path / "p.c"
    csrc.write_text(_SRC)
    out = tmp_path / "p"
    subprocess.run(
        ["gcc", "-O0", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_normal_binary_is_not_packed(tmp_path):
    report = detect_packing(parse_elf(open(_compile(tmp_path), "rb").read()))
    assert report.packed is False
    assert report.packer is None
    # 표준 .text 가 있고 섹션 헤더 테이블을 오버레이로 오인하지 않는다.
    names = {s.name for s in report.signals}
    assert "overlay-data" not in names
    assert "no-text-section" not in names


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_upx_magic_and_overlay_detected(tmp_path):
    data = open(_compile(tmp_path), "rb").read()
    # 고엔트로피 오버레이 + UPX 매직을 덧붙여 패킹 신호를 합성한다(실제 upx 불필요).
    report = detect_packing(parse_elf(data + os.urandom(8192) + b"UPX!"))
    assert report.packed is True
    assert report.packer == "UPX"
    assert report.confidence >= 50
    kinds = {s.name for s in report.signals}
    assert "packer-magic" in kinds
    assert "overlay-data" in kinds


def test_packing_report_serializes():
    report = detect_packing(parse_elf(sample_elf()))
    d = report.as_dict()
    assert set(d) >= {"packed", "packer", "confidence", "signals"}
    assert isinstance(d["signals"], list)


def test_service_packing_non_elf_is_unsupported():
    service = AnalysisService(Settings())
    result = service.packing(b"MZ\x90\x00 not an elf")
    assert result["format"] == "unsupported"
    assert result["packed"] is False


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_service_packing_elf(tmp_path):
    service = AnalysisService(Settings())
    result = service.packing(open(_compile(tmp_path), "rb").read())
    assert result["format"] == "ELF"
    assert result["packed"] is False


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC and _HAVE_UPX),
    reason="Linux/x86-64 + gcc + upx 필요(실제 패킹)",
)
def test_real_upx_packed_binary(tmp_path):
    path = _compile(tmp_path)
    subprocess.run(["upx", "-q", path], check=True, capture_output=True)
    report = detect_packing(parse_elf(open(path, "rb").read()))
    assert report.packed is True
    assert report.packer == "UPX"


# --- 합성 ElfImage 로 개별 신호 검출 로직 검증(컴파일 불필요) --------------------


def _sec(name, offset, size, *, execut=False, stype="SHT_PROGBITS"):
    return SectionInfo(
        name=name,
        addr=0x1000 + offset,
        offset=offset,
        size=size,
        flags=0,
        stype=stype,
        executable=execut,
        writable=False,
    )


def _img(sections, *, data, e_type="ET_EXEC", dyn_syms=None, segments=None):
    return ElfImage(
        data=data,
        bits=64,
        endian="little",
        machine="x86-64",
        e_type=e_type,
        entry=0x1000,
        sections=sections,
        dynamic_symbols=dyn_syms or [],
        segments=segments or [],
        has_dynamic_section=e_type == "ET_DYN",
    )


def test_packer_section_name_flags_upx():
    # 고엔트로피 실행 섹션 'UPX1' + 저엔트로피 헤더.
    data = bytearray(b"\x00" * 64)
    data += os.urandom(4096)
    img = _img(
        [_sec("UPX1", 64, 4096, execut=True)],
        data=bytes(data),
    )
    report = detect_packing(img)
    assert report.packer == "UPX"
    assert report.packed is True
    kinds = {s.name for s in report.signals}
    assert "packer-section" in kinds
    assert "high-entropy-exec" in kinds


def test_no_text_section_flagged():
    img = _img([_sec(".mystery", 64, 32, execut=True)], data=b"\x00" * 200)
    kinds = {s.name for s in detect_packing(img).signals}
    assert "no-text-section" in kinds


def test_sparse_sections_flagged():
    img = _img(
        [_sec(".text", 64, 16, execut=True), _sec(".data", 96, 16)],
        data=b"\x00" * 200,
    )
    kinds = {s.name for s in detect_packing(img).signals}
    assert "sparse-sections" in kinds


def test_few_imports_flagged_for_dynamic():
    img = _img(
        [_sec(".text", 64, 16, execut=True)],
        data=b"\x00" * 200,
        e_type="ET_DYN",
        dyn_syms=[],
    )
    kinds = {s.name for s in detect_packing(img).signals}
    assert "few-imports" in kinds


def test_entropy_falls_back_to_exec_segment_when_no_sections():
    data = bytearray(b"\x00" * 64) + bytearray(os.urandom(4096))
    seg = SegmentInfo(
        ptype="PT_LOAD",
        flags=5,
        offset=64,
        vaddr=0x1000,
        filesz=4096,
        memsz=4096,
        readable=True,
        writable=False,
        executable=True,
    )
    img = _img([], data=bytes(data), segments=[seg])
    kinds = {s.name for s in detect_packing(img).signals}
    assert "high-entropy-exec" in kinds


def test_defined_symbol_is_not_counted_as_import():
    defined = SymbolInfo(
        name="main",
        addr=0x1000,
        size=0,
        stype="STT_FUNC",
        binding="STB_GLOBAL",
        section_index=1,
        defined=True,
    )
    img = _img(
        [_sec(".text", 64, 16, execut=True)],
        data=b"\x00" * 200,
        e_type="ET_DYN",
        dyn_syms=[defined],
    )
    # 정의된 심볼은 import 가 아니므로 few-imports(0개)가 여전히 떠야 한다.
    kinds = {s.name for s in detect_packing(img).signals}
    assert "few-imports" in kinds
