"""libc 버전 식별/지문: 유출 오프셋으로 libc 특정 + base 계산."""

from __future__ import annotations

import os
import platform

import pytest

from pwnable_lab.analyzer.libc_id import (
    LibcFingerprint,
    libc_fingerprint,
    match_leaks,
    resolve_from_leak,
)
from pwnable_lab.elf.parser import parse_elf
from tests.fixtures import sample_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
_HAVE_LIBC = os.path.exists(_LIBC)


def test_match_leaks_empty_and_unknown():
    fp = LibcFingerprint(version="2.35", build_id=None, symbols={"puts": 0x80E10})
    # 지문에 없는 심볼 → False
    assert match_leaks(fp, {"printf": 0x1234}) is False
    # 빈 유출 → False(확인한 게 없음)
    assert match_leaks(fp, {}) is False
    # 하위 12비트 일치 → True
    assert match_leaks(fp, {"puts": 0x7F0000080E10}) is True
    # 불일치 → False
    assert match_leaks(fp, {"puts": 0x7F0000080E11}) is False


def test_resolve_from_leak_math():
    fp = LibcFingerprint(
        version="2.35",
        build_id=None,
        symbols={"puts": 0x80E10, "system": 0x50D70},
        binsh=0x1D8678,
    )
    base = 0x7F1234500000
    r = resolve_from_leak(fp, "puts", base + 0x80E10)
    assert r["consistent"] is True
    assert r["base"] == hex(base)
    assert r["runtime"]["system"] == hex(base + 0x50D70)
    assert r["runtime"]["binsh"] == hex(base + 0x1D8678)
    # 하위 12비트 불일치 → consistent False
    bad = resolve_from_leak(fp, "puts", base + 0x80E11)
    assert bad["consistent"] is False
    # 지문에 없는 심볼 → None
    assert resolve_from_leak(fp, "nope", base) is None


def test_fingerprint_binsh_none_and_resolve_without_binsh():
    fp = LibcFingerprint(version="2.31", build_id=None, symbols={"puts": 0x1000})
    d = fp.as_dict()
    assert d["binsh"] is None
    r = resolve_from_leak(fp, "puts", 0x7F0000001000)
    assert r["consistent"] is True
    assert "binsh" not in r["runtime"]


def test_service_libc_endpoints_reject_non_elf():
    from pwnable_lab.api.services import AnalysisService
    from pwnable_lab.config import Settings

    service = AnalysisService(Settings())
    assert service.libc_identify(b"MZ not elf")["format"] == "unsupported"
    assert (
        service.libc_resolve(b"MZ", symbol="puts", leaked=1)["format"] == "unsupported"
    )


def test_service_libc_resolve_unknown_symbol():
    from pwnable_lab.api.services import AnalysisService
    from pwnable_lab.config import Settings

    service = AnalysisService(Settings())
    r = service.libc_resolve(sample_elf(), symbol="no_such_symbol_xyz", leaked=0x1000)
    assert r["consistent"] is False
    assert r["reason"] == "unknown-symbol"


def test_fingerprint_no_note_no_build_id():
    # sample_elf 는 .note.gnu.build-id 가 없어 build_id 가 None.
    fp = libc_fingerprint(parse_elf(sample_elf()))
    assert fp.build_id is None


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_LIBC), reason="시스템 libc 필요")
def test_real_libc_fingerprint_and_resolve():
    img = parse_elf(open(_LIBC, "rb").read())
    fp = libc_fingerprint(img)
    # 버전 문자열이 뽑혀야 한다(예: 2.35).
    assert fp.version and fp.version.startswith("2.")
    # build-id 는 40자리 16진(20바이트).
    assert fp.build_id and len(fp.build_id) == 40
    # 핵심 심볼과 /bin/sh 오프셋이 있어야 한다.
    assert fp.symbols.get("system") and fp.symbols.get("puts")
    assert fp.binsh is not None

    # 자기 자신의 오프셋으로 leak 을 만들면 매칭·resolve 가 일관돼야 한다.
    base = 0x7F5555500000
    leaks = {n: base + off for n, off in fp.symbols.items()}
    assert match_leaks(fp, leaks) is True
    r = resolve_from_leak(fp, "puts", base + fp.symbols["puts"])
    assert r["base"] == hex(base)
    assert r["runtime"]["system"] == hex(base + fp.symbols["system"])
