"""libc 버전 식별 / 지문 — 유출 오프셋으로 libc 를 특정하고 base 를 계산.

원격 ret2libc 는 흔히 알려진 심볼(예: ``puts``) 주소 하나를 유출한 뒤, 그 libc 가
어떤 버전인지 알아내 ``system``/``/bin/sh`` 오프셋을 얻어야 한다. ASLR 은 libc 를
**페이지 정렬** base 로 올리므로, 유출 주소의 **하위 12비트**는 그 심볼의 libc 내
오프셋 하위 12비트와 항상 같다(libc-database 매칭 원리).

이 모듈은 libc 파일에서 버전 문자열·build-id·핵심 심볼 오프셋을 뽑아 **지문**을 만들고
(:func:`libc_fingerprint`), 유출된 심볼 주소들이 그 지문과 하위 12비트로 일치하는지
확인하며(:func:`match_leaks`), 유출 하나로 base 와 다른 심볼의 런타임 주소를 계산한다
(:func:`resolve_from_leak`).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from pwnable_lab.analyzer.strategy import find_string
from pwnable_lab.elf.parser import ElfImage

# 지문에 담을 핵심 심볼(대부분 libc 에 있고 exploit 에 자주 쓰임).
_KEY_SYMBOLS = (
    "puts",
    "printf",
    "system",
    "read",
    "write",
    "open",
    "gets",
    "__libc_start_main",
    "setvbuf",
    "sprintf",
)
_VERSION_RE = re.compile(rb"release version (\d+\.\d+)")


@dataclass
class LibcFingerprint:
    version: str | None
    build_id: str | None
    symbols: dict[str, int] = field(default_factory=dict)  # name → 오프셋
    binsh: int | None = None

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "build_id": self.build_id,
            "symbols": {k: f"0x{v:x}" for k, v in self.symbols.items()},
            "binsh": None if self.binsh is None else f"0x{self.binsh:x}",
        }


def libc_fingerprint(image: ElfImage) -> LibcFingerprint:
    """libc 이미지에서 버전·build-id·핵심 심볼 오프셋 지문을 만든다."""

    version_match = _VERSION_RE.search(image.data)
    version = version_match.group(1).decode() if version_match else None

    exported: dict[str, int] = {}
    for sym in image.dynamic_symbols + image.symbols:
        if sym.name in _KEY_SYMBOLS and sym.addr and sym.name not in exported:
            exported[sym.name] = sym.addr

    return LibcFingerprint(
        version=version,
        build_id=_build_id(image),
        symbols=exported,
        binsh=find_string(image, b"/bin/sh\x00"),
    )


def match_leaks(fingerprint: LibcFingerprint, leaks: dict[str, int]) -> bool:
    """유출 심볼 주소들이 지문과 **하위 12비트**로 모두 일치하는지 확인한다.

    ASLR base 는 페이지 정렬이라 ``leaked & 0xfff == offset & 0xfff`` 여야 한다.
    지문에 없는 심볼이 유출에 있거나, 일치하는 심볼이 하나도 없으면 False.
    """

    checked = 0
    for name, addr in leaks.items():
        offset = fingerprint.symbols.get(name)
        if offset is None:
            return False
        if (addr & 0xFFF) != (offset & 0xFFF):
            return False
        checked += 1
    return checked > 0


def resolve_from_leak(
    fingerprint: LibcFingerprint, symbol: str, leaked_addr: int
) -> dict | None:
    """유출된 ``symbol`` 주소로 libc base 와 핵심 심볼 런타임 주소를 계산한다.

    ``base = leaked_addr - offset(symbol)``. 하위 12비트가 안 맞으면(그 libc 가
    아님) None. 맞으면 base·각 심볼/``/bin/sh`` 의 런타임 주소를 돌려준다.
    """

    offset = fingerprint.symbols.get(symbol)
    if offset is None:
        return None
    if (leaked_addr & 0xFFF) != (offset & 0xFFF):
        return {"consistent": False, "reason": "low-12-bits-mismatch"}
    base = leaked_addr - offset
    runtime = {name: f"0x{base + off:x}" for name, off in fingerprint.symbols.items()}
    if fingerprint.binsh is not None:
        runtime["binsh"] = f"0x{base + fingerprint.binsh:x}"
    return {
        "consistent": True,
        "base": f"0x{base:x}",
        "leaked_symbol": symbol,
        "runtime": runtime,
    }


def _build_id(image: ElfImage) -> str | None:
    """``.note.gnu.build-id`` 노트에서 build-id 16진 문자열을 추출한다(없으면 None)."""

    section = image.section(".note.gnu.build-id")
    if section is None or section.size <= 0:
        return None
    blob = image.data[section.offset : section.offset + section.size]
    if len(blob) < 12:
        return None
    namesz, descsz, ntype = struct.unpack_from("<III", blob, 0)
    if ntype != 3:  # NT_GNU_BUILD_ID
        return None
    name_end = 12 + ((namesz + 3) & ~3)
    desc = blob[name_end : name_end + descsz]
    return desc.hex() if desc else None


__all__ = [
    "LibcFingerprint",
    "libc_fingerprint",
    "match_leaks",
    "resolve_from_leak",
]
