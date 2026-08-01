"""GOT/PLT 및 임포트(외부 함수) 개요.

동적 링크 바이너리에서 GOT/PLT 섹션 위치와 임포트 심볼을 정리한다. 정적으로
링크되었거나 해당 섹션이 없으면 빈 결과로 우아하게 축소된다.
"""

from __future__ import annotations

from dataclasses import dataclass

from pwnable_lab.elf.parser import ElfImage

_RELRO_SECTIONS = {".got", ".got.plt", ".plt", ".plt.sec", ".plt.got"}


@dataclass
class GotPltSection:
    name: str
    addr: int
    size: int
    offset: int
    writable: bool
    executable: bool


@dataclass
class Import:
    name: str
    stype: str
    binding: str
    version: str | None = None


@dataclass
class GotEntry:
    address: int
    symbol: str | None
    relocation_type: str
    relocation_section: str
    verification: str = "verified"
    confidence: float = 1.0


@dataclass
class PltEntry:
    address: int | None
    symbol: str
    got_address: int
    section: str | None
    verification: str
    confidence: float
    evidence: list[str]


@dataclass
class GotPltReport:
    sections: list[GotPltSection]
    imports: list[Import]
    got_entries: list[GotEntry]
    plt_entries: list[PltEntry]

    def as_dict(self) -> dict:
        return {
            "sections": [vars(s) for s in self.sections],
            "imports": [vars(i) for i in self.imports],
            "entries": [vars(entry) for entry in self.got_entries],
            "plt_entries": [vars(entry) for entry in self.plt_entries],
        }


def analyze_got_plt(image: ElfImage) -> GotPltReport:
    sections = [
        GotPltSection(s.name, s.addr, s.size, s.offset, s.writable, s.executable)
        for s in image.sections
        if s.name in _RELRO_SECTIONS
    ]
    imports = [Import(s.name, s.stype, s.binding) for s in image.imports]
    got_ranges = [
        (section.addr, section.addr + section.size)
        for section in image.sections
        if section.name in {".got", ".got.plt"}
    ]
    got_entries = [
        GotEntry(
            address=relocation.offset,
            symbol=relocation.symbol,
            relocation_type=relocation.relocation_type,
            relocation_section=relocation.section,
        )
        for relocation in image.relocations
        if relocation.purpose == "plt"
        or any(start <= relocation.offset < end for start, end in got_ranges)
    ]

    plt_relocations = [
        relocation
        for relocation in image.relocations
        if relocation.purpose == "plt" and relocation.symbol
    ]
    plt_section = image.section(".plt.sec") or image.section(".plt")
    plt_entries: list[PltEntry] = []
    for index, relocation in enumerate(plt_relocations):
        address: int | None = None
        verification = "unknown"
        confidence = 0.0
        evidence = [
            f"{relocation.section} relocation targets {relocation.symbol}",
            f"GOT relocation target is 0x{relocation.offset:x}",
        ]
        if plt_section is not None and plt_section.entry_size > 0:
            reserved = 0 if plt_section.name == ".plt.sec" else 1
            address = plt_section.addr + (index + reserved) * plt_section.entry_size
            verification = "inferred"
            confidence = 0.92
            evidence.append(
                f"Address derived from {plt_section.name} entry size "
                f"{plt_section.entry_size} and relocation order"
            )
        else:
            evidence.append("PLT section entry size is unavailable")
        plt_entries.append(
            PltEntry(
                address=address,
                symbol=relocation.symbol or "",
                got_address=relocation.offset,
                section=plt_section.name if plt_section else None,
                verification=verification,
                confidence=confidence,
                evidence=evidence,
            )
        )

    return GotPltReport(
        sections=sections,
        imports=imports,
        got_entries=got_entries,
        plt_entries=plt_entries,
    )
