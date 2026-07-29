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


@dataclass
class GotPltReport:
    sections: list[GotPltSection]
    imports: list[Import]

    def as_dict(self) -> dict:
        return {
            "sections": [vars(s) for s in self.sections],
            "imports": [vars(i) for i in self.imports],
        }


def analyze_got_plt(image: ElfImage) -> GotPltReport:
    sections = [
        GotPltSection(s.name, s.addr, s.size, s.offset, s.writable, s.executable)
        for s in image.sections
        if s.name in _RELRO_SECTIONS
    ]
    imports = [
        Import(s.name, s.stype, s.binding)
        for s in image.dynamic_symbols
        if s.name and s.section_index in ("SHN_UNDEF", 0)
    ]
    return GotPltReport(sections=sections, imports=imports)
