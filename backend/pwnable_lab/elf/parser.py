"""pyelftools 기반 ELF 정규화 파서.

원시 ELF 구조를 프레임워크 비의존적인 :class:`ElfImage` 데이터클래스로 정규화한다.
분석기·페이로드·문제 계층은 이 정규화된 뷰만 사용한다.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from pwnable_lab.errors import ParseError, UnsupportedFormatError


@dataclass
class SectionInfo:
    name: str
    addr: int
    offset: int
    size: int
    flags: int
    stype: str
    executable: bool
    writable: bool


@dataclass
class SymbolInfo:
    name: str
    addr: int
    size: int
    stype: str
    binding: str
    section_index: int | str


@dataclass
class SegmentInfo:
    ptype: str
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    readable: bool
    writable: bool
    executable: bool


@dataclass
class ElfImage:
    """정규화된 ELF 뷰."""

    data: bytes
    bits: int
    endian: str
    machine: str
    e_type: str
    entry: int
    sections: list[SectionInfo] = field(default_factory=list)
    symbols: list[SymbolInfo] = field(default_factory=list)
    segments: list[SegmentInfo] = field(default_factory=list)
    dynamic_symbols: list[SymbolInfo] = field(default_factory=list)
    dynamic_tags: list[str] = field(default_factory=list)
    dynamic_flags: dict[str, int] = field(default_factory=dict)

    def section(self, name: str) -> SectionInfo | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def symbol(self, name: str) -> SymbolInfo | None:
        for s in self.symbols:
            if s.name == name:
                return s
        return None

    def section_bytes(self, name: str) -> bytes:
        s = self.section(name)
        if s is None:
            return b""
        return self.data[s.offset : s.offset + s.size]


def parse_elf(data: bytes) -> ElfImage:
    """바이트에서 :class:`ElfImage` 를 생성한다.

    Raises
    ------
    UnsupportedFormatError
        ELF 매직이 아닌 경우.
    ParseError
        구조가 손상되어 파싱에 실패한 경우.
    """
    if len(data) < 4 or data[:4] != b"\x7fELF":
        raise UnsupportedFormatError("ELF 매직(\\x7fELF)이 아닙니다.")
    try:
        elf = ELFFile(io.BytesIO(data))
    except ELFError as exc:  # pragma: no cover - 방어적
        raise ParseError(f"ELF 파싱 실패: {exc}") from exc

    try:
        bits = 64 if elf.elfclass == 64 else 32
        endian = "little" if elf.little_endian else "big"
        machine = elf["e_machine"]
        e_type = elf["e_type"]
        entry = elf["e_entry"]

        sections: list[SectionInfo] = []
        for sec in elf.iter_sections():
            flags = sec["sh_flags"]
            sections.append(
                SectionInfo(
                    name=sec.name or "",
                    addr=sec["sh_addr"],
                    offset=sec["sh_offset"],
                    size=sec["sh_size"],
                    flags=flags,
                    stype=str(sec["sh_type"]),
                    executable=bool(flags & 0x4),
                    writable=bool(flags & 0x1),
                )
            )

        symbols: list[SymbolInfo] = []
        dyn_symbols: list[SymbolInfo] = []
        dynamic_tags: list[str] = []
        dynamic_flags: dict[str, int] = {}
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    name = str(tag.entry.d_tag)
                    dynamic_tags.append(name)
                    if name in {"DT_FLAGS", "DT_FLAGS_1"}:
                        dynamic_flags[name] = int(tag.entry.d_val)
            if not isinstance(sec, SymbolTableSection):
                continue
            target = dyn_symbols if sec.name == ".dynsym" else symbols
            for sym in sec.iter_symbols():
                info = sym["st_info"]
                target.append(
                    SymbolInfo(
                        name=sym.name or "",
                        addr=sym["st_value"],
                        size=sym["st_size"],
                        stype=str(info["type"]),
                        binding=str(info["bind"]),
                        section_index=sym["st_shndx"],
                    )
                )

        segments: list[SegmentInfo] = []
        for seg in elf.iter_segments():
            flags = seg["p_flags"]
            segments.append(
                SegmentInfo(
                    ptype=str(seg["p_type"]),
                    flags=flags,
                    offset=seg["p_offset"],
                    vaddr=seg["p_vaddr"],
                    filesz=seg["p_filesz"],
                    memsz=seg["p_memsz"],
                    readable=bool(flags & 0x4),
                    writable=bool(flags & 0x2),
                    executable=bool(flags & 0x1),
                )
            )
    except (ELFError, KeyError, ValueError) as exc:
        raise ParseError(f"ELF 구조 해석 실패: {exc}") from exc

    return ElfImage(
        data=data,
        bits=bits,
        endian=endian,
        machine=machine,
        e_type=e_type,
        entry=entry,
        sections=sections,
        symbols=symbols,
        segments=segments,
        dynamic_symbols=dyn_symbols,
        dynamic_tags=dynamic_tags,
        dynamic_flags=dynamic_flags,
    )
