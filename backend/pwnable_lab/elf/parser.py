"""pyelftools 기반 ELF 정규화 파서.

원시 ELF 구조를 프레임워크 비의존적인 :class:`ElfImage` 데이터클래스로 정규화한다.
분석기·페이로드·문제 계층은 이 정규화된 뷰만 사용한다.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

from elftools.common.exceptions import ELFError
from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import NoteSection, SymbolTableSection
from elftools.elf.segments import InterpSegment

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
    entry_size: int = 0
    alignment: int = 0


@dataclass
class SymbolInfo:
    name: str
    addr: int
    size: int
    stype: str
    binding: str
    section_index: int | str
    visibility: str = "STV_DEFAULT"
    table: str = "symtab"
    defined: bool = True


@dataclass
class RelocationInfo:
    section: str
    target_section: str | None
    offset: int
    relocation_type: str
    relocation_type_id: int
    symbol: str | None
    symbol_index: int
    addend: int | None
    purpose: str
    verification: str = "verified"


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
    interpreter: str | None = None
    needed_libraries: list[str] = field(default_factory=list)
    soname: str | None = None
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    build_id: str | None = None
    gnu_properties: dict[str, int] = field(default_factory=dict)
    relocations: list[RelocationInfo] = field(default_factory=list)
    has_dynamic_section: bool = False

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

    @property
    def imports(self) -> list[SymbolInfo]:
        return [
            symbol
            for symbol in self.dynamic_symbols
            if symbol.name and not symbol.defined
        ]

    @property
    def exports(self) -> list[SymbolInfo]:
        return [
            symbol
            for symbol in self.dynamic_symbols
            if symbol.name
            and symbol.defined
            and symbol.binding in {"STB_GLOBAL", "STB_WEAK"}
        ]

    @property
    def linked_libc(self) -> str | None:
        return next(
            (
                library
                for library in self.needed_libraries
                if library == "libc.so.6" or library.startswith("libc-")
            ),
            None,
        )

    @property
    def linking(self) -> str:
        return (
            "dynamic"
            if self.interpreter or self.has_dynamic_section or self.needed_libraries
            else "static"
        )


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
                    entry_size=int(sec["sh_entsize"]),
                    alignment=int(sec["sh_addralign"]),
                )
            )

        symbols: list[SymbolInfo] = []
        dyn_symbols: list[SymbolInfo] = []
        dynamic_tags: list[str] = []
        dynamic_flags: dict[str, int] = {}
        needed_libraries: list[str] = []
        soname: str | None = None
        rpath: list[str] = []
        runpath: list[str] = []
        build_id: str | None = None
        gnu_properties: dict[str, int] = {}
        has_dynamic_section = False
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                has_dynamic_section = True
                for tag in sec.iter_tags():
                    name = str(tag.entry.d_tag)
                    dynamic_tags.append(name)
                    if name in {"DT_FLAGS", "DT_FLAGS_1"}:
                        dynamic_flags[name] = int(tag.entry.d_val)
                    elif name == "DT_NEEDED":
                        needed_libraries.append(str(tag.needed))  # type: ignore[attr-defined]
                    elif name == "DT_SONAME":
                        soname = str(tag.soname)  # type: ignore[attr-defined]
                    elif name == "DT_RPATH":
                        rpath.extend(
                            part
                            for part in str(tag.rpath).split(":")  # type: ignore[attr-defined]
                            if part
                        )
                    elif name == "DT_RUNPATH":
                        runpath.extend(
                            part
                            for part in str(tag.runpath).split(":")  # type: ignore[attr-defined]
                            if part
                        )
            if isinstance(sec, NoteSection):
                for note in sec.iter_notes():
                    if note["n_type"] == "NT_GNU_BUILD_ID":
                        build_id = str(note["n_desc"])
                    if note["n_type"] != "NT_GNU_PROPERTY_TYPE_0":
                        continue
                    description = note["n_desc"]
                    if not isinstance(description, list):
                        continue
                    for prop in description:
                        prop_type = str(prop["pr_type"])
                        prop_data = prop["pr_data"]
                        if isinstance(prop_data, int):
                            gnu_properties[prop_type] = prop_data
            if not isinstance(sec, SymbolTableSection):
                continue
            target = dyn_symbols if sec.name == ".dynsym" else symbols
            table = "dynsym" if sec.name == ".dynsym" else "symtab"
            for sym in sec.iter_symbols():
                info = sym["st_info"]
                section_index = sym["st_shndx"]
                target.append(
                    SymbolInfo(
                        name=sym.name or "",
                        addr=sym["st_value"],
                        size=sym["st_size"],
                        stype=str(info["type"]),
                        binding=str(info["bind"]),
                        section_index=section_index,
                        visibility=str(sym["st_other"]["visibility"]),
                        table=table,
                        defined=section_index not in ("SHN_UNDEF", 0),
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

        interpreter: str | None = None
        for seg in elf.iter_segments():
            if isinstance(seg, InterpSegment):
                interpreter = str(seg.get_interp_name())
                break

        got_ranges = [
            (section.addr, section.addr + section.size)
            for section in sections
            if section.name in {".got", ".got.plt"}
        ]
        relocations: list[RelocationInfo] = []
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            linked = elf.get_section(sec["sh_link"])
            symbol_table = linked if isinstance(linked, SymbolTableSection) else None
            target_index = int(sec["sh_info"])
            target_section = elf.get_section(target_index) if target_index else None
            target_name = target_section.name if target_section is not None else None
            for relocation in sec.iter_relocations():
                symbol_index = int(relocation["r_info_sym"])
                symbol_name: str | None = None
                if symbol_table is not None and symbol_index:
                    symbol_name = symbol_table.get_symbol(symbol_index).name or None
                offset = int(relocation["r_offset"])
                relocation_type_id = int(relocation["r_info_type"])
                if ".plt" in sec.name:
                    purpose = "plt"
                elif any(start <= offset < end for start, end in got_ranges):
                    purpose = "got"
                else:
                    purpose = "dynamic"
                relocations.append(
                    RelocationInfo(
                        section=sec.name,
                        target_section=target_name,
                        offset=offset,
                        relocation_type=describe_reloc_type(relocation_type_id, elf),
                        relocation_type_id=relocation_type_id,
                        symbol=symbol_name,
                        symbol_index=symbol_index,
                        addend=(
                            int(relocation["r_addend"])
                            if relocation.is_RELA()
                            else None
                        ),
                        purpose=purpose,
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
        interpreter=interpreter,
        needed_libraries=needed_libraries,
        soname=soname,
        rpath=rpath,
        runpath=runpath,
        build_id=build_id,
        gnu_properties=gnu_properties,
        relocations=relocations,
        has_dynamic_section=has_dynamic_section,
    )
