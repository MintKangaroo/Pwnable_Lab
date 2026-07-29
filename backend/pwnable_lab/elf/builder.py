"""컴파일러 없이 유효한 ELF64(x86-64) 실행 파일을 합성하는 빌더.

실습 문제 생성기는 이 빌더로 작은 "취약한" 바이너리를 만들어 낸다. 생성물은
pyelftools 로 파싱 가능하고 Capstone 으로 디스어셈블 가능하며, checksec 성 완화
기법(NX/PIE/RELRO/Canary)을 문제 요구에 맞춰 켜고 끌 수 있다.

의도적으로 최소한의 구조만 만든다. 실제 로더에서 실행되는 것이 목적이 아니라
**정적 분석 대상**으로서 학습에 쓰이는 것이 목적이다.

파일 레이아웃::

    [ELF header][program headers][.text][.rodata]
    [.shstrtab][.symtab][.strtab][section headers]

섹션 헤더/심볼 테이블은 로드되지 않으므로 파일 끝쪽에 자유롭게 배치한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# --- ELF 상수 -------------------------------------------------------------
ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62

PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4

STB_LOCAL, STB_GLOBAL = 0, 1
STT_NOTYPE, STT_OBJECT, STT_FUNC = 0, 1, 2

DEFAULT_BASE = 0x400000
PAGE = 0x1000


@dataclass
class Symbol:
    """빌드 대상 심볼 하나."""

    name: str
    section: str  # ".text" 또는 ".rodata"
    offset: int  # 섹션 내 오프셋
    size: int = 0
    stype: int = STT_FUNC
    binding: int = STB_GLOBAL


@dataclass
class ElfBuilder:
    """x86-64 ELF64 실행 파일 빌더.

    Parameters
    ----------
    text:
        ``.text`` 섹션에 들어갈 기계어 바이트.
    rodata:
        ``.rodata`` 섹션에 들어갈 읽기 전용 데이터.
    symbols:
        심볼 테이블에 기록할 심볼 목록.
    pie:
        True 이면 ET_DYN(PIE), False 이면 ET_EXEC(No PIE).
    nx:
        True 이면 GNU_STACK 을 RW(NX 활성), False 이면 RWX(NX 비활성).
    relro:
        ``"full"`` | ``"partial"`` | ``"none"`` — GNU_RELRO 헤더 및 표식.
    canary:
        True 이면 ``__stack_chk_fail`` 심볼을 추가(카나리 사용 표식).
    """

    text: bytes
    rodata: bytes = b""
    symbols: list[Symbol] = field(default_factory=list)
    pie: bool = False
    nx: bool = True
    relro: str = "partial"
    canary: bool = False
    base: int = DEFAULT_BASE

    def build(self) -> bytes:
        symbols = list(self.symbols)
        if self.canary and not any(s.name == "__stack_chk_fail" for s in symbols):
            symbols.append(
                Symbol("__stack_chk_fail", ".text", 0, 0, STT_FUNC, STB_GLOBAL)
            )
        # Full RELRO 표식 (학습용 정적 바이너리 관례; checksec 이 이 심볼을 읽는다)
        if self.relro == "full" and not any(s.name == "__relro_full" for s in symbols):
            symbols.append(Symbol("__relro_full", ".text", 0, 0, STT_NOTYPE, STB_LOCAL))

        ehsize = 64
        phentsize = 56
        # RELRO 가 꺼진 바이너리에는 PT_GNU_RELRO 자체가 없어야 한다. 빈 세그먼트도
        # checksec 류 도구에서는 Partial RELRO 로 인식될 수 있다.
        phnum = 2 + (1 if self.relro != "none" else 0)

        # --- 로드되는 부분의 파일 오프셋 배치 ---
        phoff = ehsize
        text_off = phoff + phentsize * phnum
        # .text 는 16바이트 정렬
        text_off = _align(text_off, 16)
        rodata_off = _align(text_off + len(self.text), 16)
        loaded_end = rodata_off + len(self.rodata)

        # 가상 주소: 파일 오프셋과 동일한 상대 위치 (한 개의 PT_LOAD)
        base = 0 if self.pie else self.base
        text_vaddr = base + text_off
        rodata_vaddr = base + rodata_off
        entry = text_vaddr

        # --- 로드되지 않는 메타데이터: shstrtab, symtab, strtab ---
        shstrtab_names = [
            "",
            ".text",
            ".rodata",
            ".shstrtab",
            ".symtab",
            ".strtab",
        ]
        shstrtab, sh_name_off = _build_strtab(shstrtab_names)

        # 심볼 문자열 테이블
        sym_strtab_bytes = bytearray(b"\x00")
        sym_name_off: dict[str, int] = {"": 0}
        for s in symbols:
            if s.name not in sym_name_off:
                sym_name_off[s.name] = len(sym_strtab_bytes)
                sym_strtab_bytes += s.name.encode() + b"\x00"

        # 심볼 정렬: local 먼저, global 나중 (ELF 규약)
        ordered = sorted(symbols, key=lambda s: s.binding != STB_LOCAL)
        first_global = sum(1 for s in ordered if s.binding == STB_LOCAL) + 1  # +1: null

        symtab_bytes = bytearray(_pack_sym(0, 0, 0, 0, 0, 0))  # null 심볼
        for s in ordered:
            sec_vaddr = text_vaddr if s.section == ".text" else rodata_vaddr
            shndx = 1 if s.section == ".text" else 2
            st_info = (s.binding << 4) | (s.stype & 0xF)
            symtab_bytes += _pack_sym(
                sym_name_off[s.name], st_info, 0, shndx, sec_vaddr + s.offset, s.size
            )

        shstrtab_off = _align(loaded_end, 4)
        symtab_off = _align(shstrtab_off + len(shstrtab), 8)
        strtab_off = symtab_off + len(symtab_bytes)
        shoff = _align(strtab_off + len(sym_strtab_bytes), 8)

        # --- 섹션 헤더 6개 (null, .text, .rodata, .shstrtab, .symtab, .strtab) ---
        shstrtab_idx = 3
        symtab_idx = 4
        strtab_idx = 5
        sections = [
            _sh(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
            _sh(sh_name_off[".text"], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                text_vaddr, text_off, len(self.text), 0, 0, 16, 0),
            _sh(sh_name_off[".rodata"], SHT_PROGBITS, SHF_ALLOC,
                rodata_vaddr, rodata_off, len(self.rodata), 0, 0, 16, 0),
            _sh(sh_name_off[".shstrtab"], SHT_STRTAB, 0, 0, shstrtab_off,
                len(shstrtab), 0, 0, 1, 0),
            _sh(sh_name_off[".symtab"], SHT_SYMTAB, 0, 0, symtab_off,
                len(symtab_bytes), strtab_idx, first_global, 8, 24),
            _sh(sh_name_off[".strtab"], SHT_STRTAB, 0, 0, strtab_off,
                len(sym_strtab_bytes), 0, 0, 1, 0),
        ]
        shnum = len(sections)

        # --- 프로그램 헤더 ---
        load_filesz = loaded_end
        stack_flags = PF_R | PF_W | (0 if self.nx else PF_X)
        phdr_list = [
            _ph(PT_LOAD, PF_R | PF_X, 0, base, base, load_filesz, load_filesz, PAGE),
            _ph(PT_GNU_STACK, stack_flags, 0, 0, 0, 0, 0, 0x10),
        ]
        if self.relro != "none":
            phdr_list.append(
                _ph(PT_GNU_RELRO, PF_R, rodata_off, rodata_vaddr, rodata_vaddr,
                len(self.rodata) if self.relro != "none" else 0,
                len(self.rodata) if self.relro != "none" else 0, 1)
            )
        phdrs = b"".join(phdr_list)

        # --- ELF 헤더 ---
        e_type = ET_DYN if self.pie else ET_EXEC
        ehdr = _elf_header(
            e_type=e_type, entry=entry, phoff=phoff, shoff=shoff,
            phentsize=phentsize, phnum=phnum, shnum=shnum, shstrndx=shstrtab_idx,
        )

        # --- 조립 ---
        buf = bytearray(shoff + len(b"".join(sections)))
        _put(buf, 0, ehdr)
        _put(buf, phoff, phdrs)
        _put(buf, text_off, self.text)
        _put(buf, rodata_off, self.rodata)
        _put(buf, shstrtab_off, shstrtab)
        _put(buf, symtab_off, bytes(symtab_bytes))
        _put(buf, strtab_off, bytes(sym_strtab_bytes))
        _put(buf, shoff, b"".join(sections))
        return bytes(buf)


# --- 헬퍼 ---------------------------------------------------------------


def _align(value: int, alignment: int) -> int:
    rem = value % alignment
    return value if rem == 0 else value + (alignment - rem)


def _put(buf: bytearray, off: int, data: bytes) -> None:
    end = off + len(data)
    if end > len(buf):
        buf.extend(b"\x00" * (end - len(buf)))
    buf[off:end] = data


def _build_strtab(names: list[str]) -> tuple[bytes, dict[str, int]]:
    out = bytearray()
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(out)
        out += name.encode() + b"\x00"
    return bytes(out), offsets


def _elf_header(*, e_type: int, entry: int, phoff: int, shoff: int,
                phentsize: int, phnum: int, shnum: int, shstrndx: int) -> bytes:
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 64bit, LE, SysV
    return e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, EM_X86_64, 1, entry, phoff, shoff, 0,
        64, phentsize, phnum, 64, shnum, shstrndx,
    )


def _ph(p_type: int, flags: int, offset: int, vaddr: int, paddr: int,
        filesz: int, memsz: int, align: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, flags, offset, vaddr, paddr,
                       filesz, memsz, align)


def _sh(name: int, stype: int, flags: int, addr: int, offset: int, size: int,
        link: int, info: int, align: int, entsize: int) -> bytes:
    return struct.pack("<IIQQQQIIQQ", name, stype, flags, addr, offset, size,
                       link, info, align, entsize)


def _pack_sym(name: int, info: int, other: int, shndx: int, value: int,
              size: int) -> bytes:
    return struct.pack("<IBBHQQ", name, info, other, shndx, value, size)
