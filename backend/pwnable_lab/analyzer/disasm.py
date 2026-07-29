"""선형 디스어셈블(Capstone) — 함수/영역 단위 명령 나열."""

from __future__ import annotations

from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from pwnable_lab.elf.parser import ElfImage
from pwnable_lab.errors import AnalysisError


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str

    @property
    def text(self) -> str:
        return self.mnemonic if not self.op_str else f"{self.mnemonic} {self.op_str}"


def disassemble(image: ElfImage, *, address: int | None = None,
                count: int = 200, max_instructions: int = 20000) -> list[Instruction]:
    """주어진 주소(기본: entry)에서 최대 ``count`` 개 명령을 선형 디스어셈블."""
    if image.machine not in {"EM_386", "EM_X86_64"}:
        raise AnalysisError(
            f"디스어셈블리는 현재 x86/x86-64만 지원합니다: {image.machine}"
        )
    if count > max_instructions:
        raise AnalysisError(f"요청 명령 수({count})가 한계({max_instructions})를 초과했습니다.")

    text = image.section(".text")
    if text is None:
        raise AnalysisError(".text 섹션이 없습니다.")

    start = address if address is not None else (image.entry or text.addr)
    if not (text.addr <= start < text.addr + text.size):
        raise AnalysisError("주소가 .text 범위를 벗어났습니다.")

    offset = text.offset + (start - text.addr)
    blob = image.data[offset : text.offset + text.size]

    mode = CS_MODE_64 if image.bits == 64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)

    out: list[Instruction] = []
    for insn in md.disasm(blob, start):
        out.append(
            Instruction(insn.address, insn.mnemonic, insn.op_str, insn.bytes.hex())
        )
        if len(out) >= count:
            break
    return out
