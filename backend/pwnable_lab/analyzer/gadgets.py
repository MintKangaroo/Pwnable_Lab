"""ROP 가젯 파인더.

실행 가능 섹션에서 ``ret``(0xC3) 바이트를 역방향으로 스캔하여, 그 앞의 짧은
명령 시퀀스를 Capstone 으로 디스어셈블해 가젯을 수집한다. ROPgadget/ropper 의
핵심 아이디어를 축약한 구현이다.
"""

from __future__ import annotations

from dataclasses import dataclass

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    Cs,
)

from pwnable_lab.elf.parser import ElfImage
from pwnable_lab.errors import AnalysisError

# 가젯을 끝맺는 바이트: ret, ret imm16, (간접) jmp/call rax 등은 단순화를 위해 ret 만
_RET = 0xC3
_MAX_BACK = 10  # ret 앞 최대 바이트 수


@dataclass
class Gadget:
    address: int
    bytes_hex: str
    instructions: list[str]  # ["pop rdi", "ret"]

    @property
    def text(self) -> str:
        return " ; ".join(self.instructions)


def _make_cs(image: ElfImage) -> Cs:
    if image.machine not in {"EM_386", "EM_X86_64"}:
        raise AnalysisError(
            f"ROP 가젯 검색은 현재 x86/x86-64만 지원합니다: {image.machine}"
        )
    mode = CS_MODE_64 if image.bits == 64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = False
    return md


def find_gadgets(
    image: ElfImage, *, max_gadgets: int = 2000, max_depth: int = 5
) -> list[Gadget]:
    """실행 섹션에서 ROP 가젯을 수집한다.

    Parameters
    ----------
    max_gadgets: 반환 가젯 상한(DoS 방지).
    max_depth: 가젯 하나에 허용되는 최대 명령 수(ret 포함).
    """
    md = _make_cs(image)
    seen: dict[int, Gadget] = {}

    for sec in image.sections:
        if not sec.executable or sec.size == 0:
            continue
        blob = image.data[sec.offset : sec.offset + sec.size]
        base = sec.addr

        for i, byte in enumerate(blob):
            if byte != _RET:
                continue
            # ret 앞의 여러 시작점에서 디스어셈블 시도
            for start in range(max(0, i - _MAX_BACK), i + 1):
                gadget = _decode_gadget(md, blob, start, i, base, max_depth)
                if gadget and gadget.address not in seen:
                    seen[gadget.address] = gadget
                    if len(seen) >= max_gadgets:
                        return _sorted(seen)
    return _sorted(seen)


def _decode_gadget(
    md: Cs, blob: bytes, start: int, ret_index: int, base: int, max_depth: int
) -> Gadget | None:
    end = ret_index + 1
    code = blob[start:end]
    insns: list[str] = []
    consumed = 0
    for insn in md.disasm(code, base + start):
        text = insn.mnemonic if not insn.op_str else f"{insn.mnemonic} {insn.op_str}"
        insns.append(text)
        consumed += insn.size
        if len(insns) > max_depth:
            return None
    # start 부터 정확히 ret 까지 딱 떨어지고, 마지막이 ret 이어야 유효
    if consumed != len(code) or not insns or insns[-1] != "ret":
        return None
    return Gadget(
        address=base + start,
        bytes_hex=code.hex(),
        instructions=insns,
    )


def _sorted(seen: dict[int, Gadget]) -> list[Gadget]:
    return [seen[a] for a in sorted(seen)]


def search_gadgets(gadgets: list[Gadget], query: str) -> list[Gadget]:
    """가젯 텍스트에 부분 문자열 매칭."""
    q = query.lower().strip()
    if not q:
        return gadgets
    return [g for g in gadgets if q in g.text.lower()]
