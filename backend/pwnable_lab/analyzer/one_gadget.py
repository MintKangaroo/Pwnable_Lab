"""one_gadget 정적 탐지 — libc 안의 원샷 ``execve("/bin/sh")`` 가젯.

ret2libc 는 보통 ``pop rdi; "/bin/sh"; system`` 처럼 여러 가젯을 쌓아야 하지만,
libc 에는 **한 주소로 점프하면 곧바로 ``execve("/bin/sh", ...)``** 가 실행되는 지점이
있다(one_gadget). 이 모듈은 libc 실행 코드를 훑어 ``rdi = "/bin/sh"`` 로 만든 뒤
가까이서 ``execve`` 를 호출하는 지점을 찾아 그 오프셋(libc base 상대)과 제약(주로
``rsi``/``rdx`` 가 NULL 이어야 함)을 보고한다.

정직성/한계: 완전한 심볼릭 분석(진짜 ``one_gadget`` 도구)이 아니라, ``lea rdi,
[rip+/bin/sh]`` 뒤에 ``call execve`` 또는 execve ``syscall`` 이 오는 **명확한 패턴**만
찾는다. 진짜 도구가 찾는 일부 복잡한 제약 가젯은 놓칠 수 있다(보수적으로 확실한 것만).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # type: ignore[import-untyped]

from pwnable_lab.analyzer.strategy import find_string
from pwnable_lab.elf.parser import ElfImage

# rdi 로드 이후 execve 호출을 찾는 전방 탐색 창(명령 수).
_WINDOW = 24
_SYS_EXECVE = 0x3B
_RIP_DISP = re.compile(r"rip ([+-]) (0x[0-9a-fA-F]+)")


@dataclass
class OneGadget:
    """libc 안의 원샷 execve 가젯 하나."""

    offset: int  # libc base 상대 오프셋(= .so 의 vaddr).
    execve_via: str  # "call" | "syscall"
    constraints: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "execve_via": self.execve_via,
            "constraints": self.constraints,
        }


def find_one_gadgets(image: ElfImage, *, max_results: int = 16) -> list[OneGadget]:
    """libc 이미지에서 원샷 execve("/bin/sh") 가젯 후보를 찾는다.

    ``lea rdi, [rip+/bin/sh]`` 로 rdi 를 셸 문자열로 만든 뒤 ``_WINDOW`` 안에서
    ``call execve`` 또는 execve ``syscall`` 에 도달하는 지점을 후보로 본다.
    """

    if (image.bits or 64) != 64 or image.machine != "EM_X86_64":
        return []
    binsh = find_string(image, b"/bin/sh\x00")
    if binsh is None:
        return []
    execve_addrs = {
        s.addr
        for s in image.symbols + image.dynamic_symbols
        if s.name in {"execve", "__execve", "__GI_execve"} and s.addr
    }

    text = image.section(".text")
    if text is None:
        return []
    blob = image.data[text.offset : text.offset + text.size]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    insns = list(md.disasm(blob, text.addr))

    results: list[OneGadget] = []
    for i, insn in enumerate(insns):
        if not (
            insn.mnemonic == "lea"
            and insn.op_str.startswith("rdi")
            and "rip" in insn.op_str
        ):
            continue
        match = _RIP_DISP.search(insn.op_str)
        if not match:
            continue
        disp = int(match.group(2), 16)
        target = insn.address + insn.size + (disp if match.group(1) == "+" else -disp)
        if target != binsh:
            continue

        gadget = _scan_execve(insns, i, execve_addrs)
        if gadget is not None:
            results.append(gadget)
            if len(results) >= max_results:
                break
    return results


def _scan_execve(insns: list, start: int, execve_addrs: set[int]) -> OneGadget | None:
    """rdi=binsh 로드(``insns[start]``) 이후 창에서 execve 호출을 찾는다.

    도달하면 그 사이 ``rsi``/``rdx`` 가 NULL 로 설정됐는지 보고 제약을 만든다.
    """

    rsi_null = rdx_null = False
    for j in range(start + 1, min(start + 1 + _WINDOW, len(insns))):
        w = insns[j]
        mnem, ops = w.mnemonic, w.op_str
        if mnem == "xor" and ops in {"esi, esi", "rsi, rsi"}:
            rsi_null = True
        elif mnem == "xor" and ops in {"edx, edx", "rdx, rdx"}:
            rdx_null = True
        elif mnem == "mov" and ops in {"esi, 0", "rsi, 0"}:
            rsi_null = True
        elif mnem == "mov" and ops in {"edx, 0", "rdx, 0"}:
            rdx_null = True
        elif mnem == "call":
            try:
                dst = int(ops, 16)
            except ValueError:
                continue
            if dst in execve_addrs:
                return OneGadget(
                    offset=insns[start].address,
                    execve_via="call",
                    constraints=_constraints(rsi_null, rdx_null),
                )
        elif mnem == "syscall":
            return OneGadget(
                offset=insns[start].address,
                execve_via="syscall",
                constraints=_constraints(rsi_null, rdx_null),
            )
        elif mnem in {"ret", "jmp"}:
            break  # 흐름이 갈라지면 이 후보는 종료.
    return None


def _constraints(rsi_null: bool, rdx_null: bool) -> list[str]:
    out: list[str] = []
    if not rsi_null:
        out.append("rsi (argv) 가 NULL 또는 유효 포인터여야 합니다.")
    if not rdx_null:
        out.append("rdx (envp) 가 NULL 또는 유효 포인터여야 합니다.")
    if not out:
        out.append("추가 제약 없음(rsi/rdx 가 NULL 로 설정됨).")
    return out


__all__ = ["OneGadget", "find_one_gadgets"]
