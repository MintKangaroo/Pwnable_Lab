"""SROP(Sigreturn-Oriented Programming) sigreturn 프레임 빌더 (amd64).

``rt_sigreturn`` 시스템콜(rax=15)은 스택의 가짜 ``ucontext`` 에서 **모든 레지스터**
(rdi/rsi/rdx/rax/rip/rsp 등)를 한 번에 복원한다. pop 가젯이 부족해도 ``syscall`` 가젯과
rax 를 15 로 만드는 수단만 있으면 임의 레지스터 상태를 세팅할 수 있어 강력하다.

레지스터는 rsp 가 sigreturn 시점에 가리키는 ``ucontext`` 안의 ``uc_mcontext`` 에서
읽힌다. 아래 오프셋(rsp 기준 바이트)은 amd64 커널 레이아웃이다(pwntools SigreturnFrame
과 동일). ``cs`` 는 유저 코드 세그먼트 0x33 이어야 sigreturn 이 정상 복귀한다.
"""

from __future__ import annotations

import struct

# rsp 기준 각 레지스터의 바이트 오프셋(amd64 uc_mcontext.gregs).
_OFFSETS = {
    "r8": 0x28,
    "r9": 0x30,
    "r10": 0x38,
    "r11": 0x40,
    "r12": 0x48,
    "r13": 0x50,
    "r14": 0x58,
    "r15": 0x60,
    "rdi": 0x68,
    "rsi": 0x70,
    "rbp": 0x78,
    "rbx": 0x80,
    "rdx": 0x88,
    "rax": 0x90,
    "rcx": 0x98,
    "rsp": 0xA0,
    "rip": 0xA8,
    "eflags": 0xB0,
    "csgsfs": 0xB8,  # cs(하위 16비트)=0x33 필수
}
_FRAME_SIZE = 0xF8  # rip/eflags/csgsfs·&fpstate(0) 를 모두 담는 크기


def build_sigreturn_frame(**regs: int) -> bytes:
    """amd64 sigreturn 프레임 바이트를 만든다.

    ``build_sigreturn_frame(rip=..., rax=59, rdi=binsh, rsi=0, rdx=0, rsp=...)`` 처럼
    세팅할 레지스터를 키워드로 준다. ``csgsfs`` 는 기본 0x33(cs). 지정하지 않은 필드는
    0(``&fpstate=0`` 포함). 알 수 없는 레지스터 이름은 오류.
    """

    frame = bytearray(_FRAME_SIZE)
    regs.setdefault("csgsfs", 0x33)
    for name, value in regs.items():
        offset = _OFFSETS.get(name)
        if offset is None:
            raise ValueError(f"알 수 없는 레지스터: {name}")
        struct.pack_into("<Q", frame, offset, value & 0xFFFFFFFFFFFFFFFF)
    return bytes(frame)


__all__ = ["build_sigreturn_frame"]
