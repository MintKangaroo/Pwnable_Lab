"""Phase 6A — auto-exploit sandbox (오프셋 확정 코어).

정적 exploit strategy(:mod:`pwnable_lab.analyzer.strategy`)가 추정한 오프셋을
**실제 실행으로 검증**하는 격리 러너의 핵심 로직을 제공한다. 이 증분은
`docs/AUTO_EXPLOIT_SANDBOX.md` 의 첫 단계(cyclic 주입 → 크래시 관측 →
`RIP`/스택 값으로 정확한 오프셋 확정)만 구현한다.

.. warning::
   이 모듈은 **신뢰할 수 없는 바이너리를 실행**한다. 여기서는 프로세스 단위
   자원 상한(rlimit)·타임아웃·프로세스그룹 강제 종료만 강제한다. 프로덕션
   노출 전에는 반드시 Phase 6 의 network-disabled 일회용 컨테이너(nsjail/gVisor
   등) 경계 안에서 호출해야 한다. 그 경계가 없는 상태로 업로드 API 파이프라인에
   직접 연결하지 말 것(현재 기본적으로 연결돼 있지 않다).
"""

from pwnable_lab.sandbox.gate import require_sandbox_boundary
from pwnable_lab.sandbox.runner import (
    CrashObservation,
    OffsetConfirmation,
    SandboxLimits,
    confirm_return_offset,
    run_with_input,
)

__all__ = [
    "CrashObservation",
    "OffsetConfirmation",
    "SandboxLimits",
    "confirm_return_offset",
    "require_sandbox_boundary",
    "run_with_input",
]
