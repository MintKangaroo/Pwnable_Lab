"""동적 실행 게이트 — 서비스 계층과 CLI 워커가 공유하는 안전 검증.

기본 비활성이며, 통과하려면 두 조건을 만족해야 한다:

1. ``sandbox_execution_enabled`` (마스터 게이트) — 켜는 행위 자체가
   "network-disabled 일회용 컨테이너 경계를 갖췄다"는 운영자의 명시적 확인.
2. ``sandbox_isolation_marker`` 가 지정됐다면 그 경로가 실제로 존재 —
   컨테이너 엔트리포인트가 생성하는 파일을 가리켜, 컨테이너 밖(개발 호스트)
   에서의 무방비 실행을 한 겹 더 차단한다.

어느 하나라도 실패하면 :class:`~pwnable_lab.errors.SandboxError` 를 던진다.
"""

from __future__ import annotations

import os
from typing import Protocol

from pwnable_lab.errors import SandboxError


class _GateSettings(Protocol):
    sandbox_execution_enabled: bool
    sandbox_isolation_marker: str


def require_sandbox_boundary(settings: _GateSettings) -> None:
    """게이트 + 격리 마커를 검증한다. 실패 시 ``SandboxError``."""

    if not settings.sandbox_execution_enabled:
        raise SandboxError(
            "동적 오프셋 확정(sandbox 실행)이 이 배포에서 비활성화돼 있습니다. "
            "network-disabled 격리 컨테이너 안에서 "
            "PLAB_SANDBOX_EXECUTION_ENABLED=1 로만 활성화하세요."
        )
    marker = settings.sandbox_isolation_marker
    if marker and not os.path.exists(marker):
        raise SandboxError(
            "격리 마커를 찾을 수 없어 실행을 거부합니다: "
            f"{marker} (컨테이너 경계 미확인)."
        )
