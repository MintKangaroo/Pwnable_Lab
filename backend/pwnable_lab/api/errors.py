"""도메인 예외 → HTTP 상태 매핑."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from pwnable_lab.errors import (
    AnalysisError,
    ChallengeError,
    NotFoundError,
    ParseError,
    PayloadTooLargeError,
    PwnableLabError,
    SandboxError,
    ToolUnavailableError,
    UnsupportedFormatError,
)

_STATUS = {
    UnsupportedFormatError: 415,
    PayloadTooLargeError: 413,
    ParseError: 422,
    NotFoundError: 404,
    ToolUnavailableError: 503,
    # 동적 샌드박스 미가용/비활성/플랫폼 미지원 → 서비스 사용 불가.
    SandboxError: 503,
    ChallengeError: 400,
    AnalysisError: 400,
}


def install_error_handlers(app) -> None:
    @app.exception_handler(PwnableLabError)
    async def _handle(request: Request, exc: PwnableLabError):  # noqa: ANN001
        status = 500
        for exc_type, code in _STATUS.items():
            if isinstance(exc, exc_type):
                status = code
                break
        return JSONResponse(
            status_code=status,
            content={"error": exc.__class__.__name__, "detail": str(exc)},
        )
