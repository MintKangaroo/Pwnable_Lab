"""도메인 예외 계층.

분석 코어는 프레임워크(FastAPI)에 의존하지 않는다. 대신 아래의 타입이 명시된
예외를 던지고, API 레이어(:mod:`pwnable_lab.api.errors`)가 이를 HTTP 상태로 매핑한다.
"""

from __future__ import annotations


class PwnableLabError(Exception):
    """모든 도메인 예외의 최상위 타입."""


class UnsupportedFormatError(PwnableLabError):
    """지원하지 않는 바이너리 포맷(현재 코어는 ELF64만 완전 지원)."""


class PayloadTooLargeError(PwnableLabError):
    """업로드 또는 생성 요청이 설정된 자원 상한을 초과함."""


class ParseError(PwnableLabError):
    """바이너리 파싱 실패(손상된 헤더, 잘린 파일 등)."""


class AnalysisError(PwnableLabError):
    """분석 단계에서의 오류(디스어셈블 한계 초과 등)."""


class NotFoundError(PwnableLabError):
    """요청한 리소스(바이너리, 문제 등)를 찾을 수 없음."""


class ChallengeError(PwnableLabError):
    """문제 생성/채점 관련 오류."""


class ToolUnavailableError(PwnableLabError):
    """외부 도구(예: ROPgadget, one_gadget)를 사용할 수 없음."""
