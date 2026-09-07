"""프라이버시 기본 차단 LLM provider 추상화 (Phase 7).

정적 전략 분석(:func:`analyzer.strategy.analyze_strategy`)이 만든 근거를 자연어로
설명하는 **선택적** LLM 계층이다. 핵심 설계 원칙은 **프라이버시 기본 차단**이다:

* 기본 provider 는 :class:`NullProvider` — 아무 데이터도 외부로 나가지 않는다.
* :class:`AnthropicProvider` 는 명시적으로 켤 때만 쓰이며(``PLAB_LLM_ENABLED=1`` +
  ``PLAB_LLM_PROVIDER=anthropic``), ``anthropic`` SDK 를 **지연 임포트**한다(선택적
  의존성 — 기본 설치는 이 패키지가 필요 없다).
* 보내는 것은 **정적 전략 요약 텍스트**뿐이다 — 업로드 바이너리 원본이 아니다.

provider 는 :class:`LLMProvider` 프로토콜(``name`` + ``explain``)만 만족하면 되므로
테스트/다른 백엔드로 쉽게 교체된다.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pwnable_lab.config import Settings


@runtime_checkable
class LLMProvider(Protocol):
    """전략 요약을 자연어 설명으로 바꾸는 provider."""

    name: str

    def explain(self, prompt: str, *, system: str | None = None) -> str:
        """``prompt`` 에 대한 설명을 반환한다. 빈 문자열이면 '설명 없음'(정적 폴백)."""
        ...


class NullProvider:
    """기본 provider — 외부로 아무것도 보내지 않고 빈 설명을 반환한다."""

    name = "null"

    def explain(self, prompt: str, *, system: str | None = None) -> str:
        return ""


class AnthropicProvider:
    """Anthropic Claude provider(opt-in). ``anthropic`` SDK 를 지연 임포트한다.

    기본 모델은 ``claude-opus-5``. Opus 5 는 적응형 사고(adaptive thinking)가 기본이며
    안전 분류 거부(``stop_reason == "refusal"``)를 항상 확인한다.
    """

    name = "anthropic"

    def __init__(self, *, model: str = "claude-opus-5", max_tokens: int = 1024) -> None:
        self.model = model
        self.max_tokens = max_tokens

    def explain(self, prompt: str, *, system: str | None = None) -> str:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - 선택적 의존성 미설치
            raise RuntimeError(
                "anthropic provider 를 쓰려면 `anthropic` SDK 가 필요합니다"
                " (pip install anthropic)."
            ) from exc

        client = anthropic.Anthropic()
        # SDK 타입에 결합하지 않도록 응답을 동적으로 다룬다(선택적 의존성).
        response: Any = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            thinking={"type": "adaptive"},
            system=system or _DEFAULT_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        if getattr(response, "stop_reason", None) == "refusal":
            return "(요청이 안전 분류로 거부되었습니다.)"
        parts = [
            getattr(block, "text", "")
            for block in response.content
            if getattr(block, "type", None) == "text"
        ]
        return "".join(parts).strip()


_DEFAULT_SYSTEM = (
    "당신은 바이너리 취약점 분석 조교입니다. 주어진 정적 익스 전략 요약을 학습자가"
    " 이해하도록 한국어로 간결히 설명하세요. 요약에 없는 사실을 지어내지 마세요."
)


def build_provider(
    settings: Settings, *, override: LLMProvider | None = None
) -> LLMProvider:
    """설정(과 선택적 override)에 따라 provider 를 만든다.

    ``override`` 는 테스트/의존성 주입용이다. LLM 이 비활성이면 항상 NullProvider
    (프라이버시 기본 차단)를 반환한다.
    """

    if override is not None:
        return override
    if not settings.llm_enabled:
        return NullProvider()
    if settings.llm_provider == "anthropic":
        return AnthropicProvider(
            model=settings.llm_model, max_tokens=settings.llm_max_tokens
        )
    return NullProvider()


__all__ = ["AnthropicProvider", "LLMProvider", "NullProvider", "build_provider"]
