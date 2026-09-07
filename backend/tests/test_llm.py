"""LLM provider 추상화(Phase 7): 프라이버시 기본 차단 + provider 선택/설명."""

from __future__ import annotations

import sys
import types

from pwnable_lab.analyzer.llm import (
    AnthropicProvider,
    LLMProvider,
    NullProvider,
    build_provider,
)
from pwnable_lab.api.services import AnalysisService, _strategy_prompt
from pwnable_lab.config import Settings
from tests.fixtures import sample_elf


def test_null_provider_returns_empty():
    p = NullProvider()
    assert p.name == "null"
    assert p.explain("아무거나") == ""
    assert isinstance(p, LLMProvider)


def test_build_provider_defaults_to_null_when_disabled():
    # 기본 설정: LLM 비활성 → NullProvider(외부 전송 없음).
    assert build_provider(Settings()).name == "null"
    # 켰어도 provider=null 이면 NullProvider.
    assert (
        build_provider(Settings(llm_enabled=True, llm_provider="null")).name == "null"
    )


def test_build_provider_selects_anthropic_when_enabled():
    provider = build_provider(
        Settings(llm_enabled=True, llm_provider="anthropic", llm_model="claude-opus-5")
    )
    assert isinstance(provider, AnthropicProvider)
    assert provider.model == "claude-opus-5"


def test_build_provider_override_wins():
    class Fake:
        name = "fake"

        def explain(self, prompt, *, system=None):
            return "x"

    fake = Fake()
    # override 는 설정과 무관하게 우선한다(의존성 주입).
    assert build_provider(Settings(), override=fake) is fake


def _fake_anthropic(monkeypatch, *, stop_reason="end_turn", text="설명입니다"):
    """`anthropic` SDK 를 흉내내는 가짜 모듈을 sys.modules 에 심는다(라이브 호출 없음)."""
    calls = {}

    class _Block:
        def __init__(self, t):
            self.type = "text"
            self.text = t

    class _Resp:
        def __init__(self):
            self.stop_reason = stop_reason
            self.content = [_Block(text)]

    class _Messages:
        def create(self, **kwargs):
            calls.update(kwargs)
            return _Resp()

    class _Client:
        def __init__(self, *a, **k):
            self.messages = _Messages()

    module = types.ModuleType("anthropic")
    module.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", module)
    return calls


def test_anthropic_provider_calls_sdk_with_adaptive_thinking(monkeypatch):
    calls = _fake_anthropic(monkeypatch, text="ROP 로 익스합니다")
    out = AnthropicProvider(model="claude-opus-5", max_tokens=512).explain("요약")
    assert out == "ROP 로 익스합니다"
    # Opus 5 기본: 적응형 사고, 정확한 모델 ID, 요약이 user 메시지로.
    assert calls["model"] == "claude-opus-5"
    assert calls["thinking"] == {"type": "adaptive"}
    assert calls["max_tokens"] == 512
    assert calls["messages"][0]["content"] == "요약"


def test_anthropic_provider_handles_refusal(monkeypatch):
    _fake_anthropic(monkeypatch, stop_reason="refusal", text="")
    out = AnthropicProvider().explain("요약")
    assert "거부" in out


# --- 서비스 통합 ------------------------------------------------------------


def test_explain_strategy_disabled_by_default_no_egress():
    result = AnalysisService(Settings()).explain_strategy(sample_elf())
    assert "strategy" in result
    llm = result["llm"]
    assert llm["enabled"] is False
    assert llm["provider"] == "null"
    assert llm["explanation"] is None
    assert "외부 전송 없음" in llm["note"]


def test_explain_strategy_uses_injected_provider():
    class Fake:
        name = "fake"

        def explain(self, prompt, *, system=None):
            self.seen = prompt
            return "학습자용 설명"

    fake = Fake()
    service = AnalysisService(Settings(), llm_provider=fake)
    result = service.explain_strategy(sample_elf())
    assert result["llm"]["provider"] == "fake"
    assert result["llm"]["explanation"] == "학습자용 설명"
    # 프라이버시: 프롬프트에 바이너리 원본 바이트가 들어가지 않는다.
    assert "\x7fELF" not in fake.seen


def test_strategy_prompt_is_summary_only():
    strategy = {
        "machine": "x86-64",
        "bits": 64,
        "position_independent": False,
        "protections": {"nx": "NX enabled", "relro": "Partial"},
        "primitives": [{"key": "stack_overflow"}],
        "recommended_path_id": "rop_chain",
        "paths": [
            {
                "id": "rop_chain",
                "korean_title": "ROP 체인",
                "status": "likely",
                "summary": "가젯으로 execve 구성",
                "preconditions": ["쓰기 가능한 스택"],
            }
        ],
    }
    prompt = _strategy_prompt(strategy)
    assert "non-PIE" in prompt
    assert "ROP 체인" in prompt
    assert "rop_chain" in prompt
    assert "stack_overflow" in prompt
