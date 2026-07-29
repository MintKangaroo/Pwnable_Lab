"""문제 도메인 모델."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ChallengeMeta:
    slug: str
    title: str
    level: str  # "Easy" | "Medium" | "Hard"
    category: str  # "stack" | "rop" | "format-string" | "mitigation" ...
    technique: str
    description: str
    prompt: str  # 사용자가 무엇을 제출해야 하는지
    answer_format: str  # "hex-address" | "integer" | "text" | "keyword"

    def public_dict(self) -> dict:
        return {
            "slug": self.slug,
            "title": self.title,
            "level": self.level,
            "category": self.category,
            "technique": self.technique,
            "description": self.description,
            "prompt": self.prompt,
            "answer_format": self.answer_format,
        }


@dataclass
class GeneratedChallenge:
    """생성된 문제 인스턴스: 메타데이터 + 아티팩트 + 정답(서버 전용)."""

    meta: ChallengeMeta
    artifact: bytes
    answer: str
    solution: str  # 풀이 설명(정답 제출 후에만 노출)
    hints: list[str] = field(default_factory=list)

    def check(self, submission: str) -> bool:
        """정답을 상수 시간 비교로 검증한다."""
        expected = _normalize(self.answer, self.meta.answer_format)
        given = _normalize(submission, self.meta.answer_format)
        return hmac.compare_digest(expected, given)


def _normalize(value: str, answer_format: str) -> str:
    v = value.strip()
    if answer_format == "hex-address":
        v = v.lower().replace(" ", "")
        if v.startswith("0x"):
            v = v[2:]
        v = v.lstrip("0") or "0"
        return v
    if answer_format == "integer":
        v = v.replace(" ", "")
        if v.lower().startswith("0x"):
            try:
                return str(int(v, 16))
            except ValueError:
                return v
        return v.lstrip("0") or "0"
    if answer_format == "keyword":
        return v.lower()
    return v  # text: 대소문자·공백 유지
