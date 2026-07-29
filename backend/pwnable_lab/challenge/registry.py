"""문제 레지스트리 — 슬러그로 생성기를 조회하고 인스턴스를 캐시한다.

각 문제는 슬러그 기반 시드로 결정론적으로 생성되므로, 프로세스 수명 동안 (그리고
재시작 후에도) 동일한 아티팩트와 정답을 갖는다. 정답과 풀이는 서버에만 존재한다.
"""

from __future__ import annotations

from functools import lru_cache

from pwnable_lab.challenge.generators import ALL_GENERATORS
from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge
from pwnable_lab.errors import NotFoundError


@lru_cache(maxsize=1)
def get_registry() -> dict[str, GeneratedChallenge]:
    registry: dict[str, GeneratedChallenge] = {}
    for gen in ALL_GENERATORS:
        registry[gen.meta.slug] = gen.build()
    return registry


def list_challenges() -> list[ChallengeMeta]:
    return [c.meta for c in get_registry().values()]


def get_challenge(slug: str) -> GeneratedChallenge:
    try:
        return get_registry()[slug]
    except KeyError as exc:
        raise NotFoundError(f"문제를 찾을 수 없습니다: {slug}") from exc
