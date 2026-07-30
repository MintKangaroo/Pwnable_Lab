"""결정론적 문제 생성, 아티팩트, 채점 계약 테스트."""

from __future__ import annotations

import pytest

from pwnable_lab.challenge.models import _normalize
from pwnable_lab.challenge.registry import (
    get_challenge,
    get_registry,
    list_challenges,
)
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.errors import NotFoundError


def test_registry_has_six_unique_challenges():
    metas = list_challenges()
    assert len(metas) == 6
    assert len({meta.slug for meta in metas}) == 6
    assert {meta.level for meta in metas} == {"Easy", "Medium", "Hard"}


def test_every_challenge_artifact_is_valid_elf_and_answer_roundtrips():
    for slug, challenge in get_registry().items():
        image = parse_elf(challenge.artifact)
        assert image.bits == 64, slug
        assert challenge.check(challenge.answer), slug
        assert not challenge.check("__definitely_wrong__"), slug
        assert challenge.solution
        assert challenge.hints


def test_challenge_generation_is_stable():
    before = {
        slug: (challenge.artifact, challenge.answer)
        for slug, challenge in get_registry().items()
    }
    get_registry.cache_clear()
    after = {
        slug: (challenge.artifact, challenge.answer)
        for slug, challenge in get_registry().items()
    }
    assert before == after


@pytest.mark.parametrize(
    ("value", "kind", "expected"),
    [
        ("0x00401156", "hex-address", "401156"),
        (" 00072 ", "integer", "72"),
        ("0x48", "integer", "72"),
        (" PIE ", "keyword", "pie"),
        (" FLAG{Case} ", "text", "FLAG{Case}"),
    ],
)
def test_answer_normalization(value, kind, expected):
    assert _normalize(value, kind) == expected


def test_unknown_challenge_raises_not_found():
    with pytest.raises(NotFoundError):
        get_challenge("does-not-exist")


def test_challenge_list_never_leaks_answers(client):
    response = client.get("/api/challenges")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 6
    assert all("answer" not in item and "solution" not in item for item in items)
    assert all(item["stats"] == {"attempts": 0, "solved": 0} for item in items)


def test_challenge_detail_and_artifact(client):
    detail = client.get("/api/challenges/ret2win")
    assert detail.status_code == 200
    assert "answer" not in detail.json()
    assert "solution" not in detail.json()
    assert detail.json()["hints"]

    artifact = client.get("/api/challenges/ret2win/artifact")
    assert artifact.status_code == 200
    assert artifact.content.startswith(b"\x7fELF")
    assert "ret2win.elf" in artifact.headers["content-disposition"]


def test_challenge_submit_wrong_then_correct_and_updates_stats(client):
    challenge = get_challenge("ret2win")
    wrong = client.post("/api/challenges/ret2win/submit", json={"answer": "0xdeadbeef"})
    assert wrong.status_code == 200
    assert wrong.json() == {
        "correct": False,
        "solution": None,
        "message": "오답입니다. 다시 시도하세요.",
    }

    correct = client.post(
        "/api/challenges/ret2win/submit", json={"answer": challenge.answer}
    )
    assert correct.status_code == 200
    assert correct.json()["correct"] is True
    assert correct.json()["solution"] == challenge.solution

    detail = client.get("/api/challenges/ret2win").json()
    assert detail["stats"] == {"attempts": 2, "solved": 1}


def test_unknown_challenge_api_is_404(client):
    assert client.get("/api/challenges/nope").status_code == 404
    assert client.get("/api/challenges/nope/artifact").status_code == 404
