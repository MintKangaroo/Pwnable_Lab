"""실습 문제 라우트 — 목록, 아티팩트 다운로드, 정답 제출."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response

from pwnable_lab.api.dependencies import get_repository
from pwnable_lab.api.schemas import SubmitRequest, SubmitResponse
from pwnable_lab.challenge.registry import get_challenge, list_challenges
from pwnable_lab.database.repository import BinaryRepository

router = APIRouter(prefix="/challenges", tags=["challenges"])


@router.get("")
def challenges(repo: BinaryRepository = Depends(get_repository)) -> list[dict]:
    out = []
    for meta in list_challenges():
        d = meta.public_dict()
        d["stats"] = repo.stats(meta.slug)
        out.append(d)
    return out


@router.get("/{slug}")
def challenge_detail(
    slug: str, repo: BinaryRepository = Depends(get_repository)
) -> dict:
    ch = get_challenge(slug)
    d = ch.meta.public_dict()
    d["hints"] = ch.hints
    d["artifact_size"] = len(ch.artifact)
    d["stats"] = repo.stats(slug)
    return d


@router.get("/{slug}/artifact")
def challenge_artifact(slug: str) -> Response:
    ch = get_challenge(slug)
    return Response(
        content=ch.artifact,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{slug}.elf"'},
    )


@router.post("/{slug}/submit", response_model=SubmitResponse)
def submit(
    slug: str, req: SubmitRequest, repo: BinaryRepository = Depends(get_repository)
) -> SubmitResponse:
    ch = get_challenge(slug)
    correct = ch.check(req.answer)
    repo.record_submission(slug, correct)
    return SubmitResponse(
        correct=correct,
        solution=ch.solution if correct else None,
        message="정답입니다! 🎉" if correct else "오답입니다. 다시 시도하세요.",
    )
