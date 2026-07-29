"""헬스체크."""

from __future__ import annotations

from fastapi import APIRouter

from pwnable_lab import __version__
from pwnable_lab.api.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)
