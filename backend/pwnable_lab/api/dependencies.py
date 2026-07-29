"""FastAPI 의존성 — 설정, 저장소, 서비스 싱글턴."""

from __future__ import annotations

from functools import lru_cache

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings, get_settings
from pwnable_lab.database.repository import BinaryRepository
from pwnable_lab.database.session import make_engine, make_session_factory


@lru_cache(maxsize=1)
def _repo_for(database_url: str, storage_dir: str) -> BinaryRepository:
    engine = make_engine(database_url)
    factory = make_session_factory(engine)
    return BinaryRepository(session_factory=factory, storage_dir=storage_dir)


def get_repository() -> BinaryRepository:
    settings = get_settings()
    return _repo_for(settings.database_url, settings.storage_dir)


def get_service() -> AnalysisService:
    return AnalysisService(get_settings())


def get_config() -> Settings:
    return get_settings()
