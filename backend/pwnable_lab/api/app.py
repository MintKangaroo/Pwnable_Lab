"""FastAPI 애플리케이션 팩토리."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pwnable_lab import __version__
from pwnable_lab.api.errors import install_error_handlers
from pwnable_lab.api.routes import binaries, challenges, crashes, health, payload
from pwnable_lab.config import Settings, get_settings
from pwnable_lab.logging_config import configure_logging


def _build_api(settings: Settings) -> FastAPI:
    api = FastAPI(
        title=f"{settings.app_name} API",
        description="교육·CTF·허가된 바이너리를 위한 안전한 Pwnable 분석 플랫폼",
        version=__version__,
    )
    install_error_handlers(api)
    api.include_router(health.router)
    api.include_router(binaries.router)
    api.include_router(crashes.router)
    api.include_router(payload.router)
    api.include_router(challenges.router)
    return api


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title=f"{settings.app_name} Control Plane",
        description="바이너리를 직접 실행하지 않는 정적 분석 제어 평면",
        version=__version__,
        docs_url=None,
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    install_error_handlers(app)

    # `/api/v1`이 기본 계약이다. `/api`는 기존 UI/API 사용자를 위한 한시적 호환 경로다.
    app.mount("/api/v1", _build_api(settings))
    app.mount("/api", _build_api(settings))

    return app


app = create_app()
