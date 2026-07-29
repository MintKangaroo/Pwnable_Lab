"""FastAPI 애플리케이션 팩토리."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pwnable_lab import __version__
from pwnable_lab.api.errors import install_error_handlers
from pwnable_lab.api.routes import binaries, challenges, health, payload
from pwnable_lab.config import get_settings
from pwnable_lab.logging_config import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Pwnable Lab API",
        description="바이너리 익스플로잇 · 시스템 해킹 학습 플랫폼",
        version=__version__,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    install_error_handlers(app)

    api = FastAPI(title="Pwnable Lab", version=__version__)
    install_error_handlers(api)
    api.include_router(health.router)
    api.include_router(binaries.router)
    api.include_router(payload.router)
    api.include_router(challenges.router)
    app.mount("/api", api)

    return app


app = create_app()
