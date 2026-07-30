"""애플리케이션 설정 (pydantic-settings).

모든 환경 변수는 ``PLAB_`` 접두사를 사용한다. 예) ``PLAB_MAX_UPLOAD_BYTES``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PLAB_", env_file=".env", extra="ignore"
    )

    app_name: str = "PwnPilot"
    environment: str = "development"

    # 업로드/저장
    max_upload_bytes: int = Field(default=32 * 1024 * 1024, gt=0)  # 32 MiB
    upload_chunk_bytes: int = Field(default=1024 * 1024, gt=0, le=4 * 1024 * 1024)
    storage_dir: str = "./_storage"
    database_url: str = "sqlite:///./pwnable_lab.db"
    auto_create_schema: bool = True

    # 분석 한계 (DoS 방지)
    max_disasm_instructions: int = 20000
    max_gadgets: int = 2000
    max_gadget_depth: int = 5  # 하나의 가젯에 포함될 최대 명령 수
    max_strings: int = 20000
    hex_page_size: int = 512

    # 페이로드 도구 한계
    max_cyclic_length: int = 65536

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # 로깅
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
