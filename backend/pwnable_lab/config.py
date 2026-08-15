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
    max_crash_log_bytes: int = Field(default=2 * 1024 * 1024, gt=0)  # 2 MiB
    max_core_dump_bytes: int = Field(default=64 * 1024 * 1024, gt=0)  # 64 MiB
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
    max_crash_log_lines: int = Field(default=100_000, gt=0, le=1_000_000)
    max_crash_stack_entries: int = Field(default=4096, gt=0, le=100_000)
    max_core_notes: int = Field(default=4096, gt=0, le=100_000)
    max_core_note_bytes: int = Field(default=8 * 1024 * 1024, gt=0, le=64 * 1024 * 1024)

    # 페이로드 도구 한계
    max_cyclic_length: int = 65536

    # 동적 오프셋 확정 샌드박스 (Phase 6A)
    #
    # .. warning::
    #    이 기능을 켜면 서버가 **신뢰할 수 없는 업로드 바이너리를 실제로 실행**한다.
    #    반드시 network-disabled 일회용 컨테이너(nsjail/gVisor 등) 경계 안에서만
    #    ``PLAB_SANDBOX_EXECUTION_ENABLED=1`` 로 활성화할 것. 기본값은 비활성이며,
    #    이 플래그를 켜는 행위 자체가 "격리 경계를 갖췄다"는 운영자의 명시적 확인이다.
    sandbox_execution_enabled: bool = False
    # 격리 마커 경로. 비어 있지 않으면 실행 직전 이 경로가 존재해야만 러너가
    # 동작한다(컨테이너 이미지가 생성하는 파일을 지정해 무방비 노출을 한 겹 더 차단).
    sandbox_isolation_marker: str = ""
    sandbox_wall_seconds: float = Field(default=5.0, gt=0, le=60)
    sandbox_cpu_seconds: int = Field(default=2, gt=0, le=30)
    sandbox_address_space_bytes: int = Field(
        default=512 * 1024 * 1024, gt=0, le=4 * 1024 * 1024 * 1024
    )
    sandbox_pattern_length: int = Field(default=512, ge=8, le=65536)

    # 실행 위치 선택:
    #   "inprocess" — API 프로세스 안에서 러너를 직접 호출(dev/tests 기본).
    #                 API 프로세스 자체가 격리 경계 안에 있어야 안전하다.
    #   "container" — 매 요청마다 network-disabled 일회용 컨테이너를 띄워 실행.
    #                 프로덕션 권장. sandbox/run.sh 와 동일한 하드닝을 강제한다.
    sandbox_executor: str = Field(default="inprocess", pattern="^(inprocess|container)$")
    sandbox_container_image: str = "pwnpilot-sandbox"
    sandbox_docker_bin: str = "docker"
    sandbox_container_runtime: str = ""  # 예) "runsc" (gVisor)
    sandbox_container_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    sandbox_container_memory: str = "768m"
    sandbox_container_cpus: str = "1"
    sandbox_container_pids: int = Field(default=128, gt=0, le=100_000)
    sandbox_container_tmp_size: str = "64m"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # 로깅
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
