"""바이너리 업로드 및 정적 분석 라우트."""

from __future__ import annotations

from typing import Literal, cast

from fastapi import APIRouter, Depends, File, Query, Response, UploadFile, status
from starlette.concurrency import run_in_threadpool

from pwnable_lab.api.dependencies import (
    get_analysis_queue,
    get_config,
    get_repository,
    get_service,
)
from pwnable_lab.api.schemas import (
    AnalysisJobResponse,
    BinaryDetail,
    BinarySummary,
    UploadResponse,
)
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.database.models import AnalysisJobRecord
from pwnable_lab.database.repository import BinaryRepository
from pwnable_lab.jobs.queue import AnalysisJobQueue

router = APIRouter(prefix="/binaries", tags=["binaries"])


@router.post("", response_model=UploadResponse)
async def upload_binary(
    file: UploadFile = File(...),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
    settings: Settings = Depends(get_config),
) -> UploadResponse:
    staged = None
    filename = file.filename or "binary"
    try:
        staged = await repo.storage.stage(
            file,
            max_bytes=settings.max_upload_bytes,
            chunk_bytes=settings.upload_chunk_bytes,
        )
        data = await run_in_threadpool(staged.path.read_bytes)
        # 포맷 화이트리스트: ELF만 허용하고 전체 구조도 채택 전에 검증한다.
        img = await run_in_threadpool(service.image, data)
        record = await run_in_threadpool(
            repo.store_staged, staged, filename, img.machine, img.bits
        )
        return UploadResponse(
            binary_id=record.sha256,
            sha256=record.sha256,
            filename=record.filename,
            size=record.size,
            analysis_status=record.analysis_status,
        )
    finally:
        await file.close()
        if staged is not None:
            repo.storage.discard(staged)


@router.get("", response_model=list[BinarySummary])
def list_binaries(
    repo: BinaryRepository = Depends(get_repository),
) -> list[BinarySummary]:
    return [
        BinarySummary(
            sha256=r.sha256,
            filename=r.filename,
            size=r.size,
            machine=r.machine,
            bits=r.bits,
            analysis_status=r.analysis_status,
            created_at=r.created_at,
        )
        for r in repo.list()
    ]


@router.get("/{sha256}", response_model=BinaryDetail)
def binary_detail(
    sha256: str, repo: BinaryRepository = Depends(get_repository)
) -> BinaryDetail:
    record = repo.get(sha256)
    return BinaryDetail(
        sha256=record.sha256,
        filename=record.filename,
        size=record.size,
        machine=record.machine,
        bits=record.bits,
        analysis_status=record.analysis_status,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.delete("/{sha256}", status_code=status.HTTP_204_NO_CONTENT)
def delete_binary(
    sha256: str, repo: BinaryRepository = Depends(get_repository)
) -> Response:
    repo.delete(sha256)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _job_response(job: AnalysisJobRecord) -> AnalysisJobResponse:
    return AnalysisJobResponse(
        job_id=job.id,
        binary_id=job.binary_sha256,
        status=cast(
            Literal["queued", "running", "completed", "failed"],
            job.status,
        ),
        analyzer_name=job.analyzer_name,
        analyzer_version=job.analyzer_version,
        created_at=job.created_at,
        updated_at=job.updated_at,
        completed_at=job.completed_at,
        confidence=job.confidence,
        evidence=job.evidence,
        result=job.result,
        error=job.error,
    )


@router.post(
    "/{sha256}/analyze",
    response_model=AnalysisJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def analyze_binary(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
    queue: AnalysisJobQueue = Depends(get_analysis_queue),
) -> AnalysisJobResponse:
    job = await run_in_threadpool(queue.enqueue, sha256, repo, service)
    return _job_response(job)


@router.get("/{sha256}/analysis", response_model=AnalysisJobResponse)
def binary_analysis(
    sha256: str, repo: BinaryRepository = Depends(get_repository)
) -> AnalysisJobResponse:
    return _job_response(repo.latest_analysis(sha256))


@router.get("/{sha256}/info")
def binary_info(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.info(repo.load_bytes(sha256))


@router.get("/{sha256}/elf")
def binary_elf(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """Phase 2 comprehensive ELF metadata contract."""
    return service.info(repo.load_bytes(sha256))


@router.get("/{sha256}/checksec")
def binary_checksec(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.checksec(repo.load_bytes(sha256))


@router.get("/{sha256}/vulns")
def binary_vulns(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> list[dict]:
    return service.vulns(repo.load_bytes(sha256))


@router.get("/{sha256}/gadgets")
def binary_gadgets(
    sha256: str,
    q: str | None = Query(default=None),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> list[dict]:
    return service.gadgets(repo.load_bytes(sha256), query=q)


@router.get("/{sha256}/symbols")
def binary_symbols(
    sha256: str,
    kind: Literal[
        "all", "static", "dynamic", "imports", "exports", "functions"
    ] = Query(default="all"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.symbols(
        repo.load_bytes(sha256), kind=kind, offset=offset, limit=limit
    )


@router.get("/{sha256}/imports")
def binary_imports(
    sha256: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.symbols(
        repo.load_bytes(sha256), kind="imports", offset=offset, limit=limit
    )


@router.get("/{sha256}/exports")
def binary_exports(
    sha256: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.symbols(
        repo.load_bytes(sha256), kind="exports", offset=offset, limit=limit
    )


@router.get("/{sha256}/functions")
def binary_functions(
    sha256: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.symbols(
        repo.load_bytes(sha256), kind="functions", offset=offset, limit=limit
    )


@router.get("/{sha256}/relocations")
def binary_relocations(
    sha256: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.relocations(repo.load_bytes(sha256), offset=offset, limit=limit)


@router.get("/{sha256}/libraries")
def binary_libraries(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.libraries(repo.load_bytes(sha256))


@router.get("/{sha256}/got")
def binary_got(
    sha256: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.got_entries(repo.load_bytes(sha256), offset=offset, limit=limit)


@router.get("/{sha256}/plt")
def binary_plt(
    sha256: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.plt_entries(repo.load_bytes(sha256), offset=offset, limit=limit)


@router.get("/{sha256}/strings")
def binary_strings(
    sha256: str,
    min_length: int = Query(default=4, ge=1, le=64),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> list[dict]:
    return service.strings(repo.load_bytes(sha256), min_length=min_length)


@router.get("/{sha256}/disassembly")
def binary_disasm(
    sha256: str,
    address: int | None = Query(default=None),
    count: int = Query(default=200, ge=1, le=20000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> list[dict]:
    return service.disassembly(repo.load_bytes(sha256), address=address, count=count)


@router.get("/{sha256}/hex")
def binary_hex(
    sha256: str,
    page: int = Query(default=0, ge=0),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.hexdump(repo.load_bytes(sha256), page=page)
