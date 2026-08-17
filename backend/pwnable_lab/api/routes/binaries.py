"""ELF, PE, raw binary 업로드 및 정적 분석 라우트."""

from __future__ import annotations

import re
from typing import Literal, cast

from fastapi import APIRouter, Depends, File, Query, Response, UploadFile, status
from starlette.concurrency import run_in_threadpool

from pwnable_lab.analyzer.gadgets import GadgetFilter
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
    RopSimulationRequest,
    UploadResponse,
)
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.database.models import AnalysisJobRecord
from pwnable_lab.database.repository import BinaryRepository
from pwnable_lab.errors import AnalysisError
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
        # MIME/파일명을 신뢰하지 않고 포맷 구조 또는 raw 정책을 검증한다.
        inspection = await run_in_threadpool(service.inspect, data)
        record = await run_in_threadpool(
            repo.store_staged,
            staged,
            filename,
            inspection.machine,
            inspection.bits,
            inspection.format.value,
        )
        return UploadResponse(
            binary_id=record.sha256,
            sha256=record.sha256,
            filename=record.filename,
            size=record.size,
            format=record.artifact_format,
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
            format=r.artifact_format,
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
        format=record.artifact_format,
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
    return service.elf_info(repo.load_bytes(sha256))


@router.get("/{sha256}/pe")
def binary_pe(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """Validated PE32/PE32+ metadata; rejects non-PE artifacts."""

    return service.pe_info(repo.load_bytes(sha256))


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


@router.get("/{sha256}/strategy")
def binary_strategy(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """근거 기반 exploit 후보 경로와 pwntools 스켈레톤 초안."""
    return service.exploit_strategy(repo.load_bytes(sha256))


@router.post("/{sha256}/confirm-offset")
async def binary_confirm_offset(
    sha256: str,
    pattern_length: int | None = Query(default=None, ge=8, le=65536),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """동적으로 반환 주소 오프셋을 확정한다(격리 샌드박스에서 실제 실행).

    기본 비활성. 배포가 ``PLAB_SANDBOX_EXECUTION_ENABLED`` 를 켜지 않았으면 503.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.confirm_offset, data, pattern_length=pattern_length
    )


@router.post("/{sha256}/auto-exploit")
async def binary_auto_exploit(
    sha256: str,
    pattern_length: int | None = Query(default=None, ge=8, le=65536),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """정적 전략 + 동적 오프셋 확정을 결합한 exploit 초안.

    후보 경로/pwntools 스켈레톤을 만든 뒤, 격리 샌드박스로 확정한 오프셋을
    스켈레톤에 주입해 반환한다. 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.auto_exploit, data, pattern_length=pattern_length
    )


@router.post("/{sha256}/auto-ret2libc")
async def binary_auto_ret2libc(
    sha256: str,
    offset: int = Query(..., ge=0, le=1_048_576),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """완전 자동 2단계 ret2libc: leak → libc base → system("/bin/sh") (amd64, in-process).

    기본 비활성(샌드박스 실행 게이트) — 503 가능. 컨테이너 executor 는 미지원.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.auto_ret2libc, data, offset=offset)


@router.post("/{sha256}/leak")
async def binary_leak(
    sha256: str,
    offset: int = Query(..., ge=0, le=1_048_576),
    bits: int | None = Query(default=None),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """puts(puts@got) → exit 체인으로 런타임 libc 주소를 유출한다(ASLR 우회 1단계).

    기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.verify_leak, data, offset=offset)


@router.post("/{sha256}/verify-exploit")
async def binary_verify_exploit(
    sha256: str,
    offset: int = Query(..., ge=0, le=1_048_576),
    target: str = Query(
        ..., max_length=32, description="점프 대상 주소(0x… 또는 10진)"
    ),
    bits: int | None = Query(default=None),
    chain: list[str] = Query(default=[], max_length=32),
    marker: list[str] = Query(default=[], max_length=64),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """구성한 ret2win/ROP payload 를 격리 샌드박스에 주입해 익스 성공을 검증한다.

    ``payload = b'A'*offset + p{bits}(target) + Σ p{bits}(chain)`` 를 실제 실행으로
    확인한다. ``chain`` 으로 ret2system 등 다단계 ROP 를 표현한다.
    기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    target_addr = _parse_address(target)
    chain_addrs = [_parse_address(c) for c in chain]
    return await run_in_threadpool(
        lambda: service.verify_exploit(
            data,
            offset=offset,
            target=target_addr,
            bits=bits,
            chain=chain_addrs,
            markers=marker,
        )
    )


@router.get("/{sha256}/functions/{address}/pseudocode")
def binary_function_pseudocode(
    sha256: str,
    address: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """단일 함수의 규칙 기반 pseudo-C 초안(휴리스틱)."""
    return service.pseudo_c(repo.load_bytes(sha256), address=_parse_address(address))


@router.get("/{sha256}/gadgets")
def binary_gadgets(
    sha256: str,
    q: str = Query(default="", max_length=128),
    regex: bool = Query(default=False),
    register: str | None = Query(default=None, max_length=16),
    category: str | None = Query(default=None, max_length=64),
    min_stack_change: int | None = Query(default=None, ge=-1_048_576, le=1_048_576),
    max_stack_change: int | None = Query(default=None, ge=-1_048_576, le=1_048_576),
    bad_bytes: str = Query(default="", max_length=128),
    address_min: str | None = Query(default=None, max_length=32),
    address_max: str | None = Query(default=None, max_length=32),
    sort: Literal["address", "quality", "side_effects", "stack_change"] = Query(
        default="quality"
    ),
    order: Literal["asc", "desc"] = Query(default="desc"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=500),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    if (
        min_stack_change is not None
        and max_stack_change is not None
        and min_stack_change > max_stack_change
    ):
        raise AnalysisError("min_stack_change cannot exceed max_stack_change.")
    filters = GadgetFilter(
        query=q,
        regex=regex,
        register=register,
        category=category,
        min_stack_change=min_stack_change,
        max_stack_change=max_stack_change,
        bad_bytes=_parse_bad_bytes(bad_bytes),
        address_min=_parse_address(address_min) if address_min else None,
        address_max=_parse_address(address_max) if address_max else None,
        sort=sort,
        order=order,
    )
    return service.gadgets(
        repo.load_bytes(sha256), filters=filters, offset=offset, limit=limit
    )


@router.post("/{sha256}/rop/simulate")
def binary_rop_simulate(
    sha256: str,
    request: RopSimulationRequest,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.simulate_rop(
        repo.load_bytes(sha256),
        items=[item.model_dump() for item in request.items],
        rsp_mod16=request.initial_rsp_mod16,
    )


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
    q: str | None = Query(default=None, max_length=256),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.functions(
        repo.load_bytes(sha256), query=q, offset=offset, limit=limit
    )


@router.get("/{sha256}/functions/{address}")
def binary_function_detail(
    sha256: str,
    address: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.function_detail(
        repo.load_bytes(sha256), address=_parse_address(address)
    )


@router.get("/{sha256}/functions/{address}/cfg")
def binary_function_cfg(
    sha256: str,
    address: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.cfg(repo.load_bytes(sha256), address=_parse_address(address))


@router.get("/{sha256}/xrefs")
def binary_xrefs(
    sha256: str,
    address: str | None = Query(default=None, max_length=32),
    direction: Literal["to", "from"] = Query(default="to"),
    kind: Literal["all", "call", "jump", "conditional_jump"] = Query(default="all"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.xrefs(
        repo.load_bytes(sha256),
        address=_parse_address(address) if address is not None else None,
        direction=direction,
        kind=kind,
        offset=offset,
        limit=limit,
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


@router.get("/{sha256}/entropy")
def binary_entropy(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.entropy(repo.load_bytes(sha256))


@router.get("/{sha256}/disassembly")
def binary_disasm(
    sha256: str,
    address: int | None = Query(default=None, ge=0, le=0xFFFFFFFFFFFFFFFF),
    count: int = Query(default=200, ge=1, le=20000),
    architecture: Literal["x86", "x86_64"] | None = Query(default=None),
    base_address: int = Query(default=0, ge=0, le=0xFFFFFFFFFFFFFFFF),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> list[dict]:
    return service.disassembly(
        repo.load_bytes(sha256),
        address=address,
        count=count,
        architecture=architecture,
        base_address=base_address,
    )


@router.get("/{sha256}/hex")
def binary_hex(
    sha256: str,
    page: int = Query(default=0, ge=0),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    return service.hexdump(repo.load_bytes(sha256), page=page)


def _parse_address(value: str) -> int:
    try:
        address = int(value, 0)
    except ValueError as exc:
        raise AnalysisError(f"Invalid address: {value}") from exc
    if not 0 <= address <= 0xFFFFFFFFFFFFFFFF:
        raise AnalysisError("Address must be an unsigned 64-bit integer.")
    return address


def _parse_bad_bytes(value: str) -> tuple[int, ...]:
    if not value.strip():
        return ()
    pieces = [piece for piece in re.split(r"[\s,]+", value.strip()) if piece]
    if len(pieces) > 32:
        raise AnalysisError("At most 32 bad-byte values may be supplied.")
    output: set[int] = set()
    for piece in pieces:
        normalized = piece[2:] if piece.lower().startswith("0x") else piece
        if not re.fullmatch(r"[0-9a-fA-F]{2}", normalized):
            raise AnalysisError(f"Invalid bad byte: {piece}")
        output.add(int(normalized, 16))
    return tuple(sorted(output))
