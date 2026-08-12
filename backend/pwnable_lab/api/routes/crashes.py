"""Safe crash-log/core intake and deterministic, non-executing parsing routes."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile, status
from starlette.concurrency import run_in_threadpool

from pwnable_lab.analyzer.crash_log import Limits, normalize_crash_log
from pwnable_lab.api.dependencies import get_config, get_repository, get_service
from pwnable_lab.api.schemas import CrashDetail, CrashSummary
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.database.models import CrashAnalysisRecord, CrashArtifactRecord
from pwnable_lab.database.repository import BinaryRepository
from pwnable_lab.errors import ParseError, PayloadTooLargeError, UnsupportedFormatError

router = APIRouter(prefix="/crashes", tags=["crashes"])

_ARCHIVE_MAGIC = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"Rar!",
)


@router.post("", response_model=CrashDetail, status_code=status.HTTP_201_CREATED)
async def upload_crash_artifact(
    file: UploadFile = File(...),
    binary_id: str | None = Form(default=None),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
    settings: Settings = Depends(get_config),
) -> CrashDetail:
    filename = file.filename or "crash"
    try:
        data = await _read_bounded(file, settings)
        if any(data.startswith(magic) for magic in _ARCHIVE_MAGIC):
            raise UnsupportedFormatError(
                "압축 또는 아카이브 파일은 기본적으로 거부됩니다."
            )
        if data.startswith(b"\x7fELF"):
            if len(data) > settings.max_core_dump_bytes:
                raise PayloadTooLargeError(
                    f"core dump는 {settings.max_core_dump_bytes}바이트를 초과할 수 없습니다."
                )
            result = await run_in_threadpool(service.core_dump, data)
            artifact = await run_in_threadpool(
                repo.store_core_dump,
                data,
                filename,
                binary_sha256=binary_id or None,
            )
        else:
            if len(data) > settings.max_crash_log_bytes:
                raise PayloadTooLargeError(
                    f"크래시 로그는 {settings.max_crash_log_bytes}바이트를 초과할 수 없습니다."
                )
            text = _validate_text_log(data)
            result = await run_in_threadpool(service.crash_log, text)
            normalized_text = "\n".join(
                normalize_crash_log(
                    text,
                    Limits(
                        max_lines=settings.max_crash_log_lines,
                        max_stack_entries=settings.max_crash_stack_entries,
                    ),
                )
            )
            if not any(
                char.isprintable() and not char.isspace() for char in normalized_text
            ):
                raise ParseError(
                    "ANSI/control 정규화 후 분석 가능한 텍스트가 없습니다."
                )
            artifact = await run_in_threadpool(
                repo.store_crash_log,
                normalized_text,
                filename,
                binary_sha256=binary_id or None,
            )
        analysis = await run_in_threadpool(
            repo.save_crash_analysis, artifact.id, result
        )
        return _detail(artifact, analysis)
    finally:
        await file.close()


@router.get("", response_model=list[CrashSummary])
def list_crashes(
    repo: BinaryRepository = Depends(get_repository),
) -> list[CrashSummary]:
    return [_summary(artifact, analysis) for artifact, analysis in repo.list_crashes()]


@router.get("/{crash_id}", response_model=CrashDetail)
def crash_detail(
    crash_id: str, repo: BinaryRepository = Depends(get_repository)
) -> CrashDetail:
    return _detail(repo.get_crash(crash_id), repo.get_crash_analysis(crash_id))


@router.post("/{crash_id}/analyze", response_model=CrashDetail)
def analyze_crash(
    crash_id: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> CrashDetail:
    artifact = repo.get_crash(crash_id)
    if artifact.artifact_kind == "core_dump":
        result = service.core_dump(repo.load_crash_bytes(crash_id))
    else:
        if artifact.log_text is None:
            raise ParseError("저장된 크래시 로그 본문이 없습니다.")
        result = service.crash_log(artifact.log_text)
    return _detail(artifact, repo.save_crash_analysis(crash_id, result))


@router.get("/{crash_id}/registers")
def crash_registers(
    crash_id: str, repo: BinaryRepository = Depends(get_repository)
) -> dict[str, Any]:
    result = repo.get_crash_analysis(crash_id).result
    items = list(result.get("registers", []))
    return {"items": items, "total": len(items), "verification": "verified"}


@router.get("/{crash_id}/stack")
def crash_stack(
    crash_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=256, ge=1, le=1024),
    repo: BinaryRepository = Depends(get_repository),
) -> dict[str, Any]:
    items = list(repo.get_crash_analysis(crash_id).result.get("stack", []))
    return _page(items, offset, limit)


@router.get("/{crash_id}/mappings")
def crash_mappings(
    crash_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=256, ge=1, le=1024),
    repo: BinaryRepository = Depends(get_repository),
) -> dict[str, Any]:
    items = list(repo.get_crash_analysis(crash_id).result.get("mappings", []))
    return _page(items, offset, limit)


@router.get("/{crash_id}/backtrace")
def crash_backtrace(
    crash_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=64, ge=1, le=1024),
    repo: BinaryRepository = Depends(get_repository),
) -> dict[str, Any]:
    items = list(repo.get_crash_analysis(crash_id).result.get("backtrace", []))
    return _page(items, offset, limit)


@router.delete("/{crash_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_crash(
    crash_id: str, repo: BinaryRepository = Depends(get_repository)
) -> Response:
    repo.delete_crash(crash_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _read_bounded(file: UploadFile, settings: Settings) -> bytes:
    content = bytearray()
    while True:
        chunk = await file.read(settings.upload_chunk_bytes)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) >= len(b"\x7fELF"):
            max_bytes = (
                settings.max_core_dump_bytes
                if content.startswith(b"\x7fELF")
                else settings.max_crash_log_bytes
            )
        else:
            max_bytes = max(settings.max_crash_log_bytes, settings.max_core_dump_bytes)
        if len(content) > max_bytes:
            raise PayloadTooLargeError(
                f"크래시 artifact는 {max_bytes}바이트를 초과할 수 없습니다."
            )
    if not content:
        raise ParseError("비어 있는 크래시 artifact는 분석할 수 없습니다.")
    return bytes(content)


def _validate_text_log(data: bytes) -> str:
    if b"\x00" in data:
        raise UnsupportedFormatError(
            "Linux ELF core가 아닌 바이너리 크래시 artifact는 지원하지 않습니다."
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UnsupportedFormatError(
            "크래시 로그는 유효한 UTF-8 텍스트여야 합니다."
        ) from exc
    if not any(char.isprintable() and not char.isspace() for char in text):
        raise ParseError("분석 가능한 텍스트가 없습니다.")
    controls = sum(not char.isprintable() and char not in "\r\n\t\x1b" for char in text)
    if controls > max(16, len(text) // 100):
        raise UnsupportedFormatError(
            "바이너리 또는 제어 문자가 과도한 로그는 거부됩니다."
        )
    return text


def _summary(
    artifact: CrashArtifactRecord, analysis: CrashAnalysisRecord | None
) -> CrashSummary:
    result = analysis.result if analysis else {}
    signal = result.get("signal", {}).get("value")
    artifact_kind: Literal["text_log", "core_dump"] = (
        "core_dump" if artifact.artifact_kind == "core_dump" else "text_log"
    )
    return CrashSummary(
        crash_id=artifact.id,
        sha256=artifact.sha256,
        filename=artifact.filename,
        size=artifact.size,
        artifact_kind=artifact_kind,
        binary_id=artifact.binary_sha256,
        analysis_status=analysis.status if analysis else "not_started",
        signal=signal,
        created_at=artifact.created_at,
    )


def _detail(
    artifact: CrashArtifactRecord, analysis: CrashAnalysisRecord
) -> CrashDetail:
    summary = _summary(artifact, analysis)
    return CrashDetail(
        **summary.model_dump(),
        analyzer_name=analysis.analyzer_name,
        analyzer_version=analysis.analyzer_version,
        confidence=analysis.confidence,
        evidence=analysis.evidence,
        result=analysis.result,
    )


def _page(items: list[Any], offset: int, limit: int) -> dict[str, Any]:
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "offset": offset,
        "limit": limit,
    }
