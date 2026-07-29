"""바이너리 업로드 및 정적 분석 라우트."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Query, UploadFile

from pwnable_lab.api.dependencies import get_config, get_repository, get_service
from pwnable_lab.api.schemas import BinarySummary, UploadResponse
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.database.repository import BinaryRepository
from pwnable_lab.errors import PayloadTooLargeError

router = APIRouter(prefix="/binaries", tags=["binaries"])


@router.post("", response_model=UploadResponse)
async def upload_binary(
    file: UploadFile = File(...),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
    settings: Settings = Depends(get_config),
) -> UploadResponse:
    # 상한을 넘긴 파일 전체를 메모리에 올리지 않는다.
    data = await file.read(settings.max_upload_bytes + 1)
    await file.close()
    if len(data) > settings.max_upload_bytes:
        raise PayloadTooLargeError(
            f"업로드 크기가 한계({settings.max_upload_bytes} bytes)를 초과했습니다."
        )
    # 포맷 화이트리스트: ELF 만 완전 지원 (파싱으로 검증)
    img = service.image(data)  # UnsupportedFormat/ParseError 를 던질 수 있음
    record = repo.store(data, file.filename or "binary", img.machine, img.bits)
    return UploadResponse(sha256=record.sha256, filename=record.filename, size=record.size)


@router.get("", response_model=list[BinarySummary])
def list_binaries(repo: BinaryRepository = Depends(get_repository)) -> list[BinarySummary]:
    return [
        BinarySummary(sha256=r.sha256, filename=r.filename, size=r.size,
                      machine=r.machine, bits=r.bits)
        for r in repo.list()
    ]


@router.get("/{sha256}/info")
def binary_info(sha256: str, repo: BinaryRepository = Depends(get_repository),
                service: AnalysisService = Depends(get_service)) -> dict:
    return service.info(repo.load_bytes(sha256))


@router.get("/{sha256}/checksec")
def binary_checksec(sha256: str, repo: BinaryRepository = Depends(get_repository),
                    service: AnalysisService = Depends(get_service)) -> dict:
    return service.checksec(repo.load_bytes(sha256))


@router.get("/{sha256}/vulns")
def binary_vulns(sha256: str, repo: BinaryRepository = Depends(get_repository),
                 service: AnalysisService = Depends(get_service)) -> list[dict]:
    return service.vulns(repo.load_bytes(sha256))


@router.get("/{sha256}/gadgets")
def binary_gadgets(sha256: str, q: str | None = Query(default=None),
                   repo: BinaryRepository = Depends(get_repository),
                   service: AnalysisService = Depends(get_service)) -> list[dict]:
    return service.gadgets(repo.load_bytes(sha256), query=q)


@router.get("/{sha256}/got")
def binary_got(sha256: str, repo: BinaryRepository = Depends(get_repository),
               service: AnalysisService = Depends(get_service)) -> dict:
    return service.got_plt(repo.load_bytes(sha256))


@router.get("/{sha256}/strings")
def binary_strings(sha256: str, min_length: int = Query(default=4, ge=1, le=64),
                   repo: BinaryRepository = Depends(get_repository),
                   service: AnalysisService = Depends(get_service)) -> list[dict]:
    return service.strings(repo.load_bytes(sha256), min_length=min_length)


@router.get("/{sha256}/disassembly")
def binary_disasm(sha256: str, address: int | None = Query(default=None),
                  count: int = Query(default=200, ge=1, le=20000),
                  repo: BinaryRepository = Depends(get_repository),
                  service: AnalysisService = Depends(get_service)) -> list[dict]:
    return service.disassembly(repo.load_bytes(sha256), address=address, count=count)


@router.get("/{sha256}/hex")
def binary_hex(sha256: str, page: int = Query(default=0, ge=0),
               repo: BinaryRepository = Depends(get_repository),
               service: AnalysisService = Depends(get_service)) -> dict:
    return service.hexdump(repo.load_bytes(sha256), page=page)
