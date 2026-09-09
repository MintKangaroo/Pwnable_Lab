"""ELF, PE, raw binary 업로드 및 정적 분석 라우트."""

from __future__ import annotations

import re
from typing import Literal, cast

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Query,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
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


@router.get("/{sha256}/packing")
def binary_packing(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """패커/난독화 정적 탐지(실행 없음): UPX 서명·엔트로피·섹션·임포트·오버레이 신호."""
    return service.packing(repo.load_bytes(sha256))


@router.get("/{sha256}/libc-id")
def binary_libc_id(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """libc 버전 식별/지문(실행 없음): 버전·build-id·핵심 심볼 오프셋·/bin/sh."""
    return service.libc_identify(repo.load_bytes(sha256))


@router.post("/{sha256}/libc-resolve")
def binary_libc_resolve(
    sha256: str,
    symbol: str = Query(..., min_length=1, max_length=128),
    leaked: int = Query(..., ge=0),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """유출된 심볼 주소로 libc base·핵심 심볼 런타임 주소를 계산한다(실행 없음)."""
    return service.libc_resolve(repo.load_bytes(sha256), symbol=symbol, leaked=leaked)


@router.get("/{sha256}/ret2dlresolve")
def binary_ret2dlresolve(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """ret2dlresolve 위조 구조체·reloc_arg 정적 생성(실행 없음, non-PIE 지연바인딩).

    leak 없이 system 을 해석하는 위조 Elf64_Sym/Rela/문자열 blob 과 reloc 인덱스를
    만든다. glibc 2.34+ 는 하드닝되어 실제 셸 획득은 성립하지 않을 수 있다(구조체는 정확).
    """
    return service.ret2dlresolve(repo.load_bytes(sha256))


@router.get("/{sha256}/one-gadget")
def binary_one_gadget(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """libc 원샷 execve("/bin/sh") 가젯 정적 탐지(실행 없음): 오프셋·제약(rsi/rdx)."""
    return service.one_gadget(repo.load_bytes(sha256))


@router.get("/{sha256}/seccomp")
def binary_seccomp(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """seccomp-BPF 필터 정적 분석(실행 없음): 허용/차단 syscall·execve 차단·ORW 가능성."""
    return service.seccomp(repo.load_bytes(sha256))


@router.post("/{sha256}/runtime-strings")
async def binary_runtime_strings(
    sha256: str,
    breakpoint: int | None = Query(default=None, ge=0, le=0xFFFFFFFFFFFF),
    steps: int = Query(default=0, ge=0, le=1_000_000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """런타임 strings: 실행 중 메모리에서만 나타나는(복호화된) 문자열 발굴.

    브레이크포인트(절대 주소) 또는 N 스텝 뒤에 쓰기 가능/익명 메모리를 훑어 정적
    strings 에 없는 문자열만 보고한다. 신뢰할 수 없는 바이너리를 실행하므로 기본
    비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.runtime_strings, data, breakpoint=breakpoint, steps=steps
    )


@router.post("/{sha256}/oep")
async def binary_oep(
    sha256: str,
    start: int | None = Query(default=None, ge=0, le=0xFFFFFFFFFFFF),
    max_steps: int = Query(default=200_000, ge=1, le=5_000_000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """OEP 후보 탐지(언패킹 재구성 보조): 쓰기 가능·익명 실행으로의 첫 tail jump.

    ptrace 단일스텝으로 제어가 원래 코드/라이브러리 밖의 쓰기 가능·익명 실행 영역으로
    처음 이전되는 지점을 OEP 후보로 보고한다(외부 QEMU/rr 불필요). ``start`` 로 스텝
    시작 주소를 지정하면 startup/스텁 앞부분을 건너뛴다. 기본 비활성 — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.oep_candidate, data, start=start, max_steps=max_steps
    )


@router.post("/{sha256}/unpack")
async def binary_unpack(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """UPX 로 패킹된 ELF 를 `upx -d` 로 언패킹한다(대상 미실행 — 실행 게이트 없음).

    비 ELF/비 UPX/upx 미설치는 ``attempted=False`` 로 보고한다. 성공 시 언패킹 크기·
    SHA-256 등 메타데이터를 반환한다.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.unpack, data)


@router.post("/{sha256}/trace")
async def binary_trace(
    sha256: str,
    start: int | None = Query(default=None, ge=0, le=0xFFFFFFFFFFFF),
    max_steps: int = Query(default=20_000, ge=1, le=5_000_000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """실행 트레이스(rr-lite): 대상을 단일스텝해 자신의 실행 영역 안 명령 주소를 기록.

    외부 QEMU/rr 없이 ptrace 로 수행한다. ``start`` 로 스텝 시작 주소를 지정할 수 있다.
    신뢰할 수 없는 바이너리를 실행하므로 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.execution_trace, data, start=start, max_steps=max_steps
    )


@router.post("/{sha256}/heap")
async def binary_heap(
    sha256: str,
    breakpoint: int | None = Query(default=None, ge=0, le=0xFFFFFFFFFFFF),
    steps: int = Query(default=0, ge=0, le=1_000_000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """실행 중 glibc 힙 청크·tcache 파싱(heap 익스 보조): 청크 레이아웃·tcache bin 상태.

    브레이크포인트/N 스텝 시점의 `[heap]` 를 순회한다. 신뢰할 수 없는 바이너리를
    실행하므로 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.heap_inspect, data, breakpoint=breakpoint, steps=steps
    )


@router.post("/{sha256}/heap/tcache-poison")
async def binary_heap_tcache_poison(
    sha256: str,
    patch_break: int = Query(ge=0, le=0xFFFFFFFFFFFF),
    verify_break: int = Query(ge=0, le=0xFFFFFFFFFFFF),
    target_addr: int = Query(ge=0, le=0xFFFFFFFFFFFF),
    tcache_size: int = Query(ge=0x20, le=0x410),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """tcache poisoning 실측 증명: patch_break 에서 fd 오염→verify_break 에서 임의 할당 확인.

    heap 익스 primitive(safe-linking 인지)를 실제 실행으로 검증한다. 신뢰할 수 없는
    바이너리를 실행하므로 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.heap_tcache_poison,
        data,
        patch_break=patch_break,
        verify_break=verify_break,
        target_addr=target_addr,
        tcache_size=tcache_size,
    )


@router.post("/{sha256}/pe-run")
async def binary_pe_run(
    sha256: str,
    stdin_hex: str | None = Query(default=None, max_length=1_000_000),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """PE 를 wine 으로 실행해 stdout/stderr·종료코드·Windows 예외를 관측(PE 동적 분석).

    정적 PE 분석의 동적 짝. `stdin_hex` 로 표준입력을 hex 로 넘길 수 있다. 신뢰할 수
    없는 PE 를 실행하므로 기본 비활성(샌드박스 실행 게이트) — 503 가능. wine 부재 시
    attempted=False.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.pe_dynamic_run, data, stdin_hex=stdin_hex)


@router.post("/{sha256}/pe-triage")
async def binary_pe_triage(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """PE 크래시 트리아지: overflow/format/negative probe 로 동적 취약점 신호 수집.

    baseline 대비 특정 입력에서만 크래시하면 그 클래스가 취약 신호. 신뢰할 수 없는
    PE 를 실행하므로 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.pe_crash_triage, data)


@router.post("/{sha256}/memdump")
async def binary_memdump(
    sha256: str,
    breakpoint: int | None = Query(default=None, ge=0, le=0xFFFFFFFFFFFF),
    steps: int = Query(default=0, ge=0, le=1_000_000),
    select: str = Query(default="writable", pattern="^(writable|code|all)$"),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """프로세스 메모리 스냅샷: 지정 시점의 매핑 영역 바이트·엔트로피·해시 덤프.

    언패킹·복호화된 프로세스 이미지를 재구성하는 데 쓴다. ``select`` 는 writable
    (기본, 쓰기 가능·익명)/code(실행 가능)/all. 브레이크포인트 또는 N 스텝 뒤에 뜬다.
    신뢰할 수 없는 바이너리를 실행하므로 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.dump_memory,
        data,
        breakpoint=breakpoint,
        steps=steps,
        select=select,
    )


@router.post("/{sha256}/qemu-run")
async def binary_qemu_run(
    sha256: str,
    stdin: str = Query(default=""),
    strace: bool = Query(default=False),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """다른 아키텍처(ARM/MIPS 등) 바이너리를 qemu-user 로 실행해 stdout·종료코드 관측.

    네이티브 러너가 x86-64 전용이라 못 돌리는 크로스아키텍처 바이너리용. ``stdin`` 쿼리
    문자열을 표준입력으로 흘린다. ``strace=true`` 면 시스템콜 트레이스도 반환한다.
    신뢰할 수 없는 바이너리를 실행하므로 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    qemu 미설치 시 `qemu-<arch>-unavailable`.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.run_qemu, data, stdin_data=stdin.encode(), strace=strace
    )


@router.post("/{sha256}/explain-strategy")
async def binary_explain_strategy(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """정적 전략에 (선택적) LLM 자연어 설명을 덧붙인다 — 프라이버시 기본 차단.

    LLM 이 비활성(기본)이면 어떤 데이터도 외부로 나가지 않고 정적 전략만 반환한다.
    ``PLAB_LLM_ENABLED=1`` + provider 설정 시에만 **정적 전략 요약 텍스트**(바이너리
    원본이 아님)를 provider 에 보내 설명을 받는다.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.explain_strategy, data)


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


@router.post("/{sha256}/auto-fmt-leak")
async def binary_auto_fmt_leak(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """PIE 포맷스트링 in-band leak 자동 익스: base 유출 → rebase ret2win → 셸 증명.

    오버플로 오프셋·leak 인자 위치를 자체 확정하므로 offset 인자가 필요 없다. base 를
    유출값에서 계산하므로 ASLR 이 켜져 있어도 성립하는 진짜 leak(amd64 PIE, in-process).
    기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.auto_fmt_leak_pie, data)


@router.post("/{sha256}/auto-srop")
async def binary_auto_srop(
    sha256: str,
    offset: int = Query(..., ge=0, le=1_048_576),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """자동 SROP(sigreturn) 익스: syscall + pop rax + /bin/sh 로 execve 셸 증명.

    pop rdi/rsi/rdx 가젯이 부족한 경우에 유용하다(non-PIE amd64). 신뢰할 수 없는
    바이너리를 실행하므로 기본 비활성 — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.auto_srop, data, offset=offset)


@router.post("/{sha256}/auto-orw")
async def binary_auto_orw(
    sha256: str,
    offset: int = Query(..., ge=0, le=1_048_576),
    flag_path: str = Query(..., min_length=1, max_length=512),
    read_size: int = Query(default=100, ge=1, le=65536),
    expect_marker: str | None = Query(default=None, max_length=256),
    pie: bool = Query(default=False),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """ORW(open→read→write) syscall ROP 자동 익스: 플래그 파일을 열어 stdout 으로 유출.

    seccomp 로 execve 가 막힌 환경에서 셸 대신 플래그를 읽는다. ``flag_path`` 문자열이
    바이너리에 있어야 하며, ``expect_marker`` 로 유출 성공을 판정할 수 있다. ``pie=true``
    면 로드 base 를 로컬 관측(ASLR-off)해 rebase 한다(amd64). 신뢰할 수 없는 바이너리를
    실행하므로 기본 비활성 — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(
        service.auto_orw,
        data,
        offset=offset,
        flag_path=flag_path,
        read_size=read_size,
        expect_marker=expect_marker,
        pie=pie,
    )


@router.post("/{sha256}/auto-fmt-write")
async def binary_auto_fmt_write(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """포맷스트링 %n GOT 덮어쓰기 자동 익스: GOT → win 리다이렉트 → 셸 증명.

    ``printf(user_input)`` 포맷스트링 취약점을 노린다. fmt 인자 위치를 자체 확정하고
    임포트 GOT 후보를 모두 시도해 셸이 뜨는 첫 조합을 채택한다(non-PIE amd64, offset
    불필요). 기본 비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.auto_fmt_got_overwrite, data)


@router.post("/{sha256}/auto-fmt-write-pie")
async def binary_auto_fmt_write_pie(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """PIE 포맷스트링 %n GOT 덮어쓰기: base in-band leak → rebase → 셸 증명.

    대상이 흘리는 포맷스트링으로 로드 base 를 런타임 복원해 rebase 한 GOT 를 win 으로
    덮는다(ASLR 켜져도 성립하는 진짜 leak). 포맷스트링이 루프 안에 있어야 하며 Full
    RELRO 는 거부(non-PIE amd64, offset 불필요). 기본 비활성 — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.auto_fmt_got_overwrite_pie, data)


@router.post("/{sha256}/debug")
async def binary_debug_script(
    sha256: str,
    commands: list[dict] = Body(
        ..., embed=True, description="디버그 명령 목록(op 기반)"
    ),
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """ptrace 대화형 디버그 세션에서 명령 목록을 실행(GDB/MI 대체, 외부 gdb 불필요).

    본문 예: ``{"commands": [{"op": "break", "addr": 4198774}, {"op": "continue"},
    {"op": "registers"}]}``. 브레이크포인트·연속/스텝·레지스터/메모리/스택 조회·stdin
    주입을 한 세션에서 순서대로 수행한다. 신뢰할 수 없는 바이너리를 실행하므로 기본
    비활성(샌드박스 실행 게이트) — 503 가능.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.debug_script, data, commands)


@router.websocket("/{sha256}/debug/ws")
async def binary_debug_ws(
    websocket: WebSocket,
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> None:
    """ptrace 라이브 디버그 세션(WebSocket) — 명령/결과를 프레임 단위로 중계.

    클라이언트가 ``{"op": "break", "addr": ...}`` 같은 JSON 을 보내면 세션 스레드에서
    실행해 결과 JSON 을 돌려준다(``op`` 는 배치 ``/debug`` 와 동일 + ``output``).
    연결 시 ``{"event": "ready"}`` 또는 게이트/세션 오류 프레임을 보낸다. 신뢰할 수
    없는 바이너리를 실행하므로 기본 비활성(게이트 미통과 시 오류 프레임 후 종료).
    """

    await websocket.accept()
    try:
        data = repo.load_bytes(sha256)
        worker = await run_in_threadpool(service.open_debug_worker, data)
    except Exception as exc:  # 게이트/포맷/로드 오류 → 오류 프레임 후 종료.
        await websocket.send_json({"event": "error", "error": str(exc)})
        await websocket.close()
        return

    if worker.ready.get("event") != "ready":
        await websocket.send_json(worker.ready)
        await run_in_threadpool(worker.close)
        await websocket.close()
        return

    await websocket.send_json({"event": "ready"})
    try:
        while True:
            cmd = await websocket.receive_json()
            if not isinstance(cmd, dict) or cmd.get("op") == "close":
                break
            result = await run_in_threadpool(worker.execute, cmd)
            await websocket.send_json(result)
    except WebSocketDisconnect:
        pass
    finally:
        await run_in_threadpool(worker.close)
        try:
            await websocket.close()
        except RuntimeError:
            pass


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


@router.post("/{sha256}/decompile-ghidra")
async def binary_decompile_ghidra(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """Ghidra headless 로 바이너리 전체를 디컴파일한다(진짜 디컴파일러).

    기본 비활성(``PLAB_GHIDRA_ENABLED``) — 그 경우 ``{"available": false}`` 를 반환해
    UI 가 규칙 기반 pseudo-C 로 폴백하게 한다. Ghidra 는 정적 분석만(실행 안 함),
    무거우므로 threadpool 에서 실행한다.
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.decompile_ghidra, data)


@router.post("/{sha256}/analyze-ghidra")
async def binary_analyze_ghidra(
    sha256: str,
    repo: BinaryRepository = Depends(get_repository),
    service: AnalysisService = Depends(get_service),
) -> dict:
    """Ghidra 디컴파일을 vuln_scan/strategy 에 피드백한 통합 분석.

    복원한 버퍼 크기·스택 레이아웃으로 확정 오버플로·정확한 오프셋을 도출해 정적
    findings 를 승격하고 strategy 스켈레톤에 오프셋을 주입한다. 비활성/미설치면
    ``{"available": false}`` 로 폴백 신호. Ghidra 는 정적 분석만(실행 안 함).
    """
    data = repo.load_bytes(sha256)
    return await run_in_threadpool(service.analyze_ghidra, data)


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
