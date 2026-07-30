"""분석 작업 실행 인터페이스와 개발용 인라인 구현.

인라인 큐는 Phase 1 개발 모드용이다. 업로드 바이너리를 실행하지 않고 pyelftools 기반
정적 메타데이터만 계산한다. 운영용 비동기 worker는 후속 Phase에서 같은 인터페이스 뒤에
연결한다.
"""

from __future__ import annotations

from typing import Protocol

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.database.models import AnalysisJobRecord
from pwnable_lab.database.repository import BinaryRepository


class AnalysisJobQueue(Protocol):
    def enqueue(
        self,
        binary_id: str,
        repository: BinaryRepository,
        service: AnalysisService,
    ) -> AnalysisJobRecord:
        """정적 분석 작업을 등록하고 현재 상태를 반환한다."""


class InlineAnalysisJobQueue:
    """요청 프로세스에서 제한된 정적 분석만 실행하는 개발용 큐."""

    def enqueue(
        self,
        binary_id: str,
        repository: BinaryRepository,
        service: AnalysisService,
    ) -> AnalysisJobRecord:
        job = repository.create_analysis_job(binary_id)
        repository.update_analysis_job(job.id, status="running")
        try:
            data = repository.load_bytes(binary_id)
            image = service.image(data)
            result = {
                "verification": "verified",
                "source": "pyelftools ELF parser",
                "confidence": 1.0,
                "elf": {
                    "sha256": binary_id,
                    "bits": image.bits,
                    "endian": image.endian,
                    "machine": image.machine,
                    "type": image.e_type,
                    "entry": image.entry,
                    "section_count": len(image.sections),
                    "segment_count": len(image.segments),
                    "symbol_count": len(image.symbols) + len(image.dynamic_symbols),
                },
                "checksec": service.checksec(data),
            }
            return repository.update_analysis_job(
                job.id, status="completed", result=result
            )
        except Exception as exc:
            # 내부 예외 본문은 상태 조회에 보존하되 traceback/호스트 경로는 노출하지 않는다.
            return repository.update_analysis_job(
                job.id,
                status="failed",
                error=f"{exc.__class__.__name__}: {exc}",
            )
