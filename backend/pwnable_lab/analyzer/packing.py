"""패커/난독화 정적 탐지 (Phase 6C — 실행 없는 신호 수집).

바이너리를 **실행하지 않고** UPX 같은 알려진 패커 서명, 높은 엔트로피 실행 영역,
비정상 섹션 테이블, 적은 임포트, 오버레이 데이터 등 패킹/난독화 신호를 모은다.
실제 언패킹(예: ``upx -d``)이나 동적 OEP 복원은 Phase 6C/6D 후속이며, 이 모듈은
정적 판별만 한다(:mod:`analyzer.checksec`·:mod:`analyzer.vuln_scan` 와 같은 계열).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pwnable_lab.analyzer.entropy import shannon_entropy
from pwnable_lab.elf.parser import ElfImage

# 압축/암호화된 데이터로 보는 섀넌 엔트로피 임계값(바이트당 비트, 최대 8).
_HIGH_ENTROPY = 7.2
# 이보다 임포트가 적으면 패커 로더 스텁만 남은 것으로 의심.
_FEW_IMPORTS = 3
# 알려진 패커의 섹션 이름 접두사 → 패커 이름.
_PACKER_SECTIONS = {
    "UPX": "UPX",
    ".UPX": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".petite": "Petite",
    ".mpress": "MPRESS",
    ".upack": "Upack",
}
# 데이터 안에서 찾는 패커 매직 → 패커 이름.
_PACKER_MAGICS = {
    b"UPX!": "UPX",
    b"UPX0": "UPX",
    b"$Info: This file is packed with the UPX": "UPX",
}


@dataclass
class PackingSignal:
    """패킹/난독화를 시사하는 신호 하나."""

    name: str
    detail: str
    weight: int  # 0..100, 이 신호 하나의 확신도 기여.

    def as_dict(self) -> dict:
        return {"name": self.name, "detail": self.detail, "weight": self.weight}


@dataclass
class PackingReport:
    """정적 패킹 판별 결과."""

    packed: bool
    packer: str | None
    confidence: int  # 0..100
    signals: list[PackingSignal] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "packed": self.packed,
            "packer": self.packer,
            "confidence": self.confidence,
            "signals": [s.as_dict() for s in self.signals],
        }


def detect_packing(image: ElfImage) -> PackingReport:
    """정적 신호를 모아 패킹/난독화 여부를 판별한다(실행 없음).

    알려진 패커 서명(섹션 이름·매직)은 강한 신호(패커 이름 확정), 나머지(높은 엔트로피
    실행 영역·적은 임포트·비정상 섹션 테이블·오버레이)는 가중 합산으로 확신도를 만든다.
    """

    signals: list[PackingSignal] = []
    packer: str | None = None

    # 1) 알려진 패커 섹션 이름.
    for section in image.sections:
        for prefix, name in _PACKER_SECTIONS.items():
            if section.name.upper().startswith(prefix.upper()) and section.name:
                packer = packer or name
                signals.append(
                    PackingSignal(
                        "packer-section",
                        f"섹션 이름 '{section.name}' 은 {name} 패커의 특징입니다.",
                        70,
                    )
                )
                break

    # 2) 알려진 패커 매직 바이트.
    for magic, name in _PACKER_MAGICS.items():
        if magic in image.data:
            packer = packer or name
            signals.append(
                PackingSignal(
                    "packer-magic",
                    f"{name} 매직 '{magic.decode('latin-1')[:24]}' 을 발견했습니다.",
                    80,
                )
            )
            break

    # 3) 높은 엔트로피 실행 영역(압축/암호화 의심).
    exec_entropy = _max_exec_entropy(image)
    if exec_entropy is not None and exec_entropy >= _HIGH_ENTROPY:
        signals.append(
            PackingSignal(
                "high-entropy-exec",
                f"실행 영역의 섀넌 엔트로피가 {exec_entropy:.2f}/8.00 로 높습니다"
                " (압축/암호화된 코드 가능성).",
                45,
            )
        )

    # 4) 비정상 섹션 테이블(패커는 흔히 섹션 헤더를 벗겨 .text 가 없음).
    names = {s.name for s in image.sections}
    if image.sections and ".text" not in names:
        signals.append(
            PackingSignal(
                "no-text-section",
                "표준 .text 섹션이 없습니다(섹션 헤더가 벗겨졌을 수 있음).",
                40,
            )
        )
    elif len(image.sections) <= 3 and image.sections:
        signals.append(
            PackingSignal(
                "sparse-sections",
                f"섹션이 {len(image.sections)}개뿐입니다(정상 실행파일보다 매우 적음).",
                25,
            )
        )

    # 5) 적은 임포트(로더 스텁만 남은 패커 특징).
    if image.e_type == "ET_DYN" or image.has_dynamic_section:
        if len(image.imports) <= _FEW_IMPORTS:
            signals.append(
                PackingSignal(
                    "few-imports",
                    f"동적 임포트가 {len(image.imports)}개뿐입니다"
                    " (패커 로더 스텁만 남았을 수 있음).",
                    25,
                )
            )

    # 6) 오버레이(마지막 섹션 뒤에 붙은 데이터 — 패커/설치기 특징).
    overlay = _overlay_size(image)
    if overlay > 0:
        signals.append(
            PackingSignal(
                "overlay-data",
                f"마지막 섹션 뒤에 {overlay} 바이트의 오버레이 데이터가 있습니다.",
                20,
            )
        )

    # 확신도: 신호 가중치를 결합(독립 사건의 여집합 곱). 100 상한.
    remaining = 1.0
    for signal in signals:
        remaining *= 1.0 - min(signal.weight, 100) / 100.0
    confidence = round((1.0 - remaining) * 100)
    packed = confidence >= 50 or packer is not None
    return PackingReport(
        packed=packed, packer=packer, confidence=confidence, signals=signals
    )


def _max_exec_entropy(image: ElfImage) -> float | None:
    """실행 가능 섹션(없으면 실행 세그먼트) 중 최대 섀넌 엔트로피."""

    best: float | None = None
    for section in image.sections:
        if not section.executable or section.size <= 0:
            continue
        blob = image.data[section.offset : section.offset + section.size]
        if blob:
            e = shannon_entropy(blob)
            best = e if best is None else max(best, e)
    if best is not None:
        return best
    # 섹션 헤더가 없으면 실행 세그먼트로 폴백.
    for seg in image.segments:
        if not seg.executable:
            continue
        blob = image.data[seg.offset : seg.offset + seg.filesz]
        if blob:
            e = shannon_entropy(blob)
            best = e if best is None else max(best, e)
    return best


def _overlay_size(image: ElfImage) -> int:
    """정상 구조(섹션 데이터·섹션 헤더 테이블) 끝 이후에 남은 파일 데이터 크기.

    섹션 헤더 테이블은 보통 파일 끝에 오므로 그 끝을 포함해야 정상 실행파일을 오버레이로
    오인하지 않는다(그 크기는 ELF 헤더의 e_shoff/e_shentsize/e_shnum 에서 계산).
    """

    end = 0
    for section in image.sections:
        if section.stype == "SHT_NOBITS" or section.size <= 0:
            continue
        end = max(end, section.offset + section.size)
    if end == 0:
        return 0
    end = max(end, _section_header_table_end(image))
    return max(0, len(image.data) - end)


def _section_header_table_end(image: ElfImage) -> int:
    """ELF 헤더에서 섹션 헤더 테이블의 파일 끝 오프셋을 계산한다(실패 시 0)."""

    data = image.data
    byteorder: Literal["little", "big"] = (
        "little" if image.endian.lower().startswith("l") else "big"
    )
    try:
        if image.bits == 64:
            if len(data) < 0x40:
                return 0
            shoff = int.from_bytes(data[0x28:0x30], byteorder)
            shentsize = int.from_bytes(data[0x3A:0x3C], byteorder)
            shnum = int.from_bytes(data[0x3C:0x3E], byteorder)
        else:
            if len(data) < 0x34:
                return 0
            shoff = int.from_bytes(data[0x20:0x24], byteorder)
            shentsize = int.from_bytes(data[0x2E:0x30], byteorder)
            shnum = int.from_bytes(data[0x30:0x32], byteorder)
    except (ValueError, IndexError):  # pragma: no cover - 방어적
        return 0
    if shoff <= 0 or shentsize <= 0 or shnum <= 0:
        return 0
    return shoff + shentsize * shnum


__all__ = ["PackingReport", "PackingSignal", "detect_packing"]
