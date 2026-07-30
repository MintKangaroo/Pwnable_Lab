"""위험 함수 스캐너.

심볼 테이블(정적 심볼 + 동적 심볼)을 훑어 잘 알려진 위험 API 사용을 표시한다.
버퍼 오버플로우·포맷 스트링·명령 실행 등의 카테고리로 분류하고 심각도를 매긴다.
"""

from __future__ import annotations

from dataclasses import dataclass

from pwnable_lab.elf.parser import ElfImage

# 함수명 -> (카테고리, 심각도, 설명)
_DANGEROUS: dict[str, tuple[str, str, str]] = {
    "gets": (
        "buffer-overflow",
        "critical",
        "길이 검사가 없어 스택 버퍼 오버플로우가 항상 가능합니다.",
    ),
    "strcpy": (
        "buffer-overflow",
        "high",
        "대상 버퍼 크기를 확인하지 않습니다. strlcpy/strncpy 를 사용하세요.",
    ),
    "strcat": ("buffer-overflow", "high", "경계 검사가 없는 문자열 연결."),
    "sprintf": ("buffer-overflow", "high", "출력 길이 제한이 없습니다. snprintf 사용."),
    "scanf": ("buffer-overflow", "medium", "%s 포맷은 폭 지정이 없으면 위험합니다."),
    "vsprintf": ("buffer-overflow", "high", "가변 인자 sprintf — 경계 없음."),
    "read": ("buffer-overflow", "info", "길이 인자가 버퍼보다 크면 오버플로우 가능."),
    "memcpy": ("buffer-overflow", "info", "길이가 사용자 입력이면 오버플로우 가능."),
    "printf": (
        "format-string",
        "medium",
        "첫 인자가 사용자 입력이면 포맷 스트링 취약점입니다.",
    ),
    "fprintf": ("format-string", "medium", "포맷 인자가 사용자 제어면 위험."),
    "snprintf": ("format-string", "info", "포맷 인자가 사용자 제어면 위험."),
    "syslog": ("format-string", "medium", "포맷 인자가 사용자 제어면 위험."),
    "system": ("command-exec", "critical", "셸 명령 실행 — 인자가 제어되면 RCE."),
    "execve": ("command-exec", "high", "프로그램 실행 — 인자 제어 시 위험."),
    "popen": ("command-exec", "high", "셸을 통한 프로세스 실행."),
    "malloc": ("heap", "info", "힙 사용 — 크기 계산 오버플로우/UAF 여부 확인."),
    "free": ("heap", "info", "이중 해제/UAF 여부 확인."),
    "alloca": ("stack", "medium", "스택에 가변 할당 — 스택 클래시 위험."),
}

_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


@dataclass
class Finding:
    symbol: str
    category: str
    severity: str
    description: str


def scan_vulns(image: ElfImage) -> list[Finding]:
    """이미지에서 위험 함수 사용 목록을 반환(심각도 내림차순)."""
    seen: dict[str, Finding] = {}
    for sym in image.symbols + image.dynamic_symbols:
        # PLT 스텁/외부 함수는 이름만으로 매칭
        base = sym.name.split("@")[0]
        info = _DANGEROUS.get(base)
        if info and base not in seen:
            category, severity, desc = info
            seen[base] = Finding(base, category, severity, desc)
    return sorted(seen.values(), key=lambda f: (_ORDER[f.severity], f.symbol))
