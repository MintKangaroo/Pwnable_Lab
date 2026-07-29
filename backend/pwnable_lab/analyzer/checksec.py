"""완화 기법(mitigation) 점검 — ``checksec`` 유사 기능.

ELF 프로그램 헤더·동적 심볼·심볼 테이블로부터 다음을 판정한다.

* **RELRO**  — GNU_RELRO 세그먼트 + (Full 이면) BIND_NOW
* **Stack Canary** — ``__stack_chk_fail`` 심볼 존재
* **NX**    — GNU_STACK 세그먼트가 실행 불가인가
* **PIE**   — ET_DYN 이며 DYNAMIC 세그먼트가 있는가
* **RPATH/RUNPATH** — 존재 여부
* **Fortify** — ``*_chk`` 심볼 존재
"""

from __future__ import annotations

from dataclasses import dataclass

from pwnable_lab.elf.parser import ElfImage


@dataclass
class Checksec:
    relro: str  # "Full" | "Partial" | "No"
    canary: bool
    nx: bool
    pie: str  # "PIE" | "No PIE" | "DSO"
    rpath: bool
    runpath: bool
    fortify: bool
    symbols_stripped: bool

    def as_dict(self) -> dict:
        return {
            "relro": self.relro,
            "canary": self.canary,
            "nx": self.nx,
            "pie": self.pie,
            "rpath": self.rpath,
            "runpath": self.runpath,
            "fortify": self.fortify,
            "stripped": self.symbols_stripped,
        }


_CANARY_SYMBOLS = {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"}


def run_checksec(image: ElfImage) -> Checksec:
    seg_types = {s.ptype for s in image.segments}
    has_dynamic = "PT_DYNAMIC" in seg_types

    # --- NX ---
    nx = True
    for seg in image.segments:
        if seg.ptype == "PT_GNU_STACK":
            nx = not seg.executable
            break

    # --- RELRO ---
    has_relro = "PT_GNU_RELRO" in seg_types
    bind_now = _has_bind_now(image)
    if not has_relro:
        relro = "No"
    elif bind_now:
        relro = "Full"
    else:
        relro = "Partial"

    # --- Canary / Fortify ---
    all_syms = image.symbols + image.dynamic_symbols
    names = {s.name for s in all_syms}
    canary = bool(names & _CANARY_SYMBOLS)
    fortify = any(n.endswith("_chk") and n.startswith("__") for n in names)

    # --- PIE ---
    if image.e_type == "ET_DYN":
        # PIE 실행 파일은 보통 PT_INTERP 를 가지며 진입점도 설정된다. 학습용으로
        # 합성한 최소 ELF 에는 동적 로더가 없으므로 non-zero entry 도 실행 파일
        # 표식으로 인정한다.
        pie = "PIE" if "PT_INTERP" in seg_types or image.entry != 0 else "DSO"
    else:
        pie = "No PIE"

    # --- RPATH / RUNPATH (동적 태그) ---
    rpath, runpath = _dynamic_paths(image)

    stripped = len(image.symbols) == 0

    return Checksec(
        relro=relro,
        canary=canary,
        nx=nx,
        pie=pie,
        rpath=rpath,
        runpath=runpath,
        fortify=fortify,
        symbols_stripped=stripped,
    )


def _has_bind_now(image: ElfImage) -> bool:
    # DT_BIND_NOW, DF_BIND_NOW, DF_1_NOW 를 모두 처리한다. 빌더가 만든 학습용
    # 정적 ELF 는 동적 섹션이 없으므로 전용 심볼을 표식으로 쓴다.
    return (
        "DT_BIND_NOW" in image.dynamic_tags
        or bool(image.dynamic_flags.get("DT_FLAGS", 0) & 0x8)
        or bool(image.dynamic_flags.get("DT_FLAGS_1", 0) & 0x1)
        or any(s.name == "__relro_full" for s in image.symbols)
    )


def _dynamic_paths(image: ElfImage) -> tuple[bool, bool]:
    return "DT_RPATH" in image.dynamic_tags, "DT_RUNPATH" in image.dynamic_tags
