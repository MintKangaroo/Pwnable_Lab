"""Ghidra 디컴파일 결과를 vuln_scan/strategy 로 피드백하는 인사이트 추출기.

정적 disasm 휴리스틱은 ``[rbp-N]`` 변위에 의존해 버퍼 크기를 정확히 모르고(-O2
rsp-상대·스트립에서 실패), 오버플로를 ``possible`` 로만 표기한다. Ghidra 는 **실제
버퍼 크기와 스택 프레임 레이아웃**을 복원하므로:

* **오버플로 확정**: ``char buf[N]`` 에 무한 sink(gets/scanf %s)나 크기 초과 sink
  (read/fgets 의 write 크기 > N)가 있으면 *확정* 오버플로다(vs "가능").
* **정확한 오프셋**: payload 오프셋 = ``return_addr_offset - buffer_stack_offset``
  (Ghidra 프레임 기준). 실측으로 동적 확정값과 일치함을 검증했다(buf[64]→72 등).

이 모듈은 Ghidra 실행 결과(dict)만 받아 순수 파싱하므로 Ghidra 없이도 단위 테스트
가능하다. 실행/게이팅은 :mod:`analyzer.ghidra` 와 서비스 계층이 담당한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# sink 함수 -> (버퍼 인자 인덱스, 크기 인자 인덱스|None, 무한 여부)
# 무한(unbounded)=크기 제한 없이 버퍼에 쓴다(gets/strcpy/sprintf). read/fgets 는
# 크기 인자가 있어 그 값이 버퍼보다 클 때만 오버플로.
_SINKS: dict[str, tuple[int, int | None, bool]] = {
    "gets": (0, None, True),
    "read": (1, 2, False),
    "fgets": (0, 1, False),
    "strcpy": (0, None, True),
    "strcat": (0, None, True),
    "sprintf": (0, None, True),
    "scanf": (1, None, True),  # %s 무한 가정(폭 지정 검증은 정적으로 제한적)
    "__isoc99_scanf": (1, None, True),
}

# 함수 호출 파싱: name( args ). 중첩 괄호 없는 단순 호출만(디컴파일 C 는 대개 평탄).
_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^();]*)\)")
_INT = re.compile(r"^\s*(?:0x[0-9a-fA-F]+|\d+)\s*$")
# 배열 지역 선언: ``<type> name [N];`` — 진짜 버퍼 크기(원소×개수 근사로 N).
# 스트립 바이너리는 스택 Variable.getLength()==1(undefined1)이라 배열 크기가 C
# 선언에만 남는다. 여기서 이름→선언크기(N)를 뽑아 크기 판정의 1차 소스로 쓴다.
_DECL_ARRAY = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_ ]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]\s*;"
)


@dataclass
class OverflowInsight:
    """Ghidra 가 확정한 스택 버퍼 오버플로 후보."""

    function: str
    sink: str
    buffer_name: str
    buffer_size: int | None  # C 선언/스택에서 확정 못하면 None
    write_size: int | None  # 무한 sink 면 None
    unbounded: bool
    stack_offset: int  # 버퍼의 프레임 오프셋(음수)
    return_addr_offset: int
    offset: int  # payload 오프셋 = return_addr_offset - stack_offset
    confirmed: bool
    evidence: str


def _parse_int(token: str) -> int | None:
    token = token.strip()
    if not _INT.match(token):
        return None
    return int(token, 0)


def _split_args(arglist: str) -> list[str]:
    # 디컴파일 C 의 인자는 대개 단순 토큰. 문자열 리터럴 안의 콤마만 보호한다.
    args: list[str] = []
    depth = 0
    in_str = False
    cur: list[str] = []
    for ch in arglist:
        if ch == '"' and (not cur or cur[-1] != "\\"):
            in_str = not in_str
        if ch == "," and depth == 0 and not in_str:
            args.append("".join(cur).strip())
            cur = []
            continue
        if ch in "([" and not in_str:
            depth += 1
        elif ch in ")]" and not in_str:
            depth -= 1
        cur.append(ch)
    if cur:
        args.append("".join(cur).strip())
    return [a for a in args if a != ""]


def _clean_var(token: str) -> str:
    # &buf, (char *)buf 등에서 식별자만 뽑는다.
    m = re.search(r"[A-Za-z_][A-Za-z0-9_]*", token.replace("&", " "))
    return m.group(0) if m else token.strip()


def overflow_insights(ghidra_result: dict) -> list[OverflowInsight]:
    """Ghidra 결과에서 확정 스택 오버플로 후보를 심각도 높은 순으로 추출한다."""

    out: list[OverflowInsight] = []
    for func in ghidra_result.get("functions", []):
        c = func.get("c")
        if not c:
            continue
        # 스택 변수 이름 -> offset(프레임 기준). 크기는 스트립에서 1(undefined1)로
        # 뭉개지므로 여기선 오프셋만 취하고, 진짜 크기는 C 선언에서 뽑는다.
        stack_offsets = {
            v["name"]: int(v["offset"])
            for v in func.get("stack_vars", [])
            if v.get("name") is not None
        }
        if not stack_offsets:
            continue
        # C 선언에서 배열 크기: name -> N. 크기 판정의 1차 소스(스택 length 보다 정확).
        decl_sizes = {m.group(1): int(m.group(2)) for m in _DECL_ARRAY.finditer(c)}
        stack_sizes = {
            v["name"]: int(v["size"])
            for v in func.get("stack_vars", [])
            if v.get("name") is not None and v.get("size")
        }
        ret_off = int(func.get("return_addr_offset", 0))
        fname = func.get("name", "?")

        for match in _CALL.finditer(c):
            callee = match.group(1)
            spec = _SINKS.get(callee)
            if spec is None:
                continue
            buf_idx, size_idx, unbounded = spec
            args = _split_args(match.group(2))
            if buf_idx >= len(args):
                continue
            buf_name = _clean_var(args[buf_idx])
            if buf_name not in stack_offsets:
                continue
            stack_offset = stack_offsets[buf_name]
            # 진짜 배열 크기: C 선언 우선, 없으면 스택 length(≥2 일 때만 신뢰).
            buf_size = decl_sizes.get(buf_name)
            if buf_size is None:
                sv = stack_sizes.get(buf_name)
                buf_size = sv if sv and sv > 1 else None
            write_size = None
            if size_idx is not None and size_idx < len(args):
                write_size = _parse_int(args[size_idx])

            size_txt = "?" if buf_size is None else str(buf_size)
            if unbounded:
                # 무한 입력 sink 는 버퍼 크기와 무관하게 스택 버퍼를 넘긴다.
                confirmed = True
                reason = f"무한 입력 sink {callee}() 가 {size_txt}바이트 버퍼에 씀"
            elif write_size is not None and buf_size is not None:
                confirmed = write_size > buf_size
                reason = (
                    f"{callee}(...,{write_size}) 가 {buf_size}바이트 버퍼를 초과"
                    if confirmed
                    else f"{callee}(...,{write_size}) 는 {buf_size}바이트 이내(안전)"
                )
            else:
                # 크기 또는 버퍼 크기를 정적으로 못 읽음 — 확정 불가(가능 후보로만).
                confirmed = False
                reason = f"{callee}() 크기/버퍼 크기를 정적으로 확정 못함"

            offset = ret_off - stack_offset
            out.append(
                OverflowInsight(
                    function=fname,
                    sink=callee,
                    buffer_name=buf_name,
                    buffer_size=buf_size,
                    write_size=write_size,
                    unbounded=unbounded,
                    stack_offset=stack_offset,
                    return_addr_offset=ret_off,
                    offset=offset,
                    confirmed=confirmed,
                    evidence=(
                        f"{fname}(): {reason}; 버퍼 {buf_name}@frame{stack_offset} → "
                        f"오프셋 = {ret_off} - ({stack_offset}) = {offset}"
                    ),
                )
            )

    # 확정 먼저, 그 안에서 오프셋 큰(버퍼 먼) 순.
    out.sort(key=lambda i: (not i.confirmed, -i.offset))
    return out


def ghidra_offset_for_function(
    insights: list[OverflowInsight], function: str
) -> int | None:
    """지정 함수의 확정 오버플로 오프셋(여럿이면 가장 먼 것). 없으면 None.

    strategy/auto-exploit 이 정적 휴리스틱이 실패했을 때(-O2 등) 오프셋 소스로 쓴다.
    """

    best: int | None = None
    for insight in insights:
        if insight.function == function and insight.confirmed:
            if best is None or insight.offset > best:
                best = insight.offset
    return best


def best_overflow_offset(insights: list[OverflowInsight]) -> int | None:
    """전체에서 가장 유력한(확정·최대 오프셋) 오버플로 오프셋. 없으면 None."""

    confirmed = [i for i in insights if i.confirmed]
    if not confirmed:
        return None
    return max(i.offset for i in confirmed)
