"""Ghidra headless 디컴파일 백엔드(선택).

기존 :mod:`analyzer.decompile` 은 규칙 기반 경량 pseudo-C 생성기다. 이 모듈은
**진짜 디컴파일러(Ghidra)** 가 설치돼 있을 때 그걸 써서 훨씬 정확한 C 를 얻는다.
Ghidra 는 바이너리를 **실행하지 않고** 정적 분석만 하므로(샌드박스 러너와 성격이
다르다) 상대적으로 안전하지만, 무겁고 느리므로(임포트+분석 수십 초) 기본 비활성이며
온디맨드로만 호출한다. 설치가 없거나 실패하면 호출자는 규칙 기반으로 폴백한다.

동작: 업로드 바이너리를 임시 파일에 쓰고 ``support/analyzeHeadless`` 로 일회용
프로젝트에 임포트·분석한 뒤, 번들된 Java 스크립트(``ghidra_scripts/DecompileToJson``)
로 함수별 C 를 JSON 으로 덤프해 파싱한다. 프로젝트/임시 파일은 끝나면 정리한다.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra_scripts"
_SCRIPT_NAME = "DecompileToJson.java"


class GhidraError(RuntimeError):
    """Ghidra 실행 실패(미설치·타임아웃·비정상 종료·JSON 파싱 오류)."""


@dataclass
class GhidraLocation:
    """확정된 Ghidra/JDK 위치."""

    analyze_headless: str
    java_home: str | None


def _first_glob(pattern: str) -> str | None:
    matches = sorted(glob.glob(os.path.expanduser(pattern)))
    return matches[-1] if matches else None


def locate_ghidra(ghidra_home: str = "", java_home: str = "") -> GhidraLocation | None:
    """Ghidra ``analyzeHeadless`` 와 JDK 경로를 확정한다(없으면 None).

    ``ghidra_home`` 이 비면 ``~/.local/ghidra_*`` 를 자동 탐지한다. ``java_home`` 이
    비면 ``PLAB_JAVA_HOME``/``JAVA_HOME`` 환경변수, ``~/.local/jdk/jdk-*``, 마지막으로
    ``PATH`` 의 ``java`` 순으로 찾는다(찾으면 그 상위를 JAVA_HOME 으로).
    """

    home = (
        ghidra_home
        or os.environ.get("PLAB_GHIDRA_HOME", "")
        or _first_glob("~/.local/ghidra_*")
    )
    if not home:
        return None
    headless = os.path.join(home, "support", "analyzeHeadless")
    if not os.path.isfile(headless):
        return None

    jhome = (
        java_home
        or os.environ.get("PLAB_JAVA_HOME", "")
        or os.environ.get("JAVA_HOME", "")
        or _first_glob("~/.local/jdk/jdk-*")
    )
    if not jhome:
        java_bin = shutil.which("java")
        if java_bin:
            # <jdk>/bin/java → JAVA_HOME=<jdk>
            jhome = os.path.dirname(os.path.dirname(os.path.realpath(java_bin)))
    return GhidraLocation(analyze_headless=headless, java_home=jhome or None)


def ghidra_available(ghidra_home: str = "", java_home: str = "") -> bool:
    """Ghidra 로 디컴파일할 수 있는 상태인지(설치 탐지)."""

    return locate_ghidra(ghidra_home, java_home) is not None


def decompile_with_ghidra(
    data: bytes,
    *,
    max_functions: int = 200,
    timeout_seconds: float = 180.0,
    ghidra_home: str = "",
    java_home: str = "",
) -> dict:
    """``data`` 바이너리를 Ghidra headless 로 디컴파일해 구조화 dict 를 반환한다.

    반환 형태::

        {"backend": "ghidra", "program", "language", "image_base",
         "function_count", "functions": [{"name","entry","signature","c"}, ...]}

    Ghidra 미설치/실패 시 :class:`GhidraError` 를 던진다(호출자가 폴백 판단).
    """

    loc = locate_ghidra(ghidra_home, java_home)
    if loc is None:
        raise GhidraError("Ghidra 설치를 찾지 못했습니다(PLAB_GHIDRA_HOME 확인).")
    script = _SCRIPT_DIR / _SCRIPT_NAME
    if not script.is_file():
        raise GhidraError(f"디컴파일 스크립트가 없습니다: {script}")

    workdir = tempfile.mkdtemp(prefix="plab-ghidra-")
    bin_path = os.path.join(workdir, "target.bin")
    out_path = os.path.join(workdir, "decompiled.json")
    proj_dir = os.path.join(workdir, "proj")
    os.mkdir(proj_dir)
    with open(bin_path, "wb") as fh:
        fh.write(data)
    os.chmod(
        bin_path, stat.S_IRUSR | stat.S_IWUSR
    )  # 실행권 없음: Ghidra 는 정적 분석만

    env = dict(os.environ)
    if loc.java_home:
        env["JAVA_HOME"] = loc.java_home
        env["PATH"] = (
            os.path.join(loc.java_home, "bin") + os.pathsep + env.get("PATH", "")
        )

    argv = [
        loc.analyze_headless,
        proj_dir,
        "plab",
        "-import",
        bin_path,
        "-scriptPath",
        str(_SCRIPT_DIR),
        "-postScript",
        _SCRIPT_NAME,
        out_path,
        str(max_functions),
        "-deleteProject",
        "-analysisTimeoutPerFile",
        str(int(timeout_seconds)),
    ]
    try:
        proc = subprocess.run(  # noqa: S603 - argv 는 신뢰된 설정으로만 구성
            argv,
            capture_output=True,
            timeout=timeout_seconds,
            env=env,
            cwd=workdir,
        )
        if not os.path.isfile(out_path):
            tail = proc.stderr.decode("utf-8", "replace")[-800:]
            raise GhidraError(f"Ghidra 가 결과를 쓰지 못했습니다. stderr:\n{tail}")
        with open(out_path, encoding="utf-8") as fh:
            result: dict = json.load(fh)
    except subprocess.TimeoutExpired as exc:
        raise GhidraError(f"Ghidra 타임아웃({timeout_seconds}s)") from exc
    except json.JSONDecodeError as exc:
        raise GhidraError(f"Ghidra 출력 JSON 파싱 실패: {exc}") from exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    result["backend"] = "ghidra"
    return result
