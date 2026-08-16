"""오프셋 확정 실행 위치 추상화 — in-process vs 일회용 컨테이너.

두 executor 는 동일한 계약을 갖는다: 바이너리 바이트를 받아
:class:`~pwnable_lab.sandbox.OffsetConfirmation` 의 ``as_dict()`` 형태 dict 를
돌려준다.

* :func:`confirm_offset_in_process` — 현재 프로세스에서 러너를 직접 호출한다.
  실행 지점에서 격리 마커를 요구한다(:func:`require_sandbox_boundary`). API
  프로세스 자체가 격리 경계 안에 있을 때만 안전하다(dev/tests 기본).
* :func:`confirm_offset_in_container` — ``docker run`` 으로 매 요청마다
  network-disabled 일회용 컨테이너를 띄워 실행한다(``sandbox/run.sh`` 와 동일한
  하드닝). API 프로세스가 격리 경계 밖(DB/네트워크 필요)일 때의 프로덕션 경로.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from typing import Protocol

from pwnable_lab.errors import SandboxError
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.gate import require_sandbox_boundary
from pwnable_lab.sandbox.runner import (
    SandboxLimits,
    confirm_return_offset,
    verify_payload,
)


class _ExecutorSettings(Protocol):
    sandbox_execution_enabled: bool
    sandbox_isolation_marker: str
    sandbox_wall_seconds: float
    sandbox_cpu_seconds: int
    sandbox_address_space_bytes: int
    sandbox_pattern_length: int
    sandbox_container_image: str
    sandbox_docker_bin: str
    sandbox_container_runtime: str
    sandbox_container_timeout_seconds: float
    sandbox_container_memory: str
    sandbox_container_cpus: str
    sandbox_container_pids: int
    sandbox_container_tmp_size: str


def _limits(settings: _ExecutorSettings) -> SandboxLimits:
    return SandboxLimits(
        wall_seconds=settings.sandbox_wall_seconds,
        cpu_seconds=settings.sandbox_cpu_seconds,
        address_space_bytes=settings.sandbox_address_space_bytes,
    )


def confirm_offset_in_process(
    data: bytes, *, pattern_length: int, settings: _ExecutorSettings
) -> dict:
    """현재 프로세스에서 오프셋을 확정한다(격리 경계 안이라고 가정)."""

    require_sandbox_boundary(settings)  # 실행 지점에서 enabled + 마커 확인
    path = _materialize_executable(data)
    try:
        result = confirm_return_offset(
            path, pattern_length=pattern_length, limits=_limits(settings)
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return result.as_dict()


def confirm_offset_in_container(
    data: bytes, *, pattern_length: int, settings: _ExecutorSettings
) -> dict:
    """일회용 network-disabled 컨테이너에서 오프셋을 확정한다.

    바이너리는 stdin 으로 주입되고(호스트 마운트 없음), 컨테이너 엔트리포인트가
    격리 마커를 만든 뒤 CLI 를 실행한다. 격리는 아래 ``docker run`` 플래그가
    강제한다.
    """

    return _run_container(settings, ["--stdin", "--pattern-length", str(pattern_length)], data)


def verify_exploit_in_process(
    data: bytes,
    *,
    offset: int,
    target: int,
    bits: int,
    chain: list[int] | tuple[int, ...] = (),
    markers: list[str] | tuple[str, ...] = (),
    settings: _ExecutorSettings,
) -> dict:
    """현재 프로세스에서 ret2win/ROP payload 를 주입해 익스 성공을 검증한다."""

    require_sandbox_boundary(settings)
    payload = build_overflow(
        offset, target, bits=bits, chain=[RopStep(a) for a in chain]
    )
    path = _materialize_executable(data)
    try:
        result = verify_payload(
            path, payload, success_markers=markers, limits=_limits(settings)
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return result.as_dict()


def verify_exploit_in_container(
    data: bytes,
    *,
    offset: int,
    target: int,
    bits: int,
    chain: list[int] | tuple[int, ...] = (),
    markers: list[str] | tuple[str, ...] = (),
    settings: _ExecutorSettings,
) -> dict:
    """일회용 컨테이너에서 ret2win/ROP payload 를 주입해 익스 성공을 검증한다."""

    cli_args = [
        "--stdin",
        "--verify",
        "--offset", str(offset),
        "--target", str(target),
        "--bits", str(bits),
    ]
    for link in chain:
        cli_args += ["--chain", str(link)]
    for marker in markers:
        cli_args += ["--marker", marker]
    return _run_container(settings, cli_args, data)


def _run_container(
    settings: _ExecutorSettings, cli_args: list[str], data: bytes
) -> dict:
    """하드닝 docker 컨테이너를 띄워 CLI 를 실행하고 JSON 결과를 파싱한다."""

    argv = _docker_base_argv(settings) + cli_args
    try:
        proc = subprocess.run(  # noqa: S603 - argv 는 신뢰된 설정으로만 구성
            argv,
            input=data,
            capture_output=True,
            timeout=settings.sandbox_container_timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise SandboxError(
            f"docker 실행 파일을 찾을 수 없습니다: {settings.sandbox_docker_bin}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(
            "샌드박스 컨테이너가 제한 시간 내 종료하지 않았습니다 "
            f"({settings.sandbox_container_timeout_seconds}s)."
        ) from exc

    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
        tail = detail[-500:] if detail else f"exit={proc.returncode}"
        raise SandboxError(f"샌드박스 컨테이너 실패: {tail}")

    stdout = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if not stdout:
        raise SandboxError("샌드박스 컨테이너가 결과를 출력하지 않았습니다.")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SandboxError(f"샌드박스 컨테이너 출력 파싱 실패: {exc}") from exc


def _docker_base_argv(settings: _ExecutorSettings) -> list[str]:
    """``sandbox/run.sh`` 와 동일한 하드닝 플래그(이미지까지)로 argv 를 구성한다."""

    mem = settings.sandbox_container_memory
    argv = [settings.sandbox_docker_bin, "run", "--rm", "-i"]
    if settings.sandbox_container_runtime:
        argv += ["--runtime", settings.sandbox_container_runtime]
    argv += [
        "--network", "none",
        "--read-only",
        "--tmpfs", f"/tmp:rw,exec,nosuid,size={settings.sandbox_container_tmp_size},mode=1777",
        "--tmpfs", "/run:rw,noexec,nosuid,size=1m,mode=1777",
        "--cap-drop", "ALL",
        "--cap-add", "SYS_PTRACE",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(settings.sandbox_container_pids),
        "--memory", mem,
        "--memory-swap", mem,
        "--cpus", settings.sandbox_container_cpus,
        # 러너 자원 상한을 컨테이너 CLI 에도 전달(컨테이너 밖 설정과 일치시킴).
        "-e", f"PLAB_SANDBOX_WALL_SECONDS={settings.sandbox_wall_seconds}",
        "-e", f"PLAB_SANDBOX_CPU_SECONDS={settings.sandbox_cpu_seconds}",
        "-e", f"PLAB_SANDBOX_ADDRESS_SPACE_BYTES={settings.sandbox_address_space_bytes}",
        settings.sandbox_container_image,
    ]
    return argv


def _materialize_executable(data: bytes) -> str:
    """바이트를 소유자 전용(0o700) 임시 실행파일로 기록하고 경로를 반환."""

    fd, path = tempfile.mkstemp(prefix="plab-sbx-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path
