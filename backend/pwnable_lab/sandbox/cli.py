"""One-shot 샌드박스 워커 — 단일 바이너리의 반환 주소 오프셋을 확정한다.

이 프로세스는 **network-disabled 일회용 컨테이너 안에서** 실행되도록 설계됐다
(``docs/AUTO_EXPLOIT_SANDBOX.md``). 바이너리 경로 하나를 받아
:func:`~pwnable_lab.sandbox.confirm_return_offset` 를 돌리고,
:class:`~pwnable_lab.sandbox.OffsetConfirmation` 를 JSON 으로 stdout 에 출력한다.
사람이 읽는 로그·진단은 모두 stderr 로 보낸다(stdout 은 순수 JSON).

사용::

    python -m pwnable_lab.sandbox.cli /path/to/binary [--pattern-length N]
    # 또는 stdin 으로 바이너리 바이트 주입:
    python -m pwnable_lab.sandbox.cli --stdin < binary

종료 코드
--------
* 0 — 실행 완료(오프셋 확정 여부와 무관; JSON 의 ``confirmed`` 로 판단)
* 2 — 게이트/격리 마커 미충족 또는 샌드박스 구조적 실패(:class:`SandboxError`)
* 3 — 사용법/입출력 오류
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile

from pwnable_lab.config import get_settings
from pwnable_lab.errors import SandboxError
from pwnable_lab.sandbox import (
    SandboxLimits,
    confirm_return_offset,
    require_sandbox_boundary,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnable_lab.sandbox.cli",
        description="일회용 샌드박스에서 반환 주소 오프셋을 동적으로 확정한다.",
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("binary", nargs="?", help="실행할 바이너리 경로")
    src.add_argument(
        "--stdin",
        action="store_true",
        help="바이너리 바이트를 stdin 으로 읽는다(경로 대신).",
    )
    parser.add_argument(
        "--pattern-length",
        type=int,
        default=None,
        help="cyclic 패턴 길이(생략 시 PLAB_SANDBOX_PATTERN_LENGTH).",
    )
    return parser


def _materialize_stdin() -> str:
    data = sys.stdin.buffer.read()
    if not data:
        raise ValueError("stdin 에서 바이너리 바이트를 읽지 못했습니다.")
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


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    settings = get_settings()

    try:
        require_sandbox_boundary(settings)
    except SandboxError as exc:
        print(f"[sandbox-cli] 게이트 거부: {exc}", file=sys.stderr)
        return 2

    cleanup: str | None = None
    try:
        if args.stdin:
            binary_path = cleanup = _materialize_stdin()
        else:
            binary_path = args.binary
            if not os.path.isfile(binary_path):
                print(
                    f"[sandbox-cli] 파일이 없습니다: {binary_path}", file=sys.stderr
                )
                return 3
    except (OSError, ValueError) as exc:
        print(f"[sandbox-cli] 입력 오류: {exc}", file=sys.stderr)
        return 3

    length = args.pattern_length or settings.sandbox_pattern_length
    limits = SandboxLimits(
        wall_seconds=settings.sandbox_wall_seconds,
        cpu_seconds=settings.sandbox_cpu_seconds,
        address_space_bytes=settings.sandbox_address_space_bytes,
    )
    try:
        print(
            f"[sandbox-cli] confirm_return_offset 실행 (pattern_length={length})",
            file=sys.stderr,
        )
        result = confirm_return_offset(
            binary_path, pattern_length=length, limits=limits
        )
    except SandboxError as exc:
        print(f"[sandbox-cli] 샌드박스 오류: {exc}", file=sys.stderr)
        return 2
    finally:
        if cleanup is not None:
            try:
                os.unlink(cleanup)
            except OSError:
                pass

    json.dump(result.as_dict(), sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
