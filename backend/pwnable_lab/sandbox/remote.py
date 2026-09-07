"""원격 TCP 서비스 상대 셸 증명 — 생성 스크립트의 *remote-ready* 주장 실측.

:mod:`sandbox.runner` 의 셸 증명은 **로컬 프로세스**를 PTY 로 띄워 확인한다. 이 모듈은
확정된 payload 가 **네트워크 서비스**(host:port)에서도 셸을 띄우는지 소켓으로 검증한다
— :mod:`analyzer.exploit_script` 가 생성하는 ``remote(HOST,PORT)`` 스크립트의 원격
가능성 주장을 실제 TCP 연결로 뒷받침한다.

**트러스트 모델(중요)**: 이것은 network-disabled 일회용 샌드박스(:mod:`sandbox`)와
**다른 것**이다. 샌드박스는 신뢰할 수 없는 바이너리를 네트워크 없이 실행한다. 여기는
바이너리를 실행하지 않고, **사용자가 지정한 원격 엔드포인트로 바이트를 보낼 뿐**이다
(CTF 플레이어가 자기 타깃에 익스를 던지는 것과 동일). 따라서 서버가 임의 host:port 로
아웃바운드 연결하는 SSRF 위험을 만들지 않도록 **HTTP API 로 자동 노출하지 않는다** —
클라이언트측(CLI/테스트/생성 스크립트) 유틸리티다.
"""

from __future__ import annotations

import secrets
import socket
import time
from dataclasses import dataclass

from pwnable_lab.sandbox.runner import ShellProof


def prove_shell_remote(
    host: str,
    port: int,
    payload: bytes,
    *,
    marker: str,
    command: str | None = None,
    timeout: float = 5.0,
    settle_seconds: float = 0.3,
    max_recv_bytes: int = 65536,
) -> ShellProof:
    """원격 서비스에 payload 를 보내 spawn 된 셸에서 명령 실행을 증명한다.

    프로토콜(로컬 :func:`sandbox.runner.verify_shell` 과 동형): payload(개행 포함)로
    오버플로를 트리거해 ``system("/bin/sh")`` 등으로 셸을 띄우고, 이어서
    ``echo <marker>`` 를 흘린다. 셸이 이를 실행해 marker 를 되돌려주면 셸 획득 증명이다.

    ``settle_seconds`` 만큼 payload 전송 후 잠깐 기다렸다가 명령을 보낸다 — 대상이
    ``read(n)`` 처럼 길이 기반으로 읽으면 payload 와 명령이 한 번에 도착할 경우 명령이
    오버플로 버퍼로 흡수돼 셸이 못 읽으므로, 셸이 spawn 된 뒤 명령이 **별도 read** 로
    전달되게 한다(pwntools 로 프롬프트에 sync 하는 것의 단순 대체).

    소켓은 tty 가 아니라 spawn 된 셸의 stdio 가 블록 버퍼링될 수 있으므로, 명령 전송
    후 쓰기 방향을 닫아(EOF) 셸이 명령을 마치고 **종료하며 flush** 하게 한다.
    """

    cmd = command or f"echo {marker}"
    marker_bytes = marker.encode()
    chunks = bytearray()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        # 대상이 일찍 죽어 연결이 리셋되면(익스 실패) 예외 없이 실패로 보고한다.
        try:
            # 1) 오버플로 payload → 셸 spawn.
            sock.sendall(payload + b"\n")
            if settle_seconds > 0:
                time.sleep(settle_seconds)
            # 2) echo marker → 셸이 실행(payload 와 별도 read 로 도착).
            sock.sendall(cmd.encode() + b"\n")
            # EOF 신호로 비대화형 셸이 명령을 마치고 종료하며 출력을 flush 하게 한다.
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            while len(chunks) < max_recv_bytes:
                data = sock.recv(4096)
                if not data:
                    break
                chunks += data
                if marker_bytes in bytes(chunks):
                    break
        except (TimeoutError, OSError):
            pass

    output = bytes(chunks)
    return ShellProof(
        shell_spawned=marker_bytes in output,
        marker=marker,
        command=cmd,
        output=output,
    )


@dataclass
class RemoteCommandResult:
    """대화형 원격 셸에서 명령 하나의 실행 결과."""

    command: str
    output: bytes  # sentinel 앞까지의 명령 stdout(sentinel 제거됨).
    marker: str  # 이 명령의 구분자(sentinel).
    matched: bool  # sentinel 을 회수했는지(= 셸이 명령을 실행했는지).

    def as_dict(self) -> dict:
        return {
            "command": self.command,
            "output": self.output.decode("utf-8", "replace"),
            "output_hex": self.output.hex(),
            "marker": self.marker,
            "matched": self.matched,
        }


@dataclass
class InteractiveShellProof:
    """대화형 원격 셸 세션 증명(한 연결에서 여러 명령 순차 실행)."""

    shell_spawned: bool  # 첫 명령의 sentinel 회수 = 셸 획득.
    commands: list[RemoteCommandResult]

    def as_dict(self) -> dict:
        return {
            "shell_spawned": self.shell_spawned,
            "commands": [c.as_dict() for c in self.commands],
        }


def prove_interactive_shell_remote(
    host: str,
    port: int,
    payload: bytes,
    *,
    commands: list[str],
    timeout: float = 5.0,
    settle_seconds: float = 0.3,
    max_recv_bytes: int = 65536,
) -> InteractiveShellProof:
    """원격 셸에서 **여러 명령을 한 연결로 순차 실행**해 대화형 세션을 증명한다.

    :func:`prove_shell_remote` 는 명령 하나를 보내고 쓰기 방향을 닫아(EOF) 셸이
    종료하며 flush 하게 하는 **단발** 증명이다. 이 함수는 연결을 닫지 않고 각 명령
    뒤에 고유 sentinel(``echo <marker>``)을 붙여 스트림에서 명령 경계를 구분한다 —
    CTF 플레이어가 셸 획득 후 ``id`` / ``pwd`` / ``cat flag`` 를 이어 치는 흐름과
    동형이다. 각 명령 출력은 sentinel 직전까지를 담는다.

    소켓은 tty 가 아니라 입력이 에코되지 않으므로 명령 텍스트가 출력에 섞이지 않는다.
    셸이 어떤 명령에 응답을 멈추면(sentinel 미회수) 그 지점에서 중단한다. 첫 명령의
    sentinel 을 회수하면 ``shell_spawned=True``.

    트러스트 모델은 :func:`prove_shell_remote` 와 동일하다 — 바이너리 미실행,
    사용자 지정 원격에 바이트만 전송, HTTP API 미노출(클라이언트측 유틸).
    """

    results: list[RemoteCommandResult] = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        try:
            # 1) 오버플로 payload → 셸 spawn.
            sock.sendall(payload + b"\n")
            if settle_seconds > 0:
                time.sleep(settle_seconds)
            # 2) 각 명령 뒤에 sentinel 을 붙여 보내고, sentinel 까지 출력을 회수한다.
            for command in commands:
                marker = "PWNPILOT_" + secrets.token_hex(4)
                marker_bytes = marker.encode()
                sock.sendall(f"{command}; echo {marker}\n".encode())
                buf = bytearray()
                matched = False
                deadline = time.monotonic() + timeout
                while len(buf) < max_recv_bytes and time.monotonic() < deadline:
                    try:
                        data = sock.recv(4096)
                    except (TimeoutError, OSError):
                        break
                    if not data:
                        break
                    buf += data
                    if marker_bytes in bytes(buf):
                        matched = True
                        break
                # sentinel(및 이후)을 제거해 순수 명령 출력만 남긴다.
                raw = bytes(buf)
                idx = raw.find(marker_bytes)
                clean = raw[:idx] if idx != -1 else raw
                results.append(RemoteCommandResult(command, clean, marker, matched))
                if not matched:
                    break  # 셸이 응답을 멈춤 → 이후 명령 무의미.
        except (TimeoutError, OSError):
            pass

    shell_spawned = bool(results) and results[0].matched
    return InteractiveShellProof(shell_spawned=shell_spawned, commands=results)
