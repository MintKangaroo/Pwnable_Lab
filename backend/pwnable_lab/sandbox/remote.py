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

import socket
import time

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
