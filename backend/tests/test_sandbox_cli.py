"""일회용 샌드박스 CLI 워커 테스트.

게이트/사용법 오류는 플랫폼 무관, 실제 오프셋 확정만 Linux/x86-64 + gcc 요구.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess

import pytest

from pwnable_lab.config import get_settings
from pwnable_lab.sandbox import cli

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_VULN_SRC = """
#include <stdio.h>
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); return 0; }
"""


@pytest.fixture()
def _clean_settings(monkeypatch):
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _enable(monkeypatch, tmp_path=None):
    monkeypatch.setenv("PLAB_SANDBOX_EXECUTION_ENABLED", "1")
    if tmp_path is not None:
        marker = tmp_path / "marker"
        marker.write_text("x")
        monkeypatch.setenv("PLAB_SANDBOX_ISOLATION_MARKER", str(marker))
    get_settings.cache_clear()


def _compile(tmp_path):
    csrc = tmp_path / "vuln.c"
    csrc.write_text(_VULN_SRC)
    out = tmp_path / "vuln"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


def test_gate_disabled_returns_2(monkeypatch, capsys, _clean_settings):
    monkeypatch.delenv("PLAB_SANDBOX_EXECUTION_ENABLED", raising=False)
    get_settings.cache_clear()
    code = cli.main(["/bin/true"])
    assert code == 2
    assert "게이트 거부" in capsys.readouterr().err


def test_missing_marker_returns_2(monkeypatch, capsys, tmp_path, _clean_settings):
    monkeypatch.setenv("PLAB_SANDBOX_EXECUTION_ENABLED", "1")
    monkeypatch.setenv("PLAB_SANDBOX_ISOLATION_MARKER", str(tmp_path / "nope"))
    get_settings.cache_clear()
    assert cli.main(["/bin/true"]) == 2


def test_missing_file_returns_3(monkeypatch, capsys, tmp_path, _clean_settings):
    _enable(monkeypatch)
    code = cli.main([str(tmp_path / "does-not-exist")])
    assert code == 3


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_confirms_offset_via_path(monkeypatch, capsys, tmp_path, _clean_settings):
    binary = _compile(tmp_path)
    _enable(monkeypatch, tmp_path)
    code = cli.main([str(binary), "--pattern-length", "400"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["confirmed"] is True
    assert out["offset"] == 72
    assert out["verification"] == "verified"


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_confirms_offset_via_stdin(monkeypatch, capsys, tmp_path, _clean_settings):
    binary = _compile(tmp_path)
    _enable(monkeypatch, tmp_path)

    class _Buf:
        def __init__(self, data):
            self.buffer = self

        def read(self):
            return binary.read_bytes()

    monkeypatch.setattr("sys.stdin", _Buf(None))
    code = cli.main(["--stdin", "--pattern-length", "400"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["confirmed"] is True
    assert out["offset"] == 72


_HAVE_ZIG = shutil.which("zig") is not None

# amd64 ret2system 재료(pop rdi 가젯 + system + "/bin/sh").
_R2S_SRC = (
    "#include <stdio.h>\n#include <stdlib.h>\n"
    '__asm__(".global g_pop_rdi\\ng_pop_rdi: pop %rdi\\n ret\\n");\n'
    'void never(void){ char *s="/bin/sh"; system(s); }\n'
    "void vuln(void){ char buf[64]; gets(buf); }\n"
    "int main(void){ vuln(); return 0; }\n"
)


def _compile_src(tmp_path, src, *flags):
    csrc = tmp_path / "prog.c"
    csrc.write_text(src)
    out = tmp_path / "prog"
    subprocess.run(
        ["gcc", *flags, "-o", str(out), str(csrc)], check=True, capture_output=True
    )
    return out


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_cli_auto_ret2system_proves_shell(
    monkeypatch, capsys, tmp_path, _clean_settings
):
    """CLI --auto-ret2system 경로가 셸을 증명한다(핸들러 커버)."""
    binary = _compile_src(tmp_path, _R2S_SRC, "-fno-stack-protector", "-no-pie")
    _enable(monkeypatch, tmp_path)
    code = cli.main([str(binary), "--auto-ret2system", "--offset", "72"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["technique"] == "ret2system"
    assert out["succeeded"] is True


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_cli_auto_ret2system_pie_proves_shell(
    monkeypatch, capsys, tmp_path, _clean_settings
):
    """CLI --auto-ret2system-pie 경로(base 관측→rebase→셸)가 셸을 증명한다."""
    binary = _compile_src(tmp_path, _R2S_SRC, "-fno-stack-protector", "-pie", "-fPIE")
    _enable(monkeypatch, tmp_path)
    code = cli.main([str(binary), "--auto-ret2system-pie", "--offset", "72"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["technique"] == "ret2system-pie"
    assert out["succeeded"] is True


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_ZIG),
    reason="zig(32-bit static) 필요",
)
def test_cli_auto_ret2system32_pie_proves_shell(
    monkeypatch, capsys, tmp_path, _clean_settings
):
    """CLI --auto-ret2system32-pie(i386 PIE) 경로가 셸을 증명한다(신규 핸들러 커버)."""
    src = (
        "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
        'void win(void){ system("/bin/sh"); }\n'
        "void vuln(void){ char buf[64]; read(0, buf, 300); }\n"
        "int main(void){ setvbuf(stdout, 0, 2, 0); vuln(); return 0; }\n"
    )
    csrc = tmp_path / "i.c"
    csrc.write_text(src)
    out = tmp_path / "i32pie"
    try:
        subprocess.run(
            [
                "zig",
                "cc",
                "-target",
                "x86-linux-musl",
                "-fno-stack-protector",
                "-pie",
                "-fPIE",
                "-static",
                "-o",
                str(out),
                str(csrc),
            ],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError):
        pytest.skip("zig 32-bit static-PIE 컴파일 불가")
    _enable(monkeypatch, tmp_path)
    # 오프셋은 서비스가 확정하지만 CLI 는 인자로 받으므로 러너로 확정해 전달.
    from pwnable_lab.sandbox.runner import confirm_return_offset

    oc = confirm_return_offset(str(out), pattern_length=200)
    code = cli.main([str(out), "--auto-ret2system32-pie", "--offset", str(oc.offset)])
    assert code == 0
    res = json.loads(capsys.readouterr().out)
    assert res["technique"] == "ret2system-pie"
    assert res["bits"] == 32
    assert res["succeeded"] is True


def test_cli_auto_ret2system32_pie_requires_offset(
    monkeypatch, capsys, tmp_path, _clean_settings
):
    """--auto-ret2system32-pie 는 --offset 이 없으면 3 을 반환한다."""
    _enable(monkeypatch, tmp_path)
    code = cli.main(["/bin/true", "--auto-ret2system32-pie"])
    assert code == 3
    assert "--offset" in capsys.readouterr().err


# amd64 ret2win: win() 은 마커 후 깔끔히 종료(PIE control-transfer 오라클).
_WIN_SRC = (
    "#include <stdio.h>\n#include <unistd.h>\n"
    'void win(void){ puts("CLIWIN"); fflush(stdout); _exit(0); }\n'
    "void vuln(void){ char buf[64]; gets(buf); }\n"
    "int main(void){ vuln(); return 0; }\n"
)

# amd64 execve 재료(클린 pop rdi/rsi/rdx/rax + syscall + "/bin/sh").
_EXECVE_SRC = (
    "#include <stdio.h>\n"
    '__asm__(".global g\\ng:\\n pop %rdi\\n ret\\n pop %rsi\\n ret\\n'
    ' pop %rdx\\n ret\\n pop %rax\\n ret\\n syscall\\n ret\\n");\n'
    'char binsh_str[] = "/bin/sh";\n'
    "void vuln(void){ char buf[64]; gets(buf); }\n"
    "int main(void){ vuln(); return 0; }\n"
)


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_cli_auto_ret2win_pie_proves(monkeypatch, capsys, tmp_path, _clean_settings):
    """CLI --auto-ret2win-pie(base 관측→rebase) 경로를 커버한다."""
    binary = _compile_src(tmp_path, _WIN_SRC, "-fno-stack-protector", "-pie", "-fPIE")
    _enable(monkeypatch, tmp_path)
    code = cli.main([str(binary), "--auto-ret2win-pie", "--offset", "72"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["technique"] == "ret2win-pie"
    assert out["succeeded"] is True


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_cli_auto_execve_proves_shell(monkeypatch, capsys, tmp_path, _clean_settings):
    """CLI --auto-execve(execve syscall ROP) 경로가 셸을 증명한다."""
    binary = _compile_src(tmp_path, _EXECVE_SRC, "-fno-stack-protector", "-no-pie")
    _enable(monkeypatch, tmp_path)
    code = cli.main([str(binary), "--auto-execve", "--offset", "72"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["technique"] == "execve"
    assert out["succeeded"] is True


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_ZIG),
    reason="zig(32-bit static) 필요",
)
def test_cli_auto_ret2system32_proves_shell(
    monkeypatch, capsys, tmp_path, _clean_settings
):
    """CLI --auto-ret2system32(i386 non-PIE) 경로가 셸을 증명한다."""
    src = (
        "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
        'void win(void){ system("/bin/sh"); }\n'
        "void vuln(void){ char buf[64]; read(0, buf, 300); }\n"
        "int main(void){ setvbuf(stdout, 0, 2, 0); vuln(); return 0; }\n"
    )
    csrc = tmp_path / "i.c"
    csrc.write_text(src)
    out = tmp_path / "i32"
    try:
        subprocess.run(
            [
                "zig",
                "cc",
                "-target",
                "x86-linux-musl",
                "-fno-stack-protector",
                "-no-pie",
                "-static",
                "-o",
                str(out),
                str(csrc),
            ],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError):
        pytest.skip("zig 32-bit 컴파일 불가")
    _enable(monkeypatch, tmp_path)
    code = cli.main([str(out), "--auto-ret2system32", "--offset", "68"])
    assert code == 0
    res = json.loads(capsys.readouterr().out)
    assert res["technique"] == "ret2system"
    assert res["bits"] == 32
    assert res["succeeded"] is True


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_cli_verify_payload_control_transfer(
    monkeypatch, capsys, tmp_path, _clean_settings
):
    """CLI --verify 경로: win 주소로 payload 를 구성해 제어 이전을 확인한다."""
    from pwnable_lab.elf.parser import parse_elf

    binary = _compile_src(tmp_path, _WIN_SRC, "-fno-stack-protector", "-no-pie")
    win = parse_elf(binary.read_bytes()).symbol("win")
    assert win is not None
    _enable(monkeypatch, tmp_path)
    code = cli.main(
        [
            str(binary),
            "--verify",
            "--offset",
            "72",
            "--target",
            str(win.addr),
            "--bits",
            "64",
        ]
    )
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["succeeded"] is True
