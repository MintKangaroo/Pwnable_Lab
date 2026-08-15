"""컨테이너 executor 및 서비스 분기 테스트(실제 docker 불필요, subprocess 목킹)."""

from __future__ import annotations

import json
import subprocess
import types

import pytest

from pwnable_lab.config import Settings
from pwnable_lab.errors import SandboxError
from pwnable_lab.sandbox import executor


def _settings(**over):
    return Settings(
        sandbox_execution_enabled=True,
        sandbox_executor="container",
        **over,
    )


def _proc(returncode=0, stdout=b"", stderr=b""):
    return types.SimpleNamespace(
        returncode=returncode, stdout=stdout, stderr=stderr
    )


_OK = {
    "confirmed": True,
    "offset": 72,
    "method": "stack_return_slot",
    "verification": "verified",
}


def test_docker_argv_has_hardening_flags():
    argv = executor._docker_argv(_settings(sandbox_container_runtime="runsc"), 400)
    joined = " ".join(argv)
    assert argv[:4] == ["docker", "run", "--rm", "-i"]
    assert "--runtime runsc" in joined
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--cap-drop ALL" in joined
    assert "--cap-add SYS_PTRACE" in joined
    assert "no-new-privileges" in joined
    assert "/tmp:rw,exec,nosuid" in joined
    assert "/run:rw,noexec,nosuid" in joined
    # 이미지와 CLI 인자는 맨 끝.
    assert argv[-4:] == ["pwnpilot-sandbox", "--stdin", "--pattern-length", "400"]


def test_docker_argv_omits_runtime_when_unset():
    argv = executor._docker_argv(_settings(), 512)
    assert "--runtime" not in argv


def test_container_success_parses_stdout(monkeypatch):
    captured = {}

    def fake_run(argv, *, input, capture_output, timeout):
        captured["argv"] = argv
        captured["input"] = input
        captured["timeout"] = timeout
        return _proc(stdout=json.dumps(_OK).encode())

    monkeypatch.setattr(executor.subprocess, "run", fake_run)
    out = executor.confirm_offset_in_container(
        b"\x7fELFdata", pattern_length=400, settings=_settings()
    )
    assert out == _OK
    assert captured["input"] == b"\x7fELFdata"
    assert captured["argv"][-1] == "400"


def test_container_nonzero_raises(monkeypatch):
    monkeypatch.setattr(
        executor.subprocess,
        "run",
        lambda *a, **k: _proc(returncode=125, stderr=b"boom detail"),
    )
    with pytest.raises(SandboxError, match="boom detail"):
        executor.confirm_offset_in_container(
            b"x", pattern_length=400, settings=_settings()
        )


def test_container_timeout_raises(monkeypatch):
    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=30)

    monkeypatch.setattr(executor.subprocess, "run", fake_run)
    with pytest.raises(SandboxError, match="제한 시간"):
        executor.confirm_offset_in_container(
            b"x", pattern_length=400, settings=_settings()
        )


def test_container_docker_missing_raises(monkeypatch):
    def fake_run(*a, **k):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(executor.subprocess, "run", fake_run)
    with pytest.raises(SandboxError, match="docker"):
        executor.confirm_offset_in_container(
            b"x", pattern_length=400, settings=_settings()
        )


def test_container_bad_json_raises(monkeypatch):
    monkeypatch.setattr(
        executor.subprocess, "run", lambda *a, **k: _proc(stdout=b"not json")
    )
    with pytest.raises(SandboxError, match="파싱 실패"):
        executor.confirm_offset_in_container(
            b"x", pattern_length=400, settings=_settings()
        )


def test_service_routes_to_container(monkeypatch):
    from pwnable_lab.api.services import AnalysisService
    from tests.fixtures import sample_elf

    calls = {}

    def fake_container(data, *, pattern_length, settings):
        calls["data"] = data
        calls["pattern_length"] = pattern_length
        return _OK

    monkeypatch.setattr(
        "pwnable_lab.api.services.confirm_offset_in_container", fake_container
    )
    service = AnalysisService(_settings())
    out = service.confirm_offset(sample_elf(), pattern_length=256)
    assert out == _OK
    assert calls["pattern_length"] == 256
