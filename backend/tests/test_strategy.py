"""Exploit 전략 추천과 pseudo-C 초안 API 테스트."""

from __future__ import annotations

from tests.fixtures import sample_elf


def _upload(client, data=None, filename="sample.elf"):
    return client.post(
        "/api/v1/binaries",
        files={"file": (filename, data or sample_elf(), "application/octet-stream")},
    )


def test_strategy_recommends_ret2win_when_win_symbol_present(client):
    binary_id = _upload(client).json()["binary_id"]

    response = client.get(f"/api/v1/binaries/{binary_id}/strategy")
    assert response.status_code == 200
    body = response.json()

    assert body["format"] == "ELF"
    assert body["verification"] == "inferred"
    path_ids = {path["id"] for path in body["paths"]}
    assert "ret2win" in path_ids

    win = next(path for path in body["paths"] if path["id"] == "ret2win")
    assert "from pwn import *" in win["pwntools"]
    assert "win" in win["pwntools"]
    # 모든 경로가 근거/선행조건/pwntools 초안을 갖춘다.
    for path in body["paths"]:
        assert path["status"] in {"recommended", "possible", "blocked"}
        assert "pwntools" in path and path["pwntools"]
        assert isinstance(path["steps"], list)


def test_strategy_reports_primitive_evidence(client):
    binary_id = _upload(client).json()["binary_id"]
    body = client.get(f"/api/v1/binaries/{binary_id}/strategy").json()

    keys = {primitive["key"] for primitive in body["primitives"]}
    assert {"stack_overflow", "win_function", "binsh_string"} <= keys
    win_primitive = next(p for p in body["primitives"] if p["key"] == "win_function")
    assert win_primitive["present"] is True


def test_pseudocode_renders_function_draft(client):
    binary_id = _upload(client).json()["binary_id"]

    functions = client.get(f"/api/v1/binaries/{binary_id}/functions").json()
    main = next(
        (item for item in functions["items"] if item["name"] == "main"),
        functions["items"][0],
    )
    address = hex(main["address"])

    response = client.get(
        f"/api/v1/binaries/{binary_id}/functions/{address}/pseudocode"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["verification"] == "inferred"
    assert body["disassembly_verification"] == "verified"
    assert body["signature"].startswith("int ")
    assert "pseudo-C" in body["pseudocode"]
    assert body["pseudocode"].strip().endswith("}")


def test_win_functions_prefer_strong_hints():
    """강한 힌트(get_shell)가 약한 힌트(secret_admin)보다 먼저 선택된다."""
    from types import SimpleNamespace

    from pwnable_lab.analyzer.strategy import _win_functions

    def sym(name, addr):
        return SimpleNamespace(name=name, addr=addr, defined=True, stype="STT_FUNC")

    # 약한 힌트가 더 낮은 주소지만 강한 힌트가 우선되어야 한다.
    image = SimpleNamespace(
        symbols=[sym("secret_admin", 0x1000), sym("get_shell", 0x2000)],
        dynamic_symbols=[],
    )
    result = _win_functions(image)
    assert result[0][0] == "get_shell"


def test_format_string_skeleton_uses_detected_symbol():
    """포맷 스트링 스켈레톤이 하드코딩 printf 대신 탐지된 함수를 쓴다."""
    from types import SimpleNamespace

    from pwnable_lab.analyzer.strategy import _skeleton_format_string

    context = SimpleNamespace(bits=64, binary_name="./target")
    code = _skeleton_format_string(context, "fprintf")
    assert "fprintf" in code
    assert "elf.got['fprintf']" in code


def test_strategy_rejects_non_elf(client):
    from tests.fixtures import sample_raw

    binary_id = _upload(client, data=sample_raw(), filename="blob.bin").json()[
        "binary_id"
    ]
    response = client.get(f"/api/v1/binaries/{binary_id}/strategy")
    assert response.status_code == 400
