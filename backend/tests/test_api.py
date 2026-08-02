"""FastAPI 업로드·분석 엔드포인트 계약 테스트."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pwnable_lab.api import dependencies
from pwnable_lab.api.app import create_app
from pwnable_lab.config import get_settings
from tests.fixtures import sample_elf


def _upload(client, data=None, filename="sample.elf"):
    return client.post(
        "/api/binaries",
        files={"file": (filename, data or sample_elf(), "application/octet-stream")},
    )


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "1.0.0"}


def test_versioned_health_is_primary_contract(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_upload_list_and_deduplicate(client):
    first = _upload(client, filename="../../unsafe.elf")
    assert first.status_code == 200
    assert first.json()["filename"] == "unsafe.elf"
    assert len(first.json()["sha256"]) == 64

    second = _upload(client, filename="renamed.elf")
    assert second.status_code == 200
    assert second.json()["sha256"] == first.json()["sha256"]
    listed = client.get("/api/binaries")
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_phase1_binary_lifecycle_and_analysis_status(client):
    uploaded = client.post(
        "/api/v1/binaries",
        files={
            "file": (
                "..\\..\\unsafe\x01.elf",
                sample_elf(),
                "application/octet-stream",
            )
        },
    )
    assert uploaded.status_code == 200
    body = uploaded.json()
    assert body["binary_id"] == body["sha256"]
    assert body["filename"] == "unsafe.elf"
    assert body["analysis_status"] == "not_started"

    binary_id = body["binary_id"]
    detail = client.get(f"/api/v1/binaries/{binary_id}")
    assert detail.status_code == 200
    assert detail.json()["analysis_status"] == "not_started"

    no_job = client.get(f"/api/v1/binaries/{binary_id}/analysis")
    assert no_job.status_code == 404

    started = client.post(f"/api/v1/binaries/{binary_id}/analyze")
    assert started.status_code == 202
    assert started.json()["status"] == "completed"
    assert started.json()["result"]["verification"] == "verified"
    assert started.json()["result"]["elf"]["sha256"] == binary_id

    latest = client.get(f"/api/v1/binaries/{binary_id}/analysis")
    assert latest.status_code == 200
    assert latest.json()["job_id"] == started.json()["job_id"]

    refreshed = client.get(f"/api/v1/binaries/{binary_id}")
    assert refreshed.json()["analysis_status"] == "completed"

    deleted = client.delete(f"/api/v1/binaries/{binary_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/binaries/{binary_id}").status_code == 404


def test_upload_rejects_non_elf(client):
    response = _upload(client, b"this is not an ELF", "note.txt")
    assert response.status_code == 415
    assert response.json()["error"] == "UnsupportedFormatError"


def test_upload_enforces_streaming_size_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("PLAB_STORAGE_DIR", str(tmp_path / "small-storage"))
    monkeypatch.setenv("PLAB_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("PLAB_MAX_UPLOAD_BYTES", "32")
    get_settings.cache_clear()
    dependencies._repo_for.cache_clear()
    try:
        with TestClient(create_app()) as small_client:
            response = _upload(small_client, b"\x7fELF" + b"A" * 64)
        assert response.status_code == 413
        assert response.json()["error"] == "PayloadTooLargeError"
    finally:
        get_settings.cache_clear()
        dependencies._repo_for.cache_clear()


def test_binary_info_and_checksec(client):
    sha = _upload(client).json()["sha256"]
    info = client.get(f"/api/binaries/{sha}/info")
    assert info.status_code == 200
    assert info.json()["machine"] == "EM_X86_64"
    assert info.json()["type"] == "ET_EXEC"
    assert any(item["name"] == ".text" for item in info.json()["sections"])

    security = client.get(f"/api/binaries/{sha}/checksec")
    assert security.status_code == 200
    assert security.json()["nx"] is True
    assert security.json()["pie"] == "No PIE"


def test_all_binary_analysis_endpoints(client):
    sha = _upload(client).json()["sha256"]
    endpoints = [
        "vulns",
        "gadgets",
        "got",
        "strings",
        "disassembly?count=8",
        "hex?page=0",
    ]
    responses = {
        endpoint: client.get(f"/api/binaries/{sha}/{endpoint}")
        for endpoint in endpoints
    }
    assert all(response.status_code == 200 for response in responses.values())
    assert any(item["symbol"] == "gets" for item in responses["vulns"].json())
    assert any(
        "pop rdi" in item["text"] for item in responses["gadgets"].json()["items"]
    )
    assert responses["disassembly?count=8"].json()
    assert responses["hex?page=0"].json()["rows"]


def test_gadget_query_filters(client):
    sha = _upload(client).json()["sha256"]
    response = client.get(
        f"/api/binaries/{sha}/gadgets", params={"q": "pop rdi ; ret"}
    ).json()
    items = response["items"]
    assert items
    assert all("pop rdi ; ret" in item["text"] for item in items)
    assert response["quality_verification"] == "inferred"


def test_invalid_or_missing_binary_is_404(client):
    malformed = client.get("/api/binaries/not-a-hash/info")
    assert malformed.status_code == 404
    missing = client.get(f"/api/binaries/{'a' * 64}/info")
    assert missing.status_code == 404


def test_disassembly_validates_count_and_address(client):
    sha = _upload(client).json()["sha256"]
    invalid_count = client.get(f"/api/binaries/{sha}/disassembly?count=0")
    assert invalid_count.status_code == 422
    outside = client.get(f"/api/binaries/{sha}/disassembly", params={"address": 1})
    assert outside.status_code == 400


def test_hex_page_beyond_end_is_empty(client):
    sha = _upload(client).json()["sha256"]
    response = client.get(f"/api/binaries/{sha}/hex?page=9999")
    assert response.status_code == 200
    assert response.json()["rows"] == []
