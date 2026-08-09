from __future__ import annotations

from pwnable_lab.payload.cyclic import cyclic


def _log_bytes() -> bytes:
    value = int.from_bytes(cyclic(160)[64:72], "little")
    return f"""(gdb) run
Program received signal SIGSEGV, Segmentation fault.
rsp 0x7fffffffe000
rip {value:#x}
=> 0x4011a2 <vuln+44>: ret
0x7fffffffe000: {value:#x} 0x40123a
0x00400000 0x00402000 0x2000 0x0 r-xp /tmp/target
0x7ffffffde000 0x7ffffffff000 0x21000 0x0 rw-p [stack]
""".encode()


def test_crash_log_lifecycle_and_subresources(client) -> None:
    uploaded = client.post(
        "/api/v1/crashes", files={"file": ("session.log", _log_bytes(), "text/plain")}
    )
    assert uploaded.status_code == 201
    body = uploaded.json()
    crash_id = body["crash_id"]
    assert body["filename"] == "session.log"
    assert body["analysis_status"] == "completed"
    assert body["result"]["probable_overflow_pattern"]["offset"] == 64

    listing = client.get("/api/v1/crashes")
    assert listing.status_code == 200
    assert listing.json()[0]["crash_id"] == crash_id
    assert listing.json()[0]["signal"] == "SIGSEGV"

    detail = client.get(f"/api/v1/crashes/{crash_id}")
    assert detail.status_code == 200
    assert detail.json()["result"]["instruction_pointer"]["register"] == "rip"

    registers = client.get(f"/api/v1/crashes/{crash_id}/registers").json()
    assert registers["total"] == 2
    assert {item["name"] for item in registers["items"]} == {"rip", "rsp"}

    stack = client.get(f"/api/v1/crashes/{crash_id}/stack?limit=1").json()
    assert stack["total"] == 2
    assert len(stack["items"]) == 1

    mappings = client.get(f"/api/v1/crashes/{crash_id}/mappings").json()
    assert mappings["total"] == 2

    rerun = client.post(f"/api/v1/crashes/{crash_id}/analyze")
    assert rerun.status_code == 200
    assert rerun.json()["analyzer_version"] == "1.0.0"

    deleted = client.delete(f"/api/v1/crashes/{crash_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/crashes/{crash_id}").status_code == 404


def test_crash_log_filename_is_sanitized(client) -> None:
    response = client.post(
        "/api/v1/crashes",
        files={"file": ("../../escape.log", b"rip 0x401000\n", "text/plain")},
    )
    assert response.status_code == 201
    assert response.json()["filename"] == "escape.log"


def test_crash_log_rejects_binary_archive_and_empty_input(client) -> None:
    binary = client.post(
        "/api/v1/crashes",
        files={
            "file": ("core", b"\x7fELF\x00\x00\x00\x00", "application/octet-stream")
        },
    )
    assert binary.status_code == 415
    assert "UTF-8" in binary.json()["detail"]

    archive = client.post(
        "/api/v1/crashes",
        files={"file": ("logs.zip", b"PK\x03\x04payload", "application/zip")},
    )
    assert archive.status_code == 415

    empty = client.post(
        "/api/v1/crashes", files={"file": ("empty.log", b"", "text/plain")}
    )
    assert empty.status_code == 422

    ansi_only = client.post(
        "/api/v1/crashes",
        files={
            "file": ("terminal.log", b"\x1b[31m\x1b[0m", "text/plain"),
        },
    )
    assert ansi_only.status_code == 422


def test_crash_log_rejects_unknown_binary_association(client) -> None:
    response = client.post(
        "/api/v1/crashes",
        data={"binary_id": "f" * 64},
        files={"file": ("session.log", _log_bytes(), "text/plain")},
    )
    assert response.status_code == 404


def test_deleting_binary_detaches_persisted_crash_log(client) -> None:
    fixture = client.get("/api/v1/challenges/ret2win/artifact")
    binary = client.post(
        "/api/v1/binaries",
        files={"file": ("target.elf", fixture.content, "application/octet-stream")},
    ).json()
    crash = client.post(
        "/api/v1/crashes",
        data={"binary_id": binary["binary_id"]},
        files={"file": ("session.log", _log_bytes(), "text/plain")},
    ).json()
    assert crash["binary_id"] == binary["binary_id"]

    assert client.delete(f"/api/v1/binaries/{binary['binary_id']}").status_code == 204
    detached = client.get(f"/api/v1/crashes/{crash['crash_id']}").json()
    assert detached["binary_id"] is None
