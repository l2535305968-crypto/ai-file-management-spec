"""Automated tests for API endpoints and security boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AI_FM_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.delenv("AI_FM_API_KEY", raising=False)
    return TestClient(app)


def test_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_get_spec_and_prompt(client: TestClient) -> None:
    spec_resp = client.get("/api/v1/spec")
    assert spec_resp.status_code == 200
    assert "AI 文件管理规范" in spec_resp.json()["content"]

    prompt_resp = client.get("/api/v1/prompt")
    assert prompt_resp.status_code == 200
    prompt_text = prompt_resp.json()["prompt"]
    assert "先查后写" in prompt_text
    assert "当前成品" in prompt_text


def test_validate_path_accepts_clean_deliverable(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/validate/path",
        json={"relative_path": "reports/环境工程课程汇报.pptx", "is_formal_deliverable": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["errors"] == []


@pytest.mark.parametrize(
    "bad_path",
    [
        "../outside.txt",
        "../../Windows/System32/cmd.exe",
        "C:" + "\\Windows\\win.ini",
        "/etc/passwd",
        "reports/file\x00.txt",
    ],
)
def test_validate_path_blocks_traversal_and_absolute(client: TestClient, bad_path: str) -> None:
    resp = client.post("/api/v1/validate/path", json={"relative_path": bad_path})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert len(data["errors"]) >= 1


@pytest.mark.parametrize(
    "bad_name",
    [
        "docs/方案_final.pptx",
        "docs/方案_最终版.docx",
        "docs/方案_v2.xlsx",
        "旧（old）/report.md",
        "docs/CON.txt",
    ],
)
def test_validate_path_blocks_naming_redlines(client: TestClient, bad_name: str) -> None:
    resp = client.post(
        "/api/v1/validate/path",
        json={"relative_path": bad_name, "is_formal_deliverable": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert len(data["errors"]) >= 1


def test_safe_archive_preserves_integrity_and_logs_index(client: TestClient, tmp_path: Path) -> None:
    target = tmp_path / "docs" / "report.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# Report v1\ncontent", encoding="utf-8")

    resp = client.post(
        "/api/v1/archive",
        json={"relative_path": "docs/report.md", "reason": "Before updating section 2", "purpose": "report"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["archived"] is True
    record = data["record"]
    assert record["archive_path"].startswith("_archive/docs/report_v01_")
    assert (tmp_path / record["archive_path"]).exists()
    assert target.exists()  # default mode is copy, no destructive deletion

    index_path = tmp_path / "_archive" / "archive_index.jsonl"
    assert index_path.exists()
    logged = json.loads(index_path.read_text(encoding="utf-8").strip())
    assert logged["sha256"] == record["sha256"]


def test_archive_blocks_traversal(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/archive",
        json={"relative_path": "../secret.txt", "reason": "attempt escape"},
    )
    assert resp.status_code == 403


def test_security_scan_detects_secrets_and_paths(client: TestClient, tmp_path: Path) -> None:
    leaky = tmp_path / "leaky.txt"
    leaky.write_text(
        "tok" + "en = 'super_secret_" + "12345'\n"
        + "path = D:" + "\\private\\project\\file.xlsx\n",
        encoding="utf-8",
    )
    resp = client.post("/api/v1/security/scan", json={"target_subpath": "."})
    assert resp.status_code == 200
    data = resp.json()
    assert data["passed"] is False
    assert data["blocking_findings"] >= 1
    rules = {f["rule"] for f in data["findings"]}
    assert "generic_secret_assign" in rules
    assert "windows_abs_path" in rules


def test_api_key_enforcement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_FM_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("AI_FM_API_KEY", "test-secret-key")
    secured_client = TestClient(app)

    assert secured_client.get("/api/v1/prompt").status_code == 401
    assert secured_client.get("/api/v1/prompt", headers={"X-API-Key": "wrong"}).status_code == 401
    assert secured_client.get("/api/v1/prompt", headers={"X-API-Key": "test-secret-key"}).status_code == 200


def test_relocate_preview_classifies_role_and_detects_references(client: TestClient, tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    img = tmp_path / "cover.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\nfake-image")

    doc = tmp_path / "00_项目说明.md"
    doc.write_text("封面见 `cover.png`\n", encoding="utf-8")

    resp = client.post(
        "/api/v1/relocate/preview",
        json={"source_path": "cover.png", "target_dir": "assets"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["can_execute"] is True
    assert data["original_path"] == "cover.png"
    assert data["new_path"] == "assets/cover.png"
    assert data["preview"] == "cover.png -> assets/cover.png"
    assert data["filename_preserved"] is True
    assert data["role"] == "asset"
    assert "assets" in data["suggested_existing_dirs"]
    assert data["reference_count"] == 1
    assert data["references"][0]["file"] == "00_项目说明.md"
    # Preview must be read-only
    assert img.exists()
    assert not (tmp_path / "assets" / "cover.png").exists()


def test_relocate_preview_rejects_nonexistent_dir_and_conflict(client: TestClient, tmp_path: Path) -> None:
    src = tmp_path / "notes.log"
    src.write_text("debug log", encoding="utf-8")

    resp_missing = client.post(
        "/api/v1/relocate/preview",
        json={"source_path": "notes.log", "target_dir": "not_created_yet"},
    )
    assert resp_missing.status_code == 200
    assert resp_missing.json()["can_execute"] is False
    assert resp_missing.json()["target_dir_exists"] is False
    assert resp_missing.json()["role"] == "process"

    tmp_dir = tmp_path / "_tmp"
    tmp_dir.mkdir()
    (tmp_dir / "notes.log").write_text("existing", encoding="utf-8")

    resp_conflict = client.post(
        "/api/v1/relocate/preview",
        json={"source_path": "notes.log", "target_dir": "_tmp"},
    )
    assert resp_conflict.status_code == 200
    assert resp_conflict.json()["can_execute"] is False
    assert resp_conflict.json()["conflict"] is True


def test_relocate_preserves_filename_content_and_guards_references(client: TestClient, tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    src = tmp_path / "banner.png"
    original_bytes = b"\x89PNG\r\n\x1a\nexact-bytes-unchanged"
    src.write_bytes(original_bytes)
    (tmp_path / "README.md").write_text("![banner](banner.png)\n", encoding="utf-8")

    # Blocked by default when active references exist
    blocked = client.post(
        "/api/v1/relocate",
        json={"source_path": "banner.png", "target_dir": "assets", "reason": "Move asset into assets/"},
    )
    assert blocked.status_code == 409
    assert src.exists()

    # Succeeds once caller confirms allow_with_references=True
    ok = client.post(
        "/api/v1/relocate",
        json={
            "source_path": "banner.png",
            "target_dir": "assets",
            "reason": "Move asset into assets/ and will update README",
            "allow_with_references": True,
        },
    )
    assert ok.status_code == 200
    record = ok.json()["record"]
    assert record["original_path"] == "banner.png"
    assert record["new_path"] == "assets/banner.png"
    assert record["filename_preserved"] is True

    dest = tmp_path / "assets" / "banner.png"
    assert not src.exists()
    assert dest.exists()
    assert dest.read_bytes() == original_bytes

    index_path = tmp_path / "_archive" / "relocate_index.jsonl"
    assert index_path.exists()
    logged = json.loads(index_path.read_text(encoding="utf-8").strip())
    assert logged["sha256"] == record["sha256"]
    assert logged["new_path"] == "assets/banner.png"


def test_archive_move_rolls_back_on_hash_failure(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app import security

    src = tmp_path / "docs" / "spec.md"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("original content", encoding="utf-8")

    real_sha = security.compute_sha256
    calls = {"n": 0}

    def flaky_sha(path: Path) -> str:
        calls["n"] += 1
        if calls["n"] == 2:
            return "0" * 64  # simulate post-move hash mismatch
        return real_sha(path)

    monkeypatch.setattr(security, "compute_sha256", flaky_sha)

    resp = client.post(
        "/api/v1/archive",
        json={"relative_path": "docs/spec.md", "reason": "test rollback", "move": True},
    )
    assert resp.status_code == 500
    assert "rolled back" in resp.json()["detail"].lower()
    # Original file must be restored intact
    assert src.exists()
    assert src.read_text(encoding="utf-8") == "original content"


def test_relocate_rolls_back_on_index_write_failure(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "assets").mkdir()
    src = tmp_path / "clip.mp3"
    src.write_bytes(b"ID3-audio-payload")

    # Make `_archive` a regular file so writing `_archive/relocate_index.jsonl` fails
    (tmp_path / "_archive").write_text("blocker", encoding="utf-8")

    resp = client.post(
        "/api/v1/relocate",
        json={"source_path": "clip.mp3", "target_dir": "assets", "reason": "test index failure rollback"},
    )
    assert resp.status_code == 500
    assert "rolled back" in resp.json()["detail"].lower()
    assert src.exists()
    assert src.read_bytes() == b"ID3-audio-payload"
    assert not (tmp_path / "assets" / "clip.mp3").exists()
