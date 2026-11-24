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
