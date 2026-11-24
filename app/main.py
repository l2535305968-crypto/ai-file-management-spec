"""FastAPI service for AI File Management Specification & Security Boundaries."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.security import (
    ReferenceConflictError,
    RollbackError,
    SecurityBoundaryError,
    plan_relocate_file,
    safe_archive_file,
    safe_relocate_file,
    scan_workspace_security,
    validate_path_compliance,
)

BASE_DIR = Path(__file__).resolve().parent.parent
SPEC_PATH = BASE_DIR / "AI文件管理规范.md"


def get_workspace_root() -> Path:
    """Return configured workspace root (defaults to repository root)."""
    env_root = os.getenv("AI_FM_WORKSPACE_ROOT")
    return Path(env_root).resolve() if env_root else BASE_DIR


def verify_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Optional API key guard: enforced whenever AI_FM_API_KEY is configured."""
    expected = os.getenv("AI_FM_API_KEY")
    if expected and x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )


def _extract_short_prompt(markdown_text: str) -> str:
    """Extract Section 6 code block from AI文件管理规范.md."""
    section_match = re.search(
        r"## 六、可直接交给 AI 的短指令\s+```(?:text)?\s*(.*?)\s*```",
        markdown_text,
        re.DOTALL,
    )
    if section_match:
        return section_match.group(1).strip()
    return ""


app = FastAPI(
    title="AI File Management Spec API",
    version="2.2.0",
    description="HTTP API for serving AI文件管理规范.md, enforcing path/naming security boundaries, same-name relocation with reference checks, safe archiving with rollback, and pre-Git security scanning.",
)


class ValidatePathRequest(BaseModel):
    relative_path: str = Field(..., description="Target path relative to workspace root.")
    is_formal_deliverable: bool = Field(
        default=True,
        description="Whether the path represents a formal deliverable subject to naming redlines.",
    )


class ArchiveRequest(BaseModel):
    relative_path: str = Field(..., description="File path relative to workspace root to archive.")
    reason: str = Field(..., min_length=1, max_length=300, description="Why this version is being archived.")
    purpose: str = Field(default="general", max_length=100, description="Purpose category of the file.")
    move: bool = Field(
        default=False,
        description="If false (default), copies into _archive/. If true, moves into _archive/ without deleting.",
    )


class RelocatePreviewRequest(BaseModel):
    source_path: str = Field(..., description="Source file path relative to workspace root.")
    target_dir: str = Field(..., description="Existing destination directory relative to workspace root.")


class RelocateRequest(BaseModel):
    source_path: str = Field(..., description="Source file path relative to workspace root.")
    target_dir: str = Field(..., description="Existing destination directory relative to workspace root.")
    reason: str = Field(..., min_length=1, max_length=300, description="Why this file is being relocated.")
    allow_with_references: bool = Field(
        default=False,
        description="Must be true to relocate a file that still has detected workspace references.",
    )


class SecurityScanRequest(BaseModel):
    target_subpath: str = Field(default=".", description="Subpath relative to workspace root to scan.")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "2.2.0"}


@app.get("/api/v1/spec", dependencies=[Depends(verify_api_key)])
def get_spec() -> dict[str, Any]:
    if not SPEC_PATH.exists():
        raise HTTPException(status_code=404, detail="Specification file not found.")
    content = SPEC_PATH.read_text(encoding="utf-8")
    return {
        "title": "AI 文件管理规范",
        "version": "2.2",
        "filename": SPEC_PATH.name,
        "content": content,
    }


@app.get("/api/v1/prompt", dependencies=[Depends(verify_api_key)])
def get_short_prompt() -> dict[str, str]:
    if not SPEC_PATH.exists():
        raise HTTPException(status_code=404, detail="Specification file not found.")
    content = SPEC_PATH.read_text(encoding="utf-8")
    prompt = _extract_short_prompt(content)
    return {"version": "2.2", "prompt": prompt}


@app.post("/api/v1/validate/path", dependencies=[Depends(verify_api_key)])
def validate_path(req: ValidatePathRequest) -> dict[str, Any]:
    result = validate_path_compliance(
        workspace_root=get_workspace_root(),
        relative_path=req.relative_path,
        is_formal_deliverable=req.is_formal_deliverable,
    )
    return {
        "valid": result.valid,
        "normalized_path": result.normalized_path,
        "errors": result.errors,
        "warnings": result.warnings,
    }


@app.post("/api/v1/archive", dependencies=[Depends(verify_api_key)])
def archive_file(req: ArchiveRequest) -> dict[str, Any]:
    try:
        record = safe_archive_file(
            workspace_root=get_workspace_root(),
            relative_path=req.relative_path,
            reason=req.reason,
            purpose=req.purpose,
            move=req.move,
        )
        return {"archived": True, "record": record}
    except SecurityBoundaryError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RollbackError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@app.post("/api/v1/relocate/preview", dependencies=[Depends(verify_api_key)])
def preview_relocate(req: RelocatePreviewRequest) -> dict[str, Any]:
    try:
        return plan_relocate_file(
            workspace_root=get_workspace_root(),
            source_path=req.source_path,
            target_dir=req.target_dir,
        )
    except SecurityBoundaryError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@app.post("/api/v1/relocate", dependencies=[Depends(verify_api_key)])
def relocate_file(req: RelocateRequest) -> dict[str, Any]:
    try:
        record = safe_relocate_file(
            workspace_root=get_workspace_root(),
            source_path=req.source_path,
            target_dir=req.target_dir,
            reason=req.reason,
            allow_with_references=req.allow_with_references,
        )
        return {"relocated": True, "record": record}
    except SecurityBoundaryError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ReferenceConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"message": str(exc), "references": exc.references},
        ) from exc
    except RollbackError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@app.post("/api/v1/security/scan", dependencies=[Depends(verify_api_key)])
def security_scan(req: SecurityScanRequest) -> dict[str, Any]:
    try:
        return scan_workspace_security(
            workspace_root=get_workspace_root(),
            target_subpath=req.target_subpath,
        )
    except SecurityBoundaryError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
