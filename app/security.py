"""Security boundary checks, compliance validation, safe archiving, and sensitive-data scanning."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Forbidden ambiguous suffixes for formal deliverables (per AI文件管理规范.md 2.1)
AMBIGUOUS_SUFFIX_PATTERNS = [
    re.compile(r"(?:^|[_\-\s])(final|new|fixed|latest|copy|backup)(?:$|[_\-\s\d])", re.IGNORECASE),
    re.compile(r"(最终版|终版|最新版|定稿|修改版|副本|新建)", re.IGNORECASE),
    re.compile(r"[_\-\s]v\d+(?:$|[_\-\s])", re.IGNORECASE),
]

# Full-width brackets or unsafe shell/CLI characters
UNSAFE_CHAR_PATTERN = re.compile(r"[（）()<>:\"|?*\x00-\x1f]")

# Windows reserved device names
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# Sensitive information / secret / local-path patterns for pre-Git & security scanning
SENSITIVE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("api_key_openai", "high", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("api_key_github", "high", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("aws_access_key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_secret_assign", "high", re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("windows_abs_path", "medium", re.compile(r"\b[A-Za-z]:\\[^\s\"'`<>|]+")),
    ("unix_home_path", "medium", re.compile(r"(?:/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/)")),
    ("email_address", "low", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("cn_phone_number", "medium", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
]

SCAN_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}


class SecurityBoundaryError(ValueError):
    """Raised when an operation violates a workspace or security boundary."""


def resolve_safe_path(workspace_root: Path, relative_path: str) -> Path:
    """Resolve a user-supplied path strictly within workspace_root.

    Blocks null bytes, absolute paths, path traversal (`..`), and symlink escapes.
    """
    if not relative_path or not relative_path.strip():
        raise SecurityBoundaryError("Path cannot be empty.")
    if "\x00" in relative_path:
        raise SecurityBoundaryError("Null byte detected in path.")

    raw = Path(relative_path)
    if raw.is_absolute() or relative_path.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", relative_path):
        raise SecurityBoundaryError("Absolute paths are not allowed; provide a path relative to workspace root.")

    root_resolved = workspace_root.resolve()
    candidate = (root_resolved / raw).resolve()

    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise SecurityBoundaryError(f"Path traversal blocked: '{relative_path}' escapes workspace root.") from exc

    # Also verify no intermediate component is a symlink pointing outside workspace_root
    current = root_resolved
    for part in raw.parts:
        current = current / part
        if current.is_symlink():
            target = current.resolve()
            try:
                target.relative_to(root_resolved)
            except ValueError as exc:
                raise SecurityBoundaryError(f"Symlink escape blocked at '{current.name}'.") from exc

    return candidate


@dataclass
class PathValidationResult:
    valid: bool
    normalized_path: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_path_compliance(
    workspace_root: Path,
    relative_path: str,
    is_formal_deliverable: bool = True,
) -> PathValidationResult:
    """Validate a path against security boundaries and AI文件管理规范.md naming rules."""
    errors: list[str] = []
    warnings: list[str] = []

    try:
        resolved = resolve_safe_path(workspace_root, relative_path)
    except SecurityBoundaryError as exc:
        return PathValidationResult(valid=False, errors=[str(exc)])

    rel = resolved.relative_to(workspace_root.resolve())
    norm = rel.as_posix()

    # Check Windows reserved names on each path segment
    for part in rel.parts:
        stem = Path(part).stem.upper()
        if stem in WINDOWS_RESERVED_NAMES:
            errors.append(f"Reserved Windows filename segment is forbidden: '{part}'.")
        if UNSAFE_CHAR_PATTERN.search(part):
            errors.append(f"Unsafe or full-width bracket characters found in '{part}'; use ASCII-safe naming.")

    # Formal deliverable naming redline: forbid ambiguous suffixes like _final, _最终版, _v2
    if is_formal_deliverable and not any(p in {"_archive", "_tmp"} for p in rel.parts):
        stem = rel.stem
        for pattern in AMBIGUOUS_SUFFIX_PATTERNS:
            match = pattern.search(stem)
            if match:
                errors.append(
                    f"Ambiguous version/status suffix '{match.group(0).strip()}' is forbidden on formal deliverables. "
                    "Update the canonical file in place and archive old versions under '_archive/'."
                )
                break

    if any(p == "旧（old）" for p in rel.parts):
        warnings.append("Legacy archive folder '旧（old）' contains full-width brackets; prefer '_archive/'.")

    return PathValidationResult(
        valid=len(errors) == 0,
        normalized_path=norm,
        errors=errors,
        warnings=warnings,
    )


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_archive_file(
    workspace_root: Path,
    relative_path: str,
    reason: str,
    purpose: str = "general",
    move: bool = False,
) -> dict[str, Any]:
    """Archive a formal file into `_archive/` with version numbering, SHA-256, and index log.

    Never performs destructive physical deletion; by default copies (or safely moves into `_archive/`).
    """
    src = resolve_safe_path(workspace_root, relative_path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Source file not found: '{relative_path}'.")

    root_resolved = workspace_root.resolve()
    rel = src.relative_to(root_resolved)
    if rel.parts and rel.parts[0] == "_archive":
        raise SecurityBoundaryError("Cannot re-archive a file already inside '_archive/'.")

    archive_root = root_resolved / "_archive"
    archive_dir = archive_root / rel.parent
    archive_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    stem = src.stem
    suffix = src.suffix

    # Find next sequential version number v01, v02, ...
    existing_versions = list(archive_dir.glob(f"{stem}_v*_{today}{suffix}"))
    next_ver = len(existing_versions) + 1
    archive_name = f"{stem}_v{next_ver:02d}_{today}{suffix}"
    dest = archive_dir / archive_name

    sha256_before = compute_sha256(src)
    if move:
        shutil.move(str(src), str(dest))
    else:
        shutil.copy2(str(src), str(dest))

    sha256_after = compute_sha256(dest)
    if sha256_before != sha256_after:
        raise RuntimeError("Archive integrity check failed: SHA-256 mismatch.")

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "purpose": purpose,
        "original_path": rel.as_posix(),
        "archive_path": dest.relative_to(root_resolved).as_posix(),
        "version": f"v{next_ver:02d}",
        "successor_path": rel.as_posix(),
        "reason": reason,
        "mode": "move" if move else "copy",
        "sha256": sha256_after,
    }

    index_file = archive_root / "archive_index.jsonl"
    with index_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def scan_workspace_security(
    workspace_root: Path,
    target_subpath: str = ".",
    max_file_bytes: int = 512 * 1024,
) -> dict[str, Any]:
    """Scan text files in workspace for secrets, hardcoded local paths, and PII."""
    root_resolved = workspace_root.resolve()
    if target_subpath in {"", "."}:
        target = root_resolved
    else:
        target = resolve_safe_path(root_resolved, target_subpath)

    findings: list[dict[str, Any]] = []
    scanned_files = 0

    files_to_scan: list[Path] = []
    if target.is_file():
        files_to_scan = [target]
    elif target.is_dir():
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP_DIRS]
            for name in filenames:
                files_to_scan.append(Path(dirpath) / name)

    for file_path in files_to_scan:
        try:
            if file_path.stat().st_size > max_file_bytes:
                continue
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        scanned_files += 1
        rel_str = file_path.resolve().relative_to(root_resolved).as_posix()

        for line_no, line in enumerate(content.splitlines(), start=1):
            for rule_name, severity, pattern in SENSITIVE_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "file": rel_str,
                        "line": line_no,
                        "rule": rule_name,
                        "severity": severity,
                        "snippet": line.strip()[:120],
                    })

    high_or_critical = [f for f in findings if f["severity"] in {"high", "critical"}]
    return {
        "scanned_files": scanned_files,
        "total_findings": len(findings),
        "blocking_findings": len(high_or_critical),
        "passed": len(high_or_critical) == 0,
        "findings": findings,
    }
