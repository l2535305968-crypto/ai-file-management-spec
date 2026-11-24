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


class ReferenceConflictError(RuntimeError):
    """Raised when relocating a file that still has active references."""

    def __init__(self, message: str, references: list[dict[str, Any]]) -> None:
        super().__init__(message)
        self.references = references


class RollbackError(RuntimeError):
    """Raised when a move/archive operation fails after moving and triggers rollback."""


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
    moved = False
    try:
        if move:
            shutil.move(str(src), str(dest))
            moved = True
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
    except Exception as exc:
        if moved and dest.exists() and not src.exists():
            try:
                src.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(dest), str(src))
            except Exception as rollback_exc:
                raise RollbackError(
                    f"Archive failed ({exc}) and rollback from '{dest.relative_to(root_resolved).as_posix()}' "
                    f"to '{rel.as_posix()}' also failed ({rollback_exc})."
                ) from exc
            raise RollbackError(
                f"Archive failed ({exc}); rolled back file to original path '{rel.as_posix()}'."
            ) from exc
        if not move and dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass
        raise

    return record


# Directory/filename hints for classifying file roles
_PROCESS_DIR_HINTS = {"_tmp", "tmp", "temp", "cache", "logs", "log", "build", "drafts", "scratch", "过程", "临时", "草稿"}
_ASSET_DIR_HINTS = {"assets", "asset", "media", "images", "img", "audio", "video", "fonts", "materials", "素材", "资源"}
_SOURCE_DIR_HINTS = {"src", "app", "lib", "scripts", "templates", "source", "sources", "tests", "工程", "源文件", "脚本"}
_DELIVERABLE_DIR_HINTS = {"output", "outputs", "dist", "deliverables", "release", "releases", "exports", "成品", "交付", "成片"}
_ARCHIVE_DIR_HINTS = {"_archive", "archive", "old", "旧版", "归档"}
_DOC_FILENAMES = {"00_项目说明.md", "readme.md", "agents.md", "claude.md", "gemini.md", "changelog.md"}

_PROCESS_EXTS = {".tmp", ".bak", ".log", ".cache", ".part", ".swp"}
_ASSET_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".mp3", ".wav", ".aac", ".flac", ".ttf", ".otf", ".psd", ".ai"}
_SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".sh", ".ps1", ".bat", ".sql", ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".toml", ".prproj", ".aep", ".blend", ".fig"}
_DELIVERABLE_EXTS = {".pptx", ".docx", ".xlsx", ".pdf", ".mp4", ".mov", ".mkv", ".zip"}


def classify_file_role(workspace_root: Path, relative_path: str) -> dict[str, Any]:
    """Classify a file's role (deliverable, source, asset, process, archive, doc) and suggest an existing target dir."""
    root_resolved = workspace_root.resolve()
    src = resolve_safe_path(root_resolved, relative_path)
    rel = src.relative_to(root_resolved)
    parts_lower = [p.lower() for p in rel.parts[:-1]]
    name_lower = rel.name.lower()
    ext_lower = rel.suffix.lower()

    signals: list[str] = []
    role = "deliverable"
    confidence = "low"

    if any(p in _ARCHIVE_DIR_HINTS for p in parts_lower):
        role = "archive"
        confidence = "high"
        signals.append("Located under an archive directory.")
    elif name_lower in _DOC_FILENAMES:
        role = "doc"
        confidence = "high"
        signals.append(f"Matched project entry/instruction filename '{rel.name}'.")
    elif any(p in _PROCESS_DIR_HINTS for p in parts_lower) or ext_lower in _PROCESS_EXTS:
        role = "process"
        confidence = "high"
        if any(p in _PROCESS_DIR_HINTS for p in parts_lower):
            signals.append("Located under a temporary/process directory.")
        if ext_lower in _PROCESS_EXTS:
            signals.append(f"Matched temporary/process extension '{ext_lower}'.")
    elif any(p in _DELIVERABLE_DIR_HINTS for p in parts_lower):
        role = "deliverable"
        confidence = "high"
        signals.append("Located under a deliverable/output directory.")
    elif any(p in _ASSET_DIR_HINTS for p in parts_lower):
        role = "asset"
        confidence = "high"
        signals.append("Located under an asset/media directory.")
    elif any(p in _SOURCE_DIR_HINTS for p in parts_lower):
        role = "source"
        confidence = "high"
        signals.append("Located under a source/script directory.")
    elif ext_lower in _DELIVERABLE_EXTS:
        role = "deliverable"
        confidence = "medium"
        signals.append(f"Matched formal deliverable extension '{ext_lower}'.")
    elif ext_lower in _ASSET_EXTS:
        role = "asset"
        confidence = "medium"
        signals.append(f"Matched media/asset extension '{ext_lower}'.")
    elif ext_lower in _SOURCE_EXTS:
        role = "source"
        confidence = "medium"
        signals.append(f"Matched source/script/project extension '{ext_lower}'.")
    else:
        role = "deliverable"
        confidence = "low"
        signals.append("Defaulted to deliverable; review purpose before relocating.")

    # Discover existing top-level/nested directories matching the role
    role_hints_map = {
        "process": _PROCESS_DIR_HINTS,
        "asset": _ASSET_DIR_HINTS,
        "source": _SOURCE_DIR_HINTS,
        "deliverable": _DELIVERABLE_DIR_HINTS,
        "archive": _ARCHIVE_DIR_HINTS,
        "doc": {"docs", "doc", "文档"},
    }
    target_hints = role_hints_map.get(role, set())
    suggested_existing_dirs: list[str] = []
    for entry in sorted(root_resolved.iterdir(), key=lambda p: p.name.lower()):
        if entry.is_dir() and entry.name not in SCAN_SKIP_DIRS:
            if entry.name.lower() in target_hints:
                suggested_existing_dirs.append(entry.relative_to(root_resolved).as_posix())

    return {
        "role": role,
        "confidence": confidence,
        "signals": signals,
        "suggested_existing_dirs": suggested_existing_dirs,
    }


def find_file_references(
    workspace_root: Path,
    relative_path: str,
    max_file_bytes: int = 512 * 1024,
) -> list[dict[str, Any]]:
    """Scan workspace text files for references to the given file's relative path or filename."""
    root_resolved = workspace_root.resolve()
    src = resolve_safe_path(root_resolved, relative_path)
    rel = src.relative_to(root_resolved)
    rel_posix = rel.as_posix()
    rel_win = rel_posix.replace("/", "\\")
    filename = rel.name

    references: list[dict[str, Any]] = []
    skip_dirs = SCAN_SKIP_DIRS | {"_archive"}

    for dirpath, dirnames, filenames in os.walk(root_resolved):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            candidate = Path(dirpath) / name
            if candidate.resolve() == src:
                continue
            try:
                if candidate.stat().st_size > max_file_bytes:
                    continue
                content = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            cand_rel = candidate.resolve().relative_to(root_resolved).as_posix()
            for line_no, line in enumerate(content.splitlines(), start=1):
                if rel_posix in line or (rel_win != rel_posix and rel_win in line):
                    references.append({
                        "file": cand_rel,
                        "line": line_no,
                        "match_type": "relative_path",
                        "snippet": line.strip()[:160],
                    })
                elif filename in line:
                    references.append({
                        "file": cand_rel,
                        "line": line_no,
                        "match_type": "filename",
                        "snippet": line.strip()[:160],
                    })

    return references


def plan_relocate_file(
    workspace_root: Path,
    source_path: str,
    target_dir: str,
) -> dict[str, Any]:
    """Preview relocating a file into an existing directory while preserving its original filename and content.

    Performs role classification, reference scanning, destination existence/conflict checks,
    and returns an 'original_path -> new_path' plan without modifying any files.
    """
    root_resolved = workspace_root.resolve()
    errors: list[str] = []
    warnings: list[str] = []

    src = resolve_safe_path(root_resolved, source_path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Source file not found: '{source_path}'.")

    rel_src = src.relative_to(root_resolved)
    if rel_src.parts and rel_src.parts[0] == "_archive":
        raise SecurityBoundaryError("Cannot relocate a file from '_archive/' via standard relocate.")

    if target_dir in {"", "."}:
        dest_dir = root_resolved
    else:
        dest_dir = resolve_safe_path(root_resolved, target_dir)

    target_dir_exists = dest_dir.exists() and dest_dir.is_dir()
    if not target_dir_exists:
        errors.append(
            f"Target directory does not exist: '{target_dir}'. "
            "Relocation only moves files into an existing directory."
        )

    dest = (dest_dir / src.name).resolve()
    try:
        dest.relative_to(root_resolved)
    except ValueError as exc:
        raise SecurityBoundaryError("Resolved destination escapes workspace root.") from exc

    rel_dest = dest.relative_to(root_resolved)
    if rel_dest.parts and rel_dest.parts[0] == "_archive":
        errors.append("Use /api/v1/archive for '_archive/' instead of same-name relocate.")

    same_location = src == dest
    conflict = False
    if same_location:
        errors.append("Source file is already in the target directory.")
    elif dest.exists():
        conflict = True
        errors.append(
            f"Destination already exists: '{rel_dest.as_posix()}'. "
            "Refusing to overwrite; resolve conflict or archive the existing file first."
        )

    role_info = classify_file_role(root_resolved, rel_src.as_posix())
    references = find_file_references(root_resolved, rel_src.as_posix())
    if references:
        warnings.append(
            f"Found {len(references)} reference(s) to '{rel_src.as_posix()}' across the workspace; "
            "update those references after relocating or confirm before moving."
        )

    return {
        "can_execute": len(errors) == 0,
        "original_path": rel_src.as_posix(),
        "new_path": rel_dest.as_posix(),
        "preview": f"{rel_src.as_posix()} -> {rel_dest.as_posix()}",
        "filename_preserved": True,
        "target_dir_exists": target_dir_exists,
        "conflict": conflict,
        "role": role_info["role"],
        "role_confidence": role_info["confidence"],
        "role_signals": role_info["signals"],
        "suggested_existing_dirs": role_info["suggested_existing_dirs"],
        "reference_count": len(references),
        "references": references,
        "warnings": warnings,
        "errors": errors,
    }


def safe_relocate_file(
    workspace_root: Path,
    source_path: str,
    target_dir: str,
    reason: str,
    allow_with_references: bool = False,
) -> dict[str, Any]:
    """Relocate a file into an existing directory, preserving its exact filename and content.

    Checks references, verifies SHA-256 integrity after moving, writes `_archive/relocate_index.jsonl`,
    and automatically rolls the file back to its original path if verification or index logging fails.
    """
    root_resolved = workspace_root.resolve()
    plan = plan_relocate_file(root_resolved, source_path, target_dir)

    if plan["conflict"]:
        raise FileExistsError(f"Destination already exists: '{plan['new_path']}'.")
    if not plan["can_execute"]:
        raise SecurityBoundaryError("; ".join(plan["errors"]))
    if plan["reference_count"] > 0 and not allow_with_references:
        raise ReferenceConflictError(
            f"Blocked relocate: found {plan['reference_count']} active reference(s) to '{plan['original_path']}'. "
            "Review references via /api/v1/relocate/preview or set allow_with_references=true after confirming.",
            references=plan["references"],
        )

    src = resolve_safe_path(root_resolved, plan["original_path"])
    dest = resolve_safe_path(root_resolved, plan["new_path"])
    sha256_before = compute_sha256(src)

    moved = False
    try:
        shutil.move(str(src), str(dest))
        moved = True

        sha256_after = compute_sha256(dest)
        if sha256_before != sha256_after:
            raise RuntimeError("Relocate integrity check failed: SHA-256 mismatch.")

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "original_path": plan["original_path"],
            "new_path": plan["new_path"],
            "filename_preserved": True,
            "role": plan["role"],
            "reason": reason,
            "reference_count": plan["reference_count"],
            "sha256": sha256_after,
        }

        archive_root = root_resolved / "_archive"
        archive_root.mkdir(parents=True, exist_ok=True)
        index_file = archive_root / "relocate_index.jsonl"
        with index_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        if moved and dest.exists() and not src.exists():
            try:
                src.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(dest), str(src))
            except Exception as rollback_exc:
                raise RollbackError(
                    f"Relocate failed ({exc}) and rollback from '{plan['new_path']}' "
                    f"to '{plan['original_path']}' also failed ({rollback_exc})."
                ) from exc
            raise RollbackError(
                f"Relocate failed ({exc}); rolled back file to original path '{plan['original_path']}'."
            ) from exc
        raise

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
