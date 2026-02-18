"""Scanner — walk extension roots, match rules, collect findings."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from clawcare.models import ExtensionRoot, Finding
from clawcare.scanner.rules import ALL_RULES, Rule

# Default ignore directories (§8.1).
DEFAULT_EXCLUDE_DIRS: set[str] = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
}

# Default scannable extensions (§8.1).
DEFAULT_INCLUDE_EXTS: set[str] = {
    ".md", ".sh", ".bash", ".zsh", ".ps1",
    ".py", ".js", ".ts", ".yml", ".yaml", ".json", ".txt",
}


def _matches_any_glob(path: str, globs: list[str]) -> bool:
    """Return True if *path* matches any of the *globs*."""
    return any(fnmatch.fnmatch(path, g) for g in globs)


def _is_binary(file_path: Path, check_bytes: int = 512) -> bool:
    """Quick heuristic: file is binary if first *check_bytes* contain NULL."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(check_bytes)
        return b"\x00" in chunk
    except OSError:
        return True


def collect_files(
    root: ExtensionRoot,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    max_file_size_kb: int = 512,
    extra_excludes: list[str] | None = None,
) -> list[Path]:
    """Walk *root.root_path* and return scannable file paths."""
    root_dir = Path(root.root_path)
    if not root_dir.is_dir():
        return []

    # Merge exclude globs
    all_excludes = list(exclude_globs or [])
    if extra_excludes:
        all_excludes.extend(extra_excludes)

    collected: list[Path] = []
    max_bytes = max_file_size_kb * 1024

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Prune excluded directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in DEFAULT_EXCLUDE_DIRS
            and not _matches_any_glob(d, all_excludes)
        ]

        for fname in filenames:
            fpath = Path(dirpath) / fname

            # Extension filter
            if include_globs:
                rel = str(fpath.relative_to(root_dir))
                if not _matches_any_glob(rel, include_globs) and not _matches_any_glob(fname, include_globs):
                    continue
            else:
                if fpath.suffix.lower() not in DEFAULT_INCLUDE_EXTS:
                    continue

            # Size filter
            try:
                if fpath.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue

            # Binary filter
            if _is_binary(fpath):
                continue

            collected.append(fpath)

    collected.sort()
    return collected


def scan_file(file_path: Path, rules: list[Rule] | None = None) -> list[Finding]:
    """Scan a single file against all rules and return findings."""
    rules = rules or ALL_RULES
    findings: list[Finding] = []

    try:
        text = file_path.read_text(errors="replace")
    except OSError:
        return findings

    lines = text.splitlines()

    for rule in rules:
        for match in rule.pattern.finditer(text):
            # Calculate line number (1-indexed)
            line_start = text.count("\n", 0, match.start()) + 1
            # Build excerpt (the matching line)
            excerpt = lines[line_start - 1] if line_start <= len(lines) else match.group(0)

            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=str(file_path),
                    line=line_start,
                    excerpt=excerpt.strip(),
                    explanation=rule.explanation,
                    remediation=rule.remediation,
                )
            )

    return findings


def scan_root(
    root: ExtensionRoot,
    scope: dict,
    extra_excludes: list[str] | None = None,
    rules: list[Rule] | None = None,
) -> list[Finding]:
    """Scan all files in an extension root and return sorted findings."""
    files = collect_files(
        root,
        include_globs=scope.get("include_globs"),
        exclude_globs=scope.get("exclude_globs"),
        max_file_size_kb=scope.get("max_file_size_kb", 512),
        extra_excludes=extra_excludes,
    )

    all_findings: list[Finding] = []
    for fpath in files:
        all_findings.extend(scan_file(fpath, rules=rules))

    all_findings.sort(key=lambda f: f.sort_key())
    return all_findings
