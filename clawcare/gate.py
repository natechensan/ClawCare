"""Gate — mode logic (local warn vs CI block) and exit codes (§9)."""

from __future__ import annotations

import os

from clawcare.models import ScanResult, Severity


def is_ci() -> bool:
    """Heuristic: detect common CI environment variables."""
    return os.environ.get("CI", "").lower() in ("true", "1", "yes")


def decide(
    result: ScanResult,
    ci_flag: bool = False,
    enforce: bool = False,
    fail_on: str = "high",
) -> int:
    """Return the exit code based on mode and findings.

    Exit codes (§9):
        0 — pass / warn-only
        2 — CI gate failed
    """
    threshold = Severity.from_str(fail_on)
    should_block = ci_flag or is_ci() or enforce

    if not should_block:
        result.mode = "local"
        return 0

    result.mode = "ci" if (ci_flag or is_ci()) else "enforce"

    for f in result.findings + result.manifest_violations:
        if f.severity >= threshold:
            return 2

    return 0
