"""Report rendering — text and JSON outputs (§13)."""

from __future__ import annotations

import json
from typing import Any

import clawcare
from clawcare.models import Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# Text output (§13.1)
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    Severity.CRITICAL: "\033[91m",  # red
    Severity.HIGH: "\033[93m",      # yellow
    Severity.MEDIUM: "\033[94m",    # blue
    Severity.LOW: "\033[90m",       # grey
}
_RESET = "\033[0m"


def _sev_label(sev: Severity, color: bool = True) -> str:
    label = sev.name.upper()
    if color:
        return f"{_SEV_COLORS.get(sev, '')}{label}{_RESET}"
    return label


def render_text(result: ScanResult, color: bool = True) -> str:
    """Produce human-friendly text output."""
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("ClawCare Scan Report")
    lines.append("=" * 60)
    lines.append(f"Path:     {result.scanned_path}")
    lines.append(f"Adapter:  {result.adapter.name} v{result.adapter.version}")
    lines.append(f"Mode:     {result.mode}")
    lines.append(f"Fail on:  {result.fail_on}")
    lines.append("")

    # Per-root summary
    if result.roots:
        lines.append(f"Extension roots ({len(result.roots)}):")
        for r in result.roots:
            lines.append(f"  • {r.root_path}  [{r.kind}]")
        lines.append("")

    # Findings grouped by severity
    all_findings = result.all_findings
    if not all_findings:
        lines.append("✅ No findings.")
    else:
        by_sev: dict[Severity, list[Finding]] = {}
        for f in all_findings:
            by_sev.setdefault(f.severity, []).append(f)

        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            group = by_sev.get(sev, [])
            if not group:
                continue
            lines.append(f"── {_sev_label(sev, color)} ({len(group)}) ──")
            for f in group:
                loc = f"{f.file_path}:{f.line}" if f.line else f.file_path
                lines.append(f"  [{f.rule_id}] {loc}")
                lines.append(f"    {f.excerpt}")
                lines.append(f"    → {f.explanation}")
                if f.remediation:
                    lines.append(f"    ✎ {f.remediation}")
            lines.append("")

    # Summary
    lines.append("-" * 60)
    count_crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    count_high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    count_med  = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    count_low  = sum(1 for f in all_findings if f.severity == Severity.LOW)
    lines.append(
        f"Findings: {count_crit} critical, {count_high} high, "
        f"{count_med} medium, {count_low} low"
    )
    lines.append("=" * 60)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON output (§13.2)
# ---------------------------------------------------------------------------

def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": str(f.severity),
        "file": f.file_path,
        "line": f.line,
        "excerpt": f.excerpt,
        "explanation": f.explanation,
        "remediation": f.remediation,
    }


def render_json(result: ScanResult) -> str:
    """Produce stable JSON output (deterministic sorting)."""
    doc: dict[str, Any] = {
        "tool": "clawcare",
        "version": clawcare.__version__,
        "adapter_used": {
            "name": result.adapter.name,
            "version": result.adapter.version,
        },
        "scanned_path": result.scanned_path,
        "roots": [
            {
                "root_path": r.root_path,
                "id": r.id,
                "kind": r.kind,
                "metadata": r.metadata,
                "manifest_path": r.manifest_path,
            }
            for r in sorted(result.roots, key=lambda r: r.root_path)
        ],
        "summary": {
            "total_findings": len(result.findings) + len(result.manifest_violations),
            "critical": sum(
                1 for f in result.all_findings if f.severity == Severity.CRITICAL
            ),
            "high": sum(
                1 for f in result.all_findings if f.severity == Severity.HIGH
            ),
            "medium": sum(
                1 for f in result.all_findings if f.severity == Severity.MEDIUM
            ),
            "low": sum(
                1 for f in result.all_findings if f.severity == Severity.LOW
            ),
            "fail_on": result.fail_on,
            "mode": result.mode,
        },
        "findings": [_finding_to_dict(f) for f in result.all_findings if f.rule_id and not f.rule_id.startswith("MANIFEST_")],
        "manifest_violations": [_finding_to_dict(f) for f in result.all_findings if f.rule_id and f.rule_id.startswith("MANIFEST_")],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
