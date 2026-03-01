"""Data models used throughout ClawCare."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(enum.IntEnum):
    """Finding severity — ordered so higher value == more severe."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, label: str) -> Severity:
        return cls[label.upper()]

    def __str__(self) -> str:
        return self.name.lower()


# ---------------------------------------------------------------------------
# Extension root
# ---------------------------------------------------------------------------


@dataclass
class ExtensionRoot:
    """One installable extension unit discovered by an adapter."""

    root_path: str
    id: str = ""
    kind: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    manifest_path: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = self.root_path.replace("/", "_").strip("_")


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A flagged risky pattern."""

    rule_id: str
    severity: Severity
    file_path: str
    line: int
    excerpt: str
    explanation: str
    remediation: str = ""

    def sort_key(self) -> tuple:
        """Deterministic sort: severity desc, file asc, line asc."""
        return (-self.severity.value, self.file_path, self.line)


# ---------------------------------------------------------------------------
# Policy manifest
# ---------------------------------------------------------------------------


@dataclass
class PolicyManifest:
    """Parsed ``clawcare.manifest.yml`` manifest."""

    exec: str = "full"  # none | restricted | full
    network: str = "unrestricted"  # none | allowlist | unrestricted
    filesystem: str = "read_write"  # read_only | read_write
    secrets: str = "unrestricted"  # none | env_only | vault_only | unrestricted
    persistence: str = "allowed"  # forbidden | allowed
    allowed_domains: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=lambda: ["**"])
    fail_on: str | None = None  # overrides CLI --fail-on


# ---------------------------------------------------------------------------
# Adapter info (included in reports)
# ---------------------------------------------------------------------------


@dataclass
class AdapterInfo:
    name: str


# ---------------------------------------------------------------------------
# Scan result (aggregate)
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Complete output of a ClawCare run."""

    scanned_path: str
    adapter: AdapterInfo
    roots: list[ExtensionRoot] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    manifest_violations: list[Finding] = field(default_factory=list)
    mode: str = "local"
    fail_on: str = "high"

    # ---- helpers ----
    @property
    def all_findings(self) -> list[Finding]:
        return sorted(
            self.findings + self.manifest_violations,
            key=lambda f: f.sort_key(),
        )
