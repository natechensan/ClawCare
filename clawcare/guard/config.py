"""Guard configuration — loads ``~/.clawcare/config.yml`` for runtime guard settings.

Example ``~/.clawcare/config.yml``::

    guard:
      fail_on: high          # minimum severity to block (low|medium|high|critical)
      audit:
        enabled: true
        log_path: "~/.clawcare/history.jsonl"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONFIG_DIR = Path.home() / ".clawcare"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.yml"
DEFAULT_LOG_PATH = DEFAULT_CONFIG_DIR / "history.jsonl"


@dataclass
class AuditConfig:
    """Audit sub-configuration."""

    enabled: bool = True
    log_path: str = ""

    def __post_init__(self) -> None:
        if not self.log_path:
            self.log_path = str(DEFAULT_LOG_PATH)

    @property
    def resolved_log_path(self) -> Path:
        return Path(self.log_path).expanduser()


@dataclass
class GuardConfig:
    """Parsed guard configuration."""

    fail_on: str = "high"
    audit: AuditConfig = field(default_factory=AuditConfig)

    @property
    def fail_on_severity(self) -> int:
        """Return numeric severity threshold."""
        from clawcare.models import Severity
        return Severity.from_str(self.fail_on).value


def load_guard_config(config_path: str | Path | None = None) -> GuardConfig:
    """Load guard config from *config_path* (default: ``~/.clawcare/config.yml``).

    Returns default ``GuardConfig`` if the file does not exist or is invalid.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    path = path.expanduser()

    if not path.is_file():
        return GuardConfig()

    try:
        raw = yaml.safe_load(path.read_text())
    except Exception:
        return GuardConfig()

    if not isinstance(raw, dict):
        return GuardConfig()

    guard_section = raw.get("guard", {})
    if not isinstance(guard_section, dict):
        return GuardConfig()

    # Parse audit sub-section
    audit_raw = guard_section.get("audit", {})
    if isinstance(audit_raw, dict):
        audit = AuditConfig(
            enabled=bool(audit_raw.get("enabled", True)),
            log_path=str(audit_raw.get("log_path", "")) or "",
        )
    else:
        audit = AuditConfig()

    return GuardConfig(
        fail_on=str(guard_section.get("fail_on", "high")).lower(),
        audit=audit,
    )
