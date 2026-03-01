"""Unified configuration loader for ClawCare.

Configuration is resolved in priority order: **project > user > defaults**.

1. **Project-level** — ``.clawcare.yml`` in (or above) the scanned directory.
   Checked into version control, shared by the team.
2. **User-level** — ``~/.clawcare/config.yml``.
   Personal defaults across all projects.
3. **Built-in defaults** — hardcoded fallbacks (``fail_on: high``, etc.).

Both files share the same format::

    # .clawcare.yml  or  ~/.clawcare/config.yml
    scan:
      fail_on: high
      block_local: false
      rulesets:
        - default
        - ./team-rules
      exclude:
        - "vendor/**"
      ignore_rules:
        - MED_JS_EVAL
      max_file_size_kb: 512

    guard:
      fail_on: high
      audit:
        enabled: true
        log_path: "~/.clawcare/history.jsonl"

Project-level values override user-level values.  CLI flags override both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

CONFIG_FILENAME = ".clawcare.yml"
USER_CONFIG_DIR = Path.home() / ".clawcare"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yml"
DEFAULT_LOG_PATH = USER_CONFIG_DIR / "history.jsonl"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """Scan sub-configuration."""

    fail_on: str = "high"
    block_local: bool = False
    rulesets: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    max_file_size_kb: int = 512


@dataclass
class AuditConfig:
    """Audit sub-configuration for the guard."""

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
    """Guard sub-configuration."""

    fail_on: str = "high"
    audit: AuditConfig = field(default_factory=AuditConfig)

    @property
    def fail_on_severity(self) -> int:
        """Return numeric severity threshold."""
        from clawcare.models import Severity

        return Severity.from_str(self.fail_on).value


@dataclass
class ClawCareConfig:
    """Top-level configuration container (scan + guard)."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)

    # Where the effective config was loaded from (None = defaults only).
    project_config_path: str | None = None
    user_config_path: str | None = None


# ---------------------------------------------------------------------------
# Backward-compatible aliases
# ---------------------------------------------------------------------------

# ProjectConfig was the old name; keep it as an alias so existing code
# and tests that import ``ProjectConfig`` keep working.
ProjectConfig = ScanConfig


# ---------------------------------------------------------------------------
# Public loaders
# ---------------------------------------------------------------------------


def load_config(
    scan_path: str | None = None,
    config_path: str | Path | None = None,
) -> ClawCareConfig:
    """Load merged configuration (project > user > defaults).

    Parameters
    ----------
    scan_path:
        Directory to search for ``.clawcare.yml``.  When *None*, only
        the user-level file (and defaults) are considered.
    config_path:
        Explicit config file path.  When given, *only* this file is
        loaded (no project/user search).
    """
    if config_path is not None:
        raw = _load_yaml(Path(config_path).expanduser())
        return _raw_to_config(raw, config_source=str(config_path))

    user_raw = _load_yaml(USER_CONFIG_PATH)
    user_source = str(USER_CONFIG_PATH) if user_raw else None

    project_raw: dict | None = None
    project_source: str | None = None
    if scan_path is not None:
        project_path = _find_project_config(scan_path)
        if project_path is not None:
            project_raw = _load_yaml(project_path)
            project_source = str(project_path)

    merged = _merge_raw(project_raw, user_raw)
    cfg = _raw_to_config(merged)
    cfg.project_config_path = project_source
    cfg.user_config_path = user_source
    return cfg


def load_project_config(scan_path: str) -> ScanConfig:
    """Load the scan portion of the merged config.

    This is the backward-compatible entry point used by ``clawcare scan``.
    Returns a ``ScanConfig`` (aliased as ``ProjectConfig``).
    """
    merged = load_config(scan_path=scan_path)
    # Attach config_path for backward compat (tests assert on it).
    cfg = merged.scan
    # Stash on a private attr so old code that reads .config_path still works.
    object.__setattr__(cfg, "config_path", merged.project_config_path or merged.user_config_path)
    return cfg


def load_guard_config(
    config_path: str | Path | None = None,
    scan_path: str | None = None,
) -> GuardConfig:
    """Load the guard portion of the merged config.

    Parameters
    ----------
    config_path:
        Explicit guard config file to load.  Skips project/user search.
    scan_path:
        Directory to search for project-level ``.clawcare.yml``.
    """
    merged = load_config(scan_path=scan_path, config_path=config_path)
    return merged.guard


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_project_config(scan_path: str) -> Path | None:
    """Search for ``.clawcare.yml`` in *scan_path* and ancestors."""
    p = Path(scan_path)
    candidates = [p / CONFIG_FILENAME]
    for parent in p.parents:
        candidates.append(parent / CONFIG_FILENAME)
        if (parent / ".git").exists():
            break
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file, returning *None* on missing/invalid files."""
    path = path.expanduser()
    if not path.is_file():
        return None
    try:
        raw = yaml.safe_load(path.read_text())
    except Exception:
        return None
    return raw if isinstance(raw, dict) else None


def _merge_raw(
    project: dict | None,
    user: dict | None,
) -> dict:
    """Merge project and user raw dicts (project wins)."""
    base: dict = {}

    # Start with user config as the base.
    if user:
        base = _deep_copy_dict(user)

    # Overlay project config.
    if project:
        for key in ("scan", "guard"):
            section = project.get(key)
            if isinstance(section, dict):
                base.setdefault(key, {})
                base[key].update(section)
        # For list fields in scan, project replaces (not appends).
        # This is the expected behavior: project config is authoritative.

    return base


def _deep_copy_dict(d: dict) -> dict:
    """Shallow-ish copy: top-level dict and nested dicts (good enough for YAML config)."""
    out: dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = _deep_copy_dict(v)
        elif isinstance(v, list):
            out[k] = list(v)
        else:
            out[k] = v
    return out


def _raw_to_config(
    raw: dict | None,
    config_source: str | None = None,
) -> ClawCareConfig:
    """Convert a raw YAML dict to a ``ClawCareConfig``."""
    if not raw:
        return ClawCareConfig()

    scan_raw = raw.get("scan", {})
    if not isinstance(scan_raw, dict):
        scan_raw = {}

    guard_raw = raw.get("guard", {})
    if not isinstance(guard_raw, dict):
        guard_raw = {}

    scan_cfg = ScanConfig(
        fail_on=str(scan_raw.get("fail_on", "high")).lower(),
        block_local=bool(scan_raw.get("block_local", False)),
        rulesets=_as_list(scan_raw.get("rulesets", [])),
        exclude=_as_list(scan_raw.get("exclude", [])),
        ignore_rules=_as_list(scan_raw.get("ignore_rules", [])),
        max_file_size_kb=int(scan_raw.get("max_file_size_kb", 512)),
    )

    # Parse audit sub-section.
    audit_raw = guard_raw.get("audit", {})
    if isinstance(audit_raw, dict):
        audit = AuditConfig(
            enabled=bool(audit_raw.get("enabled", True)),
            log_path=str(audit_raw.get("log_path", "")) or "",
        )
    else:
        audit = AuditConfig()

    guard_cfg = GuardConfig(
        fail_on=str(guard_raw.get("fail_on", "high")).lower(),
        audit=audit,
    )

    return ClawCareConfig(
        scan=scan_cfg,
        guard=guard_cfg,
        project_config_path=config_source,
    )


def _as_list(val: object) -> list[str]:
    """Coerce a value to a list of strings."""
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val]
    return []
