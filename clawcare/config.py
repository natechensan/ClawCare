"""Project-level configuration loader for ``.clawcare.yml``.

The ``.clawcare.yml`` file lives at the root of the scanned directory and
provides declarative defaults that CLI flags can override.

Example::

    # .clawcare.yml
    scan:
      fail_on: high
      block_local: false
      rulesets:
        - default
        - ./team-rules
      exclude:
        - "vendor/**"
        - "third_party/**"
      ignore_rules:
        - MED_JS_EVAL
      max_file_size_kb: 512
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

CONFIG_FILENAME = ".clawcare.yml"


@dataclass
class ProjectConfig:
    """Parsed project configuration."""

    fail_on: str = "high"
    block_local: bool = False
    rulesets: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    max_file_size_kb: int = 512

    # Where the config was loaded from (None = defaults)
    config_path: str | None = None


def load_project_config(scan_path: str) -> ProjectConfig:
    """Search for ``.clawcare.yml`` in *scan_path* and load it.

    Returns default ``ProjectConfig`` if no config file is found.
    """
    p = Path(scan_path)

    # Look for .clawcare.yml in the scan target itself
    candidates = [p / CONFIG_FILENAME]
    # Also walk up to find it in a parent (useful when scanning a subdirectory)
    for parent in p.parents:
        candidates.append(parent / CONFIG_FILENAME)
        if (parent / ".git").exists():
            break  # stop at repo root

    for candidate in candidates:
        if candidate.is_file():
            return _parse_config(candidate)

    return ProjectConfig()


def _parse_config(config_path: Path) -> ProjectConfig:
    """Parse a ``.clawcare.yml`` file into a ``ProjectConfig``."""
    try:
        raw = yaml.safe_load(config_path.read_text())
    except Exception:
        return ProjectConfig(config_path=str(config_path))

    if not isinstance(raw, dict):
        return ProjectConfig(config_path=str(config_path))

    scan = raw.get("scan", {})
    if not isinstance(scan, dict):
        scan = {}

    return ProjectConfig(
        fail_on=str(scan.get("fail_on", "high")).lower(),
        block_local=bool(scan.get("block_local", False)),
        rulesets=_as_list(scan.get("rulesets", [])),
        exclude=_as_list(scan.get("exclude", [])),
        ignore_rules=_as_list(scan.get("ignore_rules", [])),
        max_file_size_kb=int(scan.get("max_file_size_kb", 512)),
        config_path=str(config_path),
    )


def _as_list(val: object) -> list[str]:
    """Coerce a value to a list of strings."""
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val]
    return []
