"""Declarative rule loader — loads detection rules from YAML rulesets.

A **ruleset** is a folder containing ``*.yml`` / ``*.yaml`` files, each
defining a list of detection rules.

Built-in rulesets ship under ``clawcare/rulesets/<name>/``.
The ``default`` ruleset is always loaded unless ``--ruleset none`` is given.
Users can layer additional rulesets via ``--ruleset <path>``.

YAML format per rule:
    - id: RULE_ID
      severity: critical | high | medium | low
      pattern: "regex pattern"
      explanation: "Why this is dangerous"
      remediation: "How to fix it"          # optional
      flags: IGNORECASE|MULTILINE           # optional, default shown
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from clawcare.models import Severity

# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    severity: Severity
    pattern: re.Pattern[str]
    explanation: str
    remediation: str = ""
    confidence: str = "high"  # high | medium | low
    scan_context: str = "any"  # any | code | prose


# ---------------------------------------------------------------------------
# Flag parser
# ---------------------------------------------------------------------------

_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
}

_DEFAULT_FLAGS = re.IGNORECASE | re.MULTILINE


def _parse_flags(flag_str: str | None) -> int:
    """Parse a ``|``-separated flag string like ``IGNORECASE|MULTILINE``."""
    if not flag_str:
        return _DEFAULT_FLAGS
    result = 0
    for name in flag_str.split("|"):
        name = name.strip().upper()
        if name in _FLAG_MAP:
            result |= _FLAG_MAP[name]
    return result or _DEFAULT_FLAGS


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _load_rules_from_file(path: Path) -> list[Rule]:
    """Load rules from a single YAML file."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, list):
        return []

    rules: list[Rule] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            rules.append(
                Rule(
                    id=entry["id"],
                    severity=Severity.from_str(entry["severity"]),
                    pattern=re.compile(entry["pattern"], _parse_flags(entry.get("flags"))),
                    explanation=entry.get("explanation", ""),
                    remediation=entry.get("remediation", ""),
                    confidence=entry.get("confidence", "high"),
                    scan_context=entry.get("scan_context", "any"),
                )
            )
        except (KeyError, re.error, ValueError):
            continue  # skip malformed rules gracefully
    return rules


def load_ruleset(ruleset_dir: str | Path) -> list[Rule]:
    """Load all rules from ``*.yml`` / ``*.yaml`` files in a ruleset folder."""
    p = Path(ruleset_dir)
    if not p.is_dir():
        return []
    rules: list[Rule] = []
    for path in sorted(p.glob("*.yml")):
        rules.extend(_load_rules_from_file(path))
    for path in sorted(p.glob("*.yaml")):
        rules.extend(_load_rules_from_file(path))
    return rules


# ---------------------------------------------------------------------------
# Built-in rulesets
# ---------------------------------------------------------------------------

_RULESETS_DIR = Path(__file__).resolve().parent.parent / "rulesets"


def list_builtin_rulesets() -> list[str]:
    """Return names of built-in rulesets (subdirectories of rulesets/)."""
    if not _RULESETS_DIR.is_dir():
        return []
    return sorted(
        d.name for d in _RULESETS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")
    )


def load_builtin_ruleset(name: str = "default") -> list[Rule]:
    """Load a built-in ruleset by name."""
    return load_ruleset(_RULESETS_DIR / name)


# ---------------------------------------------------------------------------
# Resolve: default + user-specified rulesets
# ---------------------------------------------------------------------------


def resolve_rules(
    rulesets: list[str] | None = None,
) -> list[Rule]:
    """Resolve rulesets into a flat list of rules.

    Behaviour:
      - No rulesets specified → load ``default`` built-in.
      - Rulesets specified → load **only** those rulesets.
        To include the built-in defaults, list ``"default"`` explicitly.

    Duplicate rule IDs from later rulesets override earlier ones.
    """
    effective = rulesets if rulesets else ["default"]

    rules_by_id: dict[str, Rule] = {}
    for rs in effective:
        rs_path = Path(rs)

        # Is it a path to a folder?
        if rs_path.is_dir():
            for rule in load_ruleset(rs_path):
                rules_by_id[rule.id] = rule
        # Is it a built-in ruleset name?
        elif (_RULESETS_DIR / rs).is_dir():
            for rule in load_builtin_ruleset(rs):
                rules_by_id[rule.id] = rule
        # else: ignore unknown rulesets

    return list(rules_by_id.values())


# ---------------------------------------------------------------------------
# Convenience: ALL_RULES for backward compatibility
# ---------------------------------------------------------------------------

ALL_RULES: list[Rule] = load_builtin_ruleset("default")
