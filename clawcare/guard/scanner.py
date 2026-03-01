"""Guard command scanner — fast regex-only scanning of command strings.

``scan_command()`` runs the existing ruleset (command-injection + sensitive-data)
against a single command string and returns matching findings.

Design goal: <10 ms for a typical command.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from clawcare.models import Severity
from clawcare.scanner.rules import Rule, resolve_rules

# ---------------------------------------------------------------------------
# Quoted-string detection — used to skip matches inside string literals
# ---------------------------------------------------------------------------

# Matches single-quoted or double-quoted strings, handling escaped quotes.
_QUOTED_RE = re.compile(
    r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*\"""",
    re.DOTALL,
)

# Patterns where the following quoted string argument is executed as code.
# We check the text immediately before a quoted span to detect these.
_EXEC_PREFIX_RE = re.compile(
    r"(?:bash|sh|zsh|dash|ksh)\s+-c\s*$"
    r"|(?:python[23]?|ruby|perl|node)\s+(?:-c|-e)\s*$"
    r"|eval\s+$",
    re.IGNORECASE,
)


def _quoted_spans(cmd: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` spans of quoted strings in *cmd*."""
    return [(m.start(), m.end()) for m in _QUOTED_RE.finditer(cmd)]


def _is_exec_context(cmd: str, span_start: int) -> bool:
    """Return True if the quoted string at *span_start* is an arg to an executor."""
    prefix = cmd[:span_start]
    return bool(_EXEC_PREFIX_RE.search(prefix))


def _should_skip_match(
    match_start: int,
    match_end: int,
    spans: list[tuple[int, int]],
    cmd: str,
) -> bool:
    """Return True if the match is inside a non-executable quoted string."""
    for qs, qe in spans:
        if qs <= match_start and match_end <= qe:
            # Match is inside this quoted span — skip only if NOT an exec context.
            return not _is_exec_context(cmd, qs)
    return False


@dataclass
class CommandVerdict:
    """Result of scanning a single command string."""

    command: str
    decision: str  # "allow" | "warn" | "block"
    findings: list[CommandFinding]

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def blocked(self) -> bool:
        return self.decision == "block"


@dataclass
class CommandFinding:
    """A single match from the command scanner."""

    rule_id: str
    severity: Severity
    matched_text: str
    explanation: str
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "matched_text": self.matched_text,
            "explanation": self.explanation,
            "remediation": self.remediation,
        }


# Cache resolved rules for performance (rules are immutable).
_COMMAND_RULES: list[Rule] | None = None


def _get_rules() -> list[Rule]:
    """Lazily resolve and cache rules."""
    global _COMMAND_RULES  # noqa: PLW0603
    if _COMMAND_RULES is None:
        _COMMAND_RULES = resolve_rules(["default"])
    return _COMMAND_RULES


def scan_command(
    cmd: str,
    *,
    fail_on: str = "high",
    rules: list[Rule] | None = None,
) -> CommandVerdict:
    """Scan *cmd* against rules and return a verdict.

    Parameters
    ----------
    cmd:
        The full command string to scan.
    fail_on:
        Minimum severity that triggers a "block" decision.
    rules:
        Override rule list (useful for testing).

    Returns
    -------
    CommandVerdict with decision and any findings.
    """
    effective_rules = rules if rules is not None else _get_rules()
    threshold = Severity.from_str(fail_on)

    findings: list[CommandFinding] = []
    quoted = _quoted_spans(cmd)

    for rule in effective_rules:
        # Only apply rules relevant to command context (code / any).
        if rule.scan_context not in ("any", "code"):
            continue
        # Use finditer to check all matches — the first match may be inside
        # a quoted string while a later one is not (see issue #1).
        for match in rule.pattern.finditer(cmd):
            if not _should_skip_match(match.start(), match.end(), quoted, cmd):
                findings.append(CommandFinding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    matched_text=match.group(0),
                    explanation=rule.explanation,
                    remediation=rule.remediation,
                ))
                break  # one finding per rule is enough

    # Determine decision
    decision = "allow"
    for f in findings:
        if f.severity >= threshold:
            decision = "block"
            break
        if decision == "allow":
            decision = "warn"

    return CommandVerdict(command=cmd, decision=decision, findings=findings)
