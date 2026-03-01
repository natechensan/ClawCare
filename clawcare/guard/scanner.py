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
# Quoted-string detection — skip matches inside quoted args of safe commands
# ---------------------------------------------------------------------------

# Matches single-quoted or double-quoted strings, handling escaped quotes.
_QUOTED_RE = re.compile(
    r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*\"""",
    re.DOTALL,
)

# Commands whose quoted arguments should still be scanned because the
# content is executed or used to access files.  If the leading command
# verb is in this set, matches inside its quoted args are NOT skipped.
_DANGEROUS_CMDS = frozenset({
    # Shells / executors
    "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
    "eval", "exec", "source", "xargs",
    # Scripting runtimes
    "python", "python3", "python2", "ruby", "perl", "node", "deno", "bun",
    "go", "rustc", "javac", "java",
    # File readers
    "cat", "less", "more", "head", "tail", "tac", "bat", "batcat",
    "nano", "vim", "vi", "nvim", "emacs", "ed",
    # File operations
    "cp", "mv", "rm", "scp", "rsync", "install",
    "ln", "link", "unlink", "shred",
    # File display / processing
    "grep", "rg", "awk", "sed", "cut", "sort", "wc", "diff",
    "strings", "xxd", "od", "hexdump", "file",
    # Network with file-like access
    "curl", "wget", "nc", "ncat", "socat",
    # Scripts
    "./", "sh", "bash",
})

# Extract the leading command verb from a (possibly compound) command.
# Handles: cmd ..., VAR=val cmd ..., sudo cmd ..., env cmd ...
_CMD_VERB_RE = re.compile(
    r"(?:(?:\w+=\S+\s+)*)"           # optional VAR=val prefixes
    r"(?:(?:sudo|env|nice|nohup)\s+)*"  # optional wrappers
    r"(\S+)",                          # the actual command verb
)


def _quoted_spans(cmd: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` spans of quoted strings in *cmd*."""
    return [(m.start(), m.end()) for m in _QUOTED_RE.finditer(cmd)]


def _extract_cmd_verb(cmd: str) -> str:
    """Return the leading command verb, stripped of path components."""
    m = _CMD_VERB_RE.match(cmd.lstrip())
    if not m:
        return ""
    verb = m.group(1)
    # Strip path: /usr/bin/cat → cat, ./script.sh → ./script.sh
    if "/" in verb and not verb.startswith("./"):
        verb = verb.rsplit("/", 1)[-1]
    return verb.lower()


def _is_dangerous_cmd(cmd: str) -> bool:
    """Return True if *cmd* starts with a command that accesses/executes its args."""
    verb = _extract_cmd_verb(cmd)
    if verb in _DANGEROUS_CMDS:
        return True
    # Match ./script.sh, ./anything patterns
    if verb.startswith("./"):
        return True
    return False


def _should_skip_match(
    match_start: int,
    match_end: int,
    spans: list[tuple[int, int]],
    cmd: str,
) -> bool:
    """Return True if the match is inside a quoted string of a non-dangerous command.

    Matches inside quoted args are skipped only when the overall command
    is NOT in the dangerous-commands list (executors, file-access, network).
    This prevents false positives like ``gh issue create --body "~/.ssh/..."``
    while still catching ``cat "~/.ssh/id_rsa"`` or ``bash -c "curl ..."``.
    """
    for qs, qe in spans:
        if qs <= match_start and match_end <= qe:
            # Match is inside this quoted span.
            # Scan inside it (don't skip) if the command is dangerous.
            return not _is_dangerous_cmd(cmd)
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
