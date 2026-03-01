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
_DANGEROUS_CMDS = frozenset(
    {
        # Shells / executors
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "eval",
        "exec",
        "source",
        "xargs",
        # Scripting runtimes
        "python",
        "python3",
        "python2",
        "ruby",
        "perl",
        "node",
        "deno",
        "bun",
        "go",
        "rustc",
        "javac",
        "java",
        # File readers
        "cat",
        "less",
        "more",
        "head",
        "tail",
        "tac",
        "bat",
        "batcat",
        "nano",
        "vim",
        "vi",
        "nvim",
        "emacs",
        "ed",
        # File operations
        "cp",
        "mv",
        "rm",
        "scp",
        "rsync",
        "install",
        "ln",
        "link",
        "unlink",
        "shred",
        # File display / processing
        "grep",
        "rg",
        "awk",
        "sed",
        "cut",
        "sort",
        "wc",
        "diff",
        "strings",
        "xxd",
        "od",
        "hexdump",
        "file",
        # Network with file-like access
        "curl",
        "wget",
        "nc",
        "ncat",
        "socat",
    }
)
# Note: ./script.sh patterns are handled via verb.startswith("./") in
# _is_dangerous_cmd, not via this set.

# Common command wrappers that should be stripped to find the real verb.
_CMD_WRAPPERS = frozenset(
    {
        "sudo",
        "env",
        "nice",
        "nohup",
        "time",
        "timeout",
        "stdbuf",
        "command",
        "builtin",
        "exec",
        "ionice",
        "taskset",
        "chroot",
        "watch",
        "unbuffer",
        "setsid",
        "chronic",
        "ifne",
    }
)

def _quoted_spans(cmd: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` spans of quoted strings in *cmd*."""
    return [(m.start(), m.end()) for m in _QUOTED_RE.finditer(cmd)]


def _segment_for_position(cmd: str, pos: int, spans: list[tuple[int, int]]) -> str:
    """Return the command segment (split on &&, ||, ;, |) containing *pos*.

    Only splits on operators that are outside quoted strings.
    """
    # Find split points outside quotes
    splits: list[int] = [0]
    i = 0
    while i < len(cmd):
        # Skip over quoted spans
        in_quote = False
        for qs, qe in spans:
            if qs <= i < qe:
                i = qe
                in_quote = True
                break
        if in_quote:
            continue
        # Check for compound operators
        ch = cmd[i]
        if ch == ";":
            splits.append(i + 1)
        elif ch == "|" and i + 1 < len(cmd) and cmd[i + 1] == "|":
            splits.append(i + 2)
            i += 2
            continue
        elif ch == "|":
            splits.append(i + 1)
        elif ch == "&" and i + 1 < len(cmd) and cmd[i + 1] == "&":
            splits.append(i + 2)
            i += 2
            continue
        i += 1
    splits.append(len(cmd))

    # Find which segment contains pos
    for j in range(len(splits) - 1):
        if splits[j] <= pos < splits[j + 1]:
            return cmd[splits[j] : splits[j + 1]].strip()
    return cmd.strip()


def _tokenize(s: str) -> list[str]:
    """Split *s* into whitespace-delimited tokens (no shell quote handling)."""
    return s.split()


def _extract_cmd_verb(segment: str) -> str:
    """Return the command verb from a single command segment.

    Iteratively strips:
    - ``VAR=val`` environment prefixes
    - Wrapper commands (sudo, env, time, etc.) and their flags/arguments
    """
    tokens = _tokenize(segment.strip())
    i = 0

    while i < len(tokens):
        tok = tokens[i]

        # Strip VAR=val prefixes (KEY=value before the command)
        if "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].isidentifier():
            i += 1
            continue

        # Normalize: /usr/bin/sudo → sudo
        bare = (
            tok.rsplit("/", 1)[-1].lower()
            if "/" in tok and not tok.startswith("./")
            else tok.lower()
        )

        if bare not in _CMD_WRAPPERS:
            # This is the real verb
            break

        # Skip the wrapper and its flags/arguments
        i += 1
        while i < len(tokens):
            next_tok = tokens[i]
            # VAR=val after wrapper (e.g. env VAR=val, sudo VAR=val)
            if (
                "=" in next_tok
                and not next_tok.startswith("-")
                and next_tok.split("=", 1)[0].isidentifier()
            ):
                i += 1
                continue
            # Flag (starts with -)
            if next_tok.startswith("-"):
                i += 1
                continue
            # Numeric arg for wrappers that take them (timeout 5, nice 10)
            if bare in ("timeout", "nice", "ionice") and next_tok.replace(".", "", 1).isdigit():
                i += 1
                continue
            # For sudo specifically, skip non-flag non-command tokens that
            # follow a flag expecting an argument (e.g. sudo -u root)
            if bare == "sudo" and i >= 2:
                prev = tokens[i - 1]
                if prev in ("-u", "-g", "-C", "-D", "-R", "-T", "-h", "-p"):
                    i += 1
                    continue
            break

    if i >= len(tokens):
        return ""
    verb = tokens[i]
    if "/" in verb and not verb.startswith("./"):
        verb = verb.rsplit("/", 1)[-1]
    return verb.lower()


def _is_dangerous_cmd(segment: str) -> bool:
    """Return True if *segment* starts with a command that accesses/executes its args."""
    verb = _extract_cmd_verb(segment)
    if verb in _DANGEROUS_CMDS:
        return True
    return bool(verb.startswith("./"))


def _should_skip_match(
    match_start: int,
    match_end: int,
    spans: list[tuple[int, int]],
    cmd: str,
) -> bool:
    """Return True if the match is inside a quoted string of a non-dangerous command.

    For compound commands (joined by ``&&``, ``||``, ``;``, ``|``), the
    dangerousness check applies to the specific segment containing the match,
    not the whole command.
    """
    for qs, qe in spans:
        if qs <= match_start and match_end <= qe:
            # Match is inside this quoted span.
            # Determine the segment containing this match.
            segment = _segment_for_position(cmd, match_start, spans)
            return not _is_dangerous_cmd(segment)
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
                findings.append(
                    CommandFinding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        matched_text=match.group(0),
                        explanation=rule.explanation,
                        remediation=rule.remediation,
                    )
                )
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
