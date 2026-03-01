"""Python AST analyzer — detect dangerous patterns structurally.

Uses the stdlib ``ast`` module to walk Python source and flag dangerous
calls (``eval``, ``exec``, ``os.system``, ``subprocess`` with
``shell=True``, etc.) without regex false positives.

Falls back gracefully when the file has syntax errors.
"""

from __future__ import annotations

import ast
from pathlib import Path

from clawcare.models import Finding, Severity

# ---------------------------------------------------------------------------
# Dangerous call patterns
# ---------------------------------------------------------------------------

# Functions that execute arbitrary code
_DANGEROUS_CALLS: dict[str, tuple[str, Severity, str]] = {
    "eval": (
        "PY_EVAL",
        Severity.MEDIUM,
        "eval() executes arbitrary expressions at runtime.",
    ),
    "exec": (
        "PY_EXEC",
        Severity.MEDIUM,
        "exec() executes arbitrary code at runtime.",
    ),
    "compile": (
        "PY_COMPILE",
        Severity.MEDIUM,
        "compile() can prepare arbitrary code for execution.",
    ),
}

# os module dangerous functions
_OS_CALLS: dict[str, tuple[str, Severity, str]] = {
    "system": (
        "PY_OS_SYSTEM",
        Severity.HIGH,
        "os.system() executes shell commands.",
    ),
    "popen": (
        "PY_OS_POPEN",
        Severity.HIGH,
        "os.popen() executes shell commands.",
    ),
}


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------


class _DangerVisitor(ast.NodeVisitor):
    """Walk Python AST and collect findings."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[Finding] = []

    # -- bare dangerous calls: eval(), exec() --
    def visit_Call(self, node: ast.Call) -> None:
        # Simple call: eval(...), exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_CALLS:
            rule_id, severity, explanation = _DANGEROUS_CALLS[node.func.id]
            self._add(node, rule_id, severity, explanation)

        # Attribute call: os.system(...), os.popen(...)
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr

            # os.system / os.popen
            if attr in _OS_CALLS and self._is_module(node.func.value, "os"):
                rule_id, severity, explanation = _OS_CALLS[attr]
                self._add(node, rule_id, severity, explanation)

            # subprocess.run/call/Popen(..., shell=True)
            if (
                attr in ("run", "call", "Popen", "check_call", "check_output")
                and self._is_module(node.func.value, "subprocess")
                and self._has_shell_true(node)
            ):
                self._add(
                    node,
                    "MED_SUBPROCESS_SHELL",
                    Severity.MEDIUM,
                    f"subprocess.{attr}(shell=True) executes commands via the shell.",
                )

        self.generic_visit(node)

    def _is_module(self, node: ast.expr, name: str) -> bool:
        """Check if *node* is a Name referencing *name*."""
        return isinstance(node, ast.Name) and node.id == name

    def _has_shell_true(self, call: ast.Call) -> bool:
        """Check if call has keyword arg shell=True."""
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        severity: Severity,
        explanation: str,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                file_path=self.file_path,
                line=getattr(node, "lineno", 0),
                excerpt=ast.dump(node)[:120],
                explanation=explanation,
                remediation="Avoid this pattern in extension code.",
            )
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_python(file_path: Path) -> list[Finding]:
    """Parse *file_path* as Python and return structural findings.

    Returns an empty list if the file has syntax errors (the regex-based
    scanner will still run as a fallback).
    """
    try:
        source = file_path.read_text(errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, OSError):
        return []

    visitor = _DangerVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.findings
