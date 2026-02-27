"""OpenClaw post-exec hook handler.

This module is invoked by the ClawCare Guard TypeScript plugin for OpenClaw as
a subprocess::

    echo '{"tool":"exec","input":{"command":"..."},...}' | \\
      clawcare guard hook --platform openclaw --stage post

The *pre*-command interception is handled entirely by the TypeScript plugin's
``before_tool_call`` hook, which calls ``clawcare guard run -- <command>``
directly.  This module only handles the **post-exec audit** path.

See also:
  clawcare/guard/plugin_assets/openclaw-plugin.ts  — the TS plugin source
  https://docs.openclaw.ai/concepts/agent-loop#hook-points
  https://docs.openclaw.ai/tools/plugin#plugin-hooks
"""

from __future__ import annotations

import json
import sys
from typing import Any

from clawcare.guard.audit import write_audit_event
from clawcare.guard.config import GuardConfig
from clawcare.guard.scanner import scan_command


def handle_post(config: GuardConfig) -> int:
    """Handle OpenClaw post-execution audit event.

    Reads JSON from stdin (piped by the TypeScript plugin's
    ``after_tool_call`` hook) and writes an audit log entry.
    """
    payload = _read_stdin_json()
    if payload is None:
        return 0

    command = _extract_command(payload) or ""
    post_verdict = scan_command(command, fail_on=config.fail_on) if command else None
    output = payload.get("output", {})

    exit_code: int | None = None
    duration_ms: float | None = None

    if isinstance(output, dict):
        raw = output.get("exit_code")
        if raw is None:
            raw = output.get("exitCode")
        if raw is not None:
            try:
                exit_code = int(raw)
            except (ValueError, TypeError):
                pass

    raw_duration = payload.get("duration_ms")
    if raw_duration is not None:
        try:
            duration_ms = float(raw_duration)
        except (ValueError, TypeError):
            pass

    if config.audit.enabled:
        write_audit_event(
            "post_exec",
            platform="openclaw",
            command=command,
            status="executed",
            findings=[f.rule_id for f in post_verdict.findings] if post_verdict else [],
            exit_code=exit_code,
            duration_ms=duration_ms,
            log_path=config.audit.log_path,
            extra={"tool": payload.get("tool", "execute")},
        )

    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_command(payload: dict[str, Any]) -> str | None:
    """Extract command string from the plugin-provided payload."""
    inp = payload.get("input", {})
    if isinstance(inp, dict):
        cmd = inp.get("command") or inp.get("cmd")
        if isinstance(cmd, str):
            return cmd

    cmd = payload.get("command")
    if isinstance(cmd, str):
        return cmd
    return None


def _read_stdin_json() -> dict[str, Any] | None:
    """Read and parse JSON from stdin."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return None
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
        return None
    except (json.JSONDecodeError, OSError):
        return None
