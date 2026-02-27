"""Audit logger — append-only JSONL log of guard events.

Each line is a JSON object with:
  - ``timestamp``: ISO-8601 UTC
  - ``event``: ``pre_scan`` | ``post_exec`` | ``post_failure`` | ``blocked``
  - ``platform``: ``claude`` | ``cursor`` | ``codex`` | ``generic``
  - ``command``: the command string (may be redacted)
  - ``status``: ``allowed`` | ``warned`` | ``blocked`` | ``executed`` | ``failed``
  - ``findings``: list of matched rule IDs
  - ``exit_code``: (post_exec / post_failure only) process exit code
  - ``duration_ms``: (post_exec / post_failure only) execution time in ms
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from clawcare.guard.config import DEFAULT_LOG_PATH


def _ensure_parent(path: Path) -> None:
    """Create parent directories if they do not exist."""
    path.parent.mkdir(parents=True, exist_ok=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_audit_event(
    event: str,
    *,
    platform: str = "generic",
    command: str = "",
    status: str = "allowed",
    findings: list[str] | None = None,
    exit_code: int | None = None,
    duration_ms: float | None = None,
    log_path: str | Path | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Append a single audit event to the JSONL log.

    Silently ignores errors (audit must never break the guard flow).
    """
    dest = Path(log_path).expanduser() if log_path else DEFAULT_LOG_PATH

    record: dict[str, Any] = {
        "timestamp": _now_iso(),
        "event": event,
        "platform": platform,
        "command": command,
        "status": status,
        "findings": findings or [],
    }

    if exit_code is not None:
        record["exit_code"] = exit_code
    if duration_ms is not None:
        record["duration_ms"] = round(duration_ms, 2)
    if extra:
        record.update(extra)

    try:
        _ensure_parent(dest)
        with open(dest, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass  # audit must never crash the guard


def read_audit_events(
    *,
    log_path: str | Path | None = None,
    since: str | None = None,
    only_violations: bool = False,
) -> list[dict[str, Any]]:
    """Read audit events from JSONL log with optional filtering.

    ``since`` supports either:
      - relative: ``15m``, ``24h``, ``7d``
      - absolute ISO-8601 timestamp
    """
    dest = Path(log_path).expanduser() if log_path else DEFAULT_LOG_PATH
    if not dest.is_file():
        return []

    cutoff = _parse_since(since) if since else None

    events: list[dict[str, Any]] = []
    try:
        with open(dest, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue

                if cutoff is not None:
                    ts = _parse_event_ts(event.get("timestamp"))
                    if ts is None or ts < cutoff:
                        continue

                if only_violations and not event.get("findings"):
                    continue

                events.append(event)
    except OSError:
        return []

    return events


def _parse_since(since: str) -> datetime | None:
    """Parse relative/absolute since value into UTC datetime."""
    val = since.strip().lower()
    now = datetime.now(timezone.utc)

    if len(val) >= 2 and val[:-1].isdigit() and val[-1] in {"m", "h", "d"}:
        amount = int(val[:-1])
        unit = val[-1]
        if unit == "m":
            return now - timedelta(minutes=amount)
        if unit == "h":
            return now - timedelta(hours=amount)
        return now - timedelta(days=amount)

    ts = _parse_event_ts(val)
    return ts


def _parse_event_ts(raw: Any) -> datetime | None:
    """Parse event timestamp to aware UTC datetime."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    val = raw.strip().replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(val)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
