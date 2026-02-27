"""CLI — click-based command-line interface (§12)."""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import click

from clawcare.adapters.registry import (
    list_registered_adapters,
    load_adapters,
    select_adapter,
)
from clawcare.config import load_project_config
from clawcare.discovery import discover
from clawcare.gate import decide
from clawcare.models import AdapterInfo, ScanResult
from clawcare.policy import enforce, resolve_manifest
from clawcare.report import render_json, render_text
from clawcare.scanner.rules import resolve_rules
from clawcare.scanner.scanner import scan_root


@click.group()
@click.version_option()
def main() -> None:
    """ClawCare — Guardian engine for agentic-tool extension security."""


# ───────────────────────────────────────────────────────────────────
# scan
# ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--adapter", "adapter_spec", default="auto",
              help="auto | <name> | import:pkg.module:Class")
@click.option("--ci", "ci_flag", is_flag=True, default=False,
              help="Force CI mode (exit 2 on fail).")
@click.option("--block-local", "block_local_flag", is_flag=True, default=None,
              help="Block locally too (exit 2 on fail).")
@click.option("--fail-on", "fail_on", default=None,
              type=click.Choice(["low", "medium", "high", "critical"],
                                case_sensitive=False),
              help="Minimum severity to fail on (default: high).")
@click.option("--manifest", "manifest_opt", default="auto",
              help="auto | <path> | none")
@click.option("--format", "fmt", default="text",
              type=click.Choice(["text", "json"], case_sensitive=False),
              help="Output format.")
@click.option("--json-out", "json_out", default=None,
              type=click.Path(), help="Write JSON report to file.")
@click.option("--exclude", "excludes", multiple=True,
              help="Extra glob patterns to exclude (repeatable).")
@click.option("--max-file-size-kb", "max_kb", default=None, type=int,
              help="Max file size to scan in KB (default 512).")
@click.option("--ruleset", "rulesets", multiple=True,
              help="Ruleset folder path or built-in name (repeatable). "
                   "Default ruleset always included.")
def scan(
    path: str,
    adapter_spec: str,
    ci_flag: bool,
    block_local_flag: bool | None,
    fail_on: str | None,
    manifest_opt: str,
    fmt: str,
    json_out: str | None,
    excludes: tuple[str, ...],
    max_kb: int | None,
    rulesets: tuple[str, ...],
) -> None:
    """Scan an extension path for risky patterns."""
    target_path = str(Path(path).resolve())

    # --- load project config (.clawcare.yml) ---
    cfg = load_project_config(target_path)

    # CLI flags override config values
    effective_fail_on = fail_on or cfg.fail_on
    effective_block_local = block_local_flag if block_local_flag is not None else cfg.block_local
    effective_max_kb = max_kb if max_kb is not None else cfg.max_file_size_kb
    effective_excludes = list(excludes) + cfg.exclude
    effective_rulesets = list(rulesets) + cfg.rulesets

    # --- adapter selection ---
    try:
        candidates = load_adapters(adapter_spec)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if adapter_spec == "auto":
        adapter = select_adapter(candidates, target_path)
        if adapter is None:
            click.echo(
                "Error: No adapter detected for the target path. "
                "Use --adapter <name> or --adapter import:... to specify one.",
                err=True,
            )
            sys.exit(1)
    else:
        adapter = candidates[0]

    # --- discovery ---
    roots = discover(adapter, target_path)

    # --- scan ---
    result = ScanResult(
        scanned_path=target_path,
        adapter=AdapterInfo(name=adapter.name, version=adapter.version),
        roots=roots,
        fail_on=effective_fail_on,
    )

    # --- load rules ---
    rules = resolve_rules(effective_rulesets if effective_rulesets else None)

    # Apply ignore_rules from config
    if rules and cfg.ignore_rules:
        ignored = set(cfg.ignore_rules)
        rules = [r for r in rules if r.id not in ignored]

    for root in roots:
        scope = adapter.scan_scope(root)
        scope.setdefault("max_file_size_kb", effective_max_kb)
        findings = scan_root(root, scope, extra_excludes=effective_excludes,
                             rules=rules)
        result.findings.extend(findings)

        # --- manifest enforcement ---
        manifest = resolve_manifest(root, adapter, manifest_opt)
        if manifest is not None:
            # Concatenate all scannable text for policy checks
            from clawcare.scanner.scanner import collect_files
            texts: list[str] = []
            for fpath in collect_files(root, scope.get("include_globs"),
                                        scope.get("exclude_globs"),
                                        scope.get("max_file_size_kb", effective_max_kb)):
                with contextlib.suppress(OSError):
                    texts.append(fpath.read_text(errors="replace"))
            all_text = "\n".join(texts)
            violations = enforce(manifest, root, all_text)
            result.manifest_violations.extend(violations)

            # Manifest-level fail_on override
            if manifest.fail_on:
                effective_fail_on = manifest.fail_on

    # Filter ignored rules from findings (for default rules path)
    if cfg.ignore_rules:
        ignored = set(cfg.ignore_rules)
        result.findings = [f for f in result.findings if f.rule_id not in ignored]

    # --- scoring ---
    result.fail_on = effective_fail_on

    # --- gate decision ---
    exit_code = decide(result, ci_flag=ci_flag, enforce=effective_block_local,
                       fail_on=effective_fail_on)

    # --- output ---
    if fmt == "json":
        output = render_json(result)
    else:
        output = render_text(result)

    click.echo(output)

    if json_out:
        Path(json_out).write_text(render_json(result))
        click.echo(f"JSON report written to {json_out}", err=True)

    sys.exit(exit_code)


# ───────────────────────────────────────────────────────────────────
# adapters
# ───────────────────────────────────────────────────────────────────

@main.group()
def adapters() -> None:
    """Manage and inspect adapters."""


@adapters.command("list")
def adapters_list() -> None:
    """List registered adapters."""
    all_adapters = list_registered_adapters()
    if not all_adapters:
        click.echo("No adapters registered.")
        return
    click.echo(f"{'Name':<20} {'Version':<10} {'Priority'}")
    click.echo("-" * 42)
    for a in sorted(all_adapters, key=lambda a: a.name):
        click.echo(f"{a.name:<20} {a.version:<10} {a.priority}")


@adapters.command("describe")
@click.argument("name")
def adapters_describe(name: str) -> None:
    """Describe a specific adapter."""
    all_adapters = list_registered_adapters()
    matched = [a for a in all_adapters if a.name == name]
    if not matched:
        click.echo(f"Adapter '{name}' not found.", err=True)
        sys.exit(1)
    a = matched[0]
    click.echo(f"Name:     {a.name}")
    click.echo(f"Version:  {a.version}")
    click.echo(f"Priority: {a.priority}")
    click.echo(f"Class:    {type(a).__module__}.{type(a).__qualname__}")


# ───────────────────────────────────────────────────────────────────
# guard
# ───────────────────────────────────────────────────────────────────

@main.group()
def guard() -> None:
    """Runtime command interception and audit (ClawCare Guard)."""


@guard.command("run")
@click.argument("command", nargs=-1, required=True)
@click.option("--fail-on", "fail_on", default=None,
              type=click.Choice(["low", "medium", "high", "critical"],
                                case_sensitive=False),
              help="Minimum severity to block (default: from config or high).")
@click.option("--dry-run", is_flag=True, default=False,
              help="Scan only — do not execute the command.")
@click.option("--config", "config_path", default=None,
              type=click.Path(), help="Path to guard config file.")
def guard_run(
    command: tuple[str, ...],
    fail_on: str | None,
    dry_run: bool,
    config_path: str | None,
) -> None:
    """Scan and execute a command (wrapper mode).

    Usage: clawcare guard run -- curl http://example.com
    """
    import subprocess
    import time

    import os

    from clawcare.guard.audit import write_audit_event
    from clawcare.guard.config import load_guard_config
    from clawcare.guard.scanner import scan_command

    cfg = load_guard_config(config_path, scan_path=None if config_path else os.getcwd())
    effective_fail_on = fail_on or cfg.fail_on
    cmd_str = " ".join(command)

    # --- pre-scan ---
    verdict = scan_command(cmd_str, fail_on=effective_fail_on)

    if cfg.audit.enabled:
        _status_map = {"allow": "allowed", "warn": "warned", "block": "blocked"}
        write_audit_event(
            "pre_scan",
            platform="generic",
            command=cmd_str,
            status=_status_map.get(verdict.decision, verdict.decision),
            findings=[f.rule_id for f in verdict.findings],
            log_path=cfg.audit.log_path,
        )

    # Show findings
    if verdict.findings:
        for f in verdict.findings:
            sev = f.severity.name.upper()
            click.echo(f"[{sev}] {f.rule_id}: {f.explanation}", err=True)

    if verdict.blocked:
        click.echo(f"\n⛔ ClawCare BLOCKED: {cmd_str}", err=True)
        sys.exit(2)

    if verdict.decision == "warn":
        click.echo(f"\n⚠ ClawCare WARNING — proceeding with: {cmd_str}", err=True)

    if dry_run:
        click.echo("(dry-run — command not executed)")
        sys.exit(0)

    # --- execute ---
    start = time.monotonic()
    result = subprocess.run(cmd_str, shell=True)  # noqa: S602
    elapsed_ms = (time.monotonic() - start) * 1000

    if cfg.audit.enabled:
        write_audit_event(
            "post_exec",
            platform="generic",
            command=cmd_str,
            status="executed",
            findings=[f.rule_id for f in verdict.findings],
            exit_code=result.returncode,
            duration_ms=elapsed_ms,
            log_path=cfg.audit.log_path,
        )

    sys.exit(result.returncode)


@guard.command("hook")
@click.option("--platform", required=True,
              type=click.Choice(["claude", "openclaw"], case_sensitive=False),
              help="Platform whose hook protocol to handle.")
@click.option("--stage", required=True,
              type=click.Choice(["pre", "post", "post-failure"], case_sensitive=False),
              help="Hook stage: pre (before execution), post (after), or post-failure (on error).")
@click.option("--config", "config_path", default=None,
              type=click.Path(), help="Path to guard config file.")
def guard_hook(platform: str, stage: str, config_path: str | None) -> None:
    """Handle a platform hook event (reads JSON from stdin).

    This command is invoked by the agent platform, not by users directly.

    \b
    Claude Code:
      PreToolUse         → clawcare guard hook --platform claude --stage pre
      PostToolUse        → clawcare guard hook --platform claude --stage post
      PostToolUseFailure → clawcare guard hook --platform claude --stage post-failure
    OpenClaw:
      after_tool_call → clawcare guard hook --platform openclaw --stage post
      (pre-command scanning is handled by the TS plugin calling
       `clawcare guard run` directly)
    """
    import os

    from clawcare.guard.config import load_guard_config
    from clawcare.guard.hooks.claude import (
        handle_post,
        handle_post_failure,
        handle_pre,
    )
    from clawcare.guard.hooks.openclaw import (
        handle_post as openclaw_handle_post,
    )

    cfg = load_guard_config(config_path, scan_path=None if config_path else os.getcwd())

    if platform == "claude":
        if stage == "pre":
            exit_code = handle_pre(cfg)
        elif stage == "post-failure":
            exit_code = handle_post_failure(cfg)
        else:
            exit_code = handle_post(cfg)
        sys.exit(exit_code)

    if platform == "openclaw":
        if stage == "pre":
            # Pre-command scanning for OpenClaw is done by the TS plugin
            # calling `clawcare guard run` directly; this path is a no-op.
            sys.exit(0)
        else:
            exit_code = openclaw_handle_post(cfg)
        sys.exit(exit_code)

    click.echo(f"Unsupported platform: {platform}", err=True)
    sys.exit(1)


@guard.command("activate")
@click.option("--platform", required=True,
              type=click.Choice(["claude", "openclaw"], case_sensitive=False),
              help="Platform to install hooks for.")
@click.option("--settings", "settings_path", default=None,
              type=click.Path(),
              help="Path to platform settings file (auto-detected if omitted).")
@click.option("--project", is_flag=True, default=False,
              help="Install at project level instead of user level.")
def guard_activate(platform: str, settings_path: str | None, project: bool) -> None:
    """Install ClawCare guard hooks into a platform's config.

    \b
    Claude Code:
      Edits ~/.claude/settings.json (or project-level .claude/settings.json)
      to intercept Bash tool calls via PreToolUse and PostToolUse hooks.
    OpenClaw:
      Installs the ClawCare Guard TypeScript plugin into
      ~/.openclaw/extensions/clawcare-guard/ and enables it in
      ~/.openclaw/openclaw.json.
    """
    if platform == "claude":
        from clawcare.guard.activate import activate_claude, _resolve_binary_path

        dest = activate_claude(settings_path, project_level=project)
        binary = _resolve_binary_path()
        click.echo(f"✅ ClawCare guard hooks installed in {dest}")
        click.echo(f"   Binary path: {binary}")
        if binary == "clawcare":
            click.echo(
                "\n⚠  Warning: Could not resolve an absolute path for 'clawcare'.\n"
                "   Hooks will use the bare command name and rely on PATH.\n"
                "   If Claude Code cannot find the binary, re-activate after\n"
                "   ensuring 'clawcare' is on PATH or installed with pipx.",
                err=True,
            )
        return

    if platform == "openclaw":
        from clawcare.guard.activate import activate_openclaw, _resolve_binary_path

        dest = activate_openclaw(
            openclaw_home=settings_path,
        )
        binary = _resolve_binary_path()
        click.echo(f"✅ ClawCare guard plugin installed in {dest}")
        click.echo(f"   Binary path: {binary}")

        if binary == "clawcare":
            click.echo(
                "\n⚠  Warning: Could not resolve an absolute path for 'clawcare'.\n"
                "   The plugin will use the bare command name and rely on PATH.\n"
                "   Consider installing with `pipx install clawcare` or adding\n"
                "   the virtualenv bin directory to your shell PATH.",
                err=True,
            )
        return

    click.echo(f"Unsupported platform: {platform}", err=True)
    sys.exit(1)


@guard.command("deactivate")
@click.option("--platform", required=True,
              type=click.Choice(["claude", "openclaw"], case_sensitive=False),
              help="Platform to remove hooks from.")
@click.option("--settings", "settings_path", default=None,
              type=click.Path(),
              help="Path to platform settings file (auto-detected if omitted).")
def guard_deactivate(platform: str, settings_path: str | None) -> None:
    """Remove ClawCare guard hooks from a platform's config."""
    if platform == "claude":
        from clawcare.guard.activate import deactivate_claude

        removed = deactivate_claude(settings_path)
        if removed:
            click.echo("✅ ClawCare guard hooks removed.")
        else:
            click.echo("No ClawCare hooks found to remove.")
        return

    if platform == "openclaw":
        from clawcare.guard.activate import deactivate_openclaw

        removed = deactivate_openclaw(
            openclaw_home=settings_path,
        )
        if removed:
            click.echo("✅ ClawCare guard plugin removed.")
        else:
            click.echo("No ClawCare plugin found to remove.")
        return

    click.echo(f"Unsupported platform: {platform}", err=True)
    sys.exit(1)


@guard.command("status")
@click.option("--platform", required=True,
              type=click.Choice(["claude", "openclaw"], case_sensitive=False),
              help="Platform to check.")
@click.option("--settings", "settings_path", default=None,
              type=click.Path(),
              help="Path to platform settings file.")
def guard_status(platform: str, settings_path: str | None) -> None:
    """Check whether ClawCare guard hooks are installed."""
    if platform == "claude":
        from clawcare.guard.activate import is_claude_active

        active = is_claude_active(settings_path)
        if active:
            click.echo("ClawCare guard hooks: ACTIVE")
        else:
            click.echo("ClawCare guard hooks: NOT INSTALLED")
        return

    if platform == "openclaw":
        from clawcare.guard.activate import is_openclaw_active

        active = is_openclaw_active(
            openclaw_home=settings_path,
        )
        if active:
            click.echo("ClawCare guard plugin: ACTIVE")
        else:
            click.echo("ClawCare guard plugin: NOT INSTALLED")
        return

    click.echo(f"Unsupported platform: {platform}", err=True)
    sys.exit(1)


@guard.command("report")
@click.option("--since", "since", default=None,
              help="Filter events since relative time (e.g. 24h, 30m, 7d) or ISO timestamp.")
@click.option("--only-violations", is_flag=True, default=False,
              help="Show only events with matched findings.")
@click.option("--format", "fmt", default="text",
              type=click.Choice(["text", "json"], case_sensitive=False),
              help="Output format.")
@click.option("--limit", "limit", default=100, type=int,
              help="Max number of events to show (newest first).")
@click.option("--config", "config_path", default=None,
              type=click.Path(), help="Path to guard config file.")
@click.option("--log-path", "log_path", default=None,
              type=click.Path(), help="Override audit log path.")
def guard_report(
    since: str | None,
    only_violations: bool,
    fmt: str,
    limit: int,
    config_path: str | None,
    log_path: str | None,
) -> None:
    """Query and summarize ClawCare Guard audit history.

    Shows command execution history with findings and statuses.
    """
    import json

    import os

    from clawcare.guard.audit import read_audit_events
    from clawcare.guard.config import load_guard_config

    cfg = load_guard_config(config_path, scan_path=None if config_path else os.getcwd())
    effective_log = log_path or cfg.audit.log_path

    events = read_audit_events(
        log_path=effective_log,
        since=since,
        only_violations=only_violations,
    )

    events = list(reversed(events))
    if limit > 0:
        events = events[:limit]

    if fmt == "json":
        click.echo(json.dumps(events, indent=2, ensure_ascii=False))
        return

    if not events:
        click.echo("No audit events found for the selected filters.")
        return

    click.echo(f"ClawCare Guard Report ({len(events)} events)")
    click.echo("-" * 72)
    for event in events:
        ts = event.get("timestamp", "-")
        platform = event.get("platform", "-")
        kind = event.get("event", "-")
        status = event.get("status", event.get("decision", "-"))
        command = event.get("command", "")
        findings = event.get("findings", [])
        finding_text = ", ".join(findings) if findings else "none"
        click.echo(f"[{ts}] {platform} {kind} status={status}")
        click.echo(f"  cmd: {command}")
        click.echo(f"  findings: {finding_text}")
        if "exit_code" in event:
            click.echo(f"  exit_code: {event.get('exit_code')}")
        if "duration_ms" in event:
            click.echo(f"  duration_ms: {event.get('duration_ms')}")
        if event.get("error"):
            click.echo(f"  error: {event.get('error')}")
        click.echo()
