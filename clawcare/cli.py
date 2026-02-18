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
    result.compute_risk_score()
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
