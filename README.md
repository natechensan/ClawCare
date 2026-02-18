# 🦞ClawCare

**Security scanner for AI agent skills and plugins — catch malicious attacks before they execute.**

ClawCare scans AI agent skills, plugins, and rules for supply-chain threats like command injection, credential theft, and data extraction. It enforces permission policies, and can be used as a CLI tool or integrated into CI/CD pipelines.

## Why

AI coding agents (Claude Code, Cursor, Codex, OpenClaw) let you install third-party skills and plugins that can read your files, run commands, access secrets and extract sensitive data. A malicious skill can:

- Pipe remote scripts into your shell (`curl ... | bash`)
- Steal SSH keys and API tokens
- Set up cron persistence
- Transfer PII data to external servers

ClawCare catches these patterns **before** they run and gives you full visibility into the risks.

## Demo

See ClawCare block a malicious PR in real-time:

👉 **[ClawCare Demo](https://github.com/natechensan/ClawCare-demo)** — fork it, open a PR with a sketchy skill, and watch CI fail.

## Quick Start

### Install

```bash
pip install clawcare
```

### Scan

```bash
# Scan a project — auto-detects the platform
clawcare scan .

# CI mode — exit code 2 on HIGH+ findings (use in GitHub Actions)
clawcare scan . --ci

# JSON output for downstream tooling
clawcare scan . --format json --json-out report.json
```

### Configure

Drop a `.clawcare.yml` in your project root to customize scan behavior:

```yaml
scan:
  fail_on: high          # block CI on high+ findings
  ignore_rules:
    - MED_JS_EVAL        # suppress rules you've accepted
  exclude:
    - "vendor/**"        # skip directories
```

CLI flags override config values. See [Project Configuration](#%EF%B8%8F-project-configuration) for the full reference.

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
Risk score: 100/100 (critical)
============================================================
```

## Features

### 27 Built-in Rules

Two rulesets ship by default:

| Ruleset | Rules | Catches |
|---------|-------|---------|
| `command-injection` | 15 | Pipe-to-shell, reverse shells, credential theft, persistence, destructive commands, subprocess abuse |
| `sensitive-data` | 12 | Hardcoded AWS keys, SSH keys, API tokens, SSN/credit card numbers, IP addresses |

All rules include [CWE](https://cwe.mitre.org/) references where applicable.

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

### Project Configuration

Create a `.clawcare.yml` in your project root:

```yaml
scan:
  fail_on: high              # minimum severity to block CI (critical | high | medium | low)
  block_local: false         # block locally too? (default: warn only)
  ignore_rules:
    - MED_JS_EVAL            # suppress specific rules
  exclude:
    - "vendor/**"            # skip directories
  max_file_size_kb: 512      # skip large files
  rulesets:
    - default                # built-in rules (included by default)
    - ./my-custom-rules      # add your own
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

## CI Integration

### GitHub Actions

```yaml
- name: Install ClawCare
  run: pip install clawcare

- name: Scan for malicious extensions
  run: clawcare scan . --ci
```

Full workflow example: [ClawCare Demo CI](https://github.com/natechen/ClawCare-demo/blob/main/.github/workflows/clawcare.yml)

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

## Development

```bash
git clone https://github.com/natechen/ClawCare
cd ClawCare
make install     # install in dev mode with ruff + pytest
make check       # lint + test (run before opening a PR)
```

Available make targets:

| Command | What it does |
|---------|-------------|
| `make install` | Install in dev mode |
| `make lint` | Run ruff linter |
| `make format` | Auto-format code |
| `make test` | Run pytest |
| `make check` | Lint + test (pre-PR gate) |

We use **GitHub Flow** — branch off `main`, open a PR, get a review, merge.

## License

[Apache 2.0](LICENSE)
