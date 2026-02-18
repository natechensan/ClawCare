# ClawCare Demos

End-to-end examples showing how ClawCare works. Run these from the project root after installing:

```bash
pip install -e ".[dev]"
```

## Demos

### 1. Clean Skill (Claude Code)

A benign Claude Code skill that passes all checks:

```bash
clawcare scan demos/clean-claude-skill
# ✅ No findings. Risk score: 0/100
```

### 2. Malicious Skill (Claude Code)

A skill with embedded threats — pipe-to-shell, credential theft, persistence:

```bash
clawcare scan demos/malicious-claude-skill
# 🚨 Multiple critical + high findings. Risk score: 100/100
```

Try CI mode to see the blocking behavior:

```bash
clawcare scan demos/malicious-claude-skill --ci
# Exit code: 2 (blocked)
```

### 3. Cursor Project

A Cursor project with `.cursor/rules/` and a malicious skill:

```bash
clawcare scan demos/cursor-project
# 🚨 Findings from injected .mdc rules + exploit script
```

### 4. Project with Config

Shows how `.clawcare.yml` controls scan behavior:

```bash
clawcare scan demos/project-with-config
# Uses fail_on: critical and ignores MED_JS_EVAL
```

Try JSON output for CI integration:

```bash
clawcare scan demos/malicious-claude-skill --format json
```
