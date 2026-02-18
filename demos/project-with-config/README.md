# Project with ClawCare Config

This demo shows how `.clawcare.yml` controls scan behavior.

The config in this project:
- Sets `fail_on: critical` (only critical findings block CI)
- Ignores `MED_JS_EVAL` (this project uses eval intentionally)
- Excludes `vendor/` from scanning

Try scanning:

```bash
clawcare scan demos/project-with-config
```

Compare with scanning without the config:

```bash
clawcare scan demos/project-with-config --ruleset default
```
