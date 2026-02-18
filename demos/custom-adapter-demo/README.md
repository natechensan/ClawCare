# Custom Adapter Demo

This demo shows how to write a custom ClawCare adapter for any AI agent platform.

The example adapter scans a hypothetical **Acme Agent** platform that stores skills
in `.acme/skills/` directories with `skill.toml` manifests.

## Try It

```bash
# From the ClawCare repo root
PYTHONPATH=demos/custom-adapter-demo \
  clawcare scan demos/custom-adapter-demo \
  --adapter import:acme_adapter:AcmeAdapter
```

You should see findings from the `evil-tool` skill (pipe-to-shell, credential theft)
while `safe-helper` produces zero findings.

## How It Works

See [`acme_adapter.py`](acme_adapter.py) — it implements four methods:

| Method | Purpose |
|--------|---------|
| `detect()` | Returns confidence 0.0–1.0 that a directory is an Acme project |
| `discover_roots()` | Finds each skill under `.acme/skills/` |
| `scan_scope()` | Limits scanning to relevant file types within each skill |
| `default_manifest()` | Points to `clawcare.manifest.yml` if present |
