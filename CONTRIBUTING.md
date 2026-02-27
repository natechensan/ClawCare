# Contributing to ClawCare

Thank you for your interest in contributing! We use **GitHub Flow** — branch off `main`, open a PR, get a review, merge.

## Development Setup

```bash
git clone https://github.com/natechensan/ClawCare
cd ClawCare
make install     # install in dev mode with ruff + pytest
make check       # lint + test (run before opening a PR)
```

## Make Targets

| Command | What it does |
|---------|-------------|
| `make install` | Install in dev mode |
| `make lint` | Run ruff linter |
| `make format` | Auto-format code |
| `make test` | Run pytest |
| `make check` | Lint + test (pre-PR gate) |
