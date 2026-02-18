.PHONY: install lint format test check clean build release

install:  ## Install in dev mode with all dependencies
	pip install -e ".[dev]"

lint:  ## Run linter (ruff check)
	ruff check clawcare/ tests/

format:  ## Auto-format code (ruff format + isort)
	ruff format clawcare/ tests/
	ruff check --fix --select I clawcare/ tests/

test:  ## Run tests
	pytest

check: lint test  ## Run lint + tests (use before opening a PR)

clean:  ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: clean check  ## Build source and wheel distribution
	python -m build

release: build  ## Upload to PyPI (requires credentials)
	python -m twine upload dist/*

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
