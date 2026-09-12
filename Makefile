# Dev conveniences. Everything here is what CI runs, so `make check`
# passing locally means CI passes too.

VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

.DEFAULT_GOAL := help
.PHONY: help setup test lint fmt check clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv and install dev dependencies
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements-dev.txt
	@echo "Ready. PDF export also needs system libs -- see README."

test: ## Run the full test suite
	$(PY) -m pytest

lint: ## Lint (same rule selection as CI, via pyproject.toml)
	$(VENV)/bin/ruff check shared/ skills/ tests/

fmt: ## Apply ruff's safe autofixes
	$(VENV)/bin/ruff check --fix shared/ skills/ tests/

check: lint test ## Everything CI gates on
	$(PY) -m compileall -q shared skills
	@for s in skills/*/scripts/*.py; do $(PY) "$$s" --help >/dev/null || exit 1; done
	@echo "All checks passed."

clean: ## Remove caches and generated reports
	rm -rf .pytest_cache .ruff_cache reports/output
	find . -path ./$(VENV) -prune -o -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
