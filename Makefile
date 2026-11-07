# Dev conveniences. Everything here is what CI runs, so `make check`
# passing locally means CI passes too.

VENV  := .venv
PY    := $(VENV)/bin/python
PIP   := $(VENV)/bin/pip
# Re-installs whenever a requirements file is newer than the last install,
# so a Dependabot floor bump can't leave the local venv testing older
# versions than CI does.
STAMP := $(VENV)/.requirements-stamp

.DEFAULT_GOAL := help
.PHONY: help setup test lint fmt check cov clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

$(STAMP): requirements.txt requirements-dev.txt
	@test -x $(PY) || python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet --upgrade -r requirements-dev.txt
	@touch $@

setup: $(STAMP) ## Create the venv and install dev dependencies
	@echo "Ready. PDF export also needs system libs -- see README."

test: $(STAMP) ## Run the full test suite
	$(PY) -m pytest

cov: $(STAMP) ## Test suite with line coverage over shared/ and skills/
	$(PY) -m pytest -q --cov=shared --cov=skills --cov-report=term-missing

lint: $(STAMP) ## Lint (same rule selection as CI, via pyproject.toml)
	$(VENV)/bin/ruff check shared/ skills/ tests/

fmt: $(STAMP) ## Apply ruff's safe autofixes
	$(VENV)/bin/ruff check --fix shared/ skills/ tests/

check: lint test ## Everything CI gates on
	$(PY) -m compileall -q shared skills
	@for s in skills/*/scripts/*.py; do $(PY) "$$s" --help >/dev/null || exit 1; done
	@echo "All checks passed."

clean: ## Remove caches and generated reports
	rm -rf .pytest_cache .ruff_cache reports/output
	find . -path ./$(VENV) -prune -o -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
