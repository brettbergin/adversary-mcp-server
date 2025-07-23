.PHONY: help install test test-fast test-cov test-html lint format clean check-all build upload install-pre-commit pre-commit pre-commit-update uninstall-pre-commit
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install package in development mode with all dependencies
	pip install -e ".[dev]"

install-uv: ## Install package using uv (faster)
	uv pip install -e ".[dev]"

sync: ## Sync dependencies using uv
	uv pip sync

lock: ## Generate uv.lock file
	uv pip compile pyproject.toml -o uv.lock
	uv pip compile --extra dev pyproject.toml -o uv-dev.lock

test: ## Run all tests with coverage and fail if coverage < 80%
	python -m pytest --cov=adversary_mcp_server --cov-report=term-missing --cov-fail-under=80 -v

test-fast: ## Run tests without coverage for faster feedback
	python -m pytest -v --tb=short

test-cov: ## Run tests with coverage report but don't fail on coverage threshold
	python -m pytest --cov=adversary_mcp_server --cov-report=term-missing -v

test-html: ## Run tests and generate HTML coverage report
	python -m pytest --cov=adversary_mcp_server --cov-report=html --cov-report=term-missing -v
	@echo "Coverage report available at htmlcov/index.html"

test-unit: ## Run only unit tests (skip integration tests)
	python -m pytest -m "not integration" -v

test-integration: ## Run only integration tests
	python -m pytest -m "integration" -v

test-security: ## Run only security-related tests
	python -m pytest -m "security" -v

lint: ## Run all linting tools
	python -m ruff check src/ tests/
	python -m mypy src/
	python -m black --check src/ tests/

format: ## Format code with black and isort
	python -m black src/ tests/
	python -m isort src/ tests/

format-check: ## Check if code formatting is correct
	python -m black --check src/ tests/
	python -m isort --check-only src/ tests/

mypy: ## Run mypy type checking
	python -m mypy src/

ruff: ## Run ruff linting
	python -m ruff check src/ tests/

ruff-fix: ## Run ruff with auto-fix
	python -m ruff check --fix src/ tests/

security-scan: ## Run security scans on the codebase
	.venv/bin/semgrep --config=auto src/

clean: ## Clean up build artifacts and cache files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf reports/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: ## Build package for distribution
	uv build

check-all: lint test security-scan ## Run all checks (linting, tests, and security scans)

dev-setup: install install-pre-commit ## Set up development environment
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make lint' to run linting"
	@echo "Run 'make security-scan' to run security scans"
	@echo "Run 'make help' to see all available commands"

dev-setup-uv: install-uv install-pre-commit ## Set up development environment using uv (faster)
	@echo "Development environment setup complete with uv!"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make lint' to run linting"
	@echo "Run 'make security-scan' to run security scans"
	@echo "Run 'make help' to see all available commands"

uv-init: ## Initialize uv virtual environment
	uv venv
	@echo "Virtual environment created. Activate with: source .venv/bin/activate"

uv-upgrade: ## Upgrade all dependencies to latest versions
	uv pip install --upgrade -e ".[dev]"

# CI targets
ci-test: ## Run tests in CI environment
	python -m pytest --cov=adversary_mcp_server --cov-report=xml --cov-report=term-missing --cov-fail-under=80 -v

ci-lint: ## Run linting in CI environment
	python -m ruff check src/ tests/
	python -m mypy src/
	python -m black --check src/ tests/
	python -m isort --check-only src/ tests/

ci-security: ## Run security scans in CI environment
	python -m semgrep --config=auto src/ --json --output=semgrep-report.json

upload: build ## Upload package to PyPI
	uv run twine upload dist/*

demo: ## Run a demo of the adversary MCP server
	python -m adversary_mcp_server.cli demo

scan-example: ## Run security scan on example files
	python -m adversary_mcp_server.cli scan examples/

# Pre-commit hooks
install-pre-commit: ## Install pre-commit hooks
	pre-commit install
	@echo "Pre-commit hooks installed. They will run automatically on commit."

pre-commit: ## Run pre-commit hooks on all files
	pre-commit run --all-files

pre-commit-update: ## Update pre-commit hook versions
	pre-commit autoupdate

uninstall-pre-commit: ## Uninstall pre-commit hooks
	pre-commit uninstall
	@echo "Pre-commit hooks uninstalled."
