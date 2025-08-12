.PHONY: help install test test-fast test-cov test-html lint format clean check-all build upload install-pre-commit pre-commit pre-commit-update uninstall-pre-commit
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install package in development mode with all dependencies
	@echo "Installing adversary-mcp-server with all dependencies..."
	uv pip install --upgrade pip
	uv pip install --upgrade -e ".[dev]"
	@echo "Verifying installation..."
	@make check-deps
	@echo "Installation complete!"

sync: ## Sync dependencies using uv
	uv pip sync

install-deps: ## Install only the runtime dependencies (no dev)
	uv pip install --upgrade -e .

reinstall: ## Uninstall and reinstall the package with all dependencies
	uv pip uninstall adversary-mcp-server || true
	uv pip install --upgrade -e ".[dev]"
	@make check-deps

check-deps: ## Check if all dependencies are installed
	@echo "Checking dependencies..."
	@python -c "import aiohttp; print('✓ aiohttp installed')" 2>/dev/null || echo "✗ aiohttp missing - run 'make install' to fix"
	@python -c "import questionary; print('✓ questionary installed')" 2>/dev/null || echo "✗ questionary missing - run 'make install' to fix"
	@python -c "import mcp; print('✓ mcp installed')" 2>/dev/null || echo "✗ mcp missing - run 'make install' to fix"
	@python -c "import semgrep; print('✓ semgrep installed')" 2>/dev/null || echo "✗ semgrep missing - run 'make install' to fix"
	@python -c "import openai; print('✓ openai installed')" 2>/dev/null || echo "✗ openai missing - run 'make install' to fix"
	@python -c "import anthropic; print('✓ anthropic installed')" 2>/dev/null || echo "✗ anthropic missing - run 'make install' to fix"

lock: ## Generate uv.lock file
	uv pip compile pyproject.toml -o uv.lock
	uv pip compile --extra dev pyproject.toml -o uv-dev.lock

test: ## Run all tests with coverage and fail if coverage < 75%
	python -m pytest --cov=adversary_mcp_server --cov-report=term-missing --cov-fail-under=75 -v

test-html: ## Run tests and generate HTML coverage report
	python -m pytest --cov=adversary_mcp_server --cov-report=html --cov-report=term-missing -v
	@echo "Coverage report available at htmlcov/index.html"

test-unit: ## Run only unit tests (skip integration tests)
	python -m pytest -m "not integration" -v

test-integration: ## Run only integration tests
	python -m pytest -m "integration" -v

test-security: ## Run only security-related tests
	python -m pytest -m "security" -v

benchmark: ## Run performance benchmarks
	uv run pytest -m "benchmark" --benchmark-verbose

benchmark-save: ## Run benchmarks and save results to .benchmarks/
	@mkdir -p .benchmarks
	uv run pytest -m "benchmark" --benchmark-json=.benchmarks/benchmark_$(shell date +%Y%m%d_%H%M%S).json --benchmark-verbose

benchmark-compare: ## Run benchmarks and compare with previous results
	@mkdir -p .benchmarks
	uv run pytest -m "benchmark" --benchmark-compare --benchmark-compare-fail=mean:5% --benchmark-json=.benchmarks/latest.json

benchmark-only: ## Run only the benchmark tests without any other tests
	uv run pytest tests/test_benchmarks.py -v --benchmark-verbose

benchmark-skip: ## Run all tests except benchmarks (this is the default behavior)
	uv run pytest -m "not benchmark" -v

test-validation: ## Run validation regression tests to prevent validation bugs
	@echo "🔍 Running validation regression tests..."
	uv run pytest tests/scanner/test_validation_regression.py tests/integration/test_validation_symmetry.py -v --tb=short -m "not slow"
	@echo "✅ Validation regression tests completed!"

test-validation-critical: ## Run critical validation tests (fast subset)
	@echo "🚨 Running critical validation tests..."
	uv run pytest tests/scanner/test_validation_regression.py -v --tb=short -k "test_directory_scan_validation_enabled_with_threats or test_file_scan_validation_enabled_with_threats"
	@echo "✅ Critical validation tests completed!"

test-validation-full: ## Run full validation test suite including slow integration tests
	@echo "🔍 Running full validation test suite..."
	uv run pytest tests/scanner/test_validation_regression.py tests/integration/test_validation_symmetry.py tests/scanner/test_llm_validator.py -v --tb=short
	@echo "✅ Full validation test suite completed!"

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
	.venv/bin/semgrep scan --config=auto src/

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

dev-setup-uv: ## Set up development environment using uv (faster)
	@echo "Setting up development environment with uv..."
	uv venv || true
	. .venv/bin/activate && uv pip install --upgrade pip
	. .venv/bin/activate && uv pip install --upgrade -e ".[dev]"
	. .venv/bin/activate && make check-deps
	@echo "Development environment setup complete with uv!"
	@echo "Activate the environment with: source .venv/bin/activate"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make lint' to run linting"
	@echo "Run 'make help' to see all available commands"

uv-init: ## Initialize uv virtual environment
	uv venv
	@echo "Virtual environment created. Activate with: source .venv/bin/activate"

uv-upgrade: ## Upgrade all dependencies to latest versions
	uv pip install --upgrade pip
	uv pip install --upgrade -e ".[dev]"
	@make check-deps

# CI targets
ci-test: ## Run tests in CI environment
	python -m pytest --cov=adversary_mcp_server --cov-report=xml --cov-report=term-missing --cov-fail-under=75 -v

ci-lint: ## Run linting in CI environment
	python -m ruff check src/ tests/
	python -m mypy src/
	python -m black --check src/ tests/
	python -m isort --check-only src/ tests/

ci-security: ## Run security scans in CI environment
	python -m semgrep scan --config=auto src/ --json --output=semgrep-report.json

deploy: build ## Upload package to PyPI
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
