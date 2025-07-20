# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Virtual Environment

**IMPORTANT**: This repository uses a virtual environment located at `.venv` in the repo root. Always activate it before running any commands:

```bash
source .venv/bin/activate
```

## Development Commands

### Testing
- `make test` - Run full test suite with coverage (must pass 80% threshold)
- `make test-fast` - Quick test run without coverage reporting
- `make test-unit` - Run only unit tests (exclude integration tests)
- `make test-integration` - Run only integration tests
- `make test-security` - Run security-specific tests
- `pytest tests/test_specific_module.py` - Run tests for specific module

### Code Quality
- `make lint` - Run all linting (ruff, mypy, black)
- `make format` - Auto-format code with black and isort
- `make mypy` - Type checking only
- `make ruff` - Linting only
- `make ruff-fix` - Auto-fix linting issues
- `make security-scan` - Run bandit and semgrep security analysis

### Development Setup
- `make dev-setup-uv` - Setup development environment with uv (recommended)
- `make dev-setup` - Setup development environment with pip
- `uv venv && source .venv/bin/activate` - Create and activate virtual environment
- `uv pip install -e ".[dev]"` - Install in development mode

### Building and Distribution
- `make build` - Build package for distribution
- `make clean` - Clean build artifacts and cache files

## Architecture Overview

This is a security analysis MCP (Model Context Protocol) server that provides vulnerability scanning capabilities through Cursor IDE integration. The system uses a hybrid approach combining traditional rule-based detection with optional AI-enhanced analysis.

### Core Components

#### MCP Server (`server.py`)
- Main MCP server implementation providing `adv_*` tools for Cursor IDE
- Tools include: `adv_scan_code`, `adv_scan_file`, `adv_diff_scan`, `adv_generate_exploit`
- Handles tool registration, parameter validation, and error handling

#### Scanning Engines
- **ScanEngine** (`scan_engine.py`) - Enhanced scanner combining multiple analysis methods
- **ASTScanner** (`ast_scanner.py`) - AST-based static analysis for Python/JS/TS
- **ThreatEngine** (`threat_engine.py`) - Rule-based pattern matching engine
- **LLMScanner** (`llm_scanner.py`) - AI-powered analysis prompts
- **GitDiffScanner** (`diff_scanner.py`) - Git diff-aware scanning for CI/CD

#### Supporting Systems
- **CredentialManager** (`credential_manager.py`) - Configuration and secrets management
- **ExploitGenerator** (`exploit_generator.py`) - Educational exploit generation
- **HotReload** (`hot_reload.py`) - Real-time rule updates during development

### Security Rules Architecture

Rules are organized in `rules/built-in/` by language and category:
- `python-rules.yaml` - Python-specific vulnerabilities (25+ rules)
- `javascript-rules.yaml` - JavaScript vulnerabilities (30+ rules) 
- `typescript-rules.yaml` - TypeScript-specific issues
- `web-security-rules.yaml` - Web application security (18+ rules)
- `api-security-rules.yaml` - API security patterns (15+ rules)
- `cryptography-rules.yaml` - Cryptographic vulnerabilities (15+ rules)
- `configuration-rules.yaml` - Configuration security issues (15+ rules)

Each rule includes:
- Pattern matching conditions (regex, AST patterns)
- Severity levels (low, medium, high, critical)
- Categories (injection, crypto, authentication, etc.)
- CWE and OWASP mappings
- Remediation guidance

### Key Workflows

#### Standard Vulnerability Scanning
1. Code is parsed by ASTScanner for language-specific analysis
2. ThreatEngine applies 95+ built-in rules
3. Results are categorized by severity and type
4. Optional LLM analysis provides additional context

#### Git Diff-Aware Scanning
1. GitDiffScanner identifies newly added lines between branches
2. Only new code is analyzed (not context lines or existing code)
3. Ideal for CI/CD pipelines to scan only changes
4. Prevents false positives from existing codebase

#### AI-Enhanced Analysis
1. Traditional rules provide baseline detection
2. LLM prompts analyze context and business logic
3. Results are merged with confidence scoring
4. Intelligent deduplication prevents duplicate findings

### Testing Strategy

- **Unit Tests**: Individual component testing with mocks
- **Integration Tests**: Full workflow testing with real files  
- **Security Tests**: Validate rule accuracy and exploit safety
- **Coverage**: Maintain 80%+ test coverage requirement
- **Markers**: Tests marked as `unit`, `integration`, `security`, `slow`

### Development Guidelines

#### Code Organization
- All source code in `src/adversary_mcp_server/`
- Comprehensive type hints required (mypy strict mode)
- Follow black formatting and isort import organization
- Use pydantic for data validation and serialization

#### Security Considerations
- This is a **defensive security tool** only
- Exploit generation includes safety warnings and educational context
- All analysis focuses on vulnerability detection and remediation
- No malicious code generation or attack facilitation

#### Error Handling
- Use `AdversaryToolError` for tool-specific failures
- Comprehensive logging with structured messages
- Graceful degradation when LLM analysis unavailable
- Input validation using pydantic models

### MCP Integration

The server provides tools for Cursor IDE through the MCP protocol:
- Configure in `.cursor/mcp.json` with Python path and environment variables
- Tools accept structured parameters with validation
- Results include detailed findings, metadata, and remediation guidance
- Hot-reload capability for real-time rule updates during development