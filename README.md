# Adversary MCP Server

<div align="center">

[![PyPI version](https://badge.fury.io/py/adversary-mcp-server.svg)](https://badge.fury.io/py/adversary-mcp-server)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-997%20passed-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Coverage](https://img.shields.io/badge/coverage-75%25-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Version](https://img.shields.io/badge/version-v1.0.5-blue.svg)](https://pypi.org/project/adversary-mcp-server/)

**🔒 Enterprise-grade security analysis with AI-powered vulnerability detection and validation**

**We think about your vulns so you don't have to.**

[Installation](#installation) • [Quick Start](#quick-start) • [Cursor Setup](#cursor-ide-setup) • [CLI Usage](#cli-usage) • [MCP Tools](#mcp-tools) • [Architecture](#architecture)

</div>

---

## Features

- 🤖 **AI-Powered Analysis** - OpenAI/Anthropic LLM integration for intelligent vulnerability detection.
- 🎯 **Smart Validation** - Reduces false positives with LLM validation
- 🔍 **Multi-Engine Scanning** - Combines Semgrep static analysis & AI analysis
- 📊 **Interactive Dashboard** - Rich web-based telemetry with Chart.js visualizations and comprehensive analytics
- 🚀 **Git Diff Scanning** - Analyze only changed code for faster CI/CD integration
- 📦 **Monorepo Ready** - Optimized for large codebases with batch processing
- 📈 **Performance Telemetry** - Automatic tracking of all operations with SQLAlchemy backend

## Installation

### Prerequisites

- **Python 3.11+**
- **uv** - Modern Python package manager ([install](https://astral.sh/uv/))
- **Semgrep** - Static analysis engine ([install](https://semgrep.dev/docs/))

### Quick Install

```bash
# Install uv (recommended package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Semgrep
brew install semgrep  # macOS
# or
pip install semgrep   # Other platforms

# Install Adversary MCP Server
uv pip install adversary-mcp-server
```

### Verify Installation

```bash
adversary-mcp-cli --version
adversary-mcp-cli status
```

## Quick Start

### 1. Configure Security Engine

```bash
# Initial configuration
adversary-mcp-cli configure

# Set up AI provider (optional but recommended)
adversary-mcp-cli configure --llm-provider openai
# Enter your OpenAI API key when prompted

adversary-mcp-cli configure --llm-provider anthropic
# Enter your Anthropic API key when prompted

# Check configuration
adversary-mcp-cli status
```

### 2. Run Your First Scan

```bash
# Scan a single file
adversary-mcp-cli scan path/to/file.py

# Scan with AI validation (reduces false positives)
adversary-mcp-cli scan path/to/file.py --use-validation

# Scan entire directory
adversary-mcp-cli scan ./src --use-llm --use-validation
```

## Cursor IDE Setup

### Configure MCP Server

Create `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "adversary": {
      "command": "uv",
      "args": ["run", "adversary-mcp-server"],
    }
  }
}
```

<details>
<summary>Alternative setups (click to expand)</summary>

#### Using pip installation:
```json
{
  "mcpServers": {
    "adversary": {
      "command": "python",
      "args": ["-m", "adversary_mcp_server.server"],
    }
  }
}
```

#### For development:
```json
{
  "mcpServers": {
    "adversary": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "adversary_mcp_server.server"]
    }
  }
}
```
</details>

### Using MCP Tools in Cursor

Once configured, these tools are available in Cursor's chat:

- **Ask Cursor**: "Scan this file for security issues using adv_scan_file"
- **Ask Cursor**: "Check for vulnerabilities in the current project with adv_scan_folder"
- **Ask Cursor**: "Show me security issues in recent changes using adv_diff_scan"

## CLI Usage

### Basic Commands

```bash
# Configure the scanner
adversary-mcp-cli configure

# Check status and configuration
adversary-mcp-cli status

# Scan files or directories
adversary-mcp-cli scan <path> [options]

# Launch comprehensive telemetry dashboard
adversary-mcp-cli dashboard

# Manage false positives
adversary-mcp-cli mark-false-positive <finding-id>
adversary-mcp-cli unmark-false-positive <finding-id>
```

### Scanning Examples

```bash
# Basic scan
adversary-mcp-cli scan app.py

# Scan with AI analysis and validation
adversary-mcp-cli scan ./src --use-llm --use-validation

# Scan only changed files (great for CI/CD)
adversary-mcp-cli diff-scan main feature-branch

# Output results as JSON
adversary-mcp-cli scan ./src --json --output results.json

# Scan with specific severity threshold
adversary-mcp-cli scan ./src --min-severity high
```

### Dashboard Commands

```bash
# Launch comprehensive telemetry dashboard
adversary-mcp-cli dashboard

# Dashboard for specific time period
adversary-mcp-cli dashboard --hours 72

# Generate dashboard without auto-launch
adversary-mcp-cli dashboard --no-launch

# Check telemetry system status
adversary-mcp-cli status
```

### Advanced Options

```bash
--use-llm              # Enable AI-powered vulnerability assessment
--use-validation       # Enable false positive filtering
--use-semgrep         # Use Semgrep rules (default: true)
--min-severity        # Filter by severity (low/medium/high/critical)
--json                # Output as JSON
--output <file>       # Save results to file
--include-stats      # Include performance metrics
```

## MCP Tools

### Available Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `adv_scan_code` | Scan code snippets | "Scan this code for vulnerabilities" |
| `adv_scan_file` | Scan specific files | "Check security issues in auth.py" |
| `adv_scan_folder` | Scan directories | "Analyze the src folder for vulnerabilities" |
| `adv_diff_scan` | Scan git changes | "Show security issues in recent commits" |
| `adv_configure_settings` | Update configuration | "Configure OpenAI for security scanning" |
| `adv_get_status` | Check server status | "Is the security scanner configured?" |
| `adv_mark_false_positive` | Mark false positives | "Mark finding XYZ as false positive" |

### MCP Tool Examples

```typescript
// In Cursor, ask the AI assistant:

// Scan current file
"Use adv_scan_file to check this file for security issues"

// Scan with validation
"Run adv_scan_file on auth.py with validation enabled"

// Check recent changes
"Use adv_diff_scan to analyze changes between main and my branch"

```

## Dashboard & Telemetry

### Comprehensive HTML Dashboard

The scanner includes a rich web-based dashboard for comprehensive telemetry analysis:

```bash
# Launch interactive dashboard
adversary-mcp-cli dashboard

# Open dashboard for specific time period
adversary-mcp-cli dashboard --hours 48

# Generate dashboard without auto-launch
adversary-mcp-cli dashboard --no-launch
```

**Dashboard Features:**
- 📊 **Interactive Charts** - Real-time performance metrics with Chart.js visualizations
- 🔍 **MCP Tool Analytics** - Track tool usage, success rates, and performance across Cursor IDE
- ⚡ **Scan Engine Metrics** - Monitor Semgrep, LLM, and validation performance
- 💾 **Cache Performance** - Analyze cache hit rates and efficiency
- 🎯 **Threat Analysis** - Categorize findings by severity and confidence
- 🏥 **System Health** - CPU, memory, and database performance monitoring
- 📈 **Language Performance** - Track scanning efficiency by programming language
- 🕒 **Recent Activity** - Timeline view of recent scans and operations

### Performance Metrics

Include `--include-stats` to see detailed metrics:

```json
{
  "performance_metrics": {
    "total_files": 200,
    "files_scanned": 200,
    "total_time": 45.2,
    "files_per_second": 4.42,
    "llm_usage": {
      "total_tokens": 125000,
      "total_cost": 0.38,
      "api_calls": 25
    }
  }
}
```

### Telemetry System

Adversary MCP Server includes comprehensive telemetry tracking:

- **Automatic Collection** - All MCP tools, CLI commands, and scan operations are automatically tracked
- **SQLAlchemy Backend** - Production-quality database with rich query capabilities
- **Zero Configuration** - Telemetry works out-of-the-box with no setup required
- **Privacy First** - All data stored locally, never transmitted to external services
- **Performance Insights** - Identify bottlenecks and optimize scanning workflows
- **Usage Analytics** - Understand tool usage patterns and effectiveness

## Architecture

<div align="center">

```mermaid
graph TB
    subgraph "Client Layer"
        A[Cursor IDE]
        B[CLI Interface]
        C[Web Dashboard]
    end

    subgraph "MCP Server"
        D[Protocol Handler]
        E[Tool Registry]
    end

    subgraph "Scan Engine"
        F[Orchestrator]
        G[Semgrep Scanner]
        H[LLM Scanner]
        I[Git Diff Scanner]
    end

    subgraph "AI Validation"
        J[LLM Validator]
        K[False Positive Filter]
    end

    subgraph "Telemetry System"
        L[Metrics Orchestrator]
        M[Telemetry Service]
        N[SQLAlchemy Database]
        O[HTML Dashboard Generator]
    end

    subgraph "Results"
        P[Finding Aggregator]
        Q[Report Generator]
    end

    A -->|MCP Protocol| D
    B -->|Direct Call| F
    C -->|Web Interface| O
    D --> E
    E --> F

    F --> G
    F --> H
    F --> I
    F -.->|Track Performance| L

    G --> P
    H --> P
    I --> P

    P --> J
    J --> K
    K --> Q

    L --> M
    M --> N
    M --> O
    D -.->|Track MCP Tools| L
    B -.->|Track CLI Commands| L

    style F fill:#e1f5fe
    style J fill:#f3e5f5
    style G fill:#e8f5e8
    style H fill:#fff3e0
    style L fill:#fff8e1
    style O fill:#f1f8e9
```

</div>

### How It Works

1. **Multi-Engine Scanning**: Combines Semgrep rules with LLM analysis
2. **Intelligent Validation**: LLM validator reduces false positives
3. **Batch Processing**: Optimizes API calls for large codebases
4. **Git Integration**: Focuses on changed code for faster CI/CD
5. **Comprehensive Telemetry**: Automatic performance tracking with SQLAlchemy backend
6. **Interactive Dashboard**: Rich web-based analytics with Chart.js visualizations
7. **Zero-Config Monitoring**: Telemetry works out-of-the-box with automatic migration

## Configuration

### Environment Variables

```bash
# Core settings
ADVERSARY_WORKSPACE_ROOT=/path/to/project
ADVERSARY_LOG_LEVEL=INFO

# LLM Configuration (optional)
ADVERSARY_LLM_PROVIDER=openai
ADVERSARY_LLM_MODEL=gpt-4-turbo-preview

# Performance tuning
ADVERSARY_MAX_CONCURRENT_SCANS=8
ADVERSARY_CACHE_SIZE_MB=200
```

### Configuration File

Settings are stored in `~/.adversary/config.json`:

```json
{
  "llm_provider": "openai",
  "enable_validation": true,
  "severity_threshold": "medium",
  "enable_caching": true,
  "telemetry_enabled": true,
  "dashboard_auto_launch": true
}
```

### Dashboard Configuration

The telemetry system creates a unified SQLAlchemy database at:
- **Location**: `~/.local/share/adversary-mcp-server/cache/adversary.db`
- **Migration**: Existing JSON metrics automatically migrated on first dashboard use
- **Retention**: Data retained indefinitely for historical analysis (configurable)

```bash
# Check telemetry status
adversary-mcp-cli status

# Manually run migration (if needed)
python -m adversary_mcp_server.migration.database_migration
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          pip install uv
          uv pip install adversary-mcp-server

      - name: Run security scan
        run: |
          adversary-mcp-cli diff-scan origin/main HEAD \
            --use-validation \
            --min-severity medium \
            --json \
            --output scan-results.json

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan
          path: scan-results.json
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/brettbergin/adversary-mcp-server.git
cd adversary-mcp-server

# Create virtual environment with uv
uv venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install in development mode
uv pip install -e ".[dev]"

# Run tests
make test

# Run with live reload
make dev
```

### Running Tests

```bash
# Full test suite (includes telemetry and dashboard tests)
make test

# Quick tests (no coverage)
make test-fast

# Specific test modules
pytest tests/test_scanner.py -v
pytest tests/test_telemetry_system.py -v
pytest tests/test_dashboard_system.py -v

# Run only integration tests
make test-integration

# Run security-specific tests
make test-security
```

## Support

- 📖 [Documentation](https://github.com/brettbergin/adversary-mcp-server/wiki)
- 🐛 [Report Issues](https://github.com/brettbergin/adversary-mcp-server/issues)
- 💬 [Discussions](https://github.com/brettbergin/adversary-mcp-server/discussions)
- 📧 Contact: brettbergin@gmail.com

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

---

<div align="center">
Made with ❤️ for software security.
</div>
