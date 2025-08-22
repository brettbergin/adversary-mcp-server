# Adversary MCP Server

<div align="center">

[![PyPI version](https://badge.fury.io/py/adversary-mcp-server.svg)](https://badge.fury.io/py/adversary-mcp-server)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-997%20passed-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Coverage](https://img.shields.io/badge/coverage-75%25-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Version](https://img.shields.io/badge/version-v1.10.6-blue.svg)](https://pypi.org/project/adversary-mcp-server/)

**🔒 Clean Architecture security analysis with AI-powered vulnerability detection and validation**

**We think about your vulns so you don't have to.**

[Installation](#installation) • [Quick Start](#quick-start) • [Claude Code Setup](#claude-code-setup) • [Cursor Setup](#cursor-ide-setup) • [CLI Usage](#cli-usage) • [MCP Tools](#mcp-tools) • [Architecture](#architecture)

</div>

---

## Features

- **AI-Powered Analysis** - OpenAI/Anthropic LLM integration for intelligent vulnerability detection
- **Smart Validation** - Reduces false positives with LLM validation (70% confidence threshold)
- **Multi-Engine Scanning** - Combines Semgrep static analysis & AI analysis
- **Automatic Persistence** - Auto-saves scan results in JSON, Markdown, and CSV formats
- **MCP Integration** - Native support for Claude Code and Cursor IDE
- **Comprehensive CLI** - Full command-line interface with all scanning capabilities
- **Rich Telemetry** - Comprehensive tracking with dashboard visualization

## Installation

### Prerequisites

- **Python 3.10+** (tested on 3.11, 3.12, 3.13)
- **Semgrep** - Static analysis engine ([install](https://semgrep.dev/docs/))

### Quick Install

```bash
# Install python uv
brew install uv

# Install Semgrep (required)
brew install semgrep  # macOS
# or
pip install semgrep   # Other platforms

# Install Adversary MCP Server
uv pip install adversary-mcp-server
```

### Verify Installation

```bash
adv --version
adv status
```

## Quick Start

### 1. Configure Security Engine

```bash
# Initial setup (interactive)
adv configure setup

# Or configure directly with options
adv configure --llm-provider openai --llm-api-key $OPENAI_API_KEY
adv configure --llm-provider anthropic --llm-api-key $ANTHROPIC_API_KEY

# Check configuration status
adv status
```

### 2. Run Your First Scan

```bash
# Scan a single file (basic)
adv scan-file path/to/file.py

# Scan with AI analysis and validation (recommended)
adv scan-file path/to/file.py --use-llm --use-validation

# Scan entire directory
adv scan-folder ./src --use-llm --use-validation

# Scan code snippet directly
adv scan-code "print('Hello World')" --language python
```

### 3. View Comprehensive Dashboard

```bash
# Launch interactive telemetry dashboard
adv dashboard
```

## Claude Code Setup

### Configure MCP Server

Create or update `~/.config/claude-code/mcp.json`:

```json
{
    "mcpServers": {
        "adversary": {
            "command": "uvx",
            "args": ["adversary-mcp-server"]
        }
    }
}
```

### Using MCP Tools in Claude Code

Once configured, these tools are available in Claude Code:

- **Ask Claude**: "Scan this file for security issues using adv_scan_file"
- **Ask Claude**: "Check for vulnerabilities in the current project with adv_scan_folder"
- **Ask Claude**: "Analyze this code snippet for security issues using adv_scan_code"

## Cursor IDE Setup

### Configure MCP Server

Create `.cursor/mcp.json` in your project:

```json
{
    "mcpServers": {
        "adversary": {
            "command": "uvx",
            "args": ["adversary-mcp-server"]
        }
    }
}
```

<details>
<summary>Alternative Cursor setups (click to expand)</summary>

#### Using pip installation:
```json
{
  "mcpServers": {
    "adversary": {
      "command": "python",
      "args": ["-m", "adversary_mcp_server.sync_main"]
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
      "args": ["-m", "adversary_mcp_server.sync_main"]
    }
  }
}
```
</details>

### Using MCP Tools in Cursor

Once configured, these tools are available in Cursor's chat:

- **Ask Cursor**: "Scan this file for security issues using adv_scan_file"
- **Ask Cursor**: "Check for vulnerabilities in the current project with adv_scan_folder"
- **Ask Cursor**: "Analyze this code snippet for security issues using adv_scan_code"

## CLI Usage

### Basic Commands

```bash
# Configure the scanner
adv configure setup

# Check status and configuration
adv status

# Scan individual files
adv scan-file <file-path> [options]

# Scan directories
adv scan-folder <directory-path> [options]

# Scan code snippets
adv scan-code <code-content> --language <lang> [options]

# Launch comprehensive telemetry dashboard
adv dashboard
```

### Scanning Examples

```bash
# Basic file scan
adv scan-file app.py

# Scan with AI analysis and validation (recommended)
adv scan-file app.py --use-llm --use-validation

# Directory scan with full analysis
adv scan-folder ./src --use-llm --use-validation

# Code snippet scan
adv scan-code "SELECT * FROM users WHERE id = ?" --language sql

# Scan with specific severity threshold
adv scan-file app.py --severity high

# Output results in different formats
adv scan-file app.py --output-format json --output-file results.json
adv scan-file app.py --output-format markdown --verbose
```

### Configuration Commands

```bash
# Interactive setup
adv configure setup

# Direct configuration
adv configure --llm-provider openai --llm-api-key your-key
adv configure --llm-provider anthropic --llm-api-key your-key

# Reset configuration
adv configure reset

# Check current configuration
adv status
```

### Available Options

```bash
--use-llm / --no-llm              # Enable/disable AI analysis
--use-validation / --no-validation # Enable/disable false positive filtering
--use-semgrep / --no-semgrep      # Enable/disable Semgrep analysis (default: true)
--severity [low|medium|high|critical] # Minimum severity threshold
--output-format [json|markdown|csv]   # Output format for results
--output-file <file>              # Save results to specific file
--verbose                         # Verbose output with detailed information
```

## MCP Tools

### Available Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `adv_scan_code` | Scan code snippets directly | "Scan this code for vulnerabilities" |
| `adv_scan_file` | Scan specific files with full analysis | "Check security issues in auth.py" |
| `adv_scan_folder` | Scan entire directories recursively | "Analyze the src folder for vulnerabilities" |
| `adv_get_status` | Check server status and capabilities | "Is the security scanner configured?" |
| `adv_get_version` | Get server version information | "What version is running?" |
| `adv_mark_false_positive` | Mark findings as false positives | "Mark finding XYZ as false positive" |
| `adv_unmark_false_positive` | Remove false positive marking | "Unmark finding ABC as false positive" |

### MCP Tool Examples

```typescript
// In Claude Code or Cursor, ask the AI assistant:

// Scan current file with full analysis
"Use adv_scan_file to check this file for security issues with LLM validation"

// Scan directory with specific options
"Run adv_scan_folder on the src directory with severity threshold of high"

// Scan code snippet
"Use adv_scan_code to analyze this SQL query for injection vulnerabilities"

// Check scanner status
"Use adv_get_status to see what scan engines are available"
```

### Automatic Result Persistence

All MCP tools automatically save scan results in multiple formats:

- **JSON**: `.adversary.json` - Machine-readable results with full metadata
- **Markdown**: `.adversary.md` - Human-readable report with remediation guidance
- **CSV**: `.adversary.csv` - Spreadsheet-compatible format for analysis

Results are automatically placed alongside scanned files/directories with intelligent conflict resolution.

## Dashboard & Telemetry

### Comprehensive HTML Dashboard

The scanner includes a rich web-based dashboard for comprehensive telemetry analysis:

```bash
# Launch interactive dashboard
adv dashboard
```

**Dashboard Features:**
- **MCP Tool Analytics** - Track tool usage, success rates, and performance
- **Scan Engine Metrics** - Monitor Semgrep, LLM, and validation performance
- **Threat Analysis** - Categorize findings by severity and confidence
- **System Health** - Performance monitoring and statistics
- **Language Analysis** - Track scanning efficiency by programming language
- **Recent Activity** - Timeline view of recent scans and operations

### Telemetry System

Adversary MCP Server includes comprehensive telemetry tracking:

- **Automatic Collection** - All MCP tools, CLI commands, and scan operations are automatically tracked
- **Local Storage** - All data stored locally, never transmitted to external services
- **Zero Configuration** - Telemetry works out-of-the-box with no setup required
- **Performance Insights** - Identify bottlenecks and optimize scanning workflows
- **Usage Analytics** - Understand tool usage patterns and effectiveness

## Architecture

### Implementation

Adversary MCP Server is built using **Clean Architecture** principles with Domain-Driven Design (DDD), ensuring separation of concerns, maintainability, and testability.

<div align="center">

```mermaid
graph TB
    subgraph "🖥️ **Presentation Layer**"
        A[Cursor IDE]
        B[CLI Interface]
        C[Web Dashboard]
    end

    subgraph "🔧 **Application Layer**"
        D[MCP Server]
        E[CLI Commands]
        F[Adapters]
        subgraph "Adapters"
            F1[SemgrepAdapter]
            F2[LLMAdapter]
            F3[ValidationAdapter]
        end
    end

    subgraph "🏛️ **Domain Layer (Business Logic)**"
        subgraph "Entities"
            G[ScanRequest]
            H[ScanResult]
            I[ThreatMatch]
        end
        subgraph "Value Objects"
            J[ScanContext]
            K[SeverityLevel]
            L[ConfidenceScore]
            M[FilePath]
        end
        subgraph "Domain Services"
            N[ScanOrchestrator]
            O[ThreatAggregator]
            P[ValidationService]
        end
        subgraph "Interfaces"
            Q[IScanStrategy]
            R[IValidationStrategy]
        end
    end

    subgraph "⚙️ **Infrastructure Layer**"
        S[SemgrepScanner]
        T[LLMScanner]
        U[LLMValidator]
        V[SQLAlchemy Database]
        W[File System]
        X[Git Operations]
        Y[Telemetry System]
    end

    A -->|MCP Protocol| D
    B --> E
    C --> Y

    D --> F
    E --> F
    F1 --> N
    F2 --> N
    F3 --> P

    N --> O
    N --> P

    G --> N
    H --> O
    I --> P
    J --> G
    K --> I
    L --> I
    M --> G

    N --> Q
    P --> R

    F1 -.-> S
    F2 -.-> T
    F3 -.-> U

    S --> W
    T --> W
    U --> V
    Y --> V
    X --> W

    style N fill:#e1f5fe,stroke:#0277bd,stroke-width:3px
    style O fill:#e1f5fe,stroke:#0277bd,stroke-width:3px
    style P fill:#e1f5fe,stroke:#0277bd,stroke-width:3px
    style G fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style H fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style I fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style F1 fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    style F2 fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    style F3 fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
```

</div>

### New Architecture Benefits

1. **Separation of Concern**: Business logic isolated from infrastructure
2. **Dependency Inversion**: High-level modules don't depend on low-level details
3. **Testability**: Pure domain logic enables comprehensive unit testing
4. **Maintainability**: Changes to infrastructure don't affect business rules
5. **Scalability**: New scan strategies and validators easily pluggable
6. **Type Safety**: Rich domain models with comprehensive validation

### Architectural Layers

#### **Domain Layer** (Core Business Logic)
- **Entities**: `ScanRequest`, `ScanResult`, `ThreatMatch` - Rich business objects
- **Value Objects**: `ScanContext`, `SeverityLevel`, `ConfidenceScore`, `FilePath` - Immutable domain concepts
- **Domain Services**: `ScanOrchestrator`, `ThreatAggregator`, `ValidationService` - Pure business orchestration
- **Interfaces**: `IScanStrategy`, `IValidationStrategy` - Contracts for external dependencies

#### **Application Layer** (Use Cases & Coordination)
- **MCP Server**: Handles Cursor IDE integration via Model Context Protocol
- **CLI Commands**: Command-line interface for security scanning operations
- **Adapters**: Bridge domain interfaces with infrastructure implementations
  - `SemgrepAdapter` - Adapts Semgrep scanner to domain `IScanStrategy`
  - `LLMAdapter` - Adapts LLM scanner to domain `IScanStrategy`
  - `ValidationAdapter` - Adapts LLM validator to domain `IValidationStrategy`

#### **Infrastructure Layer** (External Services)
- **SemgrepScanner**: Static analysis engine integration
- **LLMScanner**: AI-powered vulnerability detection
- **LLMValidator**: False positive filtering with LLM analysis
- **SQLAlchemy Database**: Persistent storage for telemetry and results
- **File System**: Code file access and Git operations
- **Telemetry System**: Performance tracking and dashboard generation

### Data Flow Architecture

1. **Input Processing**: `ScanRequest` created with `ScanContext` (file/directory/code)
2. **Domain Orchestration**: `ScanOrchestrator` coordinates scanning strategies
3. **Parallel Analysis**: Multiple `IScanStrategy` implementations execute concurrently
4. **Threat Aggregation**: `ThreatAggregator` deduplicates and merges findings
5. **Validation Pipeline**: `ValidationService` filters false positives using AI
6. **Result Assembly**: Rich `ScanResult` with comprehensive metadata
7. **Presentation**: Results formatted for CLI, MCP, or dashboard consumption

### Key Design Patterns

- **Strategy Pattern**: Pluggable scan and validation strategies
- **Adapter Pattern**: Infrastructure integration without domain coupling
- **Factory Pattern**: Bootstrap and dependency injection
- **Value Objects**: Immutable domain concepts with validation
- **Domain Services**: Complex business logic coordination

### How It Works

1. **Multi-Engine Analysis**: Parallel execution of Semgrep static analysis and LLM AI analysis
2. **Intelligent Validation**: LLM-powered false positive reduction with confidence scoring
3. **Threat Aggregation**: Smart deduplication and merging using fingerprint and proximity strategies
4. **Performance Optimization**: Async processing, caching, and batch operations
5. **Comprehensive Telemetry**: SQLAlchemy-backed metrics with interactive Chart.js dashboard
6. **Git Integration**: Diff-aware scanning for efficient CI/CD pipeline integration
7. **Zero-Config Operation**: Auto-discovery and configuration with sensible defaults

## Configuration

### Environment Variables

```bash
# Core settings (optional)
ADVERSARY_LOG_LEVEL=INFO           # Set logging level
ADVERSARY_WORKSPACE_ROOT=/path     # Override workspace detection
```

### Configuration File

Settings are automatically managed through the CLI and stored in `~/.adversary/config.json`:

```bash
# Interactive configuration
adv configure setup

# Direct configuration
adv configure --llm-provider openai --llm-api-key your-key

# Check current settings
adv status
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
          pip install adversary-mcp-server

      - name: Run security scan
        run: |
          adv scan-directory . \
            --use-llm \
            --use-validation \
            --severity medium \
            --output-format json \
            --output-file scan-results.json

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

# Create virtual environment (using uv or standard venv)
source .venv/bin/activate  # Activate existing venv

# Install in development mode
uv pip install -e .[dev]

# Run tests
make test
```

### Running Tests

```bash
# Full test suite with coverage
make test

# Specific test categories
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make test-security      # Security tests only

# Code quality checks

make format             # Auto-format code
make mypy               # Type checking
make lint               # Run all linting
make pre-commit         # Run same pre-commit in git commits.
```

## Support

- [Documentation](https://github.com/brettbergin/adversary-mcp-server/wiki)
- [Report Issues](https://github.com/brettbergin/adversary-mcp-server/issues)
- [Discussions](https://github.com/brettbergin/adversary-mcp-server/discussions)
- Contact: brettberginbc@yahoo.com

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

---

<div align="center">
Made with ❤️ for software security.
</div>
