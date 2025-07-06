# Adversary MCP Server

<div align="center">

[![PyPI version](https://badge.fury.io/py/adversary-mcp-server.svg)](https://badge.fury.io/py/adversary-mcp-server)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-294%20passed-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Version](https://img.shields.io/badge/version-v0.4.3-blue.svg)](https://pypi.org/project/adversary-mcp-server/)

**Enterprise-grade security analysis with dynamic rule management and hot-reload capabilities**

[Installation](#installation) • [Quick Start](#quick-start) • [MCP Integration](#mcp-integration) • [Rule Management](#rule-management) • [CLI Reference](#cli-reference)

</div>

---

## Installation

### Prerequisites

- **Python 3.10+** (3.11+ recommended)
- **Cursor IDE** with MCP support
- **OpenAI API key** (optional, for enhanced exploit generation)

### Quick Install

```bash
pip install adversary-mcp-server
```

### Verify Installation

```bash
adversary-mcp-cli --version
adversary-mcp-cli status
```

---

## Quick Start

### 1. Initial Setup

```bash
# Configure the security engine  
adversary-mcp-cli configure

# Optional: Add OpenAI API key for enhanced analysis
adversary-mcp-cli configure --openai-api-key sk-your-key-here

# View available rules and setup
adversary-mcp-cli rules stats
```

### 2. Cursor IDE Integration

Create `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "adversary": {
      "command": "adversary-mcp-cli",
      "args": ["server"]
    }
  }
}
```

### 3. Start Using in Cursor

Once configured, you can use these MCP tools in Cursor:

- `adv_scan_code` - Scan code snippets for vulnerabilities
- `adv_scan_file` - Scan individual files  
- `adv_scan_directory` - Scan entire directories
- `adv_list_rules` - List all security rules
- `adv_get_rule_details` - Get details about specific rules
- `adv_generate_exploit` - Generate educational exploits
- `adv_configure_settings` - Configure server settings
- `adv_get_status` - Check server status
- `adv_get_version` - Get version information

### 4. Enable Hot-Reload (Optional)

For real-time rule updates during development:

```bash
# Start hot-reload service
adversary-mcp-cli watch start

# Now edit rules and they'll automatically reload!
```

---

## MCP Integration

### Available Tools

| Tool | Description | Usage |
|------|-------------|-------|
| `adv_scan_code` | Scan source code for security vulnerabilities | Pass code content and language |
| `adv_scan_file` | Scan a file for security vulnerabilities | Pass file path |
| `adv_scan_directory` | Scan a directory for security vulnerabilities | Pass directory path |
| `adv_generate_exploit` | Generate exploit for a specific vulnerability | Pass vulnerability type and code context |
| `adv_list_rules` | List all available threat detection rules | Optional filters by category/severity/language |
| `adv_get_rule_details` | Get detailed information about a specific rule | Pass rule ID |
| `adv_configure_settings` | Configure server settings | Pass configuration options |
| `adv_get_status` | Get server status and configuration | No parameters required |
| `adv_get_version` | Get version information of the adversary MCP server | No parameters required |

### Example Usage in Cursor

```
# Scan a Python file for vulnerabilities
Use adv_scan_file to scan app.py for security issues

# Generate an exploit for SQL injection  
Use adv_generate_exploit for sql_injection vulnerability in this login function

# List all XSS detection rules
Use adv_list_rules filtered by category "xss"

# Get version information
Use adv_get_version to check the current version of the adversary MCP server
```

---

## Rule Management

### Rule Directory Structure

Rules are automatically organized in your user directory:

```
~/.local/share/adversary-mcp-server/rules/
├── built-in/              # Core security rules (109 rules)
│   ├── python-rules.yaml
│   ├── javascript-rules.yaml  
│   ├── typescript-rules.yaml
│   ├── web-security-rules.yaml
│   ├── api-security-rules.yaml
│   ├── cryptography-rules.yaml
│   └── configuration-rules.yaml
├── custom/                # Your custom rules
├── organization/          # Company/team rules
└── templates/             # Rule templates
```

### Quick Rule Management

```bash
# View rules directory and contents
adversary-mcp-cli show-rules-dir

# List all loaded rules with source files  
adversary-mcp-cli list-rules

# List rules with full file paths
adversary-mcp-cli list-rules --verbose

# View detailed rule statistics
adversary-mcp-cli rules stats

# Export rules for backup/sharing
adversary-mcp-cli rules export my-rules.yaml

# Import custom rules
adversary-mcp-cli rules import-rules external-rules.yaml

# Validate all rules
adversary-mcp-cli rules validate

# Reload rules after changes
adversary-mcp-cli rules reload
```

### Creating Custom Rules

1. **Copy template:**
```bash
cp ~/.local/share/adversary-mcp-server/rules/templates/rule-template.yaml \
   ~/.local/share/adversary-mcp-server/rules/custom/my-rule.yaml
```

2. **Edit the rule:**
```yaml
rules:
  - id: api_key_hardcode
    name: Hardcoded API Key
    description: Detects hardcoded API keys in source code
    category: secrets
    severity: critical
    languages: [python, javascript, typescript]
    
    conditions:
      - type: pattern
        value: "API_KEY\\s*=\\s*['\"][a-zA-Z0-9-_]{20,}['\"]"
    
    remediation: |
      Store API keys in environment variables:
      - Use os.getenv('API_KEY') instead of hardcoding
      - Implement proper secrets management
    
    references:
      - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
    
    cwe_id: CWE-798
    owasp_category: A05:2021
```

3. **Reload rules:**
```bash
adversary-mcp-cli rules reload
```

---

## Hot-Reload Service

Enable real-time rule updates without server restart:

### Start Hot-Reload

```bash
# Start with default settings
adversary-mcp-cli watch start

# Start with custom directories and debounce time
adversary-mcp-cli watch start \
  --directory /path/to/project/rules/ \
  --debounce 2.0
```

### Monitor Status

```bash
# Check service status
adversary-mcp-cli watch status

# Test hot-reload functionality
adversary-mcp-cli watch test
```

### Development Workflow

```bash
# Terminal 1: Start hot-reload service
adversary-mcp-cli watch start

# Terminal 2: Edit rules (auto-reloads)
vim ~/.local/share/adversary-mcp-server/rules/custom/my-rule.yaml
# Changes are automatically detected and rules reload!
```

---

## CLI Reference

### Core Commands

| Command | Description |
|---------|-------------|
| `adversary-mcp-cli configure` | Initial setup and configuration |
| `adversary-mcp-cli status` | Show server status and configuration |
| `adversary-mcp-cli scan <target>` | Scan files/directories for vulnerabilities |
| `adversary-mcp-cli server` | Start MCP server (used by Cursor) |

### Rule Management Commands

| Command | Description |
|---------|-------------|
| `adversary-mcp-cli list-rules` | List all rules with source files |
| `adversary-mcp-cli rule-details <id>` | Get detailed rule information |
| `adversary-mcp-cli rules stats` | Show comprehensive rule statistics |
| `adversary-mcp-cli rules export <file>` | Export rules to YAML/JSON |
| `adversary-mcp-cli rules import-rules <file>` | Import external rules |
| `adversary-mcp-cli rules validate` | Validate all loaded rules |
| `adversary-mcp-cli rules reload` | Reload rules from files |

### Hot-Reload Commands

| Command | Description |
|---------|-------------|
| `adversary-mcp-cli watch start` | Start hot-reload service |
| `adversary-mcp-cli watch status` | Show service status |
| `adversary-mcp-cli watch test` | Test hot-reload functionality |

### Utility Commands

| Command | Description |
|---------|-------------|
| `adversary-mcp-cli show-rules-dir` | Show rules directory location |
| `adversary-mcp-cli demo` | Run interactive demo |
| `adversary-mcp-cli reset` | Reset all configuration |

---

## Security Coverage

### Comprehensive Rule Database (109 Rules)

- **Python** (20 rules): SQL injection, command injection, deserialization, path traversal
- **JavaScript/TypeScript** (28 rules): XSS, prototype pollution, eval injection, CORS issues  
- **Web Security** (16 rules): CSRF, clickjacking, security headers, session management
- **API Security** (15 rules): Authentication bypass, parameter pollution, mass assignment
- **Cryptography** (15 rules): Weak algorithms, hardcoded keys, poor randomness
- **Configuration** (15 rules): Debug mode, default credentials, insecure settings

### Standards Compliance

- **OWASP Top 10 2021** - Complete coverage
- **CWE** - Common Weakness Enumeration mappings
- **NIST** - Security framework alignment
- **Industry best practices** - SANS, CERT guidelines

### Languages Supported

- **Python** - AST-based analysis with deep pattern matching
- **JavaScript** - Modern ES6+ and Node.js patterns  
- **TypeScript** - Type safety and framework-specific vulnerabilities

---

## Architecture

The system uses a modular architecture with external rule management:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Cursor IDE    │───▶│   MCP Server    │───▶│ Security Engine │
│                 │    │                 │    │                 │
│ • Code editing  │    │ • adv_* tools   │    │ • AST Analysis  │
│ • Chat interface│    │ • Protocol      │    │ • YAML Rules    │
│ • Tool calling  │    │   handling      │    │ • Hot-reload    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                              ┌─────────────────────────┼─────────────────────────┐
                              │                         ▼                         │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │  Built-in Rules │    │  Custom Rules   │    │Organization Rules│
                    │   (109 rules)   │    │  User defined   │    │ Company policies│
                    │ Multi-language  │    │ Project specific│    │  Compliance     │
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## Advanced Usage

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Analysis
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Adversary MCP
        run: pip install adversary-mcp-server
      
      - name: Security Scan
        run: |
          adversary-mcp-cli scan . \
            --severity medium \
            --format json \
            --output security-report.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

### Environment Configuration

```bash
# Configuration environment variables
export ADVERSARY_CONFIG_DIR="~/.local/share/adversary-mcp-server"
export ADVERSARY_RULES_DIR="~/.local/share/adversary-mcp-server/rules"
export ADVERSARY_LOG_LEVEL="INFO"
export ADVERSARY_SEVERITY_THRESHOLD="medium"
export ADVERSARY_HOT_RELOAD="enabled"
```

---

## Development

### Development Setup

```bash
# Clone repository
git clone https://github.com/brettbergin/adversary-mcp-server.git
cd adversary-mcp-server

# Install with uv (recommended)
pip install uv
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Or with traditional pip
make install

# Run tests
make test

# Code quality checks  
make lint
```

### Project Structure

```
adversary-mcp-server/
├── src/adversary_mcp_server/
│   ├── server.py           # MCP server with adv_* tools
│   ├── threat_engine.py    # Rule engine with source file tracking
│   ├── ast_scanner.py      # Static analysis engine
│   ├── exploit_generator.py # Educational exploit generation
│   ├── hot_reload.py       # Real-time rule updates
│   └── cli.py             # Command-line interface
├── rules/                 # Packaged rules (copied to user directory)
│   ├── built-in/           # 109 core security rules
│   └── templates/         # Rule creation templates
└── tests/                 # Comprehensive test suite (294 tests)
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run the test suite: `make test`
5. Submit a pull request

---

## Support

- **Documentation**: [GitHub Wiki](https://github.com/brettbergin/adversary-mcp-server/wiki)
- **Issues**: [GitHub Issues](https://github.com/brettbergin/adversary-mcp-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/brettbergin/adversary-mcp-server/discussions)

---

<div align="center">

**Built with ❤️ for secure development**

</div>