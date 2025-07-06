# Adversary MCP Server

[![PyPI version](https://badge.fury.io/py/adversary-mcp-server.svg)](https://badge.fury.io/py/adversary-mcp-server)
[![Downloads](https://pepy.tech/badge/adversary-mcp-server)](https://pepy.tech/project/adversary-mcp-server)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Coverage](https://img.shields.io/badge/coverage-88.35%25-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Tests](https://img.shields.io/badge/tests-192%20passed-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A security-focused Model Context Protocol (MCP) server designed to simulate adversary behavior during software development. This tool acts as a "mini penetration tester" embedded inside Cursor IDE, providing real-time security vulnerability detection and exploit generation.

## 🎯 Overview

The Adversary MCP Server analyzes source code (Python, JavaScript, TypeScript) and provides:
- **Real-time vulnerability detection** using AST-based static analysis
- **Exploit generation** with both template-based and LLM-powered approaches
- **Risk impact assessments** with severity ratings and remediation advice
- **Educational security insights** with CWE mappings and OWASP references

## 🚀 Features

### Core Components

1. **🔍 Threat Pattern Engine**
   - YAML-based security rules for detecting vulnerabilities
   - Support for SQL injection, XSS, command injection, deserialization, and more
   - Extensible rule system with custom DSL

2. **🧠 AST-Based Static Scanner**
   - Multi-language support (Python, JavaScript, TypeScript)
   - Deep code analysis using Abstract Syntax Trees
   - Function call tracking, import analysis, and pattern matching

3. **💥 Exploit Generator**
   - Template-based exploit generation for common vulnerabilities
   - LLM-powered exploit creation using OpenAI GPT models
   - Safety filtering to ensure educational-only exploits

4. **📡 MCP Server Integration**
   - Seamless integration with Cursor IDE
   - Real-time analysis during development
   - Rich output with code context and remediation advice

5. **🛠️ CLI Interface**
   - Standalone command-line tool for CI/CD integration
   - Configuration management with secure credential storage
   - Batch scanning capabilities

## 📦 Installation

### Requirements

- Python 3.10 or higher
- Optional: OpenAI API key for LLM-based exploit generation

### Install from PyPI

```bash
pip install adversary-mcp-server
```

### Install from Source

#### Using uv (Recommended - Fast)

```bash
# Install uv if you haven't already
pip install uv

# Clone and setup
git clone https://github.com/brettbergin/adversary-mcp-server.git
cd adversary-mcp-server

# Create virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with dependencies
uv pip install -e ".[dev]"

# Or use make for convenience
make dev-setup-uv
```

📖 **See [UV_SETUP.md](UV_SETUP.md) for detailed uv usage guide and best practices.**

#### Using pip

```bash
git clone https://github.com/brettbergin/adversary-mcp-server.git
cd adversary-mcp-server
make install
```

## 🔧 Configuration

### Initial Setup

```bash
# Configure the server
adversary-mcp-cli configure

# Check status
adversary-mcp-cli status
```

### OpenAI Integration (Optional)

For enhanced exploit generation, configure your OpenAI API key:

```bash
adversary-mcp-cli configure --openai-api-key your-api-key-here
```

## 🎮 Usage

### Command Line Interface

#### Scan a File

```bash
adversary-mcp-cli scan myapp.py --severity high --include-exploits
```

#### Scan a Directory

```bash
adversary-mcp-cli scan ./src --recursive --language python
```

#### List Available Rules

```bash
adversary-mcp-cli list-rules --category injection --severity medium
```

#### Get Rule Details

```bash
adversary-mcp-cli rule-details python_sql_injection
```

#### Run Demo

```bash
adversary-mcp-cli demo
```

### MCP Server Integration

The server provides several MCP tools for integration with Cursor IDE:

- `scan_code` - Scan source code for vulnerabilities
- `scan_file` - Scan a specific file
- `scan_directory` - Scan an entire directory
- `generate_exploit` - Generate exploits for vulnerabilities
- `list_rules` - List available detection rules
- `get_rule_details` - Get detailed rule information
- `configure_settings` - Configure server settings
- `get_status` - Get server status

### Example Output

```
# Security Scan Results for myapp.py

## Summary
**Total Threats:** 3
**High:** 2 🟠
**Medium:** 1 🟡

## Detailed Results

### 1. SQL Injection 🟠
**File:** myapp.py:15
**Severity:** High
**Category:** Injection
**Description:** Direct string concatenation in SQL queries

**Code Context:**
```
   12: def login(username, password):
   13:     conn = sqlite3.connect('users.db')
   14:     cursor = conn.cursor()
>>> 15:     query = "SELECT * FROM users WHERE username = '" + username + "'"
   16:     cursor.execute(query)
   17:     return cursor.fetchone()
```

**Exploit Examples:**
*Example 1:*
```
' OR '1'='1' --
```

**Remediation:** Use parameterized queries or prepared statements
```

## 🛡️ Security Rules

The server includes built-in rules for detecting:

### Python Vulnerabilities
- SQL Injection (string concatenation, format strings)
- Command Injection (os.system, subprocess calls)
- Unsafe Deserialization (pickle.loads)
- Path Traversal
- Code Injection (eval, exec)

### JavaScript/TypeScript Vulnerabilities
- DOM-based XSS (innerHTML, outerHTML)
- Code Injection (eval, Function constructor)
- Prototype Pollution
- Client-side Path Traversal

### Common Patterns
- Hardcoded credentials
- Insecure random number generation
- Weak cryptographic algorithms
- Information disclosure

## 🎯 Custom Rules

Create custom YAML rules for your specific security requirements:

```yaml
rules:
  - id: custom_api_key_exposure
    name: API Key Exposure
    description: Hardcoded API keys in source code
    category: disclosure
    severity: high
    languages: [python, javascript, typescript]
    conditions:
      - type: regex
        value: "(api_key|apikey|api-key)\\s*=\\s*['\"][a-zA-Z0-9-_]{20,}['\"]"
    remediation: Use environment variables or secure configuration files
    references:
      - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
```

## 🔧 Development

### Setup Development Environment

#### Using uv (Recommended)

```bash
# Initialize virtual environment
make uv-init
source .venv/bin/activate

# Install dependencies
make dev-setup-uv

# Generate lock files
make lock
```

#### Using pip

```bash
make dev-setup
```

### Dependency Management with uv

```bash
# Install dependencies from lock file
uv pip sync uv-dev.lock

# Add new dependency
uv pip install package-name
uv pip freeze > requirements.txt

# Update all dependencies
make uv-upgrade

# Regenerate lock files
make lock
```

### Run Tests

```bash
make test
```

### Run Linting

```bash
make lint
```

### Run Security Scans

```bash
make security-scan
```

## 📋 Supported Languages

| Language   | AST Parser | Function Calls | Imports | Variables |
|------------|------------|----------------|---------|-----------|
| Python     | ✅ ast     | ✅             | ✅      | ✅        |
| JavaScript | ✅ esprima | ✅             | ✅      | ✅        |
| TypeScript | ✅ esprima | ✅             | ✅      | ✅        |

## 🚨 Safety & Ethics

This tool is designed for **educational and defensive security purposes only**. 

### Safety Features
- **Exploit Safety Mode**: Filters dangerous commands and replaces them with safe alternatives
- **Educational Focus**: All exploits are designed for learning and demonstration
- **Responsible Disclosure**: Encourages proper vulnerability reporting practices

### Ethical Use
- ✅ Security research and education
- ✅ Defensive security testing
- ✅ Code review and quality assurance
- ✅ Security training and awareness
- ❌ Malicious attacks or unauthorized access
- ❌ Exploitation of systems you don't own
- ❌ Bypassing security controls without permission

## 📊 Threat Categories

| Category      | Description                      | Severity Range |
|---------------|----------------------------------|----------------|
| Injection     | SQL, Command, Code injection     | High-Critical  |
| XSS           | Cross-site scripting             | Medium-High    |
| Deserialization | Unsafe object deserialization | High-Critical  |
| Authentication | Auth bypass, weak credentials   | Medium-High    |
| Authorization | Access control issues           | Medium-High    |
| Crypto        | Weak cryptographic practices    | Medium-High    |
| Disclosure    | Information leakage             | Low-Medium     |

## 🤝 Contributing

Contributions are welcome! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Adding New Rules

1. Create YAML rule files in `rules/` directory
2. Add corresponding test cases
3. Update documentation
4. Submit PR with rule validation

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [Documentation](https://github.com/brettbergin/adversary-mcp-server#readme)
- [Issues](https://github.com/brettbergin/adversary-mcp-server/issues)
- [Cursor IDE](https://cursor.sh/)
- [Model Context Protocol](https://github.com/modelcontextprotocol/python-sdk)

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security guidelines and references
- [CWE](https://cwe.mitre.org/) for vulnerability classifications
- [Semgrep](https://semgrep.dev/) for static analysis inspiration
- [Bandit](https://bandit.readthedocs.io/) for Python security patterns

---

**⚠️ Disclaimer**: This tool is for educational and defensive security purposes only. Users are responsible for ensuring ethical and legal use of this software.