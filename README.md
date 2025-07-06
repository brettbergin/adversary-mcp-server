# Adversary MCP Server

<div align="center">

[![PyPI version](https://badge.fury.io/py/adversary-mcp-server.svg)](https://badge.fury.io/py/adversary-mcp-server)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Coverage](https://img.shields.io/badge/coverage-89%25-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Tests](https://img.shields.io/badge/tests-279%20passed-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Version](https://img.shields.io/badge/version-v0.2.0-blue.svg)](https://pypi.org/project/adversary-mcp-server/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Enterprise-grade security analysis with dynamic rule management and hot-reload capabilities**

[Installation](#installation) • [Quick Start](#quick-start) • [Rule Management](#rule-management) • [Hot-Reload](#hot-reload-service) • [Documentation](#documentation)

</div>

---

## Overview

Adversary MCP Server is a next-generation software security analysis platform that integrates seamlessly with modern development environments through the Model Context Protocol (MCP). Featuring dynamic YAML-based rule management, real-time hot-reload capabilities, and comprehensive CLI tools, it provides intelligent security analysis directly within your IDE workflow.

### Key Capabilities

- **🔍 Real-time Security Analysis** - AST-based static analysis for Python, JavaScript, and TypeScript
- **📝 Dynamic Rule Management** - YAML-based external rule system with hot-reload capabilities  
- **⚡ Hot-Reload Service** - Real-time rule updates without server restart
- **🎯 Intelligent Threat Detection** - Comprehensive rules covering OWASP Top 10 and CWE classifications  
- **💡 Educational Exploit Generation** - Template-based and LLM-powered security demonstrations
- **🔧 Advanced CLI Tools** - Complete rule lifecycle management and validation
- **📊 Comprehensive Analytics** - Detailed rule statistics and file tracking
- **🛡️ Safety-First Design** - Built-in safeguards for responsible security research

---

## Architecture

The Adversary MCP Server employs a modular architecture with external rule management and hot-reload capabilities:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Cursor IDE    │───▶│   MCP Server    │───▶│ Security Engine │
│                 │    │                 │    │                 │
│ • Code editing  │    │ • Protocol      │    │ • AST Analysis  │
│ • Chat interface│    │   handling      │    │ • YAML Rules    │
│ • Tool calling  │    │ • Tool routing  │    │ • Hot-reload    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                              ┌─────────────────────────┼─────────────────────────┐
                              │                         ▼                         │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │  Built-in Rules │    │  Custom Rules   │    │Organization Rules│
                    │                 │    │                 │    │                 │
                    │ • Python rules  │    │ • User defined  │    │ • Company std   │
                    │ • JS/TS rules   │    │ • Project rules │    │ • Team policies │
                    │ • Templates     │    │ • Local config  │    │ • Compliance    │
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                         │                         │
                              └─────────────────────────┼─────────────────────────┘
                                                        ▼
                                             ┌─────────────────┐
                                             │ Hot-Reload      │
                                             │ Service         │
                                             │                 │
                                             │ • File watching │
                                             │ • Auto-reload   │
                                             │ • Validation    │
                                             └─────────────────┘
```

### Core Components

#### 1. Dynamic Rule Management System
- **YAML-based external rules** with complete lifecycle management
- **Priority loading system** supporting built-in, custom, and organization rules
- **Rule validation and statistics** with comprehensive error reporting
- **Hot-reload capabilities** for real-time rule updates without server restart
- **CLI tools** for rule import, export, validation, and management

#### 2. Hot-Reload Service
- **Real-time file watching** with configurable debouncing
- **Multi-directory monitoring** with automatic rule discovery
- **Service management** with start, status, and test commands
- **Statistics tracking** including reload counts and file monitoring
- **Error recovery** with graceful handling of file system events

#### 3. Enhanced Threat Pattern Engine
- **External YAML rule storage** with template-based rule creation
- **Multi-language support** with language-specific detection logic
- **Severity classification** aligned with industry standards (CVSS-inspired)
- **Rule categorization** covering OWASP Top 10 and CWE classifications
- **Extensible architecture** for custom organizational security policies

#### 4. AST-Based Static Scanner
- **Deep code analysis** using Abstract Syntax Trees for precise detection
- **Context-aware scanning** that understands code semantics, not just patterns
- **Performance optimized** for real-time analysis during development
- **False positive reduction** through intelligent code flow analysis

#### 5. Exploit Generation System
- **Template-based exploits** for common vulnerability classes
- **LLM integration** (OpenAI) for sophisticated, context-aware exploit generation
- **Safety filtering** to ensure educational-only content
- **Customizable output** tailored to different skill levels and use cases

#### 6. Model Context Protocol Integration
- **Standards-compliant** MCP implementation for broad IDE compatibility
- **Tool-based architecture** exposing granular security capabilities
- **Real-time communication** with development environments
- **Stateful session management** for consistent user experience

---

## Rule Management

### Rule Directory Structure

The Adversary MCP Server uses a hierarchical rule management system located in your user configuration directory:

```
~/.local/share/adversary-mcp-server/rules/
├── built-in/              # Core security rules (auto-copied from package)
│   ├── python-rules.yaml      # Python-specific security patterns
│   ├── javascript-rules.yaml  # JavaScript/TypeScript patterns
│   └── ...
├── custom/                # User-defined rules
│   ├── project-rules.yaml     # Project-specific security patterns
│   ├── api-security.yaml      # API security rules
│   └── ...
├── organization/          # Company/team-wide rules
│   ├── compliance.yaml        # Regulatory compliance rules
│   ├── coding-standards.yaml  # Internal security standards
│   └── ...
└── templates/             # Rule templates for easy creation
    └── rule-template.yaml     # Complete rule template with examples
```

### Automatic Initialization

The rules directory is automatically created and initialized when you first use the system:

- **Directory Creation**: `~/.local/share/adversary-mcp-server/rules/` and subdirectories
- **Built-in Rules**: Core security rules are copied from the package to your user directory
- **Templates**: Rule templates are made available for customization
- **User Writable**: All rules are stored in your user directory (no need for sudo/admin)
- **Update Safe**: Your custom rules persist across package updates

### Rule Priority Loading

Rules are loaded in priority order:
1. **Built-in rules** - Core security patterns (lowest priority)
2. **Organization rules** - Company-wide policies (medium priority) 
3. **Custom rules** - User/project-specific (highest priority)

Higher priority rules can override lower priority rules with the same ID.

### Creating Custom Rules

#### 1. Using Templates

```bash
# View the rules directory location
adversary-mcp-cli show-rules-dir

# Copy the rule template
cp ~/.local/share/adversary-mcp-server/rules/templates/rule-template.yaml \
   ~/.local/share/adversary-mcp-server/rules/custom/my-security-rule.yaml

# Or use the CLI import command (copies to custom/ by default)
adversary-mcp-cli rules import-rules ~/.local/share/adversary-mcp-server/rules/templates/rule-template.yaml

# Edit the rule file with your favorite editor
vim ~/.local/share/adversary-mcp-server/rules/custom/my-security-rule.yaml
```

#### 2. Rule Structure

```yaml
# ~/.local/share/adversary-mcp-server/rules/custom/api-key-exposure.yaml
rules:
  - id: api_key_hardcode
    name: Hardcoded API Key
    description: Detects hardcoded API keys in source code
    category: disclosure
    severity: critical
    languages: [python, javascript, typescript]
    
    conditions:
      - type: pattern
        value: "API_KEY\\s*=\\s*['\"][a-zA-Z0-9-_]{20,}['\"]"
        case_sensitive: false
      - type: pattern  
        value: "apiKey:\\s*['\"][a-zA-Z0-9-_]{20,}['\"]"
        case_sensitive: false
    
    exploit_templates:
      - type: disclosure
        description: API key exposure example
        template: |
          # Found API key: {api_key}
          # This key could be used to access: {service_name}
    
    remediation: |
      Store API keys in environment variables or secure configuration:
      - Use os.getenv('API_KEY') instead of hardcoding
      - Implement proper secrets management
      - Rotate compromised keys immediately
    
    references:
      - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
      - https://cwe.mitre.org/data/definitions/798.html
    
    cwe_id: CWE-798
    owasp_category: A05:2021
    tags: [secrets, api, configuration]
```

### Rule Management CLI Commands

```bash
# Show rules directory location and contents
adversary-mcp-cli show-rules-dir

# Export rules to YAML or JSON
adversary-mcp-cli rules export my-rules.yaml --format yaml
adversary-mcp-cli rules export my-rules.json --format json

# Import external rules with validation (defaults to ~/.local/share/adversary-mcp-server/rules/custom/)
adversary-mcp-cli rules import-rules external-rules.yaml
adversary-mcp-cli rules import-rules security-pack.yaml --validate

# Import to specific directory
adversary-mcp-cli rules import-rules company-rules.yaml --target-dir ~/.local/share/adversary-mcp-server/rules/organization/

# Validate all loaded rules
adversary-mcp-cli rules validate

# Reload rules from files (without server restart)
adversary-mcp-cli rules reload

# View comprehensive rule statistics
adversary-mcp-cli rules stats
```

#### Rule Statistics Output

```bash
$ adversary-mcp-cli rules stats

📊 Rule Statistics

Total Rules: 5
Loaded Files: 2

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Category        ┃ Count   ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ injection       │ 3       │
│ xss            │ 2       │
└─────────────────┴─────────┘

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Severity        ┃ Count   ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ critical        │ 2       │
│ high           │ 3       │
└─────────────────┴─────────┘

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Language        ┃ Count   ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ python         │ 3       │
│ javascript     │ 2       │
│ typescript     │ 2       │
└─────────────────┴─────────┘

Loaded Files:
• ~/.local/share/adversary-mcp-server/rules/built-in/python-rules.yaml (3 rules)
• ~/.local/share/adversary-mcp-server/rules/built-in/javascript-rules.yaml (2 rules)
```

---

## Hot-Reload Service

### Overview

The Hot-Reload Service enables real-time rule updates without server restart, providing seamless development workflow integration.

### Features

- **Real-time file watching** with configurable debouncing
- **Multi-directory monitoring** with automatic discovery
- **Graceful error handling** and recovery
- **Statistics tracking** and service monitoring
- **Cross-platform support** (macOS, Linux, Windows)

### Hot-Reload CLI Commands

#### Starting the Service

```bash
# Start with default settings (watches ~/.local/share/adversary-mcp-server/rules/)
adversary-mcp-cli watch start

# Start with additional custom directories and debounce time
adversary-mcp-cli watch start \
  --directory /path/to/project/rules/ \
  --directory /path/to/company/rules/ \
  --debounce 2.0

# The service automatically watches the user rules directory
# Additional directories can be specified with --directory
```

#### Service Status

```bash
$ adversary-mcp-cli watch status

🔄 Hot-Reload Service Status

Service Status: 🟢 Running
Watched Directories: 2
Pending Reloads: 0
Total Reloads: 12
Debounce Time: 1.0 seconds
Last Reload: 2024-01-15 10:30:45

Watched Directories:
• /path/to/rules/built-in
• /path/to/rules/custom

Last Reload Files:
• rules/custom/api-security.yaml
• rules/organization/compliance.yaml
```

#### Testing Hot-Reload

```bash
# Test hot-reload functionality
adversary-mcp-cli watch test

# Force immediate reload
adversary-mcp-cli watch test --force
```

### Development Workflow

```bash
# Terminal 1: Start hot-reload service (automatically watches user rules directory)
adversary-mcp-cli watch start

# Terminal 2: Edit rules (changes automatically detected)
vim ~/.local/share/adversary-mcp-server/rules/custom/my-security-rule.yaml

# Or use the show-rules-dir command to navigate
adversary-mcp-cli show-rules-dir
cd ~/.local/share/adversary-mcp-server/rules/custom/
vim my-security-rule.yaml

# Service automatically reloads rules when files change
# No server restart required!
```

---

## Installation

### Prerequisites

- **Python 3.10+** (3.11+ recommended for optimal performance)
- **OpenAI API key** (optional, for enhanced exploit generation)
- **Supported IDE**: Cursor IDE with MCP support

### Quick Installation

```bash
pip install adversary-mcp-server
```

### Development Installation

#### Using uv (Recommended)

```bash
# Install uv package manager
pip install uv

# Clone repository
git clone https://github.com/brettbergin/adversary-mcp-server.git
cd adversary-mcp-server

# Setup development environment
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

# Verify installation
adversary-mcp-cli --version
```

#### Using traditional pip

```bash
git clone https://github.com/brettbergin/adversary-mcp-server.git
cd adversary-mcp-server
make install
```

---

## Quick Start

### 1. Initial Configuration

```bash
# Configure the security engine
adversary-mcp-cli configure

# Optional: Add OpenAI API key for enhanced analysis
adversary-mcp-cli configure --openai-api-key sk-your-key-here

# Verify setup and rule loading
adversary-mcp-cli status
```

### 2. Rule Management Setup

```bash
# View available rules
adversary-mcp-cli rules stats

# Export rules for customization
adversary-mcp-cli rules export my-rules.yaml

# Start hot-reload service for development
adversary-mcp-cli watch start
```

### 3. Cursor IDE Integration

Create MCP configuration in `.cursor/mcp.json` (project-specific) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "adversary-security": {
      "command": "adversary-mcp-server",
      "args": [],
      "env": {
        "ADVERSARY_CONFIG_DIR": "~/.local/share/adversary-mcp-server",
        "ADVERSARY_RULES_DIR": "~/.local/share/adversary-mcp-server/rules"
      }
    }
  }
}
```

### 4. Restart Cursor IDE

The security analysis tools will be automatically available in your chat interface.

---

## Usage Examples

### Interactive Security Analysis

**Natural Language Security Queries:**

```
You: "Scan this authentication function for security issues"

Adversary: 🚨 **Critical Security Issues Detected**

Found 2 vulnerabilities in authentication function:

1. **SQL Injection** (Line 15) - CRITICAL
   - Rule: python_sql_injection (built-in)
   - Direct string concatenation in database query
   - Impact: Complete database compromise
   
2. **Weak Password Hashing** (Line 23) - HIGH  
   - Rule: weak_password_hashing (custom)
   - Using MD5 instead of bcrypt
   - Impact: Credential compromise

Would you like detailed exploit examples and remediation guidance?
```

**Dynamic Rule Updates:**

```
You: "I just updated my custom API security rules"

Adversary: ✅ **Rules automatically reloaded!**

Hot-reload service detected changes:
• rules/custom/api-security.yaml (modified)
• Added 2 new rules for API key validation
• Updated 1 existing rule for JWT handling

All rules validated successfully. Ready for analysis with updated patterns!
```

---

## Available Tools

The Adversary MCP Server exposes ten specialized security analysis tools through the MCP interface:

### Core Analysis Tools

| Tool | Purpose | Usage Example |
|------|---------|---------------|
| `scan_code` | Analyze code snippets for vulnerabilities | `"Check this function for injection flaws"` |
| `scan_file` | Security audit of specific files | `"Scan auth.py for authentication issues"` |
| `scan_directory` | Recursive project-wide analysis | `"Audit my entire API directory"` |

### Rule Management Tools

| Tool | Purpose | Usage Example |
|------|---------|---------------|
| `list_rules` | Browse available detection rules | `"What Python security rules are available?"` |
| `get_rule_details` | Deep-dive into specific security patterns | `"Explain the SQL injection detection rule"` |

### Educational & Research Tools

| Tool | Purpose | Usage Example |
|------|---------|---------------|
| `generate_exploit` | Create educational exploit demonstrations | `"Show me how this XSS could be exploited"` |

### Management & Configuration Tools

| Tool | Purpose | Usage Example |
|------|---------|---------------|
| `configure_settings` | Adjust analysis parameters | `"Set severity threshold to high only"` |
| `get_status` | Check server health and configuration | `"Is the security scanner working properly?"` |

### CLI-Only Commands

| Command | Purpose | Usage Example |
|---------|---------|---------------|
| `show-rules-dir` | Display rules directory location and contents | `adversary-mcp-cli show-rules-dir` |

#### Example: Rules Directory Display

```bash
$ adversary-mcp-cli show-rules-dir

📁 User Rules Directory: ~/.local/share/adversary-mcp-server/rules
📂 Structure:
  • built-in/     - Core security rules
  • custom/       - User-defined rules
  • organization/ - Company/team rules
  • templates/    - Rule templates

📊 Directory contents:
  • built-in/ (2 files)
    - javascript-rules.yaml
    - python-rules.yaml
  • custom/ (0 files)
  • organization/ (0 files)
  • templates/ (1 files)
    - rule-template.yaml
```

---

## Security Detection Capabilities

### Vulnerability Categories

#### Injection Vulnerabilities
- **SQL Injection** - String concatenation, format strings, ORM misuse
- **Command Injection** - Unsafe system calls, shell command construction
- **Code Injection** - Dynamic code execution, unsafe eval/exec usage
- **LDAP Injection** - Directory service query manipulation

#### Cross-Site Scripting (XSS)
- **Reflected XSS** - Direct user input reflection
- **Stored XSS** - Persistent malicious content
- **DOM-based XSS** - Client-side script vulnerabilities

#### Authentication & Authorization
- **Weak Password Policies** - Insufficient complexity requirements
- **Hardcoded Credentials** - Embedded secrets and API keys  
- **Session Management** - Insecure session handling
- **Access Control** - Missing authorization checks

#### Cryptographic Issues
- **Weak Algorithms** - Deprecated encryption methods
- **Insecure Random** - Predictable random number generation
- **Certificate Validation** - SSL/TLS verification bypasses

#### Information Disclosure
- **Error Handling** - Verbose error messages
- **Debug Information** - Development artifacts in production
- **Sensitive Data Exposure** - Unprotected personal information

### Language-Specific Patterns

#### Python Security Patterns
```python
# SQL Injection Detection
cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # ❌ VULNERABLE
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # ✅ SECURE

# Command Injection Detection  
os.system("ls " + user_input)  # ❌ VULNERABLE
subprocess.run(["ls", user_input])  # ✅ SECURE

# Deserialization Vulnerabilities
pickle.loads(untrusted_data)  # ❌ VULNERABLE
json.loads(untrusted_data)  # ✅ SAFER
```

#### JavaScript/TypeScript Security Patterns
```javascript
// XSS Vulnerabilities
element.innerHTML = userInput;  // ❌ VULNERABLE
element.textContent = userInput;  // ✅ SECURE

// Code Injection
eval(userCode);  // ❌ VULNERABLE
// Use safe alternatives or sandboxing  // ✅ SECURE

// Prototype Pollution
obj[userKey] = userValue;  // ❌ POTENTIALLY VULNERABLE
if (Object.hasOwnProperty.call(obj, userKey)) { ... }  // ✅ SAFER
```

---

## Advanced Configuration

### Environment Configuration

```bash
# Configuration options
export ADVERSARY_CONFIG_DIR="~/.local/share/adversary-mcp-server"
export ADVERSARY_RULES_DIR="~/.local/share/adversary-mcp-server/rules"
export ADVERSARY_LOG_LEVEL="INFO"
export ADVERSARY_EXPLOIT_SAFETY="enabled"
export ADVERSARY_LLM_PROVIDER="openai"
export ADVERSARY_SEVERITY_THRESHOLD="medium"
export ADVERSARY_HOT_RELOAD="enabled"
export ADVERSARY_DEBOUNCE_TIME="1.0"
```

### Custom Rule Development

#### Rule Template Structure

```yaml
# Complete rule template with all supported fields
rules:
  - id: unique_rule_identifier
    name: Human-readable Rule Name
    description: Detailed description of the security issue
    category: injection|xss|auth|crypto|disclosure
    severity: low|medium|high|critical
    languages: [python, javascript, typescript]
    
    conditions:
      - type: pattern|regex|ast_pattern
        value: "detection_pattern"
        case_sensitive: true|false
        context: function|class|global  # optional
    
    exploit_templates:
      - type: payload|poc|example
        description: Template description
        template: "exploit template with {variables}"
    
    remediation: |
      Multi-line remediation guidance
      with specific recommendations
    
    references:
      - https://owasp.org/relevant-link
      - https://cwe.mitre.org/data/definitions/XXX.html
    
    cwe_id: CWE-XXX
    owasp_category: "A01:2021"
    tags: [custom, internal, compliance]
    
    metadata:
      author: "Security Team"
      created: "2024-01-15"
      version: "1.0"
      confidence: high|medium|low
```

---

## Command Line Interface

### Enhanced CLI Commands

#### Rule Management

```bash
# Export rules in different formats
adversary-mcp-cli rules export rules-backup.yaml --format yaml
adversary-mcp-cli rules export rules-backup.json --format json

# Import and validate external rules
adversary-mcp-cli rules import-rules security-pack.yaml \
  --target-dir rules/organization/ \
  --validate

# Comprehensive rule validation
adversary-mcp-cli rules validate

# Real-time rule reloading
adversary-mcp-cli rules reload

# Detailed rule analytics
adversary-mcp-cli rules stats
```

#### Hot-Reload Service Management

```bash
# Service lifecycle management
adversary-mcp-cli watch start --directory rules/custom/ --debounce 2.0
adversary-mcp-cli watch status
adversary-mcp-cli watch test --force

# Development workflow
adversary-mcp-cli watch start  # Terminal 1
# Edit rules in another terminal - automatic reload!
```

#### Enhanced Scanning

```bash
# Single file analysis with custom rules
adversary-mcp-cli scan app.py --severity critical --format json

# Directory scanning with rule filtering
adversary-mcp-cli scan ./src \
  --recursive \
  --language python \
  --exclude tests/ \
  --rules-dir rules/custom/

# Rule-specific analysis
adversary-mcp-cli scan ./api/ --rule-category injection
```

#### Configuration Management

```bash
# Advanced configuration
adversary-mcp-cli configure \
  --openai-api-key sk-... \
  --severity-threshold high \
  --enable-hot-reload \
  --rules-dir ./custom-rules/

# Status with rule information
adversary-mcp-cli status --verbose --include-rules
```

### Integration with CI/CD

```yaml
# .github/workflows/security.yml
name: Security Analysis with Custom Rules
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
      
      - name: Validate Custom Rules
        run: |
          adversary-mcp-cli rules validate
          adversary-mcp-cli rules stats
      
      - name: Security Scan with Custom Rules
        run: |
          adversary-mcp-cli scan . \
            --severity medium \
            --format json \
            --output security-report.json \
            --rules-dir ./security-rules/
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

---

## Development

### Development Environment Setup

```bash
# Quick setup with uv
make uv-init        # Initialize virtual environment
make dev-setup-uv   # Install development dependencies
make test           # Run test suite
make lint           # Code quality checks
make security-scan  # Self-analysis
```

### Enhanced Project Structure

```
adversary-mcp-server/
├── src/adversary_mcp_server/
│   ├── server.py           # MCP server implementation
│   ├── threat_engine.py    # Enhanced rule engine with YAML support
│   ├── ast_scanner.py      # Static analysis engine
│   ├── exploit_generator.py # Exploit generation system
│   ├── credential_manager.py # Secure configuration
│   ├── hot_reload.py       # Hot-reload service (NEW)
│   └── cli.py             # Enhanced command-line interface
├── rules/                 # Packaged rules (copied to user directory)
│   ├── built-in/           # Core security rules (source)
│   └── templates/         # Rule templates (source)
├── tests/                 # Comprehensive test suite (279 tests)
├── docs/                  # Documentation
└── examples/              # Usage examples and vulnerable code

# User rules directory (automatically created):
~/.local/share/adversary-mcp-server/rules/
├── built-in/              # Core security rules (auto-copied)
├── custom/                # User-defined rules
├── organization/          # Company-wide rules
└── templates/             # Rule templates (auto-copied)
```

### Testing

```bash
# Run all tests (279 tests, 89% coverage)
make test

# Run with coverage
make test-coverage

# Run specific test categories
pytest tests/test_threat_engine.py -v
pytest tests/test_hot_reload.py -v
pytest tests/test_cli_extended.py -v

# Integration tests
pytest tests/integration/ -v

# Test hot-reload functionality
pytest tests/test_hot_reload.py::TestHotReloadIntegration -v
```

### Adding Custom Rules

1. **Show Rules Directory Location**
   ```bash
   adversary-mcp-cli show-rules-dir
   ```

2. **Create Rule from Template**
   ```bash
   # Copy template to custom rules directory
   cp ~/.local/share/adversary-mcp-server/rules/templates/rule-template.yaml \
      ~/.local/share/adversary-mcp-server/rules/custom/my-rule.yaml
   
   # Or use CLI import (automatically copies to custom/)
   adversary-mcp-cli rules import-rules ~/.local/share/adversary-mcp-server/rules/templates/rule-template.yaml
   ```

3. **Edit Rule Definition**
   ```yaml
   # Edit rule file with your security pattern
   # ~/.local/share/adversary-mcp-server/rules/custom/my-rule.yaml
   conditions:
     - type: pattern
       value: "dangerous_function\\([^)]*\\)"
       case_sensitive: false
   ```

4. **Validate Rule**
   ```bash
   adversary-mcp-cli rules validate
   ```

5. **Test with Hot-Reload**
   ```bash
   # Terminal 1: Start hot-reload service (auto-watches user rules directory)
   adversary-mcp-cli watch start
   
   # Terminal 2: Edit rule file - automatic reload!
   vim ~/.local/share/adversary-mcp-server/rules/custom/my-rule.yaml
   ```

6. **Add Test Cases**
   ```python
   # tests/test_custom_rules.py
   def test_my_custom_rule():
       result = scanner.scan_code(vulnerable_code)
       assert len(result) == 1
       assert result[0].rule_id == "my_custom_rule"
   ```

---

## Safety & Ethical Guidelines

### Built-in Safety Mechanisms

- **Exploit Safety Mode**: Automatically sanitizes dangerous commands
- **Educational Focus**: All exploits designed for learning purposes
- **Responsible Disclosure**: Encourages proper vulnerability reporting
- **Content Filtering**: Removes potentially harmful exploit techniques
- **Rule Validation**: Prevents malicious or unsafe rule patterns

### Ethical Use Policy

#### ✅ Approved Use Cases
- Security education and training
- Defensive security testing on owned systems  
- Code review and quality assurance
- Academic research with proper oversight
- Bug bounty programs with authorization
- Custom rule development for organizational security

#### ❌ Prohibited Activities
- Unauthorized system access or testing
- Malicious exploitation of discovered vulnerabilities
- Bypassing security controls without permission
- Distribution of exploit code for malicious purposes
- Any illegal security testing activities
- Creating rules for offensive security without proper authorization

### Compliance Considerations

The Adversary MCP Server is designed to support compliance with:
- **OWASP ASVS** (Application Security Verification Standard)
- **NIST Cybersecurity Framework**
- **ISO 27001** security management standards
- **GDPR** privacy protection requirements
- **SOC 2** security controls

---

## Technical Specifications

### Language Support Matrix

| Language   | AST Parser | Function Analysis | Import Tracking | Variable Flow | Rule Support | Status |
|------------|------------|-------------------|-----------------|---------------|--------------|---------|
| Python     | ✅ ast     | ✅ Full          | ✅ Full        | ✅ Full      | ✅ Full     | Stable  |
| JavaScript | ✅ esprima | ✅ Full          | ✅ Full        | ✅ Partial   | ✅ Full     | Stable  |
| TypeScript | ✅ esprima | ✅ Full          | ✅ Full        | ✅ Partial   | ✅ Full     | Stable  |

### Performance Characteristics

- **Analysis Speed**: ~1000 lines/second for typical codebases
- **Memory Usage**: <100MB for projects up to 100k lines
- **Rule Engine**: Sub-millisecond pattern matching with YAML rules
- **Hot-Reload**: <100ms rule update latency
- **MCP Latency**: <50ms response time for most operations

### Rule System Performance

- **Rule Loading**: ~10ms for 100 YAML rules
- **File Watching**: Real-time with configurable debouncing (default 1s)
- **Rule Validation**: <5ms per rule with comprehensive error reporting
- **Statistics Generation**: <10ms for complete rule analytics

### Supported Environments

- **Operating Systems**: macOS, Linux, Windows
- **Python Versions**: 3.10, 3.11, 3.12, 3.13
- **IDEs**: Cursor IDE (primary), extensible via MCP
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, CircleCI
- **File Systems**: Local, NFS, CIFS (for rule file watching)

---

## Contributing

We welcome contributions from the security community! Please review our contribution guidelines:

### Getting Started

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/adversary-mcp-server.git
   cd adversary-mcp-server
   ```

2. **Set Up Development Environment**
   ```bash
   make dev-setup-uv
   source .venv/bin/activate
   ```

3. **Start Hot-Reload for Development**
   ```bash
   adversary-mcp-cli watch start --directory rules/custom/
   ```

4. **Create Feature Branch**
   ```bash
   git checkout -b feature/security-enhancement
   ```

5. **Make Changes and Test**
   ```bash
   make test
   make lint
   make security-scan
   ```

6. **Submit Pull Request**
   - Ensure all tests pass (279 tests, 89% coverage target)
   - Add appropriate documentation
   - Include security considerations
   - Test rule changes with hot-reload service

### Contribution Areas

- **Security Rules**: Add new vulnerability detection patterns
- **Hot-Reload Enhancements**: Improve file watching and service management
- **Language Support**: Extend analysis to additional programming languages
- **IDE Integration**: Improve MCP protocol implementations
- **Performance**: Optimize analysis algorithms and rule processing
- **Documentation**: Enhance user guides and API documentation
- **Rule Templates**: Create specialized rule templates for different security domains

---

## Resources

### Documentation
- [API Reference](docs/api.md)
- [Rule Development Guide](docs/rules.md)
- [Hot-Reload Service Guide](docs/hot-reload.md)
- [MCP Integration Guide](docs/mcp.md)
- [Security Best Practices](docs/security.md)

### External Resources
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Model Context Protocol](https://github.com/modelcontextprotocol/python-sdk)
- [Cursor IDE](https://cursor.sh/)

### Community
- [GitHub Issues](https://github.com/brettbergin/adversary-mcp-server/issues)
- [Discussions](https://github.com/brettbergin/adversary-mcp-server/discussions)
- [Security Advisories](https://github.com/brettbergin/adversary-mcp-server/security/advisories)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OWASP](https://owasp.org/) for security guidelines and vulnerability classifications
- [CWE Program](https://cwe.mitre.org/) for weakness enumeration standards  
- [Model Context Protocol](https://github.com/modelcontextprotocol) for enabling IDE integration
- [Semgrep](https://semgrep.dev/) and [Bandit](https://bandit.readthedocs.io/) for static analysis inspiration

---

<div align="center">

**⚠️ Security Notice**

This tool is designed for educational and defensive security purposes only.  
Users are responsible for ensuring ethical and legal use of this software.

[Report Security Issues](https://github.com/brettbergin/adversary-mcp-server/security/advisories/new) | [View Documentation](docs/) | [Join Community](https://github.com/brettbergin/adversary-mcp-server/discussions)

</div>