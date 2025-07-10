# Adversary MCP Server

<div align="center">

[![PyPI version](https://badge.fury.io/py/adversary-mcp-server.svg)](https://badge.fury.io/py/adversary-mcp-server)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-332%20passed%20%7C%20100%25-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Coverage](https://img.shields.io/badge/coverage-86.02%25-brightgreen.svg)](https://github.com/brettbergin/adversary-mcp-server)
[![Version](https://img.shields.io/badge/version-v0.7.1-blue.svg)](https://pypi.org/project/adversary-mcp-server/)

**Software security analysis with hybrid AI-powered threat detection and configurable built-in and custom rule management**

[Installation](#installation) • [Quick Start](#quick-start) • [AI-Powered Analysis](#ai-powered-analysis) • [MCP Integration](#mcp-integration) • [Rule Management](#rule-management) • [CLI Reference](#cli-reference)

</div>

---

## Installation

### Prerequisites

- **Python 3.10+** (3.11+ recommended)
- **Cursor IDE** with MCP support

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

# View available rules and setup
adversary-mcp-cli rules stats
```

### 2. Cursor IDE Integration

Create `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "adversary-security": {
      "command": "/Users/<user>/envs/.venv/bin/python",
      "args": ["-m", "adversary_mcp_server.server"],
      "env": {
        "ADVERSARY_CONFIG_DIR": "~/.local/share/adversary-mcp-server"
      }
    }
  }
}
```

### 3. Start Using in Cursor

Once configured, you can use these MCP tools in Cursor:

- `adv_scan_code` - Hybrid scanning with rules + AI analysis
- `adv_scan_file` - file scanning with LLM support
- `adv_scan_directory` - directory scanning
- `adv_diff_scan` - **🆕 Git diff-aware scanning** - scans only changed files between branches
- `adv_list_rules` - List all 95+ security rules
- `adv_get_rule_details` - Get details about specific rules
- `adv_generate_exploit` - exploit generation
- `adv_configure_settings` - Configuration management
- `adv_get_status` - Check server status and AI availability
- `adv_get_version` - Get version information

### 4. Enable Hot-Reload (Optional)

For real-time rule updates during development:

```bash
# Start hot-reload service
adversary-mcp-cli watch start

# Now edit rules and they'll automatically reload
```

### 5. **🆕 Git Diff-Aware Scanning**

Scan only changed files between git branches for efficient CI/CD integration:

```bash
# Scan changes in your current branch vs main
adversary-mcp-cli scan --diff

# Scan changes between specific branches
adversary-mcp-cli scan --diff --source-branch=develop --target-branch=feature/auth

# Scan with high severity filter
adversary-mcp-cli scan --diff --severity=high --use-llm=true
```

---

### ** Scanning **

```bash
# Scan with AI enhancement (hybrid mode)
Use adv_scan_code with use_llm=true for comprehensive analysis

# Traditional rules-only scanning
Use adv_scan_code with use_llm=false for simple analysis
```

### **AI Analysis Features**

- **🎯 Smart Threat Detection**: Identifies vulnerabilities that traditional rules miss
- **📊 Confidence Scoring**: Each finding includes AI-generated confidence levels
- **🔍 Detailed Explanations**: Natural language descriptions of vulnerabilities
- **🏷️ CWE/OWASP Mapping**: Automatic categorization with industry standards
- **⚡ Intelligent Deduplication**: Merges similar findings from multiple engines

### **LLM Integration**

The scanner integrates with the existing models in your client application.

```bash
adversary-mcp-cli status
```

**Note**: LLM analysis is provided through prompts that can be used with your preferred LLM service. The scanner generates structured prompts for:
- Security analysis
- Exploit generation
- Code review
- Vulnerability explanations

---

## MCP Integration

### Available Tools

| Tool | Description | **🆕 AI Features** |
|------|-------------|-------------------|
| `adv_scan_code` | **🆕 Hybrid scan** of source code | ✅ LLM prompts, confidence scoring |
| `adv_scan_file` | **🆕 Enhanced** file scanning | ✅ AI-powered prompts, detailed explanations |
| `adv_scan_directory` | **🆕 Intelligent** directory scanning | ✅ Batch LLM prompts, statistical insights |
| `adv_diff_scan` | **🆕 Git diff-aware scanning** - scans only newly added lines | ✅ Smart change detection, branch comparison, requires `working_directory` |
| `adv_generate_exploit` | **🆕 AI-enhanced** exploit generation | ✅ Context-aware prompts, safety mode |
| `adv_list_rules` | List all 95+ threat detection rules | Enhanced with AI rule categories |
| `adv_get_rule_details` | Get detailed rule information | Improved formatting and examples |
| `adv_configure_settings` | **🆕 Advanced** configuration management | ✅ LLM settings, validation |
| `adv_get_status` | Get server status and **🆕 AI availability** | ✅ LLM configuration status |
| `adv_get_version` | Get version information | Shows AI capabilities |

### **🆕 Enhanced Tool Parameters**

All scanning tools now support:

```json
{
  "use_llm": true,              // Enable LLM prompts
  "severity_threshold": "medium", // Filter by severity
  "include_exploits": true,       // Include exploit examples
  "confidence_threshold": 0.8     // AI confidence filtering
}
```

### Example Usage in Cursor

```
# NEW: AI-powered vulnerability scanning
Use adv_scan_code with use_llm=true to analyze this function

# NEW: Git diff-aware scanning
Use adv_diff_scan to scan only changed files between branches

# NEW: Generate AI-enhanced exploits
Use adv_generate_exploit for this SQL injection

# NEW: Check AI analysis availability
Use adv_get_status to get the MCP server status
```

### **🆕 Git Diff-Aware Scanning**

The new `adv_diff_scan` tool enables intelligent scanning of only changed files between git branches:

#### **Key Features:**
- **Smart Change Detection**: Analyzes only modified code, not entire repository
- **Branch Comparison**: Compares any two branches (main vs. feature, staging vs. production)
- **Line-Level Precision**: Scans **only newly added lines** (lines with `+` in git diff), ignoring context lines and removed code
- **Statistics Generation**: Provides comprehensive diff statistics and threat metrics
- **Full Integration**: Works with all existing scan options (LLM, exploits, severity filtering)

#### **🎯 Scanning Scope (Updated)**
- ✅ **Newly added lines** (lines starting with `+` in git diff)
- ❌ **Context lines** (unchanged code shown for reference)
- ❌ **Removed lines** (deleted code)
- ❌ **Existing code** in the repository

This prevents false positives from flagging existing code as new vulnerabilities.

#### **MCP Tool Parameters:**
```json
{
  "source_branch": "main",        // Branch to compare from
  "target_branch": "feature/new", // Branch to compare to
  "working_directory": "/absolute/path/to/repo",  // ⚠️ REQUIRED: Working directory for git operations
  "severity_threshold": "medium", // Filter results by severity
  "include_exploits": true,       // Include exploit examples
  "use_llm": true                // Enable AI analysis
}
```

#### **Example Usage:**
```
# Scan changes in current branch vs main
Use adv_diff_scan with source_branch="main", target_branch="HEAD", and working_directory="/path/to/your/repo"

# Scan changes between specific branches
Use adv_diff_scan with source_branch="staging", target_branch="production", and working_directory="/path/to/your/repo"

# Scan with high severity filter
Use adv_diff_scan with severity_threshold="high" and working_directory="/path/to/your/repo"
```

#### **⚠️ Important Requirements:**
1. **Must specify `working_directory`**: The absolute path to your git repository
2. **Valid git repository**: The directory must contain a `.git` folder
3. **Valid branches**: Both source and target branches must exist
4. **Git available**: `git` command must be available in PATH

---

## Rule Management

### **🆕 Enhanced Rule Engine**
- **95+ Built-in Rules** (expanded from 85)
- **🆕 AI-Enhanced Categories** with better organization
- **🆕 Confidence-Based Filtering** for more accurate results
- **🆕 Hybrid Rule Validation** using both static and AI analysis

### Rule Directory Structure

Rules are automatically organized in your user directory:

```
~/.local/share/adversary-mcp-server/rules/
├── built-in/              # Core security rules (95 rules)
│   ├── python-rules.yaml        # 🆕 Enhanced Python rules
│   ├── javascript-rules.yaml    # 🆕 Enhanced JavaScript rules  
│   ├── typescript-rules.yaml    # 🆕 Enhanced TypeScript rules
│   ├── web-security-rules.yaml  # 🆕 Enhanced Web security
│   ├── api-security-rules.yaml  # 🆕 Enhanced API security
│   ├── cryptography-rules.yaml  # 🆕 Enhanced Crypto rules
│   └── configuration-rules.yaml # 🆕 Enhanced Config rules
├── custom/                # Your custom rules
├── organization/          # Company/team rules
└── templates/             # 🆕 Enhanced rule templates
```

### **🆕 AI-Enhanced Rule Management**

```bash
# View enhanced rules with AI categories
adversary-mcp-cli list-rules --show-ai-categories

# Validate rules with AI assistance
adversary-mcp-cli rules validate --use-ai

# Enhanced rule statistics
adversary-mcp-cli rules stats --detailed
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
| `adversary-mcp-cli scan --diff` | **🆕 Git diff-aware scanning** - scan only newly added lines (no context) |
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

### **🆕 Git Diff-Aware Scanning Options**

The `scan` command now supports git diff-aware scanning with the following options:

| Option | Description | Default |
|--------|-------------|---------|
| `--diff/--no-diff` | Enable git diff-aware scanning | `false` |
| `--source-branch` | Source branch for comparison | `main` |
| `--target-branch` | Target branch for comparison | `HEAD` |
| `--severity` | Minimum severity threshold | `medium` |
| `--include-exploits/--no-exploits` | Include exploit examples | `true` |
| `--use-llm/--no-llm` | Enable AI analysis | `true` |
| `--output` | Output results to JSON file | None |

#### **Diff Scanning Examples:**
```bash
# Basic diff scan (main vs current branch) - scans only newly added lines
adversary-mcp-cli scan --diff

# Compare specific branches - scans only new code between branches
adversary-mcp-cli scan --diff --source-branch=develop --target-branch=feature/auth

# High severity threats only - filters results to high/critical severity
adversary-mcp-cli scan --diff --severity=high

# Save diff scan results to JSON file
adversary-mcp-cli scan --diff --output=security-diff.json

# Comprehensive diff analysis with AI - includes LLM prompts for enhanced analysis
adversary-mcp-cli scan --diff --use-llm=true --include-exploits=true

# Specify custom directory for git operations
adversary-mcp-cli scan /path/to/repo --diff --source-branch=main --target-branch=HEAD
```

### Utility Commands

| Command | Description |
|---------|-------------|
| `adversary-mcp-cli show-rules-dir` | Show rules directory location |
| `adversary-mcp-cli demo` | Run interactive demo |
| `adversary-mcp-cli reset` | Reset all configuration |

---

## Security Coverage

### **🆕 Comprehensive Hybrid Analysis (95+ Rules + AI)**

#### **Traditional Rule-Based Detection**
- **Python** (25+ rules): SQL injection, command injection, deserialization, path traversal
- **JavaScript/TypeScript** (30+ rules): XSS, prototype pollution, eval injection, CORS issues  
- **Web Security** (18+ rules): CSRF, clickjacking, security headers, session management
- **API Security** (15+ rules): Authentication bypass, parameter pollution, mass assignment
- **Cryptography** (15+ rules): Weak algorithms, hardcoded keys, poor randomness
- **Configuration** (15+ rules): Debug mode, default credentials, insecure settings

#### **🆕 AI-Powered Detection**
- **Context-Aware Analysis**: Understands complex vulnerability patterns
- **Business Logic Flaws**: Identifies application-specific issues
- **Advanced Injection Variants**: Detects novel attack vectors
- **Compliance Violations**: Recognizes regulatory requirement breaches
- **Security Anti-Patterns**: Identifies poor security practices

### **🆕 Enhanced Standards Compliance**

- **OWASP Top 10 2021** - Complete coverage with AI enhancement
- **CWE** - Common Weakness Enumeration mappings + AI categorization
- **NIST** - Security framework alignment with intelligent analysis
- **Industry best practices** - SANS, CERT guidelines + AI insights
- **🆕 MITRE ATT&CK** - Threat modeling integration
- **🆕 ASVS** - Application Security Verification Standard

### **Full Language Support**

- **Python** - AST-based analysis + AI semantic understanding
- **JavaScript** - Modern ES6+ and Node.js patterns + AI context analysis
- **TypeScript** - Type safety vulnerabilities + AI-powered type inference analysis

### **Limited Language Support**
- TBD
---

## 🏗️ Enhanced Architecture

The v0.7.1 release features a **hybrid architecture** combining multiple analysis engines:

```mermaid
graph TB
    A[Source Code] --> B[Enhanced Scanner]
    B --> C[AST Scanner]
    B --> D[🆕 LLM Analyzer]
    
    C --> E[Rule Engine]
    E --> F[95+ Built-in Rules]
    E --> G[Custom Rules]
    
    D --> H[LLM Service]
    H --> I[AI Security Analysis]
    
    C --> J[Threat Matches]
    D --> K[LLM Findings]
    
    J --> L[🆕 Intelligent Merger]
    K --> L
    
    L --> M[Enhanced Results]
    M --> N[Confidence Scoring]
    M --> O[Deduplication]
    M --> P[Statistical Analysis]
    
    subgraph "🆕 AI Enhancement"
        D
        H
        I
        K
    end
    
    subgraph "Traditional Analysis"
        C
        E
        F
        G
        J
    end
    
    subgraph "🆕 Hybrid Output"
        L
        M
        N
        O
        P
    end
```

### **🆕 Integration Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Cursor IDE    │───▶│🆕 Enhanced MCP  │───▶│🆕 Hybrid Engine │
│                 │    │     Server      │    │                 │
│ • Code editing  │    │ • adv_* tools   │    │ • AST Analysis  │
│ • Chat interface│    │ • AI integration│    │ • LLM Analysis  │
│ • Tool calling  │    │ • Protocol      │    │ • Hot-reload    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                              ┌─────────────────────────┼─────────────────────────┐
                              │                         ▼                         │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │🆕 Enhanced Rules│    │  Custom Rules   │    │Organization Rules│
                    │   (95+ rules)   │    │  User defined   │    │ Company policies│
                    │ Multi-language  │    │ Project specific│    │  Compliance     │
                    │ + AI Categories │    │ + AI Templates  │    │ + AI Validation │
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                              ┌─────────────────────────┼─────────────────────────┐
                              │                         ▼                         │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │ 🆕 LLM Service  │     │🆕 Confidence    │    │🆕 Statistical   │
                    │   Integration   │    │   Scoring       │    │   Analysis      │
                    │ • External APIs │    │ • Reliability   │    │ • Detailed      │
                    │ • Context-aware │    │ • Deduplication │    │   Metrics       │
                    │ • NL Explanations│   │ • Smart Merging │    │ • Trend Analysis│
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

---


#### **Traditional Rules-Only Analysis**
```bash
# Fast, deterministic scanning
adversary-mcp-cli scan myproject/ --use-llm=false --severity=medium
```

#### **🆕 AI-Enhanced Analysis**
```bash
# Comprehensive hybrid analysis with LLM prompts
adversary-mcp-cli scan myproject/ --use-llm=true --confidence-threshold=0.8
```

#### **🆕 Git Diff-Aware Scanning**
```bash
# Scan only newly added lines between branches (no context lines)
adversary-mcp-cli scan --diff --source-branch=main --target-branch=HEAD

# Scan changes with specific severity threshold - only new code
adversary-mcp-cli scan --diff --source-branch=staging --target-branch=production --severity=high

# Scan current branch changes with AI analysis - includes LLM prompts for new code
adversary-mcp-cli scan --diff --use-llm=true --include-exploits=true

# Specify repository directory for git operations
adversary-mcp-cli scan /path/to/repo --diff --source-branch=main --target-branch=feature/new
```

### **🆕 Advanced Configuration**

#### **LLM Configuration**
```bash
# Configure LLM analysis settings
adversary-mcp-cli configure --enable-llm-analysis=true
adversary-mcp-cli configure --exploit-safety-mode=true
```

#### **🆕 Confidence and Filtering**
```bash
# Filter by AI confidence levels
adversary-mcp-cli scan . --confidence-threshold 0.9 --use-llm=true

# Combine rules and AI with custom thresholds
adversary-mcp-cli scan . --severity=high --confidence-threshold=0.7
```

### **🆕 Enhanced Reporting**

#### **Detailed Analysis Reports**
```bash
# Generate comprehensive reports with AI insights
adversary-mcp-cli scan . --format=detailed --include-ai-analysis --output=report.json
```

#### **🆕 Statistical Analysis**
```bash
# Get detailed statistics about threats found
adversary-mcp-cli scan . --stats --use-llm=true
```

### **🆕 Integration Capabilities**

#### **IDE Integration**
The enhanced MCP server provides seamless integration with development environments:

- **Real-time Analysis**: Instant feedback as you type
- **Context-Aware Suggestions**: AI understands your specific codebase
- **Intelligent Deduplication**: No duplicate alerts from multiple engines
- **Confidence Indicators**: Know which findings are most reliable

#### **🆕 LLM Prompt Generation**
```python
# Use the enhanced scanner programmatically
from adversary_mcp_server.enhanced_scanner import EnhancedScanner

scanner = EnhancedScanner(enable_llm_analysis=True)
result = scanner.scan_code(source_code, file_path, language, use_llm=True)

# Access hybrid results
print(f"Total threats: {len(result.all_threats)}")
print(f"Rules-based: {len(result.rules_threats)}")
print(f"LLM prompts generated: {len(result.llm_prompts)}")
print(f"High confidence: {len(result.get_high_confidence_threats())}")
```

---

## Advanced Usage

### CI/CD Integration

#### **🆕 Git Diff-Aware CI/CD Scanning**

For efficient CI/CD pipelines, scan only newly added lines in pull requests:

```yaml
# .github/workflows/security.yml
name: Security Analysis
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Required for git diff analysis
      
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Adversary MCP
        run: pip install adversary-mcp-server
      
      - name: Diff Security Scan (PR) - Scans only newly added lines
        if: github.event_name == 'pull_request'
        run: |
          adversary-mcp-cli scan . --diff \
            --source-branch=origin/main \
            --target-branch=HEAD \
            --severity=medium \
            --output=security-diff.json
        env:
          GITHUB_WORKSPACE: ${{ github.workspace }}
      
      - name: Full Security Scan (Push to main)
        if: github.ref == 'refs/heads/main'
        run: |
          adversary-mcp-cli scan . \
            --severity medium \
            --output=security-full.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-*.json
```

#### **Traditional Full Repository Scanning**

```yaml
# Traditional approach (scans entire repository)
- name: Full Security Scan
  run: |
    adversary-mcp-cli scan . \
      --severity medium \
      --format json \
      --output security-report.json
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
│   ├── built-in/           # 95+ core security rules
│   └── templates/         # Rule creation templates
└── tests/                 # Comprehensive test suite (332 tests)
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

### Version Management

The project uses centralized version management - you only need to update the version in one place:

1. **Update version in `pyproject.toml`:**
   ```toml
   [project]
   version = "0.7.5"  # Update this line only
   ```

2. **All components automatically use the updated version:**
   - CLI: `adversary-mcp-cli --version`
   - Server: MCP server initialization 
   - Package: `from adversary_mcp_server import __version__`

3. **Lock file updates automatically:**
   ```bash
   uv sync  # Updates uv.lock with new version
   ```

**No manual updates needed** in `server.py` or elsewhere - the version is read dynamically from `pyproject.toml`.

---

## Support

- **Documentation**: [GitHub Wiki](https://github.com/brettbergin/adversary-mcp-server/wiki)
- **Issues**: [GitHub Issues](https://github.com/brettbergin/adversary-mcp-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/brettbergin/adversary-mcp-server/discussions)

---

<div align="center">

**Built with ❤️ for secure development**

</div>

## Important Notes

### Diff Scanning Scope

The `adv_diff_scan` tool **only scans newly added lines** (lines starting with `+` in git diff), not context lines or existing code. This prevents false positives from flagging existing code as new vulnerabilities.

**What gets scanned:**
- ✅ Newly added lines (actual changes)
- ❌ Context lines (unchanged code shown for reference)
- ❌ Removed lines (deleted code)

This means you'll only see security issues for code you've actually added or modified, not for existing code in the repository.

## Troubleshooting

### Git Diff Scanning Issues

If you encounter the error `"Failed to get diff summary"` when using `adv_diff_scan`, this is typically caused by one of these issues:

#### **Common Causes & Solutions:**

1. **Working Directory Issue**
   ```
   Error: Tool adv_diff_scan failed: Diff scanning failed: Git diff operation failed: Failed to get diff summary
   ```
   
   **Solution:** Specify the correct working directory:
   ```json
   {
     "source_branch": "main",
     "target_branch": "feature/my-branch", 
     "working_directory": "/path/to/your/git/repository"
   }
   ```

2. **Branch Not Found**
   ```
   Error: Branch validation failed: Branch not found
   ```
   
   **Solution:** Verify branch names exist:
   ```bash
   cd /path/to/your/repo
   git branch -a  # List all branches
   ```

3. **Not a Git Repository**
   ```
   Error: Git command failed: fatal: not a git repository
   ```
   
   **Solution:** Ensure you're pointing to a valid git repository:
   ```json
   {
     "working_directory": "/path/to/valid/git/repo"
   }
   ```

4. **Git Not Available**
   ```
   Error: Git command not found
   ```
   
   **Solution:** Install git or ensure it's in your PATH.

#### **Best Practices:**

- Always specify the `working_directory` parameter when the repository is not in the current directory
- Use full/absolute paths for `working_directory` to avoid confusion  
- Verify branch names with `git branch -a` before running scans
- For remote branches, use the full name (e.g., `origin/main` not just `main`)

#### **Example Working Configuration:**
```json
{
  "source_branch": "origin/main",
  "target_branch": "HEAD", 
  "working_directory": "/Users/username/my-project",
  "severity_threshold": "medium",
  "include_exploits": true,
  "use_llm": false
}
```