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

## 🔗 MCP Integration with Cursor IDE

### What is MCP?

The **Model Context Protocol (MCP)** allows AI assistants like Cursor to access external tools and data sources. The Adversary MCP Server acts as a security-focused "co-pilot" that analyzes your code in real-time as you develop.

### Setting Up with Cursor IDE

1. **Install the Package**
   ```bash
   pip install adversary-mcp-server
   ```

2. **Configure Cursor IDE**
   Create an MCP configuration file in one of these locations:
   - **Project-specific**: `.cursor/mcp.json` (for this project only)
   - **Global**: `~/.cursor/mcp.json` (for all projects)
   
   Add the following configuration:
   ```json
   {
     "mcpServers": {
       "adversary-security": {
         "command": "adversary-mcp-server",
         "args": [],
         "env": {
           "ADVERSARY_CONFIG_DIR": "~/.adversary-mcp"
         }
       }
     }
   }
   ```

3. **Restart Cursor IDE**
   The server will automatically start when Cursor launches.

### 🎯 User Experience Examples

#### Scenario 1: Real-time Vulnerability Detection

**You're coding in Cursor IDE:**
```python
# You type this vulnerable code:
def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)
```

**Adversary MCP Server responds instantly in chat:**
```
🚨 **Security Alert: SQL Injection Detected**

**File:** auth.py:3
**Severity:** 🟥 **CRITICAL**
**Vulnerability:** SQL Injection via string formatting

**Vulnerable Code:**
```python
query = f"SELECT * FROM users WHERE username = '{username}'"
```

**🎯 Exploit Example:**
Input: `admin' OR '1'='1' --`
Result: Bypasses authentication entirely

**✅ Recommended Fix:**
```python
query = "SELECT * FROM users WHERE username = ?"
return db.execute(query, (username,))
```

**📚 Learn More:** [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
```

#### Scenario 2: Interactive Security Analysis

**You ask Cursor:** *"Can you scan my entire authentication module for security issues?"*

**Cursor uses the MCP server:**
```
🔍 **Scanning auth_module.py for vulnerabilities...**

**Found 4 security issues:**

1. **🟥 SQL Injection** (Line 23)
   - Direct string concatenation in login query
   - **Impact:** Complete database compromise

2. **🟠 Command Injection** (Line 45) 
   - Unsanitized input to os.system()
   - **Impact:** Remote code execution

3. **🟡 Weak Password Hashing** (Line 67)
   - Using MD5 instead of bcrypt
   - **Impact:** Credential compromise

4. **🟡 Information Disclosure** (Line 89)
   - Stack traces exposed to users
   - **Impact:** System information leakage

**🛠️ Would you like me to generate secure code examples for each issue?**
```

#### Scenario 3: Educational Exploit Generation

**You ask:** *"Show me how the SQL injection on line 23 could be exploited"*

**MCP Server provides educational examples:**
```
🎓 **Educational Exploit Analysis**

**Vulnerability:** SQL Injection in user authentication

**Attack Vectors:**

1. **Authentication Bypass:**
   ```
   Username: admin' OR '1'='1' --
   Result: Logs in as admin without password
   ```

2. **Data Extraction:**
   ```
   Username: ' UNION SELECT password FROM users WHERE username='admin' --
   Result: Reveals admin password hash
   ```

3. **Database Enumeration:**
   ```
   Username: ' UNION SELECT table_name FROM information_schema.tables --
   Result: Lists all database tables
   ```

**⚠️ Safety Note:** These examples are for educational purposes only. Use responsibly in authorized testing environments.

**🛡️ Defense:** Implement parameterized queries and input validation.
```

#### Scenario 4: Code Review Integration

**During code review, you ask:** *"Review this pull request for security issues"*

**MCP Server analyzes the entire PR:**
```
📋 **Security Review for PR #123**

**Files Analyzed:** 8
**New Vulnerabilities:** 2
**Fixed Issues:** 1
**Security Score:** 🟢 **Improved** (87% → 94%)

**New Issues Found:**

📁 **src/api/user_controller.py**
- Line 34: **Insecure Direct Object Reference**
  - Users can access other users' data by changing ID parameter
  - **Recommendation:** Add authorization checks

📁 **src/utils/file_handler.py**  
- Line 12: **Path Traversal Vulnerability**
  - File paths not validated, allowing `../` attacks
  - **Recommendation:** Sanitize file paths and use allowlisting

**✅ Fixed Issues:**
- SQL injection in login function (great work!)

**🎯 Overall Assessment:** This PR significantly improves security posture. Address the 2 new issues before merging.
```

### 🔄 Continuous Security Workflow

The MCP integration creates a seamless security workflow:

1. **✍️ Write Code** → Adversary MCP monitors in real-time
2. **🚨 Get Instant Alerts** → Security issues flagged immediately  
3. **📚 Learn & Understand** → Detailed explanations and exploit examples
4. **🛠️ Fix Vulnerabilities** → Guided remediation with secure code examples
5. **✅ Verify Fixes** → Re-scan to confirm issues resolved
6. **🔄 Repeat** → Continuous security improvement

### 🎯 MCP Tools Available

When integrated with Cursor, you can use natural language to:

- **"Scan this file for vulnerabilities"** → `scan_file`
- **"Check my entire project for SQL injection"** → `scan_directory` with filtering
- **"Show me how this XSS attack works"** → `generate_exploit`
- **"What security rules are available?"** → `list_rules`
- **"Explain the OWASP Top 10 rule for injection"** → `get_rule_details`
- **"Configure my security settings"** → `configure_settings`
- **"What's the server status?"** → `get_status`

### 🏆 Benefits of MCP Integration

- **🚀 Real-time Analysis** - Catch vulnerabilities as you code
- **🎓 Educational** - Learn security through hands-on examples
- **⚡ Zero Context Switching** - Security analysis within your IDE
- **🤝 AI-Powered** - Natural language interaction with security tools
- **🔄 Continuous** - Always-on security monitoring
- **📈 Learning Curve** - Improves your security skills over time

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

### Available MCP Tools

The server exposes these tools for IDE integration:

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `scan_code` | Analyze code snippets for vulnerabilities | Paste code and get instant security feedback |
| `scan_file` | Security scan of specific files | `"Scan auth.py for injection vulnerabilities"` |
| `scan_directory` | Recursive directory analysis | `"Check my entire API folder for security issues"` |
| `generate_exploit` | Educational exploit examples | `"Show me how this XSS could be exploited"` |
| `list_rules` | Browse detection rules | `"What Python security rules are available?"` |
| `get_rule_details` | Deep dive into specific rules | `"Explain the SQL injection detection rule"` |
| `configure_settings` | Adjust server configuration | `"Enable high severity only"` |
| `get_status` | Check server health | `"Is the security scanner working?"` |

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