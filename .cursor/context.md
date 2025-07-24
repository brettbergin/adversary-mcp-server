# Adversary MCP Server - Project Context

## Project Overview

The Adversary MCP Server is a sophisticated security analysis tool that provides vulnerability detection and threat analysis capabilities through the Model Context Protocol (MCP). It combines traditional rule-based scanning with AI-powered analysis to identify security vulnerabilities in source code.

### Core Purpose
- **Security Analysis**: Automated detection of security vulnerabilities in codebases
- **Threat Detection**: AI-enhanced threat identification using multiple scanning engines
- **MCP Integration**: Seamless integration with Cursor IDE and other MCP-compatible tools
- **Rule Management**: Flexible system for built-in, custom, and organizational security rules

## Architecture Overview

### Key Components

#### 1. MCP Server (`server.py`)
- **Purpose**: Main entry point for MCP protocol handling
- **Features**: Exposes security analysis tools to MCP clients
- **Tools Provided**:
  - `adv_scan_code`: Analyze code snippets for vulnerabilities
  - `adv_scan_file`: Scan individual files
  - `adv_scan_folder`: Recursive directory scanning
  - `adv_diff_scan`: Git diff-aware scanning
  - `adv_mark_false_positive`: Mark findings as false positives
  - Rule management tools

#### 2. Scan Engine (`scan_engine.py`)
- **Purpose**: Orchestrates multiple security scanners
- **Features**: Combines results from rules, LLM, and Semgrep scanners
- **Key Classes**:
  - `ScanEngine`: Main orchestration class
  - `EnhancedScanResult`: Comprehensive scan result container

#### 3. Security Scanners

##### Rules Scanner (`threat_engine.py`)
- **Purpose**: Traditional pattern-based vulnerability detection
- **Features**: YAML-based rule definitions with pattern matching
- **Rule Categories**: Injection, XSS, Authentication, Cryptography, etc.

##### LLM Scanner (`llm_scanner.py`)
- **Purpose**: AI-powered semantic vulnerability analysis
- **Features**: Uses OpenAI API for contextual security analysis
- **Capabilities**: Complex vulnerability patterns, business logic flaws

##### Semgrep Scanner (`semgrep_scanner.py`)
- **Purpose**: Static analysis using Semgrep engine
- **Features**: Industry-standard SAST rules
- **Performance**: Optimized for large codebases

#### 4. Supporting Systems

##### False Positive Manager (`false_positive_manager.py`)
- **Purpose**: Track and suppress known false positives
- **Features**:
  - File-based storage in `.adversary.json` files
  - UUID-based tracking
  - Performance-optimized caching system
- **Recent Enhancement**: Added intelligent caching to prevent 4-minute delays

##### Exploit Generator (`exploit_generator.py`)
- **Purpose**: Generate proof-of-concept exploits for vulnerabilities
- **Features**: Template-based exploit generation with LLM enhancement

##### Credential Manager (`credential_manager.py`)
- **Purpose**: Secure handling of API keys and credentials
- **Features**: OS keyring integration, environment variable fallback

## Project Structure

```
adversary-mcp-server/
├── src/adversary_mcp_server/          # Main source code
│   ├── server.py                      # MCP server implementation
│   ├── scan_engine.py                 # Scanner orchestration
│   ├── threat_engine.py               # Rules-based scanner
│   ├── llm_scanner.py                 # AI-powered scanner
│   ├── semgrep_scanner.py             # Semgrep integration
│   ├── false_positive_manager.py      # False positive handling
│   ├── exploit_generator.py           # Exploit generation
│   ├── credential_manager.py          # Secure credential storage
│   ├── diff_scanner.py                # Git diff analysis
│   ├── ast_scanner.py                 # AST-based analysis
│   ├── hot_reload.py                  # Development hot reload
│   ├── security_config.py             # Security configuration
│   ├── logging_config.py              # Logging setup
│   └── cli.py                         # Command-line interface
├── rules/                             # Security rule definitions
│   ├── built-in/                      # Default rules
│   ├── custom/                        # User-defined rules
│   ├── organization/                  # Organization-specific rules
│   └── templates/                     # Rule templates
├── tests/                             # Comprehensive test suite
├── examples/                          # Vulnerable test code for scanner validation
│   ├── vulnerable_python.py          # Python code with security vulnerabilities
│   └── vulnerable_javascript.js      # JavaScript code with security vulnerabilities
└── scripts/                           # Utility scripts
```

## Data Models

### Core Data Types

#### ThreatMatch
- Represents a detected security vulnerability
- Contains metadata: severity, category, location, remediation
- Supports false positive tracking and exploit examples

#### EnhancedScanResult
- Comprehensive scan result container
- Aggregates findings from multiple scanners
- Includes metadata about scan execution and performance

#### ThreatRule
- YAML-based rule definitions
- Supports multiple languages and pattern types
- Includes remediation guidance and references

### JSON Schemas

#### Scan Results (`.adversary.json`)
```json
{
  "scan_metadata": { ... },
  "threats": [
    {
      "uuid": "unique-identifier",
      "rule_id": "rule-identifier",
      "severity": "critical|high|medium|low",
      "category": "injection|xss|auth|crypto|...",
      "file_path": "path/to/file",
      "line_number": 42,
      "code_snippet": "vulnerable code",
      "is_false_positive": false,
      "false_positive_metadata": null,
      ...
    }
  ]
}
```

## Security Features

### Multi-Layer Scanning
1. **Pattern-Based Rules**: Traditional regex and AST patterns
2. **AI Analysis**: Contextual understanding of business logic
3. **Static Analysis**: Industry-standard SAST tools (Semgrep)

### Vulnerability Categories
- **Injection Flaws**: SQL injection, command injection, LDAP injection
- **Cross-Site Scripting (XSS)**: Reflected, stored, DOM-based
- **Authentication Issues**: Weak passwords, session management
- **Cryptographic Failures**: Weak algorithms, improper key management
- **Information Disclosure**: Sensitive data exposure
- **Business Logic Flaws**: Application-specific vulnerabilities

### Performance Optimizations
- **Caching**: Intelligent caching for repeated operations
- **Async Processing**: Non-blocking I/O for large scans
- **Incremental Scanning**: Git diff-aware scanning
- **Memory Management**: Optimized for large codebases

## Integration Points

### MCP Protocol
- **Tools**: Expose security analysis capabilities
- **Resources**: Provide access to rules and configuration
- **Prompts**: Security-focused code analysis prompts

### External Tools
- **Semgrep**: Static analysis integration
- **OpenAI API**: LLM-powered analysis
- **Git**: Version control integration for diff scanning
- **Tree-sitter**: Syntax parsing for multiple languages

### IDE Integration
- **Cursor**: Primary IDE integration
- **VS Code**: Compatible through MCP
- **CLI**: Standalone command-line interface

## Development Patterns

### Error Handling
- Comprehensive exception handling with contextual messages
- Graceful degradation when external services are unavailable
- Detailed logging for debugging and monitoring

### Configuration Management
- Environment-based configuration
- Secure credential storage
- Flexible rule management system

### Testing Strategy
- Unit tests for individual components
- Integration tests for scanner combinations
- Security tests for vulnerability detection accuracy
- Performance tests for large codebases

## Common Workflows

### Adding New Security Rules
1. Create YAML rule definition in `rules/` directory
2. Test rule effectiveness with examples
3. Add unit tests for rule validation
4. Update documentation

### Integrating New Scanner
1. Implement scanner interface
2. Add to scan engine orchestration
3. Update result aggregation logic
4. Add comprehensive tests

### Performance Optimization
1. Profile bottlenecks using logging
2. Implement caching where appropriate
3. Optimize I/O operations
4. Test with realistic large codebases

## Key Dependencies

### Runtime Dependencies
- **MCP**: Model Context Protocol implementation
- **Pydantic**: Data validation and serialization
- **Click**: Command-line interface framework
- **Rich**: Enhanced terminal output
- **OpenAI**: AI-powered analysis
- **Semgrep**: Static analysis engine

### Development Dependencies
- **Pytest**: Testing framework
- **Black**: Code formatting
- **Ruff**: Fast Python linting
- **MyPy**: Static type checking
- **UV**: Fast Python package manager
