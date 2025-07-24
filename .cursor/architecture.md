# Adversary MCP Server - Architecture

## System Overview

The Adversary MCP Server is designed as a modular, extensible security analysis platform that integrates multiple scanning engines through a unified MCP interface. The architecture emphasizes performance, accuracy, and ease of integration with development tools.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cursor IDE / MCP Client                     │
└─────────────────────┬───────────────────────────────────────────┘
                      │ MCP Protocol
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Server Layer                            │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Tool Handler  │ │  Resource Mgr   │ │  Prompt Handler │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Scan Engine Layer                            │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │  Orchestrator   │ │ Result Merger   │ │ Performance Mgr │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─┬─────────────────┬─────────────────┬─────────────────────────┬─┘
  │                 │                 │                         │
  ▼                 ▼                 ▼                         ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐
│Rules Scanner│ │LLM Scanner  │ │Semgrep      │ │AST Scanner      │
│             │ │             │ │Scanner      │ │                 │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────────┘
  │                 │                 │                         │
  ▼                 ▼                 ▼                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Support Layer                                │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│ │False Pos    │ │Exploit Gen  │ │Credential   │ │Config     │ │
│ │Manager      │ │             │ │Manager      │ │Manager    │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. MCP Server Layer (`server.py`)

**Purpose**: Protocol adapter between MCP clients and security analysis engine

**Key Responsibilities**:
- Handle MCP protocol messages
- Validate tool requests and parameters
- Route requests to appropriate handlers
- Format responses for MCP clients
- Manage server lifecycle and resources

**MCP Tools Exposed**:
```python
# Security Analysis Tools
adv_scan_code       # Analyze code snippets
adv_scan_file       # Scan individual files
adv_scan_folder     # Recursive directory scanning
adv_diff_scan       # Git diff-aware scanning

# Rule Management Tools
adv_list_rules      # List available security rules
adv_get_rule_details# Get detailed rule information

# False Positive Management
adv_mark_false_positive    # Mark findings as false positives
adv_unmark_false_positive  # Remove false positive marking
adv_list_false_positives   # List all false positives
```

### 2. Scan Engine Layer (`scan_engine.py`)

**Purpose**: Orchestrates multiple security scanners and aggregates results

**Key Components**:

#### ScanEngine
```python
class ScanEngine:
    def __init__(self, threat_engine, credential_manager):
        self.threat_engine = threat_engine           # Rules-based scanning
        self.llm_scanner = LLMScanner()             # AI-powered analysis
        self.semgrep_scanner = OptimizedSemgrepScanner()  # Static analysis
        self.ast_scanner = ASTScanner()             # AST-based analysis
        self.false_positive_manager = FalsePositiveManager()
```

#### EnhancedScanResult
```python
@dataclass
class EnhancedScanResult:
    file_path: str
    language: Language
    rules_threats: list[ThreatMatch]    # Rules scanner results
    llm_threats: list[ThreatMatch]      # LLM scanner results
    semgrep_threats: list[ThreatMatch]  # Semgrep scanner results
    scan_metadata: dict[str, Any]       # Execution metadata

    @property
    def all_threats(self) -> list[ThreatMatch]:
        """Aggregated threats from all scanners"""
```

### 3. Security Scanner Components

#### Rules Scanner (`threat_engine.py`)
- **Technology**: YAML-based rule definitions with regex/AST patterns
- **Strengths**: Fast execution, customizable rules, low false positives
- **Use Cases**: Known vulnerability patterns, policy violations
- **Rule Structure**:
  ```yaml
  id: "sql-injection-basic"
  name: "SQL Injection Vulnerability"
  category: "injection"
  severity: "high"
  languages: ["python", "javascript"]
  conditions:
    - type: "regex"
      value: "execute\\(.*\\+.*\\)"
  ```

#### LLM Scanner (`llm_scanner.py`)
- **Technology**: OpenAI GPT models for semantic analysis
- **Strengths**: Context-aware, business logic understanding, novel vulnerability detection
- **Use Cases**: Complex vulnerabilities, code review, contextual analysis
- **Analysis Flow**:
  ```
  Code Input → Context Building → LLM Analysis → Result Parsing → ThreatMatch Objects
  ```

#### Semgrep Scanner (`semgrep_scanner.py`)
- **Technology**: Semgrep static analysis engine
- **Strengths**: Industry-standard rules, comprehensive coverage, performance
- **Use Cases**: Compliance scanning, comprehensive security assessment
- **Optimization Features**:
  - Async subprocess execution
  - Timeout management
  - Result caching
  - Error recovery

#### AST Scanner (`ast_scanner.py`)
- **Technology**: Tree-sitter for multi-language parsing
- **Strengths**: Precise pattern matching, language-aware analysis
- **Use Cases**: Syntax-specific vulnerabilities, code structure analysis

### 4. Supporting Systems

#### False Positive Manager (`false_positive_manager.py`)
- **Purpose**: Track and suppress known false positives
- **Storage**: `.adversary.json` files with UUID-based tracking
- **Performance**: Intelligent caching system (recently optimized)
- **Features**:
  - Project-specific false positive tracking
  - Cache invalidation on file changes
  - Legacy system migration support

#### Exploit Generator (`exploit_generator.py`)
- **Purpose**: Generate proof-of-concept exploits
- **Technology**: Template-based generation with LLM enhancement
- **Safety**: Designed for testing environments only

#### Credential Manager (`credential_manager.py`)
- **Purpose**: Secure API key and credential management
- **Technology**: OS keyring integration with environment fallback
- **Security**: No plaintext credential storage

## Data Flow Architecture

### 1. Scan Request Flow

```
MCP Client Request
       ▼
Parameter Validation
       ▼
Language Detection
       ▼
┌─────────────────────────────────┐
│     Parallel Scanner Execution │
├─────────────┬─────────────┬─────┴─────────────┐
│Rules Scanner│ LLM Scanner │ Semgrep Scanner   │
├─────────────┼─────────────┼───────────────────┤
│• Rule Match │• AI Analysis│• Static Analysis  │
│• Pattern Det│• Context Aw │• Industry Rules   │
│• Fast Exec  │• Semantic   │• Comprehensive    │
└─────────────┴─────────────┴───────────────────┘
       ▼             ▼              ▼
┌─────────────────────────────────────────────┐
│           Result Aggregation                │
│• Deduplication by similarity              │
│• Severity normalization                   │
│• Metadata enrichment                      │
└─────────────────────────────────────────────┘
       ▼
┌─────────────────────────────────────────────┐
│         False Positive Filtering            │
│• UUID-based lookup with caching           │
│• Project-specific suppression             │
│• Performance-optimized queries            │
└─────────────────────────────────────────────┘
       ▼
┌─────────────────────────────────────────────┐
│          Result Formatting                  │
│• JSON or text output                       │
│• Exploit generation (if requested)        │
│• Metadata inclusion                        │
└─────────────────────────────────────────────┘
       ▼
MCP Client Response
```

### 2. Rule Management Flow

```
Rule Request
       ▼
┌─────────────────────────────────────────────┐
│            Rule Discovery                   │
│• Built-in rules (rules/built-in/)          │
│• Custom rules (rules/custom/)              │
│• Organization rules (rules/organization/)  │
└─────────────────────────────────────────────┘
       ▼
┌─────────────────────────────────────────────┐
│            Rule Validation                  │
│• YAML schema validation                    │
│• Pattern syntax checking                  │
│• Language compatibility                   │
└─────────────────────────────────────────────┘
       ▼
┌─────────────────────────────────────────────┐
│            Rule Loading                     │
│• Memory-based caching                     │
│• Hot-reload support                       │
│• Error handling and logging               │
└─────────────────────────────────────────────┘
```

## Performance Architecture

### 1. Caching Strategy

```
┌─────────────────────────────────────────────┐
│               Cache Layers                  │
├─────────────────────────────────────────────┤
│ L1: False Positive Cache (Memory)          │
│ • UUID → Metadata mapping                  │
│ • File modification time tracking          │
│ • Automatic invalidation                   │
├─────────────────────────────────────────────┤
│ L2: Rule Cache (Memory)                    │
│ • Compiled rule patterns                   │
│ • Hot-reload capability                    │
│ • Language-specific indexing               │
├─────────────────────────────────────────────┤
│ L3: Semgrep Results Cache (File)           │
│ • Temporary result storage                 │
│ • Process-level caching                    │
│ • Timeout-based expiration                 │
└─────────────────────────────────────────────┘
```

### 2. Async Processing

```
┌─────────────────────────────────────────────┐
│            Async Architecture               │
├─────────────────────────────────────────────┤
│ Main Event Loop                            │
│ ├─ Scanner Task Pool                       │
│ ├─ File I/O Operations                     │
│ ├─ Network Requests (LLM API)              │
│ └─ Subprocess Management (Semgrep)         │
├─────────────────────────────────────────────┤
│ Concurrent Execution                       │
│ • Multiple files in parallel              │
│ • Scanner independence                     │
│ • Resource management                      │
└─────────────────────────────────────────────┘
```

## Security Architecture

### 1. Input Validation

```
User Input
    ▼
┌─────────────────────────────────────────────┐
│           Parameter Validation              │
│ • Pydantic schema enforcement              │
│ • Path traversal prevention                │
│ • Size limits and timeouts                 │
│ • Encoding validation                      │
└─────────────────────────────────────────────┘
    ▼
┌─────────────────────────────────────────────┐
│            Content Sanitization             │
│ • Code injection prevention                │
│ • Safe file operations                     │
│ • Resource limitation                      │
└─────────────────────────────────────────────┘
```

### 2. Credential Security

```
┌─────────────────────────────────────────────┐
│          Credential Flow                    │
│                                            │
│ Environment Variables                      │
│        ▼                                   │
│ Credential Manager                         │
│        ▼                                   │
│ OS Keyring (Secure Storage)                │
│        ▼                                   │
│ In-Memory Cache (Temporary)                │
│        ▼                                   │
│ Scanner Usage (OpenAI API)                 │
└─────────────────────────────────────────────┘
```

## Extensibility Points

### 1. Adding New Scanners

```python
class NewScanner:
    async def scan_code(self, code: str, language: Language) -> list[ThreatMatch]:
        """Scanner interface implementation"""
        pass

    async def scan_file(self, file_path: Path) -> list[ThreatMatch]:
        """File scanning implementation"""
        pass
```

### 2. Custom Rule Types

```yaml
# New rule type example
id: "custom-business-logic"
type: "semantic"  # New rule type
engine: "llm"     # Specify execution engine
conditions:
  - type: "business_logic"
    description: "Check for business logic flaws"
    context: "financial_calculations"
```

### 3. Output Formatters

```python
class CustomFormatter:
    def format_results(self, results: EnhancedScanResult) -> str:
        """Custom result formatting"""
        pass
```

## Deployment Architecture

### 1. MCP Integration

```
┌─────────────────────────────────────────────┐
│              Cursor IDE                     │
│ ┌─────────────────────────────────────────┐ │
│ │          MCP Client                     │ │
│ │ • Tool discovery                        │ │
│ │ • Request/response handling             │ │
│ │ • UI integration                        │ │
│ └─────────────────────────────────────────┘ │
└─────────────────┬───────────────────────────┘
                  │ JSON-RPC over stdio
                  ▼
┌─────────────────────────────────────────────┐
│         Adversary MCP Server               │
│ • Installed as Python package              │
│ • Configured in Cursor settings            │
│ • Auto-discovery of tools                  │
└─────────────────────────────────────────────┘
```

### 2. Standalone CLI

```
┌─────────────────────────────────────────────┐
│            CLI Interface                    │
│ • Direct command execution                 │
│ • Batch processing                         │
│ • CI/CD integration                        │
│ • Configuration file support               │
└─────────────────────────────────────────────┘
```

This architecture provides a solid foundation for extensible, performant security analysis while maintaining clean separation of concerns and strong integration capabilities.
