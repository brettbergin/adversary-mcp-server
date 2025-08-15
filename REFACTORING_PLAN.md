# Adversary MCP Server - Complete Architectural Refactoring Plan

Based on comprehensive analysis of this codebase, I've identified critical architectural problems that make it difficult to maintain, test, and extend. Here's a phased refactoring plan to transform this into a production-worthy, well-architected system.

## Current State Assessment

**Critical Issues:**
- **God Classes**: `AdversaryMCPServer` (3,408 lines), `CLI` (3,417 lines)
- **Monolithic Components**: `ScanEngine` orchestrating everything
- **Code Duplication**: 70%+ duplicate patterns across CLI commands
- **Missing Abstractions**: No domain layer, strategy patterns, or proper interfaces
- **Poor Separation of Concerns**: Business logic mixed with infrastructure

## Refactoring Strategy: Clean Architecture + Domain-Driven Design

### Phase 1: Foundation & Domain Layer (4-6 weeks)

**Priority: CRITICAL** - Establish clean foundations

#### 1.1 Create Domain Layer
```
src/adversary_mcp_server/domain/
├── entities/
│   ├── scan_request.py      # Rich domain object with validation
│   ├── scan_context.py      # Value object for scan metadata
│   ├── threat_match.py      # Enhanced threat representation
│   └── scan_result.py       # Domain result object
├── value_objects/
│   ├── file_path.py         # Validated file path operations
│   ├── severity_level.py    # Severity with comparison logic
│   ├── confidence_score.py  # Confidence with threshold logic
│   └── scan_metadata.py     # Structured scan information
├── repositories/
│   ├── scan_repository.py   # Abstract scan persistence
│   └── threat_repository.py # Abstract threat storage
└── services/
    ├── scan_orchestrator.py # Pure business orchestration
    ├── threat_aggregator.py # Domain aggregation logic
    └── validation_service.py # Domain validation rules
```

#### 1.2 Define Core Abstractions
```python
# Domain interfaces
class IScanStrategy(Protocol):
    def execute_scan(self, context: ScanContext) -> ScanResult

class IValidationStrategy(Protocol):
    def validate_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]

class IThreatAggregator(Protocol):
    def aggregate(self, threats: list[ThreatMatch]) -> list[ThreatMatch]
```

#### 1.3 Extract Business Logic
- Move validation rules from infrastructure to domain services
- Extract threat aggregation logic into domain layer
- Create domain events for scan lifecycle

**Deliverables:**
- Complete domain layer with rich objects
- Abstract interfaces for all major operations
- Business logic separated from infrastructure
- 90% test coverage for domain layer

### Phase 2: Application Layer & Use Cases (3-4 weeks)

**Priority: HIGH** - Clean application orchestration

#### 2.1 Create Application Services
```
src/adversary_mcp_server/application/
├── use_cases/
│   ├── execute_scan_use_case.py    # Scan orchestration
│   ├── validate_threats_use_case.py # Threat validation
│   ├── aggregate_results_use_case.py # Result aggregation
│   └── export_results_use_case.py   # Result export
├── commands/
│   ├── scan_command.py             # Scan command objects
│   ├── validate_command.py         # Validation commands
│   └── export_command.py           # Export commands
├── queries/
│   ├── get_scan_results_query.py   # Result retrieval
│   └── get_scan_status_query.py    # Status queries
└── services/
    ├── scan_application_service.py  # Application coordination
    └── validation_application_service.py
```

#### 2.2 Implement Command/Query Separation
```python
# Commands (modify state)
class ExecuteScanCommand:
    def __init__(self, request: ScanRequest): ...

class ExecuteScanUseCase:
    def execute(self, command: ExecuteScanCommand) -> None: ...

# Queries (return data)
class GetScanResultsQuery:
    def __init__(self, scan_id: str): ...

class GetScanResultsHandler:
    def handle(self, query: GetScanResultsQuery) -> ScanResult: ...
```

#### 2.3 Factory Pattern Implementation
```python
class ScanStrategyFactory:
    def create_strategy(self, config: ScanConfiguration) -> IScanStrategy:
        # Create appropriate strategy based on configuration

class ValidatorFactory:
    def create_validator(self, config: ValidationConfig) -> IValidator:
        # Create appropriate validator
```

**Deliverables:**
- Clean application layer with use cases
- Command/Query separation implemented
- Factory patterns for complex object creation
- Dependency injection container

### Phase 3: Infrastructure Refactoring (4-5 weeks)

**Priority: HIGH** - Fix monolithic infrastructure

#### 3.1 Break Up ScanEngine
```
src/adversary_mcp_server/infrastructure/scanning/
├── strategies/
│   ├── hybrid_scan_strategy.py     # Semgrep + LLM
│   ├── static_scan_strategy.py     # Semgrep only
│   └── ai_scan_strategy.py         # LLM only
├── orchestrators/
│   ├── scan_orchestrator.py        # Coordination logic
│   └── result_orchestrator.py      # Result processing
├── scanners/
│   ├── semgrep_engine.py           # Focused Semgrep wrapper
│   ├── llm_engine.py               # Focused LLM wrapper
│   └── hybrid_engine.py            # Strategy coordinator
└── validators/
    ├── confidence_validator.py      # Confidence-based validation
    ├── context_validator.py         # Context-aware validation
    └── composite_validator.py       # Multiple validation strategies
```

#### 3.2 Create Scanner Abstractions
```python
class IScanEngine(Protocol):
    def scan(self, context: ScanContext) -> list[ThreatMatch]

class IValidator(Protocol):
    def validate(self, threats: list[ThreatMatch]) -> ValidationResult

# Strategy implementations
class HybridScanStrategy(IScanEngine):
    def __init__(self, semgrep: SemgrepEngine, llm: LLMEngine): ...

class StaticScanStrategy(IScanEngine):
    def __init__(self, semgrep: SemgrepEngine): ...
```

#### 3.3 Extract Result Processing
```python
class ResultProcessor:
    def process(self, raw_results: RawScanData) -> ScanResult:
        # Pure result processing logic

class ResultFormatter:
    def format_json(self, result: ScanResult) -> dict:
    def format_markdown(self, result: ScanResult) -> str:
```

**Deliverables:**
- Strategy pattern for all scanners
- Separated concerns in infrastructure
- Testable, focused components
- Clear interfaces between layers

### Phase 4: Protocol Layer Refactoring (3-4 weeks)

**Priority: MEDIUM** - Clean external interfaces

#### 4.1 Break Up AdversaryMCPServer
```
src/adversary_mcp_server/interfaces/
├── mcp/
│   ├── protocol_handler.py         # Pure MCP protocol logic
│   ├── tool_registry.py            # Tool registration
│   ├── request_validator.py        # Request validation
│   └── response_formatter.py       # Response formatting
├── cli/
│   ├── command_handler.py          # CLI command coordination
│   ├── argument_parser.py          # Argument parsing logic
│   └── output_formatter.py         # CLI output formatting
└── http/
    ├── rest_api.py                 # Future REST API
    └── health_check.py             # Health endpoints
```

#### 4.2 Implement Request/Response Pattern
```python
class MCPRequest:
    def __init__(self, tool_name: str, parameters: dict): ...

class MCPResponse:
    def __init__(self, result: dict, error: Optional[str] = None): ...

class MCPToolHandler:
    def handle_scan_request(self, request: MCPRequest) -> MCPResponse:
        # Delegate to application layer
```

#### 4.3 CLI Command Refactoring
```python
class CommandExecutor:
    def execute_scan_command(self, args: ScanArgs) -> None:
        # Delegate to application use cases

# Eliminate 49 duplicate command implementations
class BaseCommand:
    def __init__(self, use_case_executor: UseCaseExecutor): ...
    def execute(self, args: CommandArgs) -> None: ...
```

**Deliverables:**
- Separated protocol handling from business logic
- Reusable CLI command infrastructure
- Request/Response pattern implemented
- Eliminated CLI code duplication

### Phase 5: Configuration & Cross-Cutting Concerns (2-3 weeks)

**Priority: MEDIUM** - Clean configuration and shared services

#### 5.1 Configuration Management
```
src/adversary_mcp_server/configuration/
├── config_builder.py              # Configuration construction
├── validation_config.py           # Validation-specific config
├── scanner_config.py              # Scanner-specific config
└── environment_config.py          # Environment variables
```

#### 5.2 Cross-Cutting Services
```
src/adversary_mcp_server/shared/
├── logging/
│   ├── structured_logger.py       # Structured logging
│   └── security_logger.py         # Security event logging
├── monitoring/
│   ├── metrics_collector.py       # Centralized metrics
│   └── performance_monitor.py     # Performance tracking
└── caching/
    ├── cache_strategy.py           # Cache strategies
    └── cache_coordinator.py        # Cache coordination
```

**Deliverables:**
- Centralized configuration management
- Consistent logging and monitoring
- Proper dependency injection
- Clean cross-cutting concerns

### Phase 6: Testing & Documentation (2-3 weeks)

**Priority: HIGH** - Ensure quality and maintainability

#### 6.1 Comprehensive Testing Strategy
```
tests/
├── unit/                          # Domain and application tests
├── integration/                   # Infrastructure integration tests
├── acceptance/                    # End-to-end scenario tests
└── performance/                   # Performance and load tests
```

#### 6.2 Documentation & Examples
- Architecture decision records (ADRs)
- API documentation for all layers
- Integration examples and tutorials
- Performance benchmarking

**Deliverables:**
- 90%+ test coverage across all layers
- Complete architectural documentation
- Performance benchmarks and optimization
- Migration guides for breaking changes

## Implementation Guidelines

### Breaking Change Strategy
1. **Backward Compatibility**: Maintain existing APIs during refactoring
2. **Feature Flags**: Use feature flags to gradually migrate functionality
3. **Deprecation Path**: Clear deprecation timeline for old APIs
4. **Migration Tooling**: Automated migration tools where possible

### Quality Gates
- **Code Coverage**: Minimum 90% for new code, 75% overall
- **Performance**: No performance regression during refactoring
- **API Stability**: No breaking changes without major version bump
- **Documentation**: All new abstractions must be documented

### Risk Mitigation
- **Incremental Delivery**: Each phase delivers working software
- **Rollback Strategy**: Ability to rollback each phase independently
- **Stakeholder Review**: Regular architecture reviews during refactoring
- **Performance Monitoring**: Continuous monitoring during migration

## Expected Outcomes

**Maintainability**:
- 80% reduction in code duplication
- Clear separation of concerns
- Easy to add new features

**Testability**:
- Unit tests for all business logic
- Integration tests for infrastructure
- Mockable dependencies

**Performance**:
- Better resource utilization
- Easier performance optimization
- Cleaner async patterns

**Developer Experience**:
- Clear APIs and abstractions
- Consistent patterns across codebase
- Self-documenting domain model

This refactoring will transform the codebase from a monolithic, hard-to-maintain system into a clean, modular, production-ready architecture that follows industry best practices.

## Detailed Analysis Summary

### Current Architectural Problems

#### Critical Monolithic Classes

1. **AdversaryMCPServer** (`server.py`) - 3,408 lines, 35 methods
   - God class handling MCP protocol, validation, file I/O, result formatting, path resolution, and business logic
   - No separation of concerns between protocol handling and domain logic
   - Directly instantiates and manages all dependencies
   - Hard to test due to monolithic structure

2. **CLI Module** (`cli.py`) - 3,417 lines, 49 Click commands
   - Procedural monolith with no class structure
   - Massive code duplication across commands
   - Global state management anti-pattern
   - Each command mixes argument parsing, business logic, and output formatting

3. **ScanEngine** (`scanner/scan_engine.py`) - 2,599 lines, 24 methods
   - Central orchestrator doing too much
   - Manages multiple scanners, validators, and result aggregation in single class
   - Missing strategy patterns for different scanning approaches
   - Complex state management makes extension difficult

#### Major Code Duplication Patterns

1. **CLI Command Duplication** (70% similarity across 49 commands)
   - Repeated initialization patterns
   - Duplicate validation logic
   - Similar error handling
   - Identical output formatting

2. **Scanner Initialization** (80% similarity across components)
   - Repeated dependency injection patterns
   - Duplicate configuration handling
   - Similar error recovery logic

3. **Result Processing** (75% similarity across formatters)
   - Duplicate JSON formatting
   - Similar aggregation logic
   - Repeated metadata extraction

#### Missing Critical Abstractions

1. **Domain Layer Completely Missing**
   - Business logic scattered across infrastructure
   - No domain objects for core concepts (ScanRequest, ThreatMatch, ScanResult)
   - Primitive obsession throughout codebase

2. **Strategy Patterns Missing**
   - Scanner selection hardcoded with boolean flags
   - No abstraction for different validation approaches
   - Threat aggregation logic hardcoded

3. **Command/Query Separation Missing**
   - Methods that both modify state and return data
   - No clear separation of read vs write operations
   - Missing request/response objects

4. **Factory Patterns Missing**
   - Complex object creation scattered throughout
   - Direct instantiation instead of proper dependency injection
   - Configuration-driven creation missing

This analysis confirms the need for comprehensive architectural refactoring to address these fundamental design problems and transform the codebase into a maintainable, extensible system.
