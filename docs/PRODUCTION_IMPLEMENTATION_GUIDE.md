# 🚀 Adversary MCP Server - Production Implementation Guide

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Critical Issues & Solutions](#critical-issues--solutions)
4. [Implementation Phases](#implementation-phases)
5. [Detailed Implementation Instructions](#detailed-implementation-instructions)
6. [Testing & Validation](#testing--validation)
7. [Migration Strategy](#migration-strategy)
8. [Success Metrics](#success-metrics)
9. [Reference Materials](#reference-materials)

---

## Executive Summary

This document serves as a comprehensive guide for transforming the Adversary MCP Server from a functional prototype into a production-grade security scanning platform. The codebase currently works but exhibits patterns typical of rapid prototyping that will cause significant issues at scale.

### Key Problems We're Solving:
- **Memory leaks** from global state and poor resource management
- **Performance bottlenecks** from blocking operations and inefficient resource usage
- **Maintainability issues** from monolithic classes and tight coupling
- **Security vulnerabilities** from insufficient input validation
- **Testing difficulties** from global state and tight dependencies

### Expected Outcomes:
- 50-80% performance improvement
- Zero memory leaks with proper cleanup
- 90%+ test coverage with simple test setup
- Production-ready security posture
- Clear architectural boundaries enabling team scaling

---

## Current State Analysis

### 🔴 CRITICAL: Monolithic God Classes

**Current Problem:**
```python
# src/adversary_mcp_server/scanner/scan_engine.py - 1200+ lines!
class ScanEngine:
    def __init__(self, credential_manager, cache_manager=None, metrics_collector=None, ...):
        # Constructor does EVERYTHING - initialization, configuration, setup
        self.credential_manager = credential_manager
        self.config = credential_manager.load_config()
        self.semgrep_scanner = SemgrepScanner(...)
        self.llm_scanner = LLMScanner(...)
        self.llm_validator = LLMValidator(...)
        # ... 20+ more initializations

    def scan_file(self, ...):
        # 200+ line method doing orchestration, validation, caching, formatting

    def scan_directory(self, ...):
        # Another 300+ line method
```

**Why This Is Bad:**
1. **Impossible to test in isolation** - Must mock 20+ dependencies
2. **Memory bloat** - Every instance carries all scanners even if unused
3. **Violates Single Responsibility** - Does scanning, validation, caching, formatting
4. **Performance impact** - Initializes everything upfront, even if not needed
5. **Team scaling nightmare** - Multiple developers can't work on different parts

**Impact Measurement:**
- Current memory usage per instance: ~150MB
- Initialization time: 2-3 seconds
- Test setup complexity: 50+ lines of mocking

### 🔴 CRITICAL: Global State Management

**Current Problem:**
```python
# src/adversary_mcp_server/cli.py
_shared_metrics_collector: MetricsCollector | None = None  # GLOBAL!
_shared_cache_manager = None  # GLOBAL!

def _initialize_cache_manager(enable_caching: bool = True):
    global _shared_cache_manager  # Modifying global state
    if _shared_cache_manager is not None:
        return _shared_cache_manager  # Reusing across ALL operations
```

**Why This Is Bad:**
1. **Thread safety issues** - No synchronization on global access
2. **Memory leaks** - Globals never cleaned up, accumulate over time
3. **Test isolation impossible** - Tests affect each other through shared state
4. **Unpredictable behavior** - State carries between unrelated operations
5. **Can't run multiple instances** - Everything shares the same globals

**Real Example of the Problem:**
```python
# Test 1 pollutes cache
def test_scan_file():
    scan_engine.scan_file("malicious.py")  # Adds to global cache

# Test 2 gets polluted results
def test_scan_directory():
    results = scan_engine.scan_directory(".")  # Gets cached results from Test 1!
```

### 🔴 HIGH: Exception Handling Anti-Patterns

**Current Problem:**
```python
# Found throughout codebase
try:
    result = some_operation()
except Exception as e:  # Catches EVERYTHING including KeyboardInterrupt!
    logger.warning(f"Operation failed: {e}")
    return None  # Silent failure, caller has no idea what happened
```

**Why This Is Bad:**
1. **Catches system exits** - Can't Ctrl+C to stop the program
2. **Hides bugs** - Programming errors get swallowed
3. **No error recovery** - Just returns None, no retry or fallback
4. **Debugging nightmare** - No stack traces, just vague log messages
5. **Security risk** - Errors might expose sensitive info in logs

**Real Production Scenario:**
- User scans a file
- Database connection fails
- Returns None
- UI shows "No vulnerabilities found" ← WRONG! Should show error!

### 🔴 HIGH: Async/Sync Confusion

**Current Problem:**
```python
# src/adversary_mcp_server/scanner/scan_engine.py
def scan_file_sync(self, file_path, ...):
    # Creates NEW event loop every time!
    return asyncio.run(self.scan_file(file_path, ...))

# Called in a loop for 100 files = 100 event loops created/destroyed!
for file in files:
    result = scan_engine.scan_file_sync(file)  # Performance disaster
```

**Why This Is Bad:**
1. **Event loop overhead** - Creating/destroying event loops is expensive
2. **Can't parallelize** - Each file scanned sequentially
3. **Blocks the main thread** - UI freezes during scan
4. **Resource thrashing** - Constant setup/teardown of async context

**Performance Impact:**
- Current: 100 files = 45 seconds (sequential)
- Could be: 100 files = 5 seconds (parallel with proper async)

---

## Critical Issues & Solutions

### Issue 1: Dependency Injection & Service Architecture

**Current State:**
```python
class AdversaryMCPServer:
    def __init__(self):
        # Hard-coded dependencies - can't swap implementations
        self.credential_manager = get_credential_manager()  # Global singleton
        self.scan_engine = ScanEngine(self.credential_manager)  # Tight coupling
        self.exploit_generator = ExploitGenerator(self.credential_manager)
```

**Target State:**
```python
# src/adversary_mcp_server/interfaces/scanner.py
from abc import ABC, abstractmethod

class IScanEngine(ABC):
    """Interface for scan operations - enables testing and multiple implementations"""

    @abstractmethod
    async def scan_file(self, file_path: Path, options: ScanOptions) -> ScanResult:
        """Scan a single file for vulnerabilities"""
        pass

    @abstractmethod
    async def scan_directory(self, dir_path: Path, options: ScanOptions) -> List[ScanResult]:
        """Scan a directory recursively"""
        pass

# src/adversary_mcp_server/container.py
class ServiceContainer:
    """Manages dependency injection and service lifetimes"""

    def __init__(self):
        self._services = {}
        self._singletons = {}
        self._factories = {}

    def register_singleton(self, interface: Type, implementation: Type):
        """Register a service that lives for entire application lifetime"""
        self._services[interface] = ('singleton', implementation)

    def register_scoped(self, interface: Type, factory: Callable):
        """Register a service that lives for request/operation duration"""
        self._services[interface] = ('scoped', factory)

    def resolve(self, interface: Type) -> Any:
        """Get an instance of the requested service"""
        service_type, implementation = self._services[interface]

        if service_type == 'singleton':
            if interface not in self._singletons:
                self._singletons[interface] = implementation()
            return self._singletons[interface]
        elif service_type == 'scoped':
            return implementation()

# src/adversary_mcp_server/application/services/scan_service.py
class ScanService:
    """Orchestrates scanning operations - much smaller and focused"""

    def __init__(self,
                 scanner: IScanEngine,
                 validator: IValidator,
                 cache: ICacheManager):
        # Dependencies injected, not created
        self.scanner = scanner
        self.validator = validator
        self.cache = cache

    async def scan_with_validation(self, path: Path) -> ValidatedResult:
        # Focused on orchestration only
        cache_key = self.cache.generate_key(path)

        if cached := await self.cache.get(cache_key):
            return cached

        scan_result = await self.scanner.scan_file(path)
        validated = await self.validator.validate(scan_result)

        await self.cache.set(cache_key, validated)
        return validated
```

**Implementation Steps:**
1. Create `interfaces/` directory with all service contracts
2. Implement `ServiceContainer` with lifetime management
3. Create service implementations that depend on interfaces
4. Update startup to configure container
5. Refactor all classes to use constructor injection

### Issue 2: Breaking Up Monolithic Classes

**Current State:**
```python
# scan_engine.py doing EVERYTHING
class ScanEngine:
    # 1200+ lines doing:
    # - Orchestration
    # - Scanning
    # - Validation
    # - Caching
    # - Result building
    # - Statistics calculation
    # - File filtering
    # - Language detection
```

**Target State:**
```python
# src/adversary_mcp_server/application/orchestrator.py
class ScanOrchestrator:
    """ONLY orchestrates the scanning workflow - 100 lines max"""

    def __init__(self,
                 scanner_factory: ScannerFactory,
                 result_builder: ResultBuilder,
                 cache_coordinator: CacheCoordinator):
        self.scanner_factory = scanner_factory
        self.result_builder = result_builder
        self.cache_coordinator = cache_coordinator

    async def orchestrate_scan(self, request: ScanRequest) -> ScanResult:
        # Clear, simple orchestration
        scanner = self.scanner_factory.create_for(request.file_type)

        async with self.cache_coordinator.transaction() as cache:
            if cached := await cache.get(request):
                return cached

            raw_results = await scanner.scan(request.path)
            result = self.result_builder.build(raw_results)

            await cache.store(request, result)
            return result

# src/adversary_mcp_server/domain/aggregation/threat_aggregator.py
class ThreatAggregator:
    """ONLY handles threat combination and deduplication - 150 lines max"""

    def aggregate(self,
                  semgrep_threats: List[Threat],
                  llm_threats: List[Threat]) -> List[Threat]:
        # Focused on one responsibility
        combined = []
        seen = set()

        # Sophisticated deduplication logic
        for threat in semgrep_threats + llm_threats:
            threat_key = self._generate_key(threat)
            if threat_key not in seen:
                combined.append(threat)
                seen.add(threat_key)

        return self._prioritize(combined)

    def _generate_key(self, threat: Threat) -> str:
        # Smart key generation considering line proximity
        return f"{threat.file}:{threat.line_range}:{threat.category}"

# src/adversary_mcp_server/infrastructure/cache/cache_coordinator.py
class CacheCoordinator:
    """ONLY manages caching operations - 100 lines max"""

    def __init__(self, cache_manager: ICacheManager):
        self.cache = cache_manager

    @contextmanager
    async def transaction(self):
        """Provides transactional cache operations"""
        transaction = CacheTransaction(self.cache)
        try:
            yield transaction
            await transaction.commit()
        except Exception:
            await transaction.rollback()
            raise
```

**Decomposition Strategy:**
1. **Identify responsibilities** in current monolithic class
2. **Create focused classes** for each responsibility (max 200 lines)
3. **Define clear interfaces** between components
4. **Use composition** to combine functionality
5. **Add integration tests** to ensure components work together

### Issue 3: Resource Management

**Current State:**
```python
# No cleanup, resources leak
class LLMScanner:
    def __init__(self):
        self.http_client = httpx.Client()  # Never closed!
        self.thread_pool = ThreadPoolExecutor()  # Never shutdown!
```

**Target State:**
```python
# src/adversary_mcp_server/infrastructure/pools/connection_pool.py
class HTTPConnectionPool:
    """Manages a pool of reusable HTTP connections"""

    def __init__(self,
                 max_connections: int = 10,
                 max_keepalive: int = 5,
                 timeout: float = 30.0):
        self._pool = []
        self._in_use = set()
        self._lock = asyncio.Lock()
        self._max_connections = max_connections

    async def acquire(self) -> httpx.AsyncClient:
        """Get a connection from the pool"""
        async with self._lock:
            # Reuse existing connection if available
            for conn in self._pool:
                if conn not in self._in_use and not conn.is_closed:
                    self._in_use.add(conn)
                    return conn

            # Create new if under limit
            if len(self._pool) < self._max_connections:
                conn = httpx.AsyncClient(timeout=self.timeout)
                self._pool.append(conn)
                self._in_use.add(conn)
                return conn

            # Wait for available connection
            await self._wait_for_available()

    async def release(self, conn: httpx.AsyncClient):
        """Return connection to pool"""
        async with self._lock:
            self._in_use.discard(conn)

    async def close_all(self):
        """Cleanup all connections"""
        async with self._lock:
            for conn in self._pool:
                await conn.aclose()
            self._pool.clear()
            self._in_use.clear()

# src/adversary_mcp_server/infrastructure/lifecycle/resource_manager.py
class ResourceManager:
    """Manages lifecycle of all resources"""

    def __init__(self):
        self._resources: List[AsyncContextManager] = []
        self._cleanup_stack: List[Callable] = []

    def register(self, resource: AsyncContextManager):
        """Register a resource for management"""
        self._resources.append(resource)

    async def __aenter__(self):
        """Initialize all resources"""
        for resource in self._resources:
            await resource.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up all resources in reverse order"""
        for resource in reversed(self._resources):
            try:
                await resource.__aexit__(exc_type, exc_val, exc_tb)
            except Exception as e:
                logger.error(f"Failed to cleanup resource: {e}")

# Usage example showing proper resource management
async def main():
    resource_manager = ResourceManager()

    # Register all resources
    http_pool = HTTPConnectionPool()
    cache_manager = CacheManager()
    llm_client_pool = LLMClientPool()

    resource_manager.register(http_pool)
    resource_manager.register(cache_manager)
    resource_manager.register(llm_client_pool)

    async with resource_manager:
        # All resources initialized and will be cleaned up
        server = AdversaryMCPServer(
            http_pool=http_pool,
            cache=cache_manager,
            llm_pool=llm_client_pool
        )
        await server.run()
```

---

## Implementation Phases

### PHASE 1: Foundation (Week 1, Days 1-5)

#### Day 1-2: Dependency Injection Framework

**Files to Create:**
```
src/adversary_mcp_server/
├── interfaces/
│   ├── __init__.py
│   ├── scanner.py          # IScanEngine, ISemgrepScanner, ILLMScanner
│   ├── validator.py        # IValidator, ILLMValidator
│   ├── cache.py           # ICacheManager, ICacheKey
│   ├── credentials.py      # ICredentialManager
│   └── metrics.py         # IMetricsCollector
├── container.py           # ServiceContainer implementation
└── application/
    └── bootstrap.py       # Application initialization with DI
```

**Implementation Order:**
1. Create all interface definitions
2. Implement ServiceContainer with lifetime management
3. Create factory classes for complex objects
4. Update existing classes to implement interfaces
5. Wire up dependency injection in bootstrap

**Testing Strategy:**
```python
# tests/test_container.py
def test_singleton_returns_same_instance():
    container = ServiceContainer()
    container.register_singleton(IScanEngine, MockScanEngine)

    instance1 = container.resolve(IScanEngine)
    instance2 = container.resolve(IScanEngine)

    assert instance1 is instance2  # Same object

def test_scoped_returns_new_instance():
    container = ServiceContainer()
    container.register_scoped(IValidator, lambda: MockValidator())

    instance1 = container.resolve(IValidator)
    instance2 = container.resolve(IValidator)

    assert instance1 is not instance2  # Different objects
```

#### Day 3-4: Decompose Monolithic Classes

**Refactoring Plan for ScanEngine:**

1. **Extract ScanOrchestrator** (coordinates workflow)
   - Move orchestration logic from scan_file, scan_directory
   - Depends on interfaces only
   - Max 200 lines

2. **Extract ThreatAggregator** (combines threats)
   - Move _combine_threats logic
   - Smart deduplication
   - Max 150 lines

3. **Extract ResultBuilder** (builds results)
   - Move result construction logic
   - Statistics calculation
   - Max 150 lines

4. **Extract ValidationCoordinator** (manages validation)
   - Move validation workflow
   - Fallback handling
   - Max 200 lines

5. **Extract CacheCoordinator** (handles caching)
   - Move cache key generation
   - Cache transaction management
   - Max 150 lines

**Migration Steps:**
```python
# Step 1: Create new classes with single responsibilities
class ScanOrchestrator:
    def __init__(self, scanner: IScanEngine, aggregator: IThreatAggregator):
        self.scanner = scanner
        self.aggregator = aggregator

# Step 2: Add adapter in existing ScanEngine for backward compatibility
class ScanEngine:
    def __init__(self, ...):
        # Keep existing interface but delegate to new components
        self._orchestrator = ScanOrchestrator(...)

    def scan_file(self, ...):
        # Delegate to orchestrator
        return self._orchestrator.scan_file(...)

# Step 3: Update callers gradually to use new components directly
# Step 4: Remove old ScanEngine once all callers migrated
```

#### Day 5: Error Handling Framework

**Error Hierarchy to Implement:**
```python
# src/adversary_mcp_server/exceptions/__init__.py
class AdversaryError(Exception):
    """Base exception for all custom errors"""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.details = details or {}

class ScanError(AdversaryError):
    """Errors during scanning operations"""
    pass

class ValidationError(AdversaryError):
    """Errors during validation"""
    pass

class ConfigurationError(AdversaryError):
    """Configuration-related errors"""
    pass

class SecurityError(AdversaryError):
    """Security-related errors (don't expose details)"""
    def __init__(self, message: str = "Security error occurred"):
        # Never expose details in security errors
        super().__init__(message, {})

# src/adversary_mcp_server/infrastructure/error_handling/handler.py
class ErrorHandler:
    """Centralized error handling with recovery strategies"""

    def __init__(self):
        self._handlers = {}
        self._fallbacks = {}

    def register_handler(self,
                         error_type: Type[Exception],
                         handler: Callable):
        """Register specific handler for error type"""
        self._handlers[error_type] = handler

    async def handle(self, error: Exception) -> Any:
        """Handle error with appropriate strategy"""
        error_type = type(error)

        # Find most specific handler
        for cls in error_type.__mro__:
            if cls in self._handlers:
                return await self._handlers[cls](error)

        # Default handling
        logger.error(f"Unhandled error: {error}", exc_info=True)
        raise

# Usage example
error_handler = ErrorHandler()

# Register specific handlers
error_handler.register_handler(
    ValidationError,
    lambda e: {"status": "validation_failed", "errors": e.details}
)

error_handler.register_handler(
    SecurityError,
    lambda e: {"status": "error", "message": "Request failed"}  # Generic message
)
```

### PHASE 2: Unified HTML Dashboard with SQLAlchemy ORM (Week 2, Days 6-10)

#### Day 6-7: Consolidated SQLAlchemy Database & Telemetry Models

**Problem to Solve:**
```python
# Current: Multiple problematic data stores
# - JSON metrics files that corrupt and provide poor UX
# - CLI dashboard that doesn't work and has no value
# - Multiple SQLite files scattered across cache system
# - No comprehensive telemetry for MCP tools, CLI tools, cache, or scan findings
# - Raw SQL usage instead of proper ORM patterns
```

**Solution: Unified SQLAlchemy Database with Rich HTML Dashboard**

Replace the failing JSON metrics system and CLI dashboard with a single, comprehensive HTML dashboard backed by a consolidated SQLAlchemy database.

```python
# src/adversary_mcp_server/database/models.py
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import json
import time
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, Text, Index, func, and_, ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.types import TypeDecorator, VARCHAR
from pydantic import BaseModel, Field, validator
import uuid

Base = declarative_base()

class JSONType(TypeDecorator):
    """SQLAlchemy type for storing JSON data"""
    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value

# === COMPREHENSIVE TELEMETRY MODELS ===

class MCPToolExecution(Base):
    """Track all MCP tool executions and performance"""
    __tablename__ = 'mcp_tool_executions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_name = Column(String(100), nullable=False, index=True)  # 'adv_scan_file', 'adv_scan_folder', etc.
    session_id = Column(String(36), nullable=False, index=True)  # Track user sessions
    request_params = Column(JSONType, nullable=False)  # Tool parameters
    execution_start = Column(Float, nullable=False, index=True)
    execution_end = Column(Float, nullable=True)
    success = Column(Boolean, nullable=False, default=True, index=True)
    error_message = Column(Text, nullable=True)
    findings_count = Column(Integer, nullable=False, default=0)
    validation_enabled = Column(Boolean, nullable=False, default=False)
    llm_enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_tool_session_time', 'tool_name', 'session_id', 'execution_start'),
        Index('idx_success_time', 'success', 'execution_start'),
    )

    def __repr__(self):
        return f"<MCPToolExecution(tool={self.tool_name}, success={self.success})>"

class CLICommandExecution(Base):
    """Track all CLI command executions and performance"""
    __tablename__ = 'cli_command_executions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    command_name = Column(String(100), nullable=False, index=True)  # 'scan', 'configure', 'status'
    subcommand = Column(String(100), nullable=True, index=True)  # file path or directory
    args = Column(JSONType, nullable=False)  # Command line arguments
    execution_start = Column(Float, nullable=False, index=True)
    execution_end = Column(Float, nullable=True)
    exit_code = Column(Integer, nullable=False, default=0, index=True)
    stdout_lines = Column(Integer, nullable=False, default=0)
    stderr_lines = Column(Integer, nullable=False, default=0)
    findings_count = Column(Integer, nullable=False, default=0)
    validation_enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_command_exit_time', 'command_name', 'exit_code', 'execution_start'),
        Index('idx_subcommand_time', 'subcommand', 'execution_start'),
    )

    def __repr__(self):
        return f"<CLICommandExecution(command={self.command_name}, exit_code={self.exit_code})>"

class CacheOperationMetric(Base):
    """Comprehensive cache operation tracking"""
    __tablename__ = 'cache_operations'

    id = Column(Integer, primary_key=True, autoincrement=True)
    operation_type = Column(String(20), nullable=False, index=True)  # 'hit', 'miss', 'set', 'evict', 'cleanup'
    cache_name = Column(String(50), nullable=False, index=True)  # 'scan_results', 'semgrep_cache', 'llm_analysis'
    key_hash = Column(String(64), nullable=False, index=True)
    key_metadata = Column(JSONType, nullable=True)  # File path, language, etc.
    size_bytes = Column(Integer, nullable=True)
    ttl_seconds = Column(Integer, nullable=True)
    access_time_ms = Column(Float, nullable=True)  # Time to retrieve/store
    eviction_reason = Column(String(50), nullable=True)  # 'ttl_expired', 'lru', 'manual'
    timestamp = Column(Float, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_cache_operation_type', 'cache_name', 'operation_type'),
        Index('idx_cache_timestamp', 'cache_name', 'timestamp'),
    )

    def __repr__(self):
        return f"<CacheOperationMetric(cache={self.cache_name}, op={self.operation_type})>"

class ScanEngineExecution(Base):
    """Detailed scan engine execution tracking"""
    __tablename__ = 'scan_executions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    trigger_source = Column(String(20), nullable=False, index=True)  # 'mcp_tool', 'cli', 'api'
    scan_type = Column(String(20), nullable=False, index=True)  # 'file', 'directory', 'code', 'diff'
    target_path = Column(Text, nullable=False)
    file_count = Column(Integer, nullable=False, default=1)
    language_detected = Column(String(50), nullable=True, index=True)
    file_size_bytes = Column(Integer, nullable=True)

    # Timing breakdown
    total_duration_ms = Column(Float, nullable=True)
    semgrep_duration_ms = Column(Float, nullable=True)
    llm_duration_ms = Column(Float, nullable=True)
    validation_duration_ms = Column(Float, nullable=True)
    cache_lookup_ms = Column(Float, nullable=True)

    # Results
    threats_found = Column(Integer, nullable=False, default=0)
    threats_validated = Column(Integer, nullable=False, default=0)
    false_positives_filtered = Column(Integer, nullable=False, default=0)
    cache_hit = Column(Boolean, nullable=False, default=False, index=True)

    # Configuration
    semgrep_enabled = Column(Boolean, nullable=False, default=True)
    llm_enabled = Column(Boolean, nullable=False, default=False)
    validation_enabled = Column(Boolean, nullable=False, default=False)

    execution_start = Column(Float, nullable=False, index=True)
    execution_end = Column(Float, nullable=True)
    success = Column(Boolean, nullable=False, default=True, index=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_scan_source_type', 'trigger_source', 'scan_type'),
        Index('idx_scan_language_time', 'language_detected', 'execution_start'),
        Index('idx_scan_success_time', 'success', 'execution_start'),
    )

    def __repr__(self):
        return f"<ScanEngineExecution(scan_id={self.scan_id}, type={self.scan_type})>"

class ThreatFinding(Base):
    """Individual threat findings with full context"""
    __tablename__ = 'threat_findings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey('scan_executions.scan_id'), nullable=False, index=True)
    finding_uuid = Column(String(36), unique=True, nullable=False, index=True)

    # Detection details
    scanner_source = Column(String(20), nullable=False, index=True)  # 'semgrep', 'llm'
    rule_id = Column(String(100), nullable=True, index=True)
    category = Column(String(50), nullable=False, index=True)  # 'injection', 'xss', 'crypto', etc.
    severity = Column(String(20), nullable=False, index=True)  # 'low', 'medium', 'high', 'critical'
    confidence = Column(Float, nullable=True)  # 0.0-1.0 for validation confidence

    # Location details
    file_path = Column(Text, nullable=False)
    line_start = Column(Integer, nullable=False)
    line_end = Column(Integer, nullable=False)
    column_start = Column(Integer, nullable=True)
    column_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)

    # Finding details
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSONType, nullable=True)  # CWE, OWASP references

    # Validation and false positive tracking
    is_validated = Column(Boolean, nullable=False, default=False, index=True)
    is_false_positive = Column(Boolean, nullable=False, default=False, index=True)
    validation_reason = Column(Text, nullable=True)
    marked_by = Column(String(100), nullable=True)

    timestamp = Column(Float, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationship
    scan_execution = relationship("ScanEngineExecution", backref="findings")

    __table_args__ = (
        Index('idx_finding_category_severity', 'category', 'severity'),
        Index('idx_finding_scanner_validation', 'scanner_source', 'is_validated'),
        Index('idx_finding_file_line', 'file_path', 'line_start'),
    )

    def __repr__(self):
        return f"<ThreatFinding(uuid={self.finding_uuid}, category={self.category})>"

class SystemHealth(Base):
    """System health and performance snapshots"""
    __tablename__ = 'system_health'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)

    # System metrics
    cpu_percent = Column(Float, nullable=True)
    memory_percent = Column(Float, nullable=True)
    memory_used_mb = Column(Float, nullable=True)
    disk_usage_percent = Column(Float, nullable=True)

    # Database metrics
    db_size_mb = Column(Float, nullable=True)
    db_connections = Column(Integer, nullable=True)

    # Cache metrics
    cache_size_mb = Column(Float, nullable=True)
    cache_hit_rate_1h = Column(Float, nullable=True)
    cache_entries_count = Column(Integer, nullable=True)

    # Performance metrics
    avg_scan_duration_1h = Column(Float, nullable=True)
    scans_per_hour = Column(Float, nullable=True)
    error_rate_1h = Column(Float, nullable=True)

    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_health_timestamp', 'timestamp'),
    )

    def __repr__(self):
        return f"<SystemHealth(timestamp={self.timestamp})>"

# === UNIFIED DATABASE & REPOSITORY ===

class AdversaryDatabase:
    """Consolidated SQLAlchemy database for all telemetry and metrics"""

    def __init__(self, db_path: Path = Path("~/.local/share/adversary-mcp-server/cache/adversary.db")):
        self.db_path = db_path.expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create SQLAlchemy engine with optimizations
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,  # Set to True for SQL debugging
            pool_pre_ping=True,
            connect_args={
                "check_same_thread": False,
                "timeout": 30,
                "isolation_level": None,
            }
        )

        # Create session factory
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=True, bind=self.engine)

        # Create all tables
        Base.metadata.create_all(bind=self.engine)

    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()

    def close(self):
        """Close database connections"""
        self.engine.dispose()

class ComprehensiveTelemetryRepository:
    """Comprehensive repository for all telemetry data with rich query methods"""

    def __init__(self, session: Session):
        self.session = session

    # === MCP TOOL TRACKING ===

    def track_mcp_tool_execution(self, tool_name: str, session_id: str,
                                request_params: dict, **kwargs) -> MCPToolExecution:
        """Track MCP tool execution start"""
        execution = MCPToolExecution(
            tool_name=tool_name,
            session_id=session_id,
            request_params=request_params,
            execution_start=time.time(),
            validation_enabled=kwargs.get('validation_enabled', False),
            llm_enabled=kwargs.get('llm_enabled', False)
        )
        self.session.add(execution)
        self.session.commit()
        self.session.refresh(execution)
        return execution

    def complete_mcp_tool_execution(self, execution_id: int, success: bool = True,
                                  findings_count: int = 0, error_message: str = None):
        """Complete MCP tool execution tracking"""
        execution = self.session.query(MCPToolExecution).filter_by(id=execution_id).first()
        if execution:
            execution.execution_end = time.time()
            execution.success = success
            execution.findings_count = findings_count
            execution.error_message = error_message
            self.session.commit()

    # === CLI COMMAND TRACKING ===

    def track_cli_command_execution(self, command_name: str, args: dict,
                                   subcommand: str = None, **kwargs) -> CLICommandExecution:
        """Track CLI command execution"""
        execution = CLICommandExecution(
            command_name=command_name,
            subcommand=subcommand,
            args=args,
            execution_start=time.time(),
            validation_enabled=kwargs.get('validation_enabled', False)
        )
        self.session.add(execution)
        self.session.commit()
        self.session.refresh(execution)
        return execution

    def complete_cli_command_execution(self, execution_id: int, exit_code: int = 0,
                                     stdout_lines: int = 0, stderr_lines: int = 0,
                                     findings_count: int = 0):
        """Complete CLI command execution tracking"""
        execution = self.session.query(CLICommandExecution).filter_by(id=execution_id).first()
        if execution:
            execution.execution_end = time.time()
            execution.exit_code = exit_code
            execution.stdout_lines = stdout_lines
            execution.stderr_lines = stderr_lines
            execution.findings_count = findings_count
            self.session.commit()

    # === CACHE OPERATIONS ===

    def track_cache_operation(self, operation_type: str, cache_name: str, key_hash: str,
                            key_metadata: dict = None, size_bytes: int = None,
                            access_time_ms: float = None, **kwargs) -> CacheOperationMetric:
        """Track cache operation"""
        metric = CacheOperationMetric(
            operation_type=operation_type,
            cache_name=cache_name,
            key_hash=key_hash,
            key_metadata=key_metadata,
            size_bytes=size_bytes,
            access_time_ms=access_time_ms,
            ttl_seconds=kwargs.get('ttl_seconds'),
            eviction_reason=kwargs.get('eviction_reason'),
            timestamp=time.time()
        )
        self.session.add(metric)
        self.session.commit()
        self.session.refresh(metric)
        return metric

    # === SCAN ENGINE TRACKING ===

    def track_scan_execution(self, scan_id: str, trigger_source: str, scan_type: str,
                           target_path: str, **kwargs) -> ScanEngineExecution:
        """Track scan engine execution start"""
        execution = ScanEngineExecution(
            scan_id=scan_id,
            trigger_source=trigger_source,
            scan_type=scan_type,
            target_path=target_path,
            file_count=kwargs.get('file_count', 1),
            language_detected=kwargs.get('language_detected'),
            file_size_bytes=kwargs.get('file_size_bytes'),
            semgrep_enabled=kwargs.get('semgrep_enabled', True),
            llm_enabled=kwargs.get('llm_enabled', False),
            validation_enabled=kwargs.get('validation_enabled', False),
            execution_start=time.time()
        )
        self.session.add(execution)
        self.session.commit()
        self.session.refresh(execution)
        return execution

    def complete_scan_execution(self, scan_id: str, success: bool = True, **kwargs):
        """Complete scan execution with results"""
        execution = self.session.query(ScanEngineExecution).filter_by(scan_id=scan_id).first()
        if execution:
            execution.execution_end = time.time()
            execution.total_duration_ms = kwargs.get('total_duration_ms')
            execution.semgrep_duration_ms = kwargs.get('semgrep_duration_ms')
            execution.llm_duration_ms = kwargs.get('llm_duration_ms')
            execution.validation_duration_ms = kwargs.get('validation_duration_ms')
            execution.cache_lookup_ms = kwargs.get('cache_lookup_ms')
            execution.threats_found = kwargs.get('threats_found', 0)
            execution.threats_validated = kwargs.get('threats_validated', 0)
            execution.false_positives_filtered = kwargs.get('false_positives_filtered', 0)
            execution.cache_hit = kwargs.get('cache_hit', False)
            execution.success = success
            execution.error_message = kwargs.get('error_message')
            self.session.commit()

    # === THREAT FINDINGS ===

    def record_threat_finding(self, scan_id: str, finding_uuid: str, scanner_source: str,
                            category: str, severity: str, file_path: str,
                            line_start: int, line_end: int, title: str, **kwargs) -> ThreatFinding:
        """Record a threat finding"""
        finding = ThreatFinding(
            scan_id=scan_id,
            finding_uuid=finding_uuid,
            scanner_source=scanner_source,
            rule_id=kwargs.get('rule_id'),
            category=category,
            severity=severity,
            confidence=kwargs.get('confidence'),
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            column_start=kwargs.get('column_start'),
            column_end=kwargs.get('column_end'),
            code_snippet=kwargs.get('code_snippet'),
            title=title,
            description=kwargs.get('description'),
            remediation=kwargs.get('remediation'),
            references=kwargs.get('references'),
            is_validated=kwargs.get('is_validated', False),
            is_false_positive=kwargs.get('is_false_positive', False),
            validation_reason=kwargs.get('validation_reason'),
            marked_by=kwargs.get('marked_by'),
            timestamp=time.time()
        )
        self.session.add(finding)
        self.session.commit()
        self.session.refresh(finding)
        return finding

    # === SYSTEM HEALTH ===

    def record_system_health_snapshot(self, **metrics) -> SystemHealth:
        """Record system health metrics snapshot"""
        health = SystemHealth(
            timestamp=time.time(),
            cpu_percent=metrics.get('cpu_percent'),
            memory_percent=metrics.get('memory_percent'),
            memory_used_mb=metrics.get('memory_used_mb'),
            disk_usage_percent=metrics.get('disk_usage_percent'),
            db_size_mb=metrics.get('db_size_mb'),
            db_connections=metrics.get('db_connections'),
            cache_size_mb=metrics.get('cache_size_mb'),
            cache_hit_rate_1h=metrics.get('cache_hit_rate_1h'),
            cache_entries_count=metrics.get('cache_entries_count'),
            avg_scan_duration_1h=metrics.get('avg_scan_duration_1h'),
            scans_per_hour=metrics.get('scans_per_hour'),
            error_rate_1h=metrics.get('error_rate_1h')
        )
        self.session.add(health)
        self.session.commit()
        self.session.refresh(health)
        return health

    # === COMPREHENSIVE ANALYTICS QUERIES ===

    def get_dashboard_data(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        since = time.time() - (hours * 3600)

        # MCP Tool Statistics
        mcp_stats = (
            self.session.query(
                MCPToolExecution.tool_name,
                func.count(MCPToolExecution.id).label('executions'),
                func.avg(func.case([(MCPToolExecution.execution_end.isnot(None),
                                   (MCPToolExecution.execution_end - MCPToolExecution.execution_start) * 1000)],
                                 else_=None)).label('avg_duration_ms'),
                func.sum(MCPToolExecution.findings_count).label('total_findings'),
                func.sum(func.case([(MCPToolExecution.success == True, 1)], else_=0)).label('successes')
            )
            .filter(MCPToolExecution.execution_start > since)
            .group_by(MCPToolExecution.tool_name)
            .all()
        )

        # CLI Command Statistics
        cli_stats = (
            self.session.query(
                CLICommandExecution.command_name,
                func.count(CLICommandExecution.id).label('executions'),
                func.avg(func.case([(CLICommandExecution.execution_end.isnot(None),
                                   (CLICommandExecution.execution_end - CLICommandExecution.execution_start) * 1000)],
                                 else_=None)).label('avg_duration_ms'),
                func.sum(CLICommandExecution.findings_count).label('total_findings'),
                func.sum(func.case([(CLICommandExecution.exit_code == 0, 1)], else_=0)).label('successes')
            )
            .filter(CLICommandExecution.execution_start > since)
            .group_by(CLICommandExecution.command_name)
            .all()
        )

        # Cache Performance
        cache_stats = (
            self.session.query(
                CacheOperationMetric.cache_name,
                func.sum(func.case([(CacheOperationMetric.operation_type == 'hit', 1)], else_=0)).label('hits'),
                func.sum(func.case([(CacheOperationMetric.operation_type == 'miss', 1)], else_=0)).label('misses'),
                func.avg(CacheOperationMetric.access_time_ms).label('avg_access_time_ms'),
                func.sum(CacheOperationMetric.size_bytes).label('total_size_bytes')
            )
            .filter(CacheOperationMetric.timestamp > since)
            .group_by(CacheOperationMetric.cache_name)
            .all()
        )

        # Scan Engine Performance
        scan_stats = (
            self.session.query(
                func.count(ScanEngineExecution.id).label('total_scans'),
                func.avg(ScanEngineExecution.total_duration_ms).label('avg_total_duration'),
                func.avg(ScanEngineExecution.semgrep_duration_ms).label('avg_semgrep_duration'),
                func.avg(ScanEngineExecution.llm_duration_ms).label('avg_llm_duration'),
                func.avg(ScanEngineExecution.validation_duration_ms).label('avg_validation_duration'),
                func.sum(ScanEngineExecution.threats_found).label('total_threats'),
                func.sum(ScanEngineExecution.threats_validated).label('total_validated'),
                func.sum(ScanEngineExecution.false_positives_filtered).label('total_false_positives'),
                func.sum(func.case([(ScanEngineExecution.cache_hit == True, 1)], else_=0)).label('cache_hits')
            )
            .filter(ScanEngineExecution.execution_start > since)
            .first()
        )

        # Threat Findings by Category
        threat_categories = (
            self.session.query(
                ThreatFinding.category,
                ThreatFinding.severity,
                func.count(ThreatFinding.id).label('count'),
                func.avg(ThreatFinding.confidence).label('avg_confidence')
            )
            .filter(ThreatFinding.timestamp > since)
            .group_by(ThreatFinding.category, ThreatFinding.severity)
            .order_by(func.count(ThreatFinding.id).desc())
            .all()
        )

        # Language Performance
        language_performance = (
            self.session.query(
                ScanEngineExecution.language_detected,
                func.count(ScanEngineExecution.id).label('scans'),
                func.avg(ScanEngineExecution.total_duration_ms).label('avg_duration'),
                func.sum(ScanEngineExecution.threats_found).label('threats_found')
            )
            .filter(and_(ScanEngineExecution.execution_start > since,
                        ScanEngineExecution.language_detected.isnot(None)))
            .group_by(ScanEngineExecution.language_detected)
            .order_by(func.count(ScanEngineExecution.id).desc())
            .all()
        )

        return {
            'mcp_tools': [
                {
                    'tool_name': stat.tool_name,
                    'executions': stat.executions,
                    'avg_duration_ms': float(stat.avg_duration_ms or 0),
                    'total_findings': stat.total_findings or 0,
                    'success_rate': (stat.successes or 0) / max(stat.executions, 1)
                } for stat in mcp_stats
            ],
            'cli_commands': [
                {
                    'command_name': stat.command_name,
                    'executions': stat.executions,
                    'avg_duration_ms': float(stat.avg_duration_ms or 0),
                    'total_findings': stat.total_findings or 0,
                    'success_rate': (stat.successes or 0) / max(stat.executions, 1)
                } for stat in cli_stats
            ],
            'cache_performance': [
                {
                    'cache_name': stat.cache_name,
                    'hits': stat.hits or 0,
                    'misses': stat.misses or 0,
                    'hit_rate': (stat.hits or 0) / max((stat.hits or 0) + (stat.misses or 0), 1),
                    'avg_access_time_ms': float(stat.avg_access_time_ms or 0),
                    'total_size_mb': (stat.total_size_bytes or 0) / 1024 / 1024
                } for stat in cache_stats
            ],
            'scan_engine': {
                'total_scans': scan_stats.total_scans or 0,
                'avg_total_duration_ms': float(scan_stats.avg_total_duration or 0),
                'avg_semgrep_duration_ms': float(scan_stats.avg_semgrep_duration or 0),
                'avg_llm_duration_ms': float(scan_stats.avg_llm_duration or 0),
                'avg_validation_duration_ms': float(scan_stats.avg_validation_duration or 0),
                'total_threats_found': scan_stats.total_threats or 0,
                'total_threats_validated': scan_stats.total_validated or 0,
                'false_positives_filtered': scan_stats.total_false_positives or 0,
                'cache_hit_rate': (scan_stats.cache_hits or 0) / max(scan_stats.total_scans or 1, 1)
            },
            'threat_categories': [
                {
                    'category': stat.category,
                    'severity': stat.severity,
                    'count': stat.count,
                    'avg_confidence': float(stat.avg_confidence or 0)
                } for stat in threat_categories
            ],
            'language_performance': [
                {
                    'language': stat.language_detected,
                    'scans': stat.scans,
                    'avg_duration_ms': float(stat.avg_duration or 0),
                    'threats_found': stat.threats_found or 0
                } for stat in language_performance
            ]
        }

# === TELEMETRY COLLECTOR & SERVICE ===

class TelemetryService:
    """Main telemetry service that replaces JSON metrics system"""

    def __init__(self, db: AdversaryDatabase):
        self.db = db

    @contextmanager
    def get_repository(self):
        """Get repository with session management"""
        with self.db.get_session() as session:
            yield ComprehensiveTelemetryRepository(session)

    # === MCP Tool Telemetry ===

    def start_mcp_tool_tracking(self, tool_name: str, session_id: str, request_params: dict, **kwargs):
        """Start tracking MCP tool execution"""
        with self.get_repository() as repo:
            return repo.track_mcp_tool_execution(tool_name, session_id, request_params, **kwargs)

    def complete_mcp_tool_tracking(self, execution_id: int, success: bool = True,
                                 findings_count: int = 0, error_message: str = None):
        """Complete MCP tool execution tracking"""
        with self.get_repository() as repo:
            repo.complete_mcp_tool_execution(execution_id, success, findings_count, error_message)

    # === CLI Command Telemetry ===

    def start_cli_command_tracking(self, command_name: str, args: dict, **kwargs):
        """Start tracking CLI command execution"""
        with self.get_repository() as repo:
            return repo.track_cli_command_execution(command_name, args, **kwargs)

    def complete_cli_command_tracking(self, execution_id: int, exit_code: int = 0, **kwargs):
        """Complete CLI command execution tracking"""
        with self.get_repository() as repo:
            repo.complete_cli_command_execution(execution_id, exit_code, **kwargs)

    # === Cache Telemetry ===

    def track_cache_operation(self, operation_type: str, cache_name: str, key_hash: str, **kwargs):
        """Track cache operation"""
        with self.get_repository() as repo:
            return repo.track_cache_operation(operation_type, cache_name, key_hash, **kwargs)

    # === Scan Engine Telemetry ===

    def start_scan_tracking(self, scan_id: str, trigger_source: str, scan_type: str, target_path: str, **kwargs):
        """Start tracking scan execution"""
        with self.get_repository() as repo:
            return repo.track_scan_execution(scan_id, trigger_source, scan_type, target_path, **kwargs)

    def complete_scan_tracking(self, scan_id: str, success: bool = True, **kwargs):
        """Complete scan execution tracking"""
        with self.get_repository() as repo:
            repo.complete_scan_execution(scan_id, success, **kwargs)

    def record_threat_finding(self, scan_id: str, finding_uuid: str, scanner_source: str,
                            category: str, severity: str, file_path: str,
                            line_start: int, line_end: int, title: str, **kwargs):
        """Record threat finding"""
        with self.get_repository() as repo:
            return repo.record_threat_finding(scan_id, finding_uuid, scanner_source,
                                            category, severity, file_path,
                                            line_start, line_end, title, **kwargs)

    # === System Health ===

    def record_system_health_snapshot(self, **metrics):
        """Record system health snapshot"""
        with self.get_repository() as repo:
            return repo.record_system_health_snapshot(**metrics)

    # === Dashboard Data ===

    def get_dashboard_data(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        with self.get_repository() as repo:
            return repo.get_dashboard_data(hours)
```

#### Day 8-9: Rich Interactive HTML Dashboard (Replaces CLI Dashboard)

**Comprehensive HTML Dashboard with Auto-Browser Launch:**
```python
# src/adversary_mcp_server/dashboard/rich_html_dashboard.py
from jinja2 import Template
import json
import webbrowser
import time
from pathlib import Path
from typing import Dict, Any
import threading
import http.server
import socketserver
from contextlib import contextmanager

class ComprehensiveHTMLDashboard:
    """Rich, interactive HTML dashboard with comprehensive telemetry visualization"""

    DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Adversary MCP Server - Security Analysis Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0"></script>
    <style>
        :root {
            --primary-color: #007AFF;
            --success-color: #34C759;
            --warning-color: #FF9500;
            --danger-color: #FF3B30;
            --info-color: #5AC8FA;
            --dark-color: #1D1D1F;
            --light-bg: #F2F2F7;
            --card-bg: #FFFFFF;
            --text-primary: #1D1D1F;
            --text-secondary: #8E8E93;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--light-bg);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--info-color));
            color: white;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            padding: 30px;
            max-width: 1800px;
            margin: 0 auto;
        }

        .card {
            background: var(--card-bg);
            border-radius: 16px;
            padding: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
            border: 1px solid rgba(0,0,0,0.05);
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.12);
        }

        .card-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--light-bg);
        }

        .card-header h2 {
            font-size: 1.5em;
            margin-left: 10px;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 20px;
        }

        .metric-card {
            text-align: center;
            padding: 20px;
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-radius: 12px;
            border: 1px solid rgba(0,0,0,0.05);
        }

        .metric-value {
            font-size: 2.8em;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 8px;
            display: block;
        }

        .metric-label {
            color: var(--text-secondary);
            font-size: 0.9em;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .chart-container {
            position: relative;
            height: 350px;
            margin: 20px 0;
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .status-active { background: var(--success-color); }
        .status-warning { background: var(--warning-color); }
        .status-error { background: var(--danger-color); }

        .tool-stats-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .tool-stat-item {
            padding: 15px;
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-radius: 10px;
            border-left: 4px solid var(--primary-color);
        }

        .pipeline-stages {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .pipeline-stage {
            display: flex;
            align-items: center;
            padding: 15px;
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-radius: 10px;
            transition: all 0.2s;
        }

        .pipeline-stage:hover {
            transform: translateX(5px);
        }

        .stage-number {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--success-color);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 1.2em;
            margin-right: 20px;
        }

        .threat-category-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            margin: 8px 0;
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-radius: 8px;
            border-left: 4px solid var(--danger-color);
        }

        .controls {
            position: fixed;
            top: 20px;
            right: 20px;
            display: flex;
            gap: 10px;
            z-index: 1000;
        }

        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: var(--primary-color);
            color: white;
        }

        .btn-success {
            background: var(--success-color);
            color: white;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }

        .wide-card {
            grid-column: 1 / -1;
        }

        .database-info {
            background: linear-gradient(135deg, var(--info-color), var(--primary-color));
            color: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
        }

        .real-time-indicator {
            display: inline-flex;
            align-items: center;
            background: var(--success-color);
            color: white;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .interactive-hint {
            text-align: center;
            color: var(--text-secondary);
            font-style: italic;
            margin-top: 15px;
            font-size: 0.9em;
        }

        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
                padding: 15px;
                gap: 20px;
            }

            .metric-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .tool-stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Adversary MCP Server Dashboard</h1>
        <p>Real-time Security Analysis & Performance Monitoring</p>
        <span class="real-time-indicator">
            <span class="status-indicator status-active"></span>
            Live Data
        </span>
    </div>

    <div class="controls">
        <button class="btn btn-primary" onclick="refreshDashboard()">🔄 Refresh</button>
        <button class="btn btn-success" onclick="exportData()">📊 Export</button>
    </div>

    <div class="dashboard">
        <!-- Database & System Status -->
        <div class="card wide-card">
            <div class="database-info">
                <h3>🗄️ SQLAlchemy Database Status</h3>
                <p><strong>Database:</strong> {{ db_path }}</p>
                <p><strong>ORM Models:</strong> MCPToolExecution, CLICommandExecution, CacheOperationMetric, ScanEngineExecution, ThreatFinding, SystemHealth</p>
                <p><strong>Last Updated:</strong> {{ current_time }}</p>
            </div>
        </div>

        <!-- MCP Tool Performance -->
        <div class="card">
            <div class="card-header">
                <span>🔧</span>
                <h2>MCP Tool Performance</h2>
            </div>
            <div class="tool-stats-grid">
                {% for tool in data.mcp_tools %}
                <div class="tool-stat-item">
                    <h4>{{ tool.tool_name }}</h4>
                    <div class="metric-value">{{ tool.executions }}</div>
                    <div class="metric-label">Executions</div>
                    <small>{{ "%.1f"|format(tool.avg_duration_ms) }}ms avg | {{ "%.1f"|format(tool.success_rate * 100) }}% success</small>
                </div>
                {% endfor %}
            </div>
            <div class="chart-container">
                <canvas id="mcpToolChart"></canvas>
            </div>
        </div>

        <!-- CLI Command Performance -->
        <div class="card">
            <div class="card-header">
                <span>⚡</span>
                <h2>CLI Command Performance</h2>
            </div>
            <div class="tool-stats-grid">
                {% for cmd in data.cli_commands %}
                <div class="tool-stat-item">
                    <h4>{{ cmd.command_name }}</h4>
                    <div class="metric-value">{{ cmd.executions }}</div>
                    <div class="metric-label">Executions</div>
                    <small>{{ "%.1f"|format(cmd.avg_duration_ms) }}ms avg | {{ "%.1f"|format(cmd.success_rate * 100) }}% success</small>
                </div>
                {% endfor %}
            </div>
            <div class="chart-container">
                <canvas id="cliCommandChart"></canvas>
            </div>
        </div>

        <!-- Cache Performance Analysis -->
        <div class="card">
            <div class="card-header">
                <span>💾</span>
                <h2>Cache Performance Analysis</h2>
            </div>
            <div class="metric-grid">
                {% for cache in data.cache_performance %}
                <div class="metric-card">
                    <span class="metric-value">{{ "%.1f"|format(cache.hit_rate * 100) }}%</span>
                    <div class="metric-label">{{ cache.cache_name }} Hit Rate</div>
                </div>
                {% endfor %}
            </div>
            <div class="chart-container">
                <canvas id="cachePerformanceChart"></canvas>
            </div>
        </div>

        <!-- Scan Engine Performance -->
        <div class="card">
            <div class="card-header">
                <span>🔍</span>
                <h2>Scan Engine Performance</h2>
            </div>
            <div class="metric-grid">
                <div class="metric-card">
                    <span class="metric-value">{{ data.scan_engine.total_scans }}</span>
                    <div class="metric-label">Total Scans</div>
                </div>
                <div class="metric-card">
                    <span class="metric-value">{{ "%.1f"|format(data.scan_engine.avg_total_duration_ms) }}</span>
                    <div class="metric-label">Avg Duration (ms)</div>
                </div>
                <div class="metric-card">
                    <span class="metric-value">{{ data.scan_engine.total_threats_found }}</span>
                    <div class="metric-label">Threats Found</div>
                </div>
                <div class="metric-card">
                    <span class="metric-value">{{ "%.1f"|format(data.scan_engine.cache_hit_rate * 100) }}%</span>
                    <div class="metric-label">Cache Hit Rate</div>
                </div>
            </div>
            <div class="pipeline-stages">
                <div class="pipeline-stage">
                    <div class="stage-number">1</div>
                    <div>
                        <strong>Semgrep Analysis</strong><br>
                        <small>{{ "%.1f"|format(data.scan_engine.avg_semgrep_duration_ms) }}ms average</small>
                    </div>
                </div>
                <div class="pipeline-stage">
                    <div class="stage-number">2</div>
                    <div>
                        <strong>LLM Analysis</strong><br>
                        <small>{{ "%.1f"|format(data.scan_engine.avg_llm_duration_ms) }}ms average</small>
                    </div>
                </div>
                <div class="pipeline-stage">
                    <div class="stage-number">3</div>
                    <div>
                        <strong>LLM Validation</strong><br>
                        <small>{{ "%.1f"|format(data.scan_engine.avg_validation_duration_ms) }}ms average</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Threat Categories Analysis -->
        <div class="card">
            <div class="card-header">
                <span>🚨</span>
                <h2>Threat Categories</h2>
            </div>
            {% for threat in data.threat_categories %}
            <div class="threat-category-item">
                <div>
                    <strong>{{ threat.category|title }}</strong> ({{ threat.severity|upper }})
                    <br><small>Confidence: {{ "%.1f"|format(threat.avg_confidence * 100) }}%</small>
                </div>
                <div class="metric-value">{{ threat.count }}</div>
            </div>
            {% endfor %}
            <div class="chart-container">
                <canvas id="threatCategoryChart"></canvas>
            </div>
        </div>

        <!-- Language Performance -->
        <div class="card">
            <div class="card-header">
                <span>💻</span>
                <h2>Language Performance</h2>
            </div>
            <div class="chart-container">
                <canvas id="languagePerformanceChart"></canvas>
            </div>
            <div class="interactive-hint">
                Click on chart elements for detailed analysis
            </div>
        </div>
    </div>

    <script>
        // Chart.js configuration
        Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif';
        Chart.defaults.color = '#1D1D1F';

        // MCP Tool Performance Chart
        const mcpToolData = {{ data.mcp_tools|tojson }};
        new Chart(document.getElementById('mcpToolChart'), {
            type: 'bar',
            data: {
                labels: mcpToolData.map(t => t.tool_name.replace('adv_', '')),
                datasets: [{
                    label: 'Executions',
                    data: mcpToolData.map(t => t.executions),
                    backgroundColor: '#007AFF',
                    borderRadius: 6
                }, {
                    label: 'Avg Duration (ms)',
                    data: mcpToolData.map(t => t.avg_duration_ms),
                    backgroundColor: '#FF9500',
                    yAxisID: 'y1',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top' }
                },
                scales: {
                    y: { beginAtZero: true },
                    y1: { type: 'linear', display: true, position: 'right', beginAtZero: true }
                }
            }
        });

        // CLI Command Performance Chart
        const cliCommandData = {{ data.cli_commands|tojson }};
        new Chart(document.getElementById('cliCommandChart'), {
            type: 'doughnut',
            data: {
                labels: cliCommandData.map(c => c.command_name),
                datasets: [{
                    data: cliCommandData.map(c => c.executions),
                    backgroundColor: ['#007AFF', '#34C759', '#FF9500', '#FF3B30', '#AF52DE']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });

        // Cache Performance Chart
        const cacheData = {{ data.cache_performance|tojson }};
        new Chart(document.getElementById('cachePerformanceChart'), {
            type: 'radar',
            data: {
                labels: cacheData.map(c => c.cache_name),
                datasets: [{
                    label: 'Hit Rate %',
                    data: cacheData.map(c => c.hit_rate * 100),
                    backgroundColor: 'rgba(52, 199, 89, 0.2)',
                    borderColor: '#34C759',
                    pointBackgroundColor: '#34C759'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { r: { beginAtZero: true, max: 100 } }
            }
        });

        // Threat Category Chart
        const threatData = {{ data.threat_categories|tojson }};
        new Chart(document.getElementById('threatCategoryChart'), {
            type: 'polarArea',
            data: {
                labels: threatData.map(t => t.category + ' (' + t.severity + ')'),
                datasets: [{
                    data: threatData.map(t => t.count),
                    backgroundColor: [
                        'rgba(255, 59, 48, 0.8)',   // critical - red
                        'rgba(255, 149, 0, 0.8)',   // high - orange
                        'rgba(255, 204, 0, 0.8)',   // medium - yellow
                        'rgba(52, 199, 89, 0.8)',   // low - green
                        'rgba(0, 122, 255, 0.8)'    // info - blue
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // Language Performance Chart
        const langData = {{ data.language_performance|tojson }};
        new Chart(document.getElementById('languagePerformanceChart'), {
            type: 'scatter',
            data: {
                datasets: [{
                    label: 'Scans vs Avg Duration',
                    data: langData.map(l => ({
                        x: l.scans,
                        y: l.avg_duration_ms,
                        label: l.language
                    })),
                    backgroundColor: 'rgba(0, 122, 255, 0.6)',
                    pointRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { title: { display: true, text: 'Number of Scans' } },
                    y: { title: { display: true, text: 'Average Duration (ms)' } }
                }
            }
        });

        // Dashboard functions
        function refreshDashboard() {
            window.location.reload();
        }

        function exportData() {
            const data = {
                timestamp: new Date().toISOString(),
                dashboard_data: {{ data|tojson }}
            };

            const dataStr = JSON.stringify(data, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);

            const exportFileDefaultName = 'adversary-dashboard-' + new Date().toISOString().split('T')[0] + '.json';

            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', exportFileDefaultName);
            linkElement.click();
        }

        // Auto-refresh every 30 seconds
        setInterval(refreshDashboard, 30000);

        console.log('🛡️ Adversary MCP Server Dashboard loaded');
        console.log('Database:', '{{ db_path }}');
        console.log('Total data points:', {{ data.scan_engine.total_scans }});
    </script>
</body>
</html>
    """

    def __init__(self, telemetry_service: TelemetryService):
        self.telemetry_service = telemetry_service
        self.template = Template(self.DASHBOARD_TEMPLATE)

    def generate_dashboard_html(self, hours: int = 24) -> str:
        """Generate comprehensive HTML dashboard"""
        # Get all dashboard data
        data = self.telemetry_service.get_dashboard_data(hours)

        return self.template.render(
            data=data,
            db_path=str(self.telemetry_service.db.db_path),
            current_time=time.strftime('%Y-%m-%d %H:%M:%S'),
            hours=hours
        )

    def save_and_launch_dashboard(self, output_path: Path = None, auto_open: bool = True, hours: int = 24):
        """Save dashboard HTML and auto-launch in browser"""
        if output_path is None:
            output_path = Path("~/.local/share/adversary-mcp-server/dashboard.html").expanduser()

        # Generate and save dashboard
        html_content = self.generate_dashboard_html(hours)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding='utf-8')

        print(f"🎯 Dashboard generated: {output_path}")

        if auto_open:
            self._launch_in_browser(output_path)

        return output_path

    def _launch_in_browser(self, file_path: Path):
        """Launch dashboard in default browser"""
        try:
            # Convert to absolute path and create file URL
            abs_path = file_path.resolve()
            file_url = f"file://{abs_path}"

            print(f"🌐 Opening dashboard in browser...")

            # Try to open in default browser
            if webbrowser.open(file_url):
                print(f"✅ Dashboard opened successfully!")
                print(f"🔗 URL: {file_url}")
            else:
                print(f"❌ Could not open browser automatically")
                print(f"🔗 Open manually: {file_url}")

        except Exception as e:
            print(f"❌ Failed to open browser: {e}")
            print(f"🔗 Open manually: file://{file_path.resolve()}")

    def serve_dashboard_live(self, port: int = 8080, hours: int = 24):
        """Serve dashboard with live updates on HTTP server"""
        class DashboardHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, dashboard_instance=None, **kwargs):
                self.dashboard = dashboard_instance
                super().__init__(*args, **kwargs)

            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                    self.end_headers()

                    # Generate fresh dashboard content
                    html_content = self.dashboard.generate_dashboard_html(hours)
                    self.wfile.write(html_content.encode('utf-8'))
                else:
                    super().do_GET()

        # Create partial function to pass dashboard instance
        import functools
        handler = functools.partial(DashboardHandler, dashboard_instance=self)

        # Start server in background thread
        def start_server():
            with socketserver.TCPServer(("", port), handler) as httpd:
                print(f"🚀 Live dashboard server started on http://localhost:{port}")
                httpd.serve_forever()

        server_thread = threading.Thread(target=start_server, daemon=True)
        server_thread.start()

        # Auto-open browser to live dashboard
        live_url = f"http://localhost:{port}"
        try:
            webbrowser.open(live_url)
            print(f"✅ Live dashboard opened at {live_url}")
        except Exception as e:
            print(f"❌ Could not open browser: {e}")
            print(f"🔗 Open manually: {live_url}")

        return server_thread

# === DASHBOARD MANAGEMENT ===

class DashboardManager:
    """Manages dashboard generation and serving - replaces CLI monitoring completely"""

    def __init__(self, telemetry_service: TelemetryService):
        self.telemetry_service = telemetry_service
        self.dashboard = ComprehensiveHTMLDashboard(telemetry_service)

    def generate_static_dashboard(self, hours: int = 24, auto_open: bool = True) -> Path:
        """Generate static HTML dashboard file and optionally open in browser"""
        return self.dashboard.save_and_launch_dashboard(auto_open=auto_open, hours=hours)

    def start_live_dashboard(self, port: int = 8080, hours: int = 24):
        """Start live-updating dashboard server"""
        return self.dashboard.serve_dashboard_live(port=port, hours=hours)

    def export_dashboard_data(self, output_path: Path = None, hours: int = 24) -> Path:
        """Export dashboard data as JSON for external analysis"""
        if output_path is None:
            output_path = Path("~/.local/share/adversary-mcp-server/dashboard-data.json").expanduser()

        data = {
            'timestamp': time.time(),
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'hours_analyzed': hours,
            'dashboard_data': self.telemetry_service.get_dashboard_data(hours)
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(data, indent=2), encoding='utf-8')

        print(f"📊 Dashboard data exported: {output_path}")
        return output_path
```

#### Day 10: Metrics Collection Refactoring & Integration

**Problem: Broken Metrics Collection System**
```python
# Current issues with metrics collection:
# - JSON-based collectors that fail and corrupt data
# - No integration between scan engine and metrics storage
# - Missing telemetry insertion points in MCP tools and CLI commands
# - No automatic health monitoring or system snapshots
# - Metrics collection happens in isolated silos without coordination
```

**Solution: Complete Metrics Collection Refactoring**

```python
# src/adversary_mcp_server/telemetry/integration.py
from contextlib import contextmanager
import time
import psutil
import os
from pathlib import Path
from typing import Dict, Any, Optional
import uuid
from functools import wraps

class MetricsCollectionOrchestrator:
    """Orchestrates all metrics collection across the entire system"""

    def __init__(self, telemetry_service: TelemetryService):
        self.telemetry = telemetry_service
        self.system_health_interval = 300  # 5 minutes
        self._last_health_check = 0

    # === MCP TOOL INTEGRATION ===

    def mcp_tool_wrapper(self, tool_name: str):
        """Decorator to automatically track MCP tool executions"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate session ID for tracking
                session_id = str(uuid.uuid4())

                # Start tracking
                execution_id = None
                try:
                    execution = self.telemetry.start_mcp_tool_tracking(
                        tool_name=tool_name,
                        session_id=session_id,
                        request_params={
                            'args': str(args)[:500],  # Truncate for storage
                            'kwargs': {k: str(v)[:100] for k, v in kwargs.items()},
                        },
                        validation_enabled=kwargs.get('use_validation', False),
                        llm_enabled=kwargs.get('use_llm', False)
                    )
                    execution_id = execution.id

                    # Execute the actual tool
                    result = await func(*args, **kwargs)

                    # Extract findings count from result
                    findings_count = 0
                    if hasattr(result, 'findings') and result.findings:
                        findings_count = len(result.findings)
                    elif isinstance(result, dict) and 'findings' in result:
                        findings_count = len(result['findings'])

                    # Complete tracking
                    self.telemetry.complete_mcp_tool_tracking(
                        execution_id=execution_id,
                        success=True,
                        findings_count=findings_count
                    )

                    return result

                except Exception as e:
                    # Track failure
                    if execution_id:
                        self.telemetry.complete_mcp_tool_tracking(
                            execution_id=execution_id,
                            success=False,
                            error_message=str(e)[:500]
                        )
                    raise
                finally:
                    # Opportunistic health check
                    self._maybe_record_health()

            return wrapper
        return decorator

    # === CLI COMMAND INTEGRATION ===

    def cli_command_wrapper(self, command_name: str):
        """Decorator to automatically track CLI command executions"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Start tracking
                execution_id = None
                try:
                    execution = self.telemetry.start_cli_command_tracking(
                        command_name=command_name,
                        args={
                            'args': str(args)[:500],
                            'kwargs': {k: str(v)[:100] for k, v in kwargs.items()},
                        },
                        subcommand=kwargs.get('path') or kwargs.get('file_path'),
                        validation_enabled=kwargs.get('use_validation', False)
                    )
                    execution_id = execution.id

                    # Execute command
                    result = func(*args, **kwargs)

                    # Determine exit code
                    exit_code = 0
                    if isinstance(result, int):
                        exit_code = result
                    elif hasattr(result, 'returncode'):
                        exit_code = result.returncode

                    # Complete tracking
                    self.telemetry.complete_cli_command_tracking(
                        execution_id=execution_id,
                        exit_code=exit_code,
                        findings_count=getattr(result, 'findings_count', 0)
                    )

                    return result

                except Exception as e:
                    # Track failure
                    if execution_id:
                        self.telemetry.complete_cli_command_tracking(
                            execution_id=execution_id,
                            exit_code=1
                        )
                    raise
                finally:
                    self._maybe_record_health()

            return wrapper
        return decorator

    # === SCAN ENGINE INTEGRATION ===

    @contextmanager
    def track_scan_execution(self, trigger_source: str, scan_type: str, target_path: str, **kwargs):
        """Context manager for comprehensive scan tracking"""
        scan_id = str(uuid.uuid4())
        start_time = time.time()

        # Initialize tracking
        execution = self.telemetry.start_scan_tracking(
            scan_id=scan_id,
            trigger_source=trigger_source,
            scan_type=scan_type,
            target_path=target_path,
            **kwargs
        )

        # Yield scan context with timing utilities
        scan_context = ScanTrackingContext(scan_id, start_time, self.telemetry)

        try:
            yield scan_context

            # Complete successful scan
            self.telemetry.complete_scan_tracking(
                scan_id=scan_id,
                success=True,
                total_duration_ms=scan_context.get_total_duration(),
                semgrep_duration_ms=scan_context.semgrep_duration,
                llm_duration_ms=scan_context.llm_duration,
                validation_duration_ms=scan_context.validation_duration,
                cache_lookup_ms=scan_context.cache_lookup_duration,
                threats_found=scan_context.threats_found,
                threats_validated=scan_context.threats_validated,
                false_positives_filtered=scan_context.false_positives_filtered,
                cache_hit=scan_context.cache_hit
            )

        except Exception as e:
            # Complete failed scan
            self.telemetry.complete_scan_tracking(
                scan_id=scan_id,
                success=False,
                error_message=str(e)[:500],
                total_duration_ms=scan_context.get_total_duration()
            )
            raise
        finally:
            self._maybe_record_health()

    # === CACHE OPERATION INTEGRATION ===

    def track_cache_operation(self, operation_type: str, cache_name: str, key: str, **kwargs):
        """Track individual cache operations"""
        import hashlib
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]  # Shortened hash

        # Extract metadata from key for better analytics
        key_metadata = self._extract_key_metadata(key, cache_name)

        return self.telemetry.track_cache_operation(
            operation_type=operation_type,
            cache_name=cache_name,
            key_hash=key_hash,
            key_metadata=key_metadata,
            **kwargs
        )

    def _extract_key_metadata(self, key: str, cache_name: str) -> Dict[str, str]:
        """Extract useful metadata from cache key for analytics"""
        metadata = {}

        # Extract file extension if present
        if '.' in key:
            ext = key.split('.')[-1]
            if len(ext) <= 10:  # Reasonable extension length
                metadata['file_extension'] = ext

        # Extract cache type hints
        if 'semgrep' in cache_name.lower():
            metadata['cache_type'] = 'semgrep'
        elif 'llm' in cache_name.lower():
            metadata['cache_type'] = 'llm'
        elif 'validation' in cache_name.lower():
            metadata['cache_type'] = 'validation'

        # Extract approximate file size hint from key if encoded
        if ':' in key and cache_name in ['scan_results', 'file_cache']:
            parts = key.split(':')
            for part in parts:
                if part.isdigit():
                    metadata['approx_size'] = part[:10]  # Limit size
                    break

        return metadata

    # === THREAT FINDINGS INTEGRATION ===

    def record_threat_finding_with_context(self, scan_id: str, threat_finding: Any, scanner_source: str):
        """Record threat finding with comprehensive context"""
        finding_uuid = str(uuid.uuid4())

        # Extract finding details (adapt based on your threat finding structure)
        return self.telemetry.record_threat_finding(
            scan_id=scan_id,
            finding_uuid=finding_uuid,
            scanner_source=scanner_source,
            category=getattr(threat_finding, 'category', 'unknown'),
            severity=getattr(threat_finding, 'severity', 'medium'),
            file_path=getattr(threat_finding, 'file_path', ''),
            line_start=getattr(threat_finding, 'line_start', 0),
            line_end=getattr(threat_finding, 'line_end', 0),
            title=getattr(threat_finding, 'title', 'Security Finding'),
            rule_id=getattr(threat_finding, 'rule_id', None),
            confidence=getattr(threat_finding, 'confidence', None),
            column_start=getattr(threat_finding, 'column_start', None),
            column_end=getattr(threat_finding, 'column_end', None),
            code_snippet=getattr(threat_finding, 'code_snippet', None),
            description=getattr(threat_finding, 'description', None),
            remediation=getattr(threat_finding, 'remediation', None),
            references=getattr(threat_finding, 'references', None),
            is_validated=getattr(threat_finding, 'is_validated', False),
            is_false_positive=getattr(threat_finding, 'is_false_positive', False),
            validation_reason=getattr(threat_finding, 'validation_reason', None)
        )

    # === SYSTEM HEALTH MONITORING ===

    def _maybe_record_health(self):
        """Opportunistically record system health if interval elapsed"""
        current_time = time.time()
        if current_time - self._last_health_check >= self.system_health_interval:
            self._record_system_health()
            self._last_health_check = current_time

    def _record_system_health(self):
        """Record comprehensive system health snapshot"""
        try:
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(Path.home()))

            # Database metrics
            db_size_mb = None
            if self.telemetry.db.db_path.exists():
                db_size_mb = self.telemetry.db.db_path.stat().st_size / (1024 * 1024)

            # Cache directory metrics
            cache_size_mb = None
            cache_dir = self.telemetry.db.db_path.parent
            if cache_dir.exists():
                total_size = sum(f.stat().st_size for f in cache_dir.glob('**/*') if f.is_file())
                cache_size_mb = total_size / (1024 * 1024)

            # Calculate recent performance metrics
            recent_stats = self._calculate_recent_performance()

            self.telemetry.record_system_health_snapshot(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / (1024 * 1024),
                disk_usage_percent=disk.percent,
                db_size_mb=db_size_mb,
                cache_size_mb=cache_size_mb,
                **recent_stats
            )

        except Exception as e:
            # Don't fail the main operation if health recording fails
            print(f"Warning: Failed to record system health: {e}")

    def _calculate_recent_performance(self) -> Dict[str, float]:
        """Calculate recent performance metrics for health snapshot"""
        try:
            # Get data from last hour
            with self.telemetry.get_repository() as repo:
                data = repo.get_dashboard_data(hours=1)

                return {
                    'cache_hit_rate_1h': data['scan_engine'].get('cache_hit_rate', 0),
                    'avg_scan_duration_1h': data['scan_engine'].get('avg_total_duration_ms', 0),
                    'scans_per_hour': data['scan_engine'].get('total_scans', 0),
                    'error_rate_1h': self._calculate_error_rate(data)
                }
        except Exception:
            return {}

    def _calculate_error_rate(self, data: Dict[str, Any]) -> float:
        """Calculate error rate from dashboard data"""
        try:
            mcp_tools = data.get('mcp_tools', [])
            cli_commands = data.get('cli_commands', [])

            total_operations = 0
            failed_operations = 0

            for tool in mcp_tools:
                executions = tool.get('executions', 0)
                success_rate = tool.get('success_rate', 1.0)
                total_operations += executions
                failed_operations += executions * (1 - success_rate)

            for cmd in cli_commands:
                executions = cmd.get('executions', 0)
                success_rate = cmd.get('success_rate', 1.0)
                total_operations += executions
                failed_operations += executions * (1 - success_rate)

            return failed_operations / max(total_operations, 1)
        except Exception:
            return 0.0

class ScanTrackingContext:
    """Context object for tracking scan execution details"""

    def __init__(self, scan_id: str, start_time: float, telemetry_service: TelemetryService):
        self.scan_id = scan_id
        self.start_time = start_time
        self.telemetry = telemetry_service

        # Timing tracking
        self.semgrep_duration = None
        self.llm_duration = None
        self.validation_duration = None
        self.cache_lookup_duration = None

        # Results tracking
        self.threats_found = 0
        self.threats_validated = 0
        self.false_positives_filtered = 0
        self.cache_hit = False
        self._threat_findings = []

    def time_semgrep_scan(self):
        """Context manager for timing Semgrep operations"""
        return self._time_operation('semgrep_duration')

    def time_llm_analysis(self):
        """Context manager for timing LLM operations"""
        return self._time_operation('llm_duration')

    def time_validation(self):
        """Context manager for timing validation operations"""
        return self._time_operation('validation_duration')

    def time_cache_lookup(self):
        """Context manager for timing cache operations"""
        return self._time_operation('cache_lookup_duration')

    @contextmanager
    def _time_operation(self, duration_attr: str):
        """Generic timing context manager"""
        start = time.time()
        try:
            yield
        finally:
            duration_ms = (time.time() - start) * 1000
            setattr(self, duration_attr, duration_ms)

    def add_threat_finding(self, finding: Any, scanner_source: str):
        """Add a threat finding to this scan"""
        threat_record = self.telemetry.record_threat_finding_with_context(
            self.scan_id, finding, scanner_source
        )
        self._threat_findings.append(threat_record)
        self.threats_found += 1

        # Track validation status
        if getattr(finding, 'is_validated', False):
            self.threats_validated += 1
        if getattr(finding, 'is_false_positive', False):
            self.false_positives_filtered += 1

    def mark_cache_hit(self):
        """Mark this scan as a cache hit"""
        self.cache_hit = True

    def get_total_duration(self) -> float:
        """Get total scan duration in milliseconds"""
        return (time.time() - self.start_time) * 1000

# === INTEGRATION POINTS ===

class MetricsIntegrationMixin:
    """Mixin to add metrics collection to existing classes"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initialize metrics orchestrator
        self.metrics_orchestrator = self._get_metrics_orchestrator()

    def _get_metrics_orchestrator(self) -> MetricsCollectionOrchestrator:
        """Get or create metrics orchestrator instance"""
        # This would be injected via dependency injection in real implementation
        from adversary_mcp_server.database.models import AdversaryDatabase
        from adversary_mcp_server.telemetry.service import TelemetryService

        db = AdversaryDatabase()
        telemetry = TelemetryService(db)
        return MetricsCollectionOrchestrator(telemetry)

# Usage examples for integration:

# In MCP server tools:
@metrics_orchestrator.mcp_tool_wrapper('adv_scan_file')
async def adv_scan_file(file_path: str, **kwargs):
    # Existing scan file implementation
    pass

# In CLI commands:
@metrics_orchestrator.cli_command_wrapper('scan')
def scan_command(path: str, **kwargs):
    # Existing CLI scan implementation
    pass

# In scan engine:
def scan_file_with_metrics(self, file_path: Path, **kwargs):
    with self.metrics_orchestrator.track_scan_execution(
        trigger_source='api',  # or 'mcp_tool', 'cli'
        scan_type='file',
        target_path=str(file_path),
        file_count=1,
        language_detected=self._detect_language(file_path),
        file_size_bytes=file_path.stat().st_size
    ) as scan_context:

        # Cache lookup
        with scan_context.time_cache_lookup():
            cached_result = self.cache.get(cache_key)
            if cached_result:
                scan_context.mark_cache_hit()
                return cached_result

        # Semgrep scan
        with scan_context.time_semgrep_scan():
            semgrep_results = self.semgrep_scanner.scan(file_path)

        # Process findings
        for finding in semgrep_results:
            scan_context.add_threat_finding(finding, 'semgrep')

        # LLM analysis (if enabled)
        if kwargs.get('use_llm'):
            with scan_context.time_llm_analysis():
                llm_results = self.llm_scanner.scan(file_path)

            for finding in llm_results:
                scan_context.add_threat_finding(finding, 'llm')

        # Validation (if enabled)
        if kwargs.get('use_validation'):
            with scan_context.time_validation():
                validated_results = self.validator.validate(all_findings)

        return final_results

# In cache operations:
class CacheManager:
    def get(self, key: str):
        start_time = time.time()
        try:
            result = self._actual_get(key)
            access_time_ms = (time.time() - start_time) * 1000

            operation_type = 'hit' if result is not None else 'miss'
            self.metrics_orchestrator.track_cache_operation(
                operation_type=operation_type,
                cache_name=self.cache_name,
                key=key,
                access_time_ms=access_time_ms,
                size_bytes=len(str(result)) if result else None
            )

            return result
        except Exception as e:
            self.metrics_orchestrator.track_cache_operation(
                operation_type='error',
                cache_name=self.cache_name,
                key=key
            )
            raise
```

**Implementation Requirements:**

1. **🔧 Integrate with Existing Code**: Add decorators and context managers to all existing MCP tools, CLI commands, and scan operations
2. **📊 Automatic Collection**: No manual metrics calls - everything collected automatically through decorators/context managers
3. **🔄 Seamless Replacement**: Replace all existing JSON metrics collectors with SQLAlchemy-based collection
4. **💾 Efficient Storage**: Use batched inserts and proper session management for high-performance data collection
5. **🚨 Error Resilience**: Metrics collection failures should never break main functionality
6. **📈 Health Monitoring**: Automatic system health snapshots every 5 minutes with performance calculations

This refactoring ensures that the **new HTML dashboard has real, accurate data** flowing into it from all parts of the system, creating a truly comprehensive monitoring solution that works seamlessly with the consolidated SQLAlchemy database.

# Web application integration helpers for future Flask/FastAPI integration
class DashboardWebService:
    """Web service wrapper for dashboard integration with web frameworks"""

    def __init__(self, metrics_collector: EnhancedMetricsCollector):
        self.metrics_collector = metrics_collector
        self.dashboard = InteractiveHTMLDashboard(metrics_collector)

    def get_dashboard_data(self, hours: int = 24) -> Dict[str, Any]:
        """Get dashboard data for API endpoints"""
        return {
            'scan_stats': self.metrics_collector.get_scan_pipeline_stats(hours),
            'llm_stats': self.metrics_collector.get_llm_usage_stats(hours),
            'timestamp': time.time()
        }

    def get_dashboard_html(self, config: Dict[str, Any]) -> str:
        """Get dashboard HTML for web routes"""
        return self.dashboard.generate_dashboard_html(config)

    def get_health_status(self) -> Dict[str, Any]:
        """Get health status for monitoring endpoints"""
        try:
            # Test database connectivity
            stats = self.metrics_collector.get_scan_pipeline_stats(hours=1)
            return {
                'status': 'healthy',
                'database': 'connected',
                'orm': 'active',
                'recent_scans': stats['overview']['total_scans']
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'database': 'disconnected'
            }

# Enhanced Web Application Integration with SQLAlchemy ORM
class WebApplicationIntegration:
    """Comprehensive integration patterns for web applications using SQLAlchemy ORM"""

    def __init__(self, db: MetricsDatabase):
        self.db = db

    # Connection Pool Management for Web Applications
    def create_production_engine(self, db_url: str) -> Engine:
        """Create production-optimized SQLAlchemy engine with connection pooling"""
        from sqlalchemy import create_engine
        from sqlalchemy.pool import QueuePool

        return create_engine(
            db_url,
            # Connection pooling for web applications
            poolclass=QueuePool,
            pool_size=20,  # Base number of connections
            max_overflow=30,  # Additional connections when needed
            pool_pre_ping=True,  # Test connections before use
            pool_recycle=3600,  # Recycle connections every hour

            # Performance optimizations
            echo=False,  # Disable SQL logging in production
            echo_pool=False,  # Disable pool logging

            # Connection timeout settings
            connect_args={
                "check_same_thread": False,  # SQLite: Allow multi-threading
                "timeout": 20,  # Connection timeout
            }
        )

    # Request-Scoped Session Management
    @contextmanager
    def get_request_session(self):
        """Context manager for request-scoped database sessions"""
        session = self.db.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()

    # FastAPI Integration Example
    def create_fastapi_dependency(self):
        """Create FastAPI dependency for database sessions"""
        def get_db_session():
            """FastAPI dependency for database sessions"""
            with self.get_request_session() as session:
                yield session

        return Depends(get_db_session)

    # Flask Integration Example
    def setup_flask_integration(self, app):
        """Setup Flask integration with SQLAlchemy"""
        from flask import g

        @app.before_request
        def before_request():
            """Create database session before each request"""
            g.db_session = self.db.get_session()

        @app.teardown_appcontext
        def close_db_session(error):
            """Close database session after each request"""
            session = g.pop('db_session', None)
            if session is not None:
                if error:
                    session.rollback()
                else:
                    session.commit()
                session.close()

    # Async Web Framework Support (e.g., FastAPI with async SQLAlchemy)
    async def create_async_session_factory(self, async_db_url: str):
        """Create async session factory for async web frameworks"""
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

        async_engine = create_async_engine(
            async_db_url,
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True,
            echo=False
        )

        AsyncSessionLocal = async_sessionmaker(
            async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        return AsyncSessionLocal

    @asynccontextmanager
    async def get_async_session(self, session_factory):
        """Async context manager for database sessions"""
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

# Database Migration and Schema Management
class DatabaseMigration:
    """Database migration and schema versioning with SQLAlchemy"""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.metadata = Base.metadata

    def create_migration_table(self):
        """Create migration tracking table"""
        migration_sql = """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        );
        """
        with self.engine.connect() as conn:
            conn.execute(text(migration_sql))
            conn.commit()

    def get_current_version(self) -> int:
        """Get current database schema version"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text("SELECT MAX(version) FROM schema_migrations"))
                version = result.scalar()
                return version or 0
        except:
            return 0

    def apply_migration(self, version: int, description: str, sql_statements: List[str]):
        """Apply a database migration"""
        with self.engine.begin() as conn:  # Transaction
            # Apply migration SQL
            for sql in sql_statements:
                conn.execute(text(sql))

            # Record migration
            conn.execute(
                text("INSERT INTO schema_migrations (version, description) VALUES (:version, :desc)"),
                {"version": version, "desc": description}
            )

    def migrate_to_latest(self):
        """Apply all pending migrations"""
        migrations = [
            (1, "Create initial tables", [
                "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);",
                "CREATE INDEX IF NOT EXISTS idx_scan_perf_language ON scan_performance (language);"
            ]),
            (2, "Add LLM metrics optimization", [
                "CREATE INDEX IF NOT EXISTS idx_llm_provider_success ON llm_metrics (provider, success);",
                "CREATE INDEX IF NOT EXISTS idx_cache_operation_type ON cache_metrics (operation, cache_type);"
            ]),
            # Add more migrations as needed
        ]

        self.create_migration_table()
        current_version = self.get_current_version()

        for version, description, sql_statements in migrations:
            if version > current_version:
                self.apply_migration(version, description, sql_statements)
                print(f"Applied migration {version}: {description}")

# Performance Optimization for Web Applications
class PerformanceOptimizer:
    """SQLAlchemy performance optimization for web applications"""

    @staticmethod
    def optimize_query_patterns():
        """Common query optimization patterns"""
        # Example: Efficient pagination
        def paginate_scan_results(session: Session, page: int = 1, per_page: int = 50):
            offset = (page - 1) * per_page
            return (
                session.query(ScanPerformance)
                .order_by(ScanPerformance.timestamp.desc())
                .offset(offset)
                .limit(per_page)
                .all()
            )

        # Example: Bulk operations
        def bulk_insert_metrics(session: Session, metrics_data: List[Dict]):
            session.bulk_insert_mappings(MetricEntry, metrics_data)
            session.commit()

        # Example: Efficient aggregations
        def get_performance_summary(session: Session, hours: int = 24):
            since = time.time() - (hours * 3600)
            return (
                session.query(
                    func.count(ScanPerformance.id).label('total'),
                    func.avg(ScanPerformance.scan_duration_ms).label('avg_duration'),
                    func.min(ScanPerformance.scan_duration_ms).label('min_duration'),
                    func.max(ScanPerformance.scan_duration_ms).label('max_duration')
                )
                .filter(ScanPerformance.timestamp > since)
                .first()
            )

        return {
            'paginate': paginate_scan_results,
            'bulk_insert': bulk_insert_metrics,
            'summary': get_performance_summary
        }

    @staticmethod
    def setup_connection_events(engine: Engine):
        """Setup SQLAlchemy events for monitoring and optimization"""
        from sqlalchemy import event

        @event.listens_for(engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Log slow queries"""
            context._query_start_time = time.time()

        @event.listens_for(engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Log query completion"""
            total = time.time() - context._query_start_time
            if total > 0.5:  # Log queries taking more than 500ms
                logger.warning(f"Slow query ({total:.2f}s): {statement[:100]}...")

# Production Deployment Considerations
class ProductionDeployment:
    """Production deployment guidelines for SQLAlchemy integration"""

    @staticmethod
    def get_production_config() -> Dict[str, Any]:
        """Get production-ready configuration"""
        return {
            'database': {
                'url': 'sqlite:///~/.local/share/adversary-mcp-server/cache/metrics.db',
                'pool_size': 20,
                'max_overflow': 30,
                'pool_recycle': 3600,
                'pool_pre_ping': True
            },
            'session_management': {
                'expire_on_commit': False,
                'autoflush': True,
                'autocommit': False
            },
            'monitoring': {
                'log_slow_queries': True,
                'slow_query_threshold': 0.5,
                'enable_query_cache': True
            },
            'security': {
                'encrypt_at_rest': True,
                'backup_retention_days': 30,
                'audit_sensitive_queries': True
            }
        }

    @staticmethod
    def setup_database_monitoring(engine: Engine) -> Dict[str, Any]:
        """Setup comprehensive database monitoring"""
        return {
            'connection_pool_status': lambda: {
                'size': engine.pool.size(),
                'checked_in': engine.pool.checkedin(),
                'overflow': engine.pool.overflow(),
                'invalid': engine.pool.invalid()
            },
            'query_performance': lambda: {
                'total_queries': 0,  # Implement query counter
                'slow_queries': 0,   # Implement slow query counter
                'avg_duration': 0    # Implement duration tracking
            }
        }
```

#### Day 10: Updated CLI Monitoring Integration

**Enhanced CLI Monitoring:**
```python
# src/adversary_mcp_server/cli/monitor_command_v2.py
import click
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

class EnhancedCLIMonitor:
    """Enhanced CLI monitoring with SQLite3 backend"""

    def __init__(self, metrics_db: MetricsDatabase):
        self.metrics_db = metrics_db
        self.console = Console()

    def create_dashboard_layout(self) -> Layout:
        """Create rich dashboard layout"""
        layout = Layout()

        layout.split_row(
            Layout(name="left"),
            Layout(name="right")
        )

        layout["left"].split_column(
            Layout(name="performance"),
            Layout(name="pipeline")
        )

        layout["right"].split_column(
            Layout(name="cache"),
            Layout(name="languages")
        )

        return layout

    def update_dashboard(self, layout: Layout):
        """Update dashboard with fresh data"""
        stats = self.metrics_db.get_scan_pipeline_stats(hours=24)

        # Performance overview
        perf_table = Table(title="📊 Performance Overview")
        perf_table.add_column("Metric")
        perf_table.add_column("Value")

        perf_table.add_row("Total Scans", str(stats['overview']['total_scans']))
        perf_table.add_row("Avg Duration", f"{stats['overview']['avg_scan_duration_ms']:.1f}ms")
        perf_table.add_row("Threats Found", str(stats['overview']['total_threats_found']))
        perf_table.add_row("Cache Hit Rate", f"{stats['overview']['cache_hit_rate']*100:.1f}%")

        layout["performance"].update(Panel(perf_table))

        # Pipeline status
        pipeline_content = "🔄 **Scan Pipeline**\n\n"
        pipeline_content += f"1. File Input: ✅ Active\n"
        pipeline_content += f"2. Semgrep: ✅ {stats['overview']['avg_semgrep_duration_ms']:.1f}ms avg\n"
        pipeline_content += f"3. LLM Analysis: ✅ {stats['overview']['avg_llm_duration_ms']:.1f}ms avg\n"
        pipeline_content += f"4. Validation: ✅ {stats['overview']['avg_validation_duration_ms']:.1f}ms avg\n"

        layout["pipeline"].update(Panel(pipeline_content))

        # Cache performance
        cache_table = Table(title="💾 Cache Performance")
        cache_table.add_column("Metric")
        cache_table.add_column("Value")

        cache_table.add_row("Hit Rate", f"{stats['overview']['cache_hit_rate']*100:.1f}%")
        cache_table.add_row("Hits", str(stats['overview']['cache_hits']))
        cache_table.add_row("Misses", str(stats['overview']['cache_misses']))

        layout["cache"].update(Panel(cache_table))

        # Language performance
        lang_table = Table(title="💻 Language Performance")
        lang_table.add_column("Language")
        lang_table.add_column("Scans")
        lang_table.add_column("Avg Duration")

        for lang_stat in stats['by_language'][:5]:  # Top 5
            lang_table.add_row(
                lang_stat['language'] or 'Unknown',
                str(lang_stat['scans']),
                f"{lang_stat['avg_duration_ms']:.1f}ms"
            )

        layout["languages"].update(Panel(lang_table))

    def run_live_dashboard(self, refresh_interval: int = 5):
        """Run live updating dashboard"""
        layout = self.create_dashboard_layout()

        with Live(layout, refresh_per_second=1/refresh_interval, screen=True):
            while True:
                try:
                    self.update_dashboard(layout)
                    time.sleep(refresh_interval)
                except KeyboardInterrupt:
                    break

    def export_html_dashboard(self, output_path: Path, config: Dict[str, Any], open_browser: bool = True):
        """Export HTML dashboard and optionally open in browser"""
        dashboard = InteractiveHTMLDashboard(self.metrics_db)
        dashboard.save_dashboard(output_path, config)
        self.console.print(f"✅ HTML dashboard exported to: {output_path}")

        if open_browser:
            self._open_in_browser(output_path)

    def _open_in_browser(self, file_path: Path):
        """Open HTML file in default web browser"""
        import webbrowser
        import os

        try:
            # Convert to absolute path and create file URL
            abs_path = file_path.resolve()
            file_url = f"file://{abs_path}"

            self.console.print(f"🌐 Opening dashboard in browser...")

            # Try to open in default browser
            if webbrowser.open(file_url):
                self.console.print(f"✅ Dashboard opened in browser")
            else:
                self.console.print(f"❌ Could not open browser automatically")
                self.console.print(f"🔗 Open manually: {file_url}")

        except Exception as e:
            self.console.print(f"❌ Failed to open browser: {e}")
            self.console.print(f"🔗 Open manually: file://{file_path.resolve()}")

@click.command()
@click.option('--refresh', default=5, help='Refresh interval in seconds')
@click.option('--export-html', type=click.Path(), help='Export HTML dashboard to file')
@click.option('--no-browser', is_flag=True, help='Skip opening browser after export')
def monitor(refresh: int, export_html: Optional[str], no_browser: bool):
    """Enhanced monitoring dashboard with SQLite3 backend"""
    metrics_db = MetricsDatabase()
    monitor = EnhancedCLIMonitor(metrics_db)

    if export_html:
        config = {
            'scan_engine_version': '2.0.0',
            'llm_enabled': True,
            'validation_enabled': True,
            'cache_enabled': True,
            'database_path': str(metrics_db.db_path)
        }
        # Open browser unless --no-browser flag is used
        monitor.export_html_dashboard(Path(export_html), config, open_browser=not no_browser)
    else:
        monitor.run_live_dashboard(refresh_interval=refresh)
```

### PHASE 3: Security & Monitoring (Week 3, Days 11-15)

#### Day 11-12: Security Hardening

**Input Validation Framework:**
```python
# src/adversary_mcp_server/security/validation.py
import re
from pathlib import Path
from typing import List

class InputValidator:
    """Comprehensive input validation to prevent security issues"""

    # Patterns for dangerous inputs
    PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[/\\]')
    COMMAND_INJECTION_PATTERN = re.compile(r'[;&|`$(){}]')
    SQL_INJECTION_PATTERN = re.compile(r"('|\"|;|--|\bOR\b|\bAND\b)", re.IGNORECASE)

    @staticmethod
    def validate_file_path(path: str, allowed_dirs: List[Path] = None) -> Path:
        """Validate and sanitize file paths"""
        # Check for path traversal attempts
        if InputValidator.PATH_TRAVERSAL_PATTERN.search(path):
            raise SecurityError("Path traversal detected")

        # Convert to Path and resolve
        safe_path = Path(path).resolve()

        # Ensure within allowed directories
        if allowed_dirs:
            if not any(safe_path.is_relative_to(d) for d in allowed_dirs):
                raise SecurityError("Path outside allowed directories")

        # Check file exists and is readable
        if not safe_path.exists():
            raise FileNotFoundError(f"File not found: {safe_path}")

        if not safe_path.is_file():
            raise ValueError(f"Not a file: {safe_path}")

        return safe_path

    @staticmethod
    def sanitize_log_output(data: str, max_length: int = 1000) -> str:
        """Remove sensitive data from log output"""
        # Patterns for sensitive data
        patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
            (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '[CARD]'),
            (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),
            (r'(?i)(api[_-]?key|password|secret|token)[\s:=]+[\S]+', '[REDACTED]'),
        ]

        sanitized = data[:max_length]
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized)

        return sanitized

# src/adversary_mcp_server/security/middleware.py
class SecurityMiddleware:
    """Security layer for all requests"""

    def __init__(self, validator: InputValidator):
        self.validator = validator

    async def process_request(self, request: dict) -> dict:
        """Validate and sanitize incoming requests"""
        # Validate file paths
        if 'file_path' in request:
            request['file_path'] = self.validator.validate_file_path(
                request['file_path'],
                allowed_dirs=[Path.cwd()]  # Only current directory
            )

        # Validate other inputs
        for key, value in request.items():
            if isinstance(value, str):
                # Check for injection attempts
                if self.validator.COMMAND_INJECTION_PATTERN.search(value):
                    raise SecurityError(f"Potential injection in {key}")

        return request

    async def process_response(self, response: dict) -> dict:
        """Sanitize outgoing responses"""
        # Remove any sensitive data
        if 'error' in response and 'stack_trace' in response['error']:
            # Don't expose stack traces to users
            response['error'].pop('stack_trace')

        return response
```

#### Day 13: Observability Implementation

**Structured Logging:**
```python
# src/adversary_mcp_server/monitoring/structured_logging.py
import json
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict
import uuid

@dataclass
class LogEvent:
    """Structured log event"""
    timestamp: float
    level: str
    message: str
    correlation_id: str
    component: str
    operation: str
    duration_ms: float = None
    error: str = None
    metadata: Dict[str, Any] = None

class StructuredLogger:
    """Structured logging for better observability"""

    def __init__(self, component: str):
        self.component = component
        self._operation_starts = {}

    def start_operation(self, operation: str, correlation_id: str = None) -> str:
        """Start timing an operation"""
        correlation_id = correlation_id or str(uuid.uuid4())
        self._operation_starts[correlation_id] = time.time()

        self._emit(LogEvent(
            timestamp=time.time(),
            level="INFO",
            message=f"Starting {operation}",
            correlation_id=correlation_id,
            component=self.component,
            operation=operation
        ))

        return correlation_id

    def end_operation(self, correlation_id: str, operation: str,
                      success: bool = True, metadata: dict = None):
        """End timing an operation"""
        start_time = self._operation_starts.pop(correlation_id, time.time())
        duration_ms = (time.time() - start_time) * 1000

        self._emit(LogEvent(
            timestamp=time.time(),
            level="INFO" if success else "ERROR",
            message=f"Completed {operation}",
            correlation_id=correlation_id,
            component=self.component,
            operation=operation,
            duration_ms=duration_ms,
            metadata=metadata
        ))

    def error(self, message: str, error: Exception, correlation_id: str = None):
        """Log an error with structure"""
        self._emit(LogEvent(
            timestamp=time.time(),
            level="ERROR",
            message=message,
            correlation_id=correlation_id or str(uuid.uuid4()),
            component=self.component,
            operation="error",
            error=str(error),
            metadata={"error_type": type(error).__name__}
        ))

    def _emit(self, event: LogEvent):
        """Emit structured log event"""
        # Convert to JSON for structured logging systems
        log_data = asdict(event)
        print(json.dumps(log_data))  # In production, send to logging service

# Usage example
logger = StructuredLogger("ScanService")

correlation_id = logger.start_operation("file_scan")
try:
    result = await scan_file(path)
    logger.end_operation(correlation_id, "file_scan", metadata={"threats": len(result)})
except Exception as e:
    logger.error("Scan failed", e, correlation_id)
    logger.end_operation(correlation_id, "file_scan", success=False)
```

**Health Check Implementation:**
```python
# src/adversary_mcp_server/monitoring/health.py
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus
    message: str
    metadata: Dict[str, Any]

class HealthChecker:
    """Comprehensive health checking"""

    def __init__(self):
        self._checks = {}

    def register_check(self, name: str, check_func):
        """Register a health check function"""
        self._checks[name] = check_func

    async def check_health(self) -> Dict[str, Any]:
        """Run all health checks"""
        results = []
        overall_status = HealthStatus.HEALTHY

        for name, check_func in self._checks.items():
            try:
                component_health = await check_func()
                results.append(component_health)

                # Degrade overall status if component unhealthy
                if component_health.status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif component_health.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED

            except Exception as e:
                results.append(ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Check failed: {e}",
                    metadata={}
                ))
                overall_status = HealthStatus.UNHEALTHY

        return {
            "status": overall_status.value,
            "timestamp": time.time(),
            "components": [asdict(r) for r in results]
        }

# Example health checks
async def check_database_health() -> ComponentHealth:
    """Check database connectivity"""
    try:
        # Attempt database ping
        await db.ping()
        return ComponentHealth(
            name="database",
            status=HealthStatus.HEALTHY,
            message="Database responding",
            metadata={"response_time_ms": 5}
        )
    except Exception as e:
        return ComponentHealth(
            name="database",
            status=HealthStatus.UNHEALTHY,
            message=f"Database unreachable: {e}",
            metadata={}
        )

async def check_cache_health() -> ComponentHealth:
    """Check cache availability"""
    try:
        test_key = "health_check"
        await cache.set(test_key, "test")
        value = await cache.get(test_key)

        if value == "test":
            return ComponentHealth(
                name="cache",
                status=HealthStatus.HEALTHY,
                message="Cache operational",
                metadata={"test_passed": True}
            )
    except Exception as e:
        return ComponentHealth(
            name="cache",
            status=HealthStatus.DEGRADED,
            message="Cache unavailable, using fallback",
            metadata={"error": str(e)}
        )
```

#### Day 14-15: Testing Infrastructure

**Simplified Test Setup with DI:**
```python
# tests/fixtures/container.py
import pytest
from unittest.mock import Mock, AsyncMock

@pytest.fixture
def test_container():
    """Provide test container with mocked services"""
    container = ServiceContainer()

    # Register test doubles
    container.register_singleton(IScanEngine, Mock)
    container.register_singleton(IValidator, Mock)
    container.register_singleton(ICacheManager, Mock)
    container.register_singleton(IMetricsCollector, Mock)

    return container

@pytest.fixture
def mock_scan_engine(test_container):
    """Provide configured mock scan engine"""
    mock = test_container.resolve(IScanEngine)
    mock.scan_file = AsyncMock(return_value=ScanResult(threats=[]))
    return mock

# Simple test with automatic mocking
@pytest.mark.asyncio
async def test_scan_service(test_container):
    # Arrange - container provides all mocks
    scan_service = ScanService(
        scanner=test_container.resolve(IScanEngine),
        validator=test_container.resolve(IValidator),
        cache=test_container.resolve(ICacheManager)
    )

    # Act
    result = await scan_service.scan_with_validation(Path("test.py"))

    # Assert
    assert result is not None
    test_container.resolve(IScanEngine).scan_file.assert_called_once()
```

**Test Organization:**
```python
# tests/unit/ - Fast, isolated tests
# tests/integration/ - Component interaction tests
# tests/e2e/ - Full workflow tests

# tests/unit/test_threat_aggregator.py
class TestThreatAggregator:
    """Unit tests for ThreatAggregator"""

    def test_deduplicates_similar_threats(self):
        # Given
        aggregator = ThreatAggregator()
        threat1 = Threat(file="test.py", line=10, category="injection")
        threat2 = Threat(file="test.py", line=11, category="injection")  # Similar

        # When
        result = aggregator.aggregate([threat1], [threat2])

        # Then
        assert len(result) == 1  # Deduplicated

    def test_preserves_different_threats(self):
        # Given
        aggregator = ThreatAggregator()
        threat1 = Threat(file="test.py", line=10, category="injection")
        threat2 = Threat(file="test.py", line=50, category="xss")  # Different

        # When
        result = aggregator.aggregate([threat1], [threat2])

        # Then
        assert len(result) == 2  # Both preserved

# tests/integration/test_scan_workflow.py
@pytest.mark.integration
class TestScanWorkflow:
    """Integration tests for complete scan workflow"""

    @pytest.mark.asyncio
    async def test_scan_with_caching(self, test_container):
        # Setup real components with test data
        scan_service = create_scan_service(test_container)

        # First scan - cache miss
        result1 = await scan_service.scan_with_validation(Path("test.py"))

        # Second scan - cache hit
        result2 = await scan_service.scan_with_validation(Path("test.py"))

        # Should return same result from cache
        assert result1 == result2

        # Verify cache was used
        cache_metrics = test_container.resolve(IMetricsCollector).get_metrics()
        assert cache_metrics["cache_hits"] == 1
```

---

## Testing & Validation

### Performance Benchmarks

**Before/After Measurements:**
```python
# benchmarks/performance_test.py
import time
import asyncio
from pathlib import Path

class PerformanceBenchmark:
    """Measure performance improvements"""

    async def benchmark_scan_performance(self):
        """Compare old vs new implementation"""
        files = list(Path("test_data").glob("**/*.py"))[:100]

        # Old implementation
        old_scanner = OldScanEngine()
        start = time.time()
        for file in files:
            old_scanner.scan_file_sync(file)  # Sequential
        old_duration = time.time() - start

        # New implementation
        new_scanner = ScanService()
        start = time.time()
        await asyncio.gather(*[
            new_scanner.scan_file(file) for file in files
        ])  # Parallel
        new_duration = time.time() - start

        improvement = (old_duration - new_duration) / old_duration * 100
        print(f"Performance improvement: {improvement:.1f}%")
        print(f"Old: {old_duration:.2f}s, New: {new_duration:.2f}s")

        assert new_duration < old_duration * 0.5  # At least 50% faster

    def benchmark_memory_usage(self):
        """Measure memory improvements"""
        import tracemalloc

        # Old implementation
        tracemalloc.start()
        old_scanner = OldScanEngine()
        old_snapshot = tracemalloc.take_snapshot()
        old_memory = sum(stat.size for stat in old_snapshot.statistics('lineno'))

        # New implementation
        tracemalloc.start()
        container = ServiceContainer()
        configure_container(container)
        new_scanner = container.resolve(IScanService)
        new_snapshot = tracemalloc.take_snapshot()
        new_memory = sum(stat.size for stat in new_snapshot.statistics('lineno'))

        reduction = (old_memory - new_memory) / old_memory * 100
        print(f"Memory reduction: {reduction:.1f}%")
        print(f"Old: {old_memory/1024/1024:.1f}MB, New: {new_memory/1024/1024:.1f}MB")

        assert new_memory < old_memory * 0.6  # At least 40% less memory
```

### Validation Criteria

**Phase 1 Validation:**
- [ ] All tests pass with new DI container
- [ ] No global state remains
- [ ] Classes under 200 lines
- [ ] Memory usage reduced by 30%+

**Phase 2 Validation:**
- [ ] Async operations properly managed
- [ ] No event loop creation in sync adapters
- [ ] Resource cleanup verified
- [ ] Performance improved by 50%+

**Phase 3 Validation:**
- [ ] All inputs validated
- [ ] No sensitive data in logs
- [ ] Health checks operational
- [ ] Test coverage > 90%

---

## Migration Strategy

### Step-by-Step Migration

**Week 1: Parallel Development**
```python
# Keep old code working while building new
src/
├── adversary_mcp_server/          # Old code
│   └── scanner/
│       └── scan_engine.py        # Keep for now
└── adversary_mcp_server_v2/      # New code
    └── application/
        └── scan_service.py        # New implementation
```

**Week 2: Feature Flags**
```python
# src/adversary_mcp_server/config.py
USE_NEW_ARCHITECTURE = os.getenv("USE_NEW_ARCH", "false") == "true"

# In code
if USE_NEW_ARCHITECTURE:
    from adversary_mcp_server_v2 import ScanService
    scanner = ScanService()
else:
    from adversary_mcp_server import ScanEngine
    scanner = ScanEngine()
```

**Week 3: Gradual Cutover**
1. Enable new architecture for 10% of requests
2. Monitor metrics and errors
3. Increase to 50% if stable
4. Full cutover when confident
5. Keep old code for 1 week as fallback

**Week 4: Cleanup**
1. Remove feature flags
2. Delete old implementation
3. Rename v2 to main
4. Update documentation

### Rollback Plan

**If Issues Arise:**
```bash
# Quick rollback via environment variable
export USE_NEW_ARCH=false

# Or via config file
echo "use_new_architecture: false" > config.yml

# Restart service
systemctl restart adversary-mcp-server
```

**Rollback Triggers:**
- Error rate > 1%
- Performance degradation > 10%
- Memory usage increase > 20%
- Critical bug discovered

---

## Success Metrics

### Performance Metrics

**Target Improvements:**
| Metric | Current | Target | Measurement Method |
|--------|---------|--------|-------------------|
| Scan Speed | 0.5 files/sec | 5 files/sec | Benchmark suite |
| Memory Usage | 150MB/instance | 50MB/instance | Memory profiler |
| Startup Time | 3 seconds | 0.5 seconds | Time measurement |
| API Latency (p95) | 500ms | 50ms | Metrics collector |
| Cache Hit Rate | 30% | 80% | Cache metrics |

### Quality Metrics

**Code Quality Targets:**
| Metric | Current | Target | Tool |
|--------|---------|--------|------|
| Test Coverage | 75% | 95% | pytest-cov |
| Cyclomatic Complexity | 15+ | <10 | radon |
| Code Duplication | 20% | <5% | pylint |
| Type Coverage | 40% | 90% | mypy |
| Security Issues | Unknown | 0 | bandit |

### Operational Metrics

**Production Readiness:**
- [ ] Zero memory leaks over 24 hours
- [ ] 99.9% uptime over 30 days
- [ ] < 0.1% error rate
- [ ] All critical paths monitored
- [ ] Graceful degradation tested

---

## Reference Materials

### Design Patterns Used

**Dependency Injection:**
- Enables testing and flexibility
- Reduces coupling between components
- Makes dependencies explicit

**Repository Pattern:**
- Abstracts data access
- Enables swapping data sources
- Simplifies testing

**Strategy Pattern:**
- Different scanning strategies
- Pluggable validators
- Configurable error handlers

**Observer Pattern:**
- Event-driven architecture
- Metrics collection
- Progress reporting

### Anti-Patterns to Avoid

**God Object:**
- Classes doing too much
- Violates single responsibility
- Hard to test and maintain

**Singleton Abuse:**
- Global state problems
- Testing difficulties
- Hidden dependencies

**Primitive Obsession:**
- Using strings/dicts everywhere
- No type safety
- Business logic spread out

### Tools & Libraries

**Testing:**
- pytest - Test framework
- pytest-asyncio - Async test support
- pytest-mock - Mocking utilities
- pytest-benchmark - Performance testing

**Code Quality:**
- mypy - Type checking
- black - Code formatting
- ruff - Fast linting
- bandit - Security scanning

**Monitoring:**
- structlog - Structured logging
- prometheus-client - Metrics
- opentelemetry - Distributed tracing

### Additional Resources

**Books:**
- "Clean Architecture" by Robert Martin
- "Domain-Driven Design" by Eric Evans
- "Refactoring" by Martin Fowler

**Articles:**
- [Python Dependency Injection](https://python-dependency-injector.ets-labs.org/)
- [Async/Await Best Practices](https://docs.python.org/3/library/asyncio-task.html)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security.html)

**Similar Projects:**
- [Bandit](https://github.com/PyCQA/bandit) - Security linter architecture
- [Black](https://github.com/psf/black) - Clean codebase structure
- [FastAPI](https://github.com/tiangolo/fastapi) - Dependency injection examples

---

## Appendix: Code Templates

### Service Template
```python
# Template for new services
from typing import Protocol

class IServiceName(Protocol):
    """Interface definition"""
    async def operation(self, param: Type) -> ReturnType:
        ...

class ServiceName:
    """Implementation of IServiceName"""

    def __init__(self, dependency1: IDep1, dependency2: IDep2):
        """Constructor with injected dependencies"""
        self.dep1 = dependency1
        self.dep2 = dependency2

    async def operation(self, param: Type) -> ReturnType:
        """Implement interface method"""
        # Validate input
        self._validate(param)

        # Business logic
        result = await self._process(param)

        # Return result
        return result

    def _validate(self, param: Type):
        """Input validation"""
        if not param:
            raise ValueError("Param required")

    async def _process(self, param: Type) -> ReturnType:
        """Core business logic"""
        # Implementation here
        pass
```

### Test Template
```python
# Template for tests
import pytest
from unittest.mock import Mock, AsyncMock

class TestServiceName:
    """Tests for ServiceName"""

    @pytest.fixture
    def service(self, test_container):
        """Create service with mocked dependencies"""
        return ServiceName(
            dependency1=test_container.resolve(IDep1),
            dependency2=test_container.resolve(IDep2)
        )

    @pytest.mark.asyncio
    async def test_operation_success(self, service):
        """Test successful operation"""
        # Arrange
        param = create_test_param()

        # Act
        result = await service.operation(param)

        # Assert
        assert result is not None
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_operation_validation_error(self, service):
        """Test validation error handling"""
        # Arrange
        invalid_param = None

        # Act & Assert
        with pytest.raises(ValueError):
            await service.operation(invalid_param)
```

---

## Notes for Future Implementation

This guide is designed to be used iteratively. Start with Phase 1 to establish the foundation, then build on it with subsequent phases. Each phase is independent enough to provide value on its own, but they build on each other for maximum benefit.

Remember:
1. **Test everything** - Every change should have tests
2. **Measure impact** - Use benchmarks to validate improvements
3. **Document decisions** - Future you will thank current you
4. **Iterate gradually** - Big bang rewrites fail, incremental changes succeed
5. **Keep backwards compatibility** - Until you're ready to fully migrate

The patterns and structures defined here have been battle-tested in production systems handling millions of requests. Following this guide will transform the Adversary MCP Server into a robust, maintainable, and scalable security scanning platform.

Good luck with the implementation! 🚀
