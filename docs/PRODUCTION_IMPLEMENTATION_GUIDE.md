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

### PHASE 2: Performance & Reliability (Week 2, Days 6-10)

#### Day 6-7: Async/Sync Optimization

**Problem to Solve:**
```python
# Current: Creating new event loop for each operation
def scan_file_sync(self, path):
    return asyncio.run(self.scan_file(path))  # BAD!
```

**Solution Implementation:**
```python
# src/adversary_mcp_server/application/adapters/sync_adapter.py
class SyncScanAdapter:
    """Provides synchronous interface to async operations efficiently"""

    def __init__(self, scan_service: ScanService):
        self.scan_service = scan_service
        self._loop = None
        self._thread = None

    def __enter__(self):
        """Start event loop in background thread"""
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup event loop"""
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)

    def scan_file(self, path: Path) -> ScanResult:
        """Synchronous scan using background event loop"""
        future = asyncio.run_coroutine_threadsafe(
            self.scan_service.scan_file(path),
            self._loop
        )
        return future.result(timeout=30)

    def scan_batch(self, paths: List[Path]) -> List[ScanResult]:
        """Efficiently scan multiple files in parallel"""
        future = asyncio.run_coroutine_threadsafe(
            self._scan_batch_async(paths),
            self._loop
        )
        return future.result(timeout=300)

    async def _scan_batch_async(self, paths: List[Path]):
        """Parallel scanning implementation"""
        tasks = [self.scan_service.scan_file(p) for p in paths]
        return await asyncio.gather(*tasks)

# CLI usage becomes efficient
def cli_scan_command(paths: List[Path]):
    with SyncScanAdapter(scan_service) as adapter:
        # Single event loop for entire operation
        results = adapter.scan_batch(paths)  # Parallel!
        return results
```

#### Day 8-9: Resource Management Implementation

**Connection Pool Implementation:**
```python
# src/adversary_mcp_server/infrastructure/pools/llm_client_pool.py
class LLMClientPool:
    """Manages pool of LLM client connections"""

    def __init__(self,
                 provider: str,
                 api_key: str,
                 max_clients: int = 5):
        self._provider = provider
        self._api_key = api_key
        self._available = asyncio.Queue(maxsize=max_clients)
        self._all_clients = []
        self._shutdown = False

        # Pre-create clients
        for _ in range(max_clients):
            client = self._create_client()
            self._all_clients.append(client)
            self._available.put_nowait(client)

    def _create_client(self):
        """Factory for creating LLM clients"""
        if self._provider == "openai":
            return OpenAIClient(self._api_key)
        elif self._provider == "anthropic":
            return AnthropicClient(self._api_key)

    @asynccontextmanager
    async def acquire(self):
        """Get client from pool with automatic return"""
        client = await self._available.get()
        try:
            yield client
        finally:
            if not self._shutdown:
                await self._available.put(client)

    async def shutdown(self):
        """Clean shutdown of all clients"""
        self._shutdown = True
        for client in self._all_clients:
            await client.close()

# Usage showing automatic resource management
async def scan_with_llm(file_path: Path, llm_pool: LLMClientPool):
    async with llm_pool.acquire() as llm_client:
        # Client automatically returned to pool after use
        result = await llm_client.analyze(file_path)
        return result
```

#### Day 10: Performance Optimizations

**Optimized Caching Implementation:**
```python
# src/adversary_mcp_server/infrastructure/cache/optimized_cache.py
import hashlib
from dataclasses import dataclass
from typing import Optional
import time

@dataclass
class CacheEntry:
    key: str
    value: Any
    size_bytes: int
    created_at: float
    last_accessed: float
    access_count: int

class OptimizedCache:
    """Memory-efficient cache with LRU eviction"""

    def __init__(self,
                 max_size_mb: int = 100,
                 ttl_seconds: int = 3600):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.ttl_seconds = ttl_seconds
        self.entries: Dict[str, CacheEntry] = {}
        self.current_size = 0
        self._lock = asyncio.Lock()

    def _generate_key(self, *args) -> str:
        """Simple, fast key generation"""
        key_data = "|".join(str(arg) for arg in args)
        return hashlib.md5(key_data.encode()).hexdigest()

    async def get(self, *args) -> Optional[Any]:
        """Get from cache with TTL check"""
        key = self._generate_key(*args)

        async with self._lock:
            if key not in self.entries:
                return None

            entry = self.entries[key]

            # Check TTL
            if time.time() - entry.created_at > self.ttl_seconds:
                self._evict(key)
                return None

            # Update access stats for LRU
            entry.last_accessed = time.time()
            entry.access_count += 1

            return entry.value

    async def set(self, value: Any, *args):
        """Add to cache with size management"""
        key = self._generate_key(*args)
        size = self._estimate_size(value)

        async with self._lock:
            # Evict if necessary to make room
            while self.current_size + size > self.max_size_bytes:
                self._evict_lru()

            # Add new entry
            self.entries[key] = CacheEntry(
                key=key,
                value=value,
                size_bytes=size,
                created_at=time.time(),
                last_accessed=time.time(),
                access_count=1
            )
            self.current_size += size

    def _evict_lru(self):
        """Evict least recently used entry"""
        if not self.entries:
            return

        lru_key = min(
            self.entries.keys(),
            key=lambda k: self.entries[k].last_accessed
        )
        self._evict(lru_key)

    def _evict(self, key: str):
        """Remove entry from cache"""
        if key in self.entries:
            entry = self.entries.pop(key)
            self.current_size -= entry.size_bytes
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
