# Adversary MCP Server - Comprehensive Remediation Plan

**Date Created**: August 10, 2025
**Current Test Status**: 64 failing tests, 1336 passed, 32 skipped
**Current Coverage**: 74.42% (Target: 75%+)
**MyPy Errors**: 27 errors across 5 files

## Overview

This document outlines a comprehensive remediation plan to address critical system failures, test failures, type system errors, missing metrics, and code quality issues discovered during Phase II (Monitoring & Telemetry) and Phase III (Security) implementation. The issues stem from architectural changes that broke existing functionality and incomplete integration of new systems.

## Critical Issues Identified

### System Architecture Breaks
- **Scan Engine Failures**: Core scanning functionality completely broken due to missing methods and attributes
- **Method Signature Mismatches**: Interface changes not propagated to all callers
- **Missing Dependencies**: New architecture components not properly wired together

### Data & Metrics Losses
- **Dashboard Data**: HTML dashboard showing "N/AB" and empty sections
- **LLM Metrics**: Token usage and cost estimation completely missing
- **Report Generation**: .adversary.json/.adversary.md files not using new metrics system

### Code Quality Issues
- **Inline Imports**: 19 files with imports not at file top
- **Type System**: 27 MyPy errors preventing proper type checking
- **Test Coverage**: Below 75% minimum threshold

---

## **PRIORITY 1: CRITICAL SYSTEM FIXES** 🚨

### 1. Fix Scan Engine Architecture Breaks

**Issue**: ScanEngine references non-existent methods and attributes
**Error Messages**:
```
'ScanEngine' object has no attribute 'apply_severity_filter'
'ScanEngine' object has no attribute 'result_builder'
```

**Root Cause**: Phase II refactoring moved these capabilities to:
- `apply_severity_filter` → ThreatAggregator component
- `result_builder` → ResultBuilder component

**Files Affected**:
- `src/adversary_mcp_server/scanner/scan_engine.py`
- `src/adversary_mcp_server/domain/aggregation/threat_aggregator.py`
- `src/adversary_mcp_server/infrastructure/builders/result_builder.py`

**Fix Strategy**:
1. Update ScanEngine to inject and use ThreatAggregator for severity filtering
2. Update ScanEngine to inject and use ResultBuilder for result construction
3. Ensure proper dependency injection in scan engine initialization
4. Update all scan engine method signatures to work with new architecture

**Test Requirements**:
- Verify scan engine can process files without attribute errors
- Ensure severity filtering works through ThreatAggregator
- Confirm result building works through ResultBuilder

---

### 2. Fix Semgrep Scanner Signature Issues

**Issue**: Method signature mismatch causing scan failures
**Error Messages**:
```
OptimizedSemgrepScanner.scan_file() missing 1 required positional argument: 'language'
```

**Root Cause**: Interface updated to require language parameter but callers not updated

**Files Affected**:
- `src/adversary_mcp_server/scanner/semgrep_scanner.py`
- `src/adversary_mcp_server/scanner/scan_engine.py`
- All code calling semgrep scanner methods

**Current Signature**:
```python
async def scan_file(self, file_path: str, language: str, config: str | None = None, ...)
```

**Fix Strategy**:
1. Audit all calls to `OptimizedSemgrepScanner.scan_file()`
2. Ensure language parameter is passed in all calls
3. Add language detection logic where missing
4. Update interface documentation

**Test Requirements**:
- Verify all semgrep scanner calls include language parameter
- Test language detection accuracy
- Ensure semgrep scans complete successfully

---

### 3. Fix ThreatAggregator Signature Changes

**Issue**: Method expects separate threat lists but receives single list
**Error Messages**:
```
ThreatAggregator.aggregate_threats() missing 1 required positional argument: 'llm_threats'
```

**Root Cause**: Method signature changed during Phase II refactoring

**Current Signature**:
```python
def aggregate_threats(
    self,
    semgrep_threats: list[ThreatMatch],
    llm_threats: list[ThreatMatch],
) -> list[ThreatMatch]:
```

**Files Affected**:
- `src/adversary_mcp_server/domain/aggregation/threat_aggregator.py`
- All test files calling `aggregate_threats()`
- All production code calling this method

**Fix Strategy**:
1. Update all callers to pass separate semgrep_threats and llm_threats lists
2. Where only one list exists, pass empty list for the other parameter
3. Update tests to use proper signature
4. Ensure backward compatibility where possible

**Test Requirements**:
- Verify aggregation works with separate threat lists
- Test aggregation with empty lists
- Confirm threat deduplication still functions

---

### 4. Fix ResultBuilder Method Name Issues

**Issue**: Tests calling non-existent method name
**Error Messages**:
```
AttributeError: 'ResultBuilder' object has no attribute 'build_scan_result'. Did you mean: 'build_enhanced_result'?
```

**Root Cause**: Method renamed during Phase II refactoring

**Correct Method Name**: `build_enhanced_result()`
**Incorrect Calls**: `build_scan_result()`

**Files Affected**:
- All test files using ResultBuilder
- Any production code with incorrect method calls

**Fix Strategy**:
1. Find all references to `build_scan_result()`
2. Replace with `build_enhanced_result()`
3. Verify method parameters still match
4. Update any related documentation

**Test Requirements**:
- Verify all ResultBuilder method calls use correct name
- Test result building functionality works as expected
- Confirm result format matches expectations

---

## **PRIORITY 2: MYPY TYPE SYSTEM FIXES** 🔧

### 5. Fix Database Models Base Class Issues

**Issue**: MyPy cannot resolve SQLAlchemy Base class
**Error Messages**:
```
src/adversary_mcp_server/database/models.py:45: error: Invalid base class "Base"
src/adversary_mcp_server/database/models.py:76: error: Invalid base class "Base"
```

**Root Cause**: SQLAlchemy Base class not properly imported or typed

**Files Affected**:
- `src/adversary_mcp_server/database/models.py`

**Fix Strategy**:
1. Ensure proper SQLAlchemy imports with typing
2. Use `DeclarativeBase` or properly typed `declarative_base()`
3. Add type hints for all model classes
4. Verify SQLAlchemy version compatibility

**Expected Import**:
```python
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass
```

---

### 6. Fix Bulk Insert Type Errors

**Issue**: SQLAlchemy bulk operations expect Mapper objects but receive class types
**Error Messages**:
```
Argument 1 to "bulk_insert_mappings" of "Session" has incompatible type "type"; expected "Mapper[Any]"
```

**Root Cause**: Incorrect SQLAlchemy API usage

**Files Affected**:
- `src/adversary_mcp_server/telemetry/bulk_operations.py`

**Fix Strategy**:
1. Use `session.bulk_insert_mappings(Table.__table__, data)` instead of passing class
2. Or use proper mapper objects from class.__mapper__
3. Update all bulk operation calls
4. Add proper type hints

**Correct Usage**:
```python
session.bulk_insert_mappings(MyModel.__mapper__, mapping_data)
```

---

### 7. Fix Object Arithmetic Type Errors

**Issue**: MyPy infers 'object' type causing arithmetic operation errors
**Error Messages**:
```
Unsupported left operand type for - ("object")
Unsupported operand types for + ("object" and "int")
```

**Root Cause**: Missing type hints causing MyPy to default to 'object'

**Files Affected**:
- `src/adversary_mcp_server/telemetry/maintenance.py`
- `src/adversary_mcp_server/migration/database_migration.py`

**Fix Strategy**:
1. Add explicit type hints for all variables used in arithmetic
2. Use Union types where multiple types are possible
3. Add type assertions where necessary
4. Update function signatures with proper return types

**Example Fix**:
```python
def calculate_duration(start: float, end: float) -> float:
    return end - start  # Now properly typed
```

---

### 8. Fix Dashboard Type Mismatches

**Issue**: Dashboard classes expect different collector types
**Error Messages**:
```
Argument 1 to "UnifiedDashboard" has incompatible type "UnifiedMetricsCollector"; expected "MetricsCollector | None"
```

**Root Cause**: Type hierarchy mismatch after metrics refactoring

**Files Affected**:
- `src/adversary_mcp_server/cli.py`
- Dashboard class constructors

**Fix Strategy**:
1. Update type annotations to match actual usage
2. Ensure UnifiedMetricsCollector inherits from or implements expected interface
3. Update constructor signatures
4. Add proper type checking

---

## **PRIORITY 3: TEST INFRASTRUCTURE FIXES** 🧪

### 9. Fix Security File Path Validation

**Issue**: Security tests using non-existent file paths
**Error Messages**:
```
FileNotFoundError: File not found: /safe/path/test.py
FileNotFoundError: File not found: /private/etc/shadow
```

**Root Cause**: Tests using hardcoded paths instead of mocking file system

**Files Affected**:
- `tests/integration/test_security_telemetry_integration.py`
- Other security validation tests

**Fix Strategy**:
1. Mock file system operations in security tests
2. Use temporary files for validation tests
3. Create test fixtures with known file paths
4. Update security validator to handle test scenarios

**Test Pattern**:
```python
@pytest.fixture
def temp_test_file():
    with tempfile.NamedTemporaryFile(suffix='.py') as f:
        f.write(b"test content")
        f.flush()
        yield f.name
```

---

### 10. Fix Test Variable Issues

**Issue**: Tests reference undefined variables
**Error Messages**:
```
NameError: name 'file_path_abs' is not defined
```

**Root Cause**: Tests not updated after method signature changes

**Files Affected**:
- `tests/scanner/test_scan_engine.py`
- Other scan engine tests

**Fix Strategy**:
1. Define all required variables in test setup
2. Update test fixtures to include new variables
3. Ensure test isolation
4. Add proper test teardown

---

### 11. Fix Cache Stats Iteration Issues

**Issue**: Tests treating CacheStats object as iterable
**Error Messages**:
```
TypeError: argument of type 'CacheStats' is not iterable
```

**Root Cause**: CacheStats is a data class, not iterable

**Files Affected**:
- `tests/cache/test_cache_manager.py`

**Fix Strategy**:
1. Access CacheStats properties directly instead of iterating
2. Update test assertions to use proper object access
3. Fix any code that expects CacheStats to be iterable

**Correct Usage**:
```python
assert stats.hit_count > 0  # Not: assert 'hit_count' in stats
```

---

### 12. Fix Container Dependency Injection Issues

**Issue**: Missing interface registrations in container tests
**Error Messages**:
```
ValueError: Service adversary_mcp_server.interfaces.scanner.ILLMScanner | None is not registered
```

**Root Cause**: Container tests not registering all required interfaces

**Files Affected**:
- `tests/test_container.py`
- Container integration tests

**Fix Strategy**:
1. Register all required interfaces in test setup
2. Use mock implementations for testing
3. Ensure proper dependency injection chains
4. Add container validation tests

---

## **PRIORITY 4: METRICS & DASHBOARD RESTORATION** 📊

### 13. Restore LLM Token & Cost Metrics

**Issue**: Dashboard showing "N/AB" for database size and missing LLM metrics
**Root Cause**: Token usage and cost estimation metrics lost during refactoring

**Missing Metrics**:
- Token usage per scan
- Estimated API costs
- Token efficiency metrics
- Cost per finding ratios

**Implementation Requirements**:
1. Re-implement token estimation in LLM scanner
2. Add cost calculation based on model pricing
3. Store token/cost data in telemetry database
4. Update dashboard queries to include token/cost data
5. Add token/cost data to CLI output

**Files to Update**:
- `src/adversary_mcp_server/llm/llm_scanner.py`
- `src/adversary_mcp_server/telemetry/service.py`
- `src/adversary_mcp_server/dashboard/html_dashboard.py`
- `src/adversary_mcp_server/cli.py`

---

### 14. Fix Dashboard Data Population

**Issue**: Dashboard sections showing empty or "N/A" values

**Specific Problems**:
- Database Size: Shows "N/AB" instead of actual size
- System metrics: Empty sections
- Language performance: No data
- Threat categories: Empty

**Root Cause**: Dashboard queries not matching telemetry database schema

**Fix Strategy**:
1. Debug dashboard data retrieval methods
2. Verify telemetry database contains expected data
3. Update SQL queries to match current schema
4. Add fallback values for missing data
5. Implement proper error handling

---

### 15. Update Report Metrics System

**Issue**: .adversary.json and .adversary.md reports still using old metrics

**Files Affected**:
- JSON report generation
- Markdown report generation
- Result formatter classes

**Required Updates**:
1. Update report generators to query new telemetry system
2. Include token usage and cost data in reports
3. Add performance metrics to reports
4. Maintain backward compatibility
5. Update report schemas

---

## **PRIORITY 5: CODE QUALITY & ORGANIZATION** 🧹

### 16. Move Inline Imports to Top

**Issue**: 19 files have imports within functions/methods

**Files with Inline Imports**:
```
src/adversary_mcp_server/database/models.py
src/adversary_mcp_server/server.py
src/adversary_mcp_server/llm/llm_client.py
src/adversary_mcp_server/cache/config_tracker.py
src/adversary_mcp_server/cache/content_hasher.py
src/adversary_mcp_server/__init__.py
src/adversary_mcp_server/dashboard/html_dashboard.py
src/adversary_mcp_server/cli.py
src/adversary_mcp_server/resilience/retry_manager.py
src/adversary_mcp_server/batch/batch_processor.py
src/adversary_mcp_server/monitoring/performance_monitor.py
src/adversary_mcp_server/monitoring/unified_dashboard.py
src/adversary_mcp_server/scanner/diff_scanner.py
src/adversary_mcp_server/scanner/streaming_utils.py
src/adversary_mcp_server/scanner/semgrep_scanner.py
src/adversary_mcp_server/scanner/scan_engine.py
src/adversary_mcp_server/scanner/file_filter.py
src/adversary_mcp_server/scanner/llm_scanner.py
src/adversary_mcp_server/migration/database_migration.py
```

**Fix Strategy**:
1. Move all imports to top of each file
2. Organize imports: stdlib, third-party, local
3. Remove duplicate imports
4. Use TYPE_CHECKING for type-only imports
5. Update import order per PEP 8

---

### 17. Fix CLI Command Assertions

**Issue**: CLI tests failing due to output format mismatches
**Error Messages**:
```
assert 1 == 0
AssertionError: Expected 'export_dashboard_report' to have been called.
```

**Root Cause**: CLI command output format changed but tests not updated

**Fix Strategy**:
1. Update test expectations to match current CLI output
2. Use more flexible assertion patterns
3. Mock external dependencies properly
4. Add proper test isolation

---

### 18. Fix Missing Import Errors

**Issue**: Classes cannot be imported
**Error Messages**:
```
ImportError: cannot import name 'ApplicationBootstrap'
ImportError: cannot import name 'Container'
```

**Root Cause**: Classes moved or renamed during refactoring

**Fix Strategy**:
1. Locate moved/renamed classes
2. Update import statements
3. Add proper __init__.py exports
4. Ensure backward compatibility aliases

---

### 19. Improve Test Coverage

**Issue**: Coverage at 74.42%, need 75%+

**Strategy**:
1. Identify uncovered code paths
2. Add targeted tests for critical functions
3. Improve integration test coverage
4. Add edge case testing

---

## **IMPLEMENTATION TIMELINE** 📅

### Phase 1: Critical System Recovery (Days 1-2)
- Fix scan engine architecture breaks (Items 1-4)
- Restore basic scanning functionality
- Verify core features work

### Phase 2: Type System Stabilization (Day 3)
- Fix all MyPy errors (Items 5-8)
- Ensure proper type checking
- Update type annotations

### Phase 3: Test Infrastructure (Day 4)
- Fix failing tests (Items 9-12)
- Restore test reliability
- Achieve stable test baseline

### Phase 4: Feature Restoration (Day 5)
- Restore metrics and dashboard features (Items 13-15)
- Re-implement missing functionality
- Validate data accuracy

### Phase 5: Code Quality (Day 6)
- Code organization improvements (Items 16-19)
- Final cleanup and optimization
- Documentation updates

---

## **VALIDATION CRITERIA** ✅

### Success Metrics
- [ ] All 64 failing tests pass
- [ ] MyPy reports 0 errors
- [ ] Test coverage ≥ 75%
- [ ] Dashboard shows real data (no "N/A" or "N/AB")
- [ ] LLM token/cost metrics restored
- [ ] All imports at file top
- [ ] Reports use new metrics system

### Quality Checks
- [ ] No inline imports remain
- [ ] All method signatures match interfaces
- [ ] Security tests use proper mocking
- [ ] Container tests register all dependencies
- [ ] Dashboard queries return expected data
- [ ] CLI commands produce expected output

---

## **RISK MITIGATION** ⚠️

### High-Risk Changes
1. **Scan Engine Architecture**: Core functionality changes
2. **Database Schema**: Potential data migration needs
3. **API Interfaces**: Breaking changes to public APIs

### Mitigation Strategies
1. **Incremental Testing**: Test each change in isolation
2. **Backup Strategy**: Create restore points before major changes
3. **Rollback Plan**: Maintain ability to revert critical changes
4. **Integration Testing**: Verify end-to-end functionality

---

## **NOTES FOR CONTINUATION** 📝

### Context Preservation
- This plan addresses issues discovered on August 10, 2025
- Based on scan failures from logs showing OptimizedSemgrepScanner errors
- Dashboard HTML showing "N/AB" values indicates metrics system disconnect
- 64 test failures indicate systematic architectural issues

### Key Log Evidence
```
Semgrep scan failed: OptimizedSemgrepScanner.scan_file() missing 1 required positional argument: 'language'
'ScanEngine' object has no attribute 'apply_severity_filter'
'ScanEngine' object has no attribute 'result_builder'
```

### Critical Dependencies
- Phase II coordination components must be properly integrated
- Phase III security validation must work with file system
- New telemetry system must feed dashboard and reports
- All interfaces must match between production and test code

This plan provides the roadmap for restoring full system functionality while maintaining production quality standards.
