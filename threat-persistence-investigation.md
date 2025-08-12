# Threat Persistence Investigation

## Problem Statement

The `threat_findings` table in `adversary.db` remains empty after running MCP tools or CLI scans, despite threats being detected during scans. The database schema exists and all infrastructure is in place, but individual threat findings are not being persisted to the database.

## Investigation Summary

### Database Schema ✅ CORRECT
- `ThreatFinding` model properly defined in `src/adversary_mcp_server/database/models.py:194-250`
- Complete schema with all necessary fields: scan_id, finding_uuid, scanner_source, category, severity, etc.
- Proper relationships and indexes configured
- Foreign key relationship to `ScanEngineExecution` table

### Repository Layer ✅ CORRECT
- `ComprehensiveTelemetryRepository.record_threat_finding()` method exists in `src/adversary_mcp_server/telemetry/repository.py:182-223`
- Method correctly creates `ThreatFinding` records and commits to database
- Comprehensive parameter handling with proper validation

### Telemetry Integration ✅ CORRECT
- `MetricsCollectionOrchestrator.record_threat_finding_with_context()` method exists in `src/adversary_mcp_server/telemetry/integration.py:242-270`
- `ScanTrackingContext.add_threat_finding()` method exists in `src/adversary_mcp_server/telemetry/integration.py:410-426`
- Both methods properly handle threat recording and call repository layer

### Root Cause ❌ MISSING INTEGRATION

**The scan engine never calls the threat recording methods.** While all infrastructure exists, the scan methods in `ScanEngine` don't actually persist individual threats.

#### Analysis of ScanEngine (`src/adversary_mcp_server/scanner/scan_engine.py`)

**What Works:**
- Scan execution metadata IS recorded (scan start/end, durations, summary stats)
- Context managers properly track scan execution with `MetricsCollectionOrchestrator.track_scan_execution()`
- `ScanTrackingContext` is available in all scan methods

**What's Missing:**
- No calls to `scan_context.add_threat_finding()` in any scan method
- Individual threat findings from SemgrepScanner and LLMScanner are never persisted
- Methods iterate through findings but only count them, don't record them

## Implementation Plan

### 1. File Scanning (`_scan_file_with_context` method)
Add threat recording after each scanner execution:

```python
# After Semgrep scan
for finding in semgrep_results.findings:
    scan_context.add_threat_finding(finding, "semgrep")

# After LLM scan
for finding in llm_results.findings:
    scan_context.add_threat_finding(finding, "llm")
```

### 2. Directory Scanning (`scan_directory` method)
Add threat recording in directory scan loop:

```python
# For each file's results
for finding in file_results.findings:
    scan_context.add_threat_finding(finding, finding.scanner_source or "unknown")
```

### 3. Code Scanning (`scan_code` method)
Add threat recording similar to file scanning:

```python
# After each scanner execution
for finding in results.findings:
    scan_context.add_threat_finding(finding, scanner_type)
```

### 4. Validation Integration
Ensure validated findings are properly marked:

```python
# After validation
if validated_finding.confidence >= threshold:
    scan_context.add_threat_finding(validated_finding, original_scanner)
```

## Expected Outcome

After implementation:
1. `threat_findings` table will populate with individual findings from each scan
2. Each finding will include full context: file location, severity, category, scanner source
3. Validation results will be properly tracked with confidence scores
4. Dashboard analytics will show detailed threat breakdowns by category and severity
5. Historical threat trend analysis will be available

## Files to Modify

- `src/adversary_mcp_server/scanner/scan_engine.py` - Add threat recording calls in all scan methods
- Tests may need updates to verify threat persistence functionality

## Verification Steps

1. Run any scan operation (MCP tool or CLI)
2. Check `adversary.db` - `threat_findings` table should contain records
3. Verify threat details match scanner outputs
4. Confirm validation status is properly tracked
5. Test dashboard analytics show threat category breakdowns
