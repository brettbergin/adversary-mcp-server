"""Metrics collection orchestration with decorators and context managers."""

import hashlib
import time
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Any

import psutil

from adversary_mcp_server.application.adapters.input_models import (
    TelemetryInput,
    safe_convert_to_input_model,
)

from .service import TelemetryService


class MetricsCollectionOrchestrator:
    """Orchestrates all metrics collection across the entire system."""

    def __init__(self, telemetry_service: TelemetryService):
        self.telemetry = telemetry_service
        self.system_health_interval = 300  # 5 minutes
        self._last_health_check = 0

    # === MCP TOOL INTEGRATION ===

    def mcp_tool_wrapper(self, tool_name: str):
        """Decorator to automatically track MCP tool executions."""

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
                            "args": str(args)[:500],  # Truncate for storage
                            "kwargs": {k: str(v)[:100] for k, v in kwargs.items()},
                        },
                        validation_enabled=kwargs.get("use_validation", False),
                        llm_enabled=kwargs.get("use_llm", False),
                    )
                    # Try to get ID, use cached version if object is detached
                    try:
                        execution_id = execution.id
                    except Exception:
                        # If object is detached, use cached ID
                        execution_id = getattr(execution, "_cached_id", None)
                        if execution_id is None:
                            raise RuntimeError(
                                "Unable to get execution ID from telemetry tracking"
                            )

                    # Create telemetry context for the tool to use
                    telemetry_context = MCPToolTelemetryContext(
                        execution_id, self.telemetry
                    )

                    # Add telemetry context to the arguments dict for MCP server methods
                    if args and isinstance(args[0], dict):
                        # If first argument is arguments dict, add telemetry context to it
                        args[0]["_telemetry_context"] = telemetry_context
                    else:
                        # Otherwise add it as a keyword argument
                        kwargs["_telemetry_context"] = telemetry_context

                    # Execute the actual tool
                    result = await func(*args, **kwargs)

                    # Use findings count from telemetry context if provided, otherwise extract from result
                    findings_count = telemetry_context.findings_count
                    if findings_count == 0:
                        # Fallback to old extraction logic for backwards compatibility
                        if hasattr(result, "findings") and result.findings:
                            findings_count = len(result.findings)
                        elif isinstance(result, dict) and "findings" in result:
                            findings_count = len(result["findings"])

                    # Complete tracking
                    self.telemetry.complete_mcp_tool_tracking(
                        execution_id=execution_id,
                        success=True,
                        findings_count=findings_count,
                    )

                    return result

                except Exception as e:
                    # Track failure
                    if execution_id:
                        self.telemetry.complete_mcp_tool_tracking(
                            execution_id=execution_id,
                            success=False,
                            error_message=str(e)[:500],
                        )
                    raise
                finally:
                    # Opportunistic health check
                    self._maybe_record_health()

            return wrapper

        return decorator

    # === CLI COMMAND INTEGRATION ===

    def cli_command_wrapper(self, command_name: str):
        """Decorator to automatically track CLI command executions."""

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Start tracking
                execution_id = None
                try:
                    execution = self.telemetry.start_cli_command_tracking(
                        command_name=command_name,
                        args={
                            "args": str(args)[:500],
                            "kwargs": {k: str(v)[:100] for k, v in kwargs.items()},
                        },
                        subcommand=kwargs.get("path") or kwargs.get("file_path"),
                        validation_enabled=kwargs.get("use_validation", False),
                    )
                    # Try to get ID, use cached version if object is detached
                    try:
                        execution_id = execution.id
                    except Exception:
                        # If object is detached, use cached ID
                        execution_id = getattr(execution, "_cached_id", None)
                        if execution_id is None:
                            raise RuntimeError(
                                "Unable to get execution ID from CLI tracking"
                            )

                    # Execute command
                    result = func(*args, **kwargs)

                    # Determine exit code
                    exit_code = 0
                    if isinstance(result, int):
                        exit_code = result
                    elif hasattr(result, "returncode"):
                        exit_code = result.returncode

                    # Complete tracking
                    self.telemetry.complete_cli_command_tracking(
                        execution_id=execution_id,
                        exit_code=exit_code,
                        findings_count=getattr(result, "findings_count", 0),
                    )

                    return result

                except Exception as e:
                    # Track failure
                    if execution_id:
                        self.telemetry.complete_cli_command_tracking(
                            execution_id=execution_id, exit_code=1
                        )
                    raise
                finally:
                    self._maybe_record_health()

            return wrapper

        return decorator

    # === SCAN ENGINE INTEGRATION ===

    @contextmanager
    def track_scan_execution(
        self, trigger_source: str, scan_type: str, target_path: str, **kwargs
    ):
        """Context manager for comprehensive scan tracking."""
        scan_id = str(uuid.uuid4())
        start_time = time.time()

        # Initialize tracking
        execution = self.telemetry.start_scan_tracking(
            scan_id=scan_id,
            trigger_source=trigger_source,
            scan_type=scan_type,
            target_path=target_path,
            **kwargs,
        )

        # Yield scan context with timing utilities
        scan_context = ScanTrackingContext(scan_id, start_time, self.telemetry)

        try:
            yield scan_context

            # Complete successful scan atomically with threat findings and validation results
            self.telemetry.record_scan_results_atomic(
                scan_id=scan_id,
                threat_findings=scan_context._pending_threat_data,
                scan_success=True,
                validation_results=scan_context._validation_results,
                total_duration_ms=scan_context.get_total_duration(),
                semgrep_duration_ms=scan_context.semgrep_duration,
                llm_duration_ms=scan_context.llm_duration,
                validation_duration_ms=scan_context.validation_duration,
                cache_lookup_ms=scan_context.cache_lookup_duration,
                threats_validated=scan_context.threats_validated,
                false_positives_filtered=scan_context.false_positives_filtered,
                cache_hit=scan_context.cache_hit,
            )

        except Exception as e:
            # Complete failed scan atomically (but still record any collected threat findings)
            self.telemetry.record_scan_results_atomic(
                scan_id=scan_id,
                threat_findings=scan_context._pending_threat_data,
                scan_success=False,
                validation_results=scan_context._validation_results,
                error_message=str(e)[:500],
                total_duration_ms=scan_context.get_total_duration(),
            )
            raise
        finally:
            self._maybe_record_health()

    # === CACHE OPERATION INTEGRATION ===

    def track_cache_operation(
        self, operation_type: str, cache_name: str, key: str, **kwargs
    ):
        """Track individual cache operations."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]  # Shortened hash

        # Extract metadata from key for better analytics
        key_metadata = self._extract_key_metadata(key, cache_name)

        return self.telemetry.track_cache_operation(
            operation_type=operation_type,
            cache_name=cache_name,
            key_hash=key_hash,
            key_metadata=key_metadata,
            **kwargs,
        )

    def _extract_key_metadata(self, key: str, cache_name: str) -> dict[str, str]:
        """Extract useful metadata from cache key for analytics."""
        metadata = {}

        # Extract file extension if present
        if "." in key:
            ext = key.split(".")[-1]
            if len(ext) <= 10:  # Reasonable extension length
                metadata["file_extension"] = ext

        # Extract cache type hints
        if "semgrep" in cache_name.lower():
            metadata["cache_type"] = "semgrep"
        elif "llm" in cache_name.lower():
            metadata["cache_type"] = "llm"
        elif "validation" in cache_name.lower():
            metadata["cache_type"] = "validation"

        # Extract approximate file size hint from key if encoded
        if ":" in key and cache_name in ["scan_results", "file_cache"]:
            parts = key.split(":")
            for part in parts:
                if part.isdigit():
                    metadata["approx_size"] = part[:10]  # Limit size
                    break

        return metadata

    # === THREAT FINDINGS INTEGRATION ===

    def record_threat_finding_with_context(
        self, scan_id: str, threat_finding: Any, scanner_source: str
    ):
        """Record threat finding with comprehensive context."""
        finding_uuid = str(uuid.uuid4())

        # Convert threat finding to type-safe input model
        safe_finding = safe_convert_to_input_model(threat_finding, TelemetryInput)

        return self.telemetry.record_threat_finding(
            scan_id=scan_id,
            finding_uuid=finding_uuid,
            scanner_source=scanner_source,
            category=safe_finding.category,
            severity=safe_finding.severity,
            file_path=safe_finding.file_path,
            line_start=safe_finding.line_start,
            line_end=safe_finding.line_end,
            title=safe_finding.title,
            rule_id=safe_finding.rule_id,
            confidence=safe_finding.confidence,
            column_start=safe_finding.column_start,
            column_end=safe_finding.column_end,
            code_snippet=safe_finding.code_snippet,
            description=safe_finding.description,
            remediation=safe_finding.remediation,
            references=safe_finding.references,
            is_validated=safe_finding.is_validated,
            is_false_positive=safe_finding.is_false_positive,
            validation_reason=safe_finding.validation_reason,
        )

    # === SYSTEM HEALTH MONITORING ===

    def _maybe_record_health(self):
        """Opportunistically record system health if interval elapsed."""
        current_time = time.time()
        if current_time - self._last_health_check >= self.system_health_interval:
            self._record_system_health()
            self._last_health_check = current_time

    def _record_system_health(self):
        """Record comprehensive system health snapshot."""
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
                total_size = sum(
                    f.stat().st_size for f in cache_dir.glob("**/*") if f.is_file()
                )
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
                **recent_stats,
            )

        except Exception as e:
            # Don't fail the main operation if health recording fails
            print(f"Warning: Failed to record system health: {e}")

    def _calculate_recent_performance(self) -> dict[str, float]:
        """Calculate recent performance metrics for health snapshot."""
        try:
            # Get data from last hour
            data = self.telemetry.get_dashboard_data(hours=1)

            return {
                "cache_hit_rate_1h": data["scan_engine"].get("cache_hit_rate", 0),
                "avg_scan_duration_1h": data["scan_engine"].get(
                    "avg_total_duration_ms", 0
                ),
                "scans_per_hour": data["scan_engine"].get("total_scans", 0),
                "error_rate_1h": self._calculate_error_rate(data),
            }
        except Exception:
            return {}

    def _calculate_error_rate(self, data: dict[str, Any]) -> float:
        """Calculate error rate from dashboard data."""
        try:
            mcp_tools = data.get("mcp_tools", [])
            cli_commands = data.get("cli_commands", [])

            total_operations = 0
            failed_operations = 0

            for tool in mcp_tools:
                executions = tool.get("executions", 0)
                success_rate = tool.get("success_rate", 1.0)
                total_operations += executions
                failed_operations += executions * (1 - success_rate)

            for cmd in cli_commands:
                executions = cmd.get("executions", 0)
                success_rate = cmd.get("success_rate", 1.0)
                total_operations += executions
                failed_operations += executions * (1 - success_rate)

            return failed_operations / max(total_operations, 1)
        except Exception:
            return 0.0


class ScanTrackingContext:
    """Context object for tracking scan execution details."""

    def __init__(self, scan_id: str, start_time: float, telemetry_service):
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
        self._pending_threat_data = []  # Store threat data for atomic recording
        self._validation_results = {}  # Store validation results for later application

    def time_semgrep_scan(self):
        """Context manager for timing Semgrep operations."""
        return self._time_operation("semgrep_duration")

    def time_llm_analysis(self):
        """Context manager for timing LLM operations."""
        return self._time_operation("llm_duration")

    def time_validation(self):
        """Context manager for timing validation operations."""
        return self._time_operation("validation_duration")

    def time_cache_lookup(self):
        """Context manager for timing cache operations."""
        return self._time_operation("cache_lookup_duration")

    @contextmanager
    def _time_operation(self, duration_attr: str):
        """Generic timing context manager."""
        start = time.time()
        try:
            yield
        finally:
            duration_ms = (time.time() - start) * 1000
            setattr(self, duration_attr, duration_ms)

    def add_threat_finding(self, finding: Any, scanner_source: str):
        """Add a threat finding to this scan for atomic recording later."""
        import uuid

        # Generate UUID for the finding
        finding_uuid = str(uuid.uuid4())

        # Collect threat data for atomic recording when scan completes
        threat_data = {
            "finding_uuid": finding_uuid,
            "scanner_source": scanner_source,
            "category": getattr(finding, "category", "unknown"),
            "severity": getattr(finding, "severity", "medium"),
            "file_path": getattr(finding, "file_path", ""),
            "line_start": getattr(finding, "line_start", 0),
            "line_end": getattr(finding, "line_end", 0),
            "title": getattr(finding, "title", "Security Finding"),
            "rule_id": getattr(finding, "rule_id", None),
            "confidence": getattr(finding, "confidence", None),
            "column_start": getattr(finding, "column_start", None),
            "column_end": getattr(finding, "column_end", None),
            "code_snippet": getattr(finding, "code_snippet", None),
            "description": getattr(finding, "description", None),
            "remediation": getattr(finding, "remediation", None),
            "references": getattr(finding, "references", None),
            "is_validated": getattr(finding, "is_validated", False),
            "is_false_positive": getattr(finding, "is_false_positive", False),
            "validation_reason": getattr(finding, "validation_reason", None),
        }

        self._pending_threat_data.append(threat_data)
        self.threats_found += 1

        # Track validation status
        if getattr(finding, "is_validated", False):
            self.threats_validated += 1
        if getattr(finding, "is_false_positive", False):
            self.false_positives_filtered += 1

    def mark_cache_hit(self):
        """Mark this scan as a cache hit."""
        self.cache_hit = True

    def set_validation_results(self, validation_results: dict):
        """Store validation results for applying to threat findings."""
        self._validation_results = validation_results

    def get_total_duration(self) -> float:
        """Get total scan duration in milliseconds."""
        return (time.time() - self.start_time) * 1000


# === INTEGRATION POINTS ===


class MCPToolTelemetryContext:
    """Context object for MCP tools to report telemetry data."""

    def __init__(self, execution_id: int, telemetry_service):
        self.execution_id = execution_id
        self.telemetry = telemetry_service
        self.findings_count = 0

    def report_findings_count(self, count: int):
        """Report the number of findings discovered by the tool."""
        self.findings_count = count


class MetricsIntegrationMixin:
    """Mixin to add metrics collection to existing classes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initialize metrics orchestrator
        self.metrics_orchestrator = self._get_metrics_orchestrator()

    def _get_metrics_orchestrator(self) -> MetricsCollectionOrchestrator:
        """Get or create metrics orchestrator instance."""
        # This would be injected via dependency injection in real implementation
        from ..database.models import AdversaryDatabase
        from .service import TelemetryService

        db = AdversaryDatabase()
        telemetry = TelemetryService(db)
        return MetricsCollectionOrchestrator(telemetry)
