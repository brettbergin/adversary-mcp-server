"""Comprehensive repository for all telemetry data with rich query methods."""

import time
from typing import Any

from sqlalchemy import and_, case, func
from sqlalchemy.orm import Session

from ..database.models import (
    CacheOperationMetric,
    CLICommandExecution,
    MCPToolExecution,
    ScanEngineExecution,
    SystemHealth,
    ThreatFinding,
)


class ComprehensiveTelemetryRepository:
    """Comprehensive repository for all telemetry data with rich query methods."""

    def __init__(self, session: Session):
        self.session = session
        self._auto_commit = True  # Default to auto-commit for backward compatibility

    def _maybe_commit(self):
        """Commit the session if auto-commit is enabled."""
        if self._auto_commit:
            self.session.commit()

    # === MCP TOOL TRACKING ===

    def track_mcp_tool_execution(
        self, tool_name: str, session_id: str, request_params: dict, **kwargs
    ) -> MCPToolExecution:
        """Track MCP tool execution start."""
        execution = MCPToolExecution(
            tool_name=tool_name,
            session_id=session_id,
            request_params=request_params,
            execution_start=time.time(),
            validation_enabled=kwargs.get("validation_enabled", False),
            llm_enabled=kwargs.get("llm_enabled", False),
        )
        self.session.add(execution)
        self.session.flush()  # Ensure object is in DB before refresh
        self.session.refresh(execution)
        self._maybe_commit()

        # Create a new detached object with the same data to avoid DetachedInstanceError
        detached_execution = MCPToolExecution(
            tool_name=execution.tool_name,
            session_id=execution.session_id,
            request_params=execution.request_params,
            execution_start=execution.execution_start,
            validation_enabled=execution.validation_enabled,
            llm_enabled=execution.llm_enabled,
            execution_end=execution.execution_end,
            success=execution.success,
            findings_count=execution.findings_count,
            error_message=execution.error_message,
        )
        detached_execution.id = execution.id
        detached_execution.created_at = execution.created_at

        return detached_execution

    def complete_mcp_tool_execution(
        self,
        execution_id: int,
        success: bool = True,
        findings_count: int = 0,
        error_message: str = None,
    ):
        """Complete MCP tool execution tracking."""
        execution = (
            self.session.query(MCPToolExecution).filter_by(id=execution_id).first()
        )
        if execution:
            execution.execution_end = time.time()
            execution.success = success
            execution.findings_count = findings_count
            execution.error_message = error_message
            self._maybe_commit()

    # === CLI COMMAND TRACKING ===

    def track_cli_command_execution(
        self, command_name: str, args: dict, subcommand: str = None, **kwargs
    ) -> CLICommandExecution:
        """Track CLI command execution."""
        execution = CLICommandExecution(
            command_name=command_name,
            subcommand=subcommand,
            args=args,
            execution_start=time.time(),
            validation_enabled=kwargs.get("validation_enabled", False),
        )
        self.session.add(execution)
        self.session.flush()  # Ensure object is in DB before refresh
        self.session.refresh(execution)
        self._maybe_commit()

        # Create a new detached object with the same data to avoid DetachedInstanceError
        detached_execution = CLICommandExecution(
            command_name=execution.command_name,
            subcommand=execution.subcommand,
            args=execution.args,
            execution_start=execution.execution_start,
            validation_enabled=execution.validation_enabled,
            execution_end=execution.execution_end,
            exit_code=execution.exit_code,
            stdout_lines=execution.stdout_lines,
            stderr_lines=execution.stderr_lines,
            findings_count=execution.findings_count,
        )
        detached_execution.id = execution.id
        detached_execution.created_at = execution.created_at

        return detached_execution

    def complete_cli_command_execution(
        self,
        execution_id: int,
        exit_code: int = 0,
        stdout_lines: int = 0,
        stderr_lines: int = 0,
        findings_count: int = 0,
    ):
        """Complete CLI command execution tracking."""
        execution = (
            self.session.query(CLICommandExecution).filter_by(id=execution_id).first()
        )
        if execution:
            execution.execution_end = time.time()
            execution.exit_code = exit_code
            execution.stdout_lines = stdout_lines
            execution.stderr_lines = stderr_lines
            execution.findings_count = findings_count
            self._maybe_commit()

    # === CACHE OPERATIONS ===

    def track_cache_operation(
        self,
        operation_type: str,
        cache_name: str,
        key_hash: str,
        key_metadata: dict = None,
        size_bytes: int = None,
        access_time_ms: float = None,
        **kwargs,
    ) -> CacheOperationMetric:
        """Track cache operation."""
        metric = CacheOperationMetric(
            operation_type=operation_type,
            cache_name=cache_name,
            key_hash=key_hash,
            key_metadata=key_metadata,
            size_bytes=size_bytes,
            access_time_ms=access_time_ms,
            ttl_seconds=kwargs.get("ttl_seconds"),
            eviction_reason=kwargs.get("eviction_reason"),
            timestamp=time.time(),
        )
        self.session.add(metric)
        self.session.flush()  # Ensure object is in DB before refresh
        self.session.refresh(metric)
        self._maybe_commit()

        # Create a new detached object with the same data to avoid DetachedInstanceError
        detached_metric = CacheOperationMetric(
            operation_type=metric.operation_type,
            cache_name=metric.cache_name,
            key_hash=metric.key_hash,
            key_metadata=metric.key_metadata,
            size_bytes=metric.size_bytes,
            access_time_ms=metric.access_time_ms,
            ttl_seconds=metric.ttl_seconds,
            eviction_reason=metric.eviction_reason,
            timestamp=metric.timestamp,
        )
        detached_metric.id = metric.id
        detached_metric.created_at = metric.created_at

        return detached_metric

    # === SCAN ENGINE TRACKING ===

    def track_scan_execution(
        self,
        scan_id: str,
        trigger_source: str,
        scan_type: str,
        target_path: str,
        **kwargs,
    ) -> ScanEngineExecution:
        """Track scan engine execution start."""
        execution = ScanEngineExecution(
            scan_id=scan_id,
            trigger_source=trigger_source,
            scan_type=scan_type,
            target_path=target_path,
            file_count=kwargs.get("file_count", 1),
            language_detected=kwargs.get("language_detected"),
            file_size_bytes=kwargs.get("file_size_bytes"),
            semgrep_enabled=kwargs.get("semgrep_enabled", True),
            llm_enabled=kwargs.get("llm_enabled", False),
            validation_enabled=kwargs.get("validation_enabled", False),
            execution_start=time.time(),
        )
        self.session.add(execution)
        self.session.flush()  # Ensure object is in DB before refresh
        self.session.refresh(execution)
        self._maybe_commit()

        # Create a new detached object with the same data to avoid DetachedInstanceError
        detached_execution = ScanEngineExecution(
            scan_id=execution.scan_id,
            trigger_source=execution.trigger_source,
            scan_type=execution.scan_type,
            target_path=execution.target_path,
            file_count=execution.file_count,
            language_detected=execution.language_detected,
            file_size_bytes=execution.file_size_bytes,
            semgrep_enabled=execution.semgrep_enabled,
            llm_enabled=execution.llm_enabled,
            validation_enabled=execution.validation_enabled,
            execution_start=execution.execution_start,
            execution_end=execution.execution_end,
            total_duration_ms=execution.total_duration_ms,
            semgrep_duration_ms=execution.semgrep_duration_ms,
            llm_duration_ms=execution.llm_duration_ms,
            validation_duration_ms=execution.validation_duration_ms,
            cache_lookup_ms=execution.cache_lookup_ms,
            threats_found=execution.threats_found,
            threats_validated=execution.threats_validated,
            false_positives_filtered=execution.false_positives_filtered,
            cache_hit=execution.cache_hit,
            success=execution.success,
            error_message=execution.error_message,
        )
        detached_execution.id = execution.id
        detached_execution.created_at = execution.created_at

        return detached_execution

    def complete_scan_execution(self, scan_id: str, success: bool = True, **kwargs):
        """Complete scan execution with results."""
        execution = (
            self.session.query(ScanEngineExecution).filter_by(scan_id=scan_id).first()
        )
        if execution:
            execution.execution_end = time.time()
            execution.total_duration_ms = kwargs.get("total_duration_ms")
            execution.semgrep_duration_ms = kwargs.get("semgrep_duration_ms")
            execution.llm_duration_ms = kwargs.get("llm_duration_ms")
            execution.validation_duration_ms = kwargs.get("validation_duration_ms")
            execution.cache_lookup_ms = kwargs.get("cache_lookup_ms")
            execution.threats_found = kwargs.get("threats_found", 0)
            execution.threats_validated = kwargs.get("threats_validated", 0)
            execution.false_positives_filtered = kwargs.get(
                "false_positives_filtered", 0
            )
            execution.cache_hit = kwargs.get("cache_hit", False)
            execution.success = success
            execution.error_message = kwargs.get("error_message")
            self._maybe_commit()

    # === THREAT FINDINGS ===

    def record_threat_finding(
        self,
        scan_id: str,
        finding_uuid: str,
        scanner_source: str,
        category: str,
        severity: str,
        file_path: str,
        line_start: int,
        line_end: int,
        title: str,
        **kwargs,
    ) -> ThreatFinding:
        """Record a threat finding."""
        finding = ThreatFinding(
            scan_id=scan_id,
            finding_uuid=finding_uuid,
            scanner_source=scanner_source,
            rule_id=kwargs.get("rule_id"),
            category=category,
            severity=severity,
            confidence=kwargs.get("confidence"),
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            column_start=kwargs.get("column_start"),
            column_end=kwargs.get("column_end"),
            code_snippet=kwargs.get("code_snippet"),
            title=title,
            description=kwargs.get("description"),
            remediation=kwargs.get("remediation"),
            references=kwargs.get("references"),
            is_validated=kwargs.get("is_validated", False),
            is_false_positive=kwargs.get("is_false_positive", False),
            validation_reason=kwargs.get("validation_reason"),
            marked_by=kwargs.get("marked_by"),
            timestamp=time.time(),
        )
        self.session.add(finding)
        self.session.flush()  # Ensure object is in DB before refresh
        self.session.refresh(finding)
        self._maybe_commit()

        # Create a new detached object with the same data to avoid DetachedInstanceError
        detached_finding = ThreatFinding(
            scan_id=finding.scan_id,
            finding_uuid=finding.finding_uuid,
            scanner_source=finding.scanner_source,
            rule_id=finding.rule_id,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            column_start=finding.column_start,
            column_end=finding.column_end,
            code_snippet=finding.code_snippet,
            title=finding.title,
            description=finding.description,
            remediation=finding.remediation,
            references=finding.references,
            is_validated=finding.is_validated,
            is_false_positive=finding.is_false_positive,
            validation_reason=finding.validation_reason,
            marked_by=finding.marked_by,
            timestamp=finding.timestamp,
        )
        detached_finding.id = finding.id
        detached_finding.created_at = finding.created_at

        return detached_finding

    def update_threat_finding_validation(
        self,
        finding_uuid: str,
        is_validated: bool,
        validation_confidence: float | None,
        validation_reasoning: str | None,
        is_false_positive: bool | None = None,
        validation_reason: str | None = None,
        exploitation_vector: str | None = None,
    ):
        """Update threat finding with validation results."""
        finding = (
            self.session.query(ThreatFinding)
            .filter_by(finding_uuid=finding_uuid)
            .first()
        )
        if finding:
            finding.is_validated = is_validated
            finding.validation_confidence = validation_confidence
            finding.validation_reasoning = validation_reasoning
            if is_false_positive is not None:
                finding.is_false_positive = is_false_positive
            if validation_reason is not None:
                finding.validation_reason = validation_reason
            # Note: exploitation_vector could be added to ThreatFinding model if needed
            self._maybe_commit()
            return finding
        return None

    # === SYSTEM HEALTH ===

    def record_system_health_snapshot(self, **metrics) -> SystemHealth:
        """Record system health metrics snapshot."""
        health = SystemHealth(
            timestamp=time.time(),
            cpu_percent=metrics.get("cpu_percent"),
            memory_percent=metrics.get("memory_percent"),
            memory_used_mb=metrics.get("memory_used_mb"),
            disk_usage_percent=metrics.get("disk_usage_percent"),
            db_size_mb=metrics.get("db_size_mb"),
            db_connections=metrics.get("db_connections"),
            cache_size_mb=metrics.get("cache_size_mb"),
            cache_hit_rate_1h=metrics.get("cache_hit_rate_1h"),
            cache_entries_count=metrics.get("cache_entries_count"),
            avg_scan_duration_1h=metrics.get("avg_scan_duration_1h"),
            scans_per_hour=metrics.get("scans_per_hour"),
            error_rate_1h=metrics.get("error_rate_1h"),
        )
        self.session.add(health)
        self.session.flush()  # Ensure object is in DB before refresh
        self.session.refresh(health)
        self._maybe_commit()

        # Create a new detached object with the same data to avoid DetachedInstanceError
        detached_health = SystemHealth(
            timestamp=health.timestamp,
            cpu_percent=health.cpu_percent,
            memory_percent=health.memory_percent,
            memory_used_mb=health.memory_used_mb,
            disk_usage_percent=health.disk_usage_percent,
            db_size_mb=health.db_size_mb,
            db_connections=health.db_connections,
            cache_size_mb=health.cache_size_mb,
            cache_hit_rate_1h=health.cache_hit_rate_1h,
            cache_entries_count=health.cache_entries_count,
            avg_scan_duration_1h=health.avg_scan_duration_1h,
            scans_per_hour=health.scans_per_hour,
            error_rate_1h=health.error_rate_1h,
        )
        detached_health.id = health.id
        detached_health.created_at = health.created_at

        return detached_health

    # === COMPREHENSIVE ANALYTICS QUERIES ===

    def get_dashboard_data(self, hours: int = 24) -> dict[str, Any]:
        """Get comprehensive dashboard data."""
        since = time.time() - (hours * 3600)

        # MCP Tool Statistics
        mcp_stats = (
            self.session.query(
                MCPToolExecution.tool_name,
                func.count(MCPToolExecution.id).label("executions"),
                func.avg(
                    case(
                        (
                            MCPToolExecution.execution_end.isnot(None),
                            (
                                MCPToolExecution.execution_end
                                - MCPToolExecution.execution_start
                            )
                            * 1000,
                        ),
                        else_=None,
                    )
                ).label("avg_duration_ms"),
                func.sum(MCPToolExecution.findings_count).label("total_findings"),
                func.sum(case((MCPToolExecution.success, 1), else_=0)).label(
                    "successes"
                ),
            )
            .filter(MCPToolExecution.execution_start > since)
            .group_by(MCPToolExecution.tool_name)
            .all()
        )

        # CLI Command Statistics
        cli_stats = (
            self.session.query(
                CLICommandExecution.command_name,
                func.count(CLICommandExecution.id).label("executions"),
                func.avg(
                    case(
                        (
                            CLICommandExecution.execution_end.isnot(None),
                            (
                                CLICommandExecution.execution_end
                                - CLICommandExecution.execution_start
                            )
                            * 1000,
                        ),
                        else_=None,
                    )
                ).label("avg_duration_ms"),
                func.sum(CLICommandExecution.findings_count).label("total_findings"),
                func.sum(case((CLICommandExecution.exit_code == 0, 1), else_=0)).label(
                    "successes"
                ),
            )
            .filter(CLICommandExecution.execution_start > since)
            .group_by(CLICommandExecution.command_name)
            .all()
        )

        # Cache Performance
        cache_stats = (
            self.session.query(
                CacheOperationMetric.cache_name,
                func.sum(
                    case((CacheOperationMetric.operation_type == "hit", 1), else_=0)
                ).label("hits"),
                func.sum(
                    case((CacheOperationMetric.operation_type == "miss", 1), else_=0)
                ).label("misses"),
                func.avg(CacheOperationMetric.access_time_ms).label(
                    "avg_access_time_ms"
                ),
                func.sum(CacheOperationMetric.size_bytes).label("total_size_bytes"),
            )
            .filter(CacheOperationMetric.timestamp > since)
            .group_by(CacheOperationMetric.cache_name)
            .all()
        )

        # Scan Engine Performance
        scan_stats = (
            self.session.query(
                func.count(ScanEngineExecution.id).label("total_scans"),
                func.avg(ScanEngineExecution.total_duration_ms).label(
                    "avg_total_duration"
                ),
                func.avg(ScanEngineExecution.semgrep_duration_ms).label(
                    "avg_semgrep_duration_ms"
                ),
                func.avg(ScanEngineExecution.llm_duration_ms).label(
                    "avg_llm_duration_ms"
                ),
                func.avg(ScanEngineExecution.validation_duration_ms).label(
                    "avg_validation_duration_ms"
                ),
                func.sum(ScanEngineExecution.threats_found).label("total_threats"),
                func.sum(ScanEngineExecution.threats_validated).label(
                    "total_validated"
                ),
                func.sum(ScanEngineExecution.false_positives_filtered).label(
                    "total_false_positives"
                ),
                func.sum(case((ScanEngineExecution.cache_hit, 1), else_=0)).label(
                    "cache_hits"
                ),
            )
            .filter(ScanEngineExecution.execution_start > since)
            .first()
        )

        # Threat Findings by Category
        threat_categories = (
            self.session.query(
                ThreatFinding.category,
                ThreatFinding.severity,
                func.count(ThreatFinding.id).label("count"),
                func.avg(ThreatFinding.confidence).label("avg_confidence"),
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
                func.count(ScanEngineExecution.id).label("scans"),
                func.avg(ScanEngineExecution.total_duration_ms).label("avg_duration"),
                func.sum(ScanEngineExecution.threats_found).label("threats_found"),
            )
            .filter(
                and_(
                    ScanEngineExecution.execution_start > since,
                    ScanEngineExecution.language_detected.isnot(None),
                )
            )
            .group_by(ScanEngineExecution.language_detected)
            .order_by(func.count(ScanEngineExecution.id).desc())
            .all()
        )

        # Get individual threat findings for detailed dashboard table
        threat_findings = (
            self.session.query(ThreatFinding)
            .filter(ThreatFinding.timestamp > since)
            .order_by(ThreatFinding.timestamp.desc())
            .limit(100)  # Limit to prevent overwhelming the dashboard
            .all()
        )

        return {
            "mcp_tools": [
                {
                    "tool_name": stat.tool_name,
                    "executions": stat.executions,
                    "avg_duration_ms": float(stat.avg_duration_ms or 0),
                    "total_findings": stat.total_findings or 0,
                    "success_rate": (stat.successes or 0) / max(stat.executions, 1),
                }
                for stat in mcp_stats
            ],
            "cli_commands": [
                {
                    "command_name": stat.command_name,
                    "executions": stat.executions,
                    "avg_duration_ms": float(stat.avg_duration_ms or 0),
                    "total_findings": stat.total_findings or 0,
                    "success_rate": (stat.successes or 0) / max(stat.executions, 1),
                }
                for stat in cli_stats
            ],
            "cache_performance": [
                {
                    "cache_name": stat.cache_name,
                    "hits": stat.hits or 0,
                    "misses": stat.misses or 0,
                    "hit_rate": (stat.hits or 0)
                    / max((stat.hits or 0) + (stat.misses or 0), 1),
                    "avg_access_time_ms": float(stat.avg_access_time_ms or 0),
                    "total_size_mb": (stat.total_size_bytes or 0) / 1024 / 1024,
                }
                for stat in cache_stats
            ],
            "scan_engine": {
                "total_scans": scan_stats.total_scans or 0,
                "avg_total_duration_ms": float(scan_stats.avg_total_duration or 0),
                "avg_semgrep_duration_ms": float(
                    scan_stats.avg_semgrep_duration_ms or 0
                ),
                "avg_llm_duration_ms": float(scan_stats.avg_llm_duration_ms or 0),
                "avg_validation_duration_ms": float(
                    scan_stats.avg_validation_duration_ms or 0
                ),
                "total_threats_found": scan_stats.total_threats or 0,
                "total_threats_validated": scan_stats.total_validated or 0,
                "false_positives_filtered": scan_stats.total_false_positives or 0,
                "cache_hit_rate": (scan_stats.cache_hits or 0)
                / max(scan_stats.total_scans or 1, 1),
            },
            "threat_categories": [
                {
                    "category": stat.category,
                    "severity": stat.severity,
                    "count": stat.count,
                    "avg_confidence": float(stat.avg_confidence or 0),
                }
                for stat in threat_categories
            ],
            "language_performance": [
                {
                    "language": stat.language_detected,
                    "scans": stat.scans,
                    "avg_duration_ms": float(stat.avg_duration or 0),
                    "threats_found": stat.threats_found or 0,
                }
                for stat in language_performance
            ],
            "threat_findings": [
                {
                    "finding_uuid": finding.finding_uuid,
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "scanner_source": finding.scanner_source,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "confidence": finding.confidence or 0,
                    "is_validated": finding.is_validated,
                    "is_false_positive": finding.is_false_positive,
                    "timestamp": finding.timestamp,
                    "scan_id": finding.scan_id,
                }
                for finding in threat_findings
            ],
        }
