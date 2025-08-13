"""Main telemetry service that replaces JSON metrics system."""

from contextlib import contextmanager
from typing import Any

from ..database.models import AdversaryDatabase
from .cache import cached_query
from .repository import ComprehensiveTelemetryRepository


class TelemetryService:
    """Main telemetry service that replaces JSON metrics system."""

    def __init__(self, db: AdversaryDatabase):
        self.db = db

    @contextmanager
    def get_repository(self):
        """Get repository with session management."""
        session = self.db.get_session()
        try:
            yield ComprehensiveTelemetryRepository(session)
        finally:
            session.close()

    @contextmanager
    def transaction(self):
        """Create a transaction context for multiple related operations."""
        session = self.db.get_session()
        try:
            repo = ComprehensiveTelemetryRepository(session)
            # Disable auto-commit in repository for transaction mode
            repo._auto_commit = False
            yield repo
            # Commit all operations at the end of the transaction
            session.commit()
        except Exception:
            # Rollback on any error
            session.rollback()
            raise
        finally:
            session.close()

    # === MCP Tool Telemetry ===

    def start_mcp_tool_tracking(
        self, tool_name: str, session_id: str, request_params: dict, **kwargs
    ):
        """Start tracking MCP tool execution."""
        with self.get_repository() as repo:
            return repo.track_mcp_tool_execution(
                tool_name, session_id, request_params, **kwargs
            )

    def complete_mcp_tool_tracking(
        self,
        execution_id: int,
        success: bool = True,
        findings_count: int = 0,
        error_message: str = None,
    ):
        """Complete MCP tool execution tracking."""
        with self.get_repository() as repo:
            repo.complete_mcp_tool_execution(
                execution_id, success, findings_count, error_message
            )

    # === CLI Command Telemetry ===

    def start_cli_command_tracking(self, command_name: str, args: dict, **kwargs):
        """Start tracking CLI command execution."""
        with self.get_repository() as repo:
            return repo.track_cli_command_execution(command_name, args, **kwargs)

    def complete_cli_command_tracking(
        self, execution_id: int, exit_code: int = 0, **kwargs
    ):
        """Complete CLI command execution tracking."""
        with self.get_repository() as repo:
            repo.complete_cli_command_execution(execution_id, exit_code, **kwargs)

    # === Cache Telemetry ===

    def track_cache_operation(
        self, operation_type: str, cache_name: str, key_hash: str, **kwargs
    ):
        """Track cache operation."""
        with self.get_repository() as repo:
            return repo.track_cache_operation(
                operation_type, cache_name, key_hash, **kwargs
            )

    # === Scan Engine Telemetry ===

    def start_scan_tracking(
        self,
        scan_id: str,
        trigger_source: str,
        scan_type: str,
        target_path: str,
        **kwargs,
    ):
        """Start tracking scan execution."""
        with self.get_repository() as repo:
            return repo.track_scan_execution(
                scan_id, trigger_source, scan_type, target_path, **kwargs
            )

    def complete_scan_tracking(self, scan_id: str, success: bool = True, **kwargs):
        """Complete scan execution tracking."""
        with self.get_repository() as repo:
            repo.complete_scan_execution(scan_id, success, **kwargs)

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
    ):
        """Record threat finding."""
        with self.get_repository() as repo:
            return repo.record_threat_finding(
                scan_id,
                finding_uuid,
                scanner_source,
                category,
                severity,
                file_path,
                line_start,
                line_end,
                title,
                **kwargs,
            )

    # === System Health ===

    def record_system_health_snapshot(self, **metrics):
        """Record system health snapshot."""
        with self.get_repository() as repo:
            return repo.record_system_health_snapshot(**metrics)

    # === TRANSACTIONAL OPERATIONS ===

    def record_scan_results_atomic(
        self,
        scan_id: str,
        threat_findings: list[dict],
        scan_success: bool = True,
        validation_results: dict | None = None,
        **scan_completion_kwargs,
    ):
        """Atomically record multiple threat findings, apply validation results, and update scan execution summary."""
        with self.transaction() as repo:
            # Record all threat findings
            for finding_data in threat_findings:
                repo.record_threat_finding(scan_id=scan_id, **finding_data)

            # Apply validation results if provided
            if validation_results:
                for finding_uuid, validation_result in validation_results.items():
                    repo.update_threat_finding_validation(
                        finding_uuid=finding_uuid,
                        is_validated=True,
                        validation_confidence=validation_result.confidence,
                        validation_reasoning=validation_result.reasoning,
                        is_false_positive=not validation_result.is_legitimate,
                        exploitation_vector=validation_result.exploitation_vector,
                    )

            # Update scan execution with final counts
            repo.complete_scan_execution(
                scan_id=scan_id,
                success=scan_success,
                threats_found=len(threat_findings),
                **scan_completion_kwargs,
            )

    def record_mcp_results_atomic(
        self,
        execution_id: int,
        threat_findings: list[dict],
        success: bool = True,
        **completion_kwargs,
    ):
        """Atomically record threat findings and update MCP tool execution summary."""
        with self.transaction() as repo:
            # Record all threat findings if any
            for finding_data in threat_findings:
                repo.record_threat_finding(**finding_data)

            # Update MCP execution with final counts
            repo.complete_mcp_tool_execution(
                execution_id=execution_id,
                success=success,
                findings_count=len(threat_findings),
                **completion_kwargs,
            )

    def update_validation_results_atomic(self, validation_results: dict):
        """Atomically update multiple threat findings with validation results."""
        with self.transaction() as repo:
            for finding_uuid, validation_result in validation_results.items():
                repo.update_threat_finding_validation(
                    finding_uuid=finding_uuid,
                    is_validated=True,
                    validation_confidence=validation_result.confidence,
                    validation_reasoning=validation_result.reasoning,
                    is_false_positive=not validation_result.is_legitimate,
                    exploitation_vector=validation_result.exploitation_vector,
                )

    # === Dashboard Data ===

    @cached_query(ttl=300, key_prefix="dashboard:")  # Cache for 5 minutes
    def get_dashboard_data(self, hours: int = 24) -> dict[str, Any]:
        """Get comprehensive dashboard data with caching."""
        with self.get_repository() as repo:
            return repo.get_dashboard_data(hours)

    # === Performance and Maintenance ===

    def invalidate_dashboard_cache(self):
        """Invalidate dashboard data cache."""
        if hasattr(self.get_dashboard_data, "invalidate_cache"):
            self.get_dashboard_data.invalidate_cache()

    def get_cache_stats(self) -> dict[str, Any]:
        """Get telemetry cache statistics."""
        if hasattr(self.get_dashboard_data, "get_cache_stats"):
            return self.get_dashboard_data.get_cache_stats()
        return {}
