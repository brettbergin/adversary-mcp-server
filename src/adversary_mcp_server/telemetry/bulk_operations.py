"""Bulk operation optimizations for telemetry system performance."""

import time
from contextlib import contextmanager
from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session

from ..database.models import (
    CacheOperationMetric,
    CLICommandExecution,
    MCPToolExecution,
    ScanEngineExecution,
    SystemHealth,
    ThreatFinding,
)


class BulkOperationManager:
    """Manager for optimized bulk database operations."""

    def __init__(self, session: Session):
        self.session = session
        self._pending_inserts: dict[type, list[dict[str, Any]]] = {}
        self._batch_size = 100
        self._auto_flush_threshold = 500

    def queue_insert(self, model_class: type, data: dict[str, Any]) -> None:
        """Queue an insert operation for bulk processing."""
        if model_class not in self._pending_inserts:
            self._pending_inserts[model_class] = []

        self._pending_inserts[model_class].append(data)

        # Auto-flush if we hit the threshold
        if len(self._pending_inserts[model_class]) >= self._auto_flush_threshold:
            self.flush_inserts(model_class)

    def flush_inserts(self, model_class: type | None = None) -> int:
        """Flush pending inserts to database using bulk operations."""
        total_inserted = 0

        if model_class:
            # Flush specific model class
            if model_class in self._pending_inserts:
                count = self._bulk_insert(
                    model_class, self._pending_inserts[model_class]
                )
                self._pending_inserts[model_class].clear()
                total_inserted += count
        else:
            # Flush all pending inserts
            for cls, records in self._pending_inserts.items():
                if records:
                    count = self._bulk_insert(cls, records)
                    total_inserted += count
            self._pending_inserts.clear()

        return total_inserted

    def _bulk_insert(self, model_class: type, records: list[dict[str, Any]]) -> int:
        """Perform bulk insert using SQLAlchemy bulk operations."""
        if not records:
            return 0

        try:
            # Use bulk_insert_mappings for best performance
            self.session.bulk_insert_mappings(model_class.__mapper__, records)
            self.session.commit()
            return len(records)
        except Exception as e:
            self.session.rollback()
            # Fallback to individual inserts for better error handling
            return self._fallback_individual_inserts(model_class, records)

    def _fallback_individual_inserts(
        self, model_class: type, records: list[dict[str, Any]]
    ) -> int:
        """Fallback to individual inserts if bulk insert fails."""
        inserted = 0
        for record in records:
            try:
                instance = model_class(**record)
                self.session.add(instance)
                self.session.commit()
                inserted += 1
            except Exception:
                self.session.rollback()
                # Skip problematic records
                continue
        return inserted

    def get_pending_count(self) -> dict[str, int]:
        """Get count of pending operations by model."""
        return {
            cls.__name__: len(records) for cls, records in self._pending_inserts.items()
        }

    @contextmanager
    def bulk_context(self):
        """Context manager for bulk operations."""
        try:
            yield self
        finally:
            self.flush_inserts()


class OptimizedTelemetryService:
    """Telemetry service with bulk operation optimizations."""

    def __init__(self, session: Session):
        self.session = session
        self.bulk_manager = BulkOperationManager(session)
        self._enable_bulk_mode = False

    def enable_bulk_mode(self) -> None:
        """Enable bulk operation mode for better performance."""
        self._enable_bulk_mode = True

    def disable_bulk_mode(self) -> None:
        """Disable bulk mode and flush pending operations."""
        self.bulk_manager.flush_inserts()
        self._enable_bulk_mode = False

    def track_mcp_tool_execution_bulk(
        self, tool_name: str, session_id: str, request_params: dict, **kwargs
    ) -> None:
        """Track MCP tool execution using bulk operations."""
        data = {
            "tool_name": tool_name,
            "session_id": session_id,
            "request_params": request_params,
            "execution_start": time.time(),
            "validation_enabled": kwargs.get("validation_enabled", False),
            "llm_enabled": kwargs.get("llm_enabled", False),
        }

        if self._enable_bulk_mode:
            self.bulk_manager.queue_insert(MCPToolExecution, data)
        else:
            # Immediate insert
            instance = MCPToolExecution(**data)
            self.session.add(instance)
            self.session.commit()

    def track_cli_command_execution_bulk(
        self, command_name: str, args: dict, subcommand: str = None, **kwargs
    ) -> None:
        """Track CLI command execution using bulk operations."""
        data = {
            "command_name": command_name,
            "subcommand": subcommand,
            "args": args,
            "execution_start": time.time(),
            "validation_enabled": kwargs.get("validation_enabled", False),
        }

        if self._enable_bulk_mode:
            self.bulk_manager.queue_insert(CLICommandExecution, data)
        else:
            instance = CLICommandExecution(**data)
            self.session.add(instance)
            self.session.commit()

    def track_cache_operations_bulk(self, operations: list[dict[str, Any]]) -> None:
        """Track multiple cache operations in bulk."""
        for op_data in operations:
            if "timestamp" not in op_data:
                op_data["timestamp"] = time.time()

        if self._enable_bulk_mode:
            for op_data in operations:
                self.bulk_manager.queue_insert(CacheOperationMetric, op_data)
        else:
            self.session.bulk_insert_mappings(
                CacheOperationMetric.__mapper__, operations
            )
            self.session.commit()

    def track_threat_findings_bulk(self, findings: list[dict[str, Any]]) -> None:
        """Track multiple threat findings in bulk."""
        for finding_data in findings:
            if "timestamp" not in finding_data:
                finding_data["timestamp"] = time.time()

        if self._enable_bulk_mode:
            for finding_data in findings:
                self.bulk_manager.queue_insert(ThreatFinding, finding_data)
        else:
            self.session.bulk_insert_mappings(ThreatFinding.__mapper__, findings)
            self.session.commit()

    def get_bulk_stats(self) -> dict[str, Any]:
        """Get bulk operation statistics."""
        return {
            "bulk_mode_enabled": self._enable_bulk_mode,
            "pending_operations": self.bulk_manager.get_pending_count(),
            "batch_size": self.bulk_manager._batch_size,
            "auto_flush_threshold": self.bulk_manager._auto_flush_threshold,
        }


def optimize_session_for_bulk_operations(session: Session) -> None:
    """Apply session-level optimizations for bulk operations."""

    # Disable autoflush for better bulk performance
    session.autoflush = False

    # Use event listeners to optimize session behavior
    @event.listens_for(session, "before_bulk_insert")
    def before_bulk_insert(query_context):
        """Optimize before bulk insert operations."""
        # Could add custom optimizations here
        pass

    @event.listens_for(session, "after_bulk_insert")
    def after_bulk_insert(insert_context):
        """Handle post-bulk insert cleanup."""
        # Could add cleanup logic here
        pass


class BatchProcessor:
    """Process telemetry operations in batches for optimal performance."""

    def __init__(self, session: Session, batch_size: int = 100):
        self.session = session
        self.batch_size = batch_size

    def process_telemetry_batch(
        self, telemetry_data: list[dict[str, Any]]
    ) -> dict[str, int]:
        """Process a batch of mixed telemetry data."""
        results = {
            "mcp_tools": 0,
            "cli_commands": 0,
            "cache_operations": 0,
            "threat_findings": 0,
            "scan_executions": 0,
            "system_health": 0,
            "errors": 0,
        }

        # Group data by type
        grouped_data = self._group_telemetry_data(telemetry_data)

        # Process each group with bulk operations
        for data_type, records in grouped_data.items():
            try:
                if data_type == "mcp_tool_executions":
                    self.session.bulk_insert_mappings(
                        MCPToolExecution.__mapper__, records
                    )
                    results["mcp_tools"] += len(records)
                elif data_type == "cli_command_executions":
                    self.session.bulk_insert_mappings(
                        CLICommandExecution.__mapper__, records
                    )
                    results["cli_commands"] += len(records)
                elif data_type == "cache_operations":
                    self.session.bulk_insert_mappings(
                        CacheOperationMetric.__mapper__, records
                    )
                    results["cache_operations"] += len(records)
                elif data_type == "threat_findings":
                    self.session.bulk_insert_mappings(ThreatFinding.__mapper__, records)
                    results["threat_findings"] += len(records)
                elif data_type == "scan_executions":
                    self.session.bulk_insert_mappings(
                        ScanEngineExecution.__mapper__, records
                    )
                    results["scan_executions"] += len(records)
                elif data_type == "system_health":
                    self.session.bulk_insert_mappings(SystemHealth.__mapper__, records)
                    results["system_health"] += len(records)

            except Exception as e:
                results["errors"] += 1
                # Log error but continue processing other types
                continue

        # Commit all changes at once
        try:
            self.session.commit()
        except Exception:
            self.session.rollback()
            results["errors"] += 1

        return results

    def _group_telemetry_data(
        self, telemetry_data: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Group telemetry data by type for batch processing."""
        grouped = {
            "mcp_tool_executions": [],
            "cli_command_executions": [],
            "cache_operations": [],
            "threat_findings": [],
            "scan_executions": [],
            "system_health": [],
        }

        for record in telemetry_data:
            data_type = record.get("_type", "unknown")
            if data_type in grouped:
                record_data = record.copy()
                record_data.pop("_type", None)  # Remove type marker
                grouped[data_type].append(record_data)

        return {k: v for k, v in grouped.items() if v}  # Filter empty groups


@contextmanager
def bulk_telemetry_context(session: Session):
    """Context manager for bulk telemetry operations."""
    service = OptimizedTelemetryService(session)
    service.enable_bulk_mode()
    try:
        yield service
    finally:
        service.disable_bulk_mode()
