"""Tests for bulk telemetry operations module."""

import time
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from adversary_mcp_server.database.models import (
    Base,
    CacheOperationMetric,
    CLICommandExecution,
    MCPToolExecution,
    ThreatFinding,
)
from adversary_mcp_server.telemetry.bulk_operations import (
    BatchProcessor,
    BulkOperationManager,
    OptimizedTelemetryService,
    bulk_telemetry_context,
    optimize_session_for_bulk_operations,
)


@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db_session(in_memory_db):
    """Create a database session for testing."""
    SessionLocal = sessionmaker(bind=in_memory_db)
    session = SessionLocal()
    yield session
    session.close()


class TestBulkOperationManager:
    """Test BulkOperationManager functionality."""

    def test_initialization(self, db_session):
        """Test BulkOperationManager initialization."""
        manager = BulkOperationManager(db_session)

        assert manager.session == db_session
        assert manager._pending_inserts == {}
        assert manager._batch_size == 100
        assert manager._auto_flush_threshold == 500

    def test_queue_insert_single_record(self, db_session):
        """Test queuing single insert."""
        manager = BulkOperationManager(db_session)

        data = {
            "tool_name": "test_tool",
            "session_id": "test_session",
            "request_params": {"param": "value"},
            "execution_start": time.time(),
        }

        manager.queue_insert(MCPToolExecution, data)

        assert MCPToolExecution in manager._pending_inserts
        assert len(manager._pending_inserts[MCPToolExecution]) == 1
        assert manager._pending_inserts[MCPToolExecution][0] == data

    def test_queue_insert_multiple_records(self, db_session):
        """Test queuing multiple inserts."""
        manager = BulkOperationManager(db_session)

        for i in range(5):
            data = {
                "tool_name": f"test_tool_{i}",
                "session_id": f"test_session_{i}",
                "request_params": {"param": f"value_{i}"},
                "execution_start": time.time(),
            }
            manager.queue_insert(MCPToolExecution, data)

        assert len(manager._pending_inserts[MCPToolExecution]) == 5

    def test_auto_flush_threshold(self, db_session):
        """Test automatic flush when threshold is reached."""
        manager = BulkOperationManager(db_session)
        manager._auto_flush_threshold = 3  # Lower threshold for testing

        # Add records up to threshold - 1
        for i in range(2):
            data = {
                "tool_name": f"test_tool_{i}",
                "session_id": f"test_session_{i}",
                "request_params": {"param": f"value_{i}"},
                "execution_start": time.time(),
            }
            manager.queue_insert(MCPToolExecution, data)

        assert len(manager._pending_inserts[MCPToolExecution]) == 2

        # Add one more to trigger auto-flush
        data = {
            "tool_name": "test_tool_3",
            "session_id": "test_session_3",
            "request_params": {"param": "value_3"},
            "execution_start": time.time(),
        }
        manager.queue_insert(MCPToolExecution, data)

        # Should be cleared due to auto-flush
        assert len(manager._pending_inserts[MCPToolExecution]) == 0

    def test_flush_inserts_specific_model(self, db_session):
        """Test flushing inserts for specific model."""
        manager = BulkOperationManager(db_session)

        # Add data for two different models
        mcp_data = {
            "tool_name": "test_tool",
            "session_id": "test_session",
            "request_params": {"param": "value"},
            "execution_start": time.time(),
        }
        cli_data = {
            "command_name": "test_command",
            "args": {"arg": "value"},
            "execution_start": time.time(),
        }

        manager.queue_insert(MCPToolExecution, mcp_data)
        manager.queue_insert(CLICommandExecution, cli_data)

        # Flush only MCP data
        count = manager.flush_inserts(MCPToolExecution)

        assert count == 1
        assert len(manager._pending_inserts.get(MCPToolExecution, [])) == 0
        assert len(manager._pending_inserts[CLICommandExecution]) == 1

    def test_flush_inserts_all_models(self, db_session):
        """Test flushing all pending inserts."""
        manager = BulkOperationManager(db_session)

        # Add data for multiple models
        mcp_data = {
            "tool_name": "test_tool",
            "session_id": "test_session",
            "request_params": {"param": "value"},
            "execution_start": time.time(),
        }
        cli_data = {
            "command_name": "test_command",
            "args": {"arg": "value"},
            "execution_start": time.time(),
        }

        manager.queue_insert(MCPToolExecution, mcp_data)
        manager.queue_insert(CLICommandExecution, cli_data)

        count = manager.flush_inserts()

        assert count == 2
        assert manager._pending_inserts == {}

    def test_bulk_insert_empty_records(self, db_session):
        """Test bulk insert with empty records list."""
        manager = BulkOperationManager(db_session)

        count = manager._bulk_insert(MCPToolExecution, [])
        assert count == 0

    def test_bulk_insert_with_exception(self, db_session):
        """Test bulk insert fallback when exception occurs."""
        manager = BulkOperationManager(db_session)

        # Mock bulk_insert_mappings to raise exception
        with patch.object(db_session, "bulk_insert_mappings") as mock_bulk:
            mock_bulk.side_effect = SQLAlchemyError("Test error")

            # Mock the fallback method
            with patch.object(manager, "_fallback_individual_inserts") as mock_fallback:
                mock_fallback.return_value = 2

                data = [
                    {
                        "tool_name": "test_tool",
                        "session_id": "test_session",
                        "request_params": {"param": "value"},
                        "execution_start": time.time(),
                    }
                ]

                count = manager._bulk_insert(MCPToolExecution, data)

                assert count == 2
                mock_fallback.assert_called_once_with(MCPToolExecution, data)

    def test_fallback_individual_inserts(self, db_session):
        """Test fallback individual inserts."""
        manager = BulkOperationManager(db_session)

        valid_data = {
            "tool_name": "test_tool",
            "session_id": "test_session",
            "request_params": {"param": "value"},
            "execution_start": time.time(),
        }

        # Mix valid and invalid data
        records = [
            valid_data,
            {"invalid": "data"},  # This should fail
            valid_data.copy(),
        ]

        count = manager._fallback_individual_inserts(MCPToolExecution, records)

        # Should insert 2 valid records, skip 1 invalid
        assert count == 2

    def test_get_pending_count(self, db_session):
        """Test getting pending operation counts."""
        manager = BulkOperationManager(db_session)

        # Add some pending data
        mcp_data = {
            "tool_name": "test_tool",
            "session_id": "test_session",
            "request_params": {"param": "value"},
            "execution_start": time.time(),
        }
        cli_data = {
            "command_name": "test_command",
            "args": {"arg": "value"},
            "execution_start": time.time(),
        }

        manager.queue_insert(MCPToolExecution, mcp_data)
        manager.queue_insert(MCPToolExecution, mcp_data)
        manager.queue_insert(CLICommandExecution, cli_data)

        counts = manager.get_pending_count()

        assert counts["MCPToolExecution"] == 2
        assert counts["CLICommandExecution"] == 1

    def test_bulk_context_manager(self, db_session):
        """Test bulk context manager."""
        manager = BulkOperationManager(db_session)

        data = {
            "tool_name": "test_tool",
            "session_id": "test_session",
            "request_params": {"param": "value"},
            "execution_start": time.time(),
        }

        with manager.bulk_context() as ctx:
            assert ctx == manager
            ctx.queue_insert(MCPToolExecution, data)
            # Data should still be pending
            assert len(manager._pending_inserts[MCPToolExecution]) == 1

        # After context exit, data should be flushed
        assert len(manager._pending_inserts.get(MCPToolExecution, [])) == 0


class TestOptimizedTelemetryService:
    """Test OptimizedTelemetryService functionality."""

    def test_initialization(self, db_session):
        """Test service initialization."""
        service = OptimizedTelemetryService(db_session)

        assert service.session == db_session
        assert isinstance(service.bulk_manager, BulkOperationManager)
        assert service._enable_bulk_mode is False

    def test_enable_disable_bulk_mode(self, db_session):
        """Test enabling and disabling bulk mode."""
        service = OptimizedTelemetryService(db_session)

        assert service._enable_bulk_mode is False

        service.enable_bulk_mode()
        assert service._enable_bulk_mode is True

        service.disable_bulk_mode()
        assert service._enable_bulk_mode is False

    def test_track_mcp_tool_execution_bulk_mode(self, db_session):
        """Test MCP tool execution tracking in bulk mode."""
        service = OptimizedTelemetryService(db_session)
        service.enable_bulk_mode()

        with patch.object(service.bulk_manager, "queue_insert") as mock_queue:
            service.track_mcp_tool_execution_bulk(
                tool_name="test_tool",
                session_id="test_session",
                request_params={"param": "value"},
                validation_enabled=True,
                llm_enabled=False,
            )

            mock_queue.assert_called_once()
            args, kwargs = mock_queue.call_args
            assert args[0] == MCPToolExecution
            assert args[1]["tool_name"] == "test_tool"
            assert args[1]["validation_enabled"] is True
            assert args[1]["llm_enabled"] is False

    def test_track_mcp_tool_execution_immediate_mode(self, db_session):
        """Test MCP tool execution tracking in immediate mode."""
        service = OptimizedTelemetryService(db_session)
        # Bulk mode is disabled by default

        service.track_mcp_tool_execution_bulk(
            tool_name="test_tool",
            session_id="test_session",
            request_params={"param": "value"},
        )

        # Should have been inserted immediately
        result = (
            db_session.query(MCPToolExecution).filter_by(tool_name="test_tool").first()
        )
        assert result is not None
        assert result.tool_name == "test_tool"

    def test_track_cli_command_execution_bulk_mode(self, db_session):
        """Test CLI command execution tracking in bulk mode."""
        service = OptimizedTelemetryService(db_session)
        service.enable_bulk_mode()

        with patch.object(service.bulk_manager, "queue_insert") as mock_queue:
            service.track_cli_command_execution_bulk(
                command_name="test_command",
                args={"arg": "value"},
                subcommand="test_sub",
                validation_enabled=True,
            )

            mock_queue.assert_called_once()
            args, kwargs = mock_queue.call_args
            assert args[0] == CLICommandExecution
            assert args[1]["command_name"] == "test_command"
            assert args[1]["subcommand"] == "test_sub"

    def test_track_cli_command_execution_immediate_mode(self, db_session):
        """Test CLI command execution tracking in immediate mode."""
        service = OptimizedTelemetryService(db_session)

        service.track_cli_command_execution_bulk(
            command_name="test_command",
            args={"arg": "value"},
        )

        result = (
            db_session.query(CLICommandExecution)
            .filter_by(command_name="test_command")
            .first()
        )
        assert result is not None
        assert result.command_name == "test_command"

    def test_track_cache_operations_bulk_mode(self, db_session):
        """Test cache operations tracking in bulk mode."""
        service = OptimizedTelemetryService(db_session)
        service.enable_bulk_mode()

        operations = [
            {
                "operation_type": "get",
                "cache_name": "scan_results",
                "key_hash": "test_key1",
                "size_bytes": 1024,
            },
            {
                "operation_type": "set",
                "cache_name": "scan_results",
                "key_hash": "test_key2",
                "size_bytes": 2048,
            },
        ]

        with patch.object(service.bulk_manager, "queue_insert") as mock_queue:
            service.track_cache_operations_bulk(operations)

            assert mock_queue.call_count == 2
            # Check timestamps were added
            for call in mock_queue.call_args_list:
                assert "timestamp" in call[0][1]

    def test_track_cache_operations_immediate_mode(self, db_session):
        """Test cache operations tracking in immediate mode."""
        service = OptimizedTelemetryService(db_session)

        operations = [
            {
                "operation_type": "get",
                "cache_name": "scan_results",
                "key_hash": "test_key1",
                "size_bytes": 1024,
            },
            {
                "operation_type": "set",
                "cache_name": "scan_results",
                "key_hash": "test_key2",
                "size_bytes": 2048,
            },
        ]

        service.track_cache_operations_bulk(operations)

        results = db_session.query(CacheOperationMetric).all()
        assert len(results) == 2
        assert results[0].operation_type in ["get", "set"]
        assert results[1].operation_type in ["get", "set"]

    def test_track_threat_findings_bulk_mode(self, db_session):
        """Test threat findings tracking in bulk mode."""
        service = OptimizedTelemetryService(db_session)
        service.enable_bulk_mode()

        findings = [
            {
                "scan_id": "scan-123",
                "finding_uuid": "finding-1",
                "scanner_source": "semgrep",
                "rule_id": "rule1",
                "category": "injection",
                "severity": "high",
                "file_path": "/test/file1.py",
                "line_start": 10,
                "line_end": 12,
            },
            {
                "scan_id": "scan-123",
                "finding_uuid": "finding-2",
                "scanner_source": "semgrep",
                "rule_id": "rule2",
                "category": "xss",
                "severity": "medium",
                "file_path": "/test/file2.py",
                "line_start": 20,
                "line_end": 22,
            },
        ]

        with patch.object(service.bulk_manager, "queue_insert") as mock_queue:
            service.track_threat_findings_bulk(findings)

            assert mock_queue.call_count == 2
            # Check timestamps were added
            for call in mock_queue.call_args_list:
                assert "timestamp" in call[0][1]

    def test_track_threat_findings_immediate_mode(self, db_session):
        """Test threat findings tracking in immediate mode."""
        service = OptimizedTelemetryService(db_session)

        findings = [
            {
                "scan_id": "scan-123",
                "finding_uuid": "finding-1",
                "scanner_source": "semgrep",
                "rule_id": "rule1",
                "category": "injection",
                "severity": "high",
                "file_path": "/test/file1.py",
                "line_start": 10,
                "line_end": 12,
                "title": "Test Finding 1",
            },
            {
                "scan_id": "scan-123",
                "finding_uuid": "finding-2",
                "scanner_source": "semgrep",
                "rule_id": "rule2",
                "category": "xss",
                "severity": "medium",
                "file_path": "/test/file2.py",
                "line_start": 20,
                "line_end": 22,
                "title": "Test Finding 2",
            },
        ]

        service.track_threat_findings_bulk(findings)

        results = db_session.query(ThreatFinding).all()
        assert len(results) == 2
        assert results[0].rule_id in ["rule1", "rule2"]
        assert results[1].rule_id in ["rule1", "rule2"]

    def test_get_bulk_stats(self, db_session):
        """Test getting bulk operation statistics."""
        service = OptimizedTelemetryService(db_session)

        stats = service.get_bulk_stats()

        assert "bulk_mode_enabled" in stats
        assert "pending_operations" in stats
        assert "batch_size" in stats
        assert "auto_flush_threshold" in stats
        assert stats["bulk_mode_enabled"] is False

        service.enable_bulk_mode()
        stats = service.get_bulk_stats()
        assert stats["bulk_mode_enabled"] is True


class TestBatchProcessor:
    """Test BatchProcessor functionality."""

    def test_initialization(self, db_session):
        """Test BatchProcessor initialization."""
        processor = BatchProcessor(db_session, batch_size=50)

        assert processor.session == db_session
        assert processor.batch_size == 50

    def test_group_telemetry_data(self, db_session):
        """Test grouping telemetry data by type."""
        processor = BatchProcessor(db_session)

        telemetry_data = [
            {"_type": "mcp_tool_executions", "tool_name": "test1"},
            {"_type": "cli_command_executions", "command_name": "test2"},
            {
                "_type": "cache_operations",
                "operation_type": "get",
                "cache_name": "scan_results",
                "key_hash": "test_key",
                "size_bytes": 1024,
            },
            {"_type": "unknown_type", "data": "should_be_ignored"},
            {"_type": "mcp_tool_executions", "tool_name": "test3"},
        ]

        grouped = processor._group_telemetry_data(telemetry_data)

        assert len(grouped["mcp_tool_executions"]) == 2
        assert len(grouped["cli_command_executions"]) == 1
        assert len(grouped["cache_operations"]) == 1
        assert "unknown_type" not in grouped

        # Check _type marker is removed
        assert "_type" not in grouped["mcp_tool_executions"][0]
        assert grouped["mcp_tool_executions"][0]["tool_name"] == "test1"

    def test_process_telemetry_batch_success(self, db_session):
        """Test successful batch processing."""
        processor = BatchProcessor(db_session)

        telemetry_data = [
            {
                "_type": "mcp_tool_executions",
                "tool_name": "test1",
                "session_id": "session1",
                "request_params": {},
                "execution_start": time.time(),
            },
            {
                "_type": "cli_command_executions",
                "command_name": "test2",
                "args": {},
                "execution_start": time.time(),
            },
        ]

        results = processor.process_telemetry_batch(telemetry_data)

        assert results["mcp_tools"] == 1
        assert results["cli_commands"] == 1
        assert results["cache_operations"] == 0
        assert results["errors"] == 0

    def test_process_telemetry_batch_with_errors(self, db_session):
        """Test batch processing with errors."""
        processor = BatchProcessor(db_session)

        # Mock bulk_insert_mappings to raise exception
        with patch.object(db_session, "bulk_insert_mappings") as mock_bulk:
            mock_bulk.side_effect = SQLAlchemyError("Test error")

            telemetry_data = [
                {
                    "_type": "mcp_tool_executions",
                    "tool_name": "test1",
                    "session_id": "session1",
                    "request_params": {},
                    "execution_start": time.time(),
                },
            ]

            results = processor.process_telemetry_batch(telemetry_data)

            assert results["mcp_tools"] == 0
            assert results["errors"] == 1

    def test_process_telemetry_batch_commit_error(self, db_session):
        """Test batch processing with commit error."""
        processor = BatchProcessor(db_session)

        # Mock commit to raise exception
        with patch.object(db_session, "commit") as mock_commit:
            mock_commit.side_effect = SQLAlchemyError("Commit error")

            telemetry_data = [
                {
                    "_type": "mcp_tool_executions",
                    "tool_name": "test1",
                    "session_id": "session1",
                    "request_params": {},
                    "execution_start": time.time(),
                },
            ]

            results = processor.process_telemetry_batch(telemetry_data)

            assert results["errors"] == 1


class TestBulkTelemetryContext:
    """Test bulk telemetry context manager."""

    def test_bulk_telemetry_context(self, db_session):
        """Test bulk telemetry context manager."""
        with bulk_telemetry_context(db_session) as service:
            assert isinstance(service, OptimizedTelemetryService)
            assert service._enable_bulk_mode is True

            # Add some data
            service.track_mcp_tool_execution_bulk(
                tool_name="test_tool",
                session_id="test_session",
                request_params={"param": "value"},
            )

            # Should be in bulk manager, not in DB yet
            assert len(service.bulk_manager.get_pending_count()) > 0

        # After context exit, bulk mode should be disabled and data flushed
        assert service._enable_bulk_mode is False


class TestOptimizeSession:
    """Test session optimization functions."""

    def test_optimize_session_for_bulk_operations(self, db_session):
        """Test session optimization for bulk operations."""
        # Session should have autoflush enabled initially
        assert db_session.autoflush is True

        # Mock the event listeners to avoid SQLAlchemy event registration issues
        with patch("adversary_mcp_server.telemetry.bulk_operations.event"):
            optimize_session_for_bulk_operations(db_session)

        # Should disable autoflush for bulk operations
        assert db_session.autoflush is False


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_bulk_manager_with_no_pending_data(self, db_session):
        """Test bulk manager operations with no pending data."""
        manager = BulkOperationManager(db_session)

        count = manager.flush_inserts()
        assert count == 0

        counts = manager.get_pending_count()
        assert counts == {}

    def test_service_track_operations_with_timestamps(self, db_session):
        """Test service operations automatically add timestamps."""
        service = OptimizedTelemetryService(db_session)

        # Cache operations should get timestamps if not provided
        operations_without_timestamps = [
            {
                "operation_type": "get",
                "cache_name": "scan_results",
                "key_hash": "test_key1",
                "size_bytes": 1024,
            },
        ]

        service.track_cache_operations_bulk(operations_without_timestamps)

        result = db_session.query(CacheOperationMetric).first()
        assert result.timestamp is not None

    def test_service_track_operations_preserve_timestamps(self, db_session):
        """Test service operations preserve existing timestamps."""
        service = OptimizedTelemetryService(db_session)

        custom_timestamp = 1234567890.0
        operations_with_timestamps = [
            {
                "operation_type": "get",
                "cache_name": "scan_results",
                "key_hash": "test_key1",
                "size_bytes": 1024,
                "timestamp": custom_timestamp,
            },
        ]

        service.track_cache_operations_bulk(operations_with_timestamps)

        result = db_session.query(CacheOperationMetric).first()
        assert result.timestamp == custom_timestamp

    def test_batch_processor_empty_data(self, db_session):
        """Test batch processor with empty data."""
        processor = BatchProcessor(db_session)

        results = processor.process_telemetry_batch([])

        assert all(count == 0 for key, count in results.items())

    def test_batch_processor_unsupported_types(self, db_session):
        """Test batch processor with unsupported data types."""
        processor = BatchProcessor(db_session)

        telemetry_data = [
            {"_type": "unsupported_type", "data": "test"},
            {"_type": "another_unsupported", "data": "test2"},
        ]

        results = processor.process_telemetry_batch(telemetry_data)

        # Should process without errors but no inserts
        assert all(count == 0 for count in results.values())


# Integration tests
class TestIntegration:
    """Integration tests for bulk operations."""

    def test_full_bulk_workflow(self, db_session):
        """Test complete bulk operation workflow."""
        service = OptimizedTelemetryService(db_session)

        # Enable bulk mode
        service.enable_bulk_mode()

        # Add various types of telemetry data
        service.track_mcp_tool_execution_bulk(
            tool_name="test_tool",
            session_id="test_session",
            request_params={"param": "value"},
        )

        service.track_cli_command_execution_bulk(
            command_name="test_command",
            args={"arg": "value"},
        )

        service.track_cache_operations_bulk(
            [
                {
                    "operation_type": "get",
                    "cache_name": "scan_results",
                    "key_hash": "test_key",
                    "size_bytes": 1024,
                },
            ]
        )

        service.track_threat_findings_bulk(
            [
                {
                    "scan_id": "scan-123",
                    "finding_uuid": "finding-1",
                    "scanner_source": "semgrep",
                    "rule_id": "rule1",
                    "category": "injection",
                    "severity": "high",
                    "file_path": "/test/file.py",
                    "line_start": 10,
                    "line_end": 12,
                    "title": "Test Finding",
                },
            ]
        )

        # Check pending counts
        stats = service.get_bulk_stats()
        assert len(stats["pending_operations"]) == 4  # 4 different model types

        # Disable bulk mode (should flush all)
        service.disable_bulk_mode()

        # Verify data was written to database
        assert db_session.query(MCPToolExecution).count() == 1
        assert db_session.query(CLICommandExecution).count() == 1
        assert db_session.query(CacheOperationMetric).count() == 1
        assert db_session.query(ThreatFinding).count() == 1

    def test_bulk_context_manager_with_exception(self, db_session):
        """Test bulk context manager handles exceptions gracefully."""
        try:
            with bulk_telemetry_context(db_session) as service:
                service.track_mcp_tool_execution_bulk(
                    tool_name="test_tool",
                    session_id="test_session",
                    request_params={"param": "value"},
                )
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Data should still be flushed even with exception
        assert db_session.query(MCPToolExecution).count() == 1

    def test_mixed_bulk_and_immediate_operations(self, db_session):
        """Test mixing bulk and immediate operations."""
        service = OptimizedTelemetryService(db_session)

        # Start with immediate mode
        service.track_mcp_tool_execution_bulk(
            tool_name="immediate_tool",
            session_id="test_session",
            request_params={"param": "value"},
        )

        # Switch to bulk mode
        service.enable_bulk_mode()
        service.track_mcp_tool_execution_bulk(
            tool_name="bulk_tool",
            session_id="test_session",
            request_params={"param": "value"},
        )

        # Check counts
        assert db_session.query(MCPToolExecution).count() == 1  # Only immediate

        # Disable bulk mode
        service.disable_bulk_mode()

        # Now should have both
        assert db_session.query(MCPToolExecution).count() == 2

        tools = db_session.query(MCPToolExecution).all()
        tool_names = [t.tool_name for t in tools]
        assert "immediate_tool" in tool_names
        assert "bulk_tool" in tool_names
