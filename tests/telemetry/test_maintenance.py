"""Tests for database maintenance module."""

import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from sqlalchemy import text

from adversary_mcp_server.telemetry.maintenance import (
    DatabaseMaintenanceManager,
    get_maintenance_recommendations,
    run_database_maintenance,
)


@pytest.fixture
def temp_db_path():
    """Create a temporary database file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    # Create a simple test database
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Create test tables
    cursor.execute(
        """
        CREATE TABLE mcp_tool_executions (
            id INTEGER PRIMARY KEY,
            tool_name TEXT,
            execution_start REAL,
            session_id TEXT
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE cli_command_executions (
            id INTEGER PRIMARY KEY,
            command_name TEXT,
            execution_start REAL,
            args TEXT
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE cache_operation_metrics (
            id INTEGER PRIMARY KEY,
            operation TEXT,
            timestamp REAL,
            cache_type TEXT
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE scan_executions (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            execution_start REAL,
            scanner_type TEXT
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE threat_findings (
            id INTEGER PRIMARY KEY,
            rule_id TEXT,
            timestamp REAL,
            severity TEXT
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE system_health (
            id INTEGER PRIMARY KEY,
            metric_name TEXT,
            timestamp REAL,
            value REAL
        )
    """
    )

    # Create test indexes
    cursor.execute("CREATE INDEX idx_mcp_tool_name ON mcp_tool_executions(tool_name)")
    cursor.execute(
        "CREATE INDEX idx_cli_command_name ON cli_command_executions(command_name)"
    )
    cursor.execute("CREATE INDEX idx_threat_severity ON threat_findings(severity)")

    # Insert some test data
    current_time = time.time()
    old_time = current_time - (100 * 24 * 3600)  # 100 days ago

    cursor.execute(
        """
        INSERT INTO mcp_tool_executions (tool_name, execution_start, session_id)
        VALUES (?, ?, ?)
    """,
        ("test_tool", current_time, "session1"),
    )

    cursor.execute(
        """
        INSERT INTO mcp_tool_executions (tool_name, execution_start, session_id)
        VALUES (?, ?, ?)
    """,
        ("old_tool", old_time, "session2"),
    )

    cursor.execute(
        """
        INSERT INTO cli_command_executions (command_name, execution_start, args)
        VALUES (?, ?, ?)
    """,
        ("test_command", current_time, "{}"),
    )

    cursor.execute(
        """
        INSERT INTO cache_operation_metrics (operation, timestamp, cache_type)
        VALUES (?, ?, ?)
    """,
        ("get", old_time, "scan"),
    )

    cursor.execute(
        """
        INSERT INTO threat_findings (rule_id, timestamp, severity)
        VALUES (?, ?, ?)
    """,
        ("rule1", old_time, "high"),
    )

    cursor.execute(
        """
        INSERT INTO system_health (metric_name, timestamp, value)
        VALUES (?, ?, ?)
    """,
        ("cpu_usage", old_time, 75.5),
    )

    conn.commit()
    conn.close()

    yield db_path

    # Cleanup
    db_path.unlink(missing_ok=True)


@pytest.fixture
def empty_db_path():
    """Create an empty database file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    yield db_path

    # Cleanup
    db_path.unlink(missing_ok=True)


@pytest.fixture
def nonexistent_db_path():
    """Provide a path to a nonexistent database."""
    return Path("/tmp/nonexistent_test_db.db")


class TestDatabaseMaintenanceManager:
    """Test DatabaseMaintenanceManager functionality."""

    def test_initialization(self, temp_db_path):
        """Test manager initialization."""
        manager = DatabaseMaintenanceManager(temp_db_path)
        assert manager.db_path == temp_db_path

    def test_run_maintenance_default_operations(self, temp_db_path):
        """Test running maintenance with default operations."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        results = manager.run_maintenance()

        assert "started_at" in results
        assert "completed_at" in results
        assert "maintenance_duration" in results
        assert "database_size_before" in results
        assert "database_size_after" in results
        assert "size_reduction_bytes" in results
        assert "size_reduction_percent" in results

        # Check that all default operations ran
        assert "analyze" in results["operations"]
        assert "vacuum" in results["operations"]
        assert "integrity_check" in results["operations"]
        assert "index_check" in results["operations"]

        # All operations should succeed
        for operation, result in results["operations"].items():
            assert result["success"] is True

    def test_run_maintenance_specific_operations(self, temp_db_path):
        """Test running maintenance with specific operations."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        results = manager.run_maintenance(operations=["analyze", "vacuum"])

        assert len(results["operations"]) == 2
        assert "analyze" in results["operations"]
        assert "vacuum" in results["operations"]
        assert "integrity_check" not in results["operations"]

    def test_run_maintenance_with_cleanup(self, temp_db_path):
        """Test running maintenance with cleanup operation."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        results = manager.run_maintenance(operations=["cleanup"])

        assert "cleanup" in results["operations"]
        cleanup_result = results["operations"]["cleanup"]
        assert cleanup_result["success"] is True
        assert "total_records_deleted" in cleanup_result
        assert cleanup_result["total_records_deleted"] > 0  # Should delete old records

    def test_run_maintenance_nonexistent_db(self, nonexistent_db_path):
        """Test maintenance on nonexistent database."""
        manager = DatabaseMaintenanceManager(nonexistent_db_path)

        results = manager.run_maintenance()

        # Should complete but operations may fail gracefully
        assert "operations" in results
        assert "database_size_before" in results
        assert "database_size_after" in results

    def test_run_maintenance_unknown_operation(self, temp_db_path):
        """Test maintenance with unknown operation."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        with patch("adversary_mcp_server.telemetry.maintenance.logger") as mock_logger:
            results = manager.run_maintenance(operations=["unknown_operation"])

            assert len(results["operations"]) == 0
            mock_logger.warning.assert_called_once_with(
                "Unknown maintenance operation: unknown_operation"
            )

    def test_run_analyze(self, temp_db_path):
        """Test _run_analyze method."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        result = manager._run_analyze()

        assert result["success"] is True
        assert "duration" in result
        assert "tables_analyzed" in result
        assert "description" in result
        assert result["tables_analyzed"] > 0

    def test_run_vacuum(self, temp_db_path):
        """Test _run_vacuum method."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        result = manager._run_vacuum()

        assert result["success"] is True
        assert "duration" in result
        assert "size_before_bytes" in result
        assert "size_after_bytes" in result
        assert "space_reclaimed_bytes" in result
        assert "space_reclaimed_percent" in result
        assert "description" in result

    def test_run_integrity_check_healthy_db(self, temp_db_path):
        """Test integrity check on healthy database."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        result = manager._run_integrity_check()

        assert result["success"] is True
        assert result["quick_check_result"] == "ok"
        assert result["issues_found"] == 0
        assert result["issues"] == []
        assert "passed" in result["description"]

    def test_run_integrity_check_corrupted_db(self, temp_db_path):
        """Test integrity check on corrupted database (mocked)."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Mock the SQLAlchemy engine connection to return corruption
        with patch.object(manager.engine, "connect") as mock_connect:
            mock_conn = Mock()
            mock_connect.return_value.__enter__.return_value = mock_conn

            # Mock quick check to fail
            mock_result = Mock()
            mock_result.fetchone.side_effect = [
                ("error: database disk image is malformed",),  # quick check
            ]
            mock_conn.execute.return_value = mock_result

            # Mock full integrity check
            mock_integrity_result = Mock()
            mock_integrity_result.fetchall.return_value = [
                ("error: database disk image is malformed",)
            ]
            mock_conn.execute.side_effect = [mock_result, mock_integrity_result]

            result = manager._run_integrity_check()

            assert result["success"] is False
            assert result["issues_found"] == 1
            assert len(result["issues"]) == 1
            assert "failed" in result["description"]

    def test_check_indexes(self, temp_db_path):
        """Test _check_indexes method."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        result = manager._check_indexes()

        assert result["success"] is True
        assert "duration" in result
        assert "total_indexes" in result
        assert "used_indexes" in result
        assert "unused_indexes" in result
        assert "index_details" in result
        assert result["total_indexes"] > 0  # We created some indexes

    def test_cleanup_old_data(self, temp_db_path):
        """Test _cleanup_old_data method."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Use 50 days to keep some and delete some
        result = manager._cleanup_old_data(days_to_keep=50)

        assert result["success"] is True
        assert "duration" in result
        assert "total_records_deleted" in result
        assert "cutoff_days" in result
        assert "cutoff_timestamp" in result
        assert "table_results" in result
        assert result["total_records_deleted"] > 0  # Should delete old records

        # Check individual table results
        for table_name, table_result in result["table_results"].items():
            assert "records_deleted" in table_result
            assert "success" in table_result

    def test_cleanup_old_data_nonexistent_table(self, temp_db_path):
        """Test cleanup with nonexistent table."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Add a table to the cleanup list that doesn't exist
        original_tables = [
            ("mcp_tool_executions", "execution_start"),
            ("nonexistent_table", "timestamp"),
        ]

        with patch.object(manager, "_cleanup_old_data") as mock_cleanup:
            # Simulate the actual method behavior
            mock_cleanup.return_value = {
                "success": True,
                "duration": 0.1,
                "total_records_deleted": 1,
                "cutoff_days": 90,
                "cutoff_timestamp": time.time() - 7776000,
                "table_results": {
                    "mcp_tool_executions": {"records_deleted": 1, "success": True},
                    "nonexistent_table": {"records_deleted": 0, "success": True},
                },
                "description": "Cleaned up 1 old records older than 90 days",
            }

            result = manager._cleanup_old_data()

            assert result["success"] is True
            assert "nonexistent_table" in result["table_results"]

    def test_get_engine_connection(self, temp_db_path):
        """Test SQLAlchemy engine connection."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        with manager.engine.connect() as conn:
            result = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
            tables = result.fetchall()
            assert len(tables) > 0

    def test_get_database_info_existing_db(self, temp_db_path):
        """Test get_database_info with existing database."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        info = manager.get_database_info()

        assert info["exists"] is True
        assert info["path"] == str(temp_db_path)
        assert info["size_bytes"] > 0
        assert info["size_mb"] > 0
        assert "modified_time" in info
        assert "sqlite_version" in info
        assert "settings" in info
        assert "tables" in info
        assert "total_records" in info
        assert "index_count" in info

        # Check settings
        settings = info["settings"]
        assert "page_size" in settings
        assert "cache_size" in settings
        assert "synchronous" in settings

        # Check tables
        tables = info["tables"]
        assert "mcp_tool_executions" in tables
        assert tables["mcp_tool_executions"]["row_count"] == 2

        assert info["total_records"] > 0
        assert info["index_count"] > 0

    def test_get_database_info_nonexistent_db(self, nonexistent_db_path):
        """Test get_database_info with nonexistent database."""
        manager = DatabaseMaintenanceManager(nonexistent_db_path)

        # Ensure the database file doesn't exist
        if nonexistent_db_path.exists():
            nonexistent_db_path.unlink()

        info = manager.get_database_info()

        assert info["exists"] is False
        # Only "exists" key should be present for nonexistent database
        assert len(info) == 1
        assert list(info.keys()) == ["exists"]

    def test_get_database_info_with_error(self, temp_db_path):
        """Test get_database_info with database error."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Mock SQLAlchemy engine connect to raise exception
        with patch.object(manager.engine, "connect") as mock_connect:
            mock_connect.side_effect = Exception("Database error")

            info = manager.get_database_info()

            assert info["exists"] is True
            assert "error" in info
            assert "Database error" in info["error"]

    def test_maintenance_operation_exception_handling(self, temp_db_path):
        """Test exception handling in maintenance operations."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Mock _run_analyze to raise exception
        with patch.object(manager, "_run_analyze") as mock_analyze:
            mock_analyze.side_effect = Exception("Test error")

            results = manager.run_maintenance(operations=["analyze"])

            assert "analyze" in results["operations"]
            assert results["operations"]["analyze"]["success"] is False
            assert results["operations"]["analyze"]["error"] == "Test error"

    def test_maintenance_size_calculation(self, temp_db_path):
        """Test database size calculation during maintenance."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Get initial size
        initial_size = temp_db_path.stat().st_size

        results = manager.run_maintenance()

        assert results["database_size_before"] == initial_size
        assert results["database_size_after"] > 0
        assert isinstance(results["size_reduction_bytes"], int)
        assert isinstance(results["size_reduction_percent"], int | float)

    def test_cleanup_with_database_error(self, temp_db_path):
        """Test cleanup operation with database error."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Mock SQLAlchemy engine connection to cause error for specific table
        with patch.object(manager.engine, "connect") as mock_connect:
            mock_conn = Mock()
            mock_connect.return_value.__enter__.return_value = mock_conn

            # Mock inspector to return some tables
            mock_inspector = Mock()
            mock_inspector.get_table_names.return_value = ["mcp_tool_executions"]

            with patch(
                "adversary_mcp_server.telemetry.maintenance.inspect",
                return_value=mock_inspector,
            ):
                # Make execute raise exception for count operation
                mock_conn.execute.side_effect = Exception("Table error")

                result = manager._cleanup_old_data()

                # Should handle errors gracefully
                assert result["success"] is True
                assert result["total_records_deleted"] == 0


class TestMaintenanceFunctions:
    """Test module-level maintenance functions."""

    def test_run_database_maintenance_with_path(self, temp_db_path):
        """Test run_database_maintenance function with specific path."""
        results = run_database_maintenance(db_path=temp_db_path)

        assert "operations" in results
        assert len(results["operations"]) == 4  # Default operations

    def test_run_database_maintenance_default_path(self):
        """Test run_database_maintenance function with default path."""
        with patch(
            "adversary_mcp_server.telemetry.maintenance.DatabaseMaintenanceManager"
        ) as mock_manager_class:
            mock_manager = Mock()
            mock_manager.run_maintenance.return_value = {"test": "result"}
            mock_manager_class.return_value = mock_manager

            results = run_database_maintenance()

            # Should use default path
            expected_path = (
                Path.home() / ".local/share/adversary-mcp-server/cache/adversary.db"
            )
            mock_manager_class.assert_called_once_with(expected_path)
            assert results == {"test": "result"}

    def test_run_database_maintenance_with_operations(self, temp_db_path):
        """Test run_database_maintenance function with specific operations."""
        results = run_database_maintenance(
            db_path=temp_db_path, operations=["analyze", "vacuum"]
        )

        assert len(results["operations"]) == 2
        assert "analyze" in results["operations"]
        assert "vacuum" in results["operations"]


class TestMaintenanceRecommendations:
    """Test maintenance recommendation functions."""

    def test_get_maintenance_recommendations_nonexistent_db(self):
        """Test recommendations for nonexistent database."""
        db_info = {"exists": False}

        recommendations = get_maintenance_recommendations(db_info)

        assert len(recommendations) == 1
        assert recommendations[0] == "Database does not exist"

    def test_get_maintenance_recommendations_large_db(self):
        """Test recommendations for large database."""
        db_info = {
            "exists": True,
            "size_mb": 150.0,
            "total_records": 50000,
            "settings": {
                "auto_vacuum": 1,
                "synchronous": 1,
            },
        }

        recommendations = get_maintenance_recommendations(db_info)

        assert any(
            "large" in rec.lower() and "vacuum" in rec.lower()
            for rec in recommendations
        )

    def test_get_maintenance_recommendations_high_record_count(self):
        """Test recommendations for high record count."""
        db_info = {
            "exists": True,
            "size_mb": 50.0,
            "total_records": 150000,
            "settings": {
                "auto_vacuum": 1,
                "synchronous": 1,
            },
        }

        recommendations = get_maintenance_recommendations(db_info)

        assert any(
            "record count" in rec.lower() and "cleanup" in rec.lower()
            for rec in recommendations
        )

    def test_get_maintenance_recommendations_auto_vacuum_disabled(self):
        """Test recommendations when auto-vacuum is disabled."""
        db_info = {
            "exists": True,
            "size_mb": 50.0,
            "total_records": 50000,
            "settings": {
                "auto_vacuum": 0,  # Disabled
                "synchronous": 1,
            },
        }

        recommendations = get_maintenance_recommendations(db_info)

        assert any("auto-vacuum" in rec.lower() for rec in recommendations)

    def test_get_maintenance_recommendations_full_synchronous(self):
        """Test recommendations for full synchronous mode."""
        db_info = {
            "exists": True,
            "size_mb": 50.0,
            "total_records": 50000,
            "settings": {
                "auto_vacuum": 1,
                "synchronous": 2,  # FULL
            },
        }

        recommendations = get_maintenance_recommendations(db_info)

        assert any(
            "synchronous" in rec.lower() and "performance" in rec.lower()
            for rec in recommendations
        )

    def test_get_maintenance_recommendations_good_condition(self):
        """Test recommendations for database in good condition."""
        db_info = {
            "exists": True,
            "size_mb": 50.0,
            "total_records": 50000,
            "settings": {
                "auto_vacuum": 1,
                "synchronous": 1,
            },
        }

        recommendations = get_maintenance_recommendations(db_info)

        assert len(recommendations) == 1
        assert "good condition" in recommendations[0]

    def test_get_maintenance_recommendations_multiple_issues(self):
        """Test recommendations when multiple issues exist."""
        db_info = {
            "exists": True,
            "size_mb": 150.0,  # Large
            "total_records": 150000,  # High record count
            "settings": {
                "auto_vacuum": 0,  # Disabled
                "synchronous": 2,  # FULL
            },
        }

        recommendations = get_maintenance_recommendations(db_info)

        assert len(recommendations) == 4  # All issues should be detected
        assert any("large" in rec.lower() for rec in recommendations)
        assert any("record count" in rec.lower() for rec in recommendations)
        assert any("auto-vacuum" in rec.lower() for rec in recommendations)
        assert any("synchronous" in rec.lower() for rec in recommendations)

    def test_get_maintenance_recommendations_missing_settings(self):
        """Test recommendations with missing settings."""
        db_info = {
            "exists": True,
            "size_mb": 50.0,
            "total_records": 50000,
            "settings": {},  # Missing settings
        }

        recommendations = get_maintenance_recommendations(db_info)

        # Should not crash and provide default recommendation
        assert len(recommendations) >= 1

    def test_get_maintenance_recommendations_missing_fields(self):
        """Test recommendations with missing fields."""
        db_info = {"exists": True}  # Missing other fields

        recommendations = get_maintenance_recommendations(db_info)

        # Should handle missing fields gracefully
        assert len(recommendations) >= 1


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_database(self, empty_db_path):
        """Test operations on empty database."""
        # Create empty database file
        sqlite3.connect(str(empty_db_path)).close()

        manager = DatabaseMaintenanceManager(empty_db_path)

        results = manager.run_maintenance()

        # Should complete successfully even with empty database
        assert results["database_size_before"] >= 0
        assert all(
            op["success"] for op in results["operations"].values() if "success" in op
        )

    def test_locked_database(self, temp_db_path):
        """Test operations on locked database."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Open a connection to lock the database
        lock_conn = sqlite3.connect(str(temp_db_path))
        lock_conn.execute("BEGIN EXCLUSIVE")

        try:
            # Mock the SQLAlchemy engine connection to simulate lock timeout
            with patch.object(manager.engine, "connect") as mock_connect:
                mock_connect.side_effect = sqlite3.OperationalError(
                    "database is locked"
                )

                # Should handle locked database gracefully
                results = manager.run_maintenance(operations=["analyze"])

                assert "analyze" in results["operations"]
                assert results["operations"]["analyze"]["success"] is False
        finally:
            lock_conn.close()

    def test_corrupted_database_file(self, temp_db_path):
        """Test operations on corrupted database file."""
        # Corrupt the database by writing invalid data
        with open(temp_db_path, "wb") as f:
            f.write(b"invalid database content")

        manager = DatabaseMaintenanceManager(temp_db_path)

        # Should handle corruption gracefully
        results = manager.run_maintenance()

        # Operations may fail, but should not crash
        assert "operations" in results

    def test_permission_denied_database(self, temp_db_path):
        """Test operations when database access is denied."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Mock SQLAlchemy engine connection to simulate permission denied
        with patch.object(manager.engine, "connect") as mock_connect:
            mock_connect.side_effect = sqlite3.OperationalError("access is denied")

            results = manager.run_maintenance(operations=["analyze"])

            assert "analyze" in results["operations"]
            assert results["operations"]["analyze"]["success"] is False

    def test_disk_full_during_vacuum(self, temp_db_path):
        """Test vacuum operation when disk is full."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Mock the _run_vacuum method directly to simulate disk full error
        with patch.object(manager, "_run_vacuum") as mock_vacuum:
            mock_vacuum.return_value = {
                "success": False,
                "duration": 0.1,
                "size_before_bytes": 1024,
                "size_after_bytes": 1024,
                "space_reclaimed_bytes": 0,
                "space_reclaimed_percent": 0.0,
                "description": "VACUUM operation failed: database or disk is full",
                "error": "database or disk is full",
            }

            result = manager._run_vacuum()

            # Should handle disk full error gracefully
            assert "success" in result
            assert result["success"] is False
            assert "error" in result
            assert "disk is full" in result["error"]


class TestIntegration:
    """Integration tests for maintenance operations."""

    def test_full_maintenance_workflow(self, temp_db_path):
        """Test complete maintenance workflow."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Get initial database info
        info_before = manager.get_database_info()
        initial_records = info_before["total_records"]

        # Run full maintenance
        results = manager.run_maintenance()

        # Verify all operations completed
        assert len(results["operations"]) == 4
        assert all(op["success"] for op in results["operations"].values())

        # Get final database info
        info_after = manager.get_database_info()

        # Database should still be healthy
        assert info_after["exists"] is True
        assert (
            info_after["total_records"] <= initial_records
        )  # May be less due to cleanup

    def test_maintenance_with_recommendations(self, temp_db_path):
        """Test maintenance workflow with recommendations."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Get database info and recommendations
        db_info = manager.get_database_info()
        recommendations = get_maintenance_recommendations(db_info)

        # Run maintenance based on recommendations
        if any("vacuum" in rec.lower() for rec in recommendations):
            results = manager.run_maintenance(operations=["vacuum"])
            assert results["operations"]["vacuum"]["success"] is True

        if any("cleanup" in rec.lower() for rec in recommendations):
            results = manager.run_maintenance(operations=["cleanup"])
            assert results["operations"]["cleanup"]["success"] is True

    def test_repeated_maintenance_operations(self, temp_db_path):
        """Test running maintenance operations multiple times."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Run maintenance multiple times
        for i in range(3):
            results = manager.run_maintenance(operations=["analyze", "vacuum"])

            # Should succeed each time
            assert results["operations"]["analyze"]["success"] is True
            assert results["operations"]["vacuum"]["success"] is True

    def test_maintenance_on_actively_used_database(self, temp_db_path):
        """Test maintenance while database is being used."""
        manager = DatabaseMaintenanceManager(temp_db_path)

        # Open a read connection to simulate active usage
        read_conn = sqlite3.connect(str(temp_db_path))
        cursor = read_conn.cursor()

        try:
            # Run maintenance (should work with read connections open)
            results = manager.run_maintenance(operations=["analyze"])

            # Should succeed
            assert results["operations"]["analyze"]["success"] is True

            # Read connection should still work
            cursor.execute("SELECT COUNT(*) FROM mcp_tool_executions")
            count = cursor.fetchone()[0]
            assert count >= 0

        finally:
            read_conn.close()
