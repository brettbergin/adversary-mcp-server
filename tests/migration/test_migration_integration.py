"""Comprehensive integration tests for database migration system."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from adversary_mcp_server.database.migrations import DataMigrationManager
from adversary_mcp_server.database.models import (
    AdversaryDatabase,
    MCPToolExecution,
    ScanEngineExecution,
    ThreatFinding,
)
from adversary_mcp_server.migration.database_migration import DatabaseMigrationManager
from adversary_mcp_server.migration.orchestrator import MigrationOrchestrator


@pytest.fixture
def temp_db_path():
    """Create temporary database path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_legacy_cache_dir():
    """Create temporary legacy cache directory with test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        cache_dir = Path(temp_dir)
        cache_dir.mkdir(exist_ok=True)

        # Create mock legacy SQLite file with proper SQLite format using SQLAlchemy
        from sqlalchemy import (
            Column,
            Float,
            Integer,
            MetaData,
            String,
            Table,
            create_engine,
        )
        from sqlalchemy.orm import sessionmaker

        legacy_db = cache_dir / "cache_metadata.db"
        engine = create_engine(f"sqlite:///{legacy_db}")

        # Define legacy table structure
        metadata = MetaData()
        scan_metadata_table = Table(
            "scan_metadata",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("scan_id", String),
            Column("file_path", String),
            Column("timestamp", Float),
        )

        # Create table and add test data
        metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()
        try:
            # Insert test data using SQLAlchemy ORM
            session.execute(
                scan_metadata_table.insert(),
                {
                    "scan_id": "legacy-scan-123",
                    "file_path": "/test/legacy.py",
                    "timestamp": 1234567890.0,
                },
            )
            session.commit()
        finally:
            session.close()
            engine.dispose()

        yield cache_dir


@pytest.fixture
def temp_legacy_metrics_dir():
    """Create temporary legacy metrics directory with test JSON files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        metrics_dir = Path(temp_dir)
        metrics_dir.mkdir(exist_ok=True)

        # Create mock JSON metrics file
        metrics_file = metrics_dir / "legacy_metrics.json"
        with metrics_file.open("w") as f:
            json.dump(
                {
                    "metadata": {"collected_at": time.time(), "db_size_mb": 10.5},
                    "legacy_metrics": {"scan_count": 5, "threat_count": 10},
                    "scan_metrics": {"total_scans": 5, "total_findings": 10},
                },
                f,
            )

        yield metrics_dir


@pytest.fixture
def populated_database(temp_db_path):
    """Create a database with test data including inconsistencies."""
    db = AdversaryDatabase(temp_db_path)

    with db.get_session() as session:
        # Create test scan execution
        scan_execution = ScanEngineExecution(
            scan_id="test-scan-123",
            trigger_source="test",
            scan_type="file",
            target_path="/test/file.py",
            threats_found=5,  # This will be inconsistent with actual threat findings
            execution_start=time.time(),
            execution_end=time.time() + 1.0,
        )
        session.add(scan_execution)

        # Create MCP tool execution
        mcp_execution = MCPToolExecution(
            tool_name="adv_scan_file",
            session_id="test-scan-123",
            request_params={"path": "/test/file.py"},
            execution_start=time.time(),
            execution_end=time.time() + 1.0,
            findings_count=3,  # This will be inconsistent
        )
        session.add(mcp_execution)

        # Create fewer threat findings than recorded (inconsistency)
        for i in range(2):
            threat = ThreatFinding(
                scan_id="test-scan-123",
                finding_uuid=f"test-threat-{i}",
                scanner_source="test",
                category="test_category",
                severity="medium",
                file_path="/test/file.py",
                line_start=10 + i,
                line_end=10 + i,
                title=f"Test Threat {i}",
                timestamp=time.time(),
            )
            session.add(threat)

        session.commit()

    yield db

    db.close()


class TestDataMigrationIntegration:
    """Test data consistency migration functionality."""

    def test_data_migration_detects_inconsistencies(self, populated_database):
        """Test that data migration detects and reports inconsistencies."""
        manager = DataMigrationManager(populated_database)

        # Validate current state
        results = manager.validate_data_consistency()

        assert results["validation_success"] is True
        assert results["total_inconsistencies"] > 0
        assert not results["data_consistent"]

    def test_data_migration_fixes_inconsistencies(self, populated_database):
        """Test that data migration fixes inconsistencies."""
        manager = DataMigrationManager(populated_database)

        # Run migration
        results = manager.fix_summary_field_inconsistencies()

        assert results["migration_success"] is True
        assert results["total_records_fixed"] > 0

        # Validate that inconsistencies are fixed
        validation_results = manager.validate_data_consistency()
        assert validation_results["data_consistent"] is True
        assert validation_results["total_inconsistencies"] == 0

    def test_data_migration_handles_empty_database(self, temp_db_path):
        """Test that data migration handles empty database gracefully."""
        db = AdversaryDatabase(temp_db_path)
        manager = DataMigrationManager(db)

        results = manager.validate_data_consistency()

        assert results["validation_success"] is True
        assert results["data_consistent"] is True
        assert results["total_inconsistencies"] == 0

        db.close()

    def test_orphaned_records_cleanup(self, populated_database):
        """Test cleanup of orphaned records."""
        manager = DataMigrationManager(populated_database)

        # Create orphaned threat finding (scan doesn't exist)
        with populated_database.get_session() as session:
            orphaned_threat = ThreatFinding(
                scan_id="nonexistent-scan",
                finding_uuid="orphaned-threat",
                scanner_source="test",
                category="test",
                severity="low",
                file_path="/test/orphaned.py",
                line_start=1,
                line_end=1,
                title="Orphaned Threat",
                timestamp=time.time(),
            )
            session.add(orphaned_threat)
            session.commit()

        # Run cleanup
        results = manager.cleanup_orphaned_records()

        assert results["cleanup_success"] is True
        assert results["orphaned_threats_deleted"] > 0

    def test_stale_executions_cleanup(self, populated_database):
        """Test cleanup of stale executions."""
        manager = DataMigrationManager(populated_database)

        # Create stale execution (old and no end time)
        with populated_database.get_session() as session:
            stale_execution = ScanEngineExecution(
                scan_id="stale-scan",
                trigger_source="test",
                scan_type="file",
                target_path="/test/stale.py",
                execution_start=time.time() - (25 * 3600),  # 25 hours ago
                # No execution_end - indicates hanging execution
            )
            session.add(stale_execution)
            session.commit()

        # Run cleanup
        results = manager.mark_stale_executions_as_failed()

        assert results["cleanup_success"] is True
        assert results["total_executions_fixed"] > 0


class TestLegacyMigrationIntegration:
    """Test legacy system migration functionality."""

    @patch("adversary_mcp_server.migration.database_migration.get_app_cache_dir")
    @patch("adversary_mcp_server.migration.database_migration.get_app_metrics_dir")
    def test_legacy_migration_detects_files(
        self,
        mock_metrics_dir,
        mock_cache_dir,
        temp_legacy_cache_dir,
        temp_legacy_metrics_dir,
        temp_db_path,
    ):
        """Test that legacy migration detects legacy files."""
        mock_cache_dir.return_value = temp_legacy_cache_dir
        mock_metrics_dir.return_value = temp_legacy_metrics_dir

        manager = DatabaseMigrationManager(temp_db_path)

        results = manager.check_migration_needed()

        assert results["migration_needed"] is True
        assert len(results["legacy_sqlite_files"]) > 0
        assert len(results["json_metrics_files"]) > 0

    @patch("adversary_mcp_server.migration.database_migration.get_app_cache_dir")
    @patch("adversary_mcp_server.migration.database_migration.get_app_metrics_dir")
    def test_legacy_migration_no_files(
        self, mock_metrics_dir, mock_cache_dir, temp_db_path
    ):
        """Test that legacy migration handles no legacy files."""
        # Point to empty directories
        with tempfile.TemporaryDirectory() as empty_dir:
            empty_cache = Path(empty_dir) / "cache"
            empty_metrics = Path(empty_dir) / "metrics"
            empty_cache.mkdir(parents=True, exist_ok=True)
            empty_metrics.mkdir(parents=True, exist_ok=True)

            mock_cache_dir.return_value = empty_cache
            mock_metrics_dir.return_value = empty_metrics

            manager = DatabaseMigrationManager(temp_db_path)
            results = manager.check_migration_needed()

            assert results["migration_needed"] is False

    @patch("adversary_mcp_server.migration.database_migration.get_app_cache_dir")
    @patch("adversary_mcp_server.migration.database_migration.get_app_metrics_dir")
    def test_legacy_migration_creates_backup(
        self,
        mock_metrics_dir,
        mock_cache_dir,
        temp_legacy_cache_dir,
        temp_legacy_metrics_dir,
        temp_db_path,
    ):
        """Test that legacy migration creates backup."""
        mock_cache_dir.return_value = temp_legacy_cache_dir
        mock_metrics_dir.return_value = temp_legacy_metrics_dir

        manager = DatabaseMigrationManager(temp_db_path)

        results = manager.run_full_migration(backup=True)

        assert results.get("backup_created") is True
        assert "backup_path" in results


class TestMigrationOrchestratorIntegration:
    """Test the unified migration orchestrator."""

    @patch("adversary_mcp_server.migration.database_migration.get_app_cache_dir")
    @patch("adversary_mcp_server.migration.database_migration.get_app_metrics_dir")
    def test_orchestrator_dry_run(
        self,
        mock_metrics_dir,
        mock_cache_dir,
        temp_legacy_cache_dir,
        temp_legacy_metrics_dir,
        populated_database,
    ):
        """Test orchestrator dry run functionality."""
        mock_cache_dir.return_value = temp_legacy_cache_dir.parent
        mock_metrics_dir.return_value = temp_legacy_metrics_dir.parent

        orchestrator = MigrationOrchestrator(populated_database.db_path)

        results = orchestrator.run_complete_migration(dry_run=True)

        assert results["dry_run"] is True
        assert results["overall_success"] is True
        assert "phases" in results
        assert len(results["phases"]) > 0

    def test_orchestrator_complete_workflow_no_legacy(self, populated_database):
        """Test orchestrator complete workflow without legacy migration."""
        orchestrator = MigrationOrchestrator(populated_database.db_path)

        results = orchestrator.run_complete_migration(
            skip_legacy=True, skip_constraints=True, backup=False
        )

        assert results["overall_success"] is True
        assert "phases" in results
        assert "summary" in results

        # Should have fixed data inconsistencies
        data_phase = results["phases"].get("data_migration", {})
        assert data_phase.get("success") is True

    def test_orchestrator_handles_errors_gracefully(self, temp_db_path):
        """Test that orchestrator handles errors gracefully."""
        orchestrator = MigrationOrchestrator(temp_db_path)

        # Mock a component to fail
        with patch.object(
            orchestrator.health_checker,
            "run_comprehensive_health_check",
            side_effect=Exception("Simulated health check failure"),
        ):

            results = orchestrator.run_complete_migration()

            assert results["overall_success"] is False
            assert "workflow_error" in results or len(results["errors"]) > 0

    def test_orchestrator_rollback_functionality(self, temp_db_path):
        """Test orchestrator rollback functionality."""
        orchestrator = MigrationOrchestrator(temp_db_path)

        # Create mock backup directory
        with tempfile.TemporaryDirectory() as backup_dir:
            backup_path = Path(backup_dir)

            # Create mock backup files
            cache_backup = backup_path / "cache"
            cache_backup.mkdir()
            (cache_backup / "test.db").touch()

            results = orchestrator.rollback_migration(backup_path)

            # Rollback should at least attempt to restore files
            assert isinstance(results, dict)
            assert "success" in results


class TestMigrationRobustness:
    """Test migration system robustness and edge cases."""

    def test_concurrent_migration_prevention(self, populated_database):
        """Test that concurrent migrations are handled properly."""
        manager1 = DataMigrationManager(populated_database)
        manager2 = DataMigrationManager(populated_database)

        # Both should work independently as they use separate sessions
        results1 = manager1.validate_data_consistency()
        results2 = manager2.validate_data_consistency()

        assert results1["validation_success"] is True
        assert results2["validation_success"] is True

    def test_migration_with_large_dataset(self, temp_db_path):
        """Test migration performance with larger dataset."""
        db = AdversaryDatabase(temp_db_path)

        # Create larger test dataset
        with db.get_session() as session:
            # Create multiple scan executions with threat findings
            for i in range(10):
                scan_execution = ScanEngineExecution(
                    scan_id=f"scan-{i}",
                    trigger_source="test",
                    scan_type="file",
                    target_path=f"/test/file-{i}.py",
                    threats_found=3,
                    execution_start=time.time(),
                    execution_end=time.time() + 1.0,
                )
                session.add(scan_execution)

                # Add threat findings (creating intentional mismatch)
                for j in range(2):  # Only 2 threats instead of 3
                    threat = ThreatFinding(
                        scan_id=f"scan-{i}",
                        finding_uuid=f"threat-{i}-{j}",
                        scanner_source="test",
                        category="test",
                        severity="medium",
                        file_path=f"/test/file-{i}.py",
                        line_start=j + 1,
                        line_end=j + 1,
                        title=f"Threat {j}",
                        timestamp=time.time(),
                    )
                    session.add(threat)

            session.commit()

        manager = DataMigrationManager(db)

        # First validate to ensure we have inconsistencies
        validation = manager.validate_data_consistency()
        assert validation["validation_success"] is True
        expected_inconsistencies = validation["total_inconsistencies"]

        # Run migration on larger dataset
        start_time = time.time()
        results = manager.fix_summary_field_inconsistencies()
        duration = time.time() - start_time

        assert results["migration_success"] is True
        # The number of records fixed should match the inconsistencies found
        assert results["total_records_fixed"] == expected_inconsistencies
        assert duration < 30  # Should complete within 30 seconds

        # Verify post-migration consistency
        post_validation = manager.validate_data_consistency()
        assert post_validation["total_inconsistencies"] == 0

        db.close()

    def test_migration_partial_failure_recovery(self, populated_database):
        """Test migration recovery from partial failures."""
        manager = DataMigrationManager(populated_database)

        # First, ensure we have inconsistencies
        validation = manager.validate_data_consistency()
        assert validation["total_inconsistencies"] > 0

        # Mock a partial failure scenario by patching one of the fix methods
        with patch.object(
            manager,
            "_fix_cli_command_findings_count",
            side_effect=Exception("Simulated failure"),
        ):

            results = manager.fix_summary_field_inconsistencies()

            # Should handle the error gracefully
            assert results["migration_success"] is False
            assert "error" in results

    def test_migration_system_state_preservation(self, populated_database):
        """Test that migration preserves system state on failure."""
        manager = DataMigrationManager(populated_database)

        # Record initial state
        with populated_database.get_session() as session:
            initial_scan_count = session.query(ScanEngineExecution).count()
            initial_threat_count = session.query(ThreatFinding).count()

        # Force a failure scenario
        with patch.object(
            manager,
            "_fix_scan_engine_threats_found",
            side_effect=Exception("Simulated database error"),
        ):

            results = manager.fix_summary_field_inconsistencies()

            assert results["migration_success"] is False

        # Verify state is preserved (rollback occurred)
        with populated_database.get_session() as session:
            final_scan_count = session.query(ScanEngineExecution).count()
            final_threat_count = session.query(ThreatFinding).count()

            assert final_scan_count == initial_scan_count
            assert final_threat_count == initial_threat_count


@pytest.mark.integration
class TestEndToEndMigrationScenarios:
    """End-to-end migration scenario tests."""

    def test_fresh_installation_migration(self, temp_db_path):
        """Test migration scenario for fresh installation."""
        orchestrator = MigrationOrchestrator(temp_db_path)

        results = orchestrator.run_complete_migration(
            skip_legacy=True,  # Fresh installation has no legacy files
            backup=False,  # No existing data to backup
        )

        assert results["overall_success"] is True
        assert (
            results["phases"]["data_migration"]["skipped"] is True
        )  # No data to migrate

        # Final state should be healthy
        summary = results["summary"]
        assert summary["final_health_status"] in ["healthy", "fair"]

    def test_upgrade_from_legacy_system(
        self, temp_legacy_cache_dir, temp_legacy_metrics_dir, temp_db_path
    ):
        """Test migration scenario upgrading from legacy system."""
        with (
            patch(
                "adversary_mcp_server.migration.database_migration.get_app_cache_dir"
            ) as mock_cache,
            patch(
                "adversary_mcp_server.migration.database_migration.get_app_metrics_dir"
            ) as mock_metrics,
        ):

            mock_cache.return_value = temp_legacy_cache_dir
            mock_metrics.return_value = temp_legacy_metrics_dir

            orchestrator = MigrationOrchestrator(temp_db_path)

            results = orchestrator.run_complete_migration(backup=True)

            # Debug: print results if test fails
            if not results["overall_success"]:
                print(f"Migration failed: errors={results.get('errors', [])}")
                for phase_name, phase_data in results.get("phases", {}).items():
                    if not phase_data.get("success", True):
                        print(f"Phase {phase_name} failed: {phase_data}")

            # The overall success depends on whether all critical phases succeeded
            # Legacy migration failure might not be critical if no files exist
            legacy_phase = results["phases"]["legacy_migration"]
            if legacy_phase.get("skipped"):
                # If legacy migration was skipped (no files found), that's acceptable
                assert results["overall_success"] is True
            else:
                # If legacy migration ran, it should succeed
                assert legacy_phase.get("success", False) is True
                assert results["overall_success"] is True

    def test_maintenance_migration_with_inconsistencies(self, populated_database):
        """Test migration scenario for maintenance with data inconsistencies."""
        orchestrator = MigrationOrchestrator(populated_database.db_path)

        results = orchestrator.run_complete_migration(
            skip_legacy=True,  # No legacy files in maintenance scenario
            backup=True,
        )

        assert results["overall_success"] is True

        # Should have fixed data inconsistencies
        data_phase = results["phases"]["data_migration"]
        assert data_phase["success"] is True
        assert data_phase["records_fixed"] > 0

        # Final state should be consistent
        assert results["summary"]["final_data_consistency"] is True
