"""Comprehensive test suite for the telemetry system."""

import tempfile
import time
from pathlib import Path

import pytest

from adversary_mcp_server.database.models import (
    AdversaryDatabase,
    CacheOperationMetric,
    CLICommandExecution,
    MCPToolExecution,
    ScanEngineExecution,
    ThreatFinding,
)
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch
from adversary_mcp_server.telemetry.integration import MetricsCollectionOrchestrator
from adversary_mcp_server.telemetry.repository import ComprehensiveTelemetryRepository
from adversary_mcp_server.telemetry.service import TelemetryService


@pytest.fixture
def temp_db_path():
    """Create a temporary database path for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir) / "test_adversary.db"


@pytest.fixture
def test_db(temp_db_path):
    """Create a test database instance."""
    db = AdversaryDatabase(temp_db_path)
    yield db
    db.close()


@pytest.fixture
def telemetry_service(test_db):
    """Create a telemetry service for testing."""
    return TelemetryService(test_db)


@pytest.fixture
def metrics_orchestrator(telemetry_service):
    """Create a metrics orchestrator for testing."""
    return MetricsCollectionOrchestrator(telemetry_service)


class TestAdversaryDatabase:
    """Test the core database functionality."""

    def test_database_initialization(self, temp_db_path):
        """Test database initialization creates all tables."""
        db = AdversaryDatabase(temp_db_path)

        # Check database file was created
        assert temp_db_path.exists()

        # Check we can get a session
        session = db.get_session()
        assert session is not None
        session.close()

        db.close()

    def test_database_tables_created(self, test_db):
        """Test that all required tables are created."""
        session = test_db.get_session()

        # Test we can create instances of all models
        try:
            # This will fail if tables don't exist
            mcp_tool = MCPToolExecution(
                tool_name="test_tool",
                session_id="test_session",
                request_params={"test": "data"},
                execution_start=time.time(),
            )
            session.add(mcp_tool)
            session.commit()

            # Verify it was inserted
            count = session.query(MCPToolExecution).count()
            assert count == 1

        finally:
            session.close()


class TestTelemetryService:
    """Test the telemetry service functionality."""

    def test_mcp_tool_tracking(self, telemetry_service):
        """Test MCP tool execution tracking."""
        # Start tracking
        execution = telemetry_service.start_mcp_tool_tracking(
            tool_name="adv_scan_file",
            session_id="test_session_123",
            request_params={"path": "/test/file.py", "use_llm": True},
            validation_enabled=True,
            llm_enabled=True,
        )

        assert execution.tool_name == "adv_scan_file"
        assert execution.session_id == "test_session_123"
        assert execution.validation_enabled is True
        assert execution.llm_enabled is True
        assert execution.execution_start is not None
        assert execution.execution_end is None

        # Complete tracking
        telemetry_service.complete_mcp_tool_tracking(
            execution_id=execution.id, success=True, findings_count=5
        )

        # Verify completion was recorded
        with telemetry_service.get_repository() as repo:
            updated_execution = (
                repo.session.query(MCPToolExecution).filter_by(id=execution.id).first()
            )
            assert updated_execution.success is True
            assert updated_execution.findings_count == 5
            assert updated_execution.execution_end is not None

    def test_cli_command_tracking(self, telemetry_service):
        """Test CLI command execution tracking."""
        # Start tracking
        execution = telemetry_service.start_cli_command_tracking(
            command_name="scan",
            args={"path": "/test/dir", "use_validation": True},
            subcommand="/test/dir",
            validation_enabled=True,
        )

        assert execution.command_name == "scan"
        assert execution.subcommand == "/test/dir"
        assert execution.validation_enabled is True

        # Complete tracking
        telemetry_service.complete_cli_command_tracking(
            execution_id=execution.id, exit_code=0, findings_count=3
        )

        # Verify completion
        with telemetry_service.get_repository() as repo:
            updated_execution = (
                repo.session.query(CLICommandExecution)
                .filter_by(id=execution.id)
                .first()
            )
            assert updated_execution.exit_code == 0
            assert updated_execution.findings_count == 3

    def test_cache_operation_tracking(self, telemetry_service):
        """Test cache operation tracking."""
        cache_op = telemetry_service.track_cache_operation(
            operation_type="hit",
            cache_name="scan_results",
            key_hash="abc123def456",
            key_metadata={"file_extension": "py", "cache_type": "semgrep"},
            size_bytes=1024,
            access_time_ms=1.5,
        )

        assert cache_op.operation_type == "hit"
        assert cache_op.cache_name == "scan_results"
        assert cache_op.size_bytes == 1024
        assert cache_op.access_time_ms == 1.5
        assert cache_op.key_metadata["file_extension"] == "py"

    def test_scan_execution_tracking(self, telemetry_service):
        """Test scan engine execution tracking."""
        # Start scan tracking
        execution = telemetry_service.start_scan_tracking(
            scan_id="scan_123",
            trigger_source="mcp_tool",
            scan_type="file",
            target_path="/test/file.py",
            file_count=1,
            language_detected="python",
            semgrep_enabled=True,
            llm_enabled=True,
            validation_enabled=True,
        )

        assert execution.scan_id == "scan_123"
        assert execution.trigger_source == "mcp_tool"
        assert execution.scan_type == "file"
        assert execution.language_detected == "python"

        # Complete scan tracking
        telemetry_service.complete_scan_tracking(
            scan_id="scan_123",
            success=True,
            total_duration_ms=1500.0,
            semgrep_duration_ms=800.0,
            llm_duration_ms=600.0,
            validation_duration_ms=100.0,
            threats_found=3,
            threats_validated=2,
            false_positives_filtered=1,
        )

        # Verify completion
        with telemetry_service.get_repository() as repo:
            updated_execution = (
                repo.session.query(ScanEngineExecution)
                .filter_by(scan_id="scan_123")
                .first()
            )
            assert updated_execution.success is True
            assert updated_execution.total_duration_ms == 1500.0
            assert updated_execution.threats_found == 3
            assert updated_execution.threats_validated == 2

    def test_threat_finding_recording(self, telemetry_service):
        """Test threat finding recording."""
        # First create a scan execution to satisfy foreign key constraint
        scan_exec = telemetry_service.start_scan_tracking(
            scan_id="scan_123",
            trigger_source="test",
            scan_type="file",
            target_path="/test/vulnerable.py",
        )

        finding = telemetry_service.record_threat_finding(
            scan_id="scan_123",
            finding_uuid="finding_456",
            scanner_source="semgrep",
            category="injection",
            severity="high",
            file_path="/test/vulnerable.py",
            line_start=15,
            line_end=17,
            title="SQL Injection Vulnerability",
            rule_id="sql-injection-001",
            confidence=0.95,
            description="Potential SQL injection vulnerability detected",
            is_validated=True,
        )

        assert finding.finding_uuid == "finding_456"
        assert finding.scanner_source == "semgrep"
        assert finding.category == "injection"
        assert finding.severity == "high"
        assert finding.confidence == 0.95
        assert finding.is_validated is True

    def test_system_health_recording(self, telemetry_service):
        """Test system health snapshot recording."""
        health = telemetry_service.record_system_health_snapshot(
            cpu_percent=45.2,
            memory_percent=68.7,
            memory_used_mb=2048.5,
            disk_usage_percent=75.3,
            db_size_mb=15.7,
            cache_hit_rate_1h=0.85,
            avg_scan_duration_1h=1200.0,
            scans_per_hour=25.0,
            error_rate_1h=0.02,
        )

        assert health.cpu_percent == 45.2
        assert health.memory_percent == 68.7
        assert health.cache_hit_rate_1h == 0.85
        assert health.error_rate_1h == 0.02

    def test_get_dashboard_data(self, telemetry_service):
        """Test dashboard data retrieval."""
        # Create some test data first
        telemetry_service.start_mcp_tool_tracking(
            tool_name="adv_scan_file",
            session_id="test_session",
            request_params={"test": "data"},
        )

        telemetry_service.track_cache_operation(
            operation_type="hit", cache_name="test_cache", key_hash="test123"
        )

        # Get dashboard data
        dashboard_data = telemetry_service.get_dashboard_data(hours=24)

        assert isinstance(dashboard_data, dict)
        assert "mcp_tools" in dashboard_data
        assert "cli_commands" in dashboard_data
        assert "cache_performance" in dashboard_data
        assert "scan_engine" in dashboard_data
        assert "threat_categories" in dashboard_data
        assert "language_performance" in dashboard_data

        # Check MCP tools data
        assert len(dashboard_data["mcp_tools"]) > 0
        mcp_tool = dashboard_data["mcp_tools"][0]
        assert "tool_name" in mcp_tool
        assert "executions" in mcp_tool
        assert "success_rate" in mcp_tool


class TestComprehensiveTelemetryRepository:
    """Test the telemetry repository functionality."""

    def test_repository_context_manager(self, telemetry_service):
        """Test repository context manager."""
        with telemetry_service.get_repository() as repo:
            assert isinstance(repo, ComprehensiveTelemetryRepository)
            assert repo.session is not None

            # Test basic query
            count = repo.session.query(MCPToolExecution).count()
            assert count >= 0  # Should not fail

    def test_dashboard_data_queries(self, telemetry_service):
        """Test complex dashboard data queries."""
        # Create test data
        with telemetry_service.get_repository() as repo:
            # Create MCP tool execution
            mcp_exec = repo.track_mcp_tool_execution(
                tool_name="adv_scan_file",
                session_id="test_session",
                request_params={"test": "data"},
            )
            repo.complete_mcp_tool_execution(
                mcp_exec.id, success=True, findings_count=5
            )

            # Create CLI command execution
            cli_exec = repo.track_cli_command_execution(
                command_name="scan", args={"test": "data"}
            )
            repo.complete_cli_command_execution(
                cli_exec.id, exit_code=0, findings_count=3
            )

            # Create cache operation
            repo.track_cache_operation(
                operation_type="hit",
                cache_name="test_cache",
                key_hash="test123",
                access_time_ms=1.0,
            )

            # Get dashboard data
            dashboard_data = repo.get_dashboard_data(hours=24)

            # Verify data structure
            assert isinstance(dashboard_data["mcp_tools"], list)
            assert isinstance(dashboard_data["cli_commands"], list)
            assert isinstance(dashboard_data["cache_performance"], list)
            assert isinstance(dashboard_data["scan_engine"], dict)


class TestMetricsCollectionOrchestrator:
    """Test the metrics collection orchestrator."""

    @pytest.mark.asyncio
    async def test_mcp_tool_wrapper(self, metrics_orchestrator):
        """Test MCP tool wrapper decorator."""

        # Create a mock function to wrap
        @metrics_orchestrator.mcp_tool_wrapper("test_tool")
        async def mock_mcp_tool(
            content="test", use_llm=False, use_validation=True, **kwargs
        ):
            return {"findings": ["finding1", "finding2"]}

        # Execute the wrapped function
        result = await mock_mcp_tool(
            content="test code", use_llm=True, use_validation=True
        )

        # Verify result
        assert result["findings"] == ["finding1", "finding2"]

        # Verify telemetry was recorded
        with metrics_orchestrator.telemetry.get_repository() as repo:
            executions = (
                repo.session.query(MCPToolExecution)
                .filter_by(tool_name="test_tool")
                .all()
            )
            assert len(executions) == 1

            execution = executions[0]
            assert execution.success is True
            assert execution.findings_count == 2
            assert execution.validation_enabled is True
            assert execution.llm_enabled is True

    def test_cli_command_wrapper(self, metrics_orchestrator):
        """Test CLI command wrapper decorator."""

        # Create a mock function to wrap
        @metrics_orchestrator.cli_command_wrapper("test_command")
        def mock_cli_command(path="/test", use_validation=False):
            return 0  # Success exit code

        # Execute the wrapped function
        result = mock_cli_command(path="/test/path", use_validation=True)

        # Verify result
        assert result == 0

        # Verify telemetry was recorded
        with metrics_orchestrator.telemetry.get_repository() as repo:
            executions = (
                repo.session.query(CLICommandExecution)
                .filter_by(command_name="test_command")
                .all()
            )
            assert len(executions) == 1

            execution = executions[0]
            assert execution.exit_code == 0
            assert execution.validation_enabled is True

    def test_scan_execution_context_manager(self, metrics_orchestrator):
        """Test scan execution context manager."""
        with metrics_orchestrator.track_scan_execution(
            trigger_source="test",
            scan_type="file",
            target_path="/test/file.py",
            semgrep_enabled=True,
            llm_enabled=False,
            validation_enabled=True,
        ) as scan_context:
            # Test timing context managers
            with scan_context.time_semgrep_scan():
                time.sleep(0.01)  # Simulate work

            with scan_context.time_validation():
                time.sleep(0.01)  # Simulate work

            # Add threat findings
            threat_finding = ThreatMatch(
                rule_id="test-telemetry-001",
                rule_name="Telemetry Test Threat",
                description="Test threat for telemetry system",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="/test/file.py",
                line_number=10,
                confidence=0.9,
                is_false_positive=False,
            )
            # Set attributes needed by telemetry system
            threat_finding.is_validated = True
            scan_context.add_threat_finding(threat_finding, "semgrep")

            # Mark cache hit
            scan_context.mark_cache_hit()

        # Verify scan was recorded
        with metrics_orchestrator.telemetry.get_repository() as repo:
            executions = repo.session.query(ScanEngineExecution).all()
            assert len(executions) == 1

            execution = executions[0]
            assert execution.success is True
            assert execution.semgrep_enabled is True
            assert execution.llm_enabled is False
            assert execution.validation_enabled is True
            assert execution.cache_hit is True
            assert execution.threats_found == 1
            assert execution.threats_validated == 1

    def test_cache_operation_tracking(self, metrics_orchestrator):
        """Test cache operation tracking."""
        result = metrics_orchestrator.track_cache_operation(
            operation_type="hit",
            cache_name="test_cache",
            key="test_key_123",
            size_bytes=1024,
        )

        # Verify cache operation was recorded
        assert result is not None

        with metrics_orchestrator.telemetry.get_repository() as repo:
            operations = repo.session.query(CacheOperationMetric).all()
            assert len(operations) == 1

            operation = operations[0]
            assert operation.operation_type == "hit"
            assert operation.cache_name == "test_cache"
            assert operation.size_bytes == 1024

    def test_threat_finding_recording(self, metrics_orchestrator):
        """Test threat finding recording with context."""
        # First create a scan execution to satisfy foreign key constraint
        scan_exec = metrics_orchestrator.telemetry.start_scan_tracking(
            scan_id="test_scan_123",
            trigger_source="test",
            scan_type="file",
            target_path="/test/file.py",
        )

        threat_finding = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Vulnerability",
            description="Test vulnerability for threat finding recording",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=10,
            confidence=0.9,
            is_false_positive=False,
        )
        # Set additional attributes needed by telemetry system
        threat_finding.line_start = 10
        threat_finding.line_end = 12
        threat_finding.title = "Test Vulnerability"
        threat_finding.is_validated = True

        result = metrics_orchestrator.record_threat_finding_with_context(
            scan_id="test_scan_123",
            threat_finding=threat_finding,
            scanner_source="semgrep",
        )

        # Verify threat finding was recorded
        assert result is not None

        with metrics_orchestrator.telemetry.get_repository() as repo:
            findings = repo.session.query(ThreatFinding).all()
            assert len(findings) == 1

            finding = findings[0]
            assert finding.scan_id == "test_scan_123"
            assert finding.category == "injection"
            assert finding.severity == "high"
            assert finding.scanner_source == "semgrep"


class TestTelemetryIntegration:
    """Test integration scenarios."""

    @pytest.mark.asyncio
    async def test_full_mcp_tool_workflow(self, metrics_orchestrator):
        """Test complete MCP tool execution workflow with telemetry."""

        @metrics_orchestrator.mcp_tool_wrapper("adv_scan_file")
        async def mock_scan_file(
            path="/test/file.py", use_llm=True, use_validation=True, **kwargs
        ):
            # Simulate scan execution with context
            with metrics_orchestrator.track_scan_execution(
                trigger_source="mcp_tool",
                scan_type="file",
                target_path=path,
                semgrep_enabled=True,
                llm_enabled=use_llm,
                validation_enabled=use_validation,
            ) as scan_context:

                # Simulate semgrep scan
                with scan_context.time_semgrep_scan():
                    time.sleep(0.01)

                # Simulate LLM analysis
                if use_llm:
                    with scan_context.time_llm_analysis():
                        time.sleep(0.01)

                # Simulate validation
                if use_validation:
                    with scan_context.time_validation():
                        time.sleep(0.01)

                # Add threat findings
                threat_finding = ThreatMatch(
                    rule_id="test-mcp-workflow-001",
                    rule_name="Mock Finding",
                    description="Mock finding for MCP workflow test",
                    category=Category.INJECTION,
                    severity=Severity.MEDIUM,
                    file_path=path,
                    line_number=5,
                    confidence=0.8,
                    is_false_positive=False,
                )
                # Set additional attributes needed by telemetry system
                threat_finding.line_start = 5
                threat_finding.line_end = 7
                threat_finding.title = "Mock Finding"
                threat_finding.is_validated = True

                scan_context.add_threat_finding(threat_finding, "semgrep")

                return {"findings": [{"title": "Mock Finding"}]}

        # Execute the workflow
        result = await mock_scan_file(
            path="/test/vulnerable.py", use_llm=True, use_validation=True
        )

        # Verify result
        assert len(result["findings"]) == 1

        # Verify comprehensive telemetry was recorded
        with metrics_orchestrator.telemetry.get_repository() as repo:
            # Check MCP tool execution
            mcp_executions = repo.session.query(MCPToolExecution).all()
            assert len(mcp_executions) == 1
            mcp_exec = mcp_executions[0]
            assert mcp_exec.tool_name == "adv_scan_file"
            assert mcp_exec.success is True
            assert mcp_exec.findings_count == 1

            # Check scan execution
            scan_executions = repo.session.query(ScanEngineExecution).all()
            assert len(scan_executions) == 1
            scan_exec = scan_executions[0]
            assert scan_exec.scan_type == "file"
            assert scan_exec.success is True
            assert scan_exec.threats_found == 1

            # Check threat findings
            findings = repo.session.query(ThreatFinding).all()
            assert len(findings) == 1
            finding = findings[0]
            assert finding.category == "injection"
            assert finding.severity == "medium"


@pytest.mark.integration
class TestTelemetrySystemIntegration:
    """Integration tests for the telemetry system."""

    def test_database_migration_compatibility(self, temp_db_path):
        """Test that the database can be recreated without issues."""
        # Create first database
        db1 = AdversaryDatabase(temp_db_path)

        # Add some data
        service1 = TelemetryService(db1)
        service1.start_mcp_tool_tracking(
            tool_name="test_tool",
            session_id="test_session",
            request_params={"test": "data"},
        )

        db1.close()

        # Recreate database (simulating restart)
        db2 = AdversaryDatabase(temp_db_path)
        service2 = TelemetryService(db2)

        # Verify data persisted
        dashboard_data = service2.get_dashboard_data(24)
        assert len(dashboard_data["mcp_tools"]) == 1

        db2.close()

    def test_concurrent_access_safety(self, test_db):
        """Test that concurrent access doesn't cause issues."""
        import queue
        import threading

        results = queue.Queue()

        def worker():
            try:
                service = TelemetryService(test_db)
                execution = service.start_mcp_tool_tracking(
                    tool_name="concurrent_tool",
                    session_id=f"session_{threading.current_thread().ident}",
                    request_params={"test": "concurrent"},
                )
                service.complete_mcp_tool_tracking(execution.id, success=True)
                results.put("success")
            except Exception as e:
                results.put(f"error: {e}")

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Check results
        success_count = 0
        while not results.empty():
            result = results.get()
            if result == "success":
                success_count += 1
            else:
                pytest.fail(f"Concurrent access failed: {result}")

        assert success_count == 5
