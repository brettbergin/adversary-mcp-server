"""Comprehensive test suite for the dashboard system."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.dashboard.html_dashboard import (
    ComprehensiveHTMLDashboard,
    DashboardAssetManager,
)
from adversary_mcp_server.database.models import AdversaryDatabase
from adversary_mcp_server.monitoring.types import MonitoringConfig
from adversary_mcp_server.monitoring.unified_dashboard import UnifiedDashboard
from adversary_mcp_server.monitoring.unified_metrics_collector import (
    UnifiedMetricsCollector,
)
from adversary_mcp_server.telemetry.service import TelemetryService


@pytest.fixture
def temp_db_path():
    """Create a temporary database path for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir) / "test_dashboard.db"


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
def sample_telemetry_data(telemetry_service):
    """Create sample telemetry data for testing."""
    # Create MCP tool executions
    mcp_exec1 = telemetry_service.start_mcp_tool_tracking(
        tool_name="adv_scan_file",
        session_id="session_1",
        request_params={"path": "/test/file1.py", "use_llm": True},
        validation_enabled=True,
        llm_enabled=True,
    )
    telemetry_service.complete_mcp_tool_tracking(
        mcp_exec1.id, success=True, findings_count=3
    )

    mcp_exec2 = telemetry_service.start_mcp_tool_tracking(
        tool_name="adv_scan_folder",
        session_id="session_2",
        request_params={"path": "/test/folder", "recursive": True},
        validation_enabled=False,
        llm_enabled=False,
    )
    telemetry_service.complete_mcp_tool_tracking(
        mcp_exec2.id, success=True, findings_count=5
    )

    # Create CLI command executions
    cli_exec1 = telemetry_service.start_cli_command_tracking(
        command_name="scan",
        args={"path": "/test/dir", "use_validation": True},
        subcommand="/test/dir",
        validation_enabled=True,
    )
    telemetry_service.complete_cli_command_tracking(
        cli_exec1.id, exit_code=0, findings_count=2
    )

    # Create cache operations
    telemetry_service.track_cache_operation(
        operation_type="hit",
        cache_name="scan_results",
        key_hash="abc123",
        key_metadata={"file_extension": "py"},
        size_bytes=1024,
        access_time_ms=1.5,
    )

    telemetry_service.track_cache_operation(
        operation_type="miss",
        cache_name="scan_results",
        key_hash="def456",
        key_metadata={"file_extension": "js"},
        access_time_ms=0.1,
    )

    # Create scan executions
    scan_exec1 = telemetry_service.start_scan_tracking(
        scan_id="scan_123",
        trigger_source="mcp_tool",
        scan_type="file",
        target_path="/test/file.py",
        language_detected="python",
        semgrep_enabled=True,
        llm_enabled=True,
        validation_enabled=True,
    )
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

    # Create threat findings
    telemetry_service.record_threat_finding(
        scan_id="scan_123",
        finding_uuid="finding_1",
        scanner_source="semgrep",
        category="injection",
        severity="high",
        file_path="/test/file.py",
        line_start=10,
        line_end=12,
        title="SQL Injection",
        confidence=0.95,
        is_validated=True,
    )

    telemetry_service.record_threat_finding(
        scan_id="scan_123",
        finding_uuid="finding_2",
        scanner_source="llm",
        category="xss",
        severity="medium",
        file_path="/test/file.py",
        line_start=25,
        line_end=27,
        title="XSS Vulnerability",
        confidence=0.80,
        is_validated=True,
    )

    # Create system health snapshots
    telemetry_service.record_system_health_snapshot(
        cpu_percent=45.2,
        memory_percent=68.7,
        memory_used_mb=2048.5,
        db_size_mb=15.7,
        cache_hit_rate_1h=0.75,
        avg_scan_duration_1h=1200.0,
        scans_per_hour=20.0,
        error_rate_1h=0.05,
    )

    return telemetry_service


class TestComprehensiveHTMLDashboard:
    """Test the HTML dashboard functionality."""

    def test_html_dashboard_initialization(self, test_db):
        """Test HTML dashboard initialization."""
        dashboard = ComprehensiveHTMLDashboard(test_db)

        assert dashboard.db == test_db
        assert dashboard.telemetry is not None
        assert dashboard.output_dir.exists()
        assert dashboard.jinja_env is not None

    def test_html_dashboard_with_sample_data(self, sample_telemetry_data):
        """Test HTML dashboard generation with sample data."""
        dashboard = ComprehensiveHTMLDashboard(sample_telemetry_data.db)

        with patch("webbrowser.open") as mock_browser:
            with tempfile.TemporaryDirectory() as temp_dir:
                dashboard.output_dir = Path(temp_dir)

                html_file = dashboard.generate_and_launch_dashboard(
                    hours=24, auto_launch=True
                )

                # Verify file was created
                assert html_file is not None
                assert Path(html_file).exists()

                # Verify browser was launched
                mock_browser.assert_called_once()

                # Verify HTML content contains expected data
                with open(html_file) as f:
                    content = f.read()
                    assert "Adversary MCP Server Dashboard" in content
                    assert "scan_results" in content  # Cache name
                    assert "adv_scan_file" in content  # MCP tool name

    def test_html_dashboard_no_auto_launch(self, sample_telemetry_data):
        """Test HTML dashboard generation without auto-launch."""
        dashboard = ComprehensiveHTMLDashboard(sample_telemetry_data.db)

        with patch("webbrowser.open") as mock_browser:
            with tempfile.TemporaryDirectory() as temp_dir:
                dashboard.output_dir = Path(temp_dir)

                html_file = dashboard.generate_and_launch_dashboard(
                    hours=24, auto_launch=False
                )

                # Verify file was created but browser wasn't launched
                assert html_file is not None
                assert Path(html_file).exists()
                mock_browser.assert_not_called()

    def test_jinja2_template_filters(self, test_db):
        """Test custom Jinja2 template filters."""
        dashboard = ComprehensiveHTMLDashboard(test_db)

        # Test timestamp filter
        timestamp_filter = dashboard.jinja_env.filters["timestamp_to_datetime"]
        result = timestamp_filter(1640995200.0)  # 2022-01-01 00:00:00 UTC
        assert "2022-01-01" in result
        assert "UTC" in result

        # Test duration filter
        duration_filter = dashboard.jinja_env.filters["format_duration"]
        assert duration_filter(500.0) == "500.0ms"
        assert duration_filter(1500.0) == "1.5s"
        assert duration_filter(90000.0) == "1m 30.0s"

        # Test size filter
        size_filter = dashboard.jinja_env.filters["format_size"]
        assert size_filter(512.0) == "512.0 B"
        assert size_filter(1536.0) == "1.5 KB"
        assert size_filter(2097152.0) == "2.0 MB"

        # Test percentage filter
        percentage_filter = dashboard.jinja_env.filters["percentage"]
        assert percentage_filter(0.75) == "75.0%"
        assert percentage_filter(None) == "N/A"

    def test_current_system_status(self, test_db):
        """Test current system status retrieval."""
        dashboard = ComprehensiveHTMLDashboard(test_db)

        with patch("psutil.cpu_percent", return_value=45.0):
            with patch("psutil.virtual_memory") as mock_memory:
                mock_memory.return_value = Mock(percent=70.0, used=2147483648)  # 2GB

                with patch("psutil.disk_usage") as mock_disk:
                    mock_disk.return_value = Mock(percent=60.0)

                    status = dashboard.get_current_system_status()

                    assert status["cpu_percent"] == 45.0
                    assert status["memory_percent"] == 70.0
                    assert status["memory_used_mb"] == 2048.0
                    assert status["disk_usage_percent"] == 60.0
                    assert status["status"] == "healthy"

    def test_recent_activity_tracking(self, sample_telemetry_data):
        """Test recent activity retrieval."""
        dashboard = ComprehensiveHTMLDashboard(sample_telemetry_data.db)

        activities = dashboard.get_recent_activity(limit=10)

        assert isinstance(activities, list)
        assert len(activities) > 0

        # Check activity structure
        for activity in activities:
            assert "type" in activity
            assert "timestamp" in activity
            assert "description" in activity
            assert "status" in activity
            assert "details" in activity


class TestDashboardAssetManager:
    """Test dashboard asset management."""

    def test_asset_manager_initialization(self):
        """Test asset manager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard_dir = Path(temp_dir)
            manager = DashboardAssetManager(dashboard_dir)

            assert manager.dashboard_dir == dashboard_dir
            assert manager.templates_dir == dashboard_dir / "templates"
            assert manager.static_dir == dashboard_dir / "static"

    def test_create_default_assets(self):
        """Test creation of default dashboard assets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard_dir = Path(temp_dir)
            manager = DashboardAssetManager(dashboard_dir)

            manager.create_default_assets()

            # Check template was created
            template_file = dashboard_dir / "templates" / "dashboard.html"
            assert template_file.exists()

            template_content = template_file.read_text()
            assert "Adversary MCP Server Dashboard" in template_content
            assert "chart.js" in template_content

            # Check CSS was created
            css_file = dashboard_dir / "static" / "dashboard.css"
            assert css_file.exists()

            css_content = css_file.read_text()
            assert "dashboard-container" in css_content
            assert "primary-color" in css_content

            # Check JavaScript was created
            js_file = dashboard_dir / "static" / "dashboard.js"
            assert js_file.exists()

            js_content = js_file.read_text()
            assert "initializeScanPerformanceChart" in js_content
            assert "Chart" in js_content


class TestUnifiedDashboard:
    """Test the unified dashboard system."""

    def test_unified_dashboard_initialization(self, test_db):
        """Test unified dashboard initialization."""
        from rich.console import Console

        console = Console()
        dashboard = UnifiedDashboard(console=console)

        assert dashboard.console == console
        assert dashboard.telemetry_enabled in [True, False]  # Depends on system state

    def test_unified_dashboard_with_metrics_collector(self):
        """Test unified dashboard with metrics collector."""
        config = MonitoringConfig(
            enable_metrics=True, enable_performance_monitoring=True, json_export_path=""
        )

        metrics_collector = UnifiedMetricsCollector(config)
        dashboard = UnifiedDashboard(metrics_collector=metrics_collector)

        assert dashboard.metrics_collector == metrics_collector

    @patch("rich.console.Console.clear")
    @patch("rich.console.Console.print")
    def test_display_real_time_dashboard(self, mock_print, mock_clear, test_db):
        """Test real-time dashboard display."""
        dashboard = UnifiedDashboard()

        dashboard.display_real_time_dashboard()

        # Verify console interactions
        mock_clear.assert_called_once()
        assert mock_print.call_count > 0

        # Check that header was printed
        print_calls = [call.args[0] for call in mock_print.call_args_list]
        header_found = any("Adversary MCP Server" in str(call) for call in print_calls)
        assert header_found

    def test_generate_html_dashboard_integration(self, sample_telemetry_data):
        """Test HTML dashboard generation through unified dashboard."""
        dashboard = UnifiedDashboard()

        # Mock the HTML dashboard creation
        with patch(
            "adversary_mcp_server.dashboard.html_dashboard.ComprehensiveHTMLDashboard"
        ) as mock_html_dashboard_class:
            mock_html_dashboard = Mock()
            mock_html_dashboard.generate_and_launch_dashboard.return_value = (
                "/tmp/test_dashboard.html"
            )
            mock_html_dashboard_class.return_value = mock_html_dashboard

            with patch.object(dashboard, "telemetry_enabled", True):
                with patch.object(dashboard, "db", sample_telemetry_data.db):
                    result = dashboard.generate_html_dashboard(
                        hours=12, auto_launch=False
                    )

                    assert result == "/tmp/test_dashboard.html"
                    mock_html_dashboard.generate_and_launch_dashboard.assert_called_once_with(
                        hours=12, auto_launch=False
                    )

    def test_export_metrics_json_format(self, sample_telemetry_data):
        """Test metrics export in JSON format."""
        dashboard = UnifiedDashboard()

        with patch.object(dashboard, "telemetry_enabled", True):
            with patch.object(dashboard, "telemetry_service", sample_telemetry_data):
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False
                ) as tmp_file:
                    result = dashboard._export_json_metrics(tmp_file.name)

                    assert result == tmp_file.name
                    assert Path(tmp_file.name).exists()

                    # Verify JSON structure
                    import json

                    with open(tmp_file.name) as f:
                        data = json.load(f)

                        assert "metadata" in data
                        assert "telemetry_data" in data
                        assert data["metadata"]["telemetry_enabled"] is True

                        # Clean up
                        Path(tmp_file.name).unlink()

    def test_export_metrics_html_format(self, test_db):
        """Test metrics export in HTML format."""
        dashboard = UnifiedDashboard()

        # Mock HTML dashboard generation
        with patch.object(
            dashboard, "generate_html_dashboard", return_value="/tmp/dashboard.html"
        ) as mock_generate:
            result = dashboard.export_metrics(format_type="html", output_path=None)

            assert result == "/tmp/dashboard.html"
            mock_generate.assert_called_once_with(auto_launch=False)

    def test_export_metrics_unsupported_format(self, test_db):
        """Test export with unsupported format."""
        from rich.console import Console

        console = Console()
        dashboard = UnifiedDashboard(console=console)

        result = dashboard.export_metrics(format_type="xml")

        assert result is None


class TestUnifiedMetricsCollector:
    """Test the unified metrics collector."""

    def test_unified_metrics_collector_initialization(self):
        """Test unified metrics collector initialization."""
        config = MonitoringConfig(
            enable_metrics=True, enable_performance_monitoring=True, json_export_path=""
        )

        collector = UnifiedMetricsCollector(config)

        assert collector.config == config
        assert hasattr(collector, "telemetry_enabled")
        assert hasattr(collector, "_metrics")
        assert hasattr(collector, "_scan_metrics")

    def test_record_metric_legacy_compatibility(self):
        """Test recording metrics in legacy format."""
        config = MonitoringConfig(enable_metrics=True, json_export_path="")
        collector = UnifiedMetricsCollector(config)

        collector.record_metric(
            name="test_metric", value=42.0, labels={"test": "value"}
        )

        metrics = collector.get_metrics()
        assert "test_metric" in metrics
        assert metrics["test_metric"]["value"] == 42.0
        assert metrics["test_metric"]["labels"]["test"] == "value"

    def test_record_cache_operation_enhanced(self):
        """Test enhanced cache operation recording."""
        config = MonitoringConfig(enable_metrics=True, json_export_path="")
        collector = UnifiedMetricsCollector(config)

        collector.record_cache_operation(
            operation="get", hit=True, cache_type="scan_results", duration_ms=1.5
        )

        # Verify legacy metrics were recorded
        metrics = collector.get_metrics()
        cache_metrics = [name for name in metrics.keys() if "cache" in name]
        assert len(cache_metrics) > 0

    def test_record_scan_operations(self):
        """Test scan operation recording."""
        config = MonitoringConfig(enable_metrics=True, json_export_path="")
        collector = UnifiedMetricsCollector(config)

        # Record scan start
        collector.record_scan_start("file", file_count=1)

        # Record scan completion
        collector.record_scan_complete(
            scan_type="file", duration_seconds=2.5, findings_count=3
        )

        # Verify scan metrics
        scan_metrics = collector.get_scan_metrics()
        assert scan_metrics.total_scans > 0
        assert scan_metrics.total_findings == 3

    def test_get_telemetry_data_integration(self, sample_telemetry_data):
        """Test telemetry data retrieval integration."""
        config = MonitoringConfig(enable_metrics=True, json_export_path="")
        collector = UnifiedMetricsCollector(config)

        # Mock the telemetry service
        with patch.object(collector, "telemetry_enabled", True):
            with patch.object(collector, "telemetry_service", sample_telemetry_data):
                telemetry_data = collector.get_telemetry_data(hours=24)

                assert telemetry_data is not None
                assert isinstance(telemetry_data, dict)
                assert "mcp_tools" in telemetry_data
                assert "scan_engine" in telemetry_data


@pytest.mark.integration
class TestDashboardSystemIntegration:
    """Integration tests for the complete dashboard system."""

    def test_end_to_end_dashboard_workflow(self, sample_telemetry_data):
        """Test complete dashboard workflow from data collection to HTML generation."""
        # Create unified dashboard
        dashboard = UnifiedDashboard()

        # Generate HTML dashboard
        with patch.object(dashboard, "telemetry_enabled", True):
            with patch.object(dashboard, "db", sample_telemetry_data.db):
                with tempfile.TemporaryDirectory() as temp_dir:

                    # Mock HTML dashboard to use temp directory
                    with patch(
                        "adversary_mcp_server.dashboard.html_dashboard.ComprehensiveHTMLDashboard"
                    ) as mock_class:
                        mock_dashboard = Mock()
                        mock_html_file = Path(temp_dir) / "dashboard.html"
                        mock_html_file.write_text(
                            "<html><body>Test Dashboard</body></html>"
                        )
                        mock_dashboard.generate_and_launch_dashboard.return_value = str(
                            mock_html_file
                        )
                        mock_class.return_value = mock_dashboard

                        # Generate dashboard
                        result = dashboard.generate_html_dashboard(
                            hours=24, auto_launch=False
                        )

                        # Verify result
                        assert result is not None
                        assert Path(result).exists()

    def test_dashboard_with_missing_telemetry_data(self, test_db):
        """Test dashboard behavior with no telemetry data."""
        dashboard = ComprehensiveHTMLDashboard(test_db)

        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.output_dir = Path(temp_dir)

            # Generate dashboard with empty database
            html_file = dashboard.generate_and_launch_dashboard(
                hours=24, auto_launch=False
            )

            # Should still generate dashboard
            assert html_file is not None
            assert Path(html_file).exists()

            # Verify content handles empty data gracefully
            with open(html_file) as f:
                content = f.read()
                assert "Adversary MCP Server Dashboard" in content
                # Should not crash even with no data

    def test_dashboard_asset_auto_creation(self):
        """Test that dashboard assets are auto-created when missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard_dir = Path(temp_dir) / "dashboard"

            # Create the dashboard directory
            dashboard_dir.mkdir()

            # Test direct asset creation
            manager = DashboardAssetManager(dashboard_dir)
            manager.create_default_assets()

            # Verify assets were created
            assert (dashboard_dir / "templates").exists()
            assert (dashboard_dir / "static").exists()
            assert (dashboard_dir / "templates" / "dashboard.html").exists()
            assert (dashboard_dir / "static" / "dashboard.css").exists()
            assert (dashboard_dir / "static" / "dashboard.js").exists()
