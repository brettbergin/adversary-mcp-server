"""Comprehensive test coverage for UnifiedDashboard."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from adversary_mcp_server.database.models import AdversaryDatabase
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
def mock_metrics_collector():
    """Create a mock metrics collector."""
    collector = Mock(spec=UnifiedMetricsCollector)
    collector.get_metrics.return_value = {
        "scans_completed": {
            "value": 10,
            "timestamp": time.time(),
            "labels": {},
            "type": "counter",
        },
        "cache_hits": {
            "value": 8,
            "timestamp": time.time(),
            "labels": {},
            "type": "counter",
        },
    }
    collector.get_scan_metrics.return_value = Mock(
        total_scans=10, average_scan_time=1.5, total_findings=25
    )
    return collector


class TestUnifiedDashboardCoverage:
    """Test coverage for UnifiedDashboard missing lines."""

    def test_init_without_psutil_import_error(self):
        """Test initialization when psutil import fails (lines 10-11)."""
        with patch("adversary_mcp_server.monitoring.unified_dashboard.psutil", None):
            # This tests the import error handling path
            dashboard = UnifiedDashboard()
            assert dashboard.console is not None
            # Should still initialize even without psutil

    def test_init_telemetry_initialization_failure(self):
        """Test telemetry initialization failure (lines 49-52)."""
        with patch(
            "adversary_mcp_server.monitoring.unified_dashboard.AdversaryDatabase"
        ) as mock_db_cls:
            mock_db_cls.side_effect = Exception("Database connection failed")

            dashboard = UnifiedDashboard()

            assert dashboard.telemetry_enabled is False
            assert dashboard.db is None
            assert dashboard.telemetry_service is None

    def test_display_real_time_dashboard_without_psutil(self, mock_metrics_collector):
        """Test display_real_time_dashboard without psutil (lines 174-177)."""
        with patch("adversary_mcp_server.monitoring.unified_dashboard.psutil", None):
            dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)

            # This should handle the missing psutil gracefully
            dashboard.display_real_time_dashboard()
            # Should not raise an exception

    def test_display_real_time_dashboard_psutil_exception(self, mock_metrics_collector):
        """Test display_real_time_dashboard with psutil exception (line 177)."""
        with patch("psutil.cpu_percent", side_effect=Exception("psutil error")):
            dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)

            # Should handle psutil exceptions gracefully
            dashboard.display_real_time_dashboard()

    def test_display_real_time_dashboard_without_telemetry(
        self, mock_metrics_collector
    ):
        """Test display without telemetry enabled (line 81)."""
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)
        dashboard.telemetry_enabled = False

        dashboard.display_real_time_dashboard()
        # Should skip telemetry overview section

    def test_display_real_time_dashboard_without_metrics_collector(self):
        """Test display without metrics collector (line 81)."""
        dashboard = UnifiedDashboard(metrics_collector=None)

        dashboard.display_real_time_dashboard()
        # Should skip performance metrics section

    def test_generate_html_dashboard_without_telemetry(self):
        """Test generate_html_dashboard without telemetry (lines 99-100)."""
        dashboard = UnifiedDashboard()
        dashboard.telemetry_enabled = False

        result = dashboard.generate_html_dashboard()

        assert result is None

    def test_generate_html_dashboard_import_error(self, test_db):
        """Test generate_html_dashboard with import error (lines 115-119)."""
        dashboard = UnifiedDashboard()
        dashboard.telemetry_enabled = True
        dashboard.db = test_db

        with patch(
            "adversary_mcp_server.dashboard.html_dashboard.ComprehensiveHTMLDashboard",
            side_effect=ImportError("HTML dashboard not available"),
        ):
            result = dashboard.generate_html_dashboard()

            assert result is None

    def test_generate_html_dashboard_general_exception(self, test_db):
        """Test generate_html_dashboard with general exception (lines 120-123)."""
        dashboard = UnifiedDashboard()
        dashboard.telemetry_enabled = True
        dashboard.db = test_db

        with patch(
            "adversary_mcp_server.dashboard.html_dashboard.ComprehensiveHTMLDashboard"
        ) as mock_html_cls:
            mock_html_cls.side_effect = Exception("Dashboard generation failed")

            result = dashboard.generate_html_dashboard()

            assert result is None

    def test_export_metrics_unsupported_format(self):
        """Test export_metrics with unsupported format (line 140)."""
        dashboard = UnifiedDashboard()

        result = dashboard.export_metrics(format_type="xml")

        assert result is None

    def test_display_metrics_overview_no_metrics_collector(self):
        """Test _display_metrics_overview without metrics collector (lines 184-185)."""
        dashboard = UnifiedDashboard(metrics_collector=None)

        # Should return early without error
        dashboard._display_metrics_overview()

    def test_display_metrics_overview_no_metrics(self, mock_metrics_collector):
        """Test _display_metrics_overview with no metrics (lines 187-189)."""
        mock_metrics_collector.get_metrics.return_value = {}
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)

        dashboard._display_metrics_overview()

    def test_display_metrics_overview_exception(self, mock_metrics_collector):
        """Test _display_metrics_overview with exception (lines 204-205)."""
        mock_metrics_collector.get_metrics.side_effect = Exception("Metrics error")
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)

        dashboard._display_metrics_overview()

    def test_display_telemetry_overview_disabled(self):
        """Test _display_telemetry_overview when disabled (line 210)."""
        dashboard = UnifiedDashboard()
        dashboard.telemetry_enabled = False

        # Should return early
        dashboard._display_telemetry_overview()

    def test_display_telemetry_overview_exception(self, telemetry_service):
        """Test _display_telemetry_overview with exception (lines 264-265)."""
        dashboard = UnifiedDashboard()
        dashboard.telemetry_enabled = True
        dashboard.telemetry_service = telemetry_service

        with patch.object(
            telemetry_service,
            "get_dashboard_data",
            side_effect=Exception("Telemetry error"),
        ):
            dashboard._display_telemetry_overview()

    def test_display_performance_metrics_exception(self, mock_metrics_collector):
        """Test _display_performance_metrics with exception (lines 284-285)."""
        mock_metrics_collector.get_scan_metrics.side_effect = Exception(
            "Performance error"
        )
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)

        dashboard._display_performance_metrics()

    def test_export_json_metrics_without_metrics_collector(self, telemetry_service):
        """Test _export_json_metrics without metrics collector (lines 302-303)."""
        dashboard = UnifiedDashboard(metrics_collector=None)
        dashboard.telemetry_enabled = True
        dashboard.telemetry_service = telemetry_service

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_export.json"
            result = dashboard._export_json_metrics(str(output_path))

            assert result is not None
            assert output_path.exists()

            # Verify JSON structure
            with open(output_path) as f:
                data = json.load(f)
            assert "metadata" in data
            assert "legacy_metrics" in data
            assert data["legacy_metrics"] == {}

    def test_export_json_metrics_without_telemetry(self, mock_metrics_collector):
        """Test _export_json_metrics without telemetry (lines 319-323)."""
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)
        dashboard.telemetry_enabled = False

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_export.json"
            result = dashboard._export_json_metrics(str(output_path))

            assert result is not None
            assert output_path.exists()

    def test_export_json_metrics_default_path(self, mock_metrics_collector):
        """Test _export_json_metrics with default export path (lines 319-323)."""
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)
        dashboard.telemetry_enabled = False

        with (
            patch("pathlib.Path.mkdir") as mock_mkdir,
            patch("builtins.open", create=True) as mock_open,
            patch("json.dump") as mock_json_dump,
        ):

            mock_file = Mock()
            mock_open.return_value.__enter__.return_value = mock_file

            result = dashboard._export_json_metrics()

            assert result is not None
            mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
            mock_json_dump.assert_called_once()

    def test_export_json_metrics_exception(self, mock_metrics_collector):
        """Test _export_json_metrics with exception (lines 332-335)."""
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)

        with patch("builtins.open", side_effect=Exception("File write error")):
            result = dashboard._export_json_metrics("/invalid/path/test.json")

            assert result is None

    def test_system_overview_with_db_info(self, test_db, mock_metrics_collector):
        """Test _display_system_overview with database info."""
        dashboard = UnifiedDashboard(metrics_collector=mock_metrics_collector)
        dashboard.telemetry_enabled = True
        dashboard.db = test_db

        # Create a test database file
        test_db.db_path.touch()

        with (
            patch("psutil.cpu_percent", return_value=50.0),
            patch("psutil.virtual_memory") as mock_memory,
        ):

            mock_memory.return_value = Mock(percent=60.0, used=1000000000)

            dashboard._display_system_overview()

    def test_console_initialization(self):
        """Test console initialization with custom console."""
        custom_console = Console()
        dashboard = UnifiedDashboard(console=custom_console)

        assert dashboard.console is custom_console

    def test_backward_compatibility_alias(self):
        """Test that MonitoringDashboard alias works."""
        from adversary_mcp_server.monitoring.unified_dashboard import (
            MonitoringDashboard,
        )

        dashboard = MonitoringDashboard()
        assert isinstance(dashboard, UnifiedDashboard)
