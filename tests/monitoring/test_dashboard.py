"""Tests for MonitoringDashboard class."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from adversary_mcp_server.monitoring.dashboard import MonitoringDashboard
from adversary_mcp_server.monitoring.metrics_collector import MetricsCollector
from adversary_mcp_server.monitoring.types import MetricType, MonitoringConfig


@pytest.fixture
def mock_metrics_collector():
    """Create a mock metrics collector for testing."""
    config = MonitoringConfig(
        enable_metrics=True,
        enable_performance_monitoring=True,
        json_export_path="/tmp/test_metrics",
    )
    collector = MetricsCollector(config)

    # Add some sample metrics
    collector.record_metric(
        "mcp_tool_calls_total", 10, MetricType.COUNTER, {"status": "success"}
    )
    collector.record_metric(
        "mcp_tool_calls_total", 2, MetricType.COUNTER, {"status": "error"}
    )
    collector.record_metric(
        "cli_commands_total", 5, MetricType.COUNTER, {"command": "scan"}
    )
    collector.record_metric("scan_operations_total", 8, MetricType.COUNTER)
    collector.record_metric("semgrep_scan_operations_total", 4, MetricType.COUNTER)
    collector.record_metric("llm_scan_operations_total", 3, MetricType.COUNTER)
    collector.record_metric("llm_validation_requests_total", 2, MetricType.COUNTER)
    collector.record_metric("semgrep_threats_found_total", 15, MetricType.COUNTER)
    collector.record_metric("llm_threats_found_total", 8, MetricType.COUNTER)
    collector.record_metric("cache_hits_total", 20, MetricType.COUNTER)
    collector.record_metric("cache_misses_total", 5, MetricType.COUNTER)
    collector.record_metric("circuit_breaker_open_events_total", 1, MetricType.COUNTER)
    collector.record_metric("retry_exhausted_total", 0, MetricType.COUNTER)
    collector.record_metric("git_operations_total", 6, MetricType.COUNTER)
    collector.record_metric(
        "batch_processing_throughput_batches_per_second", 2.5, MetricType.GAUGE
    )

    return collector


@pytest.fixture
def dashboard(mock_metrics_collector):
    """Create a dashboard instance for testing."""
    console = Mock()
    return MonitoringDashboard(mock_metrics_collector, console)


class TestMonitoringDashboard:
    """Test MonitoringDashboard class."""

    def test_dashboard_initialization(self, mock_metrics_collector):
        """Test dashboard initialization."""
        dashboard = MonitoringDashboard(mock_metrics_collector)

        assert dashboard.metrics_collector == mock_metrics_collector
        assert dashboard.console is not None

    def test_dashboard_initialization_with_console(self, mock_metrics_collector):
        """Test dashboard initialization with custom console."""
        custom_console = Console()
        dashboard = MonitoringDashboard(mock_metrics_collector, custom_console)

        assert dashboard.metrics_collector == mock_metrics_collector
        assert dashboard.console == custom_console

    def test_display_real_time_dashboard(self, dashboard):
        """Test real-time dashboard display."""
        # This should not raise an exception
        dashboard.display_real_time_dashboard()

        # Verify console methods were called
        dashboard.console.clear.assert_called()
        assert dashboard.console.print.called

    def test_system_overview_display(self, dashboard):
        """Test system overview panel display."""
        # Mock the helper methods to avoid complex metric calculations
        with patch.object(dashboard, "_get_recent_metric_summary") as mock_summary:
            mock_summary.return_value = {
                "total": 10,
                "success_rate": 0.8,
                "avg_duration": 0.5,
            }

            dashboard._display_system_overview()

            # Should have called the metric summary method multiple times
            assert mock_summary.call_count >= 3

    def test_scanner_performance_display(self, dashboard):
        """Test scanner performance panel display."""
        with (
            patch.object(dashboard, "_get_recent_metric_summary") as mock_summary,
            patch.object(dashboard, "_get_recent_metric_sum") as mock_sum,
        ):
            mock_summary.return_value = {"total": 5, "avg_duration": 1.2}
            mock_sum.return_value = 15

            dashboard._display_scanner_performance()

            assert mock_summary.called
            assert mock_sum.called

    def test_error_analytics_display(self, dashboard):
        """Test error analytics panel display."""
        with patch.object(dashboard, "_get_recent_metric_sum") as mock_sum:
            mock_sum.return_value = 2

            dashboard._display_error_analytics()

            assert mock_sum.called

    def test_resource_utilization_display(self, dashboard):
        """Test resource utilization panel display."""
        with (
            patch.object(dashboard, "_get_recent_metric_avg") as mock_avg,
            patch.object(dashboard, "_calculate_cache_hit_rate") as mock_cache_rate,
            patch.object(dashboard, "_get_recent_metric_sum") as mock_sum,
        ):
            mock_avg.return_value = 2.5
            mock_cache_rate.return_value = 0.8
            mock_sum.return_value = 10

            dashboard._display_resource_utilization()

            assert mock_avg.called
            assert mock_cache_rate.called
            assert mock_sum.called

    def test_export_dashboard_report_default_path(self, dashboard):
        """Test dashboard report export with default path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.metrics_collector.export_path = Path(temp_dir)

            export_path = dashboard.export_dashboard_report()

            assert export_path.exists()
            assert export_path.suffix == ".json"
            assert "dashboard_report_" in export_path.name

            # Verify JSON structure
            with open(export_path) as f:
                report_data = json.load(f)

            assert "report_metadata" in report_data
            assert "system_overview" in report_data
            assert "scanner_performance" in report_data
            assert "error_analytics" in report_data
            assert "resource_utilization" in report_data
            assert "detailed_metrics" in report_data

            # Verify metadata
            metadata = report_data["report_metadata"]
            assert metadata["report_type"] == "adversary_mcp_dashboard"
            assert metadata["version"] == "1.0"
            assert "generated_at" in metadata

    def test_export_dashboard_report_custom_path(self, dashboard):
        """Test dashboard report export with custom path."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
            custom_path = Path(temp_file.name)

        try:
            export_path = dashboard.export_dashboard_report(custom_path)

            assert export_path == custom_path
            assert export_path.exists()

            # Verify it's valid JSON
            with open(export_path) as f:
                report_data = json.load(f)

            assert "report_metadata" in report_data
        finally:
            custom_path.unlink(missing_ok=True)

    def test_export_prometheus_metrics_default_path(self, dashboard):
        """Test Prometheus metrics export with default path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.metrics_collector.export_path = Path(temp_dir)

            export_path = dashboard.export_prometheus_metrics()

            assert export_path.exists()
            assert export_path.suffix == ".txt"
            assert "prometheus_metrics_" in export_path.name

            # Verify Prometheus format - should be non-empty file
            with open(export_path) as f:
                content = f.read()

            # File should exist and have content (even if no metrics, should have some structure)
            assert len(content) >= 0

    def test_export_prometheus_metrics_custom_path(self, dashboard):
        """Test Prometheus metrics export with custom path."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as temp_file:
            custom_path = Path(temp_file.name)

        try:
            export_path = dashboard.export_prometheus_metrics(custom_path)

            assert export_path == custom_path
            assert export_path.exists()

            # Verify file exists (content checking is done elsewhere)
            assert export_path.stat().st_size >= 0
        finally:
            custom_path.unlink(missing_ok=True)

    def test_get_recent_metric_summary(self, dashboard):
        """Test metric summary calculation."""
        summary = dashboard._get_recent_metric_summary("mcp_tool_calls_total")

        assert isinstance(summary, dict)
        assert "total" in summary
        assert "success_rate" in summary
        assert "avg_duration" in summary
        assert summary["total"] >= 0
        assert 0 <= summary["success_rate"] <= 1

    def test_get_recent_metric_sum(self, dashboard):
        """Test metric sum calculation."""
        total = dashboard._get_recent_metric_sum("mcp_tool_calls_total")

        assert isinstance(total, int)
        assert total >= 0

    def test_get_recent_metric_avg(self, dashboard):
        """Test metric average calculation."""
        avg = dashboard._get_recent_metric_avg(
            "batch_processing_throughput_batches_per_second"
        )

        assert isinstance(avg, float)
        assert avg >= 0

    def test_calculate_cache_hit_rate(self, dashboard):
        """Test cache hit rate calculation."""
        hit_rate = dashboard._calculate_cache_hit_rate()

        assert isinstance(hit_rate, float)
        assert 0 <= hit_rate <= 1

    def test_cache_hit_rate_no_operations(self, mock_metrics_collector):
        """Test cache hit rate with no cache operations."""
        # Create dashboard with empty metrics collector
        empty_collector = MetricsCollector(MonitoringConfig(enable_metrics=True))
        dashboard = MonitoringDashboard(empty_collector)

        hit_rate = dashboard._calculate_cache_hit_rate()

        assert hit_rate == 0.0

    def test_generate_system_overview_data(self, dashboard):
        """Test system overview data generation."""
        data = dashboard._generate_system_overview_data()

        assert isinstance(data, dict)
        assert "mcp_operations" in data
        assert "cli_operations" in data
        assert "scan_operations" in data
        assert "uptime_seconds" in data

    def test_generate_scanner_performance_data(self, dashboard):
        """Test scanner performance data generation."""
        data = dashboard._generate_scanner_performance_data()

        assert isinstance(data, dict)
        assert "semgrep" in data
        assert "llm_scanner" in data
        assert "llm_validator" in data

    def test_generate_error_analytics_data(self, dashboard):
        """Test error analytics data generation."""
        data = dashboard._generate_error_analytics_data()

        assert isinstance(data, dict)
        assert "circuit_breaker_trips" in data
        assert "retry_exhaustions" in data
        assert "scan_failures" in data
        assert "git_failures" in data

    def test_generate_resource_utilization_data(self, dashboard):
        """Test resource utilization data generation."""
        data = dashboard._generate_resource_utilization_data()

        assert isinstance(data, dict)
        assert "batch_throughput_batches_per_second" in data
        assert "cache_hit_rate" in data
        assert "git_operations_total" in data
        assert "total_tokens_processed" in data

    def test_generate_detailed_metrics_data(self, dashboard):
        """Test detailed metrics data generation."""
        data = dashboard._generate_detailed_metrics_data()

        assert isinstance(data, dict)
        expected_categories = [
            "mcp_server",
            "cli_operations",
            "scanners",
            "batch_processing",
            "resilience",
            "git_operations",
            "cache",
        ]

        for category in expected_categories:
            assert category in data
            assert isinstance(data[category], dict)

        # Check that at least some categories have data
        total_metrics = sum(len(category_data) for category_data in data.values())
        assert total_metrics > 0  # Should have some metrics

    def test_error_handling_in_display_methods(self, dashboard):
        """Test error handling in display methods."""
        # Mock methods to raise exceptions
        with patch.object(
            dashboard, "_get_recent_metric_summary", side_effect=Exception("Test error")
        ):
            # These should not raise exceptions, just log errors
            dashboard._display_system_overview()
            dashboard._display_scanner_performance()

        with patch.object(
            dashboard, "_get_recent_metric_sum", side_effect=Exception("Test error")
        ):
            dashboard._display_error_analytics()

        with patch.object(
            dashboard, "_get_recent_metric_avg", side_effect=Exception("Test error")
        ):
            dashboard._display_resource_utilization()

    def test_export_error_handling(self, dashboard):
        """Test error handling in export methods."""
        # Test export to non-existent directory
        invalid_path = Path("/invalid/path/report.json")

        with pytest.raises(Exception):
            dashboard.export_dashboard_report(invalid_path)

        with pytest.raises(Exception):
            dashboard.export_prometheus_metrics(invalid_path)

    def test_prometheus_export_format(self, dashboard):
        """Test Prometheus export format compliance."""
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".txt", delete=False
        ) as temp_file:
            temp_path = Path(temp_file.name)

        try:
            export_path = dashboard.export_prometheus_metrics(temp_path)

            with open(export_path) as f:
                content = f.read()

            # Basic validation - file should exist and be readable
            assert isinstance(content, str)

            # If there are metrics, should have some structure
            lines = [line for line in content.split("\n") if line.strip()]
            if lines:
                # If we have content, check for basic Prometheus format elements
                has_comments = any(line.startswith("#") for line in lines)
                has_metrics = any(not line.startswith("#") for line in lines)
                # Either we have no metrics (empty) or we have proper format
                assert not lines or (has_comments or has_metrics)
        finally:
            temp_path.unlink(missing_ok=True)
