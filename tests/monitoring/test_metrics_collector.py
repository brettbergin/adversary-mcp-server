"""Tests for metrics collector."""

import pytest

from adversary_mcp_server.monitoring.metrics_collector import MetricsCollector
from adversary_mcp_server.monitoring.types import MetricType, MonitoringConfig


class TestMetricsCollector:
    """Test MetricsCollector class."""

    def test_initialization(self):
        """Test metrics collector initialization."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        assert collector.config == config
        assert collector._background_task is None

    def test_record_metric_basic(self):
        """Test recording a basic metric."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_metric("test_metric", 42.0, MetricType.COUNTER)

        assert "test_metric" in collector._metrics
        metrics = list(collector._metrics["test_metric"])
        assert len(metrics) == 1
        assert metrics[0].value == 42.0
        assert metrics[0].metric_type == MetricType.COUNTER

    def test_increment_counter(self):
        """Test incrementing a counter."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.increment_counter("requests", 1.0)
        collector.increment_counter("requests", 2.0)

        metrics = list(collector._metrics["requests"])
        assert len(metrics) == 2
        assert metrics[0].value == 1.0
        assert metrics[1].value == 2.0

    def test_set_gauge(self):
        """Test setting a gauge."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.set_gauge("memory_usage", 75.5, unit="percent")

        metrics = list(collector._metrics["memory_usage"])
        assert len(metrics) == 1
        assert metrics[0].value == 75.5
        assert metrics[0].metric_type == MetricType.GAUGE
        assert metrics[0].unit == "percent"

    def test_record_histogram(self):
        """Test recording a histogram."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_histogram("response_time", 123.45, unit="ms")

        metrics = list(collector._metrics["response_time"])
        assert len(metrics) == 1
        assert metrics[0].value == 123.45
        assert metrics[0].metric_type == MetricType.HISTOGRAM

    def test_record_scan_start(self):
        """Test recording scan start."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_scan_start("security_scan", 5)

        assert collector._scan_metrics.total_scans == 1

    def test_record_scan_completion(self):
        """Test recording scan completion."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_scan_completion("security_scan", 10.5, True, 3)

        assert collector._scan_metrics.successful_scans == 1
        assert collector._scan_metrics.total_scan_time == 10.5
        assert collector._scan_metrics.total_findings == 3

    def test_get_scan_metrics(self):
        """Test getting scan metrics."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_scan_start("test", 1)
        collector.record_scan_completion("test", 5.0, True, 2)

        metrics = collector.get_scan_metrics()
        assert metrics.total_scans == 1
        assert metrics.successful_scans == 1
        assert metrics.total_scan_time == 5.0

    def test_reset_metrics(self):
        """Test resetting metrics."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_metric("test", 1.0)
        collector.record_scan_start("scan", 1)

        collector.reset_metrics()

        assert len(collector._metrics) == 0
        assert collector._scan_metrics.total_scans == 0

    @pytest.mark.asyncio
    async def test_start_stop_collection(self):
        """Test starting and stopping collection."""
        config = MonitoringConfig(enable_metrics=True)
        collector = MetricsCollector(config)

        await collector.start_collection()
        assert collector._background_task is not None

        await collector.stop_collection()
        assert collector._background_task is None

    def test_get_summary(self):
        """Test getting metrics summary."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_scan_start("test", 1)
        summary = collector.get_summary()

        assert "collection_info" in summary
        assert "scan_metrics" in summary
        assert summary["collection_info"]["metrics_enabled"] is True
