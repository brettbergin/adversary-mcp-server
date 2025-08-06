"""Tests for performance monitor."""

from unittest.mock import patch

import pytest

from adversary_mcp_server.monitoring.performance_monitor import PerformanceMonitor
from adversary_mcp_server.monitoring.types import MonitoringConfig, PerformanceMetrics


class TestPerformanceMonitor:
    """Test PerformanceMonitor class."""

    def test_initialization(self):
        """Test performance monitor initialization."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        assert monitor.config == config
        assert monitor._monitoring_task is None

    @patch("psutil.Process")
    def test_initialization_with_process(self, mock_process):
        """Test initialization with psutil process."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        assert monitor._process is not None

    def test_get_current_metrics(self):
        """Test getting current metrics."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        metrics = monitor.get_current_metrics()

        assert isinstance(metrics, PerformanceMetrics)
        assert metrics.cpu_usage_percent >= 0
        assert metrics.memory_usage_mb >= 0

    def test_record_error(self):
        """Test recording errors."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        monitor.record_error("test_error", is_critical=True)

        metrics = monitor.get_current_metrics()
        assert metrics.error_count >= 1

    def test_record_scan_activity(self):
        """Test recording scan activity."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        monitor.record_scan_activity(3, 10)

        metrics = monitor.get_current_metrics()
        assert metrics.active_scans == 3
        assert metrics.queue_length == 10

    def test_get_system_info(self):
        """Test getting system info."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        info = monitor.get_system_info()

        assert isinstance(info, dict)
        assert "cpu" in info
        assert "memory" in info
        assert "system" in info

    def test_get_health_status(self):
        """Test getting health status."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        status = monitor.get_health_status()

        assert isinstance(status, dict)
        assert "status" in status
        assert status["status"] in ["healthy", "warning", "critical"]

    @pytest.mark.asyncio
    async def test_start_monitoring_enabled(self):
        """Test starting monitoring when enabled."""
        config = MonitoringConfig(enable_performance_monitoring=True)
        monitor = PerformanceMonitor(config)

        await monitor.start_monitoring()

        assert monitor._monitoring_task is not None

        # Clean up
        await monitor.stop_monitoring()

    @pytest.mark.asyncio
    async def test_start_monitoring_disabled(self):
        """Test starting monitoring when disabled."""
        config = MonitoringConfig(enable_performance_monitoring=False)
        monitor = PerformanceMonitor(config)

        await monitor.start_monitoring()

        assert monitor._monitoring_task is None

    @pytest.mark.asyncio
    async def test_stop_monitoring(self):
        """Test stopping monitoring."""
        config = MonitoringConfig(enable_performance_monitoring=True)
        monitor = PerformanceMonitor(config)

        await monitor.start_monitoring()
        assert monitor._monitoring_task is not None

        await monitor.stop_monitoring()
        # Task might still exist but should be cancelled
        if monitor._monitoring_task:
            assert monitor._monitoring_task.cancelled()
