"""Tests for performance monitor."""

import asyncio
import time
from unittest.mock import Mock, patch

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

    @patch("psutil.Process", side_effect=Exception("Process error"))
    def test_initialization_process_error(self, mock_process):
        """Test initialization when psutil.Process fails."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        assert monitor._process is None

    @pytest.mark.asyncio
    async def test_monitoring_loop_error_handling(self):
        """Test error handling in monitoring loop."""
        config = MonitoringConfig(
            enable_performance_monitoring=True,
            performance_check_interval=0.01,  # Very short interval for testing
        )
        monitor = PerformanceMonitor(config)

        # Mock _collect_performance_metrics to raise exception first time
        call_count = 0
        original_collect = monitor._collect_performance_metrics

        async def mock_collect():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Test collection error")
            # Stop monitoring after first error + retry
            await monitor.stop_monitoring()

        monitor._collect_performance_metrics = mock_collect

        await monitor.start_monitoring()

        # Wait for the loop to run and handle error
        await asyncio.sleep(0.1)

        # Should have attempted at least one retry
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_collect_performance_metrics_no_process(self):
        """Test collecting metrics when process is None."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)
        monitor._process = None

        # Should not raise exception
        await monitor._collect_performance_metrics()

    @pytest.mark.asyncio
    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    async def test_collect_performance_metrics_success(
        self, mock_disk, mock_memory, mock_cpu
    ):
        """Test successful performance metrics collection."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        # Mock system metrics
        mock_cpu.return_value = 25.5
        mock_memory.return_value = Mock(percent=60.0)
        mock_disk.return_value = Mock(used=1000 * 1024 * 1024)  # 1GB

        # Mock process metrics
        monitor._process = Mock()
        monitor._process.memory_info.return_value = Mock(rss=500 * 1024 * 1024)  # 500MB
        monitor._process.cpu_percent.return_value = 15.0

        await monitor._collect_performance_metrics()

        # Verify metrics were updated
        assert monitor._performance_metrics.cpu_usage_percent == 25.5
        assert monitor._performance_metrics.memory_usage_percent == 60.0
        assert monitor._performance_metrics.memory_usage_mb == 500.0
        assert monitor._performance_metrics.disk_usage_mb == 1000.0

    @pytest.mark.asyncio
    @patch("psutil.cpu_percent", side_effect=Exception("CPU error"))
    async def test_collect_performance_metrics_error(self, mock_cpu):
        """Test error handling in performance metrics collection."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        # Should not raise exception despite psutil error
        await monitor._collect_performance_metrics()

    @pytest.mark.asyncio
    async def test_check_alerting_thresholds_high_cpu(self):
        """Test alerting for high CPU usage."""
        config = MonitoringConfig(cpu_threshold_percent=50.0)
        monitor = PerformanceMonitor(config)
        monitor._performance_metrics.cpu_usage_percent = 75.0

        await monitor._check_alerting_thresholds()

        assert monitor._performance_metrics.warning_count == 1

    @pytest.mark.asyncio
    async def test_check_alerting_thresholds_high_memory(self):
        """Test alerting for high memory usage."""
        config = MonitoringConfig(memory_threshold_percent=70.0)
        monitor = PerformanceMonitor(config)
        monitor._performance_metrics.memory_usage_percent = 85.0

        await monitor._check_alerting_thresholds()

        assert monitor._performance_metrics.warning_count == 1

    @pytest.mark.asyncio
    async def test_check_alerting_thresholds_with_metrics_collector(self):
        """Test alerting with metrics collector integration."""
        config = MonitoringConfig(
            cpu_threshold_percent=50.0,
            scan_time_threshold_seconds=5.0,
            error_rate_threshold_percent=10.0,
        )
        metrics_collector = Mock()
        scan_metrics = Mock()
        scan_metrics.average_scan_time = 7.0  # Above threshold
        scan_metrics.total_scans = 10
        scan_metrics.failed_scans = 2  # 20% error rate, above threshold
        metrics_collector.get_scan_metrics.return_value = scan_metrics

        monitor = PerformanceMonitor(config, metrics_collector)
        monitor._performance_metrics.cpu_usage_percent = 75.0  # Above threshold

        await monitor._check_alerting_thresholds()

        # Should have recorded 3 alerts: CPU, scan time, error rate
        assert monitor._performance_metrics.warning_count == 3
        assert metrics_collector.increment_counter.call_count == 3

    def test_record_alert(self):
        """Test recording alerts."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        monitor._record_alert("high_cpu_usage", "CPU usage is high")

        assert monitor._performance_metrics.warning_count == 1
        assert len(monitor._performance_metrics.critical_errors) == 1
        assert "high_cpu_usage" in monitor._performance_metrics.critical_errors[0]

    def test_record_alert_with_metrics_collector(self):
        """Test recording alerts with metrics collector."""
        config = MonitoringConfig()
        metrics_collector = Mock()
        monitor = PerformanceMonitor(config, metrics_collector)

        monitor._record_alert("test_alert", "Test message")

        assert monitor._performance_metrics.warning_count == 1
        metrics_collector.increment_counter.assert_called_once()

    def test_record_alert_critical_errors_limit(self):
        """Test that critical errors list is limited to 10 items."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        # Add 15 critical errors
        for i in range(15):
            monitor._record_alert("critical_error", f"Error {i}")

        # Should only keep the last 10
        assert len(monitor._performance_metrics.critical_errors) == 10
        assert "Error 14" in monitor._performance_metrics.critical_errors[-1]
        assert "Error 5" in monitor._performance_metrics.critical_errors[0]

    def test_get_current_metrics_sync_context(self):
        """Test getting current metrics in synchronous context."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        metrics = monitor.get_current_metrics()

        assert isinstance(metrics, PerformanceMetrics)
        assert metrics.cpu_usage_percent >= 0

    def test_get_current_metrics_no_process(self):
        """Test getting current metrics when process is None."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)
        monitor._process = None

        metrics = monitor.get_current_metrics()

        assert isinstance(metrics, PerformanceMetrics)

    @pytest.mark.asyncio
    async def test_get_current_metrics_with_event_loop(self):
        """Test getting current metrics with running event loop."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        # This should work in an async context
        metrics = monitor.get_current_metrics()

        assert isinstance(metrics, PerformanceMetrics)

    @patch("psutil.boot_time")
    @patch("psutil.cpu_count")
    @patch("psutil.cpu_freq")
    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    def test_get_system_info_success(
        self,
        mock_disk,
        mock_memory,
        mock_cpu_percent,
        mock_cpu_freq,
        mock_cpu_count,
        mock_boot_time,
    ):
        """Test successful system info retrieval."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        # Mock system calls
        mock_boot_time.return_value = 1000.0
        mock_cpu_count.side_effect = [4, 8]  # physical, logical
        mock_cpu_freq.return_value = Mock(_asdict=lambda: {"current": 2400.0})
        mock_cpu_percent.return_value = 25.0
        mock_memory.return_value = Mock(
            _asdict=lambda: {
                "total": 8 * 1024**3,
                "available": 4 * 1024**3,
                "used": 4 * 1024**3,
            }
        )
        mock_disk.return_value = Mock(
            _asdict=lambda: {
                "total": 1000 * 1024**3,
                "used": 500 * 1024**3,
                "available": 500 * 1024**3,
            }
        )

        info = monitor.get_system_info()

        assert "system" in info
        assert "cpu" in info
        assert "memory" in info
        assert "disk" in info
        assert info["cpu"]["physical_cores"] == 4
        assert info["cpu"]["logical_cores"] == 8
        assert info["memory"]["total_gb"] == 8.0
        assert info["disk"]["total_gb"] == 1000.0

    @patch("psutil.boot_time", side_effect=Exception("System error"))
    def test_get_system_info_error(self, mock_boot_time):
        """Test system info error handling."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        info = monitor.get_system_info()

        assert "error" in info
        assert "System error" in info["error"]

    def test_record_scan_activity(self):
        """Test recording scan activity."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        monitor.record_scan_activity(5, 10)

        assert monitor._performance_metrics.active_scans == 5
        assert monitor._performance_metrics.queue_length == 10

    def test_record_scan_activity_with_metrics_collector(self):
        """Test recording scan activity with metrics collector."""
        config = MonitoringConfig()
        metrics_collector = Mock()
        monitor = PerformanceMonitor(config, metrics_collector)

        monitor.record_scan_activity(3, 7)

        assert monitor._performance_metrics.active_scans == 3
        assert monitor._performance_metrics.queue_length == 7
        assert metrics_collector.set_gauge.call_count == 2

    def test_record_error_non_critical(self):
        """Test recording non-critical errors."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        monitor.record_error("test_error", is_critical=False)

        assert monitor._performance_metrics.error_count == 1
        assert len(monitor._performance_metrics.critical_errors) == 0

    def test_record_error_critical(self):
        """Test recording critical errors."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        monitor.record_error("critical_test", is_critical=True)

        assert monitor._performance_metrics.error_count == 1
        assert len(monitor._performance_metrics.critical_errors) == 1
        assert (
            "Critical error: critical_test"
            in monitor._performance_metrics.critical_errors[0]
        )

    def test_record_error_critical_with_limit(self):
        """Test critical error recording with limit."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        # Add 15 critical errors
        for i in range(15):
            monitor.record_error(f"error_{i}", is_critical=True)

        # Should only keep 10 most recent
        assert len(monitor._performance_metrics.critical_errors) == 10
        assert "error_14" in monitor._performance_metrics.critical_errors[-1]

    def test_record_error_with_metrics_collector(self):
        """Test recording errors with metrics collector."""
        config = MonitoringConfig()
        metrics_collector = Mock()
        monitor = PerformanceMonitor(config, metrics_collector)

        monitor.record_error("test_error", is_critical=True)

        assert monitor._performance_metrics.error_count == 1
        metrics_collector.increment_counter.assert_called_once()

    def test_get_health_status_healthy(self):
        """Test health status when system is healthy."""
        config = MonitoringConfig(
            cpu_threshold_percent=80.0, memory_threshold_percent=80.0
        )
        monitor = PerformanceMonitor(config)
        monitor._performance_metrics.cpu_usage_percent = 50.0
        monitor._performance_metrics.memory_usage_percent = 60.0
        monitor._performance_metrics.last_heartbeat = time.time()

        status = monitor.get_health_status()

        assert status["status"] == "healthy"
        assert len(status["issues"]) == 0

    def test_get_health_status_warning(self):
        """Test health status with warnings."""
        config = MonitoringConfig(
            cpu_threshold_percent=50.0, memory_threshold_percent=50.0
        )
        monitor = PerformanceMonitor(config)
        monitor._performance_metrics.cpu_usage_percent = 75.0  # Above threshold
        monitor._performance_metrics.memory_usage_percent = 60.0  # Above threshold
        monitor._performance_metrics.last_heartbeat = time.time()

        status = monitor.get_health_status()

        assert status["status"] == "warning"
        assert len(status["issues"]) == 2
        assert any("High CPU usage" in issue for issue in status["issues"])
        assert any("High memory usage" in issue for issue in status["issues"])

    def test_get_health_status_critical(self):
        """Test health status with critical issues."""
        config = MonitoringConfig(performance_check_interval=1.0)
        monitor = PerformanceMonitor(config)
        monitor._performance_metrics.critical_errors = ["Critical error 1"]
        monitor._performance_metrics.last_heartbeat = time.time() - 10  # Old heartbeat

        status = monitor.get_health_status()

        assert status["status"] == "critical"
        assert len(status["issues"]) == 2
        assert any("critical errors" in issue for issue in status["issues"])
        assert any("not responsive" in issue for issue in status["issues"])

    def test_get_health_status_includes_metadata(self):
        """Test that health status includes required metadata."""
        config = MonitoringConfig()
        monitor = PerformanceMonitor(config)

        status = monitor.get_health_status()

        assert "status" in status
        assert "timestamp" in status
        assert "uptime_seconds" in status
        assert "issues" in status
        assert "metrics_summary" in status
        assert isinstance(status["uptime_seconds"], float)
        assert isinstance(status["timestamp"], float)
