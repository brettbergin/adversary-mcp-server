"""Tests for monitoring types."""

from adversary_mcp_server.monitoring.types import (
    MetricData,
    MetricType,
    MonitoringConfig,
    PerformanceMetrics,
    ScanMetrics,
)


class TestMetricType:
    """Test MetricType enum."""

    def test_metric_types(self):
        """Test metric type values."""
        assert MetricType.COUNTER == "counter"
        assert MetricType.GAUGE == "gauge"
        assert MetricType.HISTOGRAM == "histogram"
        assert MetricType.TIMER == "timer"


class TestMetricData:
    """Test MetricData dataclass."""

    def test_metric_data_creation(self):
        """Test creating metric data."""
        metric = MetricData(
            name="test_metric", metric_type=MetricType.COUNTER, value=42.0
        )

        assert metric.name == "test_metric"
        assert metric.metric_type == MetricType.COUNTER
        assert metric.value == 42.0
        assert metric.timestamp > 0
        assert metric.labels == {}
        assert metric.unit is None

    def test_metric_data_with_labels(self):
        """Test metric data with labels."""
        metric = MetricData(
            name="test_metric",
            metric_type=MetricType.GAUGE,
            value=3.14,
            labels={"env": "test", "service": "scanner"},
            unit="seconds",
        )

        assert metric.labels == {"env": "test", "service": "scanner"}
        assert metric.unit == "seconds"

    def test_metric_data_to_dict(self):
        """Test converting metric data to dictionary."""
        metric = MetricData(
            name="test_metric",
            metric_type=MetricType.HISTOGRAM,
            value=100.5,
            labels={"key": "value"},
        )

        metric_dict = metric.to_dict()

        assert isinstance(metric_dict, dict)
        assert metric_dict["name"] == "test_metric"
        assert metric_dict["type"] == "histogram"
        assert metric_dict["value"] == 100.5
        assert "timestamp" in metric_dict
        assert metric_dict["labels"] == {"key": "value"}

    def test_metric_data_from_dict(self):
        """Test creating metric data from dictionary."""
        data = {
            "name": "from_dict_metric",
            "type": "timer",
            "value": 25.0,
            "timestamp": 1234567890.123,
            "labels": {"test": "true"},
        }

        metric = MetricData.from_dict(data)

        assert metric.name == "from_dict_metric"
        assert metric.metric_type == MetricType.TIMER
        assert metric.value == 25.0
        assert metric.timestamp == 1234567890.123
        assert metric.labels == {"test": "true"}

    def test_performance_metrics_dict_conversion(self):
        """Test PerformanceMetrics dict conversion methods."""
        metrics = PerformanceMetrics(
            cpu_usage_percent=75.5,
            memory_usage_mb=512.0,
            error_count=3,
            critical_error_count=1,
        )

        # Test to_dict
        metrics_dict = metrics.to_dict()
        assert metrics_dict["cpu_usage_percent"] == 75.5
        assert metrics_dict["memory_usage_mb"] == 512.0
        assert metrics_dict["error_count"] == 3

        # Test from_dict
        reconstructed = PerformanceMetrics.from_dict(metrics_dict)
        assert reconstructed.cpu_usage_percent == 75.5
        assert reconstructed.memory_usage_mb == 512.0
        assert reconstructed.error_count == 3

    def test_scan_metrics_dict_conversion(self):
        """Test ScanMetrics dict conversion methods."""
        metrics = ScanMetrics(
            files_scanned=10,
            threats_found=2,
            scan_duration_seconds=45.3,
            lines_of_code=1500,
        )

        # Test to_dict
        metrics_dict = metrics.to_dict()
        assert metrics_dict["files_scanned"] == 10
        assert metrics_dict["threats_found"] == 2
        assert metrics_dict["scan_duration_seconds"] == 45.3

        # Test from_dict
        reconstructed = ScanMetrics.from_dict(metrics_dict)
        assert reconstructed.files_scanned == 10
        assert reconstructed.threats_found == 2
        assert reconstructed.scan_duration_seconds == 45.3


class TestScanMetrics:
    """Test ScanMetrics dataclass."""

    def test_scan_metrics_defaults(self):
        """Test default scan metrics."""
        metrics = ScanMetrics()

        assert metrics.total_scans == 0
        assert metrics.successful_scans == 0
        assert metrics.failed_scans == 0
        assert metrics.total_scan_time == 0.0
        assert metrics.average_scan_time == 0.0

    def test_calculate_derived_metrics(self):
        """Test calculating derived metrics."""
        metrics = ScanMetrics(
            total_scans=10,
            successful_scans=8,
            failed_scans=2,
            total_scan_time=100.0,
            files_processed=50,
            total_file_size_bytes=1048576,  # 1MB
            cache_hits=30,
            cache_misses=20,
        )

        metrics.calculate_derived_metrics()

        assert metrics.average_scan_time == 10.0
        assert metrics.average_file_size_bytes == 20971.52  # 1MB / 50
        assert metrics.cache_hit_rate == 0.6

    def test_to_dict(self):
        """Test converting to dictionary."""
        metrics = ScanMetrics(
            total_scans=5, successful_scans=4, failed_scans=1, total_findings=10
        )

        result = metrics.to_dict()

        assert isinstance(result, dict)
        assert "scan_execution" in result
        assert "file_processing" in result
        assert "findings" in result
        assert result["scan_execution"]["total_scans"] == 5
        assert result["scan_execution"]["success_rate"] == 0.8


class TestPerformanceMetrics:
    """Test PerformanceMetrics dataclass."""

    def test_performance_metrics_defaults(self):
        """Test default performance metrics."""
        metrics = PerformanceMetrics()

        assert metrics.cpu_usage_percent == 0.0
        assert metrics.memory_usage_mb == 0.0
        assert metrics.active_scans == 0
        assert metrics.error_count == 0

    def test_to_dict(self):
        """Test converting to dictionary."""
        metrics = PerformanceMetrics(
            cpu_usage_percent=45.5, memory_usage_mb=512.0, active_scans=2, error_count=3
        )

        result = metrics.to_dict()

        assert isinstance(result, dict)
        assert "system_resources" in result
        assert "application_state" in result
        assert result["system_resources"]["cpu_usage_percent"] == 45.5
        assert result["application_state"]["active_scans"] == 2


class TestMonitoringConfig:
    """Test MonitoringConfig dataclass."""

    def test_monitoring_config_defaults(self):
        """Test default configuration."""
        config = MonitoringConfig()

        assert config.enable_metrics is True
        assert config.collection_interval_seconds == 30
        assert config.metrics_retention_hours == 24

    def test_monitoring_config_custom(self):
        """Test custom configuration."""
        config = MonitoringConfig(
            enable_metrics=False, collection_interval_seconds=60, prometheus_port=9090
        )

        assert config.enable_metrics is False
        assert config.collection_interval_seconds == 60
        assert config.prometheus_port == 9090
