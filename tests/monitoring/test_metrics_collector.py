"""Tests for metrics collector."""

import asyncio
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from adversary_mcp_server.monitoring.metrics_collector import (
    MetricsCollector,
    TimingContext,
)
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

    def test_record_metric_disabled(self):
        """Test recording metrics when disabled."""
        config = MonitoringConfig(enable_metrics=False)
        collector = MetricsCollector(config)

        collector.record_metric("test_metric", 42.0)

        # Should not record when disabled
        assert "test_metric" not in collector._metrics

    def test_record_file_processed_success(self):
        """Test recording successful file processing."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_file_processed("/path/test.py", 1024, 0.5, True)

        assert collector._scan_metrics.files_processed == 1
        assert collector._scan_metrics.total_file_size_bytes == 1024
        assert collector._scan_metrics.files_failed == 0

    def test_record_file_processed_failure(self):
        """Test recording failed file processing."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_file_processed("/path/test.py", 1024, 0.5, False)

        assert collector._scan_metrics.files_processed == 0
        assert collector._scan_metrics.total_file_size_bytes == 0
        assert collector._scan_metrics.files_failed == 1

    def test_record_finding(self):
        """Test recording security findings."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_finding("semgrep", "high", "injection")

        assert collector._scan_metrics.findings_by_scanner["semgrep"] == 1
        assert collector._scan_metrics.findings_by_severity["high"] == 1
        assert collector._scan_metrics.findings_by_category["injection"] == 1

    def test_record_cache_operation_hit(self):
        """Test recording cache hit."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_cache_operation("scan", True)

        assert collector._scan_metrics.cache_hits == 1
        assert collector._scan_metrics.cache_misses == 0

    def test_record_cache_operation_miss(self):
        """Test recording cache miss."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_cache_operation("scan", False)

        assert collector._scan_metrics.cache_hits == 0
        assert collector._scan_metrics.cache_misses == 1

    def test_record_llm_request_success(self):
        """Test recording successful LLM request."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_llm_request("openai", "gpt-4", 500, 1.5, True)

        assert collector._scan_metrics.llm_requests == 1
        assert collector._scan_metrics.llm_tokens_consumed == 500
        assert collector._scan_metrics.llm_average_response_time == 1.5
        assert collector._scan_metrics.llm_errors == 0

    def test_record_llm_request_failure(self):
        """Test recording failed LLM request."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_llm_request("openai", "gpt-4", 500, 1.5, False)

        assert collector._scan_metrics.llm_requests == 1
        assert collector._scan_metrics.llm_tokens_consumed == 0
        assert collector._scan_metrics.llm_errors == 1

    def test_record_llm_request_average_calculation(self):
        """Test LLM average response time calculation."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        # First request: 1.0 seconds
        collector.record_llm_request("openai", "gpt-4", 100, 1.0, True)
        assert collector._scan_metrics.llm_average_response_time == 1.0

        # Second request: 2.0 seconds -> average should be 1.5
        collector.record_llm_request("openai", "gpt-4", 100, 2.0, True)
        assert collector._scan_metrics.llm_average_response_time == 1.5

    def test_record_batch_processing(self):
        """Test recording batch processing metrics."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_batch_processing(10, 5.0, 8, 2)

        assert collector._scan_metrics.batches_processed == 1

    def test_get_metric_history(self):
        """Test getting metric history."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        collector.record_metric("test", 1.0)
        collector.record_metric("test", 2.0)
        collector.record_metric("test", 3.0)

        history = collector.get_metric_history("test")
        assert len(history) == 3
        assert history[0].value == 1.0
        assert history[1].value == 2.0
        assert history[2].value == 3.0

    def test_get_metric_history_limited(self):
        """Test getting limited metric history."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        for i in range(10):
            collector.record_metric("test", float(i))

        history = collector.get_metric_history("test", limit=3)
        assert len(history) == 3
        assert history[0].value == 7.0  # Last 3 items
        assert history[1].value == 8.0
        assert history[2].value == 9.0

    def test_get_metric_history_nonexistent(self):
        """Test getting history for non-existent metric."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        history = collector.get_metric_history("nonexistent")
        assert history == []

    def test_timing_context(self):
        """Test timing context manager."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        with collector.time_operation("test_operation") as timer:
            time.sleep(0.01)  # Sleep for 10ms

        # Should have recorded a histogram metric
        assert "test_operation_duration_seconds" in collector._metrics
        metrics = list(collector._metrics["test_operation_duration_seconds"])
        assert len(metrics) == 1
        assert metrics[0].value >= 0.01  # Should be at least 10ms

    def test_custom_export_path(self):
        """Test initialization with custom export path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = MonitoringConfig(json_export_path=temp_dir)
            collector = MetricsCollector(config)

            assert collector.export_path == Path(temp_dir)

    @pytest.mark.asyncio
    async def test_start_collection_already_running(self):
        """Test starting collection when already running."""
        config = MonitoringConfig(enable_metrics=True)
        collector = MetricsCollector(config)

        # Start collection
        await collector.start_collection()

        # Try to start again - should log warning
        await collector.start_collection()

        # Clean up
        await collector.stop_collection()

    @pytest.mark.asyncio
    async def test_start_collection_disabled(self):
        """Test starting collection when metrics disabled."""
        config = MonitoringConfig(enable_metrics=False)
        collector = MetricsCollector(config)

        await collector.start_collection()

        assert collector._background_task is None

    @pytest.mark.asyncio
    async def test_collection_loop_error_handling(self):
        """Test error handling in collection loop."""
        config = MonitoringConfig(
            enable_metrics=True,
            collection_interval_seconds=0.1,  # Short interval for testing
        )
        collector = MetricsCollector(config)

        # Mock periodic tasks to raise an exception
        call_count = 0

        async def mock_periodic_tasks():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Test error")
            else:
                # Stop after first error + retry
                await collector.stop_collection()

        collector._periodic_tasks = mock_periodic_tasks

        await collector.start_collection()

        # Wait a bit for the loop to run and handle error
        await asyncio.sleep(0.5)

        # Should have attempted at least one retry
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_cleanup_old_metrics(self):
        """Test cleanup of old metrics."""
        config = MonitoringConfig(metrics_retention_hours=1)  # 1 hour retention
        collector = MetricsCollector(config)

        # Add a metric
        collector.record_metric("test", 1.0)
        assert len(collector._metrics["test"]) == 1

        # Manually set the metric timestamp to be old
        old_metric = collector._metrics["test"][0]
        old_metric.timestamp = time.time() - (2 * 3600)  # 2 hours ago

        # Run cleanup
        await collector._cleanup_old_metrics()

        # Old metric should be cleaned up
        assert len(collector._metrics["test"]) == 0

    def test_export_metrics_disabled(self):
        """Test export when disabled."""
        config = MonitoringConfig(enable_json_export=False)
        collector = MetricsCollector(config)

        result = collector.export_metrics()
        assert result is None

    def test_export_metrics_json(self):
        """Test JSON export functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = MonitoringConfig(
                enable_json_export=True, json_export_path=temp_dir
            )
            collector = MetricsCollector(config)

            # Add some test data
            collector.record_metric("test_metric", 42.0)
            collector.record_scan_start("test_scan", 5)

            # Export metrics
            export_path = collector.export_metrics()

            assert export_path is not None
            assert Path(export_path).exists()

            # Verify export content
            with open(export_path) as f:
                data = json.load(f)

            assert "timestamp" in data
            assert "uptime_seconds" in data
            assert "scan_metrics" in data
            assert "raw_metrics" in data

    @patch("builtins.open", side_effect=OSError("Test error"))
    def test_export_metrics_error(self, mock_open):
        """Test export error handling."""
        config = MonitoringConfig(enable_json_export=True)
        collector = MetricsCollector(config)

        result = collector.export_metrics()
        assert result is None

    def test_export_metrics_unsupported_format(self):
        """Test export with unsupported format."""
        config = MonitoringConfig(enable_json_export=True)
        collector = MetricsCollector(config)

        result = collector.export_metrics(format="xml")
        assert result is None

    @pytest.mark.asyncio
    async def test_export_metrics_async(self):
        """Test async export functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = MonitoringConfig(
                enable_json_export=True, json_export_path=temp_dir
            )
            collector = MetricsCollector(config)

            # Add test data
            collector.record_metric("async_test", 123.0)

            # Test async export
            await collector._export_metrics_async()

            # Should have created export file
            export_files = list(Path(temp_dir).glob("metrics_*.json"))
            assert len(export_files) > 0

    @pytest.mark.asyncio
    async def test_export_metrics_async_error(self):
        """Test async export error handling."""
        config = MonitoringConfig(enable_json_export=True)
        collector = MetricsCollector(config)

        # Mock export_metrics to raise an exception
        original_export = collector.export_metrics
        collector.export_metrics = MagicMock(side_effect=Exception("Test error"))

        # Should not raise exception
        await collector._export_metrics_async()

    @pytest.mark.asyncio
    async def test_periodic_tasks(self):
        """Test periodic tasks execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = MonitoringConfig(
                enable_json_export=True,
                json_export_path=temp_dir,
                metrics_retention_hours=24,  # Don't clean up during test
            )
            collector = MetricsCollector(config)

            # Add test data
            collector.record_metric("periodic_test", 456.0)

            # Run periodic tasks
            await collector._periodic_tasks()

            # Should have exported metrics
            export_files = list(Path(temp_dir).glob("metrics_*.json"))
            assert len(export_files) > 0


class TestTimingContext:
    """Test TimingContext class."""

    def test_timing_context_success(self):
        """Test successful timing context."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        context = TimingContext(collector, "test_op", {"label": "value"})

        with context:
            time.sleep(0.01)

        # Check that metric was recorded
        assert "test_op_duration_seconds" in collector._metrics
        metrics = list(collector._metrics["test_op_duration_seconds"])
        assert len(metrics) == 1
        assert metrics[0].value >= 0.01
        assert metrics[0].labels["label"] == "value"

    def test_timing_context_with_exception(self):
        """Test timing context when exception occurs."""
        config = MonitoringConfig()
        collector = MetricsCollector(config)

        context = TimingContext(collector, "test_op_error")

        try:
            with context:
                time.sleep(0.01)
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Should still record metric even with exception
        assert "test_op_error_duration_seconds" in collector._metrics
        metrics = list(collector._metrics["test_op_error_duration_seconds"])
        assert len(metrics) == 1
