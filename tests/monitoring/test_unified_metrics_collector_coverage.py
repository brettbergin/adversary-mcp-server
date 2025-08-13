"""Comprehensive test coverage for UnifiedMetricsCollector missing lines."""

import asyncio
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

from adversary_mcp_server.database.models import AdversaryDatabase
from adversary_mcp_server.monitoring.types import MonitoringConfig
from adversary_mcp_server.monitoring.unified_metrics_collector import (
    UnifiedMetricsCollector,
)


@pytest.fixture
def temp_db_path():
    """Create a temporary database path for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir) / "test_metrics.db"


@pytest.fixture
def test_db(temp_db_path):
    """Create a test database instance."""
    db = AdversaryDatabase(temp_db_path)
    yield db
    db.close()


@pytest.fixture
def monitoring_config():
    """Create a monitoring config for testing."""
    return MonitoringConfig(
        enable_metrics=True,
        enable_performance_monitoring=True,
        json_export_path="",
    )


@pytest.fixture
def monitoring_config_with_export_path():
    """Create a monitoring config with custom export path."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield MonitoringConfig(
            enable_metrics=True,
            enable_performance_monitoring=True,
            json_export_path=str(Path(temp_dir) / "custom_export"),
        )


class TestUnifiedMetricsCollectorCoverage:
    """Test coverage for UnifiedMetricsCollector missing lines."""

    def test_init_with_custom_export_path(self, monitoring_config_with_export_path):
        """Test initialization with custom export path (lines 39-44)."""
        collector = UnifiedMetricsCollector(monitoring_config_with_export_path)

        assert collector.export_path == Path(
            monitoring_config_with_export_path.json_export_path
        )
        assert collector.export_path.exists()

    def test_init_telemetry_initialization_failure(self, monitoring_config):
        """Test telemetry initialization failure (lines 56-62)."""
        with patch(
            "adversary_mcp_server.monitoring.unified_metrics_collector.AdversaryDatabase"
        ) as mock_db_cls:
            mock_db_cls.side_effect = Exception("Database initialization failed")

            collector = UnifiedMetricsCollector(monitoring_config)

            assert collector.telemetry_enabled is False
            assert collector.db is None
            assert collector.telemetry_service is None
            assert collector.metrics_orchestrator is None

    @pytest.mark.asyncio
    async def test_start_collection_already_running(self, monitoring_config):
        """Test start_collection when already running (lines 71-73)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        # Mock a running task
        mock_task = Mock()
        mock_task.done.return_value = False
        collector._background_task = mock_task

        await collector.start_collection()

        # Should not create a new task

    @pytest.mark.asyncio
    async def test_start_collection_metrics_disabled(self, monitoring_config):
        """Test start_collection with metrics disabled (lines 78-79)."""
        monitoring_config.enable_metrics = False
        collector = UnifiedMetricsCollector(monitoring_config)

        await collector.start_collection()

        assert collector._background_task is None

    @pytest.mark.asyncio
    async def test_stop_collection_with_task(self, monitoring_config):
        """Test stop_collection with running task (lines 83-89)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        # Create a real task that can be cancelled
        async def dummy_task():
            await asyncio.sleep(10)  # Long sleep to ensure it gets cancelled

        collector._background_task = asyncio.create_task(dummy_task())

        await collector.stop_collection()

    def test_record_metric_disabled(self, monitoring_config):
        """Test record_metric when metrics disabled (line 101)."""
        monitoring_config.enable_metrics = False
        collector = UnifiedMetricsCollector(monitoring_config)

        collector.record_metric("test_metric", 1.0)

        assert len(collector._metrics) == 0

    def test_record_metric_with_cache_telemetry_failure(
        self, monitoring_config, test_db
    ):
        """Test record_metric with cache telemetry failure (lines 134-137)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.metrics_orchestrator = Mock()
        collector.metrics_orchestrator.track_cache_operation.side_effect = Exception(
            "Telemetry failed"
        )

        # This should not raise an exception
        collector.record_metric("cache_hits", 5.0, labels={"cache_type": "test"})

    def test_record_cache_operation_telemetry_failure(self, monitoring_config):
        """Test record_cache_operation with telemetry failure (lines 169-170)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.metrics_orchestrator = Mock()
        collector.metrics_orchestrator.track_cache_operation.side_effect = Exception(
            "Cache telemetry failed"
        )

        # This should not raise an exception
        collector.record_cache_operation("get", hit=True, cache_type="test")

    def test_record_scan_completion_boolean_first_arg(self, monitoring_config):
        """Test record_scan_completion with boolean as first duration arg (lines 202-205)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        collector.record_scan_completion(
            "file", True, duration_ms=1500.0, findings_count=3
        )

        scan_metrics = collector.get_scan_metrics()
        assert scan_metrics.successful_scans > 0

    def test_record_scan_completion_with_success_param(self, monitoring_config):
        """Test record_scan_completion with explicit success parameter (lines 206-209)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        collector.record_scan_completion("file", 1.5, success=True, findings_count=2)

        scan_metrics = collector.get_scan_metrics()
        assert scan_metrics.successful_scans > 0

    def test_record_scan_completion_default_handling(self, monitoring_config):
        """Test record_scan_completion default handling (lines 211-217)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        # Test with invalid duration type
        collector.record_scan_completion("file", "invalid_duration")

        scan_metrics = collector.get_scan_metrics()
        assert scan_metrics.successful_scans > 0

    def test_record_scan_completion_failure(self, monitoring_config):
        """Test record_scan_completion with failure (line 224)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        collector.record_scan_completion("file", False)

        scan_metrics = collector.get_scan_metrics()
        assert scan_metrics.failed_scans > 0

    def test_get_telemetry_data_disabled(self, monitoring_config):
        """Test get_telemetry_data when disabled (line 249)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = False

        result = collector.get_telemetry_data()

        assert result is None

    def test_get_telemetry_data_exception(self, monitoring_config, test_db):
        """Test get_telemetry_data with exception (lines 253-255)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.telemetry_service = Mock()
        collector.telemetry_service.get_dashboard_data.side_effect = Exception(
            "Telemetry error"
        )

        result = collector.get_telemetry_data()

        assert result is None

    @pytest.mark.asyncio
    async def test_export_metrics_unsupported_format(self, monitoring_config):
        """Test export_metrics with unsupported format (lines 261-263)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        result = await collector.export_metrics("xml")

        assert result is None

    @pytest.mark.asyncio
    async def test_export_json_with_telemetry_data(self, monitoring_config, test_db):
        """Test _export_json with telemetry data (lines 286-289)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.telemetry_service = Mock()
        collector.telemetry_service.get_dashboard_data.return_value = {
            "mcp_tools": [],
            "scan_engine": {},
        }

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("json.dump") as mock_json_dump:
                result = await collector._export_json()

                assert result is not None
                mock_json_dump.assert_called_once()

    @pytest.mark.asyncio
    async def test_export_json_exception(self, monitoring_config):
        """Test _export_json with exception (lines 299-301)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        with patch("builtins.open", side_effect=Exception("File write error")):
            result = await collector._export_json()

            assert result is None

    @pytest.mark.asyncio
    async def test_collection_loop_export_disabled(self, monitoring_config):
        """Test _collection_loop with export disabled (lines 315-316)."""
        monitoring_config.enable_metrics = False
        collector = UnifiedMetricsCollector(monitoring_config)

        # Mock export_metrics to verify it's called/not called
        collector.export_metrics = Mock()

        # Create a task that will run once and then be cancelled
        async def mock_loop():
            await collector._collection_loop()

        task = asyncio.create_task(mock_loop())
        await asyncio.sleep(0.01)  # Let it start
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_collection_loop_exception_handling(self, monitoring_config):
        """Test _collection_loop exception handling (lines 323-325)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        # Mock export_metrics to raise an exception
        collector.export_metrics = Mock(side_effect=Exception("Export failed"))

        # Mock asyncio.sleep to avoid actual waiting
        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.side_effect = [
                None,
                asyncio.CancelledError(),
            ]  # First sleep succeeds, second cancels

            try:
                await collector._collection_loop()
            except asyncio.CancelledError:
                pass

    def test_cleanup_old_metrics_threshold(self, monitoring_config):
        """Test _cleanup_old_metrics when threshold exceeded (lines 331-335)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        # Add many metrics to trigger cleanup
        for i in range(950):
            collector.record_metric("test_metric", float(i))

        initial_count = len(collector._metrics["test_metric"])
        collector._cleanup_old_metrics()
        final_count = len(collector._metrics["test_metric"])

        # Should have removed some metrics
        assert final_count < initial_count

    def test_record_llm_request_with_cost(self, monitoring_config):
        """Test record_llm_request with cost (lines 376-379)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        collector.record_llm_request(
            provider="anthropic",
            model="claude-3",
            tokens_used=1000,
            cost_usd=0.05,
        )

        metrics = collector.get_metrics()
        assert "llm_cost_usd_total" in metrics

    def test_record_llm_request_with_duration(self, monitoring_config):
        """Test record_llm_request with duration (lines 382-385)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        collector.record_llm_request(
            provider="openai",
            model="gpt-4",
            tokens_used=500,
            duration_ms=1500.0,
        )

        metrics = collector.get_metrics()
        assert "llm_request_duration_ms" in metrics

    def test_time_operation_context_manager(self, monitoring_config):
        """Test time_operation context manager (lines 393-407)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        with collector.time_operation("test_operation", {"type": "test"}):
            time.sleep(0.01)  # Small delay

        metrics = collector.get_metrics()
        assert "test_operation_duration_ms" in metrics

    def test_get_summary_with_telemetry(self, monitoring_config, test_db):
        """Test get_summary with telemetry data (lines 431-442)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.telemetry_service = Mock()
        collector.telemetry_service.get_dashboard_data.return_value = {
            "scan_engine": {"total_scans": 10},
            "mcp_tools": [{"tool": "test"}],
            "cli_commands": [{"command": "scan"}],
        }

        summary = collector.get_summary()

        assert "telemetry_recent" in summary
        assert summary["telemetry_recent"]["mcp_tools_count"] == 1
        assert summary["telemetry_recent"]["cli_commands_count"] == 1

    def test_get_summary_telemetry_exception(self, monitoring_config):
        """Test get_summary with telemetry exception (lines 441-442)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.telemetry_service = Mock()
        collector.telemetry_service.get_dashboard_data.side_effect = Exception(
            "Telemetry error"
        )

        summary = collector.get_summary()

        # Should still return summary without telemetry data
        assert "metrics_collected" in summary
        assert "telemetry_recent" not in summary

    def test_get_summary_general_exception(self, monitoring_config):
        """Test get_summary with general exception (lines 445-447)."""
        collector = UnifiedMetricsCollector(monitoring_config)

        # Mock the scan_metrics to_dict method to raise an exception
        with patch.object(
            collector._scan_metrics,
            "to_dict",
            side_effect=Exception("Scan metrics error"),
        ):
            summary = collector.get_summary()

            assert "error" in summary

    def test_metrics_collector_alias(self, monitoring_config):
        """Test MetricsCollector alias for backward compatibility."""
        from adversary_mcp_server.monitoring.unified_metrics_collector import (
            MetricsCollector,
        )

        collector = MetricsCollector(monitoring_config)

        assert isinstance(collector, UnifiedMetricsCollector)

    def test_record_metric_cache_conversion_complex(self, monitoring_config):
        """Test record_metric cache conversion with complex logic (lines 120-133)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.metrics_orchestrator = Mock()

        # Test cache miss detection
        collector.record_metric(
            "cache_miss_total", 1.0, labels={"cache_type": "semgrep"}
        )

        # Test cache hit detection
        collector.record_metric("cache_hit_ratio", 0.85, labels={"cache_type": "llm"})

        # Test generic cache operation
        collector.record_metric(
            "cache_operation_time", 5.0, labels={"cache_type": "results"}
        )

        # Test large value handling (should not set size_bytes)
        collector.record_metric(
            "cache_large_value", 2000000.0, labels={"cache_type": "big"}
        )

        assert collector.metrics_orchestrator.track_cache_operation.call_count == 4

    def test_record_cache_operation_kwargs_handling(self, monitoring_config):
        """Test record_cache_operation with various kwargs (lines 155-168)."""
        collector = UnifiedMetricsCollector(monitoring_config)
        collector.telemetry_enabled = True
        collector.metrics_orchestrator = Mock()

        collector.record_cache_operation(
            "get",
            hit=False,
            cache_type="test_cache",
            duration_ms=2.5,
            extra_param="extra_value",
        )

        # Verify the telemetry call was made (should be called twice - once from record_metric, once directly)
        assert collector.metrics_orchestrator.track_cache_operation.call_count == 2

        # Check the second call (direct call with proper parameters)
        second_call = (
            collector.metrics_orchestrator.track_cache_operation.call_args_list[1]
        )
        assert second_call[1]["operation_type"] == "miss"
        assert second_call[1]["cache_name"] == "test_cache"
        assert second_call[1]["access_time_ms"] == 2.5

        # Verify legacy metrics were recorded
        metrics = collector.get_metrics()
        assert "cache_get_total" in metrics

    @pytest.mark.asyncio
    async def test_collection_loop_with_config_export_interval(self, monitoring_config):
        """Test _collection_loop with custom export interval (lines 306-308)."""
        # Set a custom export interval
        monitoring_config.export_interval_seconds = 10
        collector = UnifiedMetricsCollector(monitoring_config)

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            try:
                await collector._collection_loop()
            except asyncio.CancelledError:
                pass

            # Verify sleep was called with custom interval
            mock_sleep.assert_any_call(10)
