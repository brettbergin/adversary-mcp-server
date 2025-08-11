"""Unified metrics collection system that integrates legacy and new telemetry systems."""

import asyncio
import json
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..config import get_app_metrics_dir
from ..database.models import AdversaryDatabase
from ..logger import get_logger
from ..telemetry.integration import MetricsCollectionOrchestrator
from ..telemetry.service import TelemetryService
from .types import MetricData, MetricType, MonitoringConfig, ScanMetrics

logger = get_logger("unified_metrics_collector")


class UnifiedMetricsCollector:
    """Unified metrics collector that bridges legacy and new telemetry systems."""

    def __init__(self, config: MonitoringConfig):
        """Initialize unified metrics collector.

        Args:
            config: Monitoring configuration
        """
        self.config = config

        # Legacy in-memory storage for backward compatibility
        self._metrics: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._scan_metrics = ScanMetrics()
        self._start_time = time.time()
        self._background_task: asyncio.Task | None = None

        # Setup export path for legacy JSON exports
        if config.json_export_path:
            self.export_path = Path(config.json_export_path)
        else:
            self.export_path = get_app_metrics_dir()

        self.export_path.mkdir(parents=True, exist_ok=True)

        # Initialize new telemetry system
        self.telemetry_enabled = False
        try:
            self.db = AdversaryDatabase()
            self.telemetry_service = TelemetryService(self.db)
            self.metrics_orchestrator = MetricsCollectionOrchestrator(
                self.telemetry_service
            )
            self.telemetry_enabled = True
            logger.info("Unified telemetry system initialized successfully")
        except Exception as e:
            logger.warning(
                f"Failed to initialize telemetry system, falling back to legacy: {e}"
            )
            self.db = None
            self.telemetry_service = None
            self.metrics_orchestrator = None

        logger.info(
            f"UnifiedMetricsCollector initialized, export path: {self.export_path}"
        )
        logger.info(f"Telemetry enabled: {self.telemetry_enabled}")

    async def start_collection(self) -> None:
        """Start background metrics collection."""
        if self._background_task and not self._background_task.done():
            logger.warning("Metrics collection already running")
            return

        if self.config.enable_metrics:
            self._background_task = asyncio.create_task(self._collection_loop())
            logger.info("Unified metrics collection started")
        else:
            logger.info("Metrics collection disabled in config")

    async def stop_collection(self) -> None:
        """Stop background metrics collection."""
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
            logger.info("Metrics collection stopped")

    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.COUNTER,
        labels: dict[str, str] | None = None,
        timestamp: float | None = None,
    ) -> None:
        """Record a metric value (legacy compatibility method)."""
        if not self.config.enable_metrics:
            return

        timestamp = timestamp or time.time()
        labels = labels or {}

        # Store in legacy format for backward compatibility
        metric_data = MetricData(
            name=name,
            value=value,
            metric_type=metric_type,
            labels=labels,
            timestamp=timestamp,
        )
        self._metrics[name].append(metric_data)

        # Also record basic telemetry if available
        if self.telemetry_enabled and self.metrics_orchestrator:
            try:
                # Convert legacy metrics to telemetry cache operations where applicable
                if "cache" in name.lower():
                    cache_name = labels.get("cache_type", "unknown")
                    operation_type = (
                        "miss"
                        if "miss" in name
                        else "hit" if "hit" in name else "operation"
                    )
                    self.metrics_orchestrator.track_cache_operation(
                        operation_type=operation_type,
                        cache_name=cache_name,
                        key=f"legacy_{name}_{timestamp}",
                        size_bytes=int(value) if value < 1000000 else None,
                        access_time_ms=1.0,
                    )
            except Exception as e:
                logger.debug(
                    f"Failed to record telemetry for legacy metric {name}: {e}"
                )

    def record_histogram(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        timestamp: float | None = None,
    ) -> None:
        """Record a histogram value (legacy compatibility method)."""
        self.record_metric(name, value, MetricType.HISTOGRAM, labels, timestamp)

    def record_cache_operation(
        self, operation: str, hit: bool = True, **kwargs
    ) -> None:
        """Record cache operation metrics with enhanced telemetry."""
        # Legacy recording
        metric_name = f"cache_{operation}_total"
        labels = {"hit": str(hit).lower()}
        labels.update({k: str(v) for k, v in kwargs.items()})
        self.record_metric(metric_name, 1.0, MetricType.COUNTER, labels)

        # Enhanced telemetry recording
        if self.telemetry_enabled and self.metrics_orchestrator:
            try:
                operation_type = "hit" if hit else "miss"
                self.metrics_orchestrator.track_cache_operation(
                    operation_type=operation_type,
                    cache_name=kwargs.get("cache_type", "unknown"),
                    key=f"cache_op_{time.time()}",
                    access_time_ms=kwargs.get("duration_ms", 0.1),
                )
            except Exception as e:
                logger.debug(f"Failed to record cache telemetry: {e}")

    def record_scan_start(self, scan_type: str, file_count: int = 1, **kwargs) -> None:
        """Record scan start metrics."""
        self.record_metric("scans_started_total", 1.0, labels={"type": scan_type})
        self._scan_metrics.increment_scans()

    def record_scan_complete(
        self, scan_type: str, duration_seconds: float, findings_count: int = 0, **kwargs
    ) -> None:
        """Record scan completion metrics."""
        labels = {"type": scan_type}
        self.record_metric("scans_completed_total", 1.0, labels=labels)
        self.record_histogram("scan_duration_seconds", duration_seconds, labels=labels)
        self.record_metric("scan_findings_total", findings_count, labels=labels)

        self._scan_metrics.add_scan_time(duration_seconds)
        self._scan_metrics.add_findings(findings_count)
        self._scan_metrics.increment_successful_scans()

    def record_scan_completion(
        self,
        scan_type: str,
        duration_or_success: any,
        success: bool = None,
        findings_count: int = 0,
        validated_findings_count: int = 0,
        false_positives_count: int = 0,
        **kwargs,
    ) -> None:
        """Record the completion of a scan operation (legacy compatibility)."""
        # Handle different calling patterns
        if isinstance(duration_or_success, bool):
            # Called as: record_scan_completion(scan_type, success, duration_ms, ...)
            success_val = duration_or_success
            duration_ms = kwargs.get("duration_ms", 0.0)
        elif success is not None:
            # Called as: record_scan_completion(scan_type, duration, success=True, ...)
            duration_ms = duration_or_success * 1000.0  # Assuming seconds
            success_val = success
        else:
            # Default handling
            duration_ms = (
                duration_or_success
                if isinstance(duration_or_success, int | float)
                else 0.0
            )
            success_val = True

        duration_seconds = duration_ms / 1000.0

        if success_val:
            self.record_scan_complete(scan_type, duration_seconds, findings_count)
        else:
            self._scan_metrics.increment_failed_scans()

    def get_metrics(self) -> dict[str, Any]:
        """Get current metrics snapshot (legacy compatibility)."""
        metrics = {}

        for name, metric_queue in self._metrics.items():
            if metric_queue:
                latest_metric = metric_queue[-1]
                metrics[name] = {
                    "value": latest_metric.value,
                    "timestamp": latest_metric.timestamp,
                    "labels": latest_metric.labels,
                    "type": latest_metric.metric_type.value,
                }

        return metrics

    def get_scan_metrics(self) -> ScanMetrics:
        """Get scan-specific metrics (legacy compatibility)."""
        return self._scan_metrics

    def get_telemetry_data(self, hours: int = 24) -> dict[str, Any] | None:
        """Get comprehensive telemetry data from the new system."""
        if not self.telemetry_enabled or not self.telemetry_service:
            return None

        try:
            return self.telemetry_service.get_dashboard_data(hours)
        except Exception as e:
            logger.error(f"Failed to get telemetry data: {e}")
            return None

    async def export_metrics(self, format_type: str = "json") -> str | None:
        """Export metrics to specified format."""
        if format_type == "json":
            return await self._export_json()
        else:
            logger.warning(f"Unsupported export format: {format_type}")
            return None

    async def _export_json(self) -> str | None:
        """Export metrics to JSON format (legacy compatibility)."""
        try:
            export_data = {
                "metadata": {
                    "collected_at": time.time(),
                    "uptime_seconds": time.time() - self._start_time,
                    "metrics_count": sum(
                        len(queue) for queue in self._metrics.values()
                    ),
                    "telemetry_enabled": self.telemetry_enabled,
                },
                "legacy_metrics": self.get_metrics(),
                "scan_metrics": {
                    "total_scans": self._scan_metrics.total_scans,
                    "average_duration": self._scan_metrics.average_scan_time,
                    "total_findings": self._scan_metrics.total_findings,
                },
            }

            # Add telemetry data if available
            if self.telemetry_enabled:
                telemetry_data = self.get_telemetry_data()
                if telemetry_data:
                    export_data["telemetry_data"] = telemetry_data

            # Write to export file
            export_file = self.export_path / f"unified_metrics_{int(time.time())}.json"
            with open(export_file, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            logger.info(f"Metrics exported to {export_file}")
            return str(export_file)

        except Exception as e:
            logger.error(f"Failed to export metrics to JSON: {e}")
            return None

    async def _collection_loop(self) -> None:
        """Background collection loop."""
        logger.debug("Starting metrics collection loop")
        export_interval = getattr(
            self.config, "export_interval_seconds", 300
        )  # 5 minutes default

        while True:
            try:
                # Export metrics periodically
                await asyncio.sleep(export_interval)

                if self.config.enable_metrics:
                    await self.export_metrics()

                # Cleanup old metrics (keep last 1000 per metric)
                self._cleanup_old_metrics()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying

    def _cleanup_old_metrics(self) -> None:
        """Clean up old metrics to prevent memory growth."""
        for name, metric_queue in self._metrics.items():
            # Deque already limits size, but we can clean up if needed
            if len(metric_queue) > 900:  # Clean when approaching limit
                # Remove oldest 100 entries
                for _ in range(100):
                    if metric_queue:
                        metric_queue.popleft()

    # === IMetricsCollector Interface Methods ===
    # These methods implement the IMetricsCollector protocol

    def increment_counter(
        self,
        name: str,
        increment: float = 1.0,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Increment a counter metric."""
        self.record_metric(name, increment, MetricType.COUNTER, labels)

    def set_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Set a gauge metric value."""
        self.record_metric(name, value, MetricType.GAUGE, labels)

    def record_llm_request(
        self,
        provider: str,
        model: str,
        tokens_used: int,
        cost_usd: float | None = None,
        duration_ms: float | None = None,
        success: bool = True,
    ) -> None:
        """Record an LLM API request."""
        labels = {"provider": provider, "model": model, "success": str(success)}

        # Record token usage
        self.record_metric(
            "llm_tokens_total", float(tokens_used), MetricType.COUNTER, labels
        )

        # Record cost if available
        if cost_usd is not None:
            self.record_metric(
                "llm_cost_usd_total", cost_usd, MetricType.COUNTER, labels
            )

        # Record duration if available
        if duration_ms is not None:
            self.record_metric(
                "llm_request_duration_ms", duration_ms, MetricType.HISTOGRAM, labels
            )

        # Record request count
        self.increment_counter("llm_requests_total", 1.0, labels)

    def time_operation(self, operation_name: str, labels: dict[str, str] | None = None):
        """Context manager for timing operations."""

        @contextmanager
        def timer():
            start_time = time.time()
            try:
                yield
            finally:
                duration_ms = (time.time() - start_time) * 1000
                self.record_metric(
                    f"{operation_name}_duration_ms",
                    duration_ms,
                    MetricType.HISTOGRAM,
                    labels,
                )

        return timer()

    def get_current_metrics(self) -> dict[str, list[MetricData]]:
        """Get current metrics data."""
        result = {}
        for name, metric_queue in self._metrics.items():
            result[name] = list(metric_queue)
        return result

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of current system metrics."""
        try:
            summary = {
                "metrics_collected": len(self._metrics),
                "total_data_points": sum(
                    len(queue) for queue in self._metrics.values()
                ),
                "uptime_seconds": time.time() - self._start_time,
                "scan_metrics": self._scan_metrics.to_dict(),
                "telemetry_enabled": self.telemetry_enabled,
            }

            # Add telemetry data if available
            if self.telemetry_enabled:
                try:
                    telemetry_data = self.get_telemetry_data(hours=1)
                    if telemetry_data:
                        summary["telemetry_recent"] = {
                            "scan_engine": telemetry_data.get("scan_engine", {}),
                            "mcp_tools_count": len(telemetry_data.get("mcp_tools", [])),
                            "cli_commands_count": len(
                                telemetry_data.get("cli_commands", [])
                            ),
                        }
                except Exception as e:
                    logger.debug(f"Could not get telemetry data for summary: {e}")

            return summary
        except Exception as e:
            logger.error(f"Error generating metrics summary: {e}")
            return {"error": str(e)}


# For backward compatibility, provide an alias
MetricsCollector = UnifiedMetricsCollector
