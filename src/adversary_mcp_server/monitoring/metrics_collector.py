"""Metrics collection and aggregation system."""

import asyncio
import json
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from ..config import get_app_metrics_dir
from ..logger import get_logger
from .types import MetricData, MetricType, MonitoringConfig, ScanMetrics

logger = get_logger("metrics_collector")


class MetricsCollector:
    """Collects, aggregates, and exports application metrics using asyncio."""

    def __init__(self, config: MonitoringConfig):
        """Initialize metrics collector.

        Args:
            config: Monitoring configuration
        """
        self.config = config
        self._metrics: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._scan_metrics = ScanMetrics()
        self._start_time = time.time()
        self._background_task: asyncio.Task | None = None

        # Setup export path
        if config.json_export_path:
            self.export_path = Path(config.json_export_path)
        else:
            self.export_path = get_app_metrics_dir()

        self.export_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"MetricsCollector initialized, export path: {self.export_path}")

    async def start_collection(self) -> None:
        """Start background metrics collection."""
        if self._background_task and not self._background_task.done():
            logger.warning("Metrics collection already running")
            return

        if self.config.enable_metrics:
            self._background_task = asyncio.create_task(self._collection_loop())
            logger.info("Metrics collection started")
        else:
            logger.info("Metrics collection disabled")

    async def stop_collection(self) -> None:
        """Stop background metrics collection."""
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
            self._background_task = None
            logger.info("Metrics collection stopped")

    async def _collection_loop(self) -> None:
        """Background metrics collection loop."""
        while True:
            try:
                await asyncio.sleep(self.config.collection_interval_seconds)
                await self._periodic_tasks()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying

    async def _periodic_tasks(self) -> None:
        """Perform periodic metrics tasks."""
        # Export metrics if enabled
        if self.config.enable_json_export:
            await self._export_metrics_async()

        # Clean up old metrics
        await self._cleanup_old_metrics()

    async def _export_metrics_async(self) -> None:
        """Async version of metrics export."""
        try:
            await asyncio.get_event_loop().run_in_executor(None, self.export_metrics)
        except Exception as e:
            logger.error(f"Failed to export metrics asynchronously: {e}")

    async def _cleanup_old_metrics(self) -> None:
        """Clean up old metric entries based on retention policy."""
        current_time = time.time()
        retention_seconds = self.config.metrics_retention_hours * 3600

        # Clean up metrics older than retention period
        for name, history in self._metrics.items():
            # Remove old entries from the front of the deque
            while history and current_time - history[0].timestamp > retention_seconds:
                history.popleft()

    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        labels: dict[str, str] | None = None,
        unit: str | None = None,
    ) -> None:
        """Record a metric data point.

        Args:
            name: Metric name
            value: Metric value
            metric_type: Type of metric
            labels: Optional labels for the metric
            unit: Optional unit of measurement
        """
        if not self.config.enable_metrics:
            return

        metric = MetricData(
            name=name,
            metric_type=metric_type,
            value=value,
            labels=labels or {},
            unit=unit,
        )

        # No need for async lock for simple append operations in single event loop
        self._metrics[name].append(metric)

        logger.debug(f"Recorded metric: {name}={value} ({metric_type.value})")

    def increment_counter(
        self, name: str, value: float = 1.0, labels: dict[str, str] | None = None
    ) -> None:
        """Increment a counter metric.

        Args:
            name: Counter name
            value: Increment value
            labels: Optional labels
        """
        self.record_metric(name, value, MetricType.COUNTER, labels)

    def set_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        unit: str | None = None,
    ) -> None:
        """Set a gauge metric value.

        Args:
            name: Gauge name
            value: Gauge value
            labels: Optional labels
            unit: Optional unit
        """
        self.record_metric(name, value, MetricType.GAUGE, labels, unit)

    def record_histogram(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        unit: str | None = None,
    ) -> None:
        """Record a histogram metric.

        Args:
            name: Histogram name
            value: Value to record
            labels: Optional labels
            unit: Optional unit
        """
        self.record_metric(name, value, MetricType.HISTOGRAM, labels, unit)

    def time_operation(self, operation_name: str, labels: dict[str, str] | None = None):
        """Context manager for timing operations.

        Args:
            operation_name: Name of the operation being timed
            labels: Optional labels

        Returns:
            Context manager for timing
        """
        return TimingContext(self, operation_name, labels)

    def record_scan_start(self, scan_type: str, file_count: int = 0) -> None:
        """Record the start of a scan operation.

        Args:
            scan_type: Type of scan being performed
            file_count: Number of files to scan
        """
        self._scan_metrics.total_scans += 1

        self.increment_counter("scans_started", labels={"scan_type": scan_type})
        if file_count > 0:
            self.set_gauge(
                "scan_file_count", file_count, labels={"scan_type": scan_type}
            )

    def record_scan_completion(
        self, scan_type: str, duration: float, success: bool, findings_count: int = 0
    ) -> None:
        """Record the completion of a scan operation.

        Args:
            scan_type: Type of scan
            duration: Scan duration in seconds
            success: Whether the scan succeeded
            findings_count: Number of findings discovered
        """
        self._scan_metrics.total_scan_time += duration
        if success:
            self._scan_metrics.successful_scans += 1
        else:
            self._scan_metrics.failed_scans += 1

        self._scan_metrics.total_findings += findings_count

        status = "success" if success else "failure"
        self.increment_counter(
            "scans_completed", labels={"scan_type": scan_type, "status": status}
        )
        self.record_histogram(
            "scan_duration_seconds",
            duration,
            labels={"scan_type": scan_type},
            unit="seconds",
        )

        if findings_count > 0:
            self.set_gauge(
                "scan_findings_count", findings_count, labels={"scan_type": scan_type}
            )

    def record_file_processed(
        self, file_path: str, file_size: int, processing_time: float, success: bool
    ) -> None:
        """Record file processing metrics.

        Args:
            file_path: Path to the processed file
            file_size: Size of the file in bytes
            processing_time: Time taken to process the file
            success: Whether processing succeeded
        """
        if success:
            self._scan_metrics.files_processed += 1
            self._scan_metrics.total_file_size_bytes += file_size
        else:
            self._scan_metrics.files_failed += 1

        file_ext = Path(file_path).suffix.lower()
        status = "success" if success else "failure"

        self.increment_counter(
            "files_processed", labels={"extension": file_ext, "status": status}
        )
        self.record_histogram(
            "file_processing_time_seconds",
            processing_time,
            labels={"extension": file_ext},
            unit="seconds",
        )
        self.record_histogram(
            "file_size_bytes", file_size, labels={"extension": file_ext}, unit="bytes"
        )

    def record_finding(self, scanner: str, severity: str, category: str) -> None:
        """Record a security finding.

        Args:
            scanner: Scanner that found the issue
            severity: Severity level
            category: Finding category
        """
        self._scan_metrics.findings_by_scanner[scanner] = (
            self._scan_metrics.findings_by_scanner.get(scanner, 0) + 1
        )
        self._scan_metrics.findings_by_severity[severity] = (
            self._scan_metrics.findings_by_severity.get(severity, 0) + 1
        )
        self._scan_metrics.findings_by_category[category] = (
            self._scan_metrics.findings_by_category.get(category, 0) + 1
        )

        self.increment_counter(
            "findings_total",
            labels={"scanner": scanner, "severity": severity, "category": category},
        )

    def record_cache_operation(self, operation: str, hit: bool) -> None:
        """Record cache operation metrics.

        Args:
            operation: Type of cache operation
            hit: Whether the operation was a cache hit
        """
        if hit:
            self._scan_metrics.cache_hits += 1
        else:
            self._scan_metrics.cache_misses += 1

        result = "hit" if hit else "miss"
        self.increment_counter(
            "cache_operations", labels={"operation": operation, "result": result}
        )

    def record_llm_request(
        self, provider: str, model: str, tokens: int, duration: float, success: bool
    ) -> None:
        """Record LLM request metrics.

        Args:
            provider: LLM provider (openai, anthropic)
            model: Model name
            tokens: Number of tokens consumed
            duration: Request duration
            success: Whether request succeeded
        """
        self._scan_metrics.llm_requests += 1
        if success:
            self._scan_metrics.llm_tokens_consumed += tokens
            # Update running average
            total_time = self._scan_metrics.llm_average_response_time * (
                self._scan_metrics.llm_requests - 1
            )
            self._scan_metrics.llm_average_response_time = (
                total_time + duration
            ) / self._scan_metrics.llm_requests
        else:
            self._scan_metrics.llm_errors += 1

        status = "success" if success else "error"
        self.increment_counter(
            "llm_requests",
            labels={"provider": provider, "model": model, "status": status},
        )

        if success:
            self.record_histogram(
                "llm_tokens_consumed",
                tokens,
                labels={"provider": provider, "model": model},
                unit="tokens",
            )
            self.record_histogram(
                "llm_response_time_seconds",
                duration,
                labels={"provider": provider, "model": model},
                unit="seconds",
            )

    def record_batch_processing(
        self,
        batch_size: int,
        processing_time: float,
        success_count: int,
        failure_count: int,
    ) -> None:
        """Record batch processing metrics.

        Args:
            batch_size: Size of the batch
            processing_time: Time to process the batch
            success_count: Number of successful items
            failure_count: Number of failed items
        """
        self._scan_metrics.batches_processed += 1

        self.increment_counter("batches_processed")
        self.record_histogram("batch_size", batch_size, unit="files")
        self.record_histogram(
            "batch_processing_time_seconds", processing_time, unit="seconds"
        )
        self.set_gauge("batch_success_count", success_count)
        self.set_gauge("batch_failure_count", failure_count)

    def get_scan_metrics(self) -> ScanMetrics:
        """Get current scan metrics.

        Returns:
            Copy of current scan metrics
        """
        # Create a copy to avoid concurrent modification issues
        metrics_copy = ScanMetrics(
            total_scans=self._scan_metrics.total_scans,
            successful_scans=self._scan_metrics.successful_scans,
            failed_scans=self._scan_metrics.failed_scans,
            total_scan_time=self._scan_metrics.total_scan_time,
            files_processed=self._scan_metrics.files_processed,
            files_failed=self._scan_metrics.files_failed,
            total_file_size_bytes=self._scan_metrics.total_file_size_bytes,
            total_findings=self._scan_metrics.total_findings,
            findings_by_severity=dict(self._scan_metrics.findings_by_severity),
            findings_by_category=dict(self._scan_metrics.findings_by_category),
            findings_by_scanner=dict(self._scan_metrics.findings_by_scanner),
            cache_hits=self._scan_metrics.cache_hits,
            cache_misses=self._scan_metrics.cache_misses,
            llm_requests=self._scan_metrics.llm_requests,
            llm_tokens_consumed=self._scan_metrics.llm_tokens_consumed,
            llm_average_response_time=self._scan_metrics.llm_average_response_time,
            llm_errors=self._scan_metrics.llm_errors,
            batches_processed=self._scan_metrics.batches_processed,
        )
        return metrics_copy

    def get_metric_history(self, name: str, limit: int = 100) -> list[MetricData]:
        """Get historical data for a metric.

        Args:
            name: Metric name
            limit: Maximum number of data points to return

        Returns:
            List of metric data points
        """
        if name not in self._metrics:
            return []

        history = list(self._metrics[name])
        return history[-limit:] if limit > 0 else history

    def export_metrics(self, format: str = "json") -> str | None:
        """Export current metrics to file.

        Args:
            format: Export format ("json")

        Returns:
            Path to exported file or None if export failed
        """
        if not self.config.enable_json_export:
            return None

        try:
            timestamp = int(time.time())
            export_data = {
                "timestamp": timestamp,
                "uptime_seconds": time.time() - self._start_time,
                "scan_metrics": self.get_scan_metrics().to_dict(),
                "raw_metrics": {},
            }

            # Include recent raw metrics
            for name, history in self._metrics.items():
                if history:
                    latest = history[-1]
                    export_data["raw_metrics"][name] = {
                        "value": latest.value,
                        "type": latest.metric_type.value,
                        "timestamp": latest.timestamp,
                        "labels": latest.labels,
                        "unit": latest.unit,
                    }

            if format == "json":
                export_file = self.export_path / f"metrics_{timestamp}.json"
                with open(export_file, "w") as f:
                    json.dump(export_data, f, indent=2)

                logger.info(f"Metrics exported to {export_file}")
                return str(export_file)

        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")
            return None

        return None

    def reset_metrics(self) -> None:
        """Reset all collected metrics."""
        self._metrics.clear()
        self._scan_metrics = ScanMetrics()

        logger.info("All metrics have been reset")

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of current metrics.

        Returns:
            Dictionary containing metrics summary
        """
        scan_metrics = self.get_scan_metrics()

        return {
            "collection_info": {
                "start_time": self._start_time,
                "uptime_seconds": time.time() - self._start_time,
                "metrics_enabled": self.config.enable_metrics,
                "total_metric_types": len(self._metrics),
            },
            "scan_metrics": scan_metrics.to_dict(),
        }


class TimingContext:
    """Context manager for timing operations."""

    def __init__(
        self,
        collector: MetricsCollector,
        operation_name: str,
        labels: dict[str, str] | None = None,
    ):
        """Initialize timing context.

        Args:
            collector: Metrics collector instance
            operation_name: Name of the operation
            labels: Optional labels
        """
        self.collector = collector
        self.operation_name = operation_name
        self.labels = labels or {}
        self.start_time: float | None = None

    def __enter__(self):
        """Start timing."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """End timing and record metric."""
        if self.start_time is not None:
            duration = time.time() - self.start_time
            self.collector.record_histogram(
                f"{self.operation_name}_duration_seconds",
                duration,
                self.labels,
                "seconds",
            )
