"""Metrics collection interfaces for observability and monitoring."""

from typing import Any, Protocol, runtime_checkable

from ..monitoring.types import MetricData, MetricType, ScanMetrics


@runtime_checkable
class IMetricsCollector(Protocol):
    """Interface for comprehensive metrics collection and monitoring.

    This interface defines the contract for metrics systems that:
    - Record various metric types (counters, gauges, histograms)
    - Track scan operations and performance
    - Monitor LLM usage and costs
    - Provide time-based operation measurement
    - Export metrics for external systems
    """

    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        labels: dict[str, str] | None = None,
        unit: str | None = None,
    ) -> None:
        """Record a general metric data point.

        Args:
            name: Metric name
            value: Metric value
            metric_type: Type of metric (COUNTER, GAUGE, HISTOGRAM)
            labels: Optional labels for the metric
            unit: Optional unit for the metric value
        """
        ...

    def increment_counter(
        self,
        name: str,
        increment: float = 1.0,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Increment a counter metric.

        Args:
            name: Counter name
            increment: Amount to increment by
            labels: Optional labels for the counter
        """
        ...

    def set_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Set a gauge metric value.

        Args:
            name: Gauge name
            value: Current gauge value
            labels: Optional labels for the gauge
        """
        ...

    def record_scan_start(self, scan_type: str, file_count: int = 0) -> None:
        """Record the start of a scan operation.

        Args:
            scan_type: Type of scan being performed (file, directory, code)
            file_count: Number of files to scan
        """
        ...

    def record_scan_completion(
        self,
        scan_type: str,
        success: bool,
        duration_ms: float,
        findings_count: int = 0,
        validated_findings_count: int = 0,
        false_positives_count: int = 0,
    ) -> None:
        """Record the completion of a scan operation.

        Args:
            scan_type: Type of scan performed
            success: Whether the scan completed successfully
            duration_ms: Scan duration in milliseconds
            findings_count: Total number of findings
            validated_findings_count: Number of validated findings
            false_positives_count: Number of false positives filtered
        """
        ...

    def record_cache_operation(self, operation: str, hit: bool) -> None:
        """Record a cache operation.

        Args:
            operation: Type of cache operation (get, put, invalidate)
            hit: Whether the operation was a cache hit
        """
        ...

    def record_llm_request(
        self,
        provider: str,
        model: str,
        tokens_used: int,
        cost_usd: float | None = None,
        duration_ms: float | None = None,
        success: bool = True,
    ) -> None:
        """Record an LLM API request.

        Args:
            provider: LLM provider (openai, anthropic, etc.)
            model: Model name used
            tokens_used: Number of tokens consumed
            cost_usd: Cost in USD (if available)
            duration_ms: Request duration in milliseconds
            success: Whether the request was successful
        """
        ...

    def time_operation(self, operation_name: str, labels: dict[str, str] | None = None):
        """Context manager for timing operations.

        Args:
            operation_name: Name of the operation being timed
            labels: Optional labels for the timing metric

        Returns:
            Context manager that records operation duration
        """
        ...

    def get_scan_metrics(self) -> ScanMetrics:
        """Get current scan-related metrics.

        Returns:
            Aggregated scan metrics including counts, durations, and ratios
        """
        ...

    def get_current_metrics(self) -> dict[str, list[MetricData]]:
        """Get current metrics data.

        Returns:
            Dictionary mapping metric names to their data points
        """
        ...

    def export_metrics(self, format: str = "json") -> str | None:
        """Export metrics in the specified format.

        Args:
            format: Export format ("json", "prometheus", etc.)

        Returns:
            Exported metrics string, or None if export failed
        """
        ...

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of current system metrics.

        Returns:
            Dictionary containing key metrics and statistics
        """
        ...
