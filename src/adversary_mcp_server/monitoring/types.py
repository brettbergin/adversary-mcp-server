"""Type definitions for monitoring and metrics system."""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MetricType(str, Enum):
    """Types of metrics that can be collected."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class MetricData:
    """Individual metric data point."""

    name: str
    metric_type: MetricType
    value: float
    timestamp: float = field(default_factory=time.time)
    labels: dict[str, str] = field(default_factory=dict)
    unit: str | None = None


@dataclass
class ScanMetrics:
    """Metrics specific to security scanning operations."""

    # Scan execution metrics
    total_scans: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    total_scan_time: float = 0.0
    average_scan_time: float = 0.0

    # File processing metrics
    files_processed: int = 0
    files_failed: int = 0
    total_file_size_bytes: int = 0
    average_file_size_bytes: float = 0.0

    # Finding metrics
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    findings_by_scanner: dict[str, int] = field(default_factory=dict)

    # Cache metrics
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_rate: float = 0.0

    # LLM-specific metrics
    llm_requests: int = 0
    llm_tokens_consumed: int = 0
    llm_average_response_time: float = 0.0
    llm_errors: int = 0

    # Batch processing metrics
    batches_processed: int = 0
    average_batch_size: float = 0.0
    batch_success_rate: float = 0.0

    def calculate_derived_metrics(self) -> None:
        """Calculate derived metrics from base metrics."""
        if self.total_scans > 0:
            self.average_scan_time = self.total_scan_time / self.total_scans

        if self.files_processed > 0:
            self.average_file_size_bytes = (
                self.total_file_size_bytes / self.files_processed
            )

        total_cache_operations = self.cache_hits + self.cache_misses
        if total_cache_operations > 0:
            self.cache_hit_rate = self.cache_hits / total_cache_operations

        if self.batches_processed > 0:
            processed_files = self.files_processed + self.files_failed
            if processed_files > 0:
                self.average_batch_size = processed_files / self.batches_processed
                self.batch_success_rate = self.files_processed / processed_files

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary format."""
        self.calculate_derived_metrics()

        return {
            "scan_execution": {
                "total_scans": self.total_scans,
                "successful_scans": self.successful_scans,
                "failed_scans": self.failed_scans,
                "success_rate": self.successful_scans / max(1, self.total_scans),
                "total_scan_time_seconds": round(self.total_scan_time, 2),
                "average_scan_time_seconds": round(self.average_scan_time, 2),
            },
            "file_processing": {
                "files_processed": self.files_processed,
                "files_failed": self.files_failed,
                "total_file_size_mb": round(
                    self.total_file_size_bytes / (1024 * 1024), 2
                ),
                "average_file_size_kb": round(self.average_file_size_bytes / 1024, 2),
            },
            "findings": {
                "total_findings": self.total_findings,
                "by_severity": dict(self.findings_by_severity),
                "by_category": dict(self.findings_by_category),
                "by_scanner": dict(self.findings_by_scanner),
            },
            "caching": {
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_rate": round(self.cache_hit_rate * 100, 2),
            },
            "llm_analysis": {
                "requests": self.llm_requests,
                "tokens_consumed": self.llm_tokens_consumed,
                "average_response_time_seconds": round(
                    self.llm_average_response_time, 2
                ),
                "errors": self.llm_errors,
                "error_rate": round(
                    self.llm_errors / max(1, self.llm_requests) * 100, 2
                ),
            },
            "batch_processing": {
                "batches_processed": self.batches_processed,
                "average_batch_size": round(self.average_batch_size, 2),
                "batch_success_rate": round(self.batch_success_rate * 100, 2),
            },
        }


@dataclass
class PerformanceMetrics:
    """System-wide performance metrics."""

    # System resource metrics
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    memory_usage_percent: float = 0.0
    disk_usage_mb: float = 0.0

    # Application metrics
    active_scans: int = 0
    queue_length: int = 0
    thread_pool_size: int = 0
    connection_pool_size: int = 0

    # Timing metrics
    startup_time: float = 0.0
    uptime_seconds: float = 0.0
    last_heartbeat: float = field(default_factory=time.time)

    # Error tracking
    error_count: int = 0
    warning_count: int = 0
    critical_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert performance metrics to dictionary."""
        return {
            "system_resources": {
                "cpu_usage_percent": round(self.cpu_usage_percent, 2),
                "memory_usage_mb": round(self.memory_usage_mb, 2),
                "memory_usage_percent": round(self.memory_usage_percent, 2),
                "disk_usage_mb": round(self.disk_usage_mb, 2),
            },
            "application_state": {
                "active_scans": self.active_scans,
                "queue_length": self.queue_length,
                "thread_pool_size": self.thread_pool_size,
                "connection_pool_size": self.connection_pool_size,
                "uptime_seconds": round(self.uptime_seconds, 2),
            },
            "error_tracking": {
                "error_count": self.error_count,
                "warning_count": self.warning_count,
                "critical_errors_count": len(self.critical_errors),
                "recent_critical_errors": (
                    self.critical_errors[-5:] if self.critical_errors else []
                ),
            },
        }


@dataclass
class MonitoringConfig:
    """Configuration for the monitoring system."""

    # Collection settings
    enable_metrics: bool = True
    collection_interval_seconds: int = 30
    metrics_retention_hours: int = 24

    # Export settings
    enable_prometheus_export: bool = False
    prometheus_port: int = 8080
    enable_json_export: bool = True
    json_export_path: str | None = None

    # Performance monitoring
    enable_performance_monitoring: bool = True
    performance_check_interval: int = 60

    # Alerting thresholds
    cpu_threshold_percent: float = 80.0
    memory_threshold_percent: float = 85.0
    error_rate_threshold_percent: float = 10.0
    scan_time_threshold_seconds: float = 300.0
