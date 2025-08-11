"""System performance monitoring and resource tracking."""

import asyncio
import time

import psutil

from ..logger import get_logger
from .types import MonitoringConfig, PerformanceMetrics
from .unified_metrics_collector import UnifiedMetricsCollector as MetricsCollector

logger = get_logger("performance_monitor")


class PerformanceMonitor:
    """Monitors system performance and resource utilization using asyncio."""

    def __init__(
        self,
        config: MonitoringConfig,
        metrics_collector: MetricsCollector | None = None,
    ):
        """Initialize performance monitor.

        Args:
            config: Monitoring configuration
            metrics_collector: Optional metrics collector for recording performance data
        """
        self.config = config
        self.metrics_collector = metrics_collector
        self._performance_metrics = PerformanceMetrics()
        self._monitoring_task: asyncio.Task | None = None
        self._start_time = time.time()

        # Get initial system info
        try:
            self._process = psutil.Process()
            self._performance_metrics.startup_time = time.time() - self._start_time
            logger.info("PerformanceMonitor initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize performance monitoring: {e}")
            self._process = None

    async def start_monitoring(self) -> None:
        """Start background performance monitoring."""
        if not self.config.enable_performance_monitoring:
            logger.info("Performance monitoring is disabled")
            return

        if self._monitoring_task and not self._monitoring_task.done():
            logger.warning("Performance monitoring is already running")
            return

        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Performance monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop background performance monitoring."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            logger.info("Performance monitoring stopped")

    async def _monitoring_loop(self) -> None:
        """Main monitoring loop using asyncio."""
        while True:
            try:
                await self._collect_performance_metrics()
                await self._check_alerting_thresholds()

                # Wait for next collection interval
                await asyncio.sleep(self.config.performance_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                # Continue monitoring despite errors
                await asyncio.sleep(5)

    async def _collect_performance_metrics(self) -> None:
        """Collect current performance metrics asynchronously."""
        if not self._process:
            return

        try:
            # Run CPU intensive operations in executor to avoid blocking
            loop = asyncio.get_event_loop()

            # System-wide metrics - run in executor since cpu_percent can block
            cpu_percent = await loop.run_in_executor(None, psutil.cpu_percent, 0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            # Process-specific metrics
            process_memory = self._process.memory_info()
            process_cpu = self._process.cpu_percent()

            # Update performance metrics
            self._performance_metrics.cpu_usage_percent = cpu_percent
            self._performance_metrics.memory_usage_mb = process_memory.rss / (
                1024 * 1024
            )
            self._performance_metrics.memory_usage_percent = memory.percent
            self._performance_metrics.disk_usage_mb = disk.used / (1024 * 1024)
            self._performance_metrics.uptime_seconds = time.time() - self._start_time
            self._performance_metrics.last_heartbeat = time.time()

            # Record metrics if collector is available
            if self.metrics_collector:
                self.metrics_collector.set_gauge(
                    "system_cpu_usage_percent", cpu_percent, unit="percent"
                )
                self.metrics_collector.set_gauge(
                    "system_memory_usage_percent", memory.percent, unit="percent"
                )
                self.metrics_collector.set_gauge(
                    "process_memory_usage_mb",
                    self._performance_metrics.memory_usage_mb,
                    unit="megabytes",
                )
                self.metrics_collector.set_gauge(
                    "process_cpu_usage_percent", process_cpu, unit="percent"
                )
                self.metrics_collector.set_gauge(
                    "disk_usage_mb",
                    self._performance_metrics.disk_usage_mb,
                    unit="megabytes",
                )
                self.metrics_collector.set_gauge(
                    "uptime_seconds",
                    self._performance_metrics.uptime_seconds,
                    unit="seconds",
                )

            logger.debug(
                f"Performance metrics collected: CPU={cpu_percent:.1f}%, "
                f"Memory={memory.percent:.1f}%, ProcessMem={self._performance_metrics.memory_usage_mb:.1f}MB"
            )

        except Exception as e:
            logger.error(f"Failed to collect performance metrics: {e}")

    async def _check_alerting_thresholds(self) -> None:
        """Check if any metrics exceed alerting thresholds."""
        metrics = self._performance_metrics

        # CPU usage check
        if metrics.cpu_usage_percent > self.config.cpu_threshold_percent:
            warning_msg = f"High CPU usage: {metrics.cpu_usage_percent:.1f}% (threshold: {self.config.cpu_threshold_percent}%)"
            logger.warning(warning_msg)
            self._record_alert("high_cpu_usage", warning_msg)

        # Memory usage check
        if metrics.memory_usage_percent > self.config.memory_threshold_percent:
            warning_msg = f"High memory usage: {metrics.memory_usage_percent:.1f}% (threshold: {self.config.memory_threshold_percent}%)"
            logger.warning(warning_msg)
            self._record_alert("high_memory_usage", warning_msg)

        # Check scan duration if metrics collector is available
        if self.metrics_collector:
            scan_metrics = self.metrics_collector.get_scan_metrics()
            if scan_metrics.average_scan_time > self.config.scan_time_threshold_seconds:
                warning_msg = f"Slow average scan time: {scan_metrics.average_scan_time:.1f}s (threshold: {self.config.scan_time_threshold_seconds}s)"
                logger.warning(warning_msg)
                self._record_alert("slow_scan_performance", warning_msg)

            # Check error rate
            if scan_metrics.total_scans > 0:
                error_rate = (
                    scan_metrics.failed_scans / scan_metrics.total_scans
                ) * 100
                if error_rate > self.config.error_rate_threshold_percent:
                    warning_msg = f"High scan error rate: {error_rate:.1f}% (threshold: {self.config.error_rate_threshold_percent}%)"
                    logger.warning(warning_msg)
                    self._record_alert("high_error_rate", warning_msg)

    def _record_alert(self, alert_type: str, message: str) -> None:
        """Record an alert condition.

        Args:
            alert_type: Type of alert
            message: Alert message
        """
        self._performance_metrics.warning_count += 1

        if "critical" in alert_type.lower() or "high" in alert_type.lower():
            self._performance_metrics.critical_errors.append(f"{alert_type}: {message}")
            # Keep only recent critical errors
            if len(self._performance_metrics.critical_errors) > 10:
                self._performance_metrics.critical_errors.pop(0)

        if self.metrics_collector:
            self.metrics_collector.increment_counter(
                "performance_alerts", labels={"alert_type": alert_type}
            )

    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics.

        Returns:
            Current performance metrics
        """
        # Update metrics before returning
        if self._process:
            try:
                # Create task to collect metrics but don't wait for it
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(self._collect_performance_metrics())
                except RuntimeError:
                    # No event loop running, skip metrics update
                    pass
            except Exception as e:
                logger.debug(f"Failed to update metrics: {e}")

        return self._performance_metrics

    def get_system_info(self) -> dict[str, any]:
        """Get detailed system information.

        Returns:
            Dictionary containing system information
        """
        try:
            boot_time = psutil.boot_time()
            cpu_info = {
                "physical_cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True),
                "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                "current_usage": psutil.cpu_percent(interval=1),
            }

            memory_info = psutil.virtual_memory()._asdict()
            disk_info = psutil.disk_usage("/")._asdict()

            # Convert bytes to GB for readability
            for key in ["total", "available", "used"]:
                if key in memory_info:
                    memory_info[f"{key}_gb"] = round(memory_info[key] / (1024**3), 2)
                if key in disk_info:
                    disk_info[f"{key}_gb"] = round(disk_info[key] / (1024**3), 2)

            return {
                "system": {
                    "boot_time": boot_time,
                    "uptime_seconds": time.time() - boot_time,
                    "platform": (
                        psutil.WINDOWS if hasattr(psutil, "WINDOWS") else "unix"
                    ),
                },
                "cpu": cpu_info,
                "memory": memory_info,
                "disk": disk_info,
                "process": (
                    {
                        "pid": self._process.pid if self._process else None,
                        "create_time": (
                            self._process.create_time() if self._process else None
                        ),
                        "num_threads": (
                            self._process.num_threads() if self._process else None
                        ),
                        "num_fds": (
                            getattr(self._process, "num_fds", lambda: None)()
                            if self._process
                            else None
                        ),
                    }
                    if self._process
                    else None
                ),
            }

        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {"error": str(e)}

    def record_scan_activity(self, active_scans: int, queue_length: int = 0) -> None:
        """Record current scan activity levels.

        Args:
            active_scans: Number of currently active scans
            queue_length: Length of scan queue
        """
        self._performance_metrics.active_scans = active_scans
        self._performance_metrics.queue_length = queue_length

        if self.metrics_collector:
            self.metrics_collector.set_gauge("active_scans", active_scans)
            self.metrics_collector.set_gauge("scan_queue_length", queue_length)

    def record_error(self, error_type: str, is_critical: bool = False) -> None:
        """Record an application error.

        Args:
            error_type: Type/category of error
            is_critical: Whether this is a critical error
        """
        self._performance_metrics.error_count += 1

        if is_critical:
            error_msg = f"Critical error: {error_type}"
            self._performance_metrics.critical_errors.append(error_msg)
            logger.error(error_msg)

            # Keep only recent critical errors
            if len(self._performance_metrics.critical_errors) > 10:
                self._performance_metrics.critical_errors.pop(0)

        if self.metrics_collector:
            severity = "critical" if is_critical else "error"
            self.metrics_collector.increment_counter(
                "application_errors",
                labels={"error_type": error_type, "severity": severity},
            )

    def get_health_status(self) -> dict[str, any]:
        """Get overall system health status.

        Returns:
            Dictionary containing health status information
        """
        metrics = self.get_current_metrics()

        # Determine health status based on thresholds
        health_status = "healthy"
        issues = []

        if metrics.cpu_usage_percent > self.config.cpu_threshold_percent:
            health_status = "warning"
            issues.append(f"High CPU usage: {metrics.cpu_usage_percent:.1f}%")

        if metrics.memory_usage_percent > self.config.memory_threshold_percent:
            health_status = "warning"
            issues.append(f"High memory usage: {metrics.memory_usage_percent:.1f}%")

        if len(metrics.critical_errors) > 0:
            health_status = "critical"
            issues.append(f"{len(metrics.critical_errors)} critical errors")

        # Check if monitoring is responsive
        if (
            time.time() - metrics.last_heartbeat
            > self.config.performance_check_interval * 2
        ):
            health_status = "critical"
            issues.append("Performance monitoring not responsive")

        return {
            "status": health_status,
            "timestamp": time.time(),
            "uptime_seconds": metrics.uptime_seconds,
            "issues": issues,
            "metrics_summary": metrics.to_dict(),
        }
