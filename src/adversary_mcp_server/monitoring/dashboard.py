"""Monitoring dashboard and advanced export functionality."""

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..logger import get_logger
from .metrics_collector import MetricsCollector

logger = get_logger("monitoring_dashboard")


class MonitoringDashboard:
    """Advanced monitoring dashboard with export and visualization capabilities."""

    def __init__(
        self, metrics_collector: MetricsCollector, console: Console | None = None
    ):
        """Initialize monitoring dashboard.

        Args:
            metrics_collector: MetricsCollector instance
            console: Optional Rich console for output
        """
        self.metrics_collector = metrics_collector
        self.console = console or Console()
        logger.debug("MonitoringDashboard initialized")

    def display_real_time_dashboard(self) -> None:
        """Display real-time monitoring dashboard."""
        logger.info("Displaying real-time monitoring dashboard")

        # Clear screen and show header
        self.console.clear()
        self.console.print(
            "🔍 [bold cyan]Adversary MCP Server - Real-Time Monitoring Dashboard[/bold cyan]"
        )
        self.console.print(
            f"📊 Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        # System Overview Panel
        self._display_system_overview()

        # Scanner Performance Panel
        self._display_scanner_performance()

        # Error Analytics Panel
        self._display_error_analytics()

        # Resource Utilization Panel
        self._display_resource_utilization()

    def _display_system_overview(self) -> None:
        """Display system overview metrics."""
        try:
            # Get recent metrics
            mcp_tools = self._get_recent_metric_summary("mcp_tool_calls_total")
            cli_commands = self._get_recent_metric_summary("cli_commands_total")
            scan_operations = self._get_recent_metric_summary("scans_completed")

            # Create overview table
            overview_table = Table(
                title="System Overview", show_header=True, header_style="bold magenta"
            )
            overview_table.add_column("Metric", style="cyan")
            overview_table.add_column("Total", style="green")
            overview_table.add_column("Success Rate", style="yellow")
            overview_table.add_column("Avg Duration (s)", style="blue")

            overview_table.add_row(
                "MCP Tool Calls",
                str(mcp_tools.get("total", 0)),
                f"{mcp_tools.get('success_rate', 0):.1%}",
                f"{mcp_tools.get('avg_duration', 0):.2f}",
            )

            overview_table.add_row(
                "CLI Commands",
                str(cli_commands.get("total", 0)),
                f"{cli_commands.get('success_rate', 0):.1%}",
                f"{cli_commands.get('avg_duration', 0):.2f}",
            )

            overview_table.add_row(
                "Scan Operations",
                str(scan_operations.get("total", 0)),
                f"{scan_operations.get('success_rate', 0):.1%}",
                f"{scan_operations.get('avg_duration', 0):.2f}",
            )

            self.console.print(Panel(overview_table, border_style="green"))

        except Exception as e:
            logger.error(f"Failed to display system overview: {e}")
            self.console.print("❌ [red]Failed to load system overview metrics[/red]")

    def _display_scanner_performance(self) -> None:
        """Display scanner performance metrics."""
        try:
            # Get scanner metrics
            semgrep_metrics = self._get_recent_metric_summary("semgrep_scans_total")
            llm_metrics = self._get_recent_metric_summary("llm_scans_total")
            validation_metrics = self._get_recent_metric_summary(
                "llm_validation_requests_total"
            )

            scanner_table = Table(
                title="Scanner Performance",
                show_header=True,
                header_style="bold magenta",
            )
            scanner_table.add_column("Scanner", style="cyan")
            scanner_table.add_column("Operations", style="green")
            scanner_table.add_column("Avg Duration (s)", style="yellow")
            scanner_table.add_column("Threats Found", style="red")

            # Semgrep metrics
            semgrep_threats = self._get_recent_metric_sum("semgrep_findings_total")
            scanner_table.add_row(
                "Semgrep",
                str(semgrep_metrics.get("total", 0)),
                f"{semgrep_metrics.get('avg_duration', 0):.2f}",
                str(semgrep_threats),
            )

            # LLM Scanner metrics
            llm_threats = self._get_recent_metric_sum("llm_findings_total")
            scanner_table.add_row(
                "LLM Scanner",
                str(llm_metrics.get("total", 0)),
                f"{llm_metrics.get('avg_duration', 0):.2f}",
                str(llm_threats),
            )

            # Validation metrics
            validation_fp = self._get_recent_metric_sum(
                "llm_validation_false_positives_total"
            )
            scanner_table.add_row(
                "LLM Validator",
                str(validation_metrics.get("total", 0)),
                f"{validation_metrics.get('avg_duration', 0):.2f}",
                f"{validation_fp} FP filtered",
            )

            self.console.print(Panel(scanner_table, border_style="blue"))

        except Exception as e:
            logger.error(f"Failed to display scanner performance: {e}")
            self.console.print(
                "❌ [red]Failed to load scanner performance metrics[/red]"
            )

    def _display_error_analytics(self) -> None:
        """Display error analytics and patterns."""
        try:
            # Get error metrics
            circuit_breaker_trips = self._get_recent_metric_sum(
                "circuit_breaker_open_events_total"
            )
            retry_exhausted = self._get_recent_metric_sum("retry_exhausted_total")
            scan_failures = self._get_recent_metric_sum("scan_operations_failed_total")

            error_table = Table(
                title="Error Analytics", show_header=True, header_style="bold magenta"
            )
            error_table.add_column("Error Type", style="cyan")
            error_table.add_column("Count", style="red")
            error_table.add_column("Impact", style="yellow")

            error_table.add_row(
                "Circuit Breaker Trips",
                str(circuit_breaker_trips),
                "Service Protection",
            )
            error_table.add_row(
                "Retry Exhaustions", str(retry_exhausted), "Operation Failures"
            )
            error_table.add_row(
                "Scan Failures", str(scan_failures), "Analysis Incomplete"
            )

            self.console.print(Panel(error_table, border_style="red"))

        except Exception as e:
            logger.error(f"Failed to display error analytics: {e}")
            self.console.print("❌ [red]Failed to load error analytics[/red]")

    def _display_resource_utilization(self) -> None:
        """Display resource utilization metrics."""
        try:
            # Get resource metrics
            batch_throughput = self._get_recent_metric_avg(
                "batch_processing_throughput_batches_per_second"
            )
            cache_hit_rate = self._calculate_cache_hit_rate()
            git_operations = self._get_recent_metric_sum("git_operations_total")

            resource_table = Table(
                title="Resource Utilization",
                show_header=True,
                header_style="bold magenta",
            )
            resource_table.add_column("Resource", style="cyan")
            resource_table.add_column("Current Value", style="green")
            resource_table.add_column("Unit", style="yellow")

            resource_table.add_row(
                "Batch Throughput", f"{batch_throughput:.2f}", "batches/sec"
            )
            resource_table.add_row(
                "Cache Hit Rate", f"{cache_hit_rate:.1%}", "efficiency"
            )
            resource_table.add_row("Git Operations", str(git_operations), "commands")

            self.console.print(Panel(resource_table, border_style="cyan"))

        except Exception as e:
            logger.error(f"Failed to display resource utilization: {e}")
            self.console.print(
                "❌ [red]Failed to load resource utilization metrics[/red]"
            )

    def export_dashboard_report(self, output_path: Path | None = None) -> Path:
        """Export comprehensive dashboard report to file.

        Args:
            output_path: Optional custom output path

        Returns:
            Path to exported report file
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

        if output_path is None:
            output_path = (
                self.metrics_collector.export_path
                / f"dashboard_report_{timestamp}.json"
            )

        logger.info(f"Exporting dashboard report to {output_path}")

        try:
            report_data = {
                "report_metadata": {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "report_type": "adversary_mcp_dashboard",
                    "version": "1.0",
                },
                "system_overview": self._generate_system_overview_data(),
                "scanner_performance": self._generate_scanner_performance_data(),
                "error_analytics": self._generate_error_analytics_data(),
                "resource_utilization": self._generate_resource_utilization_data(),
                "detailed_metrics": self._generate_detailed_metrics_data(),
            }

            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2)

            logger.info(f"Dashboard report exported successfully to {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to export dashboard report: {e}")
            raise

    def export_prometheus_metrics(self, output_path: Path | None = None) -> Path:
        """Export metrics in Prometheus format.

        Args:
            output_path: Optional custom output path

        Returns:
            Path to exported Prometheus metrics file
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

        if output_path is None:
            output_path = (
                self.metrics_collector.export_path
                / f"prometheus_metrics_{timestamp}.txt"
            )

        logger.info(f"Exporting Prometheus metrics to {output_path}")

        try:
            prometheus_data = []

            # Get all current metrics
            current_metrics = self.metrics_collector.get_current_metrics()

            for metric_name, values in current_metrics.items():
                if not values:
                    continue

                # Convert metric name to Prometheus format
                prom_metric_name = metric_name.replace("-", "_")

                # Add metric documentation
                prometheus_data.append(
                    f"# HELP {prom_metric_name} {metric_name.replace('_', ' ').title()}"
                )
                prometheus_data.append(f"# TYPE {prom_metric_name} counter")

                # Add metric values with labels
                for metric_data in values:
                    if hasattr(metric_data, "labels") and metric_data.labels:
                        label_str = ",".join(
                            [f'{k}="{v}"' for k, v in metric_data.labels.items()]
                        )
                        prometheus_data.append(
                            f"{prom_metric_name}{{{label_str}}} {metric_data.value}"
                        )
                    else:
                        prometheus_data.append(
                            f"{prom_metric_name} {metric_data.value}"
                        )

                prometheus_data.append("")  # Empty line between metrics

            with open(output_path, "w") as f:
                f.write("\n".join(prometheus_data))

            logger.info(f"Prometheus metrics exported successfully to {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to export Prometheus metrics: {e}")
            raise

    def _get_recent_metric_summary(
        self, metric_name: str, lookback_minutes: int = 60
    ) -> dict[str, Any]:
        """Get summary statistics for a metric over recent time period."""
        try:
            recent_data = self.metrics_collector.get_metric_history(
                metric_name, limit=1000
            )
            if not recent_data:
                return {"total": 0, "success_rate": 0, "avg_duration": 0}

            # Filter for recent data
            cutoff_time = time.time() - (lookback_minutes * 60)
            recent_data = [d for d in recent_data if d.timestamp >= cutoff_time]

            if not recent_data:
                return {"total": 0, "success_rate": 0, "avg_duration": 0}

            total = len(recent_data)
            successful = len(
                [
                    d
                    for d in recent_data
                    if not hasattr(d, "labels") or d.labels.get("status") != "error"
                ]
            )
            success_rate = successful / total if total > 0 else 0

            # Try to calculate average duration from timing metrics
            duration_metric = metric_name.replace("_total", "_duration_seconds")
            duration_data = self.metrics_collector.get_metric_history(
                duration_metric, limit=100
            )
            duration_data = [d for d in duration_data if d.timestamp >= cutoff_time]
            avg_duration = (
                sum(d.value for d in duration_data) / len(duration_data)
                if duration_data
                else 0
            )

            return {
                "total": total,
                "success_rate": success_rate,
                "avg_duration": avg_duration,
            }

        except Exception as e:
            logger.error(f"Failed to get metric summary for {metric_name}: {e}")
            return {"total": 0, "success_rate": 0, "avg_duration": 0}

    def _get_recent_metric_sum(
        self, metric_name: str, lookback_minutes: int = 60
    ) -> int:
        """Get sum of metric values over recent time period."""
        try:
            recent_data = self.metrics_collector.get_metric_history(
                metric_name, limit=1000
            )
            cutoff_time = time.time() - (lookback_minutes * 60)
            recent_data = [d for d in recent_data if d.timestamp >= cutoff_time]
            return int(sum(d.value for d in recent_data))
        except Exception:
            return 0

    def _get_recent_metric_avg(
        self, metric_name: str, lookback_minutes: int = 60
    ) -> float:
        """Get average of metric values over recent time period."""
        try:
            recent_data = self.metrics_collector.get_metric_history(
                metric_name, limit=1000
            )
            cutoff_time = time.time() - (lookback_minutes * 60)
            recent_data = [d for d in recent_data if d.timestamp >= cutoff_time]
            return (
                sum(d.value for d in recent_data) / len(recent_data)
                if recent_data
                else 0
            )
        except Exception:
            return 0.0

    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate percentage."""
        try:
            hits = self._get_recent_metric_sum("cache_hits_total")
            misses = self._get_recent_metric_sum("cache_misses_total")
            total = hits + misses
            return hits / total if total > 0 else 0
        except Exception:
            return 0.0

    def _generate_system_overview_data(self) -> dict[str, Any]:
        """Generate system overview data for export."""
        return {
            "mcp_operations": self._get_recent_metric_summary("mcp_tool_calls_total"),
            "cli_operations": self._get_recent_metric_summary("cli_commands_total"),
            "scan_operations": self._get_recent_metric_summary("scans_completed"),
            "uptime_seconds": time.time() - self.metrics_collector._start_time,
        }

    def _generate_scanner_performance_data(self) -> dict[str, Any]:
        """Generate scanner performance data for export."""
        return {
            "semgrep": {
                **self._get_recent_metric_summary("semgrep_scans_total"),
                "threats_found": self._get_recent_metric_sum("semgrep_findings_total"),
            },
            "llm_scanner": {
                **self._get_recent_metric_summary("llm_scans_total"),
                "threats_found": self._get_recent_metric_sum("llm_findings_total"),
            },
            "llm_validator": {
                **self._get_recent_metric_summary("llm_validation_requests_total"),
                "false_positives_filtered": self._get_recent_metric_sum(
                    "llm_validation_false_positives_total"
                ),
            },
        }

    def _generate_error_analytics_data(self) -> dict[str, Any]:
        """Generate error analytics data for export."""
        return {
            "circuit_breaker_trips": self._get_recent_metric_sum(
                "circuit_breaker_open_events_total"
            ),
            "retry_exhaustions": self._get_recent_metric_sum("retry_exhausted_total"),
            "scan_failures": self._get_recent_metric_sum(
                "scan_operations_failed_total"
            ),
            "git_failures": self._get_recent_metric_sum("git_operations_total")
            - self._get_recent_metric_sum("git_operations_success_total"),
        }

    def _generate_resource_utilization_data(self) -> dict[str, Any]:
        """Generate resource utilization data for export."""
        return {
            "batch_throughput_batches_per_second": self._get_recent_metric_avg(
                "batch_processing_throughput_batches_per_second"
            ),
            "cache_hit_rate": self._calculate_cache_hit_rate(),
            "git_operations_total": self._get_recent_metric_sum("git_operations_total"),
            "total_tokens_processed": self._get_recent_metric_sum(
                "llm_tokens_processed_total"
            ),
        }

    def _generate_detailed_metrics_data(self) -> dict[str, Any]:
        """Generate detailed metrics data for export."""
        try:
            # Get all current metrics
            all_metrics = self.metrics_collector.get_current_metrics()

            # Organize by category
            detailed_metrics = {
                "mcp_server": {},
                "cli_operations": {},
                "scanners": {},
                "batch_processing": {},
                "resilience": {},
                "git_operations": {},
                "cache": {},
            }

            # Categorize metrics
            for metric_name, values in all_metrics.items():
                if not values:
                    continue

                latest_values = list(values)[-10:]  # Get last 10 values

                if metric_name.startswith("mcp_"):
                    detailed_metrics["mcp_server"][metric_name] = [
                        {
                            "timestamp": v.timestamp,
                            "value": v.value,
                            "labels": getattr(v, "labels", {}),
                        }
                        for v in latest_values
                    ]
                elif metric_name.startswith("cli_"):
                    detailed_metrics["cli_operations"][metric_name] = [
                        {
                            "timestamp": v.timestamp,
                            "value": v.value,
                            "labels": getattr(v, "labels", {}),
                        }
                        for v in latest_values
                    ]
                elif metric_name.startswith(("semgrep_", "llm_")):
                    detailed_metrics["scanners"][metric_name] = [
                        {
                            "timestamp": v.timestamp,
                            "value": v.value,
                            "labels": getattr(v, "labels", {}),
                        }
                        for v in latest_values
                    ]
                elif metric_name.startswith("batch_"):
                    detailed_metrics["batch_processing"][metric_name] = [
                        {
                            "timestamp": v.timestamp,
                            "value": v.value,
                            "labels": getattr(v, "labels", {}),
                        }
                        for v in latest_values
                    ]
                elif metric_name.startswith(("circuit_", "retry_", "error_")):
                    detailed_metrics["resilience"][metric_name] = [
                        {
                            "timestamp": v.timestamp,
                            "value": v.value,
                            "labels": getattr(v, "labels", {}),
                        }
                        for v in latest_values
                    ]
                elif metric_name.startswith("git_"):
                    detailed_metrics["git_operations"][metric_name] = [
                        {
                            "timestamp": v.timestamp,
                            "value": v.value,
                            "labels": getattr(v, "labels", {}),
                        }
                        for v in latest_values
                    ]
                elif metric_name.startswith("cache_"):
                    detailed_metrics["cache"][metric_name] = [
                        {
                            "timestamp": v.timestamp,
                            "value": v.value,
                            "labels": getattr(v, "labels", {}),
                        }
                        for v in latest_values
                    ]

            return detailed_metrics

        except Exception as e:
            logger.error(f"Failed to generate detailed metrics data: {e}")
            return {}
