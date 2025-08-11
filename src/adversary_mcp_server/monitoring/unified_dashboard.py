"""Unified dashboard system supporting both Rich console and HTML dashboards."""

import json
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..database.models import AdversaryDatabase
from ..logger import get_logger
from ..telemetry.service import TelemetryService
from .unified_metrics_collector import UnifiedMetricsCollector

logger = get_logger("unified_dashboard")


class UnifiedDashboard:
    """Unified dashboard supporting both Rich console and HTML output."""

    def __init__(
        self,
        metrics_collector: UnifiedMetricsCollector | None = None,
        console: Console | None = None,
    ):
        """Initialize unified dashboard.

        Args:
            metrics_collector: Optional UnifiedMetricsCollector instance
            console: Optional Rich console for output
        """
        self.metrics_collector = metrics_collector
        self.console = console or Console()

        # Initialize telemetry system for HTML dashboard
        self.telemetry_enabled = False
        try:
            self.db = AdversaryDatabase()
            self.telemetry_service = TelemetryService(self.db)
            self.telemetry_enabled = True
            logger.debug("Telemetry system initialized for unified dashboard")
        except Exception as e:
            logger.warning(f"Failed to initialize telemetry for dashboard: {e}")
            self.db = None
            self.telemetry_service = None

        logger.debug("UnifiedDashboard initialized")

    def display_real_time_dashboard(self) -> None:
        """Display real-time monitoring dashboard using Rich console."""
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

        # Metrics Overview
        self._display_metrics_overview()

        # Telemetry Overview (if available)
        if self.telemetry_enabled:
            self._display_telemetry_overview()

        # Performance Panel
        if self.metrics_collector:
            self._display_performance_metrics()

        # Footer
        self.console.print("\n[dim]Press Ctrl+C to exit[/dim]")

    def generate_html_dashboard(
        self, hours: int = 24, auto_launch: bool = True
    ) -> str | None:
        """Generate HTML dashboard and optionally launch in browser.

        Args:
            hours: Hours of data to include
            auto_launch: Whether to auto-launch in browser

        Returns:
            Path to generated HTML file or None if failed
        """
        if not self.telemetry_enabled:
            self.console.print("❌ [red]HTML dashboard requires telemetry system[/red]")
            return None

        try:
            from ..dashboard.html_dashboard import ComprehensiveHTMLDashboard

            html_dashboard = ComprehensiveHTMLDashboard(self.db)
            html_file = html_dashboard.generate_and_launch_dashboard(
                hours=hours, auto_launch=auto_launch
            )

            self.console.print(
                f"✅ [green]HTML dashboard generated: {html_file}[/green]"
            )
            return html_file

        except ImportError as e:
            self.console.print(
                f"❌ [red]HTML dashboard dependencies missing: {e}[/red]"
            )
            return None
        except Exception as e:
            self.console.print(f"❌ [red]Failed to generate HTML dashboard: {e}[/red]")
            logger.error(f"HTML dashboard generation failed: {e}", exc_info=True)
            return None

    def export_metrics(
        self, format_type: str = "json", output_path: str | None = None
    ) -> str | None:
        """Export metrics in specified format.

        Args:
            format_type: Export format ('json', 'html')
            output_path: Optional output path

        Returns:
            Path to exported file or None if failed
        """
        if format_type == "html":
            return self.generate_html_dashboard(auto_launch=False)
        elif format_type == "json":
            return self._export_json_metrics(output_path)
        else:
            self.console.print(
                f"❌ [red]Unsupported export format: {format_type}[/red]"
            )
            return None

    def _display_system_overview(self) -> None:
        """Display system overview panel."""
        try:
            import psutil

            # System metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()

            system_table = Table(title="System Overview", show_header=True)
            system_table.add_column("Metric", style="cyan")
            system_table.add_column("Value", style="green")

            system_table.add_row("CPU Usage", f"{cpu_percent:.1f}%")
            system_table.add_row("Memory Usage", f"{memory.percent:.1f}%")
            system_table.add_row(
                "Memory Used", f"{memory.used / 1024 / 1024 / 1024:.1f} GB"
            )

            # Database info if available
            if self.telemetry_enabled and self.db:
                if self.db.db_path.exists():
                    db_size = self.db.db_path.stat().st_size / (1024 * 1024)
                    system_table.add_row("Database Size", f"{db_size:.1f} MB")

            self.console.print(Panel(system_table, border_style="cyan"))

        except ImportError:
            self.console.print("[yellow]Install psutil for system metrics[/yellow]")
        except Exception as e:
            logger.warning(f"Failed to display system overview: {e}")

    def _display_metrics_overview(self) -> None:
        """Display metrics overview panel."""
        if not self.metrics_collector:
            return

        try:
            metrics = self.metrics_collector.get_metrics()

            if not metrics:
                self.console.print("[yellow]No metrics available[/yellow]")
                return

            metrics_table = Table(title="Legacy Metrics Overview", show_header=True)
            metrics_table.add_column("Metric", style="cyan")
            metrics_table.add_column("Value", style="green")
            metrics_table.add_column("Timestamp", style="dim")

            for name, data in metrics.items():
                timestamp_str = datetime.fromtimestamp(data["timestamp"]).strftime(
                    "%H:%M:%S"
                )
                metrics_table.add_row(name, str(data["value"]), timestamp_str)

            self.console.print(Panel(metrics_table, border_style="blue"))

        except Exception as e:
            logger.warning(f"Failed to display metrics overview: {e}")

    def _display_telemetry_overview(self) -> None:
        """Display telemetry overview panel."""
        if not self.telemetry_enabled:
            return

        try:
            telemetry_data = self.telemetry_service.get_dashboard_data(1)  # Last hour

            telemetry_table = Table(
                title="Telemetry Overview (Last Hour)", show_header=True
            )
            telemetry_table.add_column("Component", style="cyan")
            telemetry_table.add_column("Activity", style="green")
            telemetry_table.add_column("Performance", style="yellow")

            # MCP Tools
            mcp_count = len(telemetry_data.get("mcp_tools", []))
            mcp_executions = sum(
                tool.get("executions", 0)
                for tool in telemetry_data.get("mcp_tools", [])
            )
            telemetry_table.add_row(
                "MCP Tools", f"{mcp_count} tools", f"{mcp_executions} executions"
            )

            # CLI Commands
            cli_count = len(telemetry_data.get("cli_commands", []))
            cli_executions = sum(
                cmd.get("executions", 0)
                for cmd in telemetry_data.get("cli_commands", [])
            )
            telemetry_table.add_row(
                "CLI Commands", f"{cli_count} commands", f"{cli_executions} executions"
            )

            # Scan Engine
            scan_data = telemetry_data.get("scan_engine", {})
            total_scans = scan_data.get("total_scans", 0)
            threats_found = scan_data.get("total_threats_found", 0)
            telemetry_table.add_row(
                "Scan Engine", f"{total_scans} scans", f"{threats_found} threats found"
            )

            # Cache Performance
            cache_data = telemetry_data.get("cache_performance", [])
            if cache_data:
                total_hit_rate = sum(
                    cache.get("hit_rate", 0) for cache in cache_data
                ) / len(cache_data)
                telemetry_table.add_row(
                    "Cache System",
                    f"{len(cache_data)} caches",
                    f"{total_hit_rate:.1%} hit rate",
                )

            self.console.print(Panel(telemetry_table, border_style="green"))

        except Exception as e:
            logger.warning(f"Failed to display telemetry overview: {e}")

    def _display_performance_metrics(self) -> None:
        """Display performance metrics panel."""
        try:
            scan_metrics = self.metrics_collector.get_scan_metrics()

            perf_table = Table(title="Performance Metrics", show_header=True)
            perf_table.add_column("Metric", style="cyan")
            perf_table.add_column("Value", style="green")

            perf_table.add_row("Total Scans", str(scan_metrics.total_scans))
            perf_table.add_row(
                "Average Duration", f"{scan_metrics.average_scan_time:.2f}s"
            )
            perf_table.add_row("Total Findings", str(scan_metrics.total_findings))

            self.console.print(Panel(perf_table, border_style="yellow"))

        except Exception as e:
            logger.warning(f"Failed to display performance metrics: {e}")

    def _export_json_metrics(self, output_path: str | None = None) -> str | None:
        """Export metrics to JSON format."""
        try:
            export_data = {
                "metadata": {
                    "exported_at": time.time(),
                    "format": "json",
                    "telemetry_enabled": self.telemetry_enabled,
                },
                "legacy_metrics": {},
                "telemetry_data": {},
            }

            # Add legacy metrics if available
            if self.metrics_collector:
                export_data["legacy_metrics"] = self.metrics_collector.get_metrics()
                export_data["scan_metrics"] = {
                    "total_scans": self.metrics_collector.get_scan_metrics().total_scans,
                    "average_duration": self.metrics_collector.get_scan_metrics().average_scan_time,
                    "total_findings": self.metrics_collector.get_scan_metrics().total_findings,
                }

            # Add telemetry data if available
            if self.telemetry_enabled:
                export_data["telemetry_data"] = (
                    self.telemetry_service.get_dashboard_data(24)
                )

            # Determine output path
            if output_path:
                export_file = Path(output_path)
            else:
                export_dir = Path(
                    "~/.local/share/adversary-mcp-server/exports"
                ).expanduser()
                export_dir.mkdir(parents=True, exist_ok=True)
                export_file = export_dir / f"unified_metrics_{int(time.time())}.json"

            # Write file
            with open(export_file, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            self.console.print(f"✅ [green]Metrics exported to: {export_file}[/green]")
            return str(export_file)

        except Exception as e:
            self.console.print(f"❌ [red]Failed to export JSON metrics: {e}[/red]")
            logger.error(f"JSON export failed: {e}", exc_info=True)
            return None


# For backward compatibility
MonitoringDashboard = UnifiedDashboard
