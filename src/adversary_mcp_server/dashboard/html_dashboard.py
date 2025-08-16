"""Comprehensive HTML dashboard with rich interactive features."""

import time
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from ..database.models import AdversaryDatabase
from ..telemetry.service import TelemetryService


class ComprehensiveHTMLDashboard:
    """Rich interactive HTML dashboard with auto-browser launch."""

    def __init__(self, db: AdversaryDatabase = None):
        self.db = db or AdversaryDatabase()
        self.telemetry = TelemetryService(self.db)

        # Dashboard configuration
        self.dashboard_dir = Path(__file__).parent
        self.templates_dir = self.dashboard_dir / "templates"
        self.static_dir = self.dashboard_dir / "static"
        self.output_dir = Path(
            "~/.local/share/adversary-mcp-server/dashboard"
        ).expanduser()

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Add custom filters
        self.jinja_env.filters["timestamp_to_datetime"] = self._timestamp_to_datetime
        self.jinja_env.filters["format_duration"] = self._format_duration
        self.jinja_env.filters["format_size"] = self._format_size
        self.jinja_env.filters["percentage"] = self._format_percentage
        self.jinja_env.filters["basename"] = self._basename

    def generate_and_launch_dashboard(
        self, hours: int = 24, auto_launch: bool = True
    ) -> str:
        """Generate comprehensive HTML dashboard and optionally launch in browser."""
        # Get comprehensive data
        dashboard_data = self.telemetry.get_dashboard_data(hours)

        # Add metadata
        db_size_bytes = 0
        if self.db.db_path.exists():
            db_size_bytes = self.db.db_path.stat().st_size

        dashboard_data["metadata"] = {
            "generated_at": time.time(),
            "hours_covered": hours,
            "database_path": str(self.db.db_path),
            "dashboard_version": "1.0.0",
            "db_size_bytes": db_size_bytes,
        }

        # Generate HTML from template
        template = self.jinja_env.get_template("dashboard.html")

        # Add security headers to template data
        dashboard_data["security"] = {
            "csp_header": "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.jsdelivr.net/npm/chart.js; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        }

        # Inline CSS and JS content
        css_file = self.static_dir / "dashboard.css"
        js_file = self.static_dir / "dashboard.js"

        dashboard_data["css_content"] = (
            css_file.read_text() if css_file.exists() else ""
        )
        dashboard_data["js_content"] = js_file.read_text() if js_file.exists() else ""

        # Secure template rendering - validate data types and sanitize
        safe_dashboard_data = self._sanitize_dashboard_data(dashboard_data)
        html_content = template.render(**safe_dashboard_data)

        # Write HTML file
        html_file = self.output_dir / "adversary_dashboard.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Copy static assets if they exist
        self._copy_static_assets()

        # Auto-launch in browser
        if auto_launch:
            self._launch_in_browser(html_file)

        return str(html_file)

    def _copy_static_assets(self):
        """Copy CSS/JS static assets to output directory."""
        if self.static_dir.exists():
            static_output_dir = self.output_dir / "static"
            static_output_dir.mkdir(exist_ok=True)

            for static_file in self.static_dir.glob("*"):
                if static_file.is_file():
                    output_file = static_output_dir / static_file.name
                    output_file.write_text(static_file.read_text())

    def _launch_in_browser(self, html_file: Path):
        """Launch dashboard in default browser."""
        try:
            file_url = f"file://{html_file.absolute()}"
            webbrowser.open(file_url)
        except Exception as e:
            print(f"Warning: Could not auto-launch browser: {e}")
            print(f"Dashboard available at: {html_file}")

    # === JINJA2 TEMPLATE FILTERS ===

    def _timestamp_to_datetime(self, timestamp: float) -> str:
        """Convert Unix timestamp to formatted datetime string."""
        if not timestamp:
            return "N/A"
        dt = datetime.fromtimestamp(timestamp, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    def _format_duration(self, duration_ms: float) -> str:
        """Format duration in milliseconds to human readable format."""
        if not duration_ms or duration_ms < 0:
            return "N/A"

        if duration_ms < 1000:
            return f"{duration_ms:.1f}ms"
        elif duration_ms < 60000:
            return f"{duration_ms/1000:.1f}s"
        else:
            minutes = int(duration_ms / 60000)
            seconds = (duration_ms % 60000) / 1000
            return f"{minutes}m {seconds:.1f}s"

    def _format_size(self, size_bytes: float) -> str:
        """Format size in bytes to human readable format."""
        if not size_bytes or size_bytes < 0:
            return "N/A"

        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def _format_percentage(self, value: float) -> str:
        """Format decimal as percentage."""
        if value is None:
            return "N/A"
        return f"{value * 100:.1f}%"

    def _basename(self, file_path: str) -> str:
        """Get basename of file path for display."""
        if not file_path:
            return "N/A"
        from pathlib import Path

        return Path(file_path).name

    def _sanitize_dashboard_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize dashboard data to prevent injection attacks."""
        import html

        def sanitize_value(value: Any) -> Any:
            """Recursively sanitize values."""
            if isinstance(value, str):
                # HTML escape strings to prevent XSS
                return html.escape(value)
            elif isinstance(value, dict):
                return {k: sanitize_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [sanitize_value(item) for item in value]
            elif isinstance(value, int | float | bool | type(None)):
                # Safe primitive types
                return value
            else:
                # Convert other types to safe string representation
                return html.escape(str(value))

        # Create a copy and sanitize
        sanitized_data = {}
        for key, value in data.items():
            # Only allow safe keys (alphanumeric plus underscore)
            safe_key = "".join(c for c in key if c.isalnum() or c == "_")
            if safe_key == key:  # Key is already safe
                sanitized_data[key] = sanitize_value(value)

        return sanitized_data

    # === REAL-TIME DATA METHODS ===

    def get_current_system_status(self) -> dict[str, Any]:
        """Get current system status for real-time updates."""
        try:
            import psutil

            # Current system metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(Path.home()))

            # Database metrics
            db_size_mb = None
            if self.db.db_path.exists():
                db_size_mb = self.db.db_path.stat().st_size / (1024 * 1024)

            return {
                "timestamp": time.time(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_mb": memory.used / (1024 * 1024),
                "disk_usage_percent": disk.percent,
                "db_size_mb": db_size_mb,
                "status": (
                    "healthy" if cpu_percent < 80 and memory.percent < 90 else "warning"
                ),
            }
        except Exception as e:
            return {"timestamp": time.time(), "status": "error", "error": str(e)}

    def get_recent_activity(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent activity for live feed."""
        with self.telemetry.get_repository() as repo:
            session = repo.session

            # Get recent scan executions
            from ..database.models import MCPToolExecution, ScanEngineExecution

            recent_scans = (
                session.query(ScanEngineExecution)
                .filter(
                    ScanEngineExecution.execution_start > (time.time() - 3600)
                )  # Last hour
                .order_by(ScanEngineExecution.execution_start.desc())
                .limit(limit // 2)
                .all()
            )

            # Get recent MCP tool executions
            recent_mcp = (
                session.query(MCPToolExecution)
                .filter(MCPToolExecution.execution_start > (time.time() - 3600))
                .order_by(MCPToolExecution.execution_start.desc())
                .limit(limit // 2)
                .all()
            )

            activities = []

            for scan in recent_scans:
                activities.append(
                    {
                        "type": "scan",
                        "timestamp": scan.execution_start,
                        "description": f"Scan {scan.scan_type}: {scan.target_path}",
                        "status": "success" if scan.success else "error",
                        "details": {
                            "threats_found": scan.threats_found,
                            "duration_ms": scan.total_duration_ms,
                        },
                    }
                )

            for mcp in recent_mcp:
                activities.append(
                    {
                        "type": "mcp_tool",
                        "timestamp": mcp.execution_start,
                        "description": f"MCP Tool: {mcp.tool_name}",
                        "status": "success" if mcp.success else "error",
                        "details": {
                            "findings_count": mcp.findings_count,
                            "duration_ms": (
                                (mcp.execution_end - mcp.execution_start) * 1000
                                if mcp.execution_end
                                else None
                            ),
                        },
                    }
                )

            # Sort by timestamp and limit
            activities.sort(key=lambda x: x["timestamp"], reverse=True)
            return activities[:limit]


class DashboardAssetManager:
    """Manages dashboard static assets (CSS, JS, icons)."""

    def __init__(self, dashboard_dir: Path):
        self.dashboard_dir = dashboard_dir
        self.templates_dir = dashboard_dir / "templates"
        self.static_dir = dashboard_dir / "static"

    def create_default_assets(self):
        """Create default dashboard template and static assets."""
        # Create directories
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)

        # Create main HTML template
        self._create_main_template()

        # Create CSS styles
        self._create_css_styles()

        # Create JavaScript functionality
        self._create_javascript()

    def _create_main_template(self):
        """Create the main dashboard HTML template."""
        template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Adversary MCP Server Dashboard</title>
    <link rel="stylesheet" href="static/dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <header class="dashboard-header">
            <h1>🛡️ Adversary MCP Server Dashboard</h1>
            <div class="header-meta">
                <span class="generated-time">Generated: {{ metadata.generated_at | timestamp_to_datetime }}</span>
                <span class="coverage">Coverage: {{ metadata.hours_covered }} hours</span>
            </div>
        </header>

        <!-- System Status -->
        <section class="status-overview">
            <div class="status-card system-health">
                <h2>System Health</h2>
                <div class="health-metrics">
                    <div class="metric">
                        <span class="label">Database Size:</span>
                        <span class="value">{{ metadata.db_size_bytes | format_size }}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Total Scans:</span>
                        <span class="value">{{ scan_engine.total_scans }}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Cache Hit Rate:</span>
                        <span class="value">{{ scan_engine.cache_hit_rate | percentage }}</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- MCP Tools Performance -->
        <section class="mcp-tools-section">
            <h2>MCP Tools Performance</h2>
            <div class="tools-grid">
                {% for tool in mcp_tools %}
                <div class="tool-card">
                    <h3>{{ tool.tool_name }}</h3>
                    <div class="tool-stats">
                        <div class="stat">
                            <span class="label">Executions:</span>
                            <span class="value">{{ tool.executions }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Success Rate:</span>
                            <span class="value">{{ tool.success_rate | percentage }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Avg Duration:</span>
                            <span class="value">{{ tool.avg_duration_ms | format_duration }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Findings:</span>
                            <span class="value">{{ tool.total_findings }}</span>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>

        <!-- CLI Commands Performance -->
        <section class="cli-commands-section">
            <h2>CLI Commands Performance</h2>
            <div class="commands-grid">
                {% for cmd in cli_commands %}
                <div class="command-card">
                    <h3>{{ cmd.command_name }}</h3>
                    <div class="command-stats">
                        <div class="stat">
                            <span class="label">Executions:</span>
                            <span class="value">{{ cmd.executions }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Success Rate:</span>
                            <span class="value">{{ cmd.success_rate | percentage }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Avg Duration:</span>
                            <span class="value">{{ cmd.avg_duration_ms | format_duration }}</span>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>

        <!-- Scan Engine Analytics -->
        <section class="scan-analytics-section">
            <h2>Scan Engine Analytics</h2>
            <div class="analytics-grid">
                <div class="analytics-card">
                    <h3>Performance Breakdown</h3>
                    <canvas id="scanPerformanceChart"></canvas>
                </div>
                <div class="analytics-card">
                    <h3>Threat Categories</h3>
                    <div class="threat-categories">
                        {% for threat in threat_categories %}
                        <div class="threat-category">
                            <span class="category">{{ threat.category }}</span>
                            <span class="severity severity-{{ threat.severity }}">{{ threat.severity }}</span>
                            <span class="count">{{ threat.count }}</span>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </section>

        <!-- Cache Performance -->
        <section class="cache-section">
            <h2>Cache Performance</h2>
            <div class="cache-grid">
                {% for cache in cache_performance %}
                <div class="cache-card">
                    <h3>{{ cache.cache_name }}</h3>
                    <div class="cache-stats">
                        <div class="stat">
                            <span class="label">Hit Rate:</span>
                            <span class="value">{{ cache.hit_rate | percentage }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Size:</span>
                            <span class="value">{{ cache.total_size_mb | format_size }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Avg Access:</span>
                            <span class="value">{{ cache.avg_access_time_ms | format_duration }}</span>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>

        <!-- Language Performance -->
        <section class="language-section">
            <h2>Language Performance</h2>
            <div class="language-grid">
                {% for lang in language_performance %}
                <div class="language-card">
                    <h3>{{ lang.language }}</h3>
                    <div class="language-stats">
                        <div class="stat">
                            <span class="label">Scans:</span>
                            <span class="value">{{ lang.scans }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Avg Duration:</span>
                            <span class="value">{{ lang.avg_duration_ms | format_duration }}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Threats Found:</span>
                            <span class="value">{{ lang.threats_found }}</span>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>
    </div>

    <script src="static/dashboard.js"></script>
    <script>
        // Initialize charts with data
        const scanData = {
            semgrep: {{ scan_engine.avg_semgrep_duration_ms }},
            llm: {{ scan_engine.avg_llm_duration_ms }},
            validation: {{ scan_engine.avg_validation_duration_ms }}
        };
        initializeScanPerformanceChart(scanData);
    </script>
</body>
</html>"""

        template_file = self.templates_dir / "dashboard.html"
        template_file.write_text(template_content)

    def _create_css_styles(self):
        """Create comprehensive CSS styles."""
        css_content = """/* Adversary Dashboard Styles */
:root {
    --primary-color: #2563eb;
    --secondary-color: #64748b;
    --success-color: #22c55e;
    --warning-color: #f59e0b;
    --error-color: #ef4444;
    --background-color: #f8fafc;
    --card-background: #ffffff;
    --text-primary: #1e293b;
    --text-secondary: #64748b;
    --border-color: #e2e8f0;
    --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--background-color);
    color: var(--text-primary);
    line-height: 1.6;
}

.dashboard-container {
    max-width: 98%;
    margin: 0 auto;
    padding: 20px;
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
}

/* Header */
.dashboard-header {
    background: var(--card-background);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 32px;
    box-shadow: var(--shadow);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.dashboard-header h1 {
    font-size: 2rem;
    font-weight: 700;
    color: var(--primary-color);
}

.header-meta {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 4px;
}

.header-meta span {
    font-size: 0.875rem;
    color: var(--text-secondary);
}

/* Status Overview */
.status-overview {
    margin-bottom: 32px;
}

.status-card {
    background: var(--card-background);
    border-radius: 12px;
    padding: 24px;
    box-shadow: var(--shadow);
}

.status-card h2 {
    font-size: 1.5rem;
    font-weight: 600;
    margin-bottom: 20px;
    color: var(--text-primary);
}

.health-metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
}

.metric {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    background: var(--background-color);
    border-radius: 8px;
}

.metric .label {
    font-weight: 500;
    color: var(--text-secondary);
}

.metric .value {
    font-weight: 600;
    font-size: 1.125rem;
    color: var(--primary-color);
}

/* Section Styles */
section {
    margin-bottom: 32px;
}

section h2 {
    font-size: 1.75rem;
    font-weight: 600;
    margin-bottom: 24px;
    color: var(--text-primary);
}

/* Grid Layouts */
.tools-grid, .commands-grid, .cache-grid, .language-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
}

.analytics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 20px;
}

/* Card Styles */
.tool-card, .command-card, .cache-card, .language-card, .analytics-card {
    background: var(--card-background);
    border-radius: 12px;
    padding: 20px;
    box-shadow: var(--shadow);
    transition: transform 0.2s, box-shadow 0.2s;
}

.tool-card:hover, .command-card:hover, .cache-card:hover, .language-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
}

.tool-card h3, .command-card h3, .cache-card h3, .language-card h3, .analytics-card h3 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--text-primary);
    border-bottom: 2px solid var(--border-color);
    padding-bottom: 8px;
}

/* Stats Grid */
.tool-stats, .command-stats, .cache-stats, .language-stats {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
}

.stat {
    display: flex;
    flex-direction: column;
    padding: 8px;
    background: var(--background-color);
    border-radius: 6px;
}

.stat .label {
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.025em;
}

.stat .value {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--primary-color);
    margin-top: 2px;
}

/* Threat Categories */
.threat-categories {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.threat-category {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    background: var(--background-color);
    border-radius: 6px;
}

.threat-category .category {
    font-weight: 500;
    flex: 1;
}

.severity {
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.severity-low { background: #dcfce7; color: #166534; }
.severity-medium { background: #fef3c7; color: #92400e; }
.severity-high { background: #fed7d7; color: #c53030; }
.severity-critical { background: #fde8e8; color: #9b2c2c; }

.threat-category .count {
    font-weight: 600;
    color: var(--primary-color);
    min-width: 40px;
    text-align: right;
}

/* Chart Container */
canvas {
    max-height: 300px;
    width: 100% !important;
    height: auto !important;
}

/* Responsive Design */
@media (max-width: 768px) {
    .dashboard-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
    }

    .header-meta {
        align-items: flex-start;
    }

    .tools-grid, .commands-grid, .cache-grid, .language-grid {
        grid-template-columns: 1fr;
    }

    .analytics-grid {
        grid-template-columns: 1fr;
    }

    .tool-stats, .command-stats, .cache-stats, .language-stats {
        grid-template-columns: 1fr;
    }
}

/* Loading and Animation */
.loading {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 40px;
}

.spinner {
    border: 3px solid var(--border-color);
    border-top: 3px solid var(--primary-color);
    border-radius: 50%;
    width: 32px;
    height: 32px;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Threat Findings Table Styles */
.threat-findings-section {
    margin-bottom: 32px;
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
}

.threat-findings-section h2 {
    text-align: center;
    margin-bottom: 24px;
}

.threat-findings-table-container {
    background: var(--card-background);
    border-radius: 12px;
    padding: 32px;
    box-shadow: var(--shadow);
    overflow: hidden;
    width: 100%;
    max-width: none;
}

.table-responsive {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
}

.threat-findings-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 0.9rem;
    background: var(--card-background);
    table-layout: fixed;
}

.threat-findings-table th {
    background: var(--background-color);
    color: var(--text-primary);
    font-weight: 600;
    padding: 18px 16px;
    text-align: left;
    border-bottom: 2px solid var(--border-color);
    border-right: 1px solid var(--border-color);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.025em;
    white-space: nowrap;
}

.threat-findings-table th:last-child {
    border-right: none;
}

.threat-findings-table td {
    padding: 18px 16px;
    border-bottom: 1px solid var(--border-color);
    border-right: 1px solid var(--border-color);
    vertical-align: middle;
    line-height: 1.5;
    word-wrap: break-word;
    overflow: hidden;
}

.threat-findings-table td:last-child {
    border-right: none;
}

.threat-row:hover {
    background: var(--background-color);
}

/* Column widths - optimized for wider screens */
.col-uuid { width: 12%; }
.col-time { width: 15%; }
.col-title { width: 28%; }
.col-severity { width: 8%; }
.col-file { width: 15%; }
.col-line { width: 6%; }
.col-scanner { width: 8%; }
.col-confidence { width: 10%; }
.col-status { width: 8%; }

/* Title content */
.title-content {
    font-weight: 500;
    color: var(--text-primary);
    line-height: 1.4;
}

/* Severity badges */
.severity-badge {
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 0.6875rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.025em;
}

.severity-critical {
    background: #fde8e8;
    color: #9b2c2c;
}

.severity-high {
    background: #fed7d7;
    color: #c53030;
}

.severity-medium {
    background: #fef3c7;
    color: #92400e;
}

.severity-low {
    background: #dcfce7;
    color: #166534;
}

/* Category tags */
.category-tag {
    padding: 3px 6px;
    background: var(--background-color);
    border-radius: 4px;
    font-size: 0.75rem;
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
}

/* File info */
.file-info {
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 0.75rem;
    color: var(--text-secondary);
    background: var(--background-color);
    padding: 2px 6px;
    border-radius: 4px;
}

/* Scanner badges */
.scanner-badge {
    padding: 3px 6px;
    border-radius: 4px;
    font-size: 0.6875rem;
    font-weight: 500;
    text-transform: lowercase;
}

.scanner-semgrep {
    background: #e0f2fe;
    color: #0277bd;
}

.scanner-llm {
    background: #f3e5f5;
    color: #7b1fa2;
}

/* Confidence bar */
.confidence-bar {
    position: relative;
    width: 80px;
    height: 18px;
    background: var(--background-color);
    border-radius: 9px;
    overflow: hidden;
    border: 1px solid var(--border-color);
}

.confidence-fill {
    height: 100%;
    background: linear-gradient(90deg, #ef4444, #f59e0b, #22c55e);
    transition: width 0.3s ease;
}

.confidence-text {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.625rem;
    font-weight: 600;
    color: var(--text-primary);
}

/* Status badges */
.status-badge {
    padding: 3px 6px;
    border-radius: 4px;
    font-size: 0.6875rem;
    font-weight: 600;
    text-align: center;
    min-width: 24px;
    display: inline-block;
}

.status-badge.false-positive {
    background: #fef3c7;
    color: #92400e;
}

.status-badge.validated {
    background: #dcfce7;
    color: #166534;
}

.status-badge.unvalidated {
    background: var(--background-color);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
}

/* UUID display */
.uuid-short {
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 0.6875rem;
    padding: 2px 4px;
    background: var(--background-color);
    border: 1px solid var(--border-color);
    border-radius: 3px;
    color: var(--text-secondary);
}

/* Time info */
.time-info {
    font-size: 0.75rem;
    color: var(--text-secondary);
    white-space: nowrap;
}

/* No findings state */
.no-findings {
    text-align: center;
    padding: 40px 20px;
    color: var(--text-secondary);
}

.no-findings .hint {
    font-size: 0.875rem;
    margin-top: 8px;
    color: var(--text-secondary);
}

/* Responsive adjustments */
@media (max-width: 1200px) {
    .threat-findings-table {
        font-size: 0.8125rem;
    }

    .threat-findings-table th,
    .threat-findings-table td {
        padding: 8px 6px;
    }
}

@media (max-width: 768px) {
    .col-title { width: 30%; }
    .col-category { display: none; }
    .col-confidence { display: none; }
    .col-time { display: none; }
}"""

        css_file = self.static_dir / "dashboard.css"
        css_file.write_text(css_content)

    def _create_javascript(self):
        """Create dashboard JavaScript functionality."""
        js_content = """// Dashboard JavaScript Functionality
document.addEventListener('DOMContentLoaded', function() {
    console.log('Adversary Dashboard loaded');

    // Auto-refresh every 5 minutes
    setInterval(() => {
        if (confirm('Refresh dashboard data?')) {
            location.reload();
        }
    }, 300000);
});

function initializeScanPerformanceChart(data) {
    const ctx = document.getElementById('scanPerformanceChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Semgrep Analysis', 'LLM Analysis', 'Validation'],
            datasets: [{
                data: [data.semgrep || 0, data.llm || 0, data.validation || 0],
                backgroundColor: [
                    '#2563eb',
                    '#f59e0b',
                    '#22c55e'
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            return `${label}: ${value.toFixed(1)}ms`;
                        }
                    }
                }
            }
        }
    });
}

// Utility functions for data formatting
function formatDuration(ms) {
    if (!ms || ms < 0) return 'N/A';
    if (ms < 1000) return `${ms.toFixed(1)}ms`;
    if (ms < 60000) return `${(ms/1000).toFixed(1)}s`;
    const minutes = Math.floor(ms / 60000);
    const seconds = ((ms % 60000) / 1000).toFixed(1);
    return `${minutes}m ${seconds}s`;
}

function formatSize(bytes) {
    if (!bytes || bytes < 0) return 'N/A';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }

    return `${size.toFixed(1)} ${units[unitIndex]}`;
}

function formatPercentage(value) {
    if (value === null || value === undefined) return 'N/A';
    return `${(value * 100).toFixed(1)}%`;
}"""

        js_file = self.static_dir / "dashboard.js"
        js_file.write_text(js_content)


# Initialize dashboard assets when module is loaded
def ensure_dashboard_assets():
    """Ensure dashboard assets exist, create if missing."""
    dashboard_dir = Path(__file__).parent
    asset_manager = DashboardAssetManager(dashboard_dir)

    if not (dashboard_dir / "templates" / "dashboard.html").exists():
        asset_manager.create_default_assets()


# Create assets on import
ensure_dashboard_assets()
