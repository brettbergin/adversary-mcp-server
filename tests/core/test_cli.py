"""Tests for CLI module."""

import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.cli import (
    _display_scan_results,
    _initialize_monitoring,
    cli,
    configure,
    demo,
    main,
    metrics_analyze,
    monitoring,
    reset,
    scan,
    status,
)
from adversary_mcp_server.config import SecurityConfig
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestCLI:
    """Test cases for CLI functions."""

    def test_main_function_exists(self):
        """Test main function exists."""
        assert main is not None

    def test_configure_function_exists(self):
        """Test configure function exists."""
        assert configure is not None

    def test_cli_functions_exist(self):
        """Test that CLI functions can be imported."""
        # Since these are typer commands, we mainly test they can be imported
        assert status is not None
        assert scan is not None
        assert demo is not None
        assert reset is not None

    def test_display_scan_results_empty(self):
        """Test _display_scan_results with empty results."""
        with patch("adversary_mcp_server.cli.console") as mock_console:
            _display_scan_results([], "test.py")
            mock_console.print.assert_called()

    def test_display_scan_results_with_threats(self):
        """Test _display_scan_results with threats."""
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            code_snippet="test code",
            exploit_examples=["test exploit"],
            remediation="Fix it",
        )

        with patch("adversary_mcp_server.cli.console") as mock_console:
            _display_scan_results([threat], "test.py")
            mock_console.print.assert_called()

    def test_monitoring_function_exists(self):
        """Test monitoring function exists."""
        assert monitoring is not None

    def test_metrics_analyze_function_exists(self):
        """Test metrics_analyze function exists."""
        assert metrics_analyze is not None

    def test_initialize_monitoring_function_exists(self):
        """Test _initialize_monitoring function exists."""
        assert _initialize_monitoring is not None

    def test_initialize_monitoring_disabled(self):
        """Test _initialize_monitoring with metrics disabled."""
        result = _initialize_monitoring(enable_metrics=False)
        assert result is None

    def test_initialize_monitoring_enabled(self):
        """Test _initialize_monitoring with metrics enabled."""
        with (
            patch("adversary_mcp_server.cli.get_app_metrics_dir") as mock_metrics_dir,
            patch("adversary_mcp_server.cli.MonitoringConfig") as mock_config,
            patch("adversary_mcp_server.cli.MetricsCollector") as mock_collector,
        ):

            mock_metrics_dir.return_value = "/tmp/test_metrics"

            result = _initialize_monitoring(enable_metrics=True)

            mock_config.assert_called_once_with(
                enable_metrics=True,
                enable_performance_monitoring=True,
                json_export_path="/tmp/test_metrics",
            )
            mock_collector.assert_called_once()
            assert result is not None

    def test_monitoring_command_help(self):
        """Test monitoring command help."""
        runner = CliRunner()
        from adversary_mcp_server.cli import cli

        result = runner.invoke(cli, ["monitoring", "--help"])
        assert result.exit_code == 0
        assert "Monitor system metrics" in result.stdout

    def test_metrics_analyze_command_help(self):
        """Test metrics-analyze command help."""
        runner = CliRunner()
        from adversary_mcp_server.cli import cli

        result = runner.invoke(cli, ["metrics-analyze", "--help"])
        assert result.exit_code == 0
        assert "Analyze historical metrics" in result.stdout

    @patch("adversary_mcp_server.cli._initialize_monitoring")
    @patch("adversary_mcp_server.cli.MonitoringDashboard")
    @patch("adversary_mcp_server.cli.time.sleep")
    def test_monitoring_command_execution(
        self, mock_sleep, mock_dashboard_class, mock_init_monitoring
    ):
        """Test monitoring command execution."""
        runner = CliRunner()
        from adversary_mcp_server.cli import cli

        mock_collector = Mock()
        mock_init_monitoring.return_value = mock_collector
        mock_dashboard = mock_dashboard_class.return_value

        # Mock sleep to raise KeyboardInterrupt after first call to simulate Ctrl+C
        mock_sleep.side_effect = KeyboardInterrupt("Simulated user interrupt")

        result = runner.invoke(cli, ["monitoring", "--show-dashboard"])

        # Should exit cleanly with KeyboardInterrupt (exit code 0)
        assert result.exit_code == 0

        # Should have called initialization
        mock_init_monitoring.assert_called()

        # Should have attempted to display dashboard
        mock_dashboard.display_real_time_dashboard.assert_called()

    @patch("adversary_mcp_server.cli._initialize_monitoring")
    @patch("adversary_mcp_server.cli.MonitoringDashboard")
    def test_monitoring_command_export_json(
        self, mock_dashboard_class, mock_init_monitoring
    ):
        """Test monitoring command with JSON export (no infinite loop)."""
        runner = CliRunner()
        from adversary_mcp_server.cli import cli

        mock_collector = Mock()
        mock_init_monitoring.return_value = mock_collector
        mock_dashboard = mock_dashboard_class.return_value
        mock_dashboard.export_dashboard_report.return_value = Path(
            "/tmp/test_report.json"
        )

        result = runner.invoke(cli, ["monitoring", "--export-format", "json"])

        # Should complete successfully
        assert result.exit_code == 0

        # Should have called initialization
        mock_init_monitoring.assert_called()

        # Should have called export
        mock_dashboard.export_dashboard_report.assert_called()

    @patch("adversary_mcp_server.cli._initialize_monitoring")
    def test_metrics_analyze_command_execution(self, mock_init_monitoring):
        """Test metrics-analyze command execution."""
        runner = CliRunner()
        from adversary_mcp_server.cli import cli

        mock_collector = Mock()
        mock_init_monitoring.return_value = mock_collector

        with patch("adversary_mcp_server.cli.get_app_metrics_dir") as mock_metrics_dir:
            mock_metrics_dir.return_value = "/tmp/test_metrics"

            result = runner.invoke(cli, ["metrics-analyze", "--time-range", "24h"])

            # Should have attempted initialization
            mock_init_monitoring.assert_called()


class TestCLICommands:
    """Test CLI command functionality with comprehensive coverage."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli.Confirm.ask")
    def test_configure_command_comprehensive(
        self, mock_confirm, mock_console, mock_cred_manager
    ):
        """Test configure command with various options."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_manager.get_semgrep_api_key.return_value = "existing-key"
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(
            cli,
            [
                "configure",
                "--severity-threshold",
                "high",
                "--enable-safety-mode",
            ],
        )

        assert result.exit_code == 0

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    def test_status_command_comprehensive(self, mock_console, mock_cred_manager):
        """Test status command with configuration."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_config.severity_threshold = Severity.MEDIUM
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["status"])
        assert result.exit_code == 0

    @patch("adversary_mcp_server.cli.console")
    def test_invalid_command_handling(self, mock_console):
        """Test handling of invalid commands."""
        result = self.runner.invoke(cli, ["nonexistent-command"])
        assert result.exit_code != 0

    def test_file_permission_errors(self, tmp_path):
        """Test handling of file permission errors."""
        from adversary_mcp_server.cli import _save_results_to_file
        from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
        from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch

        # Create a file and remove write permissions
        restricted_file = tmp_path / "restricted.json"
        restricted_file.touch()
        restricted_file.chmod(0o444)  # Read-only

        try:
            threat = ThreatMatch(
                rule_id="test",
                rule_name="Test",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
            )

            scan_result = EnhancedScanResult(
                file_path="test.py",
                llm_threats=[],
                semgrep_threats=[threat],
                scan_metadata={},
                validation_results={},
            )

            # Should handle permission error gracefully
            try:
                _save_results_to_file(scan_result, "test_target", str(restricted_file))
            except Exception:
                pass  # Expected to raise permission error

        finally:
            restricted_file.chmod(0o644)  # Restore permissions for cleanup


class TestCLIUtilities:
    """Test CLI utility functions."""

    def test_display_scan_results_comprehensive(self):
        """Test comprehensive display of scan results."""
        from adversary_mcp_server.cli import _display_scan_results
        from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch

        threats = [
            ThreatMatch(
                rule_id="test_rule_1",
                rule_name="Test Rule 1",
                description="Test description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test1.py",
                line_number=10,
                code_snippet="vulnerable code",
                exploit_examples=["example exploit"],
                remediation="Fix the vulnerability",
            ),
            ThreatMatch(
                rule_id="test_rule_2",
                rule_name="Test Rule 2",
                description="Test description 2",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test2.js",
                line_number=20,
            ),
        ]

        # Should not raise any exceptions
        _display_scan_results(threats, "test_target")

    def test_save_results_to_file_json(self):
        """Test saving results to JSON file."""
        import json
        import tempfile
        from pathlib import Path

        from adversary_mcp_server.cli import _save_results_to_file
        from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
        from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch

        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
        )

        scan_result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[threat],
            scan_metadata={},
            validation_results={},
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            _save_results_to_file(scan_result, "test_target", output_file)

            # Verify file was created
            assert Path(output_file).exists()
            with open(output_file) as f:
                data = json.load(f)
            assert len(data["threats"]) == 1
            assert data["threats"][0]["rule_id"] == "test_rule"

        finally:
            Path(output_file).unlink()

    def test_save_results_to_file_text(self):
        """Test saving results to text file."""
        import tempfile
        from pathlib import Path

        from adversary_mcp_server.cli import _save_results_to_file
        from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
        from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch

        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
        )

        scan_result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[threat],
            scan_metadata={},
            validation_results={},
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_file = f.name

        try:
            _save_results_to_file(scan_result, "test_target", output_file)

            # Verify file was created
            assert Path(output_file).exists()
            with open(output_file) as f:
                content = f.read()
            assert "test_rule" in content

        finally:
            Path(output_file).unlink()


class TestCLIIntegration:
    """Integration tests for CLI."""

    def test_cli_import_integration(self):
        """Test that CLI components can be integrated."""
        # Test that we can import all the CLI functions
        assert main is not None
        assert configure is not None
        assert status is not None

        # Test basic CLI structure exists
        from adversary_mcp_server import cli

        assert hasattr(cli, "cli")  # Main typer app
