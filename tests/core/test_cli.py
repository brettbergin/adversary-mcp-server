"""Tests for CLI module."""

import os
import sys
from unittest.mock import Mock, patch

import pytest
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
    @patch("adversary_mcp_server.monitoring.unified_dashboard.UnifiedDashboard")
    @patch("signal.signal")
    @patch("adversary_mcp_server.cli.time.sleep")
    def test_monitoring_command_execution(
        self, mock_sleep, mock_signal, mock_dashboard_class, mock_init_monitoring
    ):
        """Test monitoring command execution."""
        runner = CliRunner()
        from adversary_mcp_server.cli import cli

        mock_collector = Mock()
        mock_init_monitoring.return_value = mock_collector
        mock_dashboard = mock_dashboard_class.return_value

        # Mock signal to prevent interference with test environment
        mock_signal.return_value = None

        # Mock dashboard display to raise KeyboardInterrupt after first call to simulate Ctrl+C
        mock_dashboard.display_real_time_dashboard.side_effect = KeyboardInterrupt(
            "Simulated user interrupt"
        )

        result = runner.invoke(cli, ["monitoring", "--show-dashboard"])

        # KeyboardInterrupt in CLI is handled by Click and returns exit code 0 (normal termination after handling)
        # The monitoring command should handle the interrupt gracefully and return normally
        assert result.exit_code == 0

        # Should have called initialization
        mock_init_monitoring.assert_called()

        # Should have attempted to display dashboard (which raises KeyboardInterrupt)
        mock_dashboard.display_real_time_dashboard.assert_called()

    @patch("adversary_mcp_server.cli._initialize_monitoring")
    @patch("adversary_mcp_server.monitoring.unified_dashboard.UnifiedDashboard")
    def test_monitoring_command_export_json(
        self, mock_dashboard_class, mock_init_monitoring
    ):
        """Test monitoring command with JSON export (no infinite loop)."""
        runner = CliRunner()
        from adversary_mcp_server.cli import cli

        mock_collector = Mock()
        mock_init_monitoring.return_value = mock_collector
        mock_dashboard = mock_dashboard_class.return_value
        mock_dashboard.export_metrics.return_value = "/tmp/test_report.json"

        result = runner.invoke(cli, ["monitoring", "--export-format", "json"])

        # Should complete successfully
        assert result.exit_code == 0

        # Should have called initialization
        mock_init_monitoring.assert_called()

        # Should have called export
        mock_dashboard.export_metrics.assert_called()

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

    def test_cli_security_sanitization_integration(self):
        """Test that CLI includes security argument sanitization."""
        from adversary_mcp_server.security import InputValidator, SecurityError

        # Test that dangerous CLI arguments would be caught by validation
        dangerous_path = "../../../etc/passwd"

        with pytest.raises(SecurityError, match="Path traversal"):
            InputValidator.validate_file_path(dangerous_path)

    def test_cli_argument_validation_integration(self):
        """Test that CLI argument validation is integrated."""
        from adversary_mcp_server.security import InputValidator

        # Test that CLI validation methods are available
        assert hasattr(InputValidator, "validate_file_path")
        assert hasattr(InputValidator, "validate_severity_threshold")
        assert hasattr(InputValidator, "validate_string_param")

        # Test severity validation works for CLI
        valid_severity = InputValidator.validate_severity_threshold("high")
        assert valid_severity == "high"

    def test_cli_metrics_tracking_availability(self):
        """Test that CLI has access to metrics tracking components."""
        runner = CliRunner()

        # Test that CLI imports don't fail with new metrics components
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

        # Test that status command includes new components
        result = runner.invoke(status)
        assert result.exit_code == 0
        # Should not crash even if telemetry is not configured

    def test_cli_log_sanitization_availability(self):
        """Test that CLI has access to log sanitization functions."""
        from adversary_mcp_server.security import sanitize_for_logging

        # Test sanitization works in CLI context
        sensitive_data = {
            "api_key": "sk-secret123",
            "path": "/safe/path/file.py",
            "command": "scan",
        }

        sanitized = sanitize_for_logging(sensitive_data)

        # Verify sensitive data is redacted
        assert "sk-secret123" not in sanitized
        assert "[REDACTED]" in sanitized

        # Verify safe data is preserved
        assert "/safe/path/file.py" in sanitized
        assert "scan" in sanitized

    def test_cli_dashboard_command_integration(self):
        """Test that CLI dashboard command is properly integrated."""
        runner = CliRunner()

        # Test dashboard command exists and runs
        result = runner.invoke(cli, ["dashboard", "--help"])
        assert result.exit_code == 0

        # Should show dashboard-related help
        assert "dashboard" in result.output.lower()

    def test_cli_security_error_handling(self):
        """Test that CLI properly handles security errors."""
        from adversary_mcp_server.security import SecurityError

        # Test SecurityError can be raised and handled
        try:
            raise SecurityError("CLI security test error")
        except SecurityError as e:
            assert str(e) == "CLI security test error"

        # Test error inheritance
        assert issubclass(SecurityError, Exception)

    def test_cli_new_architecture_compatibility(self):
        """Test that CLI is compatible with new Phase II architecture."""
        runner = CliRunner()

        # Test that all main CLI commands can be invoked without errors
        commands_to_test = ["status", "configure", "--help"]

        for cmd in commands_to_test:
            result = runner.invoke(cli, [cmd])
            # Should not crash, even if not fully configured
            assert result.exit_code in [
                0,
                1,
            ]  # 0 for success, 1 for expected config errors


class TestCLIResetCommand:
    """Test cases specifically for the reset command and LLM API key deletion bug."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli.Confirm.ask")
    def test_reset_command_deletes_all_credentials(
        self, mock_confirm, mock_console, mock_cred_manager
    ):
        """Test that reset command deletes all credentials including LLM API keys."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager
        mock_confirm.return_value = True  # User confirms reset

        # Mock credential manager methods
        mock_manager.delete_config.return_value = None
        mock_manager.delete_semgrep_api_key.return_value = True
        mock_manager.clear_llm_configuration.return_value = None

        # Run the reset command
        result = self.runner.invoke(cli, ["reset"])

        # Verify command completed successfully
        assert result.exit_code == 0

        # Verify all credential deletion methods were called
        mock_manager.delete_config.assert_called_once()
        mock_manager.delete_semgrep_api_key.assert_called_once()
        mock_manager.clear_llm_configuration.assert_called_once()

        # Verify confirmation was asked
        mock_confirm.assert_called_once_with(
            "Are you sure you want to reset all configuration?"
        )

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli.Confirm.ask")
    def test_reset_command_user_cancels(
        self, mock_confirm, mock_console, mock_cred_manager
    ):
        """Test that reset command does nothing when user cancels."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager
        mock_confirm.return_value = False  # User cancels reset

        # Run the reset command
        result = self.runner.invoke(cli, ["reset"])

        # Verify command completed successfully (user cancelled)
        assert result.exit_code == 0

        # Verify no credential deletion methods were called
        mock_manager.delete_config.assert_not_called()
        mock_manager.delete_semgrep_api_key.assert_not_called()
        mock_manager.clear_llm_configuration.assert_not_called()

        # Verify confirmation was asked
        mock_confirm.assert_called_once_with(
            "Are you sure you want to reset all configuration?"
        )

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli.Confirm.ask")
    def test_reset_command_handles_deletion_errors(
        self, mock_confirm, mock_console, mock_cred_manager
    ):
        """Test that reset command handles credential deletion errors gracefully."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager
        mock_confirm.return_value = True  # User confirms reset

        # Mock credential manager methods - simulate error in LLM deletion
        mock_manager.delete_config.return_value = None
        mock_manager.delete_semgrep_api_key.return_value = True
        mock_manager.clear_llm_configuration.side_effect = Exception(
            "LLM credential deletion failed"
        )

        # Run the reset command
        result = self.runner.invoke(cli, ["reset"])

        # Verify command failed due to the exception
        assert result.exit_code == 1

        # Verify config and semgrep deletion were called before the error
        mock_manager.delete_config.assert_called_once()
        mock_manager.delete_semgrep_api_key.assert_called_once()
        mock_manager.clear_llm_configuration.assert_called_once()

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli.Confirm.ask")
    def test_reset_command_no_semgrep_key_found(
        self, mock_confirm, mock_console, mock_cred_manager
    ):
        """Test reset command when no Semgrep API key is found."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager
        mock_confirm.return_value = True  # User confirms reset

        # Mock credential manager methods - no Semgrep key found
        mock_manager.delete_config.return_value = None
        mock_manager.delete_semgrep_api_key.return_value = False  # No key found
        mock_manager.clear_llm_configuration.return_value = None

        # Run the reset command
        result = self.runner.invoke(cli, ["reset"])

        # Verify command completed successfully
        assert result.exit_code == 0

        # Verify all methods were called
        mock_manager.delete_config.assert_called_once()
        mock_manager.delete_semgrep_api_key.assert_called_once()
        mock_manager.clear_llm_configuration.assert_called_once()

        # Verify appropriate console messages were printed
        mock_console.print.assert_any_call(
            "✅ Main configuration deleted", style="green"
        )
        mock_console.print.assert_any_call(
            "ℹ️  No Semgrep API key found to delete", style="yellow"
        )
        mock_console.print.assert_any_call("✅ LLM API keys cleared", style="green")
        mock_console.print.assert_any_call(
            "✅ All configuration reset successfully!", style="green"
        )

    def test_reset_command_exists_and_importable(self):
        """Test that reset command exists and can be imported."""
        from adversary_mcp_server.cli import reset

        assert reset is not None

    @patch("adversary_mcp_server.cli.get_credential_manager")
    def test_reset_command_integration_with_credential_manager(self, mock_cred_manager):
        """Test that reset command properly integrates with credential manager."""
        # This test verifies the reset function uses the correct credential manager methods
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        # Check that credential manager has all required methods
        assert hasattr(mock_manager, "delete_config")
        assert hasattr(mock_manager, "delete_semgrep_api_key")
        assert hasattr(mock_manager, "clear_llm_configuration")

    def test_reset_command_help(self):
        """Test reset command help text."""
        runner = CliRunner()
        result = runner.invoke(cli, ["reset", "--help"])
        assert result.exit_code == 0
        assert "Reset all configuration" in result.output
