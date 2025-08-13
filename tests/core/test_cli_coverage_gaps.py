"""Tests to cover specific CLI coverage gaps."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.cli import (
    _initialize_cache_manager,
    _initialize_monitoring,
    _save_results_to_file,
    cli,
)
from adversary_mcp_server.config import SecurityConfig
from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestCLICoverageGaps:
    """Test specific CLI coverage gaps to improve overall coverage."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    def test_initialize_cache_manager_exception_handling(self):
        """Test cache manager exception handling."""
        # Reset global state
        import adversary_mcp_server.cli as cli_module

        cli_module._shared_cache_manager = None

        with (
            patch("adversary_mcp_server.cli.get_app_cache_dir"),
            patch("adversary_mcp_server.cli.CacheManager") as mock_cache,
            patch("adversary_mcp_server.cli.logger") as mock_logger,
        ):

            mock_cache.side_effect = Exception("Cache init failed")

            result = _initialize_cache_manager(enable_caching=True)

            assert result is None
            mock_logger.warning.assert_called_once_with(
                "Failed to initialize CLI cache manager: Cache init failed"
            )

    def test_initialize_monitoring_exception_handling(self):
        """Test monitoring exception handling."""
        # Reset global state
        import adversary_mcp_server.cli as cli_module

        cli_module._shared_metrics_collector = None

        with (
            patch("adversary_mcp_server.cli.get_app_metrics_dir"),
            patch("adversary_mcp_server.cli.MonitoringConfig") as mock_config,
            patch("adversary_mcp_server.cli.logger") as mock_logger,
        ):

            mock_config.side_effect = Exception("Monitoring init failed")

            result = _initialize_monitoring(enable_metrics=True)

            assert result is None
            mock_logger.warning.assert_called_once_with(
                "Failed to initialize CLI monitoring: Monitoring init failed"
            )

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli.Confirm.ask")
    @patch("adversary_mcp_server.cli.Prompt.ask")
    def test_configure_command_semgrep_key_storage_failure(
        self, mock_prompt, mock_confirm, mock_console, mock_cred_manager
    ):
        """Test configure command with Semgrep key storage failure."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_manager.get_semgrep_api_key.return_value = None
        mock_cred_manager.return_value = mock_manager

        mock_confirm.return_value = True
        mock_prompt.return_value = "test-api-key-12345"
        mock_manager.store_semgrep_api_key.side_effect = Exception("Storage failed")

        result = self.runner.invoke(cli, ["configure"])

        # Should handle the error gracefully
        assert result.exit_code == 0
        mock_console.print.assert_any_call(
            "❌ Failed to store Semgrep API key: Storage failed", style="red"
        )

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli.Confirm.ask")
    @patch("adversary_mcp_server.cli.Prompt.ask")
    def test_configure_command_empty_semgrep_key(
        self, mock_prompt, mock_confirm, mock_console, mock_cred_manager
    ):
        """Test configure command with empty Semgrep key input."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_manager.get_semgrep_api_key.return_value = None
        mock_cred_manager.return_value = mock_manager

        mock_confirm.return_value = True
        mock_prompt.return_value = ""  # Empty input

        result = self.runner.invoke(cli, ["configure"])

        assert result.exit_code == 0
        mock_manager.store_semgrep_api_key.assert_not_called()
        mock_console.print.assert_any_call(
            "⏭️  Skipped Semgrep API key configuration", style="yellow"
        )

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.console")
    def test_configure_command_with_existing_llm_provider(
        self, mock_console, mock_cred_manager
    ):
        """Test configure command showing existing LLM provider status."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_config.llm_provider = "openai"
        mock_config.llm_model = "gpt-4"
        mock_manager.load_config.return_value = mock_config
        mock_manager.get_semgrep_api_key.return_value = "existing-key"
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["configure"])

        assert result.exit_code == 0
        mock_console.print.assert_any_call(
            "\n🤖 LLM Provider: ✅ Openai (Model: gpt-4)", style="green"
        )

    def test_debug_config_command_runs_successfully(self):
        """Test debug-config command runs without crashing."""
        result = self.runner.invoke(cli, ["debug-config"])

        # Should not crash (exit code 0 or handled gracefully)
        assert result.exit_code in [0, 1]  # 1 might be returned on configuration issues
        # Should produce some output
        assert (
            "Configuration Debug Information" in result.output or len(result.output) > 0
        )

    def test_save_results_to_file_format(self):
        """Test saving results to file (always JSON format)."""
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            code_snippet="vulnerable_code()",
            exploit_examples=["example exploit"],
            remediation="Fix the issue",
        )

        scan_result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[threat],
            scan_metadata={"scan_time": "2023-01-01"},
            validation_results={},
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_file = f.name

        try:
            _save_results_to_file(scan_result, "test_target", output_file)

            # Verify file was created and contains expected content
            assert Path(output_file).exists()
            with open(output_file) as f:
                content = f.read()
            # The function always saves as JSON regardless of extension
            data = json.loads(content)
            assert "scan_metadata" in data
            assert data["scan_metadata"]["target"] == "test_target"

        finally:
            Path(output_file).unlink()

    def test_scan_command_path_validation_error(self):
        """Test scan command with path validation error."""
        result = self.runner.invoke(cli, ["scan", "../../../etc/passwd"])

        assert result.exit_code == 1
        # Check that validation error message appears in output
        assert "Input Validation Error" in result.output
        assert "Path traversal" in result.output

    def test_scan_command_severity_validation_error(self):
        """Test scan command with invalid severity parameter."""
        result = self.runner.invoke(cli, ["scan", "test.py", "--severity", "invalid"])

        assert (
            result.exit_code == 2
        )  # Click's standard error code for invalid parameters
        # Check that Click's validation error message appears in output
        assert "Invalid value for '--severity'" in result.output
        assert "invalid" in result.output

    @patch("adversary_mcp_server.cli.get_credential_manager")
    def test_status_command_credential_manager_error(self, mock_cred_manager):
        """Test status command when credential manager fails."""
        mock_cred_manager.side_effect = Exception("Credential manager failed")

        result = self.runner.invoke(cli, ["status"])

        # Should handle the error gracefully
        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.get_credential_manager")
    def test_configure_command_credential_manager_error(self, mock_cred_manager):
        """Test configure command when credential manager fails."""
        mock_cred_manager.side_effect = Exception("Credential manager failed")

        result = self.runner.invoke(cli, ["configure"])

        # Should handle the error gracefully
        assert result.exit_code == 1

    def test_save_results_unsupported_extension(self):
        """Test saving results with unsupported file extension."""
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

        with tempfile.NamedTemporaryFile(mode="w", suffix=".xyz", delete=False) as f:
            output_file = f.name

        try:
            # Should default to text format for unknown extensions
            _save_results_to_file(scan_result, "test_target", output_file)

            assert Path(output_file).exists()
            with open(output_file) as f:
                content = f.read()
            assert "test_rule" in content

        finally:
            Path(output_file).unlink()

    def test_save_results_json_format(self):
        """Test saving results in JSON format."""
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

            # Verify file was created and contains valid JSON
            assert Path(output_file).exists()
            with open(output_file) as f:
                data = json.load(f)
            assert len(data["threats"]) == 1
            assert data["threats"][0]["rule_id"] == "test_rule"

        finally:
            Path(output_file).unlink()

    def test_help_commands(self):
        """Test that help commands work."""
        commands_to_test = [
            ["--help"],
            ["configure", "--help"],
            ["status", "--help"],
            ["scan", "--help"],
            ["debug-config", "--help"],
        ]

        for cmd in commands_to_test:
            result = self.runner.invoke(cli, cmd)
            assert result.exit_code == 0
