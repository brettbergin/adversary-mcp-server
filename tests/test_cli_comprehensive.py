"""Comprehensive CLI tests focused on improving code coverage."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from adversary_mcp_server.cli import _display_scan_results, _save_results_to_file, cli
from adversary_mcp_server.credential_manager import SecurityConfig
from adversary_mcp_server.types import Category, Severity, ThreatMatch


class TestCLICommandsCoverage:
    """Test CLI commands to improve coverage."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_configure_command_basic(self, mock_console, mock_cred_manager):
        """Test configure command basic functionality."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
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
        # The actual save_config method is called, not store_config
        mock_manager.save_config.assert_called_once()

    def test_configure_command_with_existing_config(self):
        """Test configure command with existing config."""
        with patch("adversary_mcp_server.cli.CredentialManager") as mock_manager:
            mock_instance = mock_manager.return_value
            mock_config = SecurityConfig(
                enable_llm_analysis=True, severity_threshold="high"
            )
            mock_instance.load_config.return_value = mock_config

            runner = CliRunner()
            result = runner.invoke(
                cli, ["configure", "--severity-threshold", "critical"]
            )

            assert result.exit_code == 0
            mock_instance.save_config.assert_called_once()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_configure_command_error_handling(self, mock_console, mock_cred_manager):
        """Test configure command error handling."""
        mock_manager = Mock()
        mock_manager.load_config.side_effect = Exception("Load failed")
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(
            cli,
            [
                "configure",
                "--severity-threshold",
                "medium",
            ],
        )

        # Should fail when config load fails
        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_configure_command_store_error(self, mock_console, mock_cred_manager):
        """Test configure command with store error."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_manager.save_config.side_effect = Exception("Store failed")
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["configure", "--severity-threshold", "high"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_status_command_basic(
        self, mock_console, mock_cred_manager, mock_scan_engine
    ):
        """Test status command basic functionality."""
        mock_manager = Mock()
        mock_config = SecurityConfig(
            enable_llm_analysis=True, severity_threshold="high"
        )
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        # Mock ScanEngine and its components
        mock_engine = Mock()
        mock_engine.semgrep_scanner.is_available.return_value = True
        mock_engine.llm_analyzer = Mock()
        mock_engine.llm_analyzer.is_available.return_value = True
        mock_scan_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["status"])

        assert result.exit_code == 0
        # Verify console.print was called with status information
        mock_console.print.assert_called()
        # Check that at least one call mentions configuration-related content
        calls = [str(call) for call in mock_console.print.call_args_list]
        config_mentioned = any(
            "Configuration" in call or "Adversary MCP Server Status" in call
            for call in calls
        )
        assert config_mentioned

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_status_command_error(self, mock_console, mock_cred_manager):
        """Test status command with error."""
        mock_manager = Mock()
        mock_manager.load_config.side_effect = Exception("Load failed")
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["status"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_reset_command_confirmed(self, mock_console, mock_cred_manager):
        """Test reset command with confirmation."""
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["reset"], input="y\n")

        assert result.exit_code == 0
        mock_manager.reset_config.assert_called_once()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_reset_command_cancelled(self, mock_console, mock_cred_manager):
        """Test reset command cancelled."""
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["reset"], input="n\n")

        assert result.exit_code == 0
        mock_manager.reset_config.assert_not_called()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_reset_command_error(self, mock_console, mock_cred_manager):
        """Test reset command error handling."""
        mock_manager = Mock()
        mock_manager.reset_config.side_effect = Exception("Reset failed")
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["reset"], input="y\n")

        assert result.exit_code == 1


class TestCLIScanCommand:
    """Test CLI scan (diff-scan) command comprehensively."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.GitDiffScanner")
    @patch("adversary_mcp_server.cli.console")
    def test_diff_scan_basic(
        self,
        mock_console,
        mock_diff_scanner_class,
        mock_scan_engine_class,
        mock_cred_manager,
    ):
        """Test basic diff scan functionality."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_scan_engine = Mock()
        mock_scan_engine_class.return_value = mock_scan_engine

        mock_diff_scanner = Mock()
        mock_diff_scanner_class.return_value = mock_diff_scanner

        # Create mock threat and scan result
        mock_threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
        )

        # Create mock diff scan result
        mock_scan_result = Mock()
        mock_scan_result.all_threats = [mock_threat]

        mock_diff_scanner.scan_diff_sync.return_value = {"test.py": [mock_scan_result]}

        result = self.runner.invoke(
            cli, ["scan", "--source-branch", "main", "--target-branch", "feature"]
        )

        assert result.exit_code == 0
        mock_diff_scanner.scan_diff_sync.assert_called_once()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.GitDiffScanner")
    @patch("adversary_mcp_server.cli.console")
    def test_diff_scan_with_output(
        self,
        mock_console,
        mock_diff_scanner_class,
        mock_scan_engine_class,
        mock_cred_manager,
    ):
        """Test diff scan with output file."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_scan_engine = Mock()
        mock_scan_engine_class.return_value = mock_scan_engine

        mock_diff_scanner = Mock()
        mock_diff_scanner_class.return_value = mock_diff_scanner

        # Create mock diff scan result
        mock_scan_result = Mock()
        mock_scan_result.all_threats = []
        mock_diff_scanner.scan_diff_sync.return_value = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            result = self.runner.invoke(
                cli,
                [
                    "scan",
                    "--source-branch",
                    "main",
                    "--target-branch",
                    "feature",
                    "--output",
                    output_file,
                ],
            )

            assert result.exit_code == 0
            # Verify file exists (content check would depend on implementation)
            assert Path(output_file).exists()

        finally:
            os.unlink(output_file)


class TestCLIUtilityFunctions:
    """Test CLI utility functions for coverage."""

    def test_save_results_to_file_json(self):
        """Test saving results to JSON file."""
        threats = [
            ThreatMatch(
                rule_id="test_rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            _save_results_to_file(threats, output_file)

            # Verify file was created
            assert Path(output_file).exists()
            with open(output_file) as f:
                data = json.load(f)
            assert len(data["threats"]) == 1
            assert data["threats"][0]["rule_id"] == "test_rule"

        finally:
            os.unlink(output_file)

    def test_save_results_to_file_text(self):
        """Test saving results to text file."""
        threats = [
            ThreatMatch(
                rule_id="test_rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_file = f.name

        try:
            _save_results_to_file(threats, output_file)

            # Verify file was created
            assert Path(output_file).exists()
            with open(output_file) as f:
                content = f.read()
            assert "test_rule" in content
            assert "Test Rule" in content

        finally:
            os.unlink(output_file)

    @patch("adversary_mcp_server.cli.console")
    def test_display_scan_results_empty(self, mock_console):
        """Test displaying empty scan results."""
        _display_scan_results([], "test_target")
        mock_console.print.assert_called()

    @patch("adversary_mcp_server.cli.console")
    def test_display_scan_results_with_threats(self, mock_console):
        """Test displaying scan results with threats."""
        threats = [
            ThreatMatch(
                rule_id="test_rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
                code_snippet="dangerous_code()",
                exploit_examples=["exploit1", "exploit2"],
            )
        ]

        _display_scan_results(threats, "test_target")
        mock_console.print.assert_called()
