"""Tests for CLI use_rules flag functionality."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from adversary_mcp_server.cli import cli
from adversary_mcp_server.credential_manager import SecurityConfig
from adversary_mcp_server.threat_engine import Category, Severity, ThreatMatch


class TestCLIUseRulesFlag:
    """Test CLI with --use-rules/--no-rules flags."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    def test_scan_with_no_rules_flag(
        self, mock_scan_engine, mock_threat_engine, mock_cred_manager
    ):
        """Test CLI scan with --no-rules flag."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scan_engine.return_value = mock_scan_engine_instance

        # Create mock scan result with no threats (rules disabled)
        mock_scan_result = Mock()
        mock_scan_result.all_threats = []
        mock_scan_engine_instance.scan_file_sync.return_value = mock_scan_result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import os; os.system(user_input)")
            test_file = f.name

        try:
            result = self.runner.invoke(
                cli, ["scan", test_file, "--no-rules", "--no-semgrep", "--no-llm"]
            )

            assert result.exit_code == 0
            # Verify scan_file was called with use_rules=False
            mock_scan_engine_instance.scan_file_sync.assert_called_once()
            call_args = mock_scan_engine_instance.scan_file_sync.call_args
            assert call_args.kwargs["use_rules"] is False
            assert call_args.kwargs["use_semgrep"] is False
            assert call_args.kwargs["use_llm"] is False

        finally:
            Path(test_file).unlink()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    def test_scan_with_use_rules_flag(
        self, mock_scan_engine, mock_threat_engine, mock_cred_manager
    ):
        """Test CLI scan with --use-rules flag."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scan_engine.return_value = mock_scan_engine_instance

        # Create mock scan result with threats (rules enabled)
        mock_scan_result = Mock()
        mock_scan_result.all_threats = [
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
        mock_scan_engine_instance.scan_file_sync.return_value = mock_scan_result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import os; os.system(user_input)")
            test_file = f.name

        try:
            result = self.runner.invoke(
                cli, ["scan", test_file, "--use-rules", "--no-semgrep", "--no-llm"]
            )

            assert result.exit_code == 0
            # Verify scan_file was called with use_rules=True
            mock_scan_engine_instance.scan_file_sync.assert_called_once()
            call_args = mock_scan_engine_instance.scan_file_sync.call_args
            assert call_args.kwargs["use_rules"] is True
            assert call_args.kwargs["use_semgrep"] is False
            assert call_args.kwargs["use_llm"] is False

        finally:
            Path(test_file).unlink()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    def test_scan_directory_with_no_rules(
        self, mock_scan_engine, mock_threat_engine, mock_cred_manager
    ):
        """Test CLI directory scan with --no-rules flag."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scan_engine.return_value = mock_scan_engine_instance
        mock_scan_engine_instance.scan_directory_sync.return_value = []

        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import os; os.system(user_input)")

            result = self.runner.invoke(
                cli, ["scan", temp_dir, "--no-rules", "--no-semgrep", "--no-llm"]
            )

            assert result.exit_code == 0
            # Verify scan_directory was called with use_rules=False
            mock_scan_engine_instance.scan_directory_sync.assert_called_once()
            call_args = mock_scan_engine_instance.scan_directory_sync.call_args
            assert call_args.kwargs["use_rules"] is False

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.GitDiffScanner")
    def test_diff_scan_with_no_rules(
        self, mock_diff_scanner, mock_threat_engine, mock_cred_manager
    ):
        """Test CLI diff scan with --no-rules flag."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_diff_scanner_instance = Mock()
        mock_diff_scanner.return_value = mock_diff_scanner_instance
        mock_diff_scanner_instance.scan_diff_sync.return_value = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                cli,
                [
                    "scan",
                    temp_dir,
                    "--diff",
                    "--source-branch",
                    "main",
                    "--target-branch",
                    "feature",
                    "--no-rules",
                    "--no-semgrep",
                    "--no-llm",
                ],
            )

            assert result.exit_code == 0
            # Verify scan_diff_sync was called with use_rules=False
            mock_diff_scanner_instance.scan_diff_sync.assert_called_once()
            call_args = mock_diff_scanner_instance.scan_diff_sync.call_args
            assert call_args.kwargs["use_rules"] is False

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    def test_scan_flag_combinations(
        self, mock_scan_engine, mock_threat_engine, mock_cred_manager
    ):
        """Test different flag combinations."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scan_engine.return_value = mock_scan_engine_instance
        mock_scan_result = Mock()
        mock_scan_result.all_threats = []
        mock_scan_engine_instance.scan_file_sync.return_value = mock_scan_result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import os; os.system(user_input)")
            test_file = f.name

        try:
            # Test all scanners enabled
            result1 = self.runner.invoke(
                cli, ["scan", test_file, "--use-rules", "--use-semgrep", "--use-llm"]
            )
            assert result1.exit_code == 0

            call_args = mock_scan_engine_instance.scan_file_sync.call_args
            assert call_args.kwargs["use_rules"] is True
            assert call_args.kwargs["use_semgrep"] is True
            assert call_args.kwargs["use_llm"] is True

            # Reset mock
            mock_scan_engine_instance.reset_mock()

            # Test only rules enabled
            result2 = self.runner.invoke(
                cli, ["scan", test_file, "--use-rules", "--no-semgrep", "--no-llm"]
            )
            assert result2.exit_code == 0

            call_args = mock_scan_engine_instance.scan_file_sync.call_args
            assert call_args.kwargs["use_rules"] is True
            assert call_args.kwargs["use_semgrep"] is False
            assert call_args.kwargs["use_llm"] is False

            # Reset mock
            mock_scan_engine_instance.reset_mock()

            # Test only semgrep enabled
            result3 = self.runner.invoke(
                cli, ["scan", test_file, "--no-rules", "--use-semgrep", "--no-llm"]
            )
            assert result3.exit_code == 0

            call_args = mock_scan_engine_instance.scan_file_sync.call_args
            assert call_args.kwargs["use_rules"] is False
            assert call_args.kwargs["use_semgrep"] is True
            assert call_args.kwargs["use_llm"] is False

        finally:
            Path(test_file).unlink()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    def test_scan_default_behavior(
        self, mock_scan_engine, mock_threat_engine, mock_cred_manager
    ):
        """Test that rules are enabled by default."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scan_engine.return_value = mock_scan_engine_instance
        mock_scan_result = Mock()
        mock_scan_result.all_threats = []
        mock_scan_engine_instance.scan_file_sync.return_value = mock_scan_result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import os; os.system(user_input)")
            test_file = f.name

        try:
            # Test with no flags (should use defaults)
            result = self.runner.invoke(cli, ["scan", test_file])

            assert result.exit_code == 0
            # Verify scan_file was called with default values (rules=True)
            mock_scan_engine_instance.scan_file_sync.assert_called_once()
            call_args = mock_scan_engine_instance.scan_file_sync.call_args
            assert call_args.kwargs["use_rules"] is True  # Default should be True

        finally:
            Path(test_file).unlink()

    def test_cli_help_includes_rules_flag(self):
        """Test that CLI help includes the --use-rules/--no-rules flag."""
        result = self.runner.invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--use-rules" in result.output
        assert "--no-rules" in result.output
        assert "rules-based scanner" in result.output
