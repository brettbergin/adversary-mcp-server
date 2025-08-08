"""Tests for demo command and other CLI coverage areas."""

from unittest.mock import Mock, patch

from click.testing import CliRunner

from adversary_mcp_server.cli import cli
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestDemoCommand:
    """Test demo command for coverage."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_success(
        self,
        mock_console,
        mock_scanner,
        mock_cred_manager,
    ):
        """Test demo command successful execution."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_scanner_instance = Mock()
        mock_scanner.return_value = mock_scanner_instance

        # Mock threats for demo
        python_threat = ThreatMatch(
            rule_id="python_sql_injection",
            rule_name="Python SQL Injection",
            description="SQL injection in Python",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="demo.py",
            line_number=1,
        )

        js_threat = ThreatMatch(
            rule_id="js_xss",
            rule_name="JavaScript XSS",
            description="XSS in JavaScript",
            category=Category.XSS,
            severity=Severity.HIGH,
            file_path="demo.js",
            line_number=1,
        )

        # Configure scanner to return different threats for different calls
        # Create mock EnhancedScanResult objects
        python_result = Mock()
        python_result.all_threats = [python_threat]

        js_result = Mock()
        js_result.all_threats = [js_threat]

        mock_scanner_instance.scan_code_sync.side_effect = [
            python_result,  # Python demo
            js_result,  # JavaScript demo
        ]

        result = self.runner.invoke(cli, ["demo"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

        # Verify that scan_code_sync was called for both languages
        assert mock_scanner_instance.scan_code_sync.call_count == 2

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_with_scanner_error(
        self, mock_console, mock_scanner, mock_cred_manager
    ):
        """Test demo command with scanner error handling."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_scanner_instance = Mock()
        mock_scanner_instance.scan_code_sync.side_effect = Exception("Scanner error")
        mock_scanner.return_value = mock_scanner_instance

        result = self.runner.invoke(cli, ["demo"])

        # Should handle scanner errors gracefully and still complete
        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_no_threats(
        self,
        mock_console,
        mock_scanner,
        mock_cred_manager,
    ):
        """Test demo command when no threats are found."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_scanner_instance = Mock()
        mock_scanner.return_value = mock_scanner_instance

        # Return empty threats
        empty_result = Mock()
        empty_result.all_threats = []
        mock_scanner_instance.scan_code_sync.return_value = empty_result

        result = self.runner.invoke(cli, ["demo"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

    @patch("adversary_mcp_server.cli.get_credential_manager")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_exploit_generation_error(
        self,
        mock_console,
        mock_scanner,
        mock_cred_manager,
    ):
        """Test demo command with exploit generation error."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_scanner_instance = Mock()
        mock_scanner.return_value = mock_scanner_instance

        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="demo.py",
            line_number=1,
        )
        # Create mock EnhancedScanResult
        threat_result = Mock()
        threat_result.all_threats = [threat]
        mock_scanner_instance.scan_code_sync.return_value = threat_result

        result = self.runner.invoke(cli, ["demo"])

        # Should still succeed even if exploit generation fails
        assert result.exit_code == 0
        mock_console.print.assert_called()


class TestCLIMainFunction:
    """Test CLI main function for coverage."""

    @patch("adversary_mcp_server.cli.cli")
    def test_main_function(self, mock_cli):
        """Test main function."""
        from adversary_mcp_server.cli import main

        main()
        mock_cli.assert_called_once()


class TestCLIVersionCommand:
    """Test CLI version command."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    def test_version_command(self):
        """Test version command."""
        result = self.runner.invoke(cli, ["--version"])

        assert result.exit_code == 0

    def test_help_command(self):
        """Test help command."""
        result = self.runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
