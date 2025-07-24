"""Comprehensive CLI tests focused on improving code coverage."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from adversary_mcp_server.cli import _display_scan_results, _save_results_to_file, cli
from adversary_mcp_server.credential_manager import SecurityConfig
from adversary_mcp_server.threat_engine import Category, Language, Severity, ThreatMatch


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
                "--enable-llm",
            ],
        )

        assert result.exit_code == 0
        mock_manager.store_config.assert_called_once()

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
            mock_instance.store_config.assert_called_once()

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

        # Should still work with default config
        assert result.exit_code == 0

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_configure_command_store_error(self, mock_console, mock_cred_manager):
        """Test configure command with store error."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_manager.store_config.side_effect = Exception("Store failed")
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["configure", "--severity-threshold", "high"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.ThreatEngine")
    def test_status_command_configured(self, mock_threat_engine):
        """Test status command with configured system."""
        with patch("adversary_mcp_server.cli.CredentialManager") as mock_manager:
            mock_instance = mock_manager.return_value
            mock_config = SecurityConfig(
                enable_llm_analysis=True, severity_threshold="high"
            )
            mock_instance.load_config.return_value = mock_config
            mock_instance.has_config.return_value = True

            # Mock ThreatEngine to return some sample rules
            mock_engine = Mock()
            mock_engine.list_rules.return_value = [
                {
                    "id": "test_rule",
                    "name": "Test Rule",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                }
            ]
            mock_threat_engine.return_value = mock_engine

            runner = CliRunner()
            result = runner.invoke(cli, ["status"])

            assert result.exit_code == 0
            # Check for key content that should be in the output
            assert "Server Status" in result.output or "Configuration" in result.output

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_status_command_not_configured(
        self, mock_console, mock_threat_engine, mock_cred_manager
    ):
        """Test status command with unconfigured system."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_manager.has_config.return_value = False
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_engine.list_rules.return_value = []
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["status"])

        assert result.exit_code == 0

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_status_command_error(self, mock_console, mock_cred_manager):
        """Test status command with error."""
        mock_manager = Mock()
        mock_manager.load_config.side_effect = Exception("Load failed")
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["status"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_list_rules_command_basic(self, mock_console, mock_threat_engine):
        """Test list_rules command basic functionality."""
        mock_engine = Mock()
        mock_engine.list_rules.return_value = [
            {
                "id": "sql_injection",
                "name": "SQL Injection",
                "category": "injection",
                "severity": "critical",
                "languages": ["python", "javascript"],
            }
        ]
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["list-rules"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_list_rules_command_with_filters(self, mock_console, mock_threat_engine):
        """Test list_rules command with filters."""
        mock_engine = Mock()
        mock_engine.list_rules.return_value = [
            {
                "id": "sql_injection",
                "name": "SQL Injection",
                "category": "injection",
                "severity": "critical",
                "languages": ["python"],
            },
            {
                "id": "xss",
                "name": "XSS",
                "category": "xss",
                "severity": "high",
                "languages": ["javascript"],
            },
        ]
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(
            cli,
            [
                "list-rules",
                "--category",
                "injection",
                "--severity",
                "high",
                "--language",
                "python",
            ],
        )

        assert result.exit_code == 0

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_list_rules_command_with_output(self, mock_console, mock_threat_engine):
        """Test list_rules command with output file."""
        mock_engine = Mock()
        mock_engine.list_rules.return_value = [
            {
                "id": "test_rule",
                "name": "Test Rule",
                "category": "injection",
                "severity": "medium",
                "languages": ["python"],
            }
        ]
        mock_threat_engine.return_value = mock_engine

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            result = self.runner.invoke(cli, ["list-rules", "--output", output_file])

            assert result.exit_code == 0

            # Verify file was created
            assert Path(output_file).exists()
            with open(output_file) as f:
                data = json.load(f)
            assert len(data) == 1
            assert data[0]["id"] == "test_rule"

        finally:
            os.unlink(output_file)

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_list_rules_command_error(self, mock_console, mock_threat_engine):
        """Test list_rules command error handling."""
        mock_engine = Mock()
        mock_engine.list_rules.side_effect = Exception("Rules failed")
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["list-rules"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_rule_details_command_found(self, mock_console, mock_threat_engine):
        """Test rule_details command for existing rule."""
        mock_rule = Mock()
        mock_rule.id = "test_rule"
        mock_rule.name = "Test Rule"
        mock_rule.category = Category.INJECTION
        mock_rule.severity = Severity.HIGH
        mock_rule.languages = [Language.PYTHON]
        mock_rule.description = "Test description"
        mock_rule.remediation = "Test remediation"
        mock_rule.cwe_id = "CWE-89"
        mock_rule.owasp_category = "A03"
        mock_rule.conditions = []
        mock_rule.exploit_templates = []
        mock_rule.references = ["http://example.com"]
        mock_rule.tags = None

        mock_engine = Mock()
        mock_engine.get_rule_by_id.return_value = mock_rule
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["rule-details", "test_rule"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_rule_details_command_not_found(self, mock_console, mock_threat_engine):
        """Test rule_details command for non-existing rule."""
        mock_engine = Mock()
        mock_engine.get_rule_by_id.return_value = None
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["rule-details", "nonexistent_rule"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_rule_details_command_error(self, mock_console, mock_threat_engine):
        """Test rule_details command error handling."""
        mock_engine = Mock()
        mock_engine.get_rule_by_id.side_effect = Exception("Rule details failed")
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["rule-details", "test_rule"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_reset_command_confirmed(self, mock_console, mock_cred_manager):
        """Test reset command with confirmation."""
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["reset"], input="y\n")

        assert result.exit_code == 0
        mock_manager.delete_config.assert_called_once()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_reset_command_cancelled(self, mock_console, mock_cred_manager):
        """Test reset command cancelled."""
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["reset"], input="n\n")

        assert result.exit_code == 0
        mock_manager.delete_config.assert_not_called()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_reset_command_error(self, mock_console, mock_cred_manager):
        """Test reset command error handling."""
        mock_manager = Mock()
        mock_manager.delete_config.side_effect = Exception("Delete failed")
        mock_cred_manager.return_value = mock_manager

        result = self.runner.invoke(cli, ["reset"], input="y\n")

        assert result.exit_code == 1


class TestCLIScanCommand:
    """Test CLI scan command comprehensively."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_scan_file_basic(
        self,
        mock_console,
        mock_scan_engine,
        mock_threat_engine,
        mock_cred_manager,
    ):
        """Test scanning a single file."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scan_engine.return_value = mock_scan_engine_instance

        # Create a mock EnhancedScanResult
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
            f.write("print('hello')")
            test_file = f.name

        try:
            result = self.runner.invoke(
                cli, ["scan", test_file, "--language", "python", "--severity", "medium"]
            )

            assert result.exit_code == 0
            mock_scan_engine_instance.scan_file_sync.assert_called_once()

        finally:
            os.unlink(test_file)

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_scan_directory_basic(
        self,
        mock_console,
        mock_scanner,
        mock_threat_engine,
        mock_cred_manager,
    ):
        """Test scanning a directory."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scanner.return_value = mock_scan_engine_instance
        mock_scan_engine_instance.scan_directory_sync.return_value = []

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file in the directory
            test_file = Path(temp_dir) / "test.py"
            with open(test_file, "w") as f:
                f.write("print('test')")

            result = self.runner.invoke(
                cli, ["scan", temp_dir, "--recursive", "--severity", "low"]
            )

            assert result.exit_code == 0
            # CLI calls scan_directory_sync for directory scanning
            mock_scan_engine_instance.scan_directory_sync.assert_called_once()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_scan_with_exploits(
        self,
        mock_console,
        mock_scanner,
        mock_threat_engine,
        mock_cred_manager,
    ):
        """Test scanning with exploit generation."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scanner.return_value = mock_scan_engine_instance

        # Create a mock EnhancedScanResult
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
            f.write("print('hello')")
            test_file = f.name

        try:
            result = self.runner.invoke(
                cli, ["scan", test_file, "--include-exploits", "--use-llm"]
            )

            assert result.exit_code == 0
            # Note: CLI scan command doesn't currently implement exploit generation
            # so we don't assert on exploit_generator calls

        finally:
            os.unlink(test_file)

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    @patch("adversary_mcp_server.cli._save_results_to_file")
    def test_scan_with_output_file(
        self,
        mock_save_results,
        mock_console,
        mock_scanner,
        mock_threat_engine,
        mock_cred_manager,
    ):
        """Test scanning with output file."""
        # Setup mocks
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scan_engine_instance = Mock()
        mock_scanner.return_value = mock_scan_engine_instance

        # Create a mock EnhancedScanResult
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
            f.write("print('hello')")
            test_file = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            result = self.runner.invoke(
                cli, ["scan", test_file, "--output", output_file]
            )

            assert result.exit_code == 0
            mock_save_results.assert_called_once()

        finally:
            os.unlink(test_file)
            os.unlink(output_file)

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_scan_command_with_mocked_error(
        self, mock_console, mock_scanner, mock_threat_engine, mock_cred_manager
    ):
        """Test scan command with mocked scanner error."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scanner_instance = Mock()
        mock_scanner_instance.scan_code.side_effect = Exception("Scanner error")
        mock_scanner.return_value = mock_scanner_instance

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('hello')")
            test_file = f.name

        try:
            result = self.runner.invoke(cli, ["scan", test_file])

            # Should handle scanner errors gracefully
            assert result.exit_code == 1

        finally:
            os.unlink(test_file)


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
            assert len(data) == 1
            assert data[0]["rule_id"] == "test_rule"

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
