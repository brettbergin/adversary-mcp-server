"""Tests for demo command and other CLI coverage areas."""

from unittest.mock import Mock, patch

from click.testing import CliRunner

from adversary_mcp_server.cli import cli
from adversary_mcp_server.threat_engine import Category, Language, Severity, ThreatMatch


class TestDemoCommand:
    """Test demo command for coverage."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.ExploitGenerator")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_success(
        self,
        mock_console,
        mock_exploit_gen,
        mock_scanner,
        mock_threat_engine,
        mock_cred_manager,
    ):
        """Test demo command successful execution."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

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

        mock_exploit_generator = Mock()
        mock_exploit_generator.generate_exploits.return_value = ["demo_exploit"]
        mock_exploit_gen.return_value = mock_exploit_generator

        result = self.runner.invoke(cli, ["demo"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

        # Verify that scan_code_sync was called for both languages
        assert mock_scanner_instance.scan_code_sync.call_count == 2

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_with_scanner_error(
        self, mock_console, mock_scanner, mock_threat_engine, mock_cred_manager
    ):
        """Test demo command with scanner error handling."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scanner_instance = Mock()
        mock_scanner_instance.scan_code_sync.side_effect = Exception("Scanner error")
        mock_scanner.return_value = mock_scanner_instance

        result = self.runner.invoke(cli, ["demo"])

        # Should handle scanner errors gracefully and still complete
        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.ExploitGenerator")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_no_threats(
        self,
        mock_console,
        mock_exploit_gen,
        mock_scanner,
        mock_threat_engine,
        mock_cred_manager,
    ):
        """Test demo command when no threats are found."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scanner_instance = Mock()
        mock_scanner.return_value = mock_scanner_instance

        # Return empty threats
        empty_result = Mock()
        empty_result.all_threats = []
        mock_scanner_instance.scan_code_sync.return_value = empty_result

        mock_exploit_generator = Mock()
        mock_exploit_gen.return_value = mock_exploit_generator

        result = self.runner.invoke(cli, ["demo"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.ExploitGenerator")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_exploit_generation_error(
        self,
        mock_console,
        mock_exploit_gen,
        mock_scanner,
        mock_threat_engine,
        mock_cred_manager,
    ):
        """Test demo command with exploit generation error."""
        # Setup mocks
        mock_manager = Mock()
        mock_cred_manager.return_value = mock_manager

        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

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

        mock_exploit_generator = Mock()
        mock_exploit_generator.generate_exploits.side_effect = Exception(
            "Exploit generation failed"
        )
        mock_exploit_gen.return_value = mock_exploit_generator

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


class TestCLIRuleDetailsExtended:
    """Extended tests for rule details command."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_rule_details_with_conditions_and_templates(
        self, mock_console, mock_threat_engine
    ):
        """Test rule details with conditions and exploit templates."""
        # Create mock condition
        mock_condition = Mock()
        mock_condition.type = "regex"
        mock_condition.value = "dangerous_pattern"

        # Create mock exploit template
        mock_template = Mock()
        mock_template.description = "Test exploit template"
        mock_template.type = "code_injection"
        mock_template.template = "test_template"

        mock_rule = Mock()
        mock_rule.id = "test_rule"
        mock_rule.name = "Test Rule"
        mock_rule.category = Category.INJECTION
        mock_rule.severity = Severity.HIGH
        mock_rule.languages = [Language.PYTHON, Language.JAVASCRIPT]
        mock_rule.description = "Test description"
        mock_rule.remediation = "Test remediation"
        mock_rule.cwe_id = "CWE-89"
        mock_rule.owasp_category = "A03"
        mock_rule.conditions = [mock_condition]
        mock_rule.exploit_templates = [mock_template]
        mock_rule.references = ["http://example.com", "http://test.com"]
        mock_rule.tags = None

        mock_engine = Mock()
        mock_engine.get_rule_by_id.return_value = mock_rule
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["rule-details", "test_rule"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_rule_details_minimal_rule(self, mock_console, mock_threat_engine):
        """Test rule details with minimal rule information."""
        mock_rule = Mock()
        mock_rule.id = "minimal_rule"
        mock_rule.name = "Minimal Rule"
        mock_rule.category = Category.XSS
        mock_rule.severity = Severity.LOW
        mock_rule.languages = [Language.JAVASCRIPT]
        mock_rule.description = "Minimal description"
        mock_rule.remediation = None
        mock_rule.cwe_id = None
        mock_rule.owasp_category = None
        mock_rule.conditions = None
        mock_rule.exploit_templates = None
        mock_rule.references = None
        mock_rule.tags = None

        mock_engine = Mock()
        mock_engine.get_rule_by_id.return_value = mock_rule
        mock_threat_engine.return_value = mock_engine

        result = self.runner.invoke(cli, ["rule-details", "minimal_rule"])

        assert result.exit_code == 0
        mock_console.print.assert_called()


class TestCLISeverityFiltering:
    """Test severity filtering in CLI commands."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_list_rules_severity_filtering_all_levels(
        self, mock_console, mock_threat_engine
    ):
        """Test list rules command with different severity filters."""
        mock_engine = Mock()
        mock_engine.list_rules.return_value = [
            {
                "id": "low_rule",
                "name": "Low Rule",
                "category": "injection",
                "severity": "low",
                "languages": ["python"],
            },
            {
                "id": "medium_rule",
                "name": "Medium Rule",
                "category": "injection",
                "severity": "medium",
                "languages": ["python"],
            },
            {
                "id": "high_rule",
                "name": "High Rule",
                "category": "injection",
                "severity": "high",
                "languages": ["python"],
            },
            {
                "id": "critical_rule",
                "name": "Critical Rule",
                "category": "injection",
                "severity": "critical",
                "languages": ["python"],
            },
        ]
        mock_threat_engine.return_value = mock_engine

        # Test each severity level
        for severity in ["low", "medium", "high", "critical"]:
            result = self.runner.invoke(cli, ["list-rules", "--severity", severity])

            assert result.exit_code == 0
            mock_console.print.assert_called()


class TestCLILanguageFiltering:
    """Test language filtering in CLI commands."""

    def setup_method(self):
        """Setup test fixtures."""
        self.runner = CliRunner()

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_list_rules_language_filtering(self, mock_console, mock_threat_engine):
        """Test list rules command with language filters."""
        mock_engine = Mock()
        mock_engine.list_rules.return_value = [
            {
                "id": "python_rule",
                "name": "Python Rule",
                "category": "injection",
                "severity": "high",
                "languages": ["python"],
            },
            {
                "id": "js_rule",
                "name": "JavaScript Rule",
                "category": "xss",
                "severity": "medium",
                "languages": ["javascript"],
            },
            {
                "id": "ts_rule",
                "name": "TypeScript Rule",
                "category": "injection",
                "severity": "high",
                "languages": ["typescript"],
            },
            {
                "id": "multi_rule",
                "name": "Multi Language Rule",
                "category": "injection",
                "severity": "critical",
                "languages": ["python", "javascript", "typescript"],
            },
        ]
        mock_threat_engine.return_value = mock_engine

        # Test each language
        for language in ["python", "javascript", "typescript"]:
            result = self.runner.invoke(cli, ["list-rules", "--language", language])

            assert result.exit_code == 0
            mock_console.print.assert_called()


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
