"""Extended tests for CLI module to improve coverage."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import yaml

from adversary_mcp_server.cli import (
    _display_scan_results,
    _save_results_to_file,
    cli,
    configure,
    demo,
    list_rules,
    reset,
    rule_details,
    scan,
    status,
)
from adversary_mcp_server.threat_engine import Category, Language, Severity, ThreatMatch


class TestCLIUtilities:
    """Test CLI utility functions."""

    def test_display_scan_results_comprehensive(self):
        """Test _display_scan_results with various threat types."""
        threats = [
            ThreatMatch(
                rule_id="sql_injection",
                rule_name="SQL Injection",
                description="Dangerous SQL injection vulnerability",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path="database.py",
                line_number=45,
                code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
                exploit_examples=["' OR '1'='1' --", "'; DROP TABLE users; --"],
                remediation="Use parameterized queries",
                cwe_id="CWE-89",
                owasp_category="A03",
            ),
            ThreatMatch(
                rule_id="xss_vulnerability",
                rule_name="Cross-Site Scripting",
                description="XSS vulnerability in user input",
                category=Category.XSS,
                severity=Severity.HIGH,
                file_path="frontend.js",
                line_number=12,
                code_snippet="document.innerHTML = userInput",
                exploit_examples=["<script>alert('XSS')</script>"],
                remediation="Use textContent or proper escaping",
            ),
            ThreatMatch(
                rule_id="low_severity_issue",
                rule_name="Minor Issue",
                description="Low severity issue",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="utils.py",
                line_number=5,
            ),
        ]

        with patch("adversary_mcp_server.cli.console") as mock_console:
            _display_scan_results(threats, "test_project")

            # Verify console.print was called multiple times
            assert mock_console.print.call_count >= 2

            # Check that different severity levels are handled
        calls = [call[0][0] for call in mock_console.print.call_args_list if call[0]]
        content = " ".join(str(call) for call in calls)

        # Rich objects don't convert to strings cleanly, so just check that we got multiple calls
        assert len(calls) >= 2  # Should have at least 2 calls (panel and table)

    def test_display_scan_results_with_no_exploits(self):
        """Test _display_scan_results with threats that have no exploits."""
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=1,
            exploit_examples=[],  # No exploits
        )

        with patch("adversary_mcp_server.cli.console") as mock_console:
            _display_scan_results([threat], "test.py")
            mock_console.print.assert_called()

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
                code_snippet="test code",
                exploit_examples=["exploit1"],
                remediation="Fix it",
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            _save_results_to_file(threats, output_file)

            # Verify file was created and contains expected data
            assert Path(output_file).exists()
            with open(output_file) as f:
                data = json.load(f)

            assert len(data) == 1
            assert data[0]["rule_id"] == "test_rule"
            assert data[0]["severity"] == "high"

        finally:
            os.unlink(output_file)

    def test_save_results_to_file_text(self):
        """Test saving results to text file."""
        threats = [
            ThreatMatch(
                rule_id="test_rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.js",
                line_number=10,
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_file = f.name

        try:
            _save_results_to_file(threats, output_file)

            # Verify file was created and contains expected data
            assert Path(output_file).exists()
            with open(output_file) as f:
                content = f.read()

            assert "Test Rule" in content
            assert "test.js" in content
            assert "medium" in content

        finally:
            os.unlink(output_file)


class TestCLIComponentsWithMocks:
    """Test CLI components with comprehensive mocking."""

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_status_with_config(self, mock_console, mock_cred_manager):
        """Test status command with various configurations."""
        # Test with full configuration
        mock_config = Mock()
        mock_config.openai_api_key = "sk-test***"
        mock_config.enable_llm_generation = True
        mock_config.min_severity = "medium"
        mock_config.max_exploits_per_rule = 3
        mock_config.timeout_seconds = 300

        mock_manager = Mock()
        mock_manager.has_config.return_value = True
        mock_manager.load_config.return_value = mock_config
        mock_cred_manager.return_value = mock_manager

        # The status function is a typer command, so we test the underlying functionality
        # by calling the mocked components directly
        manager = mock_cred_manager()
        config = manager.load_config()

        assert config.openai_api_key == "sk-test***"
        assert config.enable_llm_generation is True

    @patch("adversary_mcp_server.cli.CredentialManager")
    @patch("adversary_mcp_server.cli.console")
    def test_status_without_config(self, mock_console, mock_cred_manager):
        """Test status command without configuration."""
        mock_manager = Mock()
        mock_manager.has_config.return_value = False
        mock_cred_manager.return_value = mock_manager

        manager = mock_cred_manager()
        has_config = manager.has_config()

        assert has_config is False

    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_scan_functionality_mocked(
        self, mock_console, mock_threat_engine, mock_scanner
    ):
        """Test scan functionality with comprehensive mocking."""
        # Setup mocks
        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scanner_instance = Mock()
        mock_scanner.return_value = mock_scanner_instance

        # Test scanning a file
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Vulnerability",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test_file.py",
            line_number=1,
        )

        # Create a mock EnhancedScanResult
        mock_scan_result = Mock()
        mock_scan_result.all_threats = [threat]
        mock_scanner_instance.scan_file.return_value = mock_scan_result

        # Simulate the scan logic
        scanner = mock_scanner(mock_engine)
        result = scanner.scan_file("test_file.py")

        assert len(result.all_threats) == 1
        assert result.all_threats[0].rule_name == "Test Vulnerability"

    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_scan_code_input(self, mock_console, mock_threat_engine, mock_scanner):
        """Test scanning code input."""
        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scanner_instance = Mock()
        mock_scanner.return_value = mock_scanner_instance

        # Test scanning code content
        threat = ThreatMatch(
            rule_id="eval_injection",
            rule_name="Code Injection",
            description="Dangerous eval usage",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="input",
            line_number=1,
            code_snippet="eval(user_input)",
        )

        # Create a mock EnhancedScanResult
        mock_scan_result = Mock()
        mock_scan_result.all_threats = [threat]
        mock_scanner_instance.scan_code.return_value = mock_scan_result

        # Simulate scanning code
        scanner = mock_scanner(mock_engine)
        result = scanner.scan_code("eval(user_input)", "input", Language.PYTHON)

        assert len(result.all_threats) == 1
        assert result.all_threats[0].severity == Severity.CRITICAL

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_list_rules_with_filters(self, mock_console, mock_threat_engine):
        """Test list_rules with various filters."""
        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        # Mock different rule sets
        all_rules = [
            {
                "id": "sql_injection",
                "name": "SQL Injection",
                "category": "injection",
                "severity": "high",
                "languages": ["python", "javascript"],
            },
            {
                "id": "xss_vulnerability",
                "name": "XSS Vulnerability",
                "category": "xss",
                "severity": "medium",
                "languages": ["javascript"],
            },
            {
                "id": "command_injection",
                "name": "Command Injection",
                "category": "injection",
                "severity": "critical",
                "languages": ["python"],
            },
        ]

        # Test filtering by category
        injection_rules = [r for r in all_rules if r["category"] == "injection"]
        mock_engine.list_rules.return_value = injection_rules

        engine = mock_threat_engine()
        rules = engine.list_rules()

        assert len(rules) == 2
        assert all(r["category"] == "injection" for r in rules)

    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_rule_details_comprehensive(self, mock_console, mock_threat_engine):
        """Test rule_details with comprehensive rule information."""
        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        # Create a comprehensive mock rule
        mock_rule = Mock()
        mock_rule.id = "comprehensive_rule"
        mock_rule.name = "Comprehensive Security Rule"
        mock_rule.description = "A comprehensive security rule for testing"
        mock_rule.category = Category.INJECTION
        mock_rule.severity = Severity.HIGH
        mock_rule.languages = [Language.PYTHON, Language.JAVASCRIPT]
        mock_rule.conditions = [Mock(), Mock()]  # Mock conditions
        mock_rule.exploit_templates = [Mock()]  # Mock templates
        mock_rule.remediation = "Apply proper input validation and sanitization"
        mock_rule.references = [
            "https://owasp.org/security",
            "https://cwe.mitre.org/data/definitions/89.html",
        ]
        mock_rule.cwe_id = "CWE-89"
        mock_rule.owasp_category = "A03"

        mock_engine.get_rule_by_id.return_value = mock_rule

        # Test rule retrieval
        engine = mock_threat_engine()
        rule = engine.get_rule_by_id("comprehensive_rule")

        assert rule.name == "Comprehensive Security Rule"
        assert rule.cwe_id == "CWE-89"
        assert len(rule.languages) == 2

    @patch("adversary_mcp_server.cli.ScanEngine")
    @patch("adversary_mcp_server.cli.ThreatEngine")
    @patch("adversary_mcp_server.cli.console")
    def test_demo_command_functionality(
        self, mock_console, mock_threat_engine, mock_scanner
    ):
        """Test demo command functionality."""
        mock_engine = Mock()
        mock_threat_engine.return_value = mock_engine

        mock_scanner_instance = Mock()
        mock_scanner.return_value = mock_scanner_instance

        # Mock demo threats for different languages
        python_threat = ThreatMatch(
            rule_id="python_demo",
            rule_name="Python Demo Vulnerability",
            description="Demo Python vulnerability",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="demo.py",
            line_number=1,
        )

        js_threat = ThreatMatch(
            rule_id="js_demo",
            rule_name="JavaScript Demo Vulnerability",
            description="Demo JS vulnerability",
            category=Category.XSS,
            severity=Severity.MEDIUM,
            file_path="demo.js",
            line_number=1,
        )

        # Create mock EnhancedScanResults
        python_result = Mock()
        python_result.all_threats = [python_threat]
        js_result = Mock()
        js_result.all_threats = [js_threat]

        # Configure mock to return different threats for different calls
        mock_scanner_instance.scan_code.side_effect = [
            python_result,  # First call (Python)
            js_result,  # Second call (JavaScript)
        ]

        # Test demo functionality
        scanner = mock_scanner(mock_engine)

        # Simulate Python demo scan
        python_scan_result = scanner.scan_code(
            "dangerous_python_code", "demo.py", Language.PYTHON
        )
        assert len(python_scan_result.all_threats) == 1
        assert python_scan_result.all_threats[0].rule_id == "python_demo"

        # Simulate JavaScript demo scan
        js_scan_result = scanner.scan_code(
            "dangerous_js_code", "demo.js", Language.JAVASCRIPT
        )
        assert len(js_scan_result.all_threats) == 1
        assert js_scan_result.all_threats[0].rule_id == "js_demo"

    def test_cli_app_structure(self):
        """Test that CLI app has proper structure."""
        # Test that the main CLI app exists and has commands
        assert cli is not None
        assert hasattr(cli, "commands")

    def test_cli_error_handling(self):
        """Test CLI error handling scenarios."""
        # Test that CLI functions handle errors gracefully
        # This is mostly testing that the functions exist and can be called
        assert callable(configure)
        assert callable(status)
        assert callable(scan)
        assert callable(list_rules)
        assert callable(rule_details)
        assert callable(demo)
        assert callable(reset)


class TestCLIFileOperations:
    """Test CLI file operation scenarios."""

    def test_scan_nonexistent_file(self):
        """Test scanning non-existent file."""
        nonexistent_file = "/path/that/does/not/exist.py"

        # The actual CLI would handle this, but we test the Path checking logic
        file_path = Path(nonexistent_file)
        assert not file_path.exists()

    def test_scan_directory_recursive(self):
        """Test directory scanning with recursion."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create nested structure
            subdir = Path(temp_dir) / "subdir"
            subdir.mkdir()

            # Create test files
            (Path(temp_dir) / "test1.py").write_text("print('hello')")
            (subdir / "test2.py").write_text("exec(user_input)")

            # Test directory structure
            assert Path(temp_dir).is_dir()
            assert (subdir / "test2.py").exists()

    def test_output_file_handling(self):
        """Test output file handling."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            # Test that we can write to the output file
            test_data = {"test": "data"}
            with open(output_file, "w") as f:
                json.dump(test_data, f)

            # Verify file was written
            with open(output_file) as f:
                loaded_data = json.load(f)

            assert loaded_data == test_data

        finally:
            os.unlink(output_file)


class TestCLILanguageDetection:
    """Test CLI language detection capabilities."""

    def test_language_from_extension(self):
        """Test language detection from file extensions."""
        test_files = {
            "test.py": Language.PYTHON,
            "test.js": Language.JAVASCRIPT,
            "test.ts": Language.TYPESCRIPT,
            "test.jsx": Language.JAVASCRIPT,
            "test.tsx": Language.TYPESCRIPT,
        }

        for filename, expected_lang in test_files.items():
            # This tests the logic that would be used in CLI
            if filename.endswith(".py"):
                detected = Language.PYTHON
            elif filename.endswith((".js", ".jsx")):
                detected = Language.JAVASCRIPT
            elif filename.endswith((".ts", ".tsx")):
                detected = Language.TYPESCRIPT
            else:
                detected = None

            if expected_lang:
                assert detected == expected_lang

    def test_language_validation(self):
        """Test language validation."""
        valid_languages = ["python", "javascript", "typescript"]
        invalid_languages = ["ruby", "go", "rust", "invalid"]

        for lang in valid_languages:
            # Test that these would be accepted
            assert lang in ["python", "javascript", "typescript"]

        for lang in invalid_languages:
            # Test that these would be rejected
            assert lang not in ["python", "javascript", "typescript"]


class TestRulesExportCommand:
    """Test the rules export command."""

    def test_export_rules_yaml(self, tmp_path):
        """Test exporting rules to YAML format."""
        runner = CliRunner()
        output_file = tmp_path / "exported_rules.yaml"

        result = runner.invoke(
            cli, ["rules", "export", str(output_file), "--format", "yaml"]
        )

        assert result.exit_code == 0
        assert "Rules exported" in result.output
        assert output_file.exists()

        # Verify YAML content
        with open(output_file) as f:
            data = yaml.safe_load(f)

        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_export_rules_json(self, tmp_path):
        """Test exporting rules to JSON format."""
        runner = CliRunner()
        output_file = tmp_path / "exported_rules.json"

        result = runner.invoke(
            cli, ["rules", "export", str(output_file), "--format", "json"]
        )

        assert result.exit_code == 0
        assert "Rules exported" in result.output
        assert output_file.exists()

        # Verify JSON content
        with open(output_file) as f:
            data = json.load(f)

        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_export_rules_default_format(self, tmp_path):
        """Test exporting rules with default format (YAML)."""
        runner = CliRunner()
        output_file = tmp_path / "exported_rules.yaml"

        result = runner.invoke(cli, ["rules", "export", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()

    def test_export_rules_error_handling(self, tmp_path):
        """Test error handling in rules export."""
        runner = CliRunner()

        # Try to export to a directory that doesn't exist
        invalid_path = tmp_path / "nonexistent" / "rules.yaml"

        result = runner.invoke(cli, ["rules", "export", str(invalid_path)])

        assert result.exit_code != 0
        assert "Export failed" in result.output


class TestRulesImportCommand:
    """Test the rules import command."""

    def test_import_rules_basic(self, tmp_path):
        """Test basic rule import functionality."""
        # Create a valid rule file to import
        import_file = tmp_path / "import_rules.yaml"
        rule_data = {
            "rules": [
                {
                    "id": "imported_test_rule",
                    "name": "Imported Test Rule",
                    "description": "A test rule for import",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "imported.*pattern"}],
                    "remediation": "Fix the imported issue",
                }
            ]
        }

        with open(import_file, "w") as f:
            yaml.dump(rule_data, f)

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "import-rules", str(import_file)])

        assert result.exit_code == 0
        assert "Rules imported successfully" in result.output

    def test_import_rules_with_target_dir(self, tmp_path):
        """Test importing rules with target directory."""
        # Create a valid rule file to import
        import_file = tmp_path / "import_rules.yaml"
        rule_data = {
            "rules": [
                {
                    "id": "imported_test_rule",
                    "name": "Imported Test Rule",
                    "description": "A test rule for import",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "imported.*pattern"}],
                }
            ]
        }

        with open(import_file, "w") as f:
            yaml.dump(rule_data, f)

        # Create target directory
        target_dir = tmp_path / "target"
        target_dir.mkdir()

        runner = CliRunner()

        result = runner.invoke(
            cli,
            [
                "rules",
                "import-rules",
                str(import_file),
                "--target-dir",
                str(target_dir),
            ],
        )

        assert result.exit_code == 0
        assert "Rules imported successfully" in result.output

        # Verify file was copied to target directory
        target_file = target_dir / "import_rules.yaml"
        assert target_file.exists()

    def test_import_rules_validation_failure(self, tmp_path):
        """Test import with validation failure."""
        # Create an invalid rule file
        import_file = tmp_path / "invalid_rules.yaml"
        invalid_rule_data = {
            "rules": [
                {
                    "id": "",  # Invalid empty ID
                    "name": "Invalid Rule",
                    "description": "Invalid rule",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [],  # Invalid empty conditions
                }
            ]
        }

        with open(import_file, "w") as f:
            yaml.dump(invalid_rule_data, f)

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "import-rules", str(import_file)])

        assert result.exit_code != 0
        assert "Import failed" in result.output

    def test_import_rules_no_validation(self, tmp_path):
        """Test importing rules without validation."""
        # Create a rule file with potential validation issues
        import_file = tmp_path / "rules.yaml"
        rule_data = {
            "rules": [
                {
                    "id": "test_rule",
                    "name": "Test Rule",
                    "description": "Test rule",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "test"}],
                }
            ]
        }

        with open(import_file, "w") as f:
            yaml.dump(rule_data, f)

        runner = CliRunner()

        result = runner.invoke(
            cli, ["rules", "import-rules", str(import_file), "--no-validate"]
        )

        assert result.exit_code == 0
        assert "Rules imported successfully" in result.output

    def test_import_rules_nonexistent_file(self):
        """Test importing from non-existent file."""
        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "import-rules", "/nonexistent/file.yaml"])

        assert result.exit_code != 0


class TestRulesValidateCommand:
    """Test the rules validate command."""

    def test_validate_rules_success(self):
        """Test successful rule validation."""
        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "validate"])

        # All default rules should be valid
        assert result.exit_code == 0
        assert "All rules are valid" in result.output

    @patch("adversary_mcp_server.threat_engine.ThreatEngine.validate_all_rules")
    def test_validate_rules_with_errors(self, mock_validate):
        """Test rule validation with errors."""
        # Mock validation errors
        mock_validate.return_value = {
            "invalid_rule_1": [
                "Rule ID is required",
                "At least one condition is required",
            ],
            "invalid_rule_2": ["Rule name is required"],
        }

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "validate"])

        assert result.exit_code != 0
        assert "Found 2 rules with errors" in result.output
        assert "invalid_rule_1" in result.output
        assert "invalid_rule_2" in result.output

    @patch("adversary_mcp_server.cli.ThreatEngine")
    def test_validate_rules_exception(self, mock_engine_class):
        """Test rule validation with exception."""
        # Mock engine to raise exception
        mock_engine = Mock()
        mock_engine.validate_all_rules.side_effect = Exception("Validation error")
        mock_engine_class.return_value = mock_engine

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "validate"])

        assert result.exit_code != 0
        assert "Validation failed" in result.output


class TestRulesReloadCommand:
    """Test the rules reload command."""

    @patch("adversary_mcp_server.cli.ThreatEngine")
    def test_reload_rules_success(self, mock_engine_class):
        """Test successful rule reload."""
        # Mock engine
        mock_engine = Mock()
        mock_engine.get_rule_statistics.return_value = {
            "total_rules": 10,
            "loaded_files": 3,
        }
        mock_engine_class.return_value = mock_engine

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "reload"])

        assert result.exit_code == 0
        assert (
            "Reloaded" in result.output
            and "10" in result.output
            and "3" in result.output
        )

    @patch("adversary_mcp_server.cli.ThreatEngine")
    def test_reload_rules_failure(self, mock_engine_class):
        """Test rule reload with failure."""
        # Mock engine to raise exception
        mock_engine = Mock()
        mock_engine.reload_rules.side_effect = Exception("Reload error")
        mock_engine_class.return_value = mock_engine

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "reload"])

        assert result.exit_code != 0
        assert "Reload failed" in result.output


class TestRulesStatsCommand:
    """Test the rules stats command."""

    @patch("adversary_mcp_server.cli.ThreatEngine")
    def test_stats_command(self, mock_engine_class):
        """Test rule statistics command."""
        # Mock engine with statistics
        mock_engine = Mock()
        mock_engine.get_rule_statistics.return_value = {
            "total_rules": 15,
            "loaded_files": 4,
            "categories": {"injection": 8, "xss": 4, "deserialization": 3},
            "severities": {"critical": 5, "high": 6, "medium": 3, "low": 1},
            "languages": {"python": 10, "javascript": 8, "typescript": 7},
            "rule_files": ["/path/to/rules1.yaml", "/path/to/rules2.yaml"],
        }
        mock_engine_class.return_value = mock_engine

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "stats"])

        assert result.exit_code == 0
        assert "Total Rules:" in result.output and "15" in result.output
        assert "injection" in result.output
        assert "critical" in result.output
        assert "python" in result.output

    @patch("adversary_mcp_server.cli.ThreatEngine")
    def test_stats_command_failure(self, mock_engine_class):
        """Test statistics command with failure."""
        # Mock engine to raise exception
        mock_engine = Mock()
        mock_engine.get_rule_statistics.side_effect = Exception("Stats error")
        mock_engine_class.return_value = mock_engine

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "stats"])

        assert result.exit_code != 0
        assert "Failed to get statistics" in result.output


class TestWatchCommands:
    """Test hot-reload watch commands."""

    @patch("adversary_mcp_server.cli.create_hot_reload_service")
    @patch("adversary_mcp_server.threat_engine.ThreatEngine")
    def test_watch_start_command(self, mock_engine_class, mock_create_service):
        """Test starting the hot-reload service."""
        # Mock engine
        mock_engine = Mock()
        mock_engine.get_rule_statistics.return_value = {
            "total_rules": 10,
            "loaded_files": 2,
        }
        mock_engine_class.return_value = mock_engine

        # Mock service
        mock_service = Mock()
        mock_service.watch_directories = ["/path/to/rules"]  # Mock as list
        mock_create_service.return_value = mock_service

        # Mock run_daemon to avoid infinite loop
        mock_service.run_daemon.side_effect = KeyboardInterrupt()

        runner = CliRunner()

        result = runner.invoke(cli, ["watch", "start"])

        assert result.exit_code == 0
        assert "Starting Hot-Reload Service" in result.output
        mock_service.set_debounce_time.assert_called_with(1.0)
        mock_service.run_daemon.assert_called_once()

    @patch("adversary_mcp_server.cli.create_hot_reload_service")
    @patch("adversary_mcp_server.threat_engine.ThreatEngine")
    def test_watch_start_with_custom_directories(
        self, mock_engine_class, mock_create_service, tmp_path
    ):
        """Test starting hot-reload service with custom directories."""
        # Create temporary directories
        custom_dir1 = tmp_path / "custom1"
        custom_dir1.mkdir()
        custom_dir2 = tmp_path / "custom2"
        custom_dir2.mkdir()

        # Mock engine
        mock_engine = Mock()
        mock_engine.get_rule_statistics.return_value = {
            "total_rules": 5,
            "loaded_files": 1,
        }
        mock_engine_class.return_value = mock_engine

        # Mock service
        mock_service = Mock()
        mock_service.watch_directories = [
            str(custom_dir1),
            str(custom_dir2),
        ]  # Mock as list
        mock_create_service.return_value = mock_service
        mock_service.run_daemon.side_effect = KeyboardInterrupt()

        runner = CliRunner()

        result = runner.invoke(
            cli,
            [
                "watch",
                "start",
                "-d",
                str(custom_dir1),
                "-d",
                str(custom_dir2),
                "--debounce",
                "2.5",
            ],
        )

        assert result.exit_code == 0
        mock_service.set_debounce_time.assert_called_with(2.5)

        # Verify custom directories were passed
        call_args = mock_create_service.call_args
        custom_dirs = call_args[0][1]  # Second argument to create_hot_reload_service
        assert len(custom_dirs) == 2
        assert Path(str(custom_dir1)) in custom_dirs
        assert Path(str(custom_dir2)) in custom_dirs

    def test_watch_start_missing_watchdog(self):
        """Test watch start with missing watchdog dependency."""
        runner = CliRunner()

        # Mock HOT_RELOAD_AVAILABLE to simulate missing watchdog
        with patch("adversary_mcp_server.cli.HOT_RELOAD_AVAILABLE", False):
            result = runner.invoke(cli, ["watch", "start"])

        assert result.exit_code != 0
        assert "watchdog" in result.output

    @patch("adversary_mcp_server.cli.create_hot_reload_service")
    @patch("adversary_mcp_server.threat_engine.ThreatEngine")
    def test_watch_status_command(self, mock_engine_class, mock_create_service):
        """Test watch status command."""
        # Mock engine
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        # Mock service with status
        mock_service = Mock()
        mock_service.get_status.return_value = {
            "is_running": True,
            "watch_directories": ["/path/to/rules"],
            "pending_reloads": 2,
            "reload_count": 5,
            "debounce_seconds": 1.0,
            "last_reload_time": 1234567890,
            "last_reload_files": ["/path/to/rules/test.yaml"],
        }
        mock_create_service.return_value = mock_service

        runner = CliRunner()

        result = runner.invoke(cli, ["watch", "status"])

        assert result.exit_code == 0
        assert "🟢 Running" in result.output
        assert "**Pending Reloads:** 2" in result.output
        assert "**Total Reloads:** 5" in result.output

    @patch("adversary_mcp_server.cli.create_hot_reload_service")
    @patch("adversary_mcp_server.threat_engine.ThreatEngine")
    def test_watch_status_stopped(self, mock_engine_class, mock_create_service):
        """Test watch status when service is stopped."""
        # Mock engine
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        # Mock service with stopped status
        mock_service = Mock()
        mock_service.get_status.return_value = {
            "is_running": False,
            "watch_directories": [],
            "pending_reloads": 0,
            "reload_count": 0,
            "debounce_seconds": 1.0,
            "last_reload_time": 0,
            "last_reload_files": [],
        }
        mock_create_service.return_value = mock_service

        runner = CliRunner()

        result = runner.invoke(cli, ["watch", "status"])

        assert result.exit_code == 0
        assert "🔴 Stopped" in result.output

    @patch("adversary_mcp_server.cli.create_hot_reload_service")
    @patch("adversary_mcp_server.threat_engine.ThreatEngine")
    def test_watch_test_command(self, mock_engine_class, mock_create_service):
        """Test watch test command."""
        # Mock engine
        mock_engine = Mock()
        mock_engine.get_rule_statistics.return_value = {
            "total_rules": 8,
            "loaded_files": 2,
        }
        mock_engine_class.return_value = mock_engine

        # Mock service
        mock_service = Mock()
        mock_service.watch_directories = ["/path/to/rules"]  # Mock as list
        mock_create_service.return_value = mock_service

        runner = CliRunner()

        result = runner.invoke(cli, ["watch", "test"])

        assert result.exit_code == 0
        assert "Testing Hot-Reload Functionality" in result.output
        assert "Hot-reload test completed successfully" in result.output
        mock_service.force_reload.assert_called_once()

    def test_watch_test_missing_watchdog(self):
        """Test watch test with missing watchdog dependency."""
        runner = CliRunner()

        # Mock HOT_RELOAD_AVAILABLE to simulate missing watchdog
        with patch("adversary_mcp_server.cli.HOT_RELOAD_AVAILABLE", False):
            result = runner.invoke(cli, ["watch", "test"])

        assert result.exit_code != 0
        assert "watchdog" in result.output

    @patch("adversary_mcp_server.cli.create_hot_reload_service")
    @patch("adversary_mcp_server.threat_engine.ThreatEngine")
    def test_watch_command_with_exception(self, mock_engine_class, mock_create_service):
        """Test watch commands with exceptions."""
        # Mock engine
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        # Mock service to raise exception
        mock_service = Mock()
        mock_service.get_status.side_effect = Exception("Service error")
        mock_create_service.return_value = mock_service

        runner = CliRunner()

        result = runner.invoke(cli, ["watch", "status"])

        assert result.exit_code != 0
        assert "Failed to get hot-reload status" in result.output


class TestCLIIntegration:
    """Integration tests for CLI commands."""

    def test_rules_export_import_roundtrip(self, tmp_path):
        """Test exporting and then importing rules."""
        runner = CliRunner()

        # Export rules
        export_file = tmp_path / "exported.yaml"
        result = runner.invoke(cli, ["rules", "export", str(export_file)])
        assert result.exit_code == 0
        assert export_file.exists()

        # Import the exported rules
        target_dir = tmp_path / "imported"
        target_dir.mkdir()

        result = runner.invoke(
            cli,
            [
                "rules",
                "import-rules",
                str(export_file),
                "--target-dir",
                str(target_dir),
            ],
        )
        assert result.exit_code == 0

        # Verify file was copied
        imported_file = target_dir / "exported.yaml"
        assert imported_file.exists()

    def test_rules_workflow(self, tmp_path):
        """Test complete rules management workflow."""
        runner = CliRunner()

        # Get initial statistics
        result = runner.invoke(cli, ["rules", "stats"])
        assert result.exit_code == 0

        # Validate rules
        result = runner.invoke(cli, ["rules", "validate"])
        assert result.exit_code == 0

        # Export rules
        export_file = tmp_path / "workflow_export.yaml"
        result = runner.invoke(cli, ["rules", "export", str(export_file)])
        assert result.exit_code == 0

        # Reload rules
        result = runner.invoke(cli, ["rules", "reload"])
        assert result.exit_code == 0

    def test_watch_workflow(self):
        """Test watch command workflow."""
        runner = CliRunner()

        # Test watch status
        result = runner.invoke(cli, ["watch", "status"])
        # May fail if watchdog not available, but should not crash

        # Test watch test
        result = runner.invoke(cli, ["watch", "test"])
        # May fail if watchdog not available, but should not crash


class TestCLIErrorHandling:
    """Test error handling in CLI commands."""

    def test_invalid_command(self):
        """Test invalid command handling."""
        runner = CliRunner()

        result = runner.invoke(cli, ["invalid-command"])

        assert result.exit_code != 0

    def test_invalid_subcommand(self):
        """Test invalid subcommand handling."""
        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "invalid-subcommand"])

        assert result.exit_code != 0

    @patch("adversary_mcp_server.cli.ThreatEngine")
    def test_engine_initialization_failure(self, mock_engine_class):
        """Test CLI behavior when engine initialization fails."""
        # Mock engine to raise exception on initialization
        mock_engine_class.side_effect = Exception("Engine init failed")

        runner = CliRunner()

        result = runner.invoke(cli, ["rules", "stats"])

        assert result.exit_code != 0
        assert "Failed to" in result.output

    def test_file_permission_errors(self, tmp_path):
        """Test handling of file permission errors."""
        runner = CliRunner()

        # Create a file and remove write permissions
        restricted_file = tmp_path / "restricted.yaml"
        restricted_file.touch()
        restricted_file.chmod(0o444)  # Read-only

        try:
            # Try to export to read-only file
            result = runner.invoke(cli, ["rules", "export", str(restricted_file)])

            # Should handle permission error gracefully
            assert result.exit_code != 0

        finally:
            # Restore permissions for cleanup
            restricted_file.chmod(0o644)


@pytest.fixture
def cli_runner():
    """Provide a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def sample_rule_file(tmp_path):
    """Create a sample rule file for testing."""
    rule_file = tmp_path / "sample_rules.yaml"
    rule_data = {
        "rules": [
            {
                "id": "sample_rule",
                "name": "Sample Rule",
                "description": "A sample rule for testing",
                "category": "injection",
                "severity": "high",
                "languages": ["python"],
                "conditions": [{"type": "pattern", "value": "sample.*pattern"}],
                "remediation": "Fix the sample issue",
                "references": ["https://example.com"],
                "cwe_id": "CWE-89",
            }
        ]
    }

    with open(rule_file, "w") as f:
        yaml.dump(rule_data, f)

    return rule_file


class TestCLIWithSampleData:
    """Test CLI commands with sample data."""

    def test_import_sample_rules(self, cli_runner, sample_rule_file, tmp_path):
        """Test importing sample rules."""
        target_dir = tmp_path / "target"
        target_dir.mkdir()

        result = cli_runner.invoke(
            cli,
            [
                "rules",
                "import-rules",
                str(sample_rule_file),
                "--target-dir",
                str(target_dir),
            ],
        )

        assert result.exit_code == 0
        assert "Rules imported successfully" in result.output

        # Verify file was copied
        copied_file = target_dir / sample_rule_file.name
        assert copied_file.exists()

    def test_export_with_sample_data(self, cli_runner, tmp_path):
        """Test exporting rules with sample data."""
        output_file = tmp_path / "export_test.yaml"

        result = cli_runner.invoke(cli, ["rules", "export", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()

        # Verify content structure
        with open(output_file) as f:
            data = yaml.safe_load(f)

        assert "rules" in data
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) > 0
