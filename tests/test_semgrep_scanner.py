"""Tests for SemgrepScanner module."""

import json
import os
import subprocess
import sys
from unittest.mock import MagicMock, mock_open, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.semgrep_scanner import SemgrepError, SemgrepScanner
from adversary_mcp_server.threat_engine import (
    Category,
    Language,
    Severity,
    ThreatEngine,
    ThreatMatch,
)


class TestSemgrepScanner:
    """Test SemgrepScanner class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.threat_engine = ThreatEngine()
        self.scanner = SemgrepScanner(self.threat_engine)

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_check_semgrep_available_success(self, mock_run):
        """Test successful Semgrep availability check."""
        mock_run.return_value.returncode = 0

        scanner = SemgrepScanner(self.threat_engine)
        assert scanner.is_available() is True

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_check_semgrep_available_failure(self, mock_run):
        """Test failed Semgrep availability check."""
        mock_run.side_effect = FileNotFoundError()

        scanner = SemgrepScanner(self.threat_engine)
        assert scanner.is_available() is False

    def test_get_semgrep_env_with_token(self):
        """Test environment setup with Semgrep token."""
        with patch.dict(os.environ, {"SEMGREP_APP_TOKEN": "test_token"}):
            env = self.scanner._get_semgrep_env()
            assert "SEMGREP_APP_TOKEN" in env
            assert env["SEMGREP_APP_TOKEN"] == "test_token"

    def test_get_semgrep_env_without_token(self):
        """Test environment setup without Semgrep token."""
        with patch.dict(os.environ, {}, clear=True):
            env = self.scanner._get_semgrep_env()
            assert "SEMGREP_APP_TOKEN" not in env

    def test_map_semgrep_severity(self):
        """Test Semgrep severity mapping."""
        assert self.scanner._map_semgrep_severity("error") == Severity.CRITICAL
        assert self.scanner._map_semgrep_severity("critical") == Severity.CRITICAL
        assert self.scanner._map_semgrep_severity("warning") == Severity.HIGH
        assert self.scanner._map_semgrep_severity("info") == Severity.MEDIUM
        assert self.scanner._map_semgrep_severity("unknown") == Severity.LOW

    def test_map_semgrep_category(self):
        """Test Semgrep category mapping."""
        # Test SQL injection
        assert (
            self.scanner._map_semgrep_category("sql-injection", "SQL issue")
            == Category.INJECTION
        )
        assert (
            self.scanner._map_semgrep_category("sqli-test", "SQL problem")
            == Category.INJECTION
        )

        # Test XSS
        assert (
            self.scanner._map_semgrep_category("xss-vulnerability", "XSS issue")
            == Category.XSS
        )
        assert (
            self.scanner._map_semgrep_category("cross-site-scripting", "XSS")
            == Category.XSS
        )

        # Test auth
        assert (
            self.scanner._map_semgrep_category("auth-bypass", "Auth issue")
            == Category.AUTHENTICATION
        )
        assert (
            self.scanner._map_semgrep_category("jwt-vulnerability", "JWT")
            == Category.AUTHENTICATION
        )

        # Test crypto
        assert (
            self.scanner._map_semgrep_category("crypto-weakness", "Crypto")
            == Category.CRYPTOGRAPHY
        )
        assert (
            self.scanner._map_semgrep_category("weak-hash", "Hash")
            == Category.CRYPTOGRAPHY
        )

        # Test default
        assert (
            self.scanner._map_semgrep_category("unknown-rule", "Unknown")
            == Category.VALIDATION
        )

    def test_convert_semgrep_finding_to_threat(self):
        """Test conversion of Semgrep finding to ThreatMatch."""
        semgrep_finding = {
            "check_id": "python.lang.security.audit.dangerous-eval.dangerous-eval",
            "message": "Found 'eval' which can execute arbitrary code",
            "metadata": {
                "severity": "error",
                "cwe": ["CWE-95"],
                "owasp": "A03:2021",
                "references": ["https://example.com/eval-security"],
            },
            "start": {"line": 15},
            "end": {"line": 15},
            "extra": {"lines": "eval(user_input)"},
        }

        threat = self.scanner._convert_semgrep_finding_to_threat(
            semgrep_finding, "test.py"
        )

        assert (
            threat.rule_id
            == "semgrep-python.lang.security.audit.dangerous-eval.dangerous-eval"
        )
        assert (
            threat.rule_name
            == "Semgrep: python.lang.security.audit.dangerous-eval.dangerous-eval"
        )
        assert threat.description == "Found 'eval' which can execute arbitrary code"
        assert threat.severity == Severity.CRITICAL
        assert threat.file_path == "test.py"
        assert threat.line_number == 15
        assert threat.code_snippet == "eval(user_input)"
        assert threat.confidence == 0.9
        assert threat.cwe_id == "CWE-95"
        assert threat.owasp_category == "A03:2021"
        assert threat.references == ["https://example.com/eval-security"]

    def test_get_file_extension(self):
        """Test file extension mapping."""
        assert self.scanner._get_file_extension(Language.PYTHON) == ".py"
        assert self.scanner._get_file_extension(Language.JAVASCRIPT) == ".js"
        assert self.scanner._get_file_extension(Language.TYPESCRIPT) == ".ts"

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    @patch("builtins.open", create=True)
    @patch("os.unlink")
    def test_scan_code_success(self, mock_unlink, mock_open, mock_run):
        """Test successful code scanning with Semgrep."""
        # Mock Semgrep availability
        with patch.object(self.scanner, "_semgrep_available", True):
            # Mock Semgrep output
            semgrep_output = {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.dangerous-eval.dangerous-eval",
                        "message": "Found 'eval' which can execute arbitrary code",
                        "metadata": {"severity": "error"},
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {"lines": "eval(user_input)"},
                    }
                ]
            }

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(semgrep_output)
            mock_run.return_value.stderr = ""

            # Mock file operations
            mock_file = MagicMock()
            mock_file.name = "/tmp/test.py"
            mock_open.return_value.__enter__.return_value = mock_file

            source_code = "eval(user_input)"
            threats = self.scanner.scan_code(source_code, "test.py", Language.PYTHON)

            assert len(threats) == 1
            assert (
                threats[0].rule_id
                == "semgrep-python.lang.security.audit.dangerous-eval.dangerous-eval"
            )
            assert threats[0].severity == Severity.CRITICAL

            # Verify Semgrep was called correctly
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "semgrep" in args
            assert "--json" in args
            assert "--config" in args
            assert "auto" in args

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_scan_code_unavailable(self, mock_run):
        """Test code scanning when Semgrep is unavailable."""
        with patch.object(self.scanner, "_semgrep_available", False):
            source_code = "eval(user_input)"
            threats = self.scanner.scan_code(source_code, "test.py", Language.PYTHON)

            assert threats == []
            mock_run.assert_not_called()

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    @patch("builtins.open", create=True)
    @patch("os.unlink")
    def test_scan_code_timeout(self, mock_unlink, mock_open, mock_run):
        """Test code scanning with timeout."""
        with patch.object(self.scanner, "_semgrep_available", True):
            mock_run.side_effect = subprocess.TimeoutExpired("semgrep", 60)

            # Mock file operations
            mock_file = MagicMock()
            mock_file.name = "/tmp/test.py"
            mock_open.return_value.__enter__.return_value = mock_file

            source_code = "eval(user_input)"

            with pytest.raises(SemgrepError, match="timed out"):
                self.scanner.scan_code(
                    source_code, "test.py", Language.PYTHON, timeout=60
                )

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    @patch("builtins.open", create=True)
    @patch("os.unlink")
    def test_scan_code_invalid_json(self, mock_unlink, mock_open, mock_run):
        """Test code scanning with invalid JSON output."""
        with patch.object(self.scanner, "_semgrep_available", True):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "invalid json"
            mock_run.return_value.stderr = ""

            # Mock file operations
            mock_file = MagicMock()
            mock_file.name = "/tmp/test.py"
            mock_open.return_value.__enter__.return_value = mock_file

            source_code = "eval(user_input)"
            threats = self.scanner.scan_code(source_code, "test.py", Language.PYTHON)

            assert threats == []

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    @patch("builtins.open", create=True)
    @patch("os.unlink")
    def test_scan_code_custom_config(self, mock_unlink, mock_open, mock_run):
        """Test code scanning with custom config."""
        with patch.object(self.scanner, "_semgrep_available", True):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = '{"results": []}'
            mock_run.return_value.stderr = ""

            # Mock file operations
            mock_file = MagicMock()
            mock_file.name = "/tmp/test.py"
            mock_open.return_value.__enter__.return_value = mock_file

            source_code = "eval(user_input)"
            threats = self.scanner.scan_code(
                source_code, "test.py", Language.PYTHON, config="custom-config.yml"
            )

            assert threats == []

            # Verify custom config was used
            args = mock_run.call_args[0][0]
            assert "custom-config.yml" in args

    @patch("builtins.open", create=True)
    def test_scan_file_success(self, mock_open):
        """Test successful file scanning."""
        mock_file_content = "eval(user_input)"
        mock_open.return_value.__enter__.return_value.read.return_value = (
            mock_file_content
        )

        with patch.object(self.scanner, "scan_code") as mock_scan_code:
            mock_scan_code.return_value = [
                ThreatMatch(
                    rule_id="test_rule",
                    rule_name="Test Rule",
                    description="Test threat",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path="test.py",
                    line_number=1,
                )
            ]

            threats = self.scanner.scan_file("test.py", Language.PYTHON)

            assert len(threats) == 1
            mock_scan_code.assert_called_once_with(
                source_code=mock_file_content,
                file_path="test.py",
                language=Language.PYTHON,
                config=None,
                rules=None,
                timeout=60,
                severity_threshold=None,
            )

    def test_scan_file_unavailable(self):
        """Test file scanning when Semgrep is unavailable."""
        with patch.object(self.scanner, "_semgrep_available", False):
            threats = self.scanner.scan_file("test.py", Language.PYTHON)
            assert threats == []

    @patch("builtins.open", side_effect=FileNotFoundError("File not found"))
    def test_scan_file_not_found(self, mock_open):
        """Test file scanning with missing file."""
        with pytest.raises(SemgrepError, match="Failed to scan file"):
            self.scanner.scan_file("nonexistent.py", Language.PYTHON)


class TestSemgrepScannerIntegration:
    """Integration tests for SemgrepScanner."""

    def setup_method(self):
        """Set up test fixtures."""
        self.threat_engine = ThreatEngine()
        self.scanner = SemgrepScanner(self.threat_engine)

    def test_python_code_with_eval(self):
        """Test scanning Python code with eval vulnerability."""
        python_code = """
def dangerous_function(user_input):
    result = eval(user_input)  # This should be detected
    return result
"""

        with patch.object(self.scanner, "_semgrep_available", True):
            with patch(
                "adversary_mcp_server.semgrep_scanner.subprocess.run"
            ) as mock_run:
                # Mock realistic Semgrep output for eval detection
                semgrep_output = {
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.dangerous-eval.dangerous-eval",
                            "message": "Found 'eval' which can execute arbitrary code",
                            "metadata": {
                                "severity": "error",
                                "cwe": ["CWE-95"],
                                "owasp": "A03:2021",
                            },
                            "start": {"line": 3},
                            "end": {"line": 3},
                            "extra": {
                                "lines": "    result = eval(user_input)  # This should be detected"
                            },
                        }
                    ]
                }

                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = json.dumps(semgrep_output)
                mock_run.return_value.stderr = ""

                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_file.name = "/tmp/test.py"
                    mock_open.return_value.__enter__.return_value = mock_file

                    with patch("os.unlink"):
                        threats = self.scanner.scan_code(
                            python_code, "test.py", Language.PYTHON
                        )

                assert len(threats) == 1
                threat = threats[0]
                assert "eval" in threat.description.lower()
                assert threat.severity == Severity.CRITICAL
                assert threat.category == Category.RCE  # eval maps to RCE
                assert threat.confidence == 0.9

    def test_javascript_code_with_xss(self):
        """Test scanning JavaScript code with XSS vulnerability."""
        js_code = """
function displayUser(userInput) {
    document.innerHTML = userInput;  // This should be detected as XSS
}
"""

        with patch.object(self.scanner, "_semgrep_available", True):
            with patch(
                "adversary_mcp_server.semgrep_scanner.subprocess.run"
            ) as mock_run:
                # Mock realistic Semgrep output for XSS detection
                semgrep_output = {
                    "results": [
                        {
                            "check_id": "javascript.lang.security.audit.xss.innerHTML-xss",
                            "message": "Detected XSS vulnerability via innerHTML",
                            "metadata": {
                                "severity": "warning",
                                "cwe": ["CWE-79"],
                                "owasp": "A07:2021",
                            },
                            "start": {"line": 2},
                            "end": {"line": 2},
                            "extra": {"lines": "    document.innerHTML = userInput;"},
                        }
                    ]
                }

                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = json.dumps(semgrep_output)
                mock_run.return_value.stderr = ""

                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_file.name = "/tmp/test.js"
                    mock_open.return_value.__enter__.return_value = mock_file

                    with patch("os.unlink"):
                        threats = self.scanner.scan_code(
                            js_code, "test.js", Language.JAVASCRIPT
                        )

                assert len(threats) == 1
                threat = threats[0]
                assert "xss" in threat.description.lower()
                assert threat.severity == Severity.HIGH
                assert threat.category == Category.XSS

    def test_no_vulnerabilities_found(self):
        """Test scanning code with no vulnerabilities."""
        safe_code = """
def safe_function():
    return "Hello, World!"
"""

        with patch.object(self.scanner, "_semgrep_available", True):
            with patch(
                "adversary_mcp_server.semgrep_scanner.subprocess.run"
            ) as mock_run:
                # Mock empty Semgrep output
                semgrep_output = {"results": []}

                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = json.dumps(semgrep_output)
                mock_run.return_value.stderr = ""

                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_file.name = "/tmp/test.py"
                    mock_open.return_value.__enter__.return_value = mock_file

                    with patch("os.unlink"):
                        threats = self.scanner.scan_code(
                            safe_code, "test.py", Language.PYTHON
                        )

                assert len(threats) == 0

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_severity_filtering_with_threshold(self, mock_run):
        """Test severity filtering with severity threshold."""
        # Mock Semgrep output with mixed severities
        semgrep_output = {
            "results": [
                {
                    "check_id": "test.high.severity",
                    "message": "High severity issue",
                    "path": "test.py",
                    "start": {"line": 1},
                    "metadata": {"severity": "warning"},  # Maps to HIGH
                },
                {
                    "check_id": "test.medium.severity", 
                    "message": "Medium severity issue",
                    "path": "test.py",
                    "start": {"line": 2},
                    "metadata": {"severity": "info"},  # Maps to MEDIUM
                },
                {
                    "check_id": "test.critical.severity",
                    "message": "Critical severity issue", 
                    "path": "test.py",
                    "start": {"line": 3},
                    "metadata": {"severity": "error"},  # Maps to CRITICAL
                }
            ]
        }

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(semgrep_output)
        mock_run.return_value.stderr = ""

        # Test with HIGH threshold - should only get HIGH and CRITICAL
        with patch("tempfile.NamedTemporaryFile"):
            with patch("os.unlink"):
                threats = self.scanner.scan_code(
                    "test code", "test.py", Language.PYTHON, severity_threshold=Severity.HIGH
                )
                
                assert len(threats) == 2
                severities = [t.severity for t in threats]
                assert Severity.HIGH in severities
                assert Severity.CRITICAL in severities
                assert Severity.MEDIUM not in severities

    def test_filter_by_severity_method(self):
        """Test the _filter_by_severity method directly."""
        # Create test threats with different severities
        threats = [
            ThreatMatch(
                rule_id="rule1", rule_name="Rule 1", description="Test",
                category=Category.INJECTION, severity=Severity.LOW,
                file_path="test.py", line_number=1
            ),
            ThreatMatch(
                rule_id="rule2", rule_name="Rule 2", description="Test",
                category=Category.INJECTION, severity=Severity.MEDIUM,
                file_path="test.py", line_number=2
            ),
            ThreatMatch(
                rule_id="rule3", rule_name="Rule 3", description="Test",
                category=Category.INJECTION, severity=Severity.HIGH,
                file_path="test.py", line_number=3
            ),
            ThreatMatch(
                rule_id="rule4", rule_name="Rule 4", description="Test", 
                category=Category.INJECTION, severity=Severity.CRITICAL,
                file_path="test.py", line_number=4
            )
        ]

        # Filter with MEDIUM threshold
        filtered = self.scanner._filter_by_severity(threats, Severity.MEDIUM)
        assert len(filtered) == 3
        severities = [t.severity for t in filtered]
        assert Severity.LOW not in severities
        assert Severity.MEDIUM in severities
        assert Severity.HIGH in severities
        assert Severity.CRITICAL in severities

        # Filter with HIGH threshold
        filtered = self.scanner._filter_by_severity(threats, Severity.HIGH)
        assert len(filtered) == 2
        severities = [t.severity for t in filtered]
        assert Severity.LOW not in severities
        assert Severity.MEDIUM not in severities
        assert Severity.HIGH in severities
        assert Severity.CRITICAL in severities

    def test_severity_extraction_multiple_locations(self):
        """Test severity extraction from different locations in semgrep output."""
        # Test severity in metadata.severity
        finding1 = {
            "check_id": "test.rule",
            "message": "Test message",
            "metadata": {"severity": "warning"},
            "start": {"line": 1}
        }
        threat1 = self.scanner._convert_semgrep_finding_to_threat(finding1, "test.py")
        assert threat1.severity == Severity.HIGH

        # Test severity in extra.severity
        finding2 = {
            "check_id": "test.rule",
            "message": "Test message", 
            "extra": {"severity": "error"},
            "start": {"line": 1}
        }
        threat2 = self.scanner._convert_semgrep_finding_to_threat(finding2, "test.py")
        assert threat2.severity == Severity.CRITICAL

        # Test severity in top-level
        finding3 = {
            "check_id": "test.rule",
            "message": "Test message",
            "severity": "critical",
            "start": {"line": 1}
        }
        threat3 = self.scanner._convert_semgrep_finding_to_threat(finding3, "test.py")
        assert threat3.severity == Severity.CRITICAL

        # Test fallback to default
        finding4 = {
            "check_id": "test.rule",
            "message": "Test message",
            "start": {"line": 1}
        }
        threat4 = self.scanner._convert_semgrep_finding_to_threat(finding4, "test.py")
        assert threat4.severity == Severity.MEDIUM  # Default fallback

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_scan_file_with_severity_threshold(self, mock_run):
        """Test scan_file method with severity threshold parameter."""
        # Mock semgrep output
        semgrep_output = {
            "results": [
                {
                    "check_id": "test.rule",
                    "message": "Test message",
                    "path": "test.py", 
                    "start": {"line": 1},
                    "metadata": {"severity": "warning"}  # HIGH severity
                }
            ]
        }

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(semgrep_output)
        mock_run.return_value.stderr = ""

        with patch("builtins.open", mock_open(read_data="test code")):
            with patch("tempfile.NamedTemporaryFile"):
                with patch("os.unlink"):
                    # Test with CRITICAL threshold - should filter out HIGH severity
                    threats = self.scanner.scan_file(
                        "test.py", Language.PYTHON, severity_threshold=Severity.CRITICAL
                    )
                    assert len(threats) == 0

                    # Test with MEDIUM threshold - should include HIGH severity  
                    threats = self.scanner.scan_file(
                        "test.py", Language.PYTHON, severity_threshold=Severity.MEDIUM
                    )
                    assert len(threats) == 1

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_scan_directory_with_severity_threshold(self, mock_run):
        """Test scan_directory method with severity threshold parameter."""
        # Mock semgrep output with mixed severities
        semgrep_output = {
            "results": [
                {
                    "check_id": "test.high", 
                    "message": "High issue",
                    "path": "file1.py",
                    "start": {"line": 1},
                    "metadata": {"severity": "warning"}  # HIGH
                },
                {
                    "check_id": "test.medium",
                    "message": "Medium issue", 
                    "path": "file2.py",
                    "start": {"line": 1},
                    "metadata": {"severity": "info"}  # MEDIUM
                }
            ]
        }

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(semgrep_output)
        mock_run.return_value.stderr = ""

        # Test with HIGH threshold
        threats = self.scanner.scan_directory(
            "/test/dir", severity_threshold=Severity.HIGH
        )
        assert len(threats) == 1
        assert threats[0].severity == Severity.HIGH

    def test_semgrep_severity_mapping_comprehensive(self):
        """Test comprehensive semgrep severity mapping."""
        test_cases = [
            ("error", Severity.CRITICAL),
            ("critical", Severity.CRITICAL), 
            ("warning", Severity.HIGH),
            ("info", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("unknown", Severity.LOW),  # Fallback case
            ("", Severity.LOW),  # Empty string fallback
        ]

        for semgrep_severity, expected_severity in test_cases:
            result = self.scanner._map_semgrep_severity(semgrep_severity)
            assert result == expected_severity, f"Failed for severity: {semgrep_severity}"

    def test_category_mapping_edge_cases(self):
        """Test category mapping with edge cases."""
        test_cases = [
            ("sql-injection", "SQL injection detected", Category.INJECTION),
            ("xss-stored", "Cross-site scripting found", Category.XSS),
            ("authentication-bypass", "Auth bypass", Category.AUTHENTICATION),
            ("crypto-weak", "Weak cryptography", Category.CRYPTOGRAPHY),
            ("path-traversal", "Directory traversal", Category.PATH_TRAVERSAL),
            ("rce-command", "Remote code execution", Category.RCE),
            ("ssrf-request", "Server-side request forgery", Category.SSRF),
            ("deserial-pickle", "Insecure deserialization", Category.DESERIALIZATION),
            ("secret-key", "Hardcoded secret", Category.SECRETS),
            ("csrf-missing", "CSRF protection missing", Category.CSRF),
            ("dos-regex", "ReDoS vulnerability", Category.DOS),
            ("config-debug", "Debug mode enabled", Category.CONFIGURATION),
            ("log-injection", "Log injection", Category.INJECTION),
            ("log-format", "Log format issue", Category.LOGGING),
            ("input-validation", "Input validation missing", Category.VALIDATION),
            ("unknown-rule", "Unknown rule type", Category.VALIDATION),  # Default fallback
        ]

        for rule_id, message, expected_category in test_cases:
            result = self.scanner._map_semgrep_category(rule_id, message)
            assert result == expected_category, f"Failed for rule_id: {rule_id}"

    def test_get_file_extension_mapping(self):
        """Test file extension mapping for different languages."""
        assert self.scanner._get_file_extension(Language.PYTHON) == ".py"
        assert self.scanner._get_file_extension(Language.JAVASCRIPT) == ".js" 
        assert self.scanner._get_file_extension(Language.TYPESCRIPT) == ".ts"

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_scan_code_with_semgrep_unavailable(self, mock_run):
        """Test scan_code when semgrep is not available."""
        # Create scanner with semgrep unavailable
        with patch.object(self.scanner, '_semgrep_available', False):
            threats = self.scanner.scan_code(
                "test code", "test.py", Language.PYTHON
            )
            assert threats == []
            # Ensure subprocess.run was not called
            mock_run.assert_not_called()

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_scan_file_with_semgrep_unavailable(self, mock_run):
        """Test scan_file when semgrep is not available."""
        with patch.object(self.scanner, '_semgrep_available', False):
            threats = self.scanner.scan_file("test.py", Language.PYTHON)
            assert threats == []
            mock_run.assert_not_called()

    @patch("adversary_mcp_server.semgrep_scanner.subprocess.run")
    def test_scan_directory_with_semgrep_unavailable(self, mock_run):
        """Test scan_directory when semgrep is not available."""
        with patch.object(self.scanner, '_semgrep_available', False):
            threats = self.scanner.scan_directory("/test/dir")
            assert threats == []
            mock_run.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
