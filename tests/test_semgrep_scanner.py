"""Tests for SemgrepScanner module."""

import os
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
        # Force semgrep to be available for unit tests (override actual system state)
        self.scanner._semgrep_available = True

    def teardown_method(self):
        """Clean up test fixtures."""
        # Reset any potential state
        if hasattr(self, "scanner"):
            # Reset cached availability state
            self.scanner._semgrep_available = self.scanner._check_semgrep_available()
        self.threat_engine = None
        self.scanner = None

    @patch("adversary_mcp_server.semgrep_scanner._SEMGREP_AVAILABLE", True)
    def test_check_semgrep_available_success(self):
        """Test successful Semgrep availability check."""
        scanner = SemgrepScanner(self.threat_engine)
        assert scanner.is_available() is True

    @patch("adversary_mcp_server.semgrep_scanner._SEMGREP_AVAILABLE", False)
    def test_check_semgrep_available_failure(self):
        """Test failed Semgrep availability check."""
        scanner = SemgrepScanner(self.threat_engine)
        assert scanner.is_available() is False

    def test_get_semgrep_env_info_with_token(self):
        """Test environment info with Semgrep token."""
        with patch.dict(os.environ, {"SEMGREP_APP_TOKEN": "test_token"}):
            env_info = self.scanner._get_semgrep_env_info()
            assert env_info["has_token"] == "true"

    def test_get_semgrep_env_info_without_token(self):
        """Test environment info without Semgrep token."""
        with patch.dict(os.environ, {}, clear=True):
            env_info = self.scanner._get_semgrep_env_info()
            assert env_info["has_token"] == "false"

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

    @pytest.mark.asyncio
    @patch("semgrep.run_scan.run_scan_and_return_json")
    async def test_scan_code_success(self, mock_semgrep_run):
        """Test successful code scanning with Semgrep Python API."""
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
                        "path": "test.py",
                    }
                ]
            }

            mock_semgrep_run.return_value = semgrep_output

            source_code = "eval(user_input)"
            threats = await self.scanner.scan_code(
                source_code, "test.py", Language.PYTHON
            )

            assert len(threats) == 1
            assert (
                threats[0].rule_id
                == "semgrep-python.lang.security.audit.dangerous-eval.dangerous-eval"
            )
            assert threats[0].severity == Severity.CRITICAL

            # Verify Semgrep API was called
            mock_semgrep_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_code_unavailable(self):
        """Test code scanning when Semgrep is unavailable."""
        with patch.object(self.scanner, "_semgrep_available", False):
            source_code = "eval(user_input)"
            threats = await self.scanner.scan_code(
                source_code, "test.py", Language.PYTHON
            )

            assert threats == []

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_code_error_handling(self, mock_semgrep_run):
        """Test code scanning with error handling."""
        with patch.object(self.scanner, "_semgrep_available", True):
            mock_semgrep_run.side_effect = Exception("Semgrep scan failed")

            source_code = "eval(user_input)"

            with pytest.raises(SemgrepError, match="Semgrep scan failed"):
                await self.scanner.scan_code(source_code, "test.py", Language.PYTHON)

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_code_invalid_response(self, mock_semgrep_run):
        """Test code scanning with invalid response format."""
        with patch.object(self.scanner, "_semgrep_available", True):
            mock_semgrep_run.return_value = "invalid response"

            source_code = "eval(user_input)"
            threats = await self.scanner.scan_code(
                source_code, "test.py", Language.PYTHON
            )

            assert threats == []

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_code_custom_config(self, mock_semgrep_run):
        """Test code scanning with custom config."""
        with patch.object(self.scanner, "_semgrep_available", True):
            mock_semgrep_run.return_value = {"results": []}

            source_code = "eval(user_input)"
            threats = await self.scanner.scan_code(
                source_code, "test.py", Language.PYTHON, config="custom-config.yml"
            )

            assert threats == []

            # Verify custom config was used
            call_args = mock_semgrep_run.call_args
            assert str(call_args[1]["config"]).endswith("custom-config.yml")

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_file_success(self, mock_semgrep_run):
        """Test successful file scanning."""
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
                    "path": "test.py",
                }
            ]
        }

        mock_semgrep_run.return_value = semgrep_output

        with patch.object(self.scanner, "_semgrep_available", True):
            threats = await self.scanner.scan_file("test.py", Language.PYTHON)

            assert len(threats) == 1
            assert (
                threats[0].rule_id
                == "semgrep-python.lang.security.audit.dangerous-eval.dangerous-eval"
            )
            assert threats[0].severity == Severity.CRITICAL

            # Verify Semgrep API was called
            mock_semgrep_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_file_unavailable(self):
        """Test file scanning when Semgrep is unavailable."""
        with patch.object(self.scanner, "_semgrep_available", False):
            threats = await self.scanner.scan_file("test.py", Language.PYTHON)
            assert threats == []

    @patch("builtins.open", side_effect=FileNotFoundError("File not found"))
    @pytest.mark.asyncio
    async def test_scan_file_not_found(self, mock_open):
        """Test file scanning with missing file."""
        with pytest.raises(SemgrepError, match="Failed to scan file"):
            await self.scanner.scan_file("nonexistent.py", Language.PYTHON)


class TestSemgrepScannerIntegration:
    """Integration tests for SemgrepScanner."""

    def setup_method(self):
        """Set up test fixtures."""
        self.threat_engine = ThreatEngine()
        self.scanner = SemgrepScanner(self.threat_engine)
        # Force semgrep to be available for unit tests (override actual system state)
        self.scanner._semgrep_available = True

    def teardown_method(self):
        """Clean up test fixtures."""
        # Reset any potential state
        if hasattr(self, "scanner"):
            # Reset cached availability state
            self.scanner._semgrep_available = self.scanner._check_semgrep_available()
        self.threat_engine = None
        self.scanner = None

    @pytest.mark.asyncio
    async def test_python_code_with_eval(self):
        """Test scanning Python code with eval vulnerability."""
        python_code = """
def dangerous_function(user_input):
    result = eval(user_input)  # This should be detected
    return result
"""

        with patch.object(self.scanner, "_semgrep_available", True):
            with patch("semgrep.run_scan.run_scan_and_return_json") as mock_semgrep_run:
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

                mock_semgrep_run.return_value = semgrep_output

                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_file.name = "/tmp/test.py"
                    mock_open.return_value.__enter__.return_value = mock_file

                    with patch("os.unlink"):
                        threats = await self.scanner.scan_code(
                            python_code, "test.py", Language.PYTHON
                        )

                assert len(threats) == 1
                threat = threats[0]
                assert "eval" in threat.description.lower()
                assert threat.severity == Severity.CRITICAL
                assert threat.category == Category.RCE  # eval maps to RCE
                assert threat.confidence == 0.9

    @pytest.mark.asyncio
    async def test_javascript_code_with_xss(self):
        """Test scanning JavaScript code with XSS vulnerability."""
        js_code = """
function displayUser(userInput) {
    document.innerHTML = userInput;  // This should be detected as XSS
}
"""

        with patch.object(self.scanner, "_semgrep_available", True):
            with patch("semgrep.run_scan.run_scan_and_return_json") as mock_semgrep_run:
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

                mock_semgrep_run.return_value = semgrep_output

                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_file.name = "/tmp/test.js"
                    mock_open.return_value.__enter__.return_value = mock_file

                    with patch("os.unlink"):
                        threats = await self.scanner.scan_code(
                            js_code, "test.js", Language.JAVASCRIPT
                        )

                assert len(threats) == 1
                threat = threats[0]
                assert "xss" in threat.description.lower()
                assert threat.severity == Severity.HIGH
                assert threat.category == Category.XSS

    @pytest.mark.asyncio
    async def test_no_vulnerabilities_found(self):
        """Test scanning code with no vulnerabilities."""
        safe_code = """
def safe_function():
    return "Hello, World!"
"""

        with patch.object(self.scanner, "_semgrep_available", True):
            with patch("semgrep.run_scan.run_scan_and_return_json") as mock_semgrep_run:
                # Mock empty Semgrep output
                semgrep_output = {"results": []}

                mock_semgrep_run.return_value = semgrep_output

                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_file.name = "/tmp/test.py"
                    mock_open.return_value.__enter__.return_value = mock_file

                    with patch("os.unlink"):
                        threats = await self.scanner.scan_code(
                            safe_code, "test.py", Language.PYTHON
                        )

                assert len(threats) == 0

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_severity_filtering_with_threshold(self, mock_semgrep_run):
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
                },
            ]
        }

        mock_semgrep_run.return_value = semgrep_output

        # Test with HIGH threshold - should only get HIGH and CRITICAL
        with patch("tempfile.NamedTemporaryFile"):
            with patch("os.unlink"):
                threats = await self.scanner.scan_code(
                    "test code",
                    "test.py",
                    Language.PYTHON,
                    severity_threshold=Severity.HIGH,
                )

                assert len(threats) == 2
                severities = [t.severity for t in threats]
                assert Severity.HIGH in severities
                assert Severity.CRITICAL in severities
                assert Severity.MEDIUM not in severities

    @pytest.mark.asyncio
    async def test_filter_by_severity_method(self):
        """Test the _filter_by_severity method directly."""
        # Create test threats with different severities
        threats = [
            ThreatMatch(
                rule_id="rule1",
                rule_name="Rule 1",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=1,
            ),
            ThreatMatch(
                rule_id="rule2",
                rule_name="Rule 2",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=2,
            ),
            ThreatMatch(
                rule_id="rule3",
                rule_name="Rule 3",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=3,
            ),
            ThreatMatch(
                rule_id="rule4",
                rule_name="Rule 4",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=4,
            ),
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

    @pytest.mark.asyncio
    async def test_severity_extraction_multiple_locations(self):
        """Test severity extraction from different locations in semgrep output."""
        # Test severity in metadata.severity
        finding1 = {
            "check_id": "test.rule",
            "message": "Test message",
            "metadata": {"severity": "warning"},
            "start": {"line": 1},
        }
        threat1 = self.scanner._convert_semgrep_finding_to_threat(finding1, "test.py")
        assert threat1.severity == Severity.HIGH

        # Test severity in extra.severity
        finding2 = {
            "check_id": "test.rule",
            "message": "Test message",
            "extra": {"severity": "error"},
            "start": {"line": 1},
        }
        threat2 = self.scanner._convert_semgrep_finding_to_threat(finding2, "test.py")
        assert threat2.severity == Severity.CRITICAL

        # Test severity in top-level
        finding3 = {
            "check_id": "test.rule",
            "message": "Test message",
            "severity": "critical",
            "start": {"line": 1},
        }
        threat3 = self.scanner._convert_semgrep_finding_to_threat(finding3, "test.py")
        assert threat3.severity == Severity.CRITICAL

        # Test fallback to default
        finding4 = {
            "check_id": "test.rule",
            "message": "Test message",
            "start": {"line": 1},
        }
        threat4 = self.scanner._convert_semgrep_finding_to_threat(finding4, "test.py")
        assert threat4.severity == Severity.MEDIUM  # Default fallback

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_file_with_severity_threshold(self, mock_semgrep_run):
        """Test scan_file method with severity threshold parameter."""
        # Mock semgrep output
        semgrep_output = {
            "results": [
                {
                    "check_id": "test.rule",
                    "message": "Test message",
                    "path": "test.py",
                    "start": {"line": 1},
                    "metadata": {"severity": "warning"},  # HIGH severity
                }
            ]
        }

        mock_semgrep_run.return_value = semgrep_output

        with patch("builtins.open", mock_open(read_data="test code")):
            with patch("tempfile.NamedTemporaryFile"):
                with patch("os.unlink"):
                    # Test with CRITICAL threshold - should filter out HIGH severity
                    threats = await self.scanner.scan_file(
                        "test.py", Language.PYTHON, severity_threshold=Severity.CRITICAL
                    )
                    assert len(threats) == 0

                    # Test with MEDIUM threshold - should include HIGH severity
                    threats = await self.scanner.scan_file(
                        "test.py", Language.PYTHON, severity_threshold=Severity.MEDIUM
                    )
                    assert len(threats) == 1

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_directory_with_severity_threshold(self, mock_semgrep_run):
        """Test scan_directory method with severity threshold parameter."""
        # Mock semgrep output with mixed severities
        semgrep_output = {
            "results": [
                {
                    "check_id": "test.high",
                    "message": "High issue",
                    "path": "test.py",
                    "start": {"line": 1},
                    "metadata": {"severity": "warning"},  # HIGH
                },
                {
                    "check_id": "test.medium",
                    "message": "Medium issue",
                    "path": "test.py",
                    "start": {"line": 1},
                    "metadata": {"severity": "info"},  # MEDIUM
                },
            ]
        }

        mock_semgrep_run.return_value = semgrep_output

        # Test with HIGH threshold
        threats = await self.scanner.scan_directory(
            "/test/dir", severity_threshold=Severity.HIGH
        )
        assert len(threats) == 1
        assert threats[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_semgrep_severity_mapping_comprehensive(self):
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
            assert (
                result == expected_severity
            ), f"Failed for severity: {semgrep_severity}"

    @pytest.mark.asyncio
    async def test_category_mapping_edge_cases(self):
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
            (
                "unknown-rule",
                "Unknown rule type",
                Category.VALIDATION,
            ),  # Default fallback
        ]

        for rule_id, message, expected_category in test_cases:
            result = self.scanner._map_semgrep_category(rule_id, message)
            assert result == expected_category, f"Failed for rule_id: {rule_id}"

    @pytest.mark.asyncio
    async def test_get_file_extension_mapping(self):
        """Test file extension mapping for different languages."""
        assert self.scanner._get_file_extension(Language.PYTHON) == ".py"
        assert self.scanner._get_file_extension(Language.JAVASCRIPT) == ".js"
        assert self.scanner._get_file_extension(Language.TYPESCRIPT) == ".ts"

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_code_with_semgrep_unavailable(self, mock_semgrep_run):
        """Test scan_code when semgrep is not available."""
        # Create scanner with semgrep unavailable
        with patch.object(self.scanner, "_semgrep_available", False):
            threats = await self.scanner.scan_code(
                "test code", "test.py", Language.PYTHON
            )
            assert threats == []
            # Ensure subprocess.run was not called
            mock_semgrep_run.assert_not_called()

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_file_with_semgrep_unavailable(self, mock_semgrep_run):
        """Test scan_file when semgrep is not available."""
        with patch.object(self.scanner, "_semgrep_available", False):
            threats = await self.scanner.scan_file("test.py", Language.PYTHON)
            assert threats == []
            mock_semgrep_run.assert_not_called()

    @patch("semgrep.run_scan.run_scan_and_return_json")
    @pytest.mark.asyncio
    async def test_scan_directory_with_semgrep_unavailable(self, mock_semgrep_run):
        """Test scan_directory when semgrep is not available."""
        with patch.object(self.scanner, "_semgrep_available", False):
            threats = await self.scanner.scan_directory("/test/dir")
            assert threats == []
            mock_semgrep_run.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
