"""Tests for SemgrepScanner module."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.semgrep_scanner import SemgrepScanner
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

    def teardown_method(self):
        """Clean up test fixtures."""
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

    def test_get_status_when_available(self):
        """Test get_status when Semgrep is available."""
        with patch("subprocess.run") as mock_run:
            # Mock successful semgrep --version call
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "1.128.1"
            mock_run.return_value = mock_result

            status = self.scanner.get_status()

            assert status["available"] is True
            assert status["installation_status"] == "available"
            assert "1.128.1" in status["version"]
            assert "semgrep_path" in status
            assert status["has_pro_features"] is False  # Conservative assumption

    def test_get_status_when_not_available(self):
        """Test get_status when Semgrep is not found."""
        with patch(
            "subprocess.run", side_effect=FileNotFoundError("Semgrep not found")
        ):
            status = self.scanner.get_status()

            assert status["available"] is False
            assert status["installation_status"] == "not_installed"
            assert "Semgrep not found in PATH" in status["error"]
            assert "Install semgrep" in status["installation_guidance"]

    def test_get_status_timeout_handling(self):
        """Test get_status handles timeout properly."""
        import subprocess

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 5)
        ):
            status = self.scanner.get_status()

            assert status["available"] is False
            assert status["installation_status"] == "not_installed"
            assert "Semgrep not found in PATH" in status["error"]

    def test_get_status_virtual_environment_priority(self):
        """Test get_status checks virtual environment first."""
        with (
            patch("subprocess.run") as mock_run,
            patch("sys.executable", "/some/venv/bin/python"),
        ):

            # Mock venv semgrep available
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "1.128.1 (venv)"
            mock_run.return_value = mock_result

            status = self.scanner.get_status()

            # Should call semgrep from virtual environment first
            mock_run.assert_called_with(
                ["/some/venv/bin/semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            assert status["available"] is True
            assert status["semgrep_path"] == "/some/venv/bin/semgrep"

    def test_get_status_fallback_to_system_path(self):
        """Test get_status falls back to system PATH when venv semgrep not found."""
        with (
            patch("subprocess.run") as mock_run,
            patch("sys.executable", "/some/venv/bin/python"),
        ):

            def mock_subprocess_run(cmd, **kwargs):
                if "/some/venv/bin/semgrep" in cmd:
                    # Venv semgrep not found
                    raise FileNotFoundError("Venv semgrep not found")
                elif "semgrep" in cmd:
                    # System semgrep found
                    mock_result = MagicMock()
                    mock_result.returncode = 0
                    mock_result.stdout = "1.128.1 (system)"
                    return mock_result
                else:
                    raise FileNotFoundError("Command not found")

            mock_run.side_effect = mock_subprocess_run

            status = self.scanner.get_status()

            assert status["available"] is True
            assert status["semgrep_path"] == "semgrep"
            assert "system" in status["version"]

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
    async def test_scan_code_unavailable(self):
        """Test code scanning when Semgrep is unavailable."""
        with patch.object(self.scanner, "is_available", return_value=False):
            source_code = "eval(user_input)"
            threats = await self.scanner.scan_code(
                source_code, "test.py", Language.PYTHON
            )

            assert threats == []

    @pytest.mark.asyncio
    async def test_scan_file_unavailable(self):
        """Test file scanning when Semgrep is unavailable."""
        with patch.object(self.scanner, "is_available", return_value=False):
            threats = await self.scanner.scan_file("test.py", Language.PYTHON)
            assert threats == []


class TestSemgrepScannerIntegration:
    """Integration tests for SemgrepScanner."""

    def setup_method(self):
        """Set up test fixtures."""
        self.threat_engine = ThreatEngine()
        self.scanner = SemgrepScanner(self.threat_engine)

    def teardown_method(self):
        """Clean up test fixtures."""
        self.threat_engine = None
        self.scanner = None

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
        assert (
            threat4.severity == Severity.HIGH
        )  # Default is WARNING which maps to HIGH

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

    @pytest.mark.asyncio
    async def test_scan_code_with_semgrep_unavailable(self):
        """Test scan_code when semgrep is not available."""
        # Create scanner with semgrep unavailable
        with patch.object(self.scanner, "is_available", return_value=False):
            threats = await self.scanner.scan_code(
                "test code", "test.py", Language.PYTHON
            )
            assert threats == []

    @pytest.mark.asyncio
    async def test_scan_file_with_semgrep_unavailable(self):
        """Test scan_file when semgrep is not available."""
        with patch.object(self.scanner, "is_available", return_value=False):
            threats = await self.scanner.scan_file("test.py", Language.PYTHON)
            assert threats == []

    @pytest.mark.asyncio
    async def test_scan_directory_with_semgrep_unavailable(self):
        """Test scan_directory when semgrep is not available."""
        with patch.object(self.scanner, "is_available", return_value=False):
            threats = await self.scanner.scan_directory("/test/dir")
            assert threats == []


if __name__ == "__main__":
    pytest.main([__file__])
