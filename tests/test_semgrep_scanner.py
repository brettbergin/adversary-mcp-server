"""Tests for SemgrepScanner module."""

import asyncio
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.semgrep_scanner import (
    ScanResult,
    SemgrepError,
    SemgrepScanner,
)
from adversary_mcp_server.types import Category, Language, Severity, ThreatMatch


class TestSemgrepScanner:
    """Test SemgrepScanner class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = SemgrepScanner()

    def teardown_method(self):
        """Clean up test fixtures."""
        self.threat_engine = None
        self.scanner = None

    @patch("adversary_mcp_server.semgrep_scanner._SEMGREP_AVAILABLE", True)
    def test_check_semgrep_available_success(self):
        """Test successful Semgrep availability check."""
        scanner = SemgrepScanner()
        assert scanner.is_available() is True

    @patch("adversary_mcp_server.semgrep_scanner._SEMGREP_AVAILABLE", False)
    def test_check_semgrep_available_failure(self):
        """Test failed Semgrep availability check."""
        scanner = SemgrepScanner()
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

    def test_get_semgrep_env_info_with_api_key_from_credential_manager(self):
        """Test environment info with API key from credential manager (Semgrep Pro)."""
        mock_credential_manager = MagicMock()
        mock_credential_manager.get_semgrep_api_key.return_value = (
            "sk-test-api-key-12345"
        )

        scanner = SemgrepScanner(credential_manager=mock_credential_manager)
        env_info = scanner._get_semgrep_env_info()

        assert env_info["has_token"] == "true"
        assert env_info["semgrep_user_agent"] == "adversary-mcp-server"
        mock_credential_manager.get_semgrep_api_key.assert_called_once()

    def test_get_semgrep_env_info_without_api_key_from_credential_manager(self):
        """Test environment info without API key from credential manager (free tier)."""
        mock_credential_manager = MagicMock()
        mock_credential_manager.get_semgrep_api_key.return_value = None

        scanner = SemgrepScanner(credential_manager=mock_credential_manager)
        env_info = scanner._get_semgrep_env_info()

        assert env_info["has_token"] == "false"
        assert env_info["semgrep_user_agent"] == "adversary-mcp-server"
        mock_credential_manager.get_semgrep_api_key.assert_called_once()

    def test_get_semgrep_env_info_without_credential_manager(self):
        """Test environment info without credential manager (free tier fallback)."""
        scanner = SemgrepScanner(credential_manager=None)
        env_info = scanner._get_semgrep_env_info()

        assert env_info["has_token"] == "false"
        assert env_info["semgrep_user_agent"] == "adversary-mcp-server"

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
            with patch.object(
                self.scanner,
                "_perform_scan",
                side_effect=FileNotFoundError("semgrep not found"),
            ):
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
        self.scanner = SemgrepScanner()

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


class TestSemgrepScannerEdgeCases:
    """Test edge cases and error conditions for SemgrepScanner."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = SemgrepScanner()

    @patch("adversary_mcp_server.semgrep_scanner.subprocess")
    def test_module_availability_exception_handling(self, mock_subprocess):
        """Test module availability check exception handling."""
        # Mock subprocess to raise an exception during module import
        mock_subprocess.run.side_effect = Exception("Unexpected error")

        # Import the module again to trigger the exception path

        import adversary_mcp_server.semgrep_scanner as scanner_module

        # Reload to test exception handling
        with patch.object(scanner_module, "_SEMGREP_AVAILABLE", False):
            scanner = SemgrepScanner()
            assert not scanner.is_available()

    @pytest.mark.asyncio
    async def test_find_semgrep_file_not_found_and_timeout(self):
        """Test _find_semgrep with FileNotFoundError and timeout."""
        scanner = SemgrepScanner()
        scanner._semgrep_path = None  # Clear cache

        with patch("asyncio.create_subprocess_exec") as mock_create:
            # All attempts fail - FileNotFoundError and then timeout
            mock_create.side_effect = [
                FileNotFoundError("semgrep not found"),
                FileNotFoundError("semgrep not found"),
                FileNotFoundError("semgrep not found"),
                FileNotFoundError("semgrep not found"),
                FileNotFoundError("semgrep not found"),
            ]

            with pytest.raises(RuntimeError, match="Semgrep not found"):
                await scanner._find_semgrep()

    @pytest.mark.asyncio
    async def test_find_semgrep_success_after_failures(self):
        """Test _find_semgrep succeeds after some failures."""
        scanner = SemgrepScanner()
        scanner._semgrep_path = None  # Clear cache

        with patch("asyncio.create_subprocess_exec") as mock_create:
            # First attempt fails, second succeeds
            mock_proc_fail = AsyncMock()
            mock_proc_success = AsyncMock()
            mock_proc_success.returncode = 0

            mock_create.side_effect = [
                FileNotFoundError("first path fails"),
                mock_proc_success,
            ]

            with patch("asyncio.wait_for", return_value=None):
                result = await scanner._find_semgrep()
                assert result == "semgrep"
                assert scanner._semgrep_path == "semgrep"

    def test_cache_validation_edge_cases(self):
        """Test cache validation edge cases."""
        scanner = SemgrepScanner(cache_ttl=60)

        # Test invalid cache - different hash
        old_result = ScanResult.__new__(ScanResult)
        old_result.findings = []
        old_result.timestamp = time.time()
        old_result.file_hash = "old_hash"

        assert not scanner._is_cache_valid(old_result, "new_hash")

        # Test expired cache - same hash but old timestamp
        old_result.file_hash = "same_hash"
        old_result.timestamp = time.time() - 120  # 2 minutes ago, TTL is 60s

        assert not scanner._is_cache_valid(old_result, "same_hash")

        # Test valid cache
        fresh_result = ScanResult.__new__(ScanResult)
        fresh_result.findings = []
        fresh_result.timestamp = time.time()
        fresh_result.file_hash = "current_hash"

        assert scanner._is_cache_valid(fresh_result, "current_hash")

    def test_convert_finding_error_handling(self):
        """Test error handling in _convert_semgrep_finding_to_threat."""
        scanner = SemgrepScanner()

        # Test malformed finding that causes exception
        malformed_finding = {
            "check_id": None,  # This could cause issues
            "start": {"line": "not_a_number"},  # Invalid line number
            "metadata": "not_a_dict",  # Invalid metadata
        }

        # Should return error threat instead of crashing
        threat = scanner._convert_semgrep_finding_to_threat(
            malformed_finding, "test.py"
        )

        assert threat.rule_id == "semgrep_conversion_error"
        assert threat.rule_name == "Semgrep Finding Conversion Error"
        assert "Failed to convert Semgrep finding" in threat.description
        assert threat.severity == Severity.LOW
        assert threat.file_path == "test.py"

    def test_convert_finding_cwe_handling(self):
        """Test CWE handling in finding conversion."""
        scanner = SemgrepScanner()

        # Test with CWE as list
        finding_with_cwe_list = {
            "check_id": "test.rule",
            "message": "Test message",
            "start": {"line": 1},
            "metadata": {"cwe": ["CWE-89", "CWE-95"]},
        }

        threat = scanner._convert_semgrep_finding_to_threat(
            finding_with_cwe_list, "test.py"
        )
        assert threat.cwe_id == "CWE-89"  # First one in list

        # Test with empty CWE list
        finding_with_empty_cwe = {
            "check_id": "test.rule",
            "message": "Test message",
            "start": {"line": 1},
            "metadata": {"cwe": []},
        }

        threat = scanner._convert_semgrep_finding_to_threat(
            finding_with_empty_cwe, "test.py"
        )
        assert threat.cwe_id is None

        # Test with CWE as string
        finding_with_cwe_string = {
            "check_id": "test.rule",
            "message": "Test message",
            "start": {"line": 1},
            "metadata": {"cwe": "CWE-79"},
        }

        threat = scanner._convert_semgrep_finding_to_threat(
            finding_with_cwe_string, "test.py"
        )
        assert threat.cwe_id == "CWE-79"

    @pytest.mark.asyncio
    async def test_scan_code_cache_hit_path(self):
        """Test scan_code cache hit execution path."""
        scanner = SemgrepScanner()

        # Pre-populate cache
        cache_key = scanner._get_cache_key("test code", "test.py", "python")
        file_hash = scanner._get_file_hash("test code")

        cached_findings = [
            {
                "check_id": "test.rule",
                "message": "Cached finding",
                "start": {"line": 1},
                "metadata": {"severity": "warning"},
            }
        ]

        scanner._cache[cache_key] = ScanResult.__new__(ScanResult)
        scanner._cache[cache_key].findings = cached_findings
        scanner._cache[cache_key].timestamp = time.time()
        scanner._cache[cache_key].file_hash = file_hash

        # Test cache hit with severity filtering
        threats = await scanner.scan_code(
            "test code", "test.py", Language.PYTHON, severity_threshold=Severity.MEDIUM
        )

        assert len(threats) == 1
        assert threats[0].description == "Cached finding"

    @pytest.mark.asyncio
    async def test_scan_code_conversion_error_handling(self):
        """Test scan_code handling of conversion errors."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_perform_scan") as mock_perform:
            # Mock findings that will cause conversion errors
            mock_perform.return_value = [
                {"malformed": "finding"},  # Will cause conversion error
                {
                    "check_id": "good.rule",
                    "message": "Good finding",
                    "start": {"line": 1},
                },
            ]

            with patch.object(
                scanner, "_convert_semgrep_finding_to_threat"
            ) as mock_convert:
                # First call raises exception, second succeeds
                mock_convert.side_effect = [
                    Exception("Conversion failed"),
                    ThreatMatch(
                        rule_id="good.rule",
                        rule_name="Good Rule",
                        description="Good finding",
                        category=Category.VALIDATION,
                        severity=Severity.MEDIUM,
                        file_path="test.py",
                        line_number=1,
                    ),
                ]

                threats = await scanner.scan_code("test", "test.py", Language.PYTHON)

                # Should get one threat (second one that succeeded)
                assert len(threats) == 1
                assert threats[0].rule_id == "good.rule"

    @pytest.mark.asyncio
    async def test_scan_file_not_found_error(self):
        """Test scan_file with file not found."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "is_available", return_value=True):
            with patch("os.path.isfile", return_value=False):
                with pytest.raises(SemgrepError, match="File not found"):
                    await scanner.scan_file("nonexistent.py", Language.PYTHON)

    @pytest.mark.asyncio
    async def test_scan_file_unicode_decode_error(self):
        """Test scan_file with unicode decode error."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "is_available", return_value=True):
            with patch("os.path.isfile", return_value=True):
                with patch("builtins.open", mock_open()) as mock_file:
                    mock_file.side_effect = UnicodeDecodeError(
                        "utf-8", b"", 0, 1, "invalid start byte"
                    )

                    threats = await scanner.scan_file("binary.py", Language.PYTHON)
                    assert threats == []  # Should return empty list for binary files

    @pytest.mark.asyncio
    async def test_scan_file_cache_hit(self):
        """Test scan_file cache hit path."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "is_available", return_value=True):
            with patch("os.path.isfile", return_value=True):
                with patch("builtins.open", mock_open(read_data="test code")):
                    # Pre-populate cache
                    cache_key = scanner._get_cache_key("test code", "test.py", "python")
                    file_hash = scanner._get_file_hash("test code")

                    cached_findings = [
                        {
                            "check_id": "cached.rule",
                            "message": "Cached finding",
                            "start": {"line": 5},
                        }
                    ]

                    scanner._cache[cache_key] = ScanResult.__new__(ScanResult)
                    scanner._cache[cache_key].findings = cached_findings
                    scanner._cache[cache_key].timestamp = time.time()
                    scanner._cache[cache_key].file_hash = file_hash

                    threats = await scanner.scan_file("test.py", Language.PYTHON)

                    assert len(threats) == 1
                    assert threats[0].description == "Cached finding"
                    assert threats[0].line_number == 5

    @pytest.mark.asyncio
    async def test_scan_file_with_severity_threshold(self):
        """Test scan_file with severity threshold filtering."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "is_available", return_value=True):
            with patch("os.path.isfile", return_value=True):
                with patch("builtins.open", mock_open(read_data="test code")):
                    with patch.object(scanner, "_perform_scan") as mock_perform:
                        mock_perform.return_value = [
                            {
                                "check_id": "low.rule",
                                "message": "Low severity",
                                "start": {"line": 1},
                                "metadata": {"severity": "info"},
                            },
                            {
                                "check_id": "high.rule",
                                "message": "High severity",
                                "start": {"line": 2},
                                "metadata": {"severity": "error"},
                            },
                        ]

                        threats = await scanner.scan_file(
                            "test.py", Language.PYTHON, severity_threshold=Severity.HIGH
                        )

                        # Should only get the high severity threat
                        assert len(threats) == 1
                        assert threats[0].description == "High severity"

    @pytest.mark.asyncio
    async def test_scan_directory_not_found(self):
        """Test scan_directory with directory not found."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "is_available", return_value=True):
            with patch("os.path.isdir", return_value=False):
                with pytest.raises(FileNotFoundError, match="Directory not found"):
                    await scanner.scan_directory("/nonexistent/dir")

    @pytest.mark.asyncio
    async def test_scan_directory_cache_hit(self):
        """Test scan_directory cache hit path."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "is_available", return_value=True):
            with patch("os.path.isdir", return_value=True):
                with patch.object(
                    scanner, "_get_directory_hash", return_value="test_hash"
                ):
                    # Pre-populate cache
                    cache_key = scanner._get_cache_key("", "/test/dir", "directory")

                    cached_findings = [
                        {
                            "check_id": "dir.rule",
                            "message": "Directory finding",
                            "path": "/test/dir/file.py",
                            "start": {"line": 10},
                        }
                    ]

                    scanner._cache[cache_key] = ScanResult.__new__(ScanResult)
                    scanner._cache[cache_key].findings = cached_findings
                    scanner._cache[cache_key].timestamp = time.time()
                    scanner._cache[cache_key].file_hash = "test_hash"

                    threats = await scanner.scan_directory("/test/dir")

                    assert len(threats) == 1
                    assert threats[0].description == "Directory finding"
                    assert threats[0].file_path == "/test/dir/file.py"

    @pytest.mark.asyncio
    async def test_scan_directory_with_filtering(self):
        """Test scan_directory with severity filtering."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "is_available", return_value=True):
            with patch("os.path.isdir", return_value=True):
                with patch.object(scanner, "_perform_directory_scan") as mock_scan:
                    mock_scan.return_value = [
                        {
                            "check_id": "info.rule",
                            "message": "Info level",
                            "path": "/test/file1.py",
                            "start": {"line": 1},
                            "metadata": {"severity": "info"},
                        },
                        {
                            "check_id": "critical.rule",
                            "message": "Critical level",
                            "path": "/test/file2.py",
                            "start": {"line": 1},
                            "metadata": {"severity": "error"},
                        },
                    ]

                    threats = await scanner.scan_directory(
                        "/test/dir", severity_threshold=Severity.HIGH
                    )

                    # Should only get critical threat
                    assert len(threats) == 1
                    assert threats[0].description == "Critical level"

    def test_get_directory_hash_os_error(self):
        """Test _get_directory_hash with OSError."""
        scanner = SemgrepScanner()

        with patch("os.stat", side_effect=OSError("Access denied")):
            # Should fallback to timestamp-based hash
            hash1 = scanner._get_directory_hash("/test/dir")
            hash2 = scanner._get_directory_hash("/test/dir")

            # Hashes should be different (timestamp-based)
            assert hash1 != hash2
            assert len(hash1) == 64  # SHA256 hex length

    @pytest.mark.asyncio
    async def test_perform_scan_timeout_error(self):
        """Test _perform_scan with timeout."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test.py"
                mock_temp.return_value.__enter__.return_value = mock_file

                with patch("asyncio.create_subprocess_exec") as mock_create:
                    mock_proc = AsyncMock()
                    mock_create.return_value = mock_proc

                    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                        findings = await scanner._perform_scan(
                            "code", "test.py", "python", 30
                        )

                        assert findings == []
                        # Should kill the process on timeout
                        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_perform_scan_json_decode_error(self):
        """Test _perform_scan with JSON parse error."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test.py"
                mock_temp.return_value.__enter__.return_value = mock_file

                with patch("asyncio.create_subprocess_exec") as mock_create:
                    mock_proc = AsyncMock()
                    mock_proc.returncode = 0
                    mock_create.return_value = mock_proc

                    # Return invalid JSON
                    with patch("asyncio.wait_for", return_value=(b"invalid json", b"")):
                        findings = await scanner._perform_scan(
                            "code", "test.py", "python", 30
                        )

                        assert findings == []

    @pytest.mark.asyncio
    async def test_perform_scan_nonzero_returncode(self):
        """Test _perform_scan with non-zero return code."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test.py"
                mock_temp.return_value.__enter__.return_value = mock_file

                with patch("asyncio.create_subprocess_exec") as mock_create:
                    mock_proc = AsyncMock()
                    mock_proc.returncode = 1
                    mock_create.return_value = mock_proc

                    with patch(
                        "asyncio.wait_for", return_value=(b"", b"Error occurred")
                    ):
                        findings = await scanner._perform_scan(
                            "code", "test.py", "python", 30
                        )

                        assert findings == []

    @pytest.mark.asyncio
    async def test_perform_scan_temp_file_cleanup(self):
        """Test _perform_scan cleans up temp file even on errors."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test.py"
                mock_temp.return_value.__enter__.return_value = mock_file
                mock_temp.return_value.__exit__.return_value = False

                with patch("os.unlink") as mock_unlink:
                    with patch("asyncio.create_subprocess_exec") as mock_create:
                        mock_proc = AsyncMock()
                        mock_proc.returncode = 0
                        mock_create.return_value = mock_proc

                        # Simulate JSON decode error which is caught
                        with patch(
                            "asyncio.wait_for", return_value=(b"invalid json", b"")
                        ):
                            findings = await scanner._perform_scan(
                                "code", "test.py", "python", 30
                            )

                            assert findings == []
                            mock_unlink.assert_called_with("/tmp/test.py")

    @pytest.mark.asyncio
    async def test_perform_scan_unlink_oserror(self):
        """Test _perform_scan handles OSError during temp file cleanup."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test.py"
                mock_temp.return_value.__enter__.return_value = mock_file

                with patch("asyncio.create_subprocess_exec") as mock_create:
                    mock_proc = AsyncMock()
                    mock_proc.returncode = 0
                    mock_create.return_value = mock_proc

                    with patch(
                        "asyncio.wait_for", return_value=(b'{"results": []}', b"")
                    ):
                        with patch("os.unlink", side_effect=OSError("Delete failed")):
                            # Should not raise exception even if unlink fails
                            findings = await scanner._perform_scan(
                                "code", "test.py", "python", 30
                            )

                            assert findings == []

    @pytest.mark.asyncio
    async def test_perform_directory_scan_timeout(self):
        """Test _perform_directory_scan with timeout."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("asyncio.create_subprocess_exec") as mock_create:
                mock_proc = AsyncMock()
                mock_create.return_value = mock_proc

                with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                    findings = await scanner._perform_directory_scan(
                        "/test/dir", 60, True
                    )

                    assert findings == []
                    mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_perform_directory_scan_json_error(self):
        """Test _perform_directory_scan with JSON parse error."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("asyncio.create_subprocess_exec") as mock_create:
                mock_proc = AsyncMock()
                mock_proc.returncode = 0
                mock_create.return_value = mock_proc

                with patch("asyncio.wait_for", return_value=(b"malformed json", b"")):
                    findings = await scanner._perform_directory_scan(
                        "/test/dir", 60, True
                    )

                    assert findings == []

    @pytest.mark.asyncio
    async def test_perform_directory_scan_recursive_flag(self):
        """Test _perform_directory_scan handles recursive flag."""
        scanner = SemgrepScanner()

        with patch.object(scanner, "_find_semgrep", return_value="semgrep"):
            with patch("asyncio.create_subprocess_exec") as mock_create:
                mock_proc = AsyncMock()
                mock_proc.returncode = 0
                mock_create.return_value = mock_proc

                with patch("asyncio.wait_for", return_value=(b'{"results": []}', b"")):
                    # Test non-recursive scan
                    await scanner._perform_directory_scan("/test/dir", 60, False)

                    # Should include --max-depth=1 in command
                    call_args = mock_create.call_args[0]  # Get positional args
                    assert "--max-depth=1" in call_args

    def test_get_extension_for_language_edge_cases(self):
        """Test _get_extension_for_language with edge cases."""
        scanner = SemgrepScanner()

        # Test None language
        assert scanner._get_extension_for_language(None) == ".py"

        # Test unknown language
        assert scanner._get_extension_for_language("unknown") == ".py"

        # Test case sensitivity
        assert scanner._get_extension_for_language("PYTHON") == ".py"
        assert scanner._get_extension_for_language("JavaScript") == ".js"

    def test_get_clean_env(self):
        """Test _get_clean_env removes semgrep metrics vars."""
        scanner = SemgrepScanner()

        with patch.dict(
            os.environ,
            {
                "SEMGREP_SEND_METRICS": "1",
                "SEMGREP_METRICS_ON": "true",
                "OTHER_VAR": "keep_this",
                "SEMGREP_SOME_OTHER": "keep_this_too",
            },
        ):
            env = scanner._get_clean_env()

            # Should remove metrics-related vars
            assert "SEMGREP_SEND_METRICS" not in env
            assert "SEMGREP_METRICS_ON" not in env

            # Should keep other vars
            assert env["OTHER_VAR"] == "keep_this"
            assert env["SEMGREP_SOME_OTHER"] == "keep_this_too"

            # Should set user agent
            assert env["SEMGREP_USER_AGENT_APPEND"] == "adversary-mcp-server"

    def test_clear_cache(self):
        """Test clear_cache functionality."""
        scanner = SemgrepScanner()

        # Add some cache entries
        scanner._cache["key1"] = "value1"
        scanner._cache["key2"] = "value2"

        assert len(scanner._cache) == 2

        scanner.clear_cache()

        assert len(scanner._cache) == 0

    def test_get_cache_stats(self):
        """Test get_cache_stats functionality."""
        scanner = SemgrepScanner(cache_ttl=300)

        # Add cache entries
        result1 = ScanResult.__new__(ScanResult)
        result1.findings = [{"rule": "test1"}, {"rule": "test2"}]
        result1.timestamp = time.time() - 60  # 1 minute ago

        result2 = ScanResult.__new__(ScanResult)
        result2.findings = [{"rule": "test3"}]
        result2.timestamp = time.time() - 10  # 10 seconds ago

        scanner._cache["key1"] = result1
        scanner._cache["key2"] = result2

        stats = scanner.get_cache_stats()

        assert stats["cache_size"] == 2
        assert stats["cache_ttl"] == 300
        assert len(stats["entries"]) == 2

        # Check entry details
        for entry in stats["entries"]:
            assert "key" in entry
            assert "findings_count" in entry
            assert "age_seconds" in entry
            assert entry["key"].endswith("...")  # Truncated key

        # Check findings counts
        findings_counts = [entry["findings_count"] for entry in stats["entries"]]
        assert 2 in findings_counts  # result1 has 2 findings
        assert 1 in findings_counts  # result2 has 1 finding


class TestSemgrepScannerCompatibility:
    """Test compatibility methods and aliases."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = SemgrepScanner()

    def test_semgrep_scanner_alias(self):
        """Test that SemgrepScanner alias works."""
        from adversary_mcp_server.semgrep_scanner import (
            OptimizedSemgrepScanner,
            SemgrepScanner,
        )

        # Should be the same class
        assert SemgrepScanner is OptimizedSemgrepScanner

        # Should create same type of instance
        scanner1 = SemgrepScanner()
        scanner2 = OptimizedSemgrepScanner()

        assert type(scanner1) is type(scanner2)

    def test_get_file_extension_compatibility(self):
        """Test _get_file_extension compatibility method."""
        scanner = SemgrepScanner()

        # Test with Language enum
        assert scanner._get_file_extension(Language.PYTHON) == ".py"
        assert scanner._get_file_extension(Language.JAVASCRIPT) == ".js"

        # Test with string-like object
        class MockLanguage:
            value = "typescript"

        mock_lang = MockLanguage()
        assert scanner._get_file_extension(mock_lang) == ".ts"

    def test_initialization_with_optional_params(self):
        """Test initialization with optional threat_engine and credential_manager."""
        mock_threat_engine = MagicMock()
        mock_credential_manager = MagicMock()

        scanner = SemgrepScanner(
            config="custom-config",
            cache_ttl=600,
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
        )

        assert scanner.config == "custom-config"
        assert scanner.cache_ttl == 600
        assert scanner.threat_engine is mock_threat_engine
        assert scanner.credential_manager is mock_credential_manager

    def test_get_clean_env_with_api_key_from_credential_manager(self):
        """Test _get_clean_env sets SEMGREP_APP_TOKEN from credential manager (Pro tier)."""
        mock_credential_manager = MagicMock()
        mock_credential_manager.get_semgrep_api_key.return_value = (
            "sk-test-api-key-12345"
        )

        scanner = SemgrepScanner(credential_manager=mock_credential_manager)

        with patch.dict(os.environ, {"EXISTING_VAR": "value"}, clear=True):
            env = scanner._get_clean_env()

            # Should set API token from credential manager
            assert env["SEMGREP_APP_TOKEN"] == "sk-test-api-key-12345"
            assert env["SEMGREP_USER_AGENT_APPEND"] == "adversary-mcp-server"
            mock_credential_manager.get_semgrep_api_key.assert_called_once()

    def test_get_clean_env_without_api_key_from_credential_manager(self):
        """Test _get_clean_env without API key from credential manager (free tier)."""
        mock_credential_manager = MagicMock()
        mock_credential_manager.get_semgrep_api_key.return_value = None

        scanner = SemgrepScanner(credential_manager=mock_credential_manager)

        with patch.dict(os.environ, {"SEMGREP_APP_TOKEN": "old_env_token"}, clear=True):
            env = scanner._get_clean_env()

            # Should remove any existing env var token
            assert "SEMGREP_APP_TOKEN" not in env
            assert env["SEMGREP_USER_AGENT_APPEND"] == "adversary-mcp-server"
            mock_credential_manager.get_semgrep_api_key.assert_called_once()

    def test_get_clean_env_without_credential_manager(self):
        """Test _get_clean_env without credential manager (no token management)."""
        scanner = SemgrepScanner(credential_manager=None)

        with patch.dict(
            os.environ,
            {"SEMGREP_APP_TOKEN": "env_token", "OTHER_VAR": "value"},
            clear=True,
        ):
            env = scanner._get_clean_env()

            # Should preserve existing environment token when no credential manager
            assert env["SEMGREP_APP_TOKEN"] == "env_token"
            assert env["SEMGREP_USER_AGENT_APPEND"] == "adversary-mcp-server"

    def test_get_clean_env_removes_metrics_vars(self):
        """Test _get_clean_env removes SEMGREP metrics variables."""
        mock_credential_manager = MagicMock()
        mock_credential_manager.get_semgrep_api_key.return_value = "test-key"

        scanner = SemgrepScanner(credential_manager=mock_credential_manager)

        test_env = {
            "SEMGREP_METRICS_ON": "true",
            "SEMGREP_ANONYMOUS_METRICS": "false",
            "SEMGREP_OTHER_VAR": "keep",
            "REGULAR_VAR": "keep",
        }

        with patch.dict(os.environ, test_env, clear=True):
            env = scanner._get_clean_env()

            # Should remove metrics variables
            assert "SEMGREP_METRICS_ON" not in env
            assert "SEMGREP_ANONYMOUS_METRICS" not in env
            # Should keep non-metrics SEMGREP vars and regular vars
            assert env["SEMGREP_OTHER_VAR"] == "keep"
            assert env["REGULAR_VAR"] == "keep"
            # Should set our custom vars
            assert env["SEMGREP_APP_TOKEN"] == "test-key"
            assert env["SEMGREP_USER_AGENT_APPEND"] == "adversary-mcp-server"


if __name__ == "__main__":
    pytest.main([__file__])
