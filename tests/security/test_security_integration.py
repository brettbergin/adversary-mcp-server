"""Integration tests for security measures in MCP server and CLI."""

import os
import tempfile
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.security import SecurityError
from adversary_mcp_server.server import AdversaryMCPServer


class TestSecurityIntegration:
    """Integration tests for security measures."""

    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
            tmp.write(b"print('hello world')")
            yield tmp.name
        os.unlink(tmp.name)

    @pytest.fixture
    def mock_server(self):
        """Create a mock MCP server for testing."""
        with (
            patch("adversary_mcp_server.server.get_credential_manager") as mock_creds,
            patch("adversary_mcp_server.server.AdversaryDatabase") as mock_db,
            patch("adversary_mcp_server.server.TelemetryService") as mock_telemetry,
            patch(
                "adversary_mcp_server.server.MetricsCollectionOrchestrator"
            ) as mock_orchestrator,
            patch(
                "adversary_mcp_server.server.FalsePositiveManager"
            ) as mock_fp_manager,
            patch("adversary_mcp_server.server.ExploitGenerator") as mock_exploit_gen,
            patch("adversary_mcp_server.server.ScanEngine") as mock_scan_engine,
            patch("adversary_mcp_server.server.GitDiffScanner") as mock_diff_scanner,
        ):

            # Mock the heavy components but allow security validation to work
            mock_creds.return_value = Mock()
            mock_db.return_value = Mock()
            mock_telemetry.return_value = Mock()
            mock_orchestrator.return_value = Mock()
            mock_fp_manager.return_value = Mock()
            mock_exploit_gen.return_value = Mock()
            mock_scan_engine.return_value = Mock()
            mock_diff_scanner.return_value = Mock()

            # Create server with security validation intact
            server = AdversaryMCPServer()
            yield server

    def test_mcp_tool_validation_blocks_path_traversal(self):
        """Test that MCP tools block path traversal attempts."""
        from adversary_mcp_server.security import InputValidator, SecurityError

        # Test dangerous path traversal attempt
        dangerous_args = {
            "path": "../../../etc/passwd",
            "use_validation": False,
            "use_llm": False,
            "severity_threshold": "medium",
        }

        # Should raise SecurityError during input validation
        with pytest.raises(SecurityError, match="Path traversal"):
            InputValidator.validate_mcp_arguments(dangerous_args)

    def test_mcp_tool_validation_blocks_null_bytes(self):
        """Test that MCP tools block null bytes in arguments."""
        from adversary_mcp_server.security import InputValidator, SecurityError

        dangerous_args = {"path": "test.py\x00.exe", "use_validation": False}

        # Should raise SecurityError during input validation
        with pytest.raises(SecurityError, match="Null bytes"):
            InputValidator.validate_mcp_arguments(dangerous_args)

    def test_mcp_tool_validation_blocks_invalid_severity(self):
        """Test that MCP tools block invalid severity values."""
        from adversary_mcp_server.security import InputValidator

        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
            tmp.write(b"test")
            tmp_path = tmp.name

        try:
            dangerous_args = {
                "path": tmp_path,
                "severity_threshold": "extreme",  # Invalid severity
                "use_validation": False,
            }

            # Should raise ValueError for invalid severity
            with pytest.raises(ValueError, match="Invalid severity"):
                InputValidator.validate_mcp_arguments(dangerous_args)

        finally:
            os.unlink(tmp_path)

    def test_mcp_tool_validation_accepts_valid_input(self, temp_file):
        """Test that valid input passes validation and normalization."""
        from adversary_mcp_server.security import InputValidator

        valid_args = {
            "path": temp_file,
            "severity_threshold": "medium",
            "use_validation": False,
            "use_llm": False,
            "use_semgrep": True,
        }

        # Should validate successfully and return normalized arguments
        result = InputValidator.validate_mcp_arguments(valid_args)

        # Verify arguments were validated and normalized
        assert result["severity_threshold"] == "medium"
        assert result["use_validation"] is False
        assert result["use_llm"] is False
        assert result["use_semgrep"] is True

    def test_log_sanitization_in_server_logs(self, caplog):
        """Test that sensitive data is sanitized in server logs."""
        from adversary_mcp_server.security import sanitize_for_logging

        # Test data that should be sanitized
        sensitive_data = {
            "api_key": "sk-secret123456",
            "semgrep_api_key": "abc123def456",
            "password": "mysecret",
            "file_path": "/home/user/test.py",
            "use_validation": True,
        }

        sanitized = sanitize_for_logging(sensitive_data)

        # Check that sensitive data is redacted
        assert "sk-secret123456" not in sanitized
        assert "abc123def456" not in sanitized
        assert "mysecret" not in sanitized
        assert "[REDACTED" in sanitized

        # Check that safe data is preserved
        assert "/home/user/test.py" in sanitized
        assert "use_validation" in sanitized

    def test_env_var_sanitization(self):
        """Test that environment variables are properly sanitized."""
        from adversary_mcp_server.security import sanitize_env_vars

        test_env = {
            "ADVERSARY_SEMGREP_API_KEY": "secret123",
            "ADVERSARY_LLM_API_KEY": "sk-abc123",
            "ADVERSARY_DEBUG": "true",
            "HOME": "/home/user",
            "API_KEY": "dangerous",
            "NORMAL_VAR": "safe_value",
        }

        sanitized = sanitize_env_vars(test_env)

        # Sensitive vars should be redacted
        assert sanitized["ADVERSARY_SEMGREP_API_KEY"] == "[REDACTED]"
        assert sanitized["ADVERSARY_LLM_API_KEY"] == "[REDACTED]"
        assert sanitized["API_KEY"] == "[REDACTED]"

        # Safe vars should be preserved
        assert sanitized["ADVERSARY_DEBUG"] == "true"
        assert sanitized["HOME"] == "/home/user"
        assert sanitized["NORMAL_VAR"] == "safe_value"

    def test_mcp_code_scanning_validation(self):
        """Test that code scanning validates input content."""
        from adversary_mcp_server.security import InputValidator

        # Test with valid code
        valid_args = {
            "content": "function test() { return 'hello'; }",
            "severity_threshold": "medium",
            "use_validation": False,
        }

        # Should validate successfully
        result = InputValidator.validate_mcp_arguments(valid_args)
        assert result["content"] == "function test() { return 'hello'; }"
        assert result["severity_threshold"] == "medium"
        assert result["use_validation"] is False

    def test_mcp_code_scanning_blocks_null_bytes(self):
        """Test that code scanning blocks null bytes in content."""
        from adversary_mcp_server.security import InputValidator, SecurityError

        dangerous_args = {
            "content": "function test()\x00 { malicious(); }",
            "severity_threshold": "medium",
        }

        # Should raise SecurityError during validation
        with pytest.raises(SecurityError, match="Null bytes"):
            InputValidator.validate_mcp_arguments(dangerous_args)

    def test_comprehensive_mcp_argument_validation(self, temp_file):
        """Test comprehensive validation of all MCP argument types."""
        from adversary_mcp_server.security import InputValidator

        complex_args = {
            "path": temp_file,
            "severity_threshold": "HIGH",  # Case insensitive
            "use_validation": "true",  # String boolean
            "use_llm": False,  # Actual boolean
            "use_semgrep": "1",  # Numeric string boolean
            "include_exploits": "yes",  # Text boolean
            "timeout": "60",  # String integer
            "output_format": "json",
            "recursive": "enabled",  # Boolean variant
        }

        # Should validate and normalize all arguments
        result = InputValidator.validate_mcp_arguments(complex_args)

        # Verify normalization occurred
        assert result["severity_threshold"] == "high"  # Normalized to lowercase
        assert result["use_validation"] is True  # Converted from "true"
        assert result["use_llm"] is False  # Preserved
        assert result["use_semgrep"] is True  # Converted from "1"
        assert result["include_exploits"] is True  # Converted from "yes"
        assert result["timeout"] == 60  # Converted to int
        assert result["recursive"] is True  # Converted from "enabled"

    def test_security_error_inheritance(self):
        """Test that SecurityError is properly defined and usable."""
        # Should be able to raise and catch SecurityError
        with pytest.raises(SecurityError):
            raise SecurityError("Test security error")

        # Should be a subclass of Exception
        assert issubclass(SecurityError, Exception)

        # Should have proper error message
        error = SecurityError("Test message")
        assert str(error) == "Test message"

    @pytest.mark.parametrize(
        "dangerous_input,expected_error",
        [
            ("../../../etc/passwd", "Path traversal"),
            ("file\x00.exe", "Null bytes"),
            ("..\\..\\windows\\system32", "Path traversal"),  # Windows path traversal
        ],
    )
    def test_path_validation_edge_cases(self, dangerous_input, expected_error):
        """Test edge cases in path validation."""
        from adversary_mcp_server.security import InputValidator, SecurityError

        with pytest.raises(SecurityError, match=expected_error):
            InputValidator.validate_file_path(dangerous_input)

    def test_input_validator_comprehensive_coverage(self):
        """Test that InputValidator covers all expected validation scenarios."""
        from adversary_mcp_server.security import InputValidator

        # Verify all expected methods exist
        expected_methods = [
            "validate_file_path",
            "validate_directory_path",
            "validate_severity_threshold",
            "validate_boolean_param",
            "validate_integer_param",
            "validate_string_param",
            "validate_code_content",
            "validate_mcp_arguments",
            "get_allowed_scan_directories",
        ]

        for method_name in expected_methods:
            assert hasattr(
                InputValidator, method_name
            ), f"Missing method: {method_name}"
            assert callable(
                getattr(InputValidator, method_name)
            ), f"Method not callable: {method_name}"
