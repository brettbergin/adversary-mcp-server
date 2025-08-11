"""Basic security integration tests that don't require complex mocking."""

import tempfile
from pathlib import Path

import pytest

from adversary_mcp_server.security import (
    InputValidator,
    SecurityError,
    sanitize_for_logging,
)


def test_input_validation_integration():
    """Test that input validation works as expected."""
    # Test path traversal detection
    with pytest.raises(SecurityError, match="Path traversal"):
        InputValidator.validate_file_path("../../../etc/passwd")

    # Test null byte detection
    with pytest.raises(SecurityError, match="Null bytes"):
        InputValidator.validate_file_path("test\x00.exe")

    # Test valid file path with temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"test content")
        tmp_path = tmp.name

    try:
        result = InputValidator.validate_file_path(tmp_path)
        assert isinstance(result, Path)
        assert result.exists()
    finally:
        Path(tmp_path).unlink()


def test_log_sanitization_integration():
    """Test that log sanitization works as expected."""
    # Test API key redaction
    sensitive_data = "api_key: sk-secret123456789"
    sanitized = sanitize_for_logging(sensitive_data)
    assert "sk-secret123456789" not in sanitized
    assert "[REDACTED]" in sanitized

    # Test password redaction
    sensitive_data = "password: mysecretpassword"
    sanitized = sanitize_for_logging(sensitive_data)
    assert "mysecretpassword" not in sanitized
    assert "[REDACTED]" in sanitized

    # Test safe data preservation
    safe_data = "file_path: /home/user/test.py, status: success"
    sanitized = sanitize_for_logging(safe_data)
    assert sanitized == safe_data


def test_mcp_arguments_validation_integration():
    """Test that MCP arguments validation works correctly."""
    # Test with temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
        tmp.write(b"print('hello')")
        tmp_path = tmp.name

    try:
        # Test valid arguments
        valid_args = {
            "path": tmp_path,
            "severity_threshold": "medium",
            "use_validation": True,
            "use_llm": "false",
            "timeout": "30",
        }

        result = InputValidator.validate_mcp_arguments(valid_args)

        # Check validation and normalization occurred
        assert "path" in result
        assert result["severity_threshold"] == "medium"
        assert result["use_validation"] is True
        assert result["use_llm"] is False
        assert result["timeout"] == 30

        # Test dangerous arguments
        dangerous_args = {"path": "../../../etc/passwd"}

        with pytest.raises(SecurityError):
            InputValidator.validate_mcp_arguments(dangerous_args)

    finally:
        Path(tmp_path).unlink()


def test_security_error_handling():
    """Test that SecurityError is properly raised and handled."""
    # Test that SecurityError can be raised
    with pytest.raises(SecurityError) as exc_info:
        raise SecurityError("Test security error")

    assert str(exc_info.value) == "Test security error"
    assert isinstance(exc_info.value, Exception)


def test_comprehensive_security_coverage():
    """Test that all security components work together."""
    # Create test data with sensitive information
    test_data = {
        "mcp_arguments": {
            "path": "/home/user/test.py",
            "api_key": "sk-secret123456",
            "password": "supersecret",
            "use_validation": "true",
        }
    }

    # Test sanitization
    sanitized = sanitize_for_logging(test_data)
    assert "sk-secret123456" not in sanitized
    assert "supersecret" not in sanitized
    assert "[REDACTED]" in sanitized
    assert "/home/user/test.py" in sanitized  # Safe data preserved

    # Test input validation patterns
    dangerous_inputs = [
        "../../../etc/passwd",
        "test\x00.exe",
        "file.txt/../../../secret",
    ]

    for dangerous in dangerous_inputs:
        with pytest.raises(SecurityError):
            InputValidator.validate_file_path(dangerous)


def test_env_var_security():
    """Test environment variable sanitization."""
    from adversary_mcp_server.security import sanitize_env_vars

    env_vars = {
        "ADVERSARY_SEMGREP_API_KEY": "secret123",
        "ADVERSARY_DEBUG": "true",
        "PATH": "/usr/bin:/bin",
        "API_KEY": "dangerous",
    }

    sanitized = sanitize_env_vars(env_vars)

    # Check sensitive vars are redacted
    assert sanitized["ADVERSARY_SEMGREP_API_KEY"] == "[REDACTED]"
    assert sanitized["API_KEY"] == "[REDACTED]"

    # Check safe vars are preserved
    assert sanitized["ADVERSARY_DEBUG"] == "true"
    assert sanitized["PATH"] == "/usr/bin:/bin"
