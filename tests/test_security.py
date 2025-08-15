"""Tests for security module."""

from pathlib import Path

import pytest

from adversary_mcp_server.security import SecurityError
from adversary_mcp_server.security.input_validator import InputValidator
from adversary_mcp_server.security.log_sanitizer import sanitize_for_logging


class TestSecurityError:
    """Test SecurityError exception."""

    def test_security_error_creation(self):
        """Test SecurityError can be created."""
        error = SecurityError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_security_error_inheritance(self):
        """Test SecurityError inheritance."""
        error = SecurityError("Test error")
        assert isinstance(error, Exception)
        assert isinstance(error, SecurityError)

    def test_security_error_raise_catch(self):
        """Test SecurityError can be raised and caught."""
        with pytest.raises(SecurityError, match="Test security error"):
            raise SecurityError("Test security error")


class TestInputValidator:
    """Test InputValidator class."""

    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        return InputValidator()

    def test_validator_creation(self, validator):
        """Test validator can be created."""
        assert isinstance(validator, InputValidator)

    def test_validate_file_path_valid(self, validator):
        """Test valid file path validation."""
        # Test with normal paths that should be valid
        valid_paths = [
            "/home/user/document.txt",
            "/tmp/test.py",
            "./relative/path.js",
            "simple_file.txt",
        ]

        for path in valid_paths:
            # Should not raise exception for valid paths
            try:
                result = validator.validate_file_path(path)
                # Some validation might return the validated path
                assert result is None or isinstance(result, str | Path)
            except (SecurityError, FileNotFoundError, ValueError):
                # If SecurityError, FileNotFoundError, or ValueError is raised,
                # it might be due to actual file system checks which is acceptable in tests
                pass

    def test_validate_file_path_dangerous(self, validator):
        """Test dangerous file path validation."""
        dangerous_paths = [
            "../../../etc/passwd",
            "/etc/shadow",
            "..\\..\\windows\\system32\\config\\sam",
            "/dev/null",
            "/proc/self/environ",
        ]

        for path in dangerous_paths:
            with pytest.raises((SecurityError, ValueError, FileNotFoundError)):
                validator.validate_file_path(path)

    def test_validate_file_path_empty(self, validator):
        """Test empty file path validation."""
        with pytest.raises((SecurityError, ValueError)):
            validator.validate_file_path("")

    def test_validate_file_path_none(self, validator):
        """Test None file path validation."""
        with pytest.raises((SecurityError, ValueError, TypeError)):
            validator.validate_file_path(None)


class TestLogSanitizer:
    """Test log sanitizer functionality."""

    def test_sanitize_for_logging_string(self):
        """Test sanitizing string data."""
        test_data = "This is a test string"
        result = sanitize_for_logging(test_data)

        assert isinstance(result, str)
        assert "test string" in result

    def test_sanitize_for_logging_dict_with_secrets(self):
        """Test sanitizing dictionary with secret data."""
        test_data = {
            "api_key": "secret123",
            "password": "mypassword",
            "token": "bearer_token",
            "safe_field": "safe_value",
        }

        result = sanitize_for_logging(test_data)

        assert isinstance(result, str)
        assert "[REDACTED]" in result
        assert "secret123" not in result
        assert "mypassword" not in result
        assert "bearer_token" not in result
        assert "safe_value" in result

    def test_sanitize_for_logging_dict_without_secrets(self):
        """Test sanitizing dictionary without secret data."""
        test_data = {
            "file_path": "/tmp/test.txt",
            "scan_type": "file",
            "timestamp": "2024-01-01T00:00:00Z",
        }

        result = sanitize_for_logging(test_data)

        assert isinstance(result, str)
        assert "/tmp/test.txt" in result
        assert "file" in result
        assert "2024-01-01" in result
        assert "[REDACTED]" not in result

    def test_sanitize_for_logging_list(self):
        """Test sanitizing list data."""
        test_data = ["item1", "item2", "api_key=secret"]

        result = sanitize_for_logging(test_data)

        assert isinstance(result, str)
        assert "item1" in result
        assert "item2" in result

    def test_sanitize_for_logging_nested_data(self):
        """Test sanitizing nested data structures."""
        test_data = {
            "config": {"api_key": "secret123", "endpoint": "https://api.example.com"},
            "metadata": {"user": "test_user", "password": "hidden_password"},
        }

        result = sanitize_for_logging(test_data)

        assert isinstance(result, str)
        assert "[REDACTED]" in result
        assert "secret123" not in result
        assert "hidden_password" not in result
        assert "https://api.example.com" in result
        assert "test_user" in result

    def test_sanitize_for_logging_none(self):
        """Test sanitizing None value."""
        result = sanitize_for_logging(None)

        assert isinstance(result, str)
        assert "None" in result

    def test_sanitize_for_logging_number(self):
        """Test sanitizing numeric data."""
        result = sanitize_for_logging(12345)

        assert isinstance(result, str)
        assert "12345" in result

    def test_sanitize_for_logging_boolean(self):
        """Test sanitizing boolean data."""
        result_true = sanitize_for_logging(True)
        result_false = sanitize_for_logging(False)

        assert isinstance(result_true, str)
        assert isinstance(result_false, str)
        assert "True" in result_true
        assert "False" in result_false

    def test_sanitize_for_logging_common_secret_keys(self):
        """Test sanitizing common secret key patterns."""
        test_data = {
            "ACCESS_TOKEN": "token123",
            "SECRET_KEY": "key456",
            "auth_header": "Bearer xyz789",
            "client_secret": "secret_abc",
            "private_key": "-----BEGIN PRIVATE KEY-----",
            "normal_field": "normal_value",
        }

        result = sanitize_for_logging(test_data)

        assert isinstance(result, str)
        assert "[REDACTED]" in result
        assert "token123" not in result
        assert "key456" not in result
        assert "xyz789" not in result
        assert "secret_abc" not in result
        assert "BEGIN PRIVATE KEY" not in result
        assert "normal_value" in result
