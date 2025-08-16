"""Basic tests for input_validator.py to improve coverage."""

from pathlib import Path

from adversary_mcp_server.security.input_validator import (
    InputValidator,
    SecurityError,
    SeverityThreshold,
)


class TestInputValidatorBasic:
    """Basic tests for InputValidator to increase coverage."""

    def test_severity_threshold_enum(self):
        """Test SeverityThreshold enum values."""
        assert SeverityThreshold.LOW == "low"
        assert SeverityThreshold.MEDIUM == "medium"
        assert SeverityThreshold.HIGH == "high"
        assert SeverityThreshold.CRITICAL == "critical"

    def test_security_error(self):
        """Test SecurityError exception."""
        error = SecurityError("test message")
        assert str(error) == "test message"
        assert isinstance(error, Exception)

    def test_allowed_extensions(self):
        """Test ALLOWED_EXTENSIONS contains expected values."""
        extensions = InputValidator.ALLOWED_EXTENSIONS
        assert ".py" in extensions
        assert ".js" in extensions
        assert ".java" in extensions
        assert ".json" in extensions

    def test_patterns_exist(self):
        """Test security patterns are defined."""
        assert hasattr(InputValidator, "PATH_TRAVERSAL_PATTERN")
        assert hasattr(InputValidator, "COMMAND_INJECTION_PATTERN")
        assert hasattr(InputValidator, "SQL_INJECTION_PATTERN")
        assert hasattr(InputValidator, "NULL_BYTE_PATTERN")

    def test_validate_severity_threshold_valid(self):
        """Test valid severity thresholds."""
        for severity in ["low", "medium", "high", "critical"]:
            result = InputValidator.validate_severity_threshold(severity)
            assert result == severity

    def test_validate_boolean_param_true(self):
        """Test boolean validation for true values."""
        for value in [True, "true", "True", "TRUE"]:
            result = InputValidator.validate_boolean_param(value, "test")
            assert result is True

    def test_validate_boolean_param_false(self):
        """Test boolean validation for false values."""
        for value in [False, "false", "False", "FALSE"]:
            result = InputValidator.validate_boolean_param(value, "test")
            assert result is False

    def test_validate_integer_param_valid(self):
        """Test integer parameter validation."""
        result = InputValidator.validate_integer_param(
            50, "test", min_val=1, max_val=100
        )
        assert result == 50

    def test_validate_string_param_safe(self):
        """Test string parameter validation with safe strings."""
        safe_string = "normal text"
        result = InputValidator.validate_string_param(safe_string, "test")
        assert result == safe_string

    def test_validate_code_content_normal(self):
        """Test code content validation."""
        code = "def hello():\n    print('world')"
        result = InputValidator.validate_code_content(code)
        assert result == code

    def test_validate_file_path_basic(self):
        """Test basic file path validation."""
        # Use __file__ which should exist

        path = __file__  # This test file should exist
        result = InputValidator.validate_file_path(path)
        assert isinstance(result, Path)

    def test_validate_directory_path_basic(self):
        """Test basic directory path validation."""
        # Use current directory which should exist
        import os

        path = os.path.dirname(__file__)  # Directory of this test file
        result = InputValidator.validate_directory_path(path)
        assert isinstance(result, Path)

    def test_pattern_matching(self):
        """Test that patterns can match dangerous inputs."""
        # Test path traversal pattern
        assert InputValidator.PATH_TRAVERSAL_PATTERN.search("../etc/passwd")
        assert not InputValidator.PATH_TRAVERSAL_PATTERN.search("normal/path")

        # Test command injection pattern
        assert InputValidator.COMMAND_INJECTION_PATTERN.search("test; rm -rf /")
        assert not InputValidator.COMMAND_INJECTION_PATTERN.search("normal text")

        # Test SQL injection pattern
        assert InputValidator.SQL_INJECTION_PATTERN.search("'; DROP TABLE")
        assert not InputValidator.SQL_INJECTION_PATTERN.search("normal text")

        # Test null byte pattern
        assert InputValidator.NULL_BYTE_PATTERN.search("test\x00")
        assert not InputValidator.NULL_BYTE_PATTERN.search("normal text")
