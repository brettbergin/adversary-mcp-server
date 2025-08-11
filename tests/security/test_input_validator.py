"""Tests for input validation functionality."""

import os
import tempfile
from pathlib import Path

import pytest

from adversary_mcp_server.security.input_validator import InputValidator, SecurityError


class TestInputValidator:
    """Test input validation functions."""

    def test_validate_file_path_success(self):
        """Test successful file path validation."""
        # Create a temporary file for testing
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            tmp_path = tmp.name

        try:
            result = InputValidator.validate_file_path(tmp_path)
            assert isinstance(result, Path)
            assert result.exists()
            assert result.is_file()
        finally:
            os.unlink(tmp_path)

    def test_validate_file_path_traversal_attack(self):
        """Test that path traversal attacks are blocked."""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/tmp/test/../../../etc/passwd",
            "file.txt/../../../secret.key",
        ]

        for path in malicious_paths:
            with pytest.raises(SecurityError, match="Path traversal"):
                InputValidator.validate_file_path(path)

    def test_validate_file_path_null_bytes(self):
        """Test that null bytes in paths are blocked."""
        malicious_paths = [
            "file.txt\x00.exe",
            "/etc/passwd\x00",
            "test\x00/../../secret",
        ]

        for path in malicious_paths:
            with pytest.raises(SecurityError, match="Null bytes"):
                InputValidator.validate_file_path(path)

    def test_validate_file_path_nonexistent(self):
        """Test that non-existent files raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            InputValidator.validate_file_path("/this/file/does/not/exist.txt")

    def test_validate_directory_path_success(self):
        """Test successful directory path validation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = InputValidator.validate_directory_path(tmp_dir)
            assert isinstance(result, Path)
            assert result.exists()
            assert result.is_dir()

    def test_validate_directory_path_security_issues(self):
        """Test directory path validation blocks security issues."""
        with pytest.raises(SecurityError):
            InputValidator.validate_directory_path("../../../etc")

    def test_validate_severity_threshold(self):
        """Test severity threshold validation."""
        valid_severities = ["low", "medium", "high", "critical"]

        for severity in valid_severities:
            result = InputValidator.validate_severity_threshold(severity)
            assert result == severity.lower()

        # Test case insensitive
        assert InputValidator.validate_severity_threshold("HIGH") == "high"
        assert InputValidator.validate_severity_threshold("  Medium  ") == "medium"

        # Test invalid severities
        invalid_severities = ["invalid", "extreme", "", 123]
        for severity in invalid_severities:
            with pytest.raises(ValueError):
                InputValidator.validate_severity_threshold(severity)

    def test_validate_boolean_param(self):
        """Test boolean parameter validation."""
        # Test actual booleans
        assert InputValidator.validate_boolean_param(True, "test") is True
        assert InputValidator.validate_boolean_param(False, "test") is False

        # Test truthy strings
        truthy = ["true", "1", "yes", "on", "enabled", "TRUE", "True"]
        for value in truthy:
            assert InputValidator.validate_boolean_param(value, "test") is True

        # Test falsy strings
        falsy = ["false", "0", "no", "off", "disabled", "FALSE", "False"]
        for value in falsy:
            assert InputValidator.validate_boolean_param(value, "test") is False

        # Test invalid values
        invalid = ["maybe", "invalid", 123, None, []]
        for value in invalid:
            with pytest.raises(ValueError):
                InputValidator.validate_boolean_param(value, "test")

    def test_validate_integer_param(self):
        """Test integer parameter validation."""
        # Test valid integers
        assert InputValidator.validate_integer_param(5, "test") == 5
        assert InputValidator.validate_integer_param("10", "test") == 10
        assert InputValidator.validate_integer_param("  20  ", "test") == 20

        # Test bounds checking
        with pytest.raises(ValueError, match="must be between"):
            InputValidator.validate_integer_param(-1, "test", min_val=0, max_val=100)

        with pytest.raises(ValueError, match="must be between"):
            InputValidator.validate_integer_param(101, "test", min_val=0, max_val=100)

        # Test invalid types
        invalid = ["not_a_number", None, [], {}]
        for value in invalid:
            with pytest.raises(ValueError):
                InputValidator.validate_integer_param(value, "test")

    def test_validate_string_param(self):
        """Test string parameter validation."""
        # Test valid strings
        result = InputValidator.validate_string_param("test", "param")
        assert result == "test"

        result = InputValidator.validate_string_param("  test  ", "param")
        assert result == "test"

        # Test max length
        with pytest.raises(ValueError, match="too long"):
            InputValidator.validate_string_param("a" * 1001, "param", max_length=1000)

        # Test non-string input
        with pytest.raises(ValueError, match="must be a string"):
            InputValidator.validate_string_param(123, "param")

    def test_validate_string_param_security_patterns(self):
        """Test that dangerous patterns are blocked in strings."""
        dangerous_strings = [
            "test\x00null",  # null bytes
            "test; rm -rf /",  # command injection
            "'; DROP TABLE users; --",  # SQL injection
            "test && malicious",  # command injection
            "test | evil_command",  # command injection
        ]

        for dangerous in dangerous_strings:
            with pytest.raises(SecurityError):
                InputValidator.validate_string_param(dangerous, "param")

    def test_validate_code_content(self):
        """Test code content validation."""
        # Test valid code
        valid_code = "function test() { return 'hello'; }"
        result = InputValidator.validate_code_content(valid_code)
        assert result == valid_code

        # Test max length
        with pytest.raises(ValueError, match="too long"):
            InputValidator.validate_code_content("a" * 1000001, max_length=1000000)

        # Test null bytes
        with pytest.raises(SecurityError, match="Null bytes"):
            InputValidator.validate_code_content("code\x00test")

        # Test non-string
        with pytest.raises(ValueError):
            InputValidator.validate_code_content(123)

    def test_validate_mcp_arguments(self):
        """Test MCP arguments validation."""
        # Create temporary file for testing
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test")
            tmp_path = tmp.name

        try:
            valid_args = {
                "path": tmp_path,
                "severity": "medium",
                "use_validation": True,
                "use_llm": "false",
                "timeout": 30,
                "content": "function test() {}",
                "output_format": "json",
            }

            result = InputValidator.validate_mcp_arguments(valid_args)

            # Check all arguments are present and properly typed
            assert "path" in result
            assert result["severity"] == "medium"
            assert result["use_validation"] is True
            assert result["use_llm"] is False
            assert result["timeout"] == 30
            assert result["content"] == "function test() {}"
            assert result["output_format"] == "json"

        finally:
            os.unlink(tmp_path)

    def test_validate_mcp_arguments_security_issues(self):
        """Test that MCP arguments validation blocks security issues."""
        # Test path traversal
        dangerous_args = {"path": "../../../etc/passwd"}

        with pytest.raises(SecurityError):
            InputValidator.validate_mcp_arguments(dangerous_args)

        # Test invalid severity
        invalid_args = {"severity": "extreme"}

        with pytest.raises(ValueError):
            InputValidator.validate_mcp_arguments(invalid_args)

    def test_validate_mcp_arguments_non_dict(self):
        """Test that non-dict arguments raise ValueError."""
        with pytest.raises(ValueError, match="must be a dictionary"):
            InputValidator.validate_mcp_arguments("not a dict")

    def test_get_allowed_scan_directories(self):
        """Test that allowed scan directories are reasonable."""
        allowed_dirs = InputValidator.get_allowed_scan_directories()

        # Should return a list of Path objects
        assert isinstance(allowed_dirs, list)
        for dir_path in allowed_dirs:
            assert isinstance(dir_path, Path)
            assert dir_path.exists()
            assert dir_path.is_dir()

        # Should include common safe directories
        home = Path.home()
        cwd = Path.cwd()

        # At least current directory and some home subdirs should be present
        dir_names = [str(d) for d in allowed_dirs]
        assert str(cwd) in dir_names

    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            yield tmp.name
        os.unlink(tmp.name)

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            yield tmp_dir

    def test_validate_file_path_with_allowed_dirs(self, temp_file):
        """Test file path validation with allowed directories restriction."""
        temp_path = Path(temp_file)
        parent_dir = temp_path.parent

        # Should work with parent directory in allowed list
        result = InputValidator.validate_file_path(str(temp_path), [parent_dir])
        assert result == temp_path.resolve()

        # Should fail with different allowed directory
        different_dir = Path.home()
        if different_dir != parent_dir:
            with pytest.raises(SecurityError, match="outside allowed directories"):
                InputValidator.validate_file_path(str(temp_path), [different_dir])

    def test_comprehensive_argument_validation(self):
        """Test comprehensive validation of complex argument structures."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test code")
            tmp_path = tmp.name

        try:
            complex_args = {
                "path": tmp_path,
                "severity_threshold": "HIGH",  # Test case insensitive
                "use_validation": "true",  # Test string boolean
                "use_llm": False,  # Test actual boolean
                "recursive": "1",  # Test numeric string boolean
                "max_findings": "50",  # Test string integer
                "output_format": "markdown",
                "source_branch": "feature-123",
                "target_branch": "main",
                "content": "const test = 'hello world';",
                "finding_uuid": "abc-123-def",
            }

            result = InputValidator.validate_mcp_arguments(complex_args)

            # Verify all transformations occurred correctly
            assert result["severity_threshold"] == "high"  # normalized
            assert result["use_validation"] is True  # converted from string
            assert result["use_llm"] is False  # preserved
            assert result["recursive"] is True  # converted from "1"
            assert result["max_findings"] == 50  # converted from string
            assert result["output_format"] == "markdown"  # preserved

        finally:
            os.unlink(tmp_path)
