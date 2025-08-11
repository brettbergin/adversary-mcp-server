"""Tests for log sanitization functionality."""

from adversary_mcp_server.security.log_sanitizer import (
    sanitize_dict_for_logging,
    sanitize_env_vars,
    sanitize_for_logging,
)


class TestLogSanitizer:
    """Test log sanitization functions."""

    def test_sanitize_api_keys(self):
        """Test that API keys are properly redacted."""
        test_cases = [
            ("api_key: sk-abc123def456", "[REDACTED]"),
            ('"api_key": "sk-abc123def456"', "[REDACTED]"),
            ("semgrep_api_key=xyz789", "xyz789"),  # Original value shouldn't appear
            ("llm_api_key: 'secret123'", "[REDACTED]"),
        ]

        for input_text, should_not_contain in test_cases:
            result = sanitize_for_logging(input_text)
            # Check that sensitive values are either redacted or don't appear
            if should_not_contain == "[REDACTED]":
                assert (
                    "[REDACTED]" in result
                ), f"Failed to redact: {input_text} -> {result}"
            else:
                assert (
                    should_not_contain not in result or "[REDACTED]" in result
                ), f"Sensitive value not hidden: {input_text} -> {result}"

    def test_sanitize_tokens(self):
        """Test that tokens are properly redacted."""
        test_cases = [
            ("token: bearer123456", "bearer123456"),
            ("access_token=abc123def", "abc123def"),
            ("bearer_token: 'xyz789'", "xyz789"),
        ]

        for input_text, sensitive_value in test_cases:
            result = sanitize_for_logging(input_text)
            # Check that sensitive token value doesn't appear or is redacted
            assert (
                sensitive_value not in result or "[REDACTED]" in result
            ), f"Token not hidden: {input_text} -> {result}"

    def test_sanitize_passwords(self):
        """Test that passwords are properly redacted."""
        test_cases = [
            ("password: secret123", "secret123"),
            ('"password": "mypass"', "mypass"),
            ("pass=admin123", "admin123"),
        ]

        for input_text, sensitive_value in test_cases:
            result = sanitize_for_logging(input_text)
            # Check that password value doesn't appear or is redacted
            assert (
                sensitive_value not in result or "[REDACTED]" in result
            ), f"Password not hidden: {input_text} -> {result}"

    def test_sanitize_openai_keys(self):
        """Test that OpenAI-style keys are redacted."""
        openai_key = "sk-" + "a" * 48
        result = sanitize_for_logging(openai_key)
        assert "[REDACTED-OPENAI-KEY]" in result
        assert "sk-" + "a" * 48 not in result

    def test_sanitize_jwt_tokens(self):
        """Test that JWT tokens are redacted."""
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        )
        result = sanitize_for_logging(jwt_token)
        assert "[REDACTED-JWT]" in result
        assert jwt_token not in result

    def test_preserve_safe_content(self):
        """Test that safe content is preserved."""
        safe_content = "file_path: /home/user/test.py, status: success"
        result = sanitize_for_logging(safe_content)
        assert result == safe_content

    def test_sanitize_dict_structure(self):
        """Test dictionary sanitization preserves structure."""
        test_dict = {
            "api_key": "sk-secret123",
            "file_path": "/home/user/test.py",
            "password": "secret",
            "config": {"token": "bearer123", "debug": True},
        }

        result = sanitize_dict_for_logging(test_dict)

        # Check structure is preserved
        assert "api_key" in result
        assert "file_path" in result
        assert "config" in result
        assert "debug" in result["config"]

        # Check sensitive data is redacted
        assert result["api_key"] == "[REDACTED]"
        assert result["password"] == "[REDACTED]"
        assert result["config"]["token"] == "[REDACTED]"

        # Check safe data is preserved
        assert result["file_path"] == "/home/user/test.py"
        assert result["config"]["debug"] is True

    def test_sanitize_env_vars(self):
        """Test environment variable sanitization."""
        env_dict = {
            "ADVERSARY_SEMGREP_API_KEY": "secret123",
            "ADVERSARY_LLM_API_KEY": "sk-abc123",
            "ADVERSARY_DEBUG": "true",
            "PATH": "/usr/bin:/bin",
            "API_KEY": "dangerous",
            "HOME": "/home/user",
        }

        result = sanitize_env_vars(env_dict)

        # Check sensitive vars are redacted
        assert result["ADVERSARY_SEMGREP_API_KEY"] == "[REDACTED]"
        assert result["ADVERSARY_LLM_API_KEY"] == "[REDACTED]"
        assert result["API_KEY"] == "[REDACTED]"

        # Check safe vars are preserved
        assert result["ADVERSARY_DEBUG"] == "true"
        assert result["PATH"] == "/usr/bin:/bin"
        assert result["HOME"] == "/home/user"

    def test_sanitize_complex_data(self):
        """Test sanitization with complex nested data."""
        complex_data = {
            "mcp_arguments": {
                "path": "/home/user/test.py",
                "api_key": "sk-secret123",
                "config": {
                    "semgrep_api_key": "abc123",
                    "use_validation": True,
                    "nested": {"token": "bearer456", "file": "test.js"},
                },
            }
        }

        result = sanitize_dict_for_logging(complex_data)

        # Check nested structure is preserved
        assert "mcp_arguments" in result
        assert "config" in result["mcp_arguments"]
        assert "nested" in result["mcp_arguments"]["config"]

        # Check sensitive data at all levels is redacted
        assert result["mcp_arguments"]["api_key"] == "[REDACTED]"
        assert result["mcp_arguments"]["config"]["semgrep_api_key"] == "[REDACTED]"
        assert result["mcp_arguments"]["config"]["nested"]["token"] == "[REDACTED]"

        # Check safe data is preserved
        assert result["mcp_arguments"]["path"] == "/home/user/test.py"
        assert result["mcp_arguments"]["config"]["use_validation"] is True
        assert result["mcp_arguments"]["config"]["nested"]["file"] == "test.js"

    def test_handle_non_dict_input(self):
        """Test that non-dict input is handled gracefully."""
        assert sanitize_dict_for_logging("string") == "string"
        assert sanitize_dict_for_logging(123) == 123
        assert sanitize_dict_for_logging(None) is None
        assert sanitize_dict_for_logging([1, 2, 3]) == [1, 2, 3]

    def test_handle_none_input(self):
        """Test that None input is handled."""
        assert sanitize_for_logging(None) == "None"

    def test_empty_inputs(self):
        """Test empty inputs are handled correctly."""
        assert sanitize_for_logging("") == ""
        assert sanitize_dict_for_logging({}) == {}
        assert sanitize_env_vars({}) == {}
