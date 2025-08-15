"""Tests for security modules to increase coverage."""

from adversary_mcp_server.security.log_sanitizer import (
    sanitize_dict_for_logging,
    sanitize_env_vars,
    sanitize_for_logging,
)


class TestSecurityCoverage:
    """Test security modules for coverage."""

    def test_sanitize_for_logging_basic(self):
        """Test sanitize_for_logging basic functionality."""
        # Test with normal text
        assert sanitize_for_logging("normal text") == "normal text"
        assert sanitize_for_logging("") == ""
        assert sanitize_for_logging(None) == "None"

        # Test with sensitive patterns
        sensitive_text = "password=secret123"
        sanitized = sanitize_for_logging(sensitive_text)
        assert "secret123" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_for_logging_api_keys(self):
        """Test API key sanitization."""
        text_with_api_key = "api_key=sk-abc123xyz"
        sanitized = sanitize_for_logging(text_with_api_key)
        assert "sk-abc123xyz" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_dict_for_logging_basic(self):
        """Test sanitize_dict_for_logging functionality."""
        test_dict = {
            "username": "user1",
            "password": "secret123",
            "api_key": "sk-123456789",
            "normal_field": "normal_value",
        }

        sanitized = sanitize_dict_for_logging(test_dict)

        assert sanitized["username"] == "user1"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["normal_field"] == "normal_value"

    def test_sanitize_dict_for_logging_nested(self):
        """Test nested dictionary sanitization."""
        nested_dict = {
            "config": {"api_key": "secret-key", "debug": True},
            "users": [
                {"name": "user1", "token": "user-token"},
                {"name": "user2", "password": "user-pass"},
            ],
        }

        sanitized = sanitize_dict_for_logging(nested_dict)

        assert sanitized["config"]["api_key"] == "[REDACTED]"
        assert sanitized["config"]["debug"] is True
        assert sanitized["users"][0]["token"] == "[REDACTED]"
        assert sanitized["users"][1]["password"] == "[REDACTED]"

    def test_sanitize_env_vars(self):
        """Test environment variable sanitization."""
        env_dict = {
            "HOME": "/home/user",
            "ADVERSARY_SEMGREP_API_KEY": "secret-key",
            "API_KEY": "another-secret",
            "DEBUG": "true",
        }

        sanitized = sanitize_env_vars(env_dict)

        assert sanitized["HOME"] == "/home/user"
        assert sanitized["ADVERSARY_SEMGREP_API_KEY"] == "[REDACTED]"
        assert sanitized["API_KEY"] == "[REDACTED]"
        assert sanitized["DEBUG"] == "true"
