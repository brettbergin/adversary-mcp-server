"""Tests for configuration module."""

from pathlib import Path

from adversary_mcp_server.config import (
    SecurityConfig,
    get_app_cache_dir,
    get_app_data_dir,
    get_app_metrics_dir,
)


class TestConfigDirectories:
    """Test application directory configuration."""

    def test_get_app_cache_dir(self):
        """Test cache directory configuration."""
        cache_dir = get_app_cache_dir()
        assert isinstance(cache_dir, Path)
        assert "adversary-mcp-server" in str(cache_dir)

    def test_get_app_data_dir(self):
        """Test data directory configuration."""
        data_dir = get_app_data_dir()
        assert isinstance(data_dir, Path)
        assert "adversary-mcp-server" in str(data_dir)

    def test_get_app_metrics_dir(self):
        """Test metrics directory configuration."""
        metrics_dir = get_app_metrics_dir()
        assert isinstance(metrics_dir, Path)
        assert "adversary-mcp-server" in str(metrics_dir)


class TestSecurityConfig:
    """Test SecurityConfig class."""

    def test_security_config_initialization(self):
        """Test SecurityConfig initialization."""
        config = SecurityConfig()

        # Test default values
        assert hasattr(config, "enable_semgrep_scanning")
        assert hasattr(config, "enable_caching")
        assert hasattr(config, "max_file_size_mb")
        assert hasattr(config, "llm_provider")
        assert hasattr(config, "llm_api_key")

        # Test boolean defaults
        assert isinstance(config.enable_semgrep_scanning, bool)
        assert isinstance(config.enable_caching, bool)

        # Test numeric defaults
        assert isinstance(config.max_file_size_mb, int)
        assert config.max_file_size_mb > 0

    def test_security_config_custom_values(self):
        """Test SecurityConfig with custom values."""
        config = SecurityConfig()
        config.enable_semgrep_scanning = False
        config.max_file_size_mb = 5
        config.llm_provider = "openai"

        assert config.enable_semgrep_scanning is False
        assert config.max_file_size_mb == 5
        assert config.llm_provider == "openai"

    def test_security_config_semgrep_options(self):
        """Test SecurityConfig Semgrep-related options."""
        config = SecurityConfig()

        # Test Semgrep configuration attributes exist
        assert hasattr(config, "semgrep_config")
        assert hasattr(config, "semgrep_rules")

        # Test that they can be set
        config.semgrep_config = "auto"
        config.semgrep_rules = ["python.lang.security"]

        assert config.semgrep_config == "auto"
        assert config.semgrep_rules == ["python.lang.security"]

    def test_security_config_llm_options(self):
        """Test SecurityConfig LLM-related options."""
        config = SecurityConfig()

        # Test LLM configuration attributes exist
        assert hasattr(config, "llm_model")
        assert hasattr(config, "llm_batch_size")
        assert hasattr(config, "llm_max_tokens")

        # Test that they can be set
        config.llm_model = "gpt-4"
        config.llm_batch_size = 10
        config.llm_max_tokens = 8000

        assert config.llm_model == "gpt-4"
        assert config.llm_batch_size == 10
        assert config.llm_max_tokens == 8000

    def test_security_config_cache_options(self):
        """Test SecurityConfig cache-related options."""
        config = SecurityConfig()

        # Test cache configuration attributes exist
        assert hasattr(config, "cache_max_size_mb")
        assert hasattr(config, "cache_max_age_hours")
        assert hasattr(config, "cache_llm_responses")

        # Test that they can be set
        config.cache_max_size_mb = 200
        config.cache_max_age_hours = 48
        config.cache_llm_responses = True

        assert config.cache_max_size_mb == 200
        assert config.cache_max_age_hours == 48
        assert config.cache_llm_responses is True
