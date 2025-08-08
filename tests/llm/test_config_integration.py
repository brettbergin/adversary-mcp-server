"""Tests for LLM configuration integration."""

from unittest.mock import MagicMock, patch

import pytest

from adversary_mcp_server.config import SecurityConfig
from adversary_mcp_server.credentials import get_credential_manager


class TestSecurityConfigLLM:
    """Test LLM-related SecurityConfig functionality."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SecurityConfig()

        assert config.enable_llm_analysis is True
        assert config.enable_llm_validation is True
        assert config.llm_provider is None
        assert config.llm_api_key is None
        assert config.llm_model is None
        assert config.llm_temperature == 0.1
        assert config.llm_max_tokens == 4000
        assert config.llm_batch_size == 10

    def test_validate_llm_configuration_disabled(self):
        """Test validation when LLM is disabled."""
        config = SecurityConfig(enable_llm_analysis=False, enable_llm_validation=False)

        is_valid, error = config.validate_llm_configuration()
        assert is_valid is True
        assert error == ""

    def test_validate_llm_configuration_no_provider(self):
        """Test validation when no provider is configured."""
        config = SecurityConfig(enable_llm_analysis=True, llm_provider=None)

        is_valid, error = config.validate_llm_configuration()
        assert is_valid is False
        assert "LLM provider not configured" in error

    def test_validate_llm_configuration_invalid_provider(self):
        """Test validation with invalid provider."""
        config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="invalid-provider"
        )

        is_valid, error = config.validate_llm_configuration()
        assert is_valid is False
        assert "Invalid LLM provider" in error

    def test_validate_llm_configuration_no_api_key(self):
        """Test validation when no API key is configured."""
        config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key=None
        )

        is_valid, error = config.validate_llm_configuration()
        assert is_valid is False
        assert "API key not configured" in error

    def test_validate_llm_configuration_valid_openai(self):
        """Test validation with valid OpenAI configuration."""
        config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )

        is_valid, error = config.validate_llm_configuration()
        assert is_valid is True
        assert error == ""

    def test_validate_llm_configuration_valid_anthropic(self):
        """Test validation with valid Anthropic configuration."""
        config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="anthropic",
            llm_api_key="anthropic-key",
        )

        is_valid, error = config.validate_llm_configuration()
        assert is_valid is True
        assert error == ""

    def test_is_llm_analysis_available_disabled(self):
        """Test LLM availability when disabled."""
        config = SecurityConfig(enable_llm_analysis=False, enable_llm_validation=False)

        assert config.is_llm_analysis_available() is False

    def test_is_llm_analysis_available_valid_config(self):
        """Test LLM availability with valid configuration."""
        config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )

        assert config.is_llm_analysis_available() is True

    def test_is_llm_analysis_available_validation_only(self):
        """Test LLM availability with only validation enabled."""
        config = SecurityConfig(
            enable_llm_analysis=False,
            enable_llm_validation=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
        )

        assert config.is_llm_analysis_available() is True

    def test_get_configuration_summary(self):
        """Test configuration summary generation."""
        config = SecurityConfig(
            enable_llm_analysis=True,
            enable_llm_validation=True,
            llm_provider="openai",
            llm_model="gpt-4",
            llm_api_key="sk-test-key",
        )

        summary = config.get_configuration_summary()

        assert summary["llm_analysis_enabled"] is True
        assert summary["llm_validation_enabled"] is True
        assert summary["llm_analysis_available"] is True
        assert summary["llm_provider"] == "openai"
        assert summary["llm_model"] == "gpt-4"
        assert summary["llm_configured"] is True
        assert summary["llm_configuration_error"] is None

    def test_get_configuration_summary_with_error(self):
        """Test configuration summary with configuration error."""
        config = SecurityConfig(enable_llm_analysis=True, llm_provider=None)

        summary = config.get_configuration_summary()

        assert summary["llm_configured"] is False
        assert summary["llm_configuration_error"] is not None
        assert "LLM provider not configured" in summary["llm_configuration_error"]


class TestCredentialManagerLLM:
    """Test LLM-related CredentialManager functionality."""

    def test_store_llm_api_key_openai(self):
        """Test storing OpenAI API key."""
        with patch("keyring.set_password") as mock_set:
            manager = get_credential_manager()
            manager.store_llm_api_key("openai", "sk-test-key")

            mock_set.assert_called_once_with(
                "adversary-mcp-server", "llm_openai_api_key", "sk-test-key"
            )

    def test_store_llm_api_key_anthropic(self):
        """Test storing Anthropic API key."""
        with patch("keyring.set_password") as mock_set:
            manager = get_credential_manager()
            manager.store_llm_api_key("anthropic", "anthropic-key")

            mock_set.assert_called_once_with(
                "adversary-mcp-server", "llm_anthropic_api_key", "anthropic-key"
            )

    def test_store_llm_api_key_invalid_provider(self):
        """Test storing API key with invalid provider."""
        manager = get_credential_manager()

        with pytest.raises(ValueError, match="Invalid LLM provider"):
            manager.store_llm_api_key("invalid", "key")

    def test_get_llm_api_key_openai(self):
        """Test getting OpenAI API key."""
        with patch("keyring.get_password", return_value="sk-test-key") as mock_get:
            manager = get_credential_manager()
            key = manager.get_llm_api_key("openai")

            assert key == "sk-test-key"
            mock_get.assert_called_once_with(
                "adversary-mcp-server", "llm_openai_api_key"
            )

    def test_get_llm_api_key_not_found(self):
        """Test getting API key when not found."""
        with patch("keyring.get_password", return_value=None):
            manager = get_credential_manager()
            key = manager.get_llm_api_key("openai")

            assert key is None

    def test_get_llm_api_key_invalid_provider(self):
        """Test getting API key with invalid provider."""
        manager = get_credential_manager()
        key = manager.get_llm_api_key("invalid")

        assert key is None

    def test_delete_llm_api_key_openai(self):
        """Test deleting OpenAI API key."""
        with patch("keyring.delete_password", return_value=None) as mock_delete:
            manager = get_credential_manager()
            result = manager.delete_llm_api_key("openai")

            assert result is True
            mock_delete.assert_called_once_with(
                "adversary-mcp-server", "llm_openai_api_key"
            )

    def test_delete_llm_api_key_invalid_provider(self):
        """Test deleting API key with invalid provider."""
        manager = get_credential_manager()
        result = manager.delete_llm_api_key("invalid")

        assert result is False

    def test_get_configured_llm_provider(self):
        """Test getting configured LLM provider."""
        mock_config = MagicMock()
        mock_config.llm_provider = "openai"

        manager = get_credential_manager()
        with patch.object(manager, "load_config", return_value=mock_config):
            provider = manager.get_configured_llm_provider()

            assert provider == "openai"

    def test_clear_llm_configuration(self):
        """Test clearing LLM configuration."""
        mock_config = SecurityConfig()
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "sk-test-key"
        mock_config.llm_model = "gpt-4"

        manager = get_credential_manager()
        with patch.object(manager, "load_config", return_value=mock_config):
            with patch.object(manager, "store_config") as mock_store:
                with patch.object(manager, "delete_llm_api_key") as mock_delete:
                    manager.clear_llm_configuration()

                    # Check that API keys were deleted
                    assert mock_delete.call_count == 2
                    mock_delete.assert_any_call("openai")
                    mock_delete.assert_any_call("anthropic")

                    # Check that config was cleared
                    assert mock_config.llm_provider is None
                    assert mock_config.llm_api_key is None
                    assert mock_config.llm_model is None

                    mock_store.assert_called_once_with(mock_config)
