"""Corrected tests for credential manager module with actual interfaces."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.credentials import (
    CredentialDecryptionError,
    CredentialError,
    CredentialManager,
    CredentialNotFoundError,
    CredentialStorageError,
    SecurityConfig,
)


class TestSecurityConfigCorrected:
    """Test SecurityConfig with actual structure."""

    def test_security_config_defaults(self):
        """Test SecurityConfig default values."""
        config = SecurityConfig()

        # Check LLM Configuration
        assert config.enable_llm_analysis is True

        # Check Scanner Configuration
        assert config.enable_semgrep_scanning is True

        # Check Exploit Generation
        assert config.enable_exploit_generation is True
        assert config.exploit_safety_mode is True

        # Check Analysis Configuration
        assert config.max_file_size_mb == 10
        assert config.timeout_seconds == 300

        # Check Rule Configuration
        assert config.severity_threshold == "medium"

    def test_security_config_custom_values(self):
        """Test SecurityConfig with custom values."""
        config = SecurityConfig(
            enable_llm_analysis=True,
            severity_threshold="high",
            exploit_safety_mode=False,
            max_file_size_mb=20,
        )

        assert config.enable_llm_analysis is True
        assert config.severity_threshold == "high"
        assert config.exploit_safety_mode is False
        assert config.max_file_size_mb == 20

    def test_security_config_is_dataclass(self):
        """Test that SecurityConfig is a dataclass with expected fields."""
        config = SecurityConfig()

        # Check that it's a dataclass with expected fields
        expected_fields = {
            "enable_llm_analysis",
            "enable_llm_validation",
            "llm_provider",
            "llm_api_key",
            "llm_model",
            "llm_temperature",
            "llm_max_tokens",
            "llm_batch_size",
            "enable_semgrep_scanning",
            "semgrep_config",
            "semgrep_rules",
            "semgrep_api_key",
            "enable_exploit_generation",
            "exploit_safety_mode",
            "max_file_size_mb",
            "timeout_seconds",
            "severity_threshold",
            "enable_caching",
            "cache_max_size_mb",
            "cache_max_age_hours",
            "cache_llm_responses",
            "validation_fallback_mode",
            "fallback_confidence_threshold",
            "high_severity_always_suspicious",
        }

        actual_fields = set(config.__dict__.keys())

        # Check that all expected fields are present
        for field in expected_fields:
            assert field in actual_fields, f"Missing field: {field}"


class TestCredentialManagerCorrected:
    """Test CredentialManager with actual methods."""

    def test_credential_manager_initialization(self):
        """Test CredentialManager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))
            assert manager.config_dir == Path(temp_dir)
            assert manager.config_file == Path(temp_dir) / "config.json"

    def test_credential_manager_custom_config_dir(self):
        """Test CredentialManager with custom config directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_dir = Path(temp_dir) / "custom_config"
            manager = CredentialManager(config_dir=custom_dir)

            assert manager.config_dir == custom_dir
            assert manager.config_file == custom_dir / "config.json"
            assert custom_dir.exists()  # Directory should be created

    def test_has_config_method(self):
        """Test that CredentialManager has has_config method."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))
            assert hasattr(manager, "has_config")
            assert callable(manager.has_config)

    def test_store_and_load_config(self):
        """Test storing and loading configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create a config
            config = SecurityConfig(
                enable_llm_analysis=True,
                llm_provider="openai",
                llm_api_key="test-key",
            )

            # Store config
            manager.store_config(config)

            # Load config
            loaded_config = manager.load_config()
            assert loaded_config is not None
            assert loaded_config.enable_llm_analysis is True
            assert loaded_config.llm_provider == "openai"
            assert loaded_config.llm_api_key == "test-key"

    def test_load_config_default_when_missing(self):
        """Test loading configuration returns default when none exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Load config when none exists
            config = manager.load_config()

            assert config is not None
            # Should have default values
            assert config.enable_llm_analysis is True

    def test_delete_config(self):
        """Test deleting configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store a config
            config = SecurityConfig(llm_provider="anthropic")
            manager.store_config(config)

            # Verify it exists
            assert manager.has_config() is True

            # Delete it
            manager.delete_config()

            # Verify it's gone
            assert manager.has_config() is False

    def test_machine_id_generation(self):
        """Test _get_machine_id generates consistent ID."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            machine_id_1 = manager._get_machine_id()
            machine_id_2 = manager._get_machine_id()

            assert machine_id_1 == machine_id_2
            assert len(machine_id_1) > 0

    def test_encryption_methods(self):
        """Test encryption and decryption methods."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            test_data = "sensitive data"
            password = "test_password"

            # Encrypt
            encrypted = manager._encrypt_data(test_data, password)
            assert "encrypted_data" in encrypted
            assert "salt" in encrypted

            # Decrypt
            decrypted = manager._decrypt_data(
                encrypted["encrypted_data"], encrypted["salt"], password
            )

            assert decrypted == test_data

    def test_decrypt_with_wrong_password(self):
        """Test decryption fails with wrong password."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            test_data = "sensitive data"
            password = "correct_password"
            wrong_password = "wrong_password"

            # Encrypt with correct password
            encrypted = manager._encrypt_data(test_data, password)

            # Try to decrypt with wrong password
            with pytest.raises(CredentialDecryptionError):
                manager._decrypt_data(
                    encrypted["encrypted_data"], encrypted["salt"], wrong_password
                )

    def test_credential_exceptions(self):
        """Test credential exception classes."""
        # Test base exception
        base_ex = CredentialError("Base error")
        assert str(base_ex) == "Base error"

        # Test not found exception
        not_found_ex = CredentialNotFoundError("Not found")
        assert isinstance(not_found_ex, CredentialError)

        # Test storage exception
        storage_ex = CredentialStorageError("Storage failed")
        assert isinstance(storage_ex, CredentialError)

        # Test decryption exception
        decrypt_ex = CredentialDecryptionError("Decryption failed")
        assert isinstance(decrypt_ex, CredentialError)

    def test_config_file_creation(self):
        """Test that config can be stored and retrieved."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Initially no config
            assert not manager.has_config()

            # Store config
            config = SecurityConfig()
            manager.store_config(config)

            # Config should be retrievable now (either from keyring or file)
            assert manager.has_config()
            loaded = manager.load_config()
            assert loaded is not None

    def test_concurrent_config_access(self):
        """Test that multiple CredentialManager instances share config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager1 = CredentialManager(config_dir=Path(temp_dir))
            manager2 = CredentialManager(config_dir=Path(temp_dir))

            # Store config with first manager
            config = SecurityConfig(llm_provider="openai")
            manager1.store_config(config)

            # Load with second manager
            loaded_config = manager2.load_config()
            assert loaded_config.llm_provider == "openai"

    def test_config_directory_permissions(self):
        """Test config directory is created with proper permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_dir = Path(temp_dir) / "secure_config"
            manager = CredentialManager(config_dir=custom_dir)

            assert custom_dir.exists()
            # Directory should be created
            assert manager.config_dir.is_dir()

    def test_config_with_none_values(self):
        """Test configuration with None values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Test data
            config = SecurityConfig(enable_llm_analysis=False)

            # Store config
            manager.store_config(config)
            loaded_config = manager.load_config()

            assert loaded_config.enable_llm_analysis is False

    def test_config_caching(self):
        """Test that configuration is cached in memory to reduce keychain access."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Initial state - no cache
            assert manager._config_cache is None
            assert manager._cache_loaded is False

            # Store a config
            config = SecurityConfig(llm_provider="anthropic")
            manager.store_config(config)

            # Cache should be updated
            assert manager._config_cache is not None
            assert manager._cache_loaded is True
            assert manager._config_cache.llm_provider == "anthropic"

    def test_load_config_uses_cache(self):
        """Test that load_config uses cache when available."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store a config
            config = SecurityConfig(llm_provider="openai", llm_api_key="key1")
            manager.store_config(config)

            # Load config - this should populate cache
            loaded1 = manager.load_config()
            assert loaded1.llm_api_key == "key1"

            # Manually modify cache
            manager._config_cache.llm_api_key = "cached_key"

            # Load again - should use cache
            loaded2 = manager.load_config()
            assert loaded2.llm_api_key == "cached_key"

    def test_delete_config_clears_cache(self):
        """Test that delete_config clears the cache."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store a config
            config = SecurityConfig(llm_provider="openai")
            manager.store_config(config)

            # Cache should be populated
            assert manager._config_cache is not None
            assert manager._cache_loaded is True

            # Delete config
            manager.delete_config()

            # Cache should be cleared
            assert manager._config_cache is None
            assert manager._cache_loaded is False

    def test_has_config_uses_cache(self):
        """Test that has_config uses cache when loaded."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Initially no config
            assert manager.has_config() is False

            # Store a config
            config = SecurityConfig(llm_provider="openai")
            manager.store_config(config)

            # Cache should be loaded
            assert manager._cache_loaded is True

            # has_config should use cache
            assert manager.has_config() is True

    @patch("adversary_mcp_server.credentials.keyring")
    def test_cache_reduces_keyring_calls(self, mock_keyring):
        """Test that caching reduces the number of keyring access calls."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Mock keyring to succeed
            config_dict = {"enable_llm_analysis": True, "severity_threshold": "high"}
            mock_keyring.get_password.return_value = json.dumps(
                {
                    "enable_llm_analysis": True,
                    "severity_threshold": "high",
                    "enable_semgrep_scanning": True,
                    "semgrep_config": None,
                    "semgrep_rules": None,
                    "enable_exploit_generation": True,
                    "exploit_safety_mode": True,
                    "max_file_size_mb": 10,
                    "timeout_seconds": 300,
                }
            )
            mock_keyring.set_password.return_value = None

            # First load_config call
            config1 = manager.load_config()
            first_call_count = mock_keyring.get_password.call_count

            # Second load_config call should use cache
            config2 = manager.load_config()
            second_call_count = mock_keyring.get_password.call_count

            # Should not have made additional keyring calls
            assert second_call_count == first_call_count
            assert config1.enable_llm_analysis == config2.enable_llm_analysis
