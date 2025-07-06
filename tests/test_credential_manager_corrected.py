"""Corrected tests for credential manager module with actual interfaces."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.credential_manager import (
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

        assert config.openai_api_key == ""
        assert config.openai_model == "gpt-4"
        assert config.openai_max_tokens == 2048
        assert config.enable_ast_scanning is True
        assert config.enable_exploit_generation is True
        assert config.exploit_safety_mode is True
        assert config.max_file_size_mb == 10
        assert config.max_scan_depth == 5
        assert config.timeout_seconds == 300
        assert config.severity_threshold == "medium"
        assert config.include_exploit_examples is True
        assert config.include_remediation_advice is True
        assert config.verbose_output is False

    def test_security_config_custom_values(self):
        """Test SecurityConfig with custom values."""
        config = SecurityConfig(
            openai_api_key="sk-custom123",
            openai_model="gpt-3.5-turbo",
            openai_max_tokens=1024,
            enable_ast_scanning=False,
            enable_exploit_generation=False,
            exploit_safety_mode=False,
            max_file_size_mb=20,
            max_scan_depth=10,
            timeout_seconds=600,
            severity_threshold="high",
            include_exploit_examples=False,
            include_remediation_advice=False,
            verbose_output=True,
        )

        assert config.openai_api_key == "sk-custom123"
        assert config.openai_model == "gpt-3.5-turbo"
        assert config.openai_max_tokens == 1024
        assert config.enable_ast_scanning is False
        assert config.enable_exploit_generation is False
        assert config.exploit_safety_mode is False
        assert config.max_file_size_mb == 20
        assert config.max_scan_depth == 10
        assert config.timeout_seconds == 600
        assert config.severity_threshold == "high"
        assert config.include_exploit_examples is False
        assert config.include_remediation_advice is False
        assert config.verbose_output is True

    def test_security_config_is_dataclass(self):
        """Test that SecurityConfig is a dataclass."""
        config = SecurityConfig()

        # Should be able to convert to dict using asdict
        from dataclasses import asdict

        config_dict = asdict(config)
        assert isinstance(config_dict, dict)
        assert "openai_api_key" in config_dict
        assert "openai_model" in config_dict


class TestCredentialManagerCorrected:
    """Test CredentialManager with actual interfaces."""

    def test_credential_manager_initialization(self):
        """Test CredentialManager initialization."""
        manager = CredentialManager()

        # Check default paths
        assert manager.config_dir.name == "adversary-mcp-server"
        assert manager.config_file.name == "config.json"
        assert manager.keyring_service == "adversary-mcp-server"

    def test_credential_manager_custom_config_dir(self):
        """Test CredentialManager with custom config directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_dir = Path(temp_dir) / "custom_config"
            manager = CredentialManager(config_dir=custom_dir)

            assert manager.config_dir == custom_dir
            assert manager.config_file == custom_dir / "config.json"

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_has_config_method(self, mock_keyring):
        """Test has_config method."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Force keyring to fail so no config is found initially
            from keyring.errors import KeyringError

            mock_keyring.get_password.side_effect = KeyringError("No config")

            # Initially no config (since keyring fails and no file exists)
            assert not manager.has_config()

            # Configure keyring to also fail on store, so it falls back to file
            mock_keyring.set_password.side_effect = KeyringError("Store failed")

            # Create a config
            config = SecurityConfig(openai_api_key="sk-test123")
            manager.store_config(config)

            # Now should have config (stored in file since keyring failed)
            assert manager.has_config()

    def test_store_and_load_config(self):
        """Test storing and loading config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create test config
            config = SecurityConfig(
                openai_api_key="sk-test123",
                openai_model="gpt-4",
                enable_exploit_generation=True,
                severity_threshold="high",
            )

            # Store config
            manager.store_config(config)

            # Load config
            loaded_config = manager.load_config()

            # Verify loaded config
            assert loaded_config.openai_api_key == "sk-test123"
            assert loaded_config.openai_model == "gpt-4"
            assert loaded_config.enable_exploit_generation is True
            assert loaded_config.severity_threshold == "high"

    def test_load_config_default_when_missing(self):
        """Test loading default config when file missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Load config when file doesn't exist
            config = manager.load_config()

            # Should return default config
            assert isinstance(config, SecurityConfig)
            # Note: config may have values from environment or other sources
            assert config.openai_model == "gpt-4"

    def test_delete_config(self):
        """Test deleting config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store a config
            config = SecurityConfig(openai_api_key="sk-to-delete")
            manager.store_config(config)
            assert manager.has_config()

            # Delete config
            manager.delete_config()

            # Should no longer have config
            assert not manager.has_config()

    def test_get_openai_api_key(self):
        """Test getting OpenAI API key."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # No config initially
            assert manager.get_openai_api_key() is None

            # Store config with API key
            config = SecurityConfig(openai_api_key="sk-test-key")
            manager.store_config(config)

            # Should retrieve API key
            assert manager.get_openai_api_key() == "sk-test-key"

    def test_update_openai_api_key(self):
        """Test updating OpenAI API key."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Update API key
            manager.update_openai_api_key("sk-new-key")

            # Should be stored
            assert manager.get_openai_api_key() == "sk-new-key"

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_keyring_fallback(self, mock_keyring):
        """Test keyring fallback when keyring fails."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Configure keyring to fail on store but succeed on load (for this test)
            from keyring.errors import KeyringError

            mock_keyring.set_password.side_effect = KeyringError("Keyring error")
            mock_keyring.get_password.side_effect = KeyringError("Keyring error")

            config = SecurityConfig(openai_api_key="sk-fallback-test")

            # Should fallback to file storage
            manager.store_config(config)

            # Should be able to load
            loaded_config = manager.load_config()
            assert loaded_config.openai_api_key == "sk-fallback-test"

    def test_machine_id_generation(self):
        """Test machine ID generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Should generate some machine ID
            machine_id = manager._get_machine_id()
            assert isinstance(machine_id, str)
            assert len(machine_id) > 0

    def test_encryption_methods(self):
        """Test encryption and decryption methods."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Test data
            test_data = "sensitive information"
            password = "test_password"

            # Encrypt
            encrypted = manager._encrypt_data(test_data, password)
            assert isinstance(encrypted, dict)
            assert "encrypted_data" in encrypted
            assert "salt" in encrypted

            # Decrypt
            decrypted = manager._decrypt_data(
                encrypted["encrypted_data"], encrypted["salt"], password
            )
            assert decrypted == test_data

    def test_decrypt_with_wrong_password(self):
        """Test decryption with wrong password."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            test_data = "sensitive information"
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
        """Test credential exception hierarchy."""
        # Test base exception
        error = CredentialError("Base error")
        assert str(error) == "Base error"

        # Test specific exceptions
        not_found = CredentialNotFoundError("Not found")
        assert str(not_found) == "Not found"
        assert isinstance(not_found, CredentialError)

        storage_error = CredentialStorageError("Storage failed")
        assert str(storage_error) == "Storage failed"
        assert isinstance(storage_error, CredentialError)

        decrypt_error = CredentialDecryptionError("Decryption failed")
        assert str(decrypt_error) == "Decryption failed"
        assert isinstance(decrypt_error, CredentialError)

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_config_file_creation(self, mock_keyring):
        """Test that config file is created properly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Force keyring to fail so file storage is used
            from keyring.errors import KeyringError

            mock_keyring.set_password.side_effect = KeyringError("Keyring error")
            mock_keyring.get_password.side_effect = KeyringError("Keyring error")

            config = SecurityConfig(openai_api_key="sk-file-test", verbose_output=True)

            # Store config
            manager.store_config(config)

            # Check file exists (should exist since keyring failed)
            assert manager.config_file.exists()

            # Check file content structure
            with open(manager.config_file, "r") as f:
                content = f.read()
                assert "openai_api_key" in content or "encrypted_data" in content

    def test_concurrent_config_access(self):
        """Test concurrent access to config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager1 = CredentialManager(config_dir=Path(temp_dir))
            manager2 = CredentialManager(config_dir=Path(temp_dir))

            # Store config with manager1
            config1 = SecurityConfig(openai_api_key="sk-concurrent1")
            manager1.store_config(config1)

            # Read with manager2
            config2 = manager2.load_config()
            assert config2.openai_api_key == "sk-concurrent1"

            # Update with manager2
            config2.openai_api_key = "sk-concurrent2"
            manager2.store_config(config2)

            # Read with manager1
            config3 = manager1.load_config()
            assert config3.openai_api_key == "sk-concurrent2"

    def test_config_directory_permissions(self):
        """Test config directory permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir) / "secure")

            # Store config (should create directory)
            config = SecurityConfig(openai_api_key="sk-permissions")
            manager.store_config(config)

            # Directory should exist
            assert manager.config_dir.exists()
            assert manager.config_dir.is_dir()

    def test_config_with_none_values(self):
        """Test config with None values."""
        config = SecurityConfig(
            openai_api_key=None, custom_rules_path=None  # This should work
        )

        # None should be converted to empty string for API key
        assert config.openai_api_key is None or config.openai_api_key == ""
        assert config.custom_rules_path is None
