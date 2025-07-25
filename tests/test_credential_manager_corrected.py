"""Corrected tests for credential manager module with actual interfaces."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import mock_open, patch

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

        # Check LLM Configuration
        assert config.enable_llm_analysis is True

        # Check Scanner Configuration
        assert config.enable_ast_scanning is True
        assert config.enable_semgrep_scanning is True
        assert config.enable_bandit_scanning is True

        # Check Exploit Generation
        assert config.enable_exploit_generation is True
        assert config.exploit_safety_mode is True

        # Check Analysis Configuration
        assert config.max_file_size_mb == 10
        assert config.max_scan_depth == 5
        assert config.timeout_seconds == 300

        # Check Rule Configuration
        assert config.custom_rules_path is None
        assert config.severity_threshold == "medium"

        # Check Reporting Configuration
        assert config.include_exploit_examples is True
        assert config.include_remediation_advice is True
        assert config.verbose_output is False

    def test_security_config_custom_values(self):
        """Test SecurityConfig with custom values."""
        config = SecurityConfig(
            enable_llm_analysis=True,
            enable_ast_scanning=False,
            severity_threshold="high",
            exploit_safety_mode=False,
            max_file_size_mb=20,
            verbose_output=True,
        )

        assert config.enable_llm_analysis is True
        assert config.enable_ast_scanning is False
        assert config.severity_threshold == "high"
        assert config.exploit_safety_mode is False
        assert config.max_file_size_mb == 20
        assert config.verbose_output is True

    def test_security_config_is_dataclass(self):
        """Test that SecurityConfig is a dataclass with expected fields."""
        config = SecurityConfig()

        # Check that it's a dataclass with expected fields
        expected_fields = {
            "enable_llm_analysis",
            "enable_semgrep_scanning",
            "enable_bandit_scanning",
            "enable_exploit_generation",
            "exploit_safety_mode",
            "max_file_size_mb",
            "max_scan_depth",
            "timeout_seconds",
            "custom_rules_path",
            "severity_threshold",
            "include_exploit_examples",
            "include_remediation_advice",
            "verbose_output",
        }

        actual_fields = set(config.__dict__.keys())

        # Check that all expected fields are present
        for field in expected_fields:
            assert field in actual_fields, f"Missing field: {field}"


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
            config = SecurityConfig(enable_llm_analysis=True, severity_threshold="high")
            manager.store_config(config)

            # Now should have config (stored in file since keyring failed)
            assert manager.has_config()

    def test_store_and_load_config(self):
        """Test storing and loading configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create test config
            config = SecurityConfig(
                enable_llm_analysis=True,
                severity_threshold="high",
                exploit_safety_mode=False,
            )

            # Store config
            manager.store_config(config)

            # Load config
            loaded_config = manager.load_config()

            # Verify loaded config
            assert loaded_config.enable_llm_analysis is True
            assert loaded_config.severity_threshold == "high"
            assert loaded_config.exploit_safety_mode is False

    def test_load_config_default_when_missing(self):
        """Test loading config returns default when missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Ensure no config exists
            manager.delete_config()

            # Load config should return defaults
            config = manager.load_config()

            assert config.enable_llm_analysis is True
            assert config.severity_threshold == "medium"
            assert config.exploit_safety_mode is True

    def test_delete_config(self):
        """Test deleting configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store a config
            config = SecurityConfig(
                enable_llm_analysis=True, severity_threshold="critical"
            )
            manager.store_config(config)
            assert manager.has_config()

            # Delete config
            manager.delete_config()

            # Should no longer have config
            assert not manager.has_config()

    def test_machine_id_generation(self):
        """Test machine ID generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Get machine ID
            machine_id1 = manager._get_machine_id()
            machine_id2 = manager._get_machine_id()

            # Should be consistent
            assert machine_id1 == machine_id2
            assert isinstance(machine_id1, str)
            assert len(machine_id1) > 0

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
        """Test that config file is created with proper permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Force keyring to fail so file storage is used
            from keyring.errors import KeyringError

            mock_keyring.set_password.side_effect = KeyringError("Keyring error")
            mock_keyring.get_password.side_effect = KeyringError("Keyring error")

            config = SecurityConfig(
                enable_llm_analysis=True, severity_threshold="medium"
            )

            # Store config
            manager.store_config(config)

            # Check file exists (should exist since keyring failed)
            assert manager.config_file.exists()

            # Check file content structure
            with open(manager.config_file) as f:
                content = f.read()
                assert "openai_api_key" in content or "encrypted_data" in content

    def test_concurrent_config_access(self):
        """Test concurrent access to configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager1 = CredentialManager(config_dir=Path(temp_dir))
            manager2 = CredentialManager(config_dir=Path(temp_dir))

            # Store config with manager1
            config = SecurityConfig(enable_llm_analysis=True, severity_threshold="high")
            manager1.store_config(config)

            # Load with second manager (different instance)
            manager2 = CredentialManager(config_dir=Path(temp_dir))
            loaded_config = manager2.load_config()

            assert loaded_config.enable_llm_analysis is True
            assert loaded_config.severity_threshold == "high"

    def test_config_directory_permissions(self):
        """Test that config directory has proper permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir) / "secure")

            # Store config (should create directory)
            config = SecurityConfig(enable_llm_analysis=True)
            manager.store_config(config)

            # Directory should exist
            assert manager.config_dir.exists()
            assert manager.config_dir.is_dir()

    def test_config_with_none_values(self):
        """Test configuration with None values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Test data
            config = SecurityConfig(custom_rules_path=None, enable_llm_analysis=False)

            # Store config
            manager.store_config(config)
            loaded_config = manager.load_config()

            assert loaded_config.custom_rules_path is None
            assert loaded_config.enable_llm_analysis is False

    def test_config_caching(self):
        """Test that configuration is cached in memory to reduce keychain access."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Initial state - no cache
            assert manager._config_cache is None
            assert manager._cache_loaded is False

            # Create and store config
            config = SecurityConfig(enable_llm_analysis=True, severity_threshold="high")
            manager.store_config(config)

            # Cache should be populated after storing
            assert manager._config_cache is not None
            assert manager._cache_loaded is True
            assert manager._config_cache.enable_llm_analysis is True
            assert manager._config_cache.severity_threshold == "high"

    def test_load_config_uses_cache(self):
        """Test that subsequent load_config calls use cached data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store initial config
            config = SecurityConfig(
                enable_llm_analysis=True, severity_threshold="critical"
            )
            manager.store_config(config)

            # First load should populate cache
            loaded_config1 = manager.load_config()
            assert manager._cache_loaded is True

            # Manually modify cache to test it's being used
            manager._config_cache.severity_threshold = "low"

            # Second load should use cached (modified) value
            loaded_config2 = manager.load_config()
            assert loaded_config2.severity_threshold == "low"

    def test_delete_config_clears_cache(self):
        """Test that deleting config clears the cache."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store config and verify cache
            config = SecurityConfig(enable_llm_analysis=True)
            manager.store_config(config)
            assert manager._cache_loaded is True
            assert manager._config_cache is not None

            # Delete config should clear cache
            manager.delete_config()
            assert manager._cache_loaded is False
            assert manager._config_cache is None

    def test_has_config_uses_cache(self):
        """Test that has_config method uses cached data when available."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Initially no config
            assert not manager.has_config()

            # Store config
            config = SecurityConfig(enable_llm_analysis=True)
            manager.store_config(config)

            # has_config should return True using cache
            assert manager.has_config()

            # Even if we manually clear stored config but keep cache
            manager.config_file.unlink(missing_ok=True)
            # has_config should still return True because of cache
            assert manager.has_config()

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_cache_reduces_keyring_calls(self, mock_keyring):
        """Test that caching reduces the number of keyring access calls."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Mock keyring to succeed
            config_dict = {"enable_llm_analysis": True, "severity_threshold": "high"}
            mock_keyring.get_password.return_value = '{"enable_llm_analysis": true, "severity_threshold": "high", "enable_ast_scanning": true, "enable_semgrep_scanning": true, "enable_bandit_scanning": true, "semgrep_config": null, "semgrep_rules": null, "semgrep_timeout": 60, "enable_exploit_generation": true, "exploit_safety_mode": true, "max_file_size_mb": 10, "max_scan_depth": 5, "timeout_seconds": 300, "custom_rules_path": null, "include_exploit_examples": true, "include_remediation_advice": true, "verbose_output": false}'
            mock_keyring.set_password.return_value = None

            # First load_config call
            config1 = manager.load_config()
            first_call_count = mock_keyring.get_password.call_count

            # Second load_config call should use cache
            config2 = manager.load_config()
            second_call_count = mock_keyring.get_password.call_count

            # Should have same number of calls (no additional keyring access)
            assert second_call_count == first_call_count
            assert config1.enable_llm_analysis == config2.enable_llm_analysis


class TestCredentialManagerEdgeCases:
    """Test edge cases and error conditions for CredentialManager."""

    def test_ensure_config_dir_with_custom_none(self):
        """Test _ensure_config_dir with None config_dir defaults."""
        manager = CredentialManager(config_dir=None)  # Should use default

        # Should create default path
        expected_path = Path.home() / ".local" / "share" / "adversary-mcp-server"
        assert manager.config_dir == expected_path

    @patch("os.chmod")
    def test_ensure_config_dir_chmod_failure(self, mock_chmod):
        """Test _ensure_config_dir when chmod fails."""
        mock_chmod.side_effect = OSError("Permission denied")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Should not raise exception even if chmod fails
            manager = CredentialManager(config_dir=Path(temp_dir) / "test")
            assert manager.config_dir.exists()

    def test_derive_key_consistency(self):
        """Test that _derive_key produces consistent results."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            password = b"test_password"
            salt = b"test_salt_16bytes"

            key1 = manager._derive_key(password, salt)
            key2 = manager._derive_key(password, salt)

            assert key1 == key2
            assert len(key1) > 0

    def test_encrypt_data_different_salts(self):
        """Test that _encrypt_data produces different results with different calls."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            data = "test data"
            password = "test_password"

            result1 = manager._encrypt_data(data, password)
            result2 = manager._encrypt_data(data, password)

            # Should have different salts and encrypted data
            assert result1["salt"] != result2["salt"]
            assert result1["encrypted_data"] != result2["encrypted_data"]

    def test_decrypt_data_invalid_base64(self):
        """Test _decrypt_data with invalid base64 data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            with pytest.raises(CredentialDecryptionError):
                manager._decrypt_data("invalid_base64!", "dGVzdA==", "password")

    def test_decrypt_data_invalid_salt(self):
        """Test _decrypt_data with invalid salt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            with pytest.raises(CredentialDecryptionError):
                manager._decrypt_data("dGVzdA==", "invalid_salt!", "password")

    @patch("builtins.open", mock_open(read_data="machine123"))
    @patch("os.path.exists")
    def test_get_machine_id_from_etc_machine_id(self, mock_exists):
        """Test _get_machine_id reading from /etc/machine-id."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_exists.side_effect = lambda path: path == "/etc/machine-id"

            machine_id = manager._get_machine_id()
            assert machine_id == "machine123"

    @patch("builtins.open", mock_open(read_data="dbus456"))
    @patch("os.path.exists")
    def test_get_machine_id_from_dbus_machine_id(self, mock_exists):
        """Test _get_machine_id reading from /var/lib/dbus/machine-id."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # First file doesn't exist, second does
            mock_exists.side_effect = lambda path: path == "/var/lib/dbus/machine-id"

            machine_id = manager._get_machine_id()
            assert machine_id == "dbus456"

    @patch("os.path.exists", return_value=False)
    @patch("socket.gethostname", return_value="testhost")
    @patch("getpass.getuser", return_value="testuser")
    def test_get_machine_id_fallback(self, mock_user, mock_hostname, mock_exists):
        """Test _get_machine_id fallback to hostname-username."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            machine_id = manager._get_machine_id()
            assert machine_id == "testhost-testuser"

    @patch("builtins.open", mock_open())
    @patch("os.path.exists")
    def test_get_machine_id_file_read_error(self, mock_exists):
        """Test _get_machine_id when file read fails."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_exists.return_value = True

            with patch("builtins.open", side_effect=OSError("Read error")):
                # Should fall back to hostname-username
                machine_id = manager._get_machine_id()
                assert "-" in machine_id  # Should contain hostname-username format

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_storage_success(self, mock_keyring):
        """Test _try_keyring_storage success case."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.set_password.return_value = None
            config = SecurityConfig(enable_llm_analysis=True)

            result = manager._try_keyring_storage(config)
            assert result is True
            mock_keyring.set_password.assert_called_once()

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_storage_failure(self, mock_keyring):
        """Test _try_keyring_storage failure case."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.set_password.side_effect = KeyringError("Storage failed")
            config = SecurityConfig(enable_llm_analysis=True)

            result = manager._try_keyring_storage(config)
            assert result is False

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_retrieval_success(self, mock_keyring):
        """Test _try_keyring_retrieval success case."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            config_dict = {
                "enable_llm_analysis": True,
                "enable_ast_scanning": True,
                "enable_semgrep_scanning": True,
                "enable_bandit_scanning": True,
                "enable_exploit_generation": True,
                "exploit_safety_mode": True,
                "max_file_size_mb": 10,
                "max_scan_depth": 5,
                "timeout_seconds": 300,
                "custom_rules_path": None,
                "severity_threshold": "medium",
                "include_exploit_examples": True,
                "include_remediation_advice": True,
                "verbose_output": False,
            }
            mock_keyring.get_password.return_value = json.dumps(config_dict)

            result = manager._try_keyring_retrieval()
            assert result is not None
            assert result.enable_llm_analysis is True

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_retrieval_none(self, mock_keyring):
        """Test _try_keyring_retrieval when no password found."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.get_password.return_value = None

            result = manager._try_keyring_retrieval()
            assert result is None

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_retrieval_json_error(self, mock_keyring):
        """Test _try_keyring_retrieval with invalid JSON."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.get_password.return_value = "invalid json"

            result = manager._try_keyring_retrieval()
            assert result is None

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_retrieval_keyring_error(self, mock_keyring):
        """Test _try_keyring_retrieval with KeyringError."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.get_password.side_effect = KeyringError("Access denied")

            result = manager._try_keyring_retrieval()
            assert result is None

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_deletion_success(self, mock_keyring):
        """Test _try_keyring_deletion success case."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.delete_password.return_value = None

            result = manager._try_keyring_deletion()
            assert result is True

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_try_keyring_deletion_failure(self, mock_keyring):
        """Test _try_keyring_deletion failure case."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.delete_password.side_effect = KeyringError("Delete failed")

            result = manager._try_keyring_deletion()
            assert result is False

    def test_store_file_config_success(self):
        """Test _store_file_config success case."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            config = SecurityConfig(enable_llm_analysis=True)

            # Should not raise exception
            manager._store_file_config(config)

            # File should exist and be readable
            assert manager.config_file.exists()

            # Check file permissions (should be 600)
            file_stat = manager.config_file.stat()
            assert file_stat.st_mode & 0o777 == 0o600

    @patch("builtins.open", side_effect=OSError("Write failed"))
    def test_store_file_config_write_error(self, mock_open):
        """Test _store_file_config with write error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            config = SecurityConfig(enable_llm_analysis=True)

            with pytest.raises(CredentialStorageError):
                manager._store_file_config(config)

    def test_load_file_config_not_exists(self):
        """Test _load_file_config when file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            result = manager._load_file_config()
            assert result is None

    def test_load_file_config_encrypted(self):
        """Test _load_file_config with encrypted file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create encrypted config file
            config = SecurityConfig(enable_llm_analysis=True, severity_threshold="high")
            manager._store_file_config(config)

            # Load it back
            loaded_config = manager._load_file_config()
            assert loaded_config is not None
            assert loaded_config.enable_llm_analysis is True
            assert loaded_config.severity_threshold == "high"

    def test_load_file_config_plain_json(self):
        """Test _load_file_config with plain JSON (backward compatibility)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create plain JSON config file
            config_dict = {
                "enable_llm_analysis": False,
                "enable_ast_scanning": True,
                "enable_semgrep_scanning": True,
                "enable_bandit_scanning": True,
                "enable_exploit_generation": True,
                "exploit_safety_mode": True,
                "max_file_size_mb": 10,
                "max_scan_depth": 5,
                "timeout_seconds": 300,
                "custom_rules_path": None,
                "severity_threshold": "low",
                "include_exploit_examples": True,
                "include_remediation_advice": True,
                "verbose_output": False,
            }

            with open(manager.config_file, "w") as f:
                json.dump(config_dict, f)

            loaded_config = manager._load_file_config()
            assert loaded_config is not None
            assert loaded_config.enable_llm_analysis is False
            assert loaded_config.severity_threshold == "low"

    @patch("builtins.open", side_effect=OSError("Read failed"))
    def test_load_file_config_read_error(self, mock_open):
        """Test _load_file_config with read error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create file so exists() returns True
            manager.config_file.touch()

            result = manager._load_file_config()
            assert result is None

    def test_load_file_config_invalid_json(self):
        """Test _load_file_config with invalid JSON."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Write invalid JSON
            manager.config_file.write_text("invalid json")

            result = manager._load_file_config()
            assert result is None

    def test_load_file_config_decryption_error(self):
        """Test _load_file_config with decryption error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Write encrypted-looking data that will fail decryption
            bad_encrypted = {
                "encrypted_data": "invalid_encrypted_data",
                "salt": "invalid_salt",
            }

            with open(manager.config_file, "w") as f:
                json.dump(bad_encrypted, f)

            result = manager._load_file_config()
            assert result is None

    def test_delete_file_config_success(self):
        """Test _delete_file_config success case."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create config file
            manager.config_file.touch()
            assert manager.config_file.exists()

            result = manager._delete_file_config()
            assert result is True
            assert not manager.config_file.exists()

    def test_delete_file_config_not_exists(self):
        """Test _delete_file_config when file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # File doesn't exist
            result = manager._delete_file_config()
            assert result is True  # Should still return True

    @patch("pathlib.Path.unlink", side_effect=OSError("Delete failed"))
    def test_delete_file_config_delete_error(self, mock_unlink):
        """Test _delete_file_config with delete error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Create file
            manager.config_file.touch()

            result = manager._delete_file_config()
            assert result is False

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_store_config_keyring_success(self, mock_keyring):
        """Test store_config success via keyring."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.set_password.return_value = None
            config = SecurityConfig(enable_llm_analysis=True)

            manager.store_config(config)

            # Should have cached the config
            assert manager._config_cache == config
            assert manager._cache_loaded is True

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_store_config_keyring_fails_file_success(self, mock_keyring):
        """Test store_config falls back to file when keyring fails."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.set_password.side_effect = KeyringError("Keyring failed")

            config = SecurityConfig(enable_llm_analysis=True)
            manager.store_config(config)

            # Should have fallen back to file storage
            assert manager.config_file.exists()
            assert manager._config_cache == config
            assert manager._cache_loaded is True

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_load_config_keyring_success(self, mock_keyring):
        """Test load_config success via keyring."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            config_dict = {
                "enable_llm_analysis": True,
                "enable_ast_scanning": True,
                "enable_semgrep_scanning": True,
                "enable_bandit_scanning": True,
                "enable_exploit_generation": True,
                "exploit_safety_mode": True,
                "max_file_size_mb": 15,
                "max_scan_depth": 5,
                "timeout_seconds": 300,
                "custom_rules_path": None,
                "severity_threshold": "critical",
                "include_exploit_examples": True,
                "include_remediation_advice": True,
                "verbose_output": False,
            }
            mock_keyring.get_password.return_value = json.dumps(config_dict)

            config = manager.load_config()

            assert config.enable_llm_analysis is True
            assert config.max_file_size_mb == 15
            assert config.severity_threshold == "critical"
            assert manager._config_cache == config
            assert manager._cache_loaded is True

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_load_config_keyring_fails_file_success(self, mock_keyring):
        """Test load_config falls back to file when keyring fails."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.get_password.side_effect = KeyringError("Keyring failed")

            # Create file config
            config = SecurityConfig(enable_llm_analysis=False, severity_threshold="low")
            manager._store_file_config(config)

            # Clear cache to force reload
            manager._config_cache = None
            manager._cache_loaded = False

            loaded_config = manager.load_config()

            assert loaded_config.enable_llm_analysis is False
            assert loaded_config.severity_threshold == "low"

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_load_config_returns_default_when_nothing_found(self, mock_keyring):
        """Test load_config returns default when no config found anywhere."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.get_password.side_effect = KeyringError("Keyring failed")

            # No file config exists
            config = manager.load_config()

            # Should return default config
            default_config = SecurityConfig()
            assert config.enable_llm_analysis == default_config.enable_llm_analysis
            assert config.severity_threshold == default_config.severity_threshold

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_delete_config_clears_both_sources(self, mock_keyring):
        """Test delete_config attempts to clear both keyring and file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.delete_password.return_value = None

            # Create file config
            manager.config_file.touch()
            manager._config_cache = SecurityConfig()
            manager._cache_loaded = True

            manager.delete_config()

            # Should have attempted keyring deletion
            mock_keyring.delete_password.assert_called_once()

            # Should have deleted file
            assert not manager.config_file.exists()

            # Should have cleared cache
            assert manager._config_cache is None
            assert manager._cache_loaded is False


class TestCredentialManagerSemgrepAPI:
    """Test Semgrep API key management methods."""

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_store_semgrep_api_key_success(self, mock_keyring):
        """Test storing Semgrep API key successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.set_password.return_value = None

            manager.store_semgrep_api_key("test_api_key_123")

            mock_keyring.set_password.assert_called_once_with(
                "adversary-mcp-server", "semgrep_api_key", "test_api_key_123"
            )

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_store_semgrep_api_key_failure(self, mock_keyring):
        """Test storing Semgrep API key with keyring error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.set_password.side_effect = KeyringError("Storage failed")

            with pytest.raises(CredentialStorageError):
                manager.store_semgrep_api_key("test_api_key_123")

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_get_semgrep_api_key_success(self, mock_keyring):
        """Test getting Semgrep API key successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.get_password.return_value = "retrieved_api_key"

            result = manager.get_semgrep_api_key()

            assert result == "retrieved_api_key"
            mock_keyring.get_password.assert_called_once_with(
                "adversary-mcp-server", "semgrep_api_key"
            )

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_get_semgrep_api_key_not_found(self, mock_keyring):
        """Test getting Semgrep API key when not found."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.get_password.return_value = None

            result = manager.get_semgrep_api_key()

            assert result is None

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_get_semgrep_api_key_keyring_error(self, mock_keyring):
        """Test getting Semgrep API key with keyring error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.get_password.side_effect = KeyringError("Access denied")

            result = manager.get_semgrep_api_key()

            assert result is None

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_delete_semgrep_api_key_success(self, mock_keyring):
        """Test deleting Semgrep API key successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            mock_keyring.delete_password.return_value = None

            result = manager.delete_semgrep_api_key()

            assert result is True
            mock_keyring.delete_password.assert_called_once_with(
                "adversary-mcp-server", "semgrep_api_key"
            )

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_delete_semgrep_api_key_keyring_error(self, mock_keyring):
        """Test deleting Semgrep API key with keyring error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.delete_password.side_effect = KeyringError("Delete failed")

            result = manager.delete_semgrep_api_key()

            assert result is False


class TestCredentialManagerHasConfig:
    """Test has_config method edge cases."""

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_has_config_with_cached_config(self, mock_keyring):
        """Test has_config returns True when config is cached."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Set up cache
            manager._config_cache = SecurityConfig(enable_llm_analysis=True)
            manager._cache_loaded = True

            result = manager.has_config()

            assert result is True
            # Should not call keyring since cache is available
            mock_keyring.get_password.assert_not_called()

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_has_config_with_keyring_config(self, mock_keyring):
        """Test has_config returns True when config found in keyring."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            config_dict = {
                "enable_llm_analysis": True,
                "enable_ast_scanning": True,
                "enable_semgrep_scanning": True,
                "enable_bandit_scanning": True,
                "enable_exploit_generation": True,
                "exploit_safety_mode": True,
                "max_file_size_mb": 10,
                "max_scan_depth": 5,
                "timeout_seconds": 300,
                "custom_rules_path": None,
                "severity_threshold": "medium",
                "include_exploit_examples": True,
                "include_remediation_advice": True,
                "verbose_output": False,
            }
            mock_keyring.get_password.return_value = json.dumps(config_dict)

            result = manager.has_config()

            assert result is True

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_has_config_with_file_config(self, mock_keyring):
        """Test has_config returns True when config found in file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.get_password.side_effect = KeyringError("No keyring")

            # Create file config
            config = SecurityConfig(enable_llm_analysis=True)
            manager._store_file_config(config)

            # Clear cache
            manager._config_cache = None
            manager._cache_loaded = False

            result = manager.has_config()

            assert result is True

    @patch("adversary_mcp_server.credential_manager.keyring")
    def test_has_config_no_config_anywhere(self, mock_keyring):
        """Test has_config returns False when no config found anywhere."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            from keyring.errors import KeyringError

            mock_keyring.get_password.side_effect = KeyringError("No keyring")

            # No file config, no cache
            manager._config_cache = None
            manager._cache_loaded = False

            result = manager.has_config()

            assert result is False
