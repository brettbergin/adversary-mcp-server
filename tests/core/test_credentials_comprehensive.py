"""Comprehensive tests for credential management."""

import json
import stat
import tempfile
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest
from keyring.errors import KeyringError

from src.adversary_mcp_server.config import SecurityConfig
from src.adversary_mcp_server.credentials import (
    CredentialDecryptionError,
    CredentialError,
    CredentialManager,
    CredentialNotFoundError,
    CredentialStorageError,
    get_credential_manager,
    reset_credential_manager,
)


class TestCredentialExceptions:
    """Test credential exception classes."""

    def test_credential_error(self):
        """Test base CredentialError exception."""
        error = CredentialError("test error")
        assert str(error) == "test error"
        assert isinstance(error, Exception)

    def test_credential_not_found_error(self):
        """Test CredentialNotFoundError exception."""
        error = CredentialNotFoundError("not found")
        assert str(error) == "not found"
        assert isinstance(error, CredentialError)

    def test_credential_storage_error(self):
        """Test CredentialStorageError exception."""
        error = CredentialStorageError("storage failed")
        assert str(error) == "storage failed"
        assert isinstance(error, CredentialError)

    def test_credential_decryption_error(self):
        """Test CredentialDecryptionError exception."""
        error = CredentialDecryptionError("decryption failed")
        assert str(error) == "decryption failed"
        assert isinstance(error, CredentialError)


class TestCredentialManagerSingleton:
    """Test CredentialManager singleton behavior."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    def test_singleton_pattern(self):
        """Test that CredentialManager follows singleton pattern."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"

            # Create two instances with same config_dir
            manager1 = CredentialManager(config_dir)
            manager2 = CredentialManager(config_dir)

            # Should be the same instance
            assert manager1 is manager2
            assert id(manager1) == id(manager2)

    def test_get_credential_manager_singleton(self):
        """Test get_credential_manager function returns singleton."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"

            # First call creates instance
            manager1 = get_credential_manager(config_dir)
            # Second call returns same instance
            manager2 = get_credential_manager()

            assert manager1 is manager2

    def test_reset_credential_manager(self):
        """Test resetting the credential manager."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"

            # Create initial instance
            manager1 = get_credential_manager(config_dir)
            manager1._config_cache = Mock()
            manager1._cache_loaded = True

            # Reset
            reset_credential_manager()

            # New instance should be different
            manager2 = get_credential_manager(config_dir)
            assert manager1 is not manager2
            assert not manager2._cache_loaded


class TestCredentialManagerInit:
    """Test CredentialManager initialization."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    def test_init_with_custom_config_dir(self):
        """Test initialization with custom config directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "custom_config"

            manager = CredentialManager(config_dir)

            assert manager.config_dir == config_dir
            assert manager.config_file == config_dir / "config.json"
            assert manager.keyring_service == "adversary-mcp-server"
            assert not manager._cache_loaded
            assert manager._config_cache is None

    def test_init_with_default_config_dir(self):
        """Test initialization with default config directory."""
        manager = CredentialManager()

        expected_dir = Path.home() / ".local" / "share" / "adversary-mcp-server"
        assert manager.config_dir == expected_dir

    def test_init_creates_config_directory(self):
        """Test that initialization creates config directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "new_config"
            assert not config_dir.exists()

            CredentialManager(config_dir)

            assert config_dir.exists()
            assert config_dir.is_dir()

    @patch("src.adversary_mcp_server.credentials.Path.chmod")
    def test_init_sets_directory_permissions(self, mock_chmod):
        """Test that initialization sets restrictive permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"

            CredentialManager(config_dir)

            mock_chmod.assert_called_with(stat.S_IRWXU)

    @patch("src.adversary_mcp_server.credentials.Path.chmod")
    def test_init_handles_permission_error(self, mock_chmod):
        """Test that initialization handles permission errors gracefully."""
        mock_chmod.side_effect = OSError("Permission denied")

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"

            # Should not raise exception
            manager = CredentialManager(config_dir)
            assert manager.config_dir == config_dir


class TestCredentialManagerEncryption:
    """Test encryption and decryption functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    def test_derive_key(self):
        """Test key derivation from password and salt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            password = b"test_password"
            salt = b"test_salt_123456"

            key1 = manager._derive_key(password, salt)
            key2 = manager._derive_key(password, salt)

            # Same inputs should produce same key
            assert key1 == key2
            assert isinstance(key1, bytes)
            assert len(key1) > 0

    def test_derive_key_different_inputs(self):
        """Test that different inputs produce different keys."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            password1 = b"password1"
            password2 = b"password2"
            salt = b"same_salt_123456"

            key1 = manager._derive_key(password1, salt)
            key2 = manager._derive_key(password2, salt)

            assert key1 != key2

    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            original_data = "sensitive configuration data"
            password = "encryption_password"

            # Encrypt data
            encrypted_result = manager._encrypt_data(original_data, password)

            assert "encrypted_data" in encrypted_result
            assert "salt" in encrypted_result
            assert isinstance(encrypted_result["encrypted_data"], str)
            assert isinstance(encrypted_result["salt"], str)

            # Decrypt data
            decrypted_data = manager._decrypt_data(
                encrypted_result["encrypted_data"], encrypted_result["salt"], password
            )

            assert decrypted_data == original_data

    def test_decrypt_with_wrong_password(self):
        """Test decryption with wrong password raises error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            original_data = "sensitive data"
            correct_password = "correct_password"
            wrong_password = "wrong_password"

            encrypted_result = manager._encrypt_data(original_data, correct_password)

            with pytest.raises(CredentialDecryptionError):
                manager._decrypt_data(
                    encrypted_result["encrypted_data"],
                    encrypted_result["salt"],
                    wrong_password,
                )

    def test_decrypt_with_invalid_data(self):
        """Test decryption with invalid data raises error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            with pytest.raises(CredentialDecryptionError):
                manager._decrypt_data("invalid_data", "invalid_salt", "password")


class TestCredentialManagerMachineId:
    """Test machine ID functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="machine123")
    def test_get_machine_id_linux_etc(self, mock_file, mock_exists):
        """Test getting machine ID from /etc/machine-id."""
        # Mock /etc/machine-id exists
        mock_exists.side_effect = lambda path: path == "/etc/machine-id"

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            machine_id = manager._get_machine_id()

            assert machine_id == "machine123"
            mock_file.assert_called_with("/etc/machine-id")

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="dbus456")
    def test_get_machine_id_linux_dbus(self, mock_file, mock_exists):
        """Test getting machine ID from /var/lib/dbus/machine-id."""
        # Mock /var/lib/dbus/machine-id exists but not /etc/machine-id
        mock_exists.side_effect = lambda path: path == "/var/lib/dbus/machine-id"

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            machine_id = manager._get_machine_id()

            assert machine_id == "dbus456"

    @patch("os.path.exists", return_value=False)
    @patch("socket.gethostname", return_value="testhost")
    @patch("getpass.getuser", return_value="testuser")
    def test_get_machine_id_fallback(self, mock_getuser, mock_hostname, mock_exists):
        """Test machine ID fallback to hostname-username."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            machine_id = manager._get_machine_id()

            assert machine_id == "testhost-testuser"

    @patch("os.path.exists")
    @patch("builtins.open", side_effect=OSError("Permission denied"))
    @patch("socket.gethostname", return_value="testhost")
    @patch("getpass.getuser", return_value="testuser")
    def test_get_machine_id_file_error(
        self, mock_getuser, mock_hostname, mock_file, mock_exists
    ):
        """Test machine ID with file read error falls back."""
        mock_exists.return_value = True

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            machine_id = manager._get_machine_id()

            assert machine_id == "testhost-testuser"


class TestCredentialManagerKeyring:
    """Test keyring operations."""

    def setup_method(self):
        """Setup test fixtures."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    @patch("src.adversary_mcp_server.credentials.keyring.set_password")
    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_try_keyring_storage_success(self, mock_get, mock_set):
        """Test successful keyring storage."""
        mock_get.return_value = '{"llm_provider": "openai"}'

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = SecurityConfig(llm_provider="openai")
            result = manager._try_keyring_storage(config)

            assert result is True
            mock_set.assert_called_once()

    @patch("src.adversary_mcp_server.credentials.keyring.set_password")
    def test_try_keyring_storage_keyring_error(self, mock_set):
        """Test keyring storage with KeyringError."""
        mock_set.side_effect = KeyringError("Keyring not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = SecurityConfig(llm_provider="openai")
            result = manager._try_keyring_storage(config)

            assert result is False

    @patch("src.adversary_mcp_server.credentials.keyring.set_password")
    def test_try_keyring_storage_unexpected_error(self, mock_set):
        """Test keyring storage with unexpected error."""
        mock_set.side_effect = Exception("Unexpected error")

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = SecurityConfig(llm_provider="openai")
            result = manager._try_keyring_storage(config)

            assert result is False

    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_try_keyring_retrieval_success(self, mock_get):
        """Test successful keyring retrieval."""
        config_data = {
            "llm_provider": "openai",
            "llm_model": "gpt-4",
            "llm_api_key": None,
        }
        mock_get.return_value = json.dumps(config_data)

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = manager._try_keyring_retrieval()

            assert config is not None
            assert config.llm_provider == "openai"
            assert config.llm_model == "gpt-4"

    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_try_keyring_retrieval_not_found(self, mock_get):
        """Test keyring retrieval when no config found."""
        mock_get.return_value = None

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = manager._try_keyring_retrieval()

            assert config is None

    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_try_keyring_retrieval_json_error(self, mock_get):
        """Test keyring retrieval with JSON decode error."""
        mock_get.return_value = "invalid json"

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = manager._try_keyring_retrieval()

            assert config is None

    @patch("src.adversary_mcp_server.credentials.keyring.delete_password")
    def test_try_keyring_deletion_success(self, mock_delete):
        """Test successful keyring deletion."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            result = manager._try_keyring_deletion()

            assert result is True
            mock_delete.assert_called_once_with("adversary-mcp-server", "config")

    @patch("src.adversary_mcp_server.credentials.keyring.delete_password")
    def test_try_keyring_deletion_error(self, mock_delete):
        """Test keyring deletion with error."""
        mock_delete.side_effect = KeyringError("Delete failed")

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            result = manager._try_keyring_deletion()

            assert result is False


class TestCredentialManagerAPIKeys:
    """Test API key storage and retrieval."""

    def setup_method(self):
        """Setup test fixtures."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    @patch("src.adversary_mcp_server.credentials.keyring.set_password")
    def test_store_llm_api_key_success(self, mock_set):
        """Test successful LLM API key storage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            manager.store_llm_api_key("openai", "sk-test123")

            mock_set.assert_called_once_with(
                "adversary-mcp-server", "llm_openai_api_key", "sk-test123"
            )

    def test_store_llm_api_key_invalid_provider(self):
        """Test storing LLM API key with invalid provider."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            with pytest.raises(ValueError, match="Invalid LLM provider"):
                manager.store_llm_api_key("invalid", "key123")

    @patch("src.adversary_mcp_server.credentials.keyring.set_password")
    def test_store_llm_api_key_keyring_error(self, mock_set):
        """Test LLM API key storage with keyring error."""
        mock_set.side_effect = KeyringError("Storage failed")

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            with pytest.raises(CredentialStorageError):
                manager.store_llm_api_key("openai", "sk-test123")

    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_get_llm_api_key_success(self, mock_get):
        """Test successful LLM API key retrieval."""
        mock_get.return_value = "sk-test123"

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            api_key = manager.get_llm_api_key("openai")

            assert api_key == "sk-test123"
            mock_get.assert_called_once_with(
                "adversary-mcp-server", "llm_openai_api_key"
            )

    def test_get_llm_api_key_invalid_provider(self):
        """Test getting LLM API key with invalid provider."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            api_key = manager.get_llm_api_key("invalid")

            assert api_key is None

    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_get_llm_api_key_not_found(self, mock_get):
        """Test getting LLM API key when not found."""
        mock_get.return_value = None

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            api_key = manager.get_llm_api_key("openai")

            assert api_key is None

    @patch("src.adversary_mcp_server.credentials.keyring.delete_password")
    def test_delete_llm_api_key_success(self, mock_delete):
        """Test successful LLM API key deletion."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            result = manager.delete_llm_api_key("anthropic")

            assert result is True
            mock_delete.assert_called_once_with(
                "adversary-mcp-server", "llm_anthropic_api_key"
            )

    def test_delete_llm_api_key_invalid_provider(self):
        """Test deleting LLM API key with invalid provider."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            result = manager.delete_llm_api_key("invalid")

            assert result is False

    @patch("src.adversary_mcp_server.credentials.keyring.set_password")
    def test_store_semgrep_api_key_success(self, mock_set):
        """Test successful Semgrep API key storage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            manager.store_semgrep_api_key("sgp_test123")

            mock_set.assert_called_once_with(
                "adversary-mcp-server", "semgrep_api_key", "sgp_test123"
            )

    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_get_semgrep_api_key_success(self, mock_get):
        """Test successful Semgrep API key retrieval."""
        mock_get.return_value = "sgp_test123"

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            api_key = manager.get_semgrep_api_key()

            assert api_key == "sgp_test123"

    @patch("src.adversary_mcp_server.credentials.keyring.delete_password")
    def test_delete_semgrep_api_key_success(self, mock_delete):
        """Test successful Semgrep API key deletion."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            result = manager.delete_semgrep_api_key()

            assert result is True
            mock_delete.assert_called_once_with(
                "adversary-mcp-server", "semgrep_api_key"
            )


class TestCredentialManagerFileOperations:
    """Test file storage operations."""

    def setup_method(self):
        """Setup test fixtures."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    def test_store_file_config_success(self):
        """Test successful file config storage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = SecurityConfig(llm_provider="openai")

            # Should not raise exception
            manager._store_file_config(config)

            # File should exist
            assert manager.config_file.exists()

            # File should have restrictive permissions
            file_mode = manager.config_file.stat().st_mode
            # Check that only owner has read/write permissions
            assert file_mode & stat.S_IRWXU  # Owner has read/write/execute
            assert not (file_mode & stat.S_IRWXG)  # Group has no permissions
            assert not (file_mode & stat.S_IRWXO)  # Others have no permissions

    def test_load_file_config_encrypted_success(self):
        """Test successful encrypted file config loading."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            # Store a config first
            original_config = SecurityConfig(llm_provider="openai", llm_model="gpt-4")
            manager._store_file_config(original_config)

            # Load it back
            loaded_config = manager._load_file_config()

            assert loaded_config is not None
            assert loaded_config.llm_provider == "openai"
            assert loaded_config.llm_model == "gpt-4"

    def test_load_file_config_not_exists(self):
        """Test loading file config when file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = manager._load_file_config()

            assert config is None

    def test_load_file_config_plain_json_compatibility(self):
        """Test loading plain JSON config for backward compatibility."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            # Create plain JSON config file
            plain_config = {"llm_provider": "anthropic", "llm_model": "claude-3"}
            with open(manager.config_file, "w") as f:
                json.dump(plain_config, f)

            config = manager._load_file_config()

            assert config is not None
            assert config.llm_provider == "anthropic"
            assert config.llm_model == "claude-3"

    def test_delete_file_config_success(self):
        """Test successful file config deletion."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            # Create a config file first
            config = SecurityConfig(llm_provider="openai")
            manager._store_file_config(config)
            assert manager.config_file.exists()

            # Delete it
            result = manager._delete_file_config()

            assert result is True
            assert not manager.config_file.exists()

    def test_delete_file_config_not_exists(self):
        """Test deleting file config when file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            result = manager._delete_file_config()

            assert result is True


class TestCredentialManagerHighLevel:
    """Test high-level credential manager operations."""

    def setup_method(self):
        """Setup test fixtures."""
        reset_credential_manager()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_credential_manager()

    @patch(
        "src.adversary_mcp_server.credentials.CredentialManager._try_keyring_storage"
    )
    def test_store_config_keyring_success(self, mock_keyring_store):
        """Test config storage when keyring succeeds."""
        mock_keyring_store.return_value = True

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = SecurityConfig(llm_provider="openai", llm_api_key="sk-test")
            manager.store_config(config)

            # Cache should be updated
            assert manager._cache_loaded is True
            assert manager._config_cache == config
            mock_keyring_store.assert_called_once()

    @patch(
        "src.adversary_mcp_server.credentials.CredentialManager._try_keyring_storage"
    )
    @patch("src.adversary_mcp_server.credentials.CredentialManager._store_file_config")
    def test_store_config_keyring_fallback(self, mock_file_store, mock_keyring_store):
        """Test config storage falls back to file when keyring fails."""
        mock_keyring_store.return_value = False

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            config = SecurityConfig(llm_provider="openai")
            manager.store_config(config)

            mock_keyring_store.assert_called_once()
            mock_file_store.assert_called_once()

    def test_has_config_with_cache(self):
        """Test has_config when config is cached."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            # Setup cache
            manager._config_cache = SecurityConfig()
            manager._cache_loaded = True

            assert manager.has_config() is True

    @patch(
        "src.adversary_mcp_server.credentials.CredentialManager._try_keyring_retrieval"
    )
    def test_has_config_with_keyring(self, mock_keyring_get):
        """Test has_config when config is in keyring."""
        mock_keyring_get.return_value = SecurityConfig()

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            assert manager.has_config() is True

    @patch(
        "src.adversary_mcp_server.credentials.CredentialManager._try_keyring_retrieval"
    )
    @patch("src.adversary_mcp_server.credentials.CredentialManager._load_file_config")
    def test_has_config_with_file(self, mock_file_load, mock_keyring_get):
        """Test has_config when config is in file."""
        mock_keyring_get.return_value = None
        mock_file_load.return_value = SecurityConfig()

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            assert manager.has_config() is True

    @patch(
        "src.adversary_mcp_server.credentials.CredentialManager._try_keyring_retrieval"
    )
    @patch("src.adversary_mcp_server.credentials.CredentialManager._load_file_config")
    def test_has_config_none_found(self, mock_file_load, mock_keyring_get):
        """Test has_config when no config found."""
        mock_keyring_get.return_value = None
        mock_file_load.return_value = None

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            assert manager.has_config() is False

    def test_get_configured_llm_provider(self):
        """Test getting configured LLM provider."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            # Setup cache with provider
            config = SecurityConfig(llm_provider="anthropic")
            manager._config_cache = config
            manager._cache_loaded = True

            provider = manager.get_configured_llm_provider()

            assert provider == "anthropic"

    @patch("src.adversary_mcp_server.credentials.CredentialManager.delete_llm_api_key")
    @patch("src.adversary_mcp_server.credentials.CredentialManager.load_config")
    @patch("src.adversary_mcp_server.credentials.CredentialManager.store_config")
    def test_clear_llm_configuration(self, mock_store, mock_load, mock_delete):
        """Test clearing LLM configuration."""
        mock_delete.return_value = True
        config = SecurityConfig(llm_provider="openai", llm_api_key="sk-test")
        mock_load.return_value = config

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            manager.clear_llm_configuration()

            # Should have called delete for both providers
            assert mock_delete.call_count == 2
            mock_store.assert_called_once()

    @patch("src.adversary_mcp_server.credentials.keyring.get_password")
    def test_debug_keyring_state(self, mock_get):
        """Test debug keyring state method."""

        # Mock keyring responses
        def mock_get_side_effect(service, key):
            if key == "config":
                return json.dumps({"llm_provider": "openai"})
            elif key == "llm_openai_api_key":
                return "sk-test123"
            return None

        mock_get.side_effect = mock_get_side_effect

        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            manager = CredentialManager(config_dir)

            state = manager.debug_keyring_state()

            assert "keyring_service" in state
            assert "main_config" in state
            assert "llm_openai_key" in state
            assert state["main_config"]["found"] is True
            assert state["llm_openai_key"]["found"] is True
