"""Secure credential management for Adversary MCP server."""

import getpass
import json
import os
import socket
import stat
from base64 import b64decode, b64encode
from dataclasses import asdict
from pathlib import Path

import keyring
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from keyring.errors import KeyringError

from .security_config import SecurityConfig


class CredentialError(Exception):
    """Base exception for credential errors."""

    pass


class CredentialNotFoundError(CredentialError):
    """Exception raised when credentials are not found."""

    pass


class CredentialStorageError(CredentialError):
    """Exception raised when credential storage fails."""

    pass


class CredentialDecryptionError(CredentialError):
    """Exception raised when credential decryption fails."""

    pass


class CredentialManager:
    """Secure credential manager for Adversary MCP server configuration."""

    def __init__(self, config_dir: Path | None = None) -> None:
        """Initialize credential manager.

        Args:
            config_dir: Configuration directory (default: ~/.local/share/adversary-mcp-server)
        """
        if config_dir is None:
            config_dir = Path.home() / ".local" / "share" / "adversary-mcp-server"

        self.config_dir = config_dir
        self.config_file = config_dir / "config.json"
        self.keyring_service = "adversary-mcp-server"

        # In-memory cache to reduce keychain access
        self._config_cache: SecurityConfig | None = None
        self._cache_loaded = False

        # Ensure config directory exists with proper permissions
        self._ensure_config_dir()

    def _ensure_config_dir(self) -> None:
        """Ensure configuration directory exists with proper permissions."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions (owner only)
        try:
            self.config_dir.chmod(stat.S_IRWXU)  # 700
        except OSError:
            # May fail on some systems, but not critical
            pass

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive encryption key from password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return b64encode(kdf.derive(password))

    def _encrypt_data(self, data: str, password: str) -> dict[str, str]:
        """Encrypt data with password.

        Args:
            data: Data to encrypt
            password: Password for encryption

        Returns:
            Dictionary with encrypted data and salt
        """
        salt = os.urandom(16)
        key = self._derive_key(password.encode(), salt)
        f = Fernet(key)

        encrypted_data = f.encrypt(data.encode())

        return {
            "encrypted_data": b64encode(encrypted_data).decode(),
            "salt": b64encode(salt).decode(),
        }

    def _decrypt_data(self, encrypted_data: str, salt: str, password: str) -> str:
        """Decrypt data with password.

        Args:
            encrypted_data: Encrypted data
            salt: Salt used for encryption
            password: Password for decryption

        Returns:
            Decrypted data

        Raises:
            CredentialDecryptionError: If decryption fails
        """
        try:
            salt_bytes = b64decode(salt.encode())
            key = self._derive_key(password.encode(), salt_bytes)
            f = Fernet(key)

            encrypted_bytes = b64decode(encrypted_data.encode())
            decrypted_data = f.decrypt(encrypted_bytes)

            return decrypted_data.decode()
        except (InvalidToken, ValueError, UnicodeDecodeError) as e:
            raise CredentialDecryptionError(f"Failed to decrypt data: {e}")

    def _get_machine_id(self) -> str:
        """Get a machine-specific identifier for encryption."""
        # Try to get a machine-specific ID
        machine_id = None

        # Try /etc/machine-id (Linux)
        if os.path.exists("/etc/machine-id"):
            try:
                with open("/etc/machine-id") as f:
                    machine_id = f.read().strip()
            except OSError:
                pass

        # Try /var/lib/dbus/machine-id (Linux)
        if not machine_id and os.path.exists("/var/lib/dbus/machine-id"):
            try:
                with open("/var/lib/dbus/machine-id") as f:
                    machine_id = f.read().strip()
            except OSError:
                pass

        # Fallback to hostname + username
        if not machine_id:
            machine_id = f"{socket.gethostname()}-{getpass.getuser()}"

        return machine_id

    def _try_keyring_storage(self, config: SecurityConfig) -> bool:
        """Try to store configuration using keyring.

        Args:
            config: Security configuration to store

        Returns:
            True if storage succeeded, False otherwise
        """
        try:
            config_json = json.dumps(asdict(config))
            keyring.set_password(self.keyring_service, "config", config_json)
            return True
        except KeyringError:
            return False

    def _try_keyring_retrieval(self) -> SecurityConfig | None:
        """Try to retrieve configuration from keyring.

        Returns:
            SecurityConfig if found, None otherwise
        """
        try:
            config_json = keyring.get_password(self.keyring_service, "config")
            if config_json:
                config_dict = json.loads(config_json)
                return SecurityConfig(**config_dict)
        except (KeyringError, json.JSONDecodeError, TypeError):
            pass
        return None

    def _try_keyring_deletion(self) -> bool:
        """Try to delete configuration from keyring.

        Returns:
            True if deletion succeeded, False otherwise
        """
        try:
            keyring.delete_password(self.keyring_service, "config")
            return True
        except KeyringError:
            return False

    def _store_file_config(self, config: SecurityConfig) -> None:
        """Store configuration in encrypted file.

        Args:
            config: Security configuration to store

        Raises:
            CredentialStorageError: If storage fails
        """
        try:
            config_json = json.dumps(asdict(config))
            machine_id = self._get_machine_id()
            encrypted_data = self._encrypt_data(config_json, machine_id)

            with open(self.config_file, "w") as f:
                json.dump(encrypted_data, f)

            # Set restrictive permissions
            self.config_file.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600

        except (OSError, json.JSONEncodeError) as e:
            raise CredentialStorageError(f"Failed to store configuration: {e}")

    def _load_file_config(self) -> SecurityConfig | None:
        """Load configuration from encrypted file.

        Returns:
            SecurityConfig if found and decrypted successfully, None otherwise
        """
        if not self.config_file.exists():
            return None

        try:
            with open(self.config_file) as f:
                data = json.load(f)

            # Check if this is an encrypted file (has encrypted_data and salt)
            if "encrypted_data" in data and "salt" in data:
                # Handle encrypted file
                machine_id = self._get_machine_id()
                config_json = self._decrypt_data(
                    data["encrypted_data"],
                    data["salt"],
                    machine_id,
                )
                config_dict = json.loads(config_json)
            else:
                # Handle plain JSON file (backward compatibility)
                config_dict = data

            return SecurityConfig(**config_dict)

        except (
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            CredentialDecryptionError,
        ):
            return None

    def _delete_file_config(self) -> bool:
        """Delete configuration file.

        Returns:
            True if deletion succeeded, False otherwise
        """
        try:
            if self.config_file.exists():
                self.config_file.unlink()
            return True
        except OSError:
            return False

    def store_config(self, config: SecurityConfig) -> None:
        """Store security configuration.

        Args:
            config: Security configuration to store

        Raises:
            CredentialStorageError: If storage fails in both keyring and file
        """
        # Try keyring first
        if self._try_keyring_storage(config):
            # Update cache on successful storage
            self._config_cache = config
            self._cache_loaded = True
            return

        # Fall back to encrypted file
        self._store_file_config(config)
        # Update cache on successful storage
        self._config_cache = config
        self._cache_loaded = True

    def load_config(self) -> SecurityConfig:
        """Load security configuration.

        Returns:
            SecurityConfig loaded from storage

        Raises:
            CredentialNotFoundError: If no configuration is found
        """
        # Return cached config if available
        if self._cache_loaded and self._config_cache is not None:
            return self._config_cache

        # Try keyring first
        config = self._try_keyring_retrieval()
        if config is not None:
            # Cache the loaded config
            self._config_cache = config
            self._cache_loaded = True
            return config

        # Try encrypted file
        config = self._load_file_config()
        if config is not None:
            # Cache the loaded config
            self._config_cache = config
            self._cache_loaded = True
            return config

        # Return default configuration if none found and cache it
        default_config = SecurityConfig()
        self._config_cache = default_config
        self._cache_loaded = True
        return default_config

    def delete_config(self) -> None:
        """Delete stored configuration."""
        # Try to delete from keyring
        self._try_keyring_deletion()

        # Try to delete file
        self._delete_file_config()

        # Clear cache
        self._config_cache = None
        self._cache_loaded = False

    def store_semgrep_api_key(self, api_key: str) -> None:
        """Store Semgrep API key securely.

        Args:
            api_key: Semgrep API key to store

        Raises:
            CredentialStorageError: If storage fails
        """
        try:
            keyring.set_password(self.keyring_service, "semgrep_api_key", api_key)
        except KeyringError as e:
            raise CredentialStorageError(f"Failed to store Semgrep API key: {e}")

    def get_semgrep_api_key(self) -> str | None:
        """Get stored Semgrep API key.

        Returns:
            API key if found, None otherwise
        """
        try:
            return keyring.get_password(self.keyring_service, "semgrep_api_key")
        except KeyringError:
            return None

    def delete_semgrep_api_key(self) -> bool:
        """Delete stored Semgrep API key.

        Returns:
            True if deletion succeeded, False otherwise
        """
        try:
            keyring.delete_password(self.keyring_service, "semgrep_api_key")
            return True
        except KeyringError:
            return False

    def has_config(self) -> bool:
        """Check if configuration exists and can be loaded.

        Returns:
            True if configuration exists and is valid, False otherwise
        """
        # If we have a cached config, return True
        if self._cache_loaded and self._config_cache is not None:
            return True

        # Check keyring
        if self._try_keyring_retrieval() is not None:
            return True

        # Check if file config can be loaded
        if self._load_file_config() is not None:
            return True

        return False
