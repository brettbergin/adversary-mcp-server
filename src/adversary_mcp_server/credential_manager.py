"""Secure credential management for Adversary MCP server."""

import getpass
import json
import os
import socket
import stat
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

import keyring
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from keyring.errors import KeyringError


@dataclass
class SecurityConfig:
    """Security configuration for the adversary MCP server."""

    # LLM Configuration
    openai_api_key: str = ""
    openai_model: str = "gpt-4"
    openai_max_tokens: int = 2048
    enable_llm_analysis: bool = True  # Enable LLM-based security analysis

    # Scanner Configuration
    enable_ast_scanning: bool = True
    enable_semgrep_scanning: bool = True
    enable_bandit_scanning: bool = True

    # Exploit Generation
    enable_exploit_generation: bool = True
    exploit_safety_mode: bool = True  # Limit exploit generation to safe examples

    # Analysis Configuration
    max_file_size_mb: int = 10
    max_scan_depth: int = 5
    timeout_seconds: int = 300

    # Rule Configuration
    custom_rules_path: Optional[str] = None
    severity_threshold: str = "medium"  # low, medium, high, critical

    # Reporting Configuration
    include_exploit_examples: bool = True
    include_remediation_advice: bool = True
    verbose_output: bool = False

    def validate_llm_configuration(self) -> tuple[bool, str]:
        """Validate LLM configuration.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if self.enable_llm_analysis and not self.openai_api_key:
            return False, "OpenAI API key is required when LLM analysis is enabled. Set it using adv_configure_settings."
        
        if self.enable_llm_analysis and self.openai_api_key and not self.openai_api_key.startswith("sk-"):
            return False, "Invalid OpenAI API key format. API keys should start with 'sk-'."
        
        return True, ""
    
    def is_llm_analysis_available(self) -> bool:
        """Check if LLM analysis is available and properly configured.
        
        Returns:
            True if LLM analysis can be used
        """
        return self.enable_llm_analysis and bool(self.openai_api_key)
    
    def get_configuration_summary(self) -> dict[str, Any]:
        """Get a summary of the current configuration.
        
        Returns:
            Dictionary with configuration summary
        """
        is_valid, error = self.validate_llm_configuration()
        
        return {
            "llm_analysis_enabled": self.enable_llm_analysis,
            "llm_analysis_available": self.is_llm_analysis_available(),
            "openai_api_key_configured": bool(self.openai_api_key),
            "openai_model": self.openai_model,
            "configuration_valid": is_valid,
            "configuration_error": error if not is_valid else None,
            "exploit_generation_enabled": self.enable_exploit_generation,
            "exploit_safety_mode": self.exploit_safety_mode,
            "severity_threshold": self.severity_threshold,
        }


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

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        """Initialize credential manager.

        Args:
            config_dir: Configuration directory (default: ~/.local/share/adversary-mcp-server)
        """
        if config_dir is None:
            config_dir = Path.home() / ".local" / "share" / "adversary-mcp-server"

        self.config_dir = config_dir
        self.config_file = config_dir / "config.json"
        self.keyring_service = "adversary-mcp-server"

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

    def _try_keyring_retrieval(self) -> Optional[SecurityConfig]:
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

    def _load_file_config(self) -> Optional[SecurityConfig]:
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
            return

        # Fall back to encrypted file
        self._store_file_config(config)

    def load_config(self) -> SecurityConfig:
        """Load security configuration.

        Returns:
            SecurityConfig loaded from storage

        Raises:
            CredentialNotFoundError: If no configuration is found
        """
        # Try keyring first
        config = self._try_keyring_retrieval()
        if config is not None:
            return config

        # Try encrypted file
        config = self._load_file_config()
        if config is not None:
            return config

        # Return default configuration if none found
        return SecurityConfig()

    def delete_config(self) -> None:
        """Delete stored configuration."""
        # Try to delete from keyring
        self._try_keyring_deletion()

        # Try to delete file
        self._delete_file_config()

    def has_config(self) -> bool:
        """Check if configuration exists and can be loaded.

        Returns:
            True if configuration exists and is valid, False otherwise
        """
        # Check keyring
        if self._try_keyring_retrieval() is not None:
            return True

        # Check if file config can be loaded
        if self._load_file_config() is not None:
            return True
            
        return False

    def get_openai_api_key(self) -> Optional[str]:
        """Get OpenAI API key from configuration.

        Returns:
            OpenAI API key if configured, None otherwise
        """
        try:
            config = self.load_config()
            return config.openai_api_key if config.openai_api_key else None
        except CredentialNotFoundError:
            return None

    def update_openai_api_key(self, api_key: str) -> None:
        """Update OpenAI API key in configuration.

        Args:
            api_key: OpenAI API key to store
        """
        config = self.load_config()
        config.openai_api_key = api_key
        self.store_config(config)
