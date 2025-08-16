"""Secure credential management for Adversary MCP server."""

import getpass
import json
import os
import socket
import stat
from base64 import b64decode, b64encode
from dataclasses import asdict
from pathlib import Path
from typing import Any

import keyring
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from keyring.errors import KeyringError

from .config import SecurityConfig
from .logger import get_logger

logger = get_logger("credentials")

# Module-level singleton instance to prevent repeated keychain access
_credential_manager_instance = None


def get_credential_manager(config_dir: Path | None = None) -> "CredentialManager":
    """Get or create the singleton CredentialManager instance.

    This function ensures only one CredentialManager instance exists per process,
    preventing repeated keychain access prompts.

    Args:
        config_dir: Configuration directory (only used on first call)

    Returns:
        The singleton CredentialManager instance
    """
    global _credential_manager_instance
    if _credential_manager_instance is None:
        _credential_manager_instance = CredentialManager(config_dir)
    return _credential_manager_instance


def reset_credential_manager():
    """Reset the singleton instance. Used primarily for testing.

    WARNING: This will clear all cached credentials and force a reload
    from keychain on next access.
    """
    global _credential_manager_instance
    if _credential_manager_instance is not None:
        # Clear the instance's cache
        _credential_manager_instance._config_cache = None
        _credential_manager_instance._cache_loaded = False

    _credential_manager_instance = None
    CredentialManager._instance = None
    CredentialManager._initialized = False


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
    """Secure credential manager for Adversary MCP server configuration.

    Implements singleton pattern to prevent repeated keychain access.
    """

    _instance = None
    _initialized = False

    def __new__(cls, config_dir: Path | None = None):
        """Create or return the singleton instance."""
        if cls._instance is None:
            logger.info("Creating new CredentialManager singleton instance")
            cls._instance = super().__new__(cls)
        else:
            logger.debug("Returning existing CredentialManager singleton instance")
        return cls._instance

    def __init__(self, config_dir: Path | None = None) -> None:
        """Initialize credential manager.

        Args:
            config_dir: Configuration directory (default: ~/.local/share/adversary-mcp-server)
        """
        # Only initialize once to prevent repeated keychain access
        if CredentialManager._initialized:
            logger.debug("CredentialManager already initialized, skipping")
            return

        logger.info("Initializing CredentialManager for the first time")
        CredentialManager._initialized = True

        if config_dir is None:
            config_dir = Path.home() / ".local" / "share" / "adversary-mcp-server"
            logger.debug(f"Using default config directory: {config_dir}")
        else:
            logger.debug(f"Using custom config directory: {config_dir}")

        self.config_dir = config_dir
        self.config_file = config_dir / "config.json"
        self.keyring_service = "adversary-mcp-server"
        logger.debug(f"Config file path: {self.config_file}")
        logger.debug(f"Keyring service name: {self.keyring_service}")

        # In-memory cache to reduce keychain access
        self._config_cache: SecurityConfig | None = None
        self._cache_loaded = False
        logger.debug("Initialized credential cache")

        # Ensure config directory exists with proper permissions
        self._ensure_config_dir()
        logger.info("CredentialManager initialization complete")

    def _ensure_config_dir(self) -> None:
        """Ensure configuration directory exists with proper permissions."""
        logger.debug(f"Ensuring config directory exists: {self.config_dir}")

        if not self.config_dir.exists():
            logger.info(f"Creating config directory: {self.config_dir}")
            self.config_dir.mkdir(parents=True, exist_ok=True)
        else:
            logger.debug("Config directory already exists")

        # Set restrictive permissions (owner only)
        try:
            self.config_dir.chmod(stat.S_IRWXU)  # 700
            logger.debug("Set restrictive permissions (700) on config directory")
        except OSError as e:
            # May fail on some systems, but not critical
            logger.warning(
                f"Failed to set restrictive permissions on config directory: {e}"
            )

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
        logger.debug("Attempting to store configuration in keyring")
        logger.debug(f"Keyring service: {self.keyring_service}")
        logger.debug(
            f"Config to store in keyring - LLM provider: {config.llm_provider}, "
            f"LLM API key: {'SET' if config.llm_api_key else 'NULL'}, "
            f"Semgrep API key: {'SET' if config.semgrep_api_key else 'NULL'}"
        )
        try:
            config_dict = asdict(config)
            config_json = json.dumps(config_dict)
            logger.debug(f"Config JSON length: {len(config_json)} characters")
            logger.debug(
                f"Storing at keyring service '{self.keyring_service}' with key 'config'"
            )

            keyring.set_password(self.keyring_service, "config", config_json)

            # Immediately verify the storage worked (only if not in test environment)
            try:
                logger.debug(
                    "Verifying keyring storage by attempting immediate retrieval..."
                )
                verification_json = keyring.get_password(self.keyring_service, "config")
                if verification_json:
                    verification_config = SecurityConfig(
                        **json.loads(verification_json)
                    )
                    logger.info(
                        f"Keyring storage verified - stored config has provider: {verification_config.llm_provider}"
                    )
                else:
                    # Don't fail on verification issues - storage might still have worked
                    logger.debug(
                        "⚠️ Keyring storage verification returned None (may be normal in test environments)"
                    )
            except Exception as e:
                # Don't fail on verification issues - the main storage operation succeeded
                logger.debug(
                    f"⚠️ Keyring storage verification failed: {e} (may be normal in test environments)"
                )

            logger.info("Successfully stored configuration in keyring")
            return True
        except KeyringError as e:
            logger.warning(f"Failed to store configuration in keyring: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error storing configuration in keyring: {e}")
            return False

    def _try_keyring_retrieval(self) -> SecurityConfig | None:
        """Try to retrieve configuration from keyring.

        Returns:
            SecurityConfig if found, None otherwise
        """
        logger.debug("Attempting to retrieve configuration from keyring")
        logger.debug(f"Keyring service: {self.keyring_service}")
        logger.debug(
            f"Looking for key 'config' in keyring service '{self.keyring_service}'"
        )

        try:
            config_json = keyring.get_password(self.keyring_service, "config")
            if config_json:
                logger.debug(
                    f"Configuration found in keyring, JSON length: {len(config_json)} characters"
                )
                logger.debug("Parsing JSON configuration...")
                config_dict = json.loads(config_json)
                logger.debug(f"Parsed config dict keys: {list(config_dict.keys())}")

                # Handle backward compatibility for missing fields
                # Add default values for any fields that might be missing from older configs
                defaults = {
                    "enable_llm_analysis": True,
                    "enable_llm_validation": True,
                    "llm_temperature": 0.1,
                    "llm_max_tokens": 4000,
                    "llm_batch_size": 10,
                    "enable_semgrep_scanning": True,
                    "semgrep_config": None,
                    "semgrep_rules": None,
                    "enable_exploit_generation": True,
                    "exploit_safety_mode": True,
                    "max_file_size_mb": 10,
                    "timeout_seconds": 300,
                    "severity_threshold": "medium",
                    "enable_caching": True,
                    "cache_max_size_mb": 100,
                    "cache_max_age_hours": 24,
                    "cache_llm_responses": True,
                }

                # Apply defaults for missing keys
                for key, default_value in defaults.items():
                    if key not in config_dict:
                        config_dict[key] = default_value
                        logger.debug(
                            f"Added missing field '{key}' with default value: {default_value}"
                        )

                config = SecurityConfig(**config_dict)
                logger.debug(
                    f"Created SecurityConfig object - LLM provider: {config.llm_provider}, "
                    f"LLM API key: {'SET' if config.llm_api_key else 'NULL'}, "
                    f"Semgrep API key: {'SET' if config.semgrep_api_key else 'NULL'}"
                )

                logger.info("Successfully retrieved configuration from keyring")
                return config
            else:
                logger.debug(
                    "No configuration found in keyring (keyring.get_password returned None)"
                )
        except KeyringError as e:
            logger.warning(f"KeyringError retrieving configuration from keyring: {e}")
        except json.JSONDecodeError as e:
            logger.warning(
                f"JSON decode error retrieving configuration from keyring: {e}"
            )
        except TypeError as e:
            logger.warning(f"TypeError retrieving configuration from keyring: {e}")
        except Exception as e:
            logger.error(f"Unexpected error retrieving configuration from keyring: {e}")
        return None

    def _try_keyring_deletion(self) -> bool:
        """Try to delete configuration from keyring.

        Returns:
            True if deletion succeeded, False otherwise
        """
        logger.debug("Attempting to delete configuration from keyring")
        try:
            keyring.delete_password(self.keyring_service, "config")
            logger.info("Successfully deleted configuration from keyring")
            return True
        except KeyringError as e:
            logger.warning(f"Failed to delete configuration from keyring: {e}")
            return False

    def _store_file_config(self, config: SecurityConfig) -> None:
        """Store configuration in encrypted file.

        Args:
            config: Security configuration to store

        Raises:
            CredentialStorageError: If storage fails
        """
        logger.debug(f"Storing encrypted configuration to file: {self.config_file}")
        try:
            config_json = json.dumps(asdict(config))
            machine_id = self._get_machine_id()
            logger.debug(f"Using machine ID for encryption: {machine_id[:10]}...")

            encrypted_data = self._encrypt_data(config_json, machine_id)
            logger.debug("Configuration encrypted successfully")

            with open(self.config_file, "w") as f:
                json.dump(encrypted_data, f)
            logger.debug("Encrypted configuration written to file")

            # Set restrictive permissions
            self.config_file.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
            logger.debug("Set restrictive permissions (600) on config file")
            logger.info("Successfully stored encrypted configuration to file")

        except OSError as e:
            logger.error(f"Failed to store configuration to file: {e}")
            raise CredentialStorageError(f"Failed to store configuration: {e}")

    def _load_file_config(self) -> SecurityConfig | None:
        """Load configuration from encrypted file.

        Returns:
            SecurityConfig if found and decrypted successfully, None otherwise
        """
        logger.debug(f"Attempting to load configuration from file: {self.config_file}")

        if not self.config_file.exists():
            logger.debug("Configuration file does not exist")
            return None

        try:
            with open(self.config_file) as f:
                data = json.load(f)
            logger.debug("Configuration file loaded successfully")

            # Check if this is an encrypted file (has encrypted_data and salt)
            if "encrypted_data" in data and "salt" in data:
                logger.debug("Detected encrypted configuration file, decrypting")
                # Handle encrypted file
                machine_id = self._get_machine_id()
                config_json = self._decrypt_data(
                    data["encrypted_data"],
                    data["salt"],
                    machine_id,
                )
                config_dict = json.loads(config_json)
                logger.debug("Configuration decrypted successfully")
            else:
                logger.debug(
                    "Detected plain JSON configuration file (backward compatibility)"
                )
                # Handle plain JSON file (backward compatibility)
                config_dict = data

            # Handle backward compatibility for missing fields (same as keyring loading)
            defaults = {
                "enable_llm_analysis": True,
                "enable_llm_validation": True,
                "llm_temperature": 0.1,
                "llm_max_tokens": 4000,
                "llm_batch_size": 10,
                "enable_semgrep_scanning": True,
                "semgrep_config": None,
                "semgrep_rules": None,
                "enable_exploit_generation": True,
                "exploit_safety_mode": True,
                "max_file_size_mb": 10,
                "timeout_seconds": 300,
                "severity_threshold": "medium",
                "enable_caching": True,
                "cache_max_size_mb": 100,
                "cache_max_age_hours": 24,
                "cache_llm_responses": True,
            }

            # Apply defaults for missing keys
            for key, default_value in defaults.items():
                if key not in config_dict:
                    config_dict[key] = default_value
                    logger.debug(
                        f"Added missing field '{key}' with default value: {default_value}"
                    )

            config = SecurityConfig(**config_dict)
            logger.info("Successfully loaded configuration from file")
            return config

        except (
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            CredentialDecryptionError,
        ) as e:
            logger.warning(f"Failed to load configuration from file: {e}")
            return None

    def _delete_file_config(self) -> bool:
        """Delete configuration file.

        Returns:
            True if deletion succeeded, False otherwise
        """
        logger.debug(f"Attempting to delete configuration file: {self.config_file}")
        try:
            if self.config_file.exists():
                self.config_file.unlink()
                logger.info("Successfully deleted configuration file")
            else:
                logger.debug("Configuration file does not exist, nothing to delete")
            return True
        except OSError as e:
            logger.warning(f"Failed to delete configuration file: {e}")
            return False

    def store_config(self, config: SecurityConfig) -> None:
        """Store security configuration.

        Args:
            config: Security configuration to store

        Raises:
            CredentialStorageError: If storage fails in both keyring and file
        """
        logger.info("=== STORING SECURITY CONFIGURATION ===")
        logger.info("Storing security configuration")
        logger.debug(
            f"Configuration to store - LLM provider: {config.llm_provider}, "
            f"LLM API key configured: {bool(config.llm_api_key)}, Model: {config.llm_model}, "
            f"Semgrep enabled: {config.enable_semgrep_scanning}, "
            f"Semgrep API key configured: {bool(config.semgrep_api_key)}, "
            f"Use LLM validation: {config.enable_llm_validation}"
        )

        # Store individual API keys separately before storing main config
        if config.llm_provider and config.llm_api_key:
            logger.info(
                f"Storing {config.llm_provider} API key separately in keyring..."
            )
            try:
                self.store_llm_api_key(config.llm_provider, config.llm_api_key)
                logger.info(
                    f"Successfully stored {config.llm_provider} API key separately"
                )
            except Exception as e:
                logger.error(
                    f"Failed to store {config.llm_provider} API key separately: {e}"
                )

        if config.semgrep_api_key:
            logger.info("Storing Semgrep API key separately in keyring...")
            try:
                self.store_semgrep_api_key(config.semgrep_api_key)
                logger.info("Successfully stored Semgrep API key separately")
            except Exception as e:
                logger.error(f"Failed to store Semgrep API key separately: {e}")

        # Create a copy of config with API keys set to None for main storage
        # (Following the pattern from CLI where keys are stored separately)
        from dataclasses import replace

        config_for_storage = replace(
            config,
            llm_api_key=None,  # Don't store the actual API key in config
            semgrep_api_key=None,  # Don't store the actual API key in config
        )

        logger.debug(
            f"Config for main storage (API keys nullified) - LLM provider: {config_for_storage.llm_provider}, "
            f"LLM API key: {'SET' if config_for_storage.llm_api_key else 'NULL'}, "
            f"Semgrep API key: {'SET' if config_for_storage.semgrep_api_key else 'NULL'}"
        )

        # Try keyring first
        logger.info("Attempting to store main config in keyring...")
        if self._try_keyring_storage(config_for_storage):
            # Update cache with the ORIGINAL config (with API keys)
            self._config_cache = config
            self._cache_loaded = True
            logger.info("Configuration stored successfully in keyring")
            logger.info(
                f"Cache updated with full config (LLM key: {'SET' if config.llm_api_key else 'NULL'}, Semgrep key: {'SET' if config.semgrep_api_key else 'NULL'})"
            )
            return

        # Fall back to encrypted file
        logger.info("Keyring storage failed, falling back to encrypted file")
        self._store_file_config(config_for_storage)
        # Update cache with the ORIGINAL config (with API keys)
        self._config_cache = config
        self._cache_loaded = True
        logger.info("Configuration stored successfully in encrypted file")
        logger.info(
            f"Cache updated with full config (LLM key: {'SET' if config.llm_api_key else 'NULL'}, Semgrep key: {'SET' if config.semgrep_api_key else 'NULL'})"
        )

    def load_config(self) -> SecurityConfig:
        """Load security configuration.

        Returns:
            SecurityConfig loaded from storage

        Raises:
            CredentialNotFoundError: If no configuration is found
        """
        logger.info("=== LOADING SECURITY CONFIGURATION ===")
        logger.debug("Loading security configuration")

        # Return cached config if available
        if self._cache_loaded and self._config_cache is not None:
            logger.info("Returning cached configuration")
            logger.debug(
                f"Cached config - LLM provider: {self._config_cache.llm_provider}, "
                f"API key configured: {bool(self._config_cache.llm_api_key)}, "
                f"Semgrep key configured: {bool(self._config_cache.semgrep_api_key)}"
            )
            return self._config_cache

        # Try keyring first
        logger.info("Attempting to load configuration from keyring...")
        config = self._try_keyring_retrieval()
        if config is not None:
            logger.info("Configuration found in keyring, injecting API keys...")
            logger.debug(
                f"Raw keyring config - LLM provider: {config.llm_provider}, "
                f"API key status: {'SET' if config.llm_api_key else 'NULL'}, "
                f"Semgrep key status: {'SET' if config.semgrep_api_key else 'NULL'}"
            )

            # Inject API keys from keyring if provider is configured
            if config.llm_provider and not config.llm_api_key:
                logger.debug(
                    f"Attempting to inject {config.llm_provider} API key from keyring..."
                )
                api_key = self.get_llm_api_key(config.llm_provider)
                if api_key:
                    config.llm_api_key = api_key
                    logger.info(
                        f"Successfully injected {config.llm_provider} API key from keyring"
                    )
                else:
                    logger.warning(
                        f"Failed to retrieve {config.llm_provider} API key from keyring"
                    )
            elif config.llm_provider and config.llm_api_key:
                logger.info(f"{config.llm_provider} API key already present in config")
            elif not config.llm_provider:
                logger.debug("No LLM provider configured, skipping API key injection")

            # Also inject Semgrep API key if needed
            if config.enable_semgrep_scanning and not config.semgrep_api_key:
                logger.debug("Attempting to inject Semgrep API key from keyring...")
                semgrep_key = self.get_semgrep_api_key()
                if semgrep_key:
                    config.semgrep_api_key = semgrep_key
                    logger.info("Successfully injected Semgrep API key from keyring")
                else:
                    logger.warning("Failed to retrieve Semgrep API key from keyring")
            elif config.enable_semgrep_scanning and config.semgrep_api_key:
                logger.info("Semgrep API key already present in config")

            # Log final configuration state
            logger.info(
                f"Final keyring config - LLM provider: {config.llm_provider}, "
                f"LLM API key status: {'SET' if config.llm_api_key else 'NULL'}, "
                f"Semgrep key status: {'SET' if config.semgrep_api_key else 'NULL'}"
            )

            # Cache the loaded config
            self._config_cache = config
            self._cache_loaded = True
            logger.info("Configuration loaded from keyring and cached")
            return config

        # Try encrypted file
        logger.info(
            "Keyring failed, attempting to load configuration from encrypted file..."
        )
        config = self._load_file_config()
        if config is not None:
            logger.info("Configuration found in file, injecting API keys...")
            logger.debug(
                f"Raw file config - LLM provider: {config.llm_provider}, "
                f"API key status: {'SET' if config.llm_api_key else 'NULL'}, "
                f"Semgrep key status: {'SET' if config.semgrep_api_key else 'NULL'}"
            )

            # Inject API keys from keyring if provider is configured
            if config.llm_provider and not config.llm_api_key:
                logger.debug(
                    f"Attempting to inject {config.llm_provider} API key from keyring..."
                )
                api_key = self.get_llm_api_key(config.llm_provider)
                if api_key:
                    config.llm_api_key = api_key
                    logger.info(
                        f"Successfully injected {config.llm_provider} API key from keyring"
                    )
                else:
                    logger.warning(
                        f"Failed to retrieve {config.llm_provider} API key from keyring"
                    )
            elif config.llm_provider and config.llm_api_key:
                logger.info(f"{config.llm_provider} API key already present in config")

            # Also inject Semgrep API key if needed
            if config.enable_semgrep_scanning and not config.semgrep_api_key:
                logger.debug("Attempting to inject Semgrep API key from keyring...")
                semgrep_key = self.get_semgrep_api_key()
                if semgrep_key:
                    config.semgrep_api_key = semgrep_key
                    logger.info("Successfully injected Semgrep API key from keyring")
                else:
                    logger.warning("Failed to retrieve Semgrep API key from keyring")
            elif config.enable_semgrep_scanning and config.semgrep_api_key:
                logger.info("Semgrep API key already present in config")

            # Log final configuration state
            logger.info(
                f"Final file config - LLM provider: {config.llm_provider}, "
                f"LLM API key status: {'SET' if config.llm_api_key else 'NULL'}, "
                f"Semgrep key status: {'SET' if config.semgrep_api_key else 'NULL'}"
            )

            # Cache the loaded config
            self._config_cache = config
            self._cache_loaded = True
            logger.info("Configuration loaded from encrypted file and cached")
            return config

        # Return default configuration if none found and cache it
        logger.info("No stored configuration found, using default configuration")
        default_config = SecurityConfig()
        self._config_cache = default_config
        self._cache_loaded = True
        return default_config

    def delete_config(self) -> None:
        """Delete stored configuration."""
        logger.info("Deleting stored configuration")

        # Try to delete from keyring
        keyring_deleted = self._try_keyring_deletion()

        # Try to delete file
        file_deleted = self._delete_file_config()

        # Clear cache
        self._config_cache = None
        self._cache_loaded = False
        logger.debug("Configuration cache cleared")

        if keyring_deleted or file_deleted:
            logger.info("Configuration deletion completed")
        else:
            logger.warning("No configuration found to delete")

    def store_semgrep_api_key(self, api_key: str) -> None:
        """Store Semgrep API key securely.

        Args:
            api_key: Semgrep API key to store

        Raises:
            CredentialStorageError: If storage fails
        """
        logger.info("Storing Semgrep API key")
        logger.debug(f"API key length: {len(api_key)} characters")
        try:
            keyring.set_password(self.keyring_service, "semgrep_api_key", api_key)
            logger.info("Successfully stored Semgrep API key in keyring")
        except KeyringError as e:
            logger.error(f"Failed to store Semgrep API key: {e}")
            raise CredentialStorageError(f"Failed to store Semgrep API key: {e}")

    def get_semgrep_api_key(self) -> str | None:
        """Get stored Semgrep API key.

        Returns:
            API key if found, None otherwise
        """
        logger.debug("Retrieving Semgrep API key from keyring")
        try:
            keyring_key = "semgrep_api_key"
            logger.debug(f"Checking keyring for key: {keyring_key}")
            api_key = keyring.get_password(self.keyring_service, keyring_key)
            if api_key:
                logger.info(
                    f"Semgrep API key found in keyring (length: {len(api_key)} chars)"
                )
            else:
                logger.warning(
                    f"No Semgrep API key found in keyring at key: {keyring_key}"
                )
            return api_key
        except KeyringError as e:
            logger.error(f"KeyringError retrieving Semgrep API key: {e}")
            return None

    def delete_semgrep_api_key(self) -> bool:
        """Delete stored Semgrep API key.

        Returns:
            True if deletion succeeded, False otherwise
        """
        logger.info("Deleting Semgrep API key")
        try:
            keyring.delete_password(self.keyring_service, "semgrep_api_key")
            logger.info("Successfully deleted Semgrep API key from keyring")
            return True
        except KeyringError as e:
            logger.warning(f"Failed to delete Semgrep API key: {e}")
            return False

    def store_llm_api_key(self, provider: str, api_key: str) -> None:
        """Store LLM API key securely.

        Args:
            provider: LLM provider (openai or anthropic)
            api_key: API key to store

        Raises:
            CredentialStorageError: If storage fails
            ValueError: If provider is invalid
        """
        if provider not in ["openai", "anthropic"]:
            raise ValueError(f"Invalid LLM provider: {provider}")

        logger.info(f"Storing API key for LLM provider: {provider}")
        logger.debug(f"API key length: {len(api_key)} characters")
        try:
            keyring.set_password(
                self.keyring_service, f"llm_{provider}_api_key", api_key
            )
            logger.info(f"Successfully stored {provider} API key in keyring")
        except KeyringError as e:
            logger.error(f"Failed to store {provider} API key: {e}")
            raise CredentialStorageError(f"Failed to store {provider} API key: {e}")

    def get_llm_api_key(self, provider: str) -> str | None:
        """Get stored LLM API key.

        Args:
            provider: LLM provider (openai or anthropic)

        Returns:
            API key if found, None otherwise
        """
        logger.debug(f"Retrieving API key for LLM provider: {provider}")

        if provider not in ["openai", "anthropic"]:
            logger.warning(f"Invalid LLM provider requested: {provider}")
            return None

        try:
            keyring_key = f"llm_{provider}_api_key"
            logger.debug(f"Checking keyring for key: {keyring_key}")
            api_key = keyring.get_password(self.keyring_service, keyring_key)
            if api_key:
                logger.info(
                    f"{provider} API key found in keyring (length: {len(api_key)} chars)"
                )
            else:
                logger.warning(
                    f"No {provider} API key found in keyring at key: {keyring_key}"
                )
            return api_key
        except KeyringError as e:
            logger.error(f"KeyringError retrieving {provider} API key: {e}")
            return None

    def delete_llm_api_key(self, provider: str) -> bool:
        """Delete stored LLM API key.

        Args:
            provider: LLM provider (openai or anthropic)

        Returns:
            True if deletion succeeded, False otherwise
        """
        logger.info(f"Deleting API key for LLM provider: {provider}")

        if provider not in ["openai", "anthropic"]:
            logger.warning(f"Invalid LLM provider for deletion: {provider}")
            return False

        try:
            keyring.delete_password(self.keyring_service, f"llm_{provider}_api_key")
            logger.info(f"Successfully deleted {provider} API key from keyring")
            return True
        except KeyringError as e:
            logger.warning(f"Failed to delete {provider} API key: {e}")
            return False

    def get_configured_llm_provider(self) -> str | None:
        """Get the currently configured LLM provider.

        Returns:
            Provider name if configured, None otherwise
        """
        logger.debug("Getting configured LLM provider")
        config = self.load_config()
        provider = config.llm_provider
        if provider:
            logger.debug(f"Configured LLM provider: {provider}")
        else:
            logger.debug("No LLM provider configured")
        return provider

    def clear_llm_configuration(self) -> None:
        """Clear all LLM configuration including API keys."""
        logger.info("Clearing all LLM configuration")

        # Delete API keys for both providers
        openai_deleted = self.delete_llm_api_key("openai")
        anthropic_deleted = self.delete_llm_api_key("anthropic")
        logger.debug(
            f"API key deletion results - OpenAI: {openai_deleted}, Anthropic: {anthropic_deleted}"
        )

        # Clear configuration
        config = self.load_config()
        old_provider = config.llm_provider
        config.llm_provider = None
        config.llm_api_key = None
        config.llm_model = None
        self.store_config(config)
        logger.info(f"Cleared LLM configuration (was: {old_provider})")

        # Clear cache
        self._config_cache = None
        self._cache_loaded = False
        logger.debug("LLM configuration cache cleared")

    def has_config(self) -> bool:
        """Check if configuration exists and can be loaded.

        Returns:
            True if configuration exists and is valid, False otherwise
        """
        logger.debug("Checking if configuration exists")

        # If we have a cached config, return True
        if self._cache_loaded and self._config_cache is not None:
            logger.debug("Configuration found in cache")
            return True

        # Check keyring
        if self._try_keyring_retrieval() is not None:
            logger.debug("Configuration found in keyring")
            return True

        # Check if file config can be loaded
        if self._load_file_config() is not None:
            logger.debug("Configuration found in encrypted file")
            return True

        logger.debug("No configuration found")
        return False

    def debug_keyring_state(self) -> dict[str, Any]:
        """Debug method to inspect complete keyring state.

        Returns:
            Dictionary with keyring state information
        """
        logger.info("=== DEBUGGING KEYRING STATE ===")

        state = {
            "keyring_service": self.keyring_service,
            "main_config": None,
            "llm_openai_key": None,
            "llm_anthropic_key": None,
            "semgrep_key": None,
            "cache_loaded": self._cache_loaded,
            "cached_config": None,
        }

        # Check main config
        try:
            config_json = keyring.get_password(self.keyring_service, "config")
            if config_json:
                config_dict = json.loads(config_json)
                state["main_config"] = {
                    "found": True,
                    "llm_provider": config_dict.get("llm_provider"),
                    "llm_model": config_dict.get("llm_model"),
                    "llm_api_key_status": (
                        "SET" if config_dict.get("llm_api_key") else "NULL"
                    ),
                    "semgrep_api_key_status": (
                        "SET" if config_dict.get("semgrep_api_key") else "NULL"
                    ),
                    "enable_semgrep_scanning": config_dict.get(
                        "enable_semgrep_scanning"
                    ),
                    "enable_llm_validation": config_dict.get("enable_llm_validation"),
                }
            else:
                state["main_config"] = {"found": False}
        except Exception as e:
            state["main_config"] = {"found": False, "error": str(e)}

        # Check individual API keys
        for provider in ["openai", "anthropic"]:
            try:
                key = keyring.get_password(
                    self.keyring_service, f"llm_{provider}_api_key"
                )
                state[f"llm_{provider}_key"] = {
                    "found": bool(key),
                    "length": len(key) if key else 0,
                }
            except Exception as e:
                state[f"llm_{provider}_key"] = {"found": False, "error": str(e)}

        # Check Semgrep key
        try:
            key = keyring.get_password(self.keyring_service, "semgrep_api_key")
            state["semgrep_key"] = {
                "found": bool(key),
                "length": len(key) if key else 0,
            }
        except Exception as e:
            state["semgrep_key"] = {"found": False, "error": str(e)}

        # Check cached config
        if self._config_cache:
            state["cached_config"] = {
                "found": True,
                "llm_provider": self._config_cache.llm_provider,
                "llm_model": self._config_cache.llm_model,
                "llm_api_key_status": (
                    "SET" if self._config_cache.llm_api_key else "NULL"
                ),
                "semgrep_api_key_status": (
                    "SET" if self._config_cache.semgrep_api_key else "NULL"
                ),
                "enable_semgrep_scanning": self._config_cache.enable_semgrep_scanning,
                "enable_llm_validation": self._config_cache.enable_llm_validation,
            }
        else:
            state["cached_config"] = {"found": False}

        # Log the complete state
        logger.info("Keyring state summary:")
        logger.info(f"  Service: {state['keyring_service']}")
        logger.info(f"  Main config found: {state['main_config'].get('found', False)}")
        logger.info(
            f"  OpenAI key found: {state['llm_openai_key'].get('found', False)}"
        )
        logger.info(
            f"  Anthropic key found: {state['llm_anthropic_key'].get('found', False)}"
        )
        logger.info(f"  Semgrep key found: {state['semgrep_key'].get('found', False)}")
        logger.info(f"  Cache loaded: {state['cache_loaded']}")
        logger.info(
            f"  Cached config found: {state['cached_config'].get('found', False)}"
        )

        return state
