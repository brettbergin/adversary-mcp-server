"""Credential management interfaces for secure configuration storage."""

from typing import Protocol, runtime_checkable

from ..config import SecurityConfig


@runtime_checkable
class ICredentialManager(Protocol):
    """Interface for secure credential and configuration management.

    This interface defines the contract for credential storage systems that:
    - Store and retrieve security configurations securely
    - Support both keyring and encrypted file storage
    - Handle API keys and sensitive settings
    - Provide caching for performance
    - Ensure secure deletion of credentials
    """

    def store_config(self, config: SecurityConfig) -> None:
        """Store security configuration securely.

        Attempts to store configuration in the system keyring first,
        falling back to encrypted file storage if keyring is unavailable.

        Args:
            config: Security configuration to store

        Raises:
            CredentialStorageError: If storage fails in both keyring and file
        """
        ...

    def load_config(self) -> SecurityConfig:
        """Load security configuration from secure storage.

        Returns cached configuration if available, otherwise loads from
        keyring or encrypted file storage.

        Returns:
            SecurityConfig loaded from storage

        Raises:
            CredentialNotFoundError: If no configuration is found
        """
        ...

    def delete_config(self) -> None:
        """Delete stored security configuration.

        Removes configuration from both keyring and file storage,
        and clears any cached configuration.
        """
        ...

    def store_semgrep_api_key(self, api_key: str) -> None:
        """Store Semgrep API key securely.

        Args:
            api_key: Semgrep API key to store
        """
        ...
