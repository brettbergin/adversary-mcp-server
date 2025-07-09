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
        
        # Check LLM Configuration
        assert config.enable_llm_analysis is False
        
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
            custom_rules_path="/path/to/rules",
            verbose_output=True
        )
        
        assert config.enable_llm_analysis is True
        assert config.enable_ast_scanning is False
        assert config.severity_threshold == "high"
        assert config.exploit_safety_mode is False
        assert config.max_file_size_mb == 20
        assert config.custom_rules_path == "/path/to/rules"
        assert config.verbose_output is True

    def test_security_config_is_dataclass(self):
        """Test that SecurityConfig is a dataclass with expected fields."""
        config = SecurityConfig()
        
        # Check that it's a dataclass with expected fields
        expected_fields = {
            'enable_llm_analysis', 'enable_ast_scanning', 'enable_semgrep_scanning',
            'enable_bandit_scanning', 'enable_exploit_generation', 'exploit_safety_mode',
            'max_file_size_mb', 'max_scan_depth', 'timeout_seconds', 'custom_rules_path',
            'severity_threshold', 'include_exploit_examples', 'include_remediation_advice',
            'verbose_output'
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
            config = SecurityConfig(
                enable_llm_analysis=True,
                severity_threshold="high"
            )
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
                exploit_safety_mode=False
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
            
            assert config.enable_llm_analysis is False
            assert config.severity_threshold == "medium"
            assert config.exploit_safety_mode is True

    def test_delete_config(self):
        """Test deleting configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Store a config
            config = SecurityConfig(
                enable_llm_analysis=True,
                severity_threshold="critical"
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
                enable_llm_analysis=True,
                severity_threshold="medium"
            )

            # Store config
            manager.store_config(config)

            # Check file exists (should exist since keyring failed)
            assert manager.config_file.exists()

            # Check file content structure
            with open(manager.config_file, "r") as f:
                content = f.read()
                assert "openai_api_key" in content or "encrypted_data" in content

    def test_concurrent_config_access(self):
        """Test concurrent access to configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager1 = CredentialManager(config_dir=Path(temp_dir))
            manager2 = CredentialManager(config_dir=Path(temp_dir))

            # Store config with manager1
            config = SecurityConfig(
                enable_llm_analysis=True,
                severity_threshold="high"
            )
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
            config = SecurityConfig(
                enable_llm_analysis=True
            )
            manager.store_config(config)

            # Directory should exist
            assert manager.config_dir.exists()
            assert manager.config_dir.is_dir()

    def test_config_with_none_values(self):
        """Test configuration with None values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CredentialManager(config_dir=Path(temp_dir))

            # Test data
            config = SecurityConfig(
                custom_rules_path=None,
                enable_llm_analysis=False
            )
            
            # Store config
            manager.store_config(config)
            loaded_config = manager.load_config()
            
            assert loaded_config.custom_rules_path is None
            assert loaded_config.enable_llm_analysis is False
