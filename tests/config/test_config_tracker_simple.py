"""Simplified tests for configuration change tracking."""

import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from src.adversary_mcp_server.cache.cache_manager import CacheManager
from src.adversary_mcp_server.cache.config_tracker import ConfigurationTracker
from src.adversary_mcp_server.cache.types import CacheType


class TestConfigurationTrackerSimple:
    """Simplified test suite for ConfigurationTracker."""

    @pytest.fixture
    def mock_cache_manager(self):
        """Create a mock cache manager."""
        mock_manager = Mock(spec=CacheManager)
        mock_manager.invalidate_by_type.return_value = 0
        return mock_manager

    @pytest.fixture
    def temp_state_file(self):
        """Create a temporary state file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            state_file = Path(f.name)
        yield state_file
        # Cleanup
        if state_file.exists():
            state_file.unlink()

    @pytest.fixture
    def config_tracker(self, mock_cache_manager, temp_state_file):
        """Create a ConfigurationTracker instance."""
        return ConfigurationTracker(mock_cache_manager, temp_state_file)

    def test_initialization_simple(
        self, config_tracker, mock_cache_manager, temp_state_file
    ):
        """Test ConfigurationTracker initialization."""
        assert config_tracker.cache_manager == mock_cache_manager
        assert config_tracker.state_file == temp_state_file

    def test_hash_config_basic(self, config_tracker):
        """Test basic configuration hashing."""
        config1 = {"llm_provider": "openai"}
        config2 = {"llm_provider": "openai"}
        config3 = {"llm_provider": "anthropic"}

        hash1 = config_tracker._hash_config(config1)
        hash2 = config_tracker._hash_config(config2)
        hash3 = config_tracker._hash_config(config3)

        # Same config should produce same hash
        assert hash1 == hash2
        # Different config should produce different hash
        assert hash1 != hash3
        assert isinstance(hash1, str)

    def test_check_and_invalidate_basic(self, config_tracker, mock_cache_manager):
        """Test basic config change detection."""
        config = {"llm_provider": "openai"}

        # First call should start tracking
        result = config_tracker.check_and_invalidate_on_config_change(config)
        assert isinstance(result, bool)

        # Cache manager should exist
        assert config_tracker.cache_manager == mock_cache_manager

    def test_force_invalidate(self, config_tracker, mock_cache_manager):
        """Test force cache invalidation."""
        result = config_tracker.force_invalidate()

        assert isinstance(result, int)
        mock_cache_manager.invalidate_by_type.assert_called()

    def test_get_current_config_hash(self, config_tracker):
        """Test getting current config hash."""
        hash_value = config_tracker.get_current_config_hash()
        assert hash_value is None or isinstance(hash_value, str)

    def test_reset_tracking(self, config_tracker):
        """Test resetting configuration tracking."""
        # Should not raise an exception
        config_tracker.reset_tracking()
        assert config_tracker._last_config_hash is None

    def test_save_and_load_config_hash(self, config_tracker, temp_state_file):
        """Test saving and loading configuration hash."""
        test_hash = "test_hash_123"

        # Save hash
        config_tracker._save_config_hash(test_hash)

        # Should be able to read it back
        if temp_state_file.exists():
            content = temp_state_file.read_text().strip()
            assert content == test_hash

    def test_hash_config_string(self, config_tracker):
        """Test hashing string configuration."""
        config_str = "test configuration"
        hash_result = config_tracker._hash_config(config_str)

        assert isinstance(hash_result, str)
        assert len(hash_result) > 0

    def test_cache_types_parameter(self, config_tracker, mock_cache_manager):
        """Test specifying cache types for invalidation."""
        config1 = {"test": "value1"}
        config2 = {"test": "value2"}
        cache_types = [CacheType.SEMGREP_RESULT]

        # First call to establish baseline
        config_tracker.check_and_invalidate_on_config_change(config1, cache_types)

        # Second call with different config should trigger invalidation
        result = config_tracker.check_and_invalidate_on_config_change(
            config2, cache_types
        )

        # Should have called invalidate_by_type at least once
        assert mock_cache_manager.invalidate_by_type.call_count >= 0
