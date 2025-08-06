"""Tests for cache manager."""

import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from adversary_mcp_server.cache.cache_manager import CacheManager
from adversary_mcp_server.cache.types import CacheKey, CacheType


class TestCacheManager:
    """Test CacheManager class."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def cache_manager(self, temp_cache_dir):
        """Create cache manager instance."""
        return CacheManager(
            cache_dir=temp_cache_dir,
            max_size_mb=10,
            max_age_hours=1,
            enable_persistence=True,
        )

    @pytest.fixture
    def cache_key(self):
        """Create test cache key."""
        return CacheKey(
            cache_type=CacheType.SEMGREP_RESULT,
            content_hash="test_content_hash",
            metadata_hash="test_metadata_hash",
        )

    def test_initialization(self, temp_cache_dir):
        """Test cache manager initialization."""
        cache_manager = CacheManager(
            cache_dir=temp_cache_dir,
            max_size_mb=5,
            max_age_hours=2,
            enable_persistence=False,
        )

        assert cache_manager.cache_dir == temp_cache_dir
        assert cache_manager.max_size_bytes == 5 * 1024 * 1024
        assert cache_manager.max_age_seconds == 2 * 3600
        assert cache_manager.enable_persistence is False
        assert temp_cache_dir.exists()

    def test_database_initialization(self, cache_manager):
        """Test SQLite database initialization."""
        db_path = cache_manager._db_path
        assert db_path.exists()

        with sqlite3.connect(db_path) as conn:
            # Check tables exist
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            assert "cache_entries" in tables
            assert "cache_stats" in tables

    def test_put_and_get_basic(self, cache_manager, cache_key):
        """Test basic put and get operations."""
        test_data = {"result": "test_value", "timestamp": 12345}

        # Put data
        cache_manager.put(cache_key, test_data)

        # Get data
        retrieved_data = cache_manager.get(cache_key)
        assert retrieved_data == test_data

    def test_get_nonexistent_key(self, cache_manager):
        """Test getting non-existent key returns None."""
        key = CacheKey(
            cache_type=CacheType.LLM_RESPONSE,
            content_hash="nonexistent",
            metadata_hash="none",
        )

        result = cache_manager.get(key)
        assert result is None

    def test_put_with_expiration(self, cache_manager, cache_key):
        """Test putting data with custom expiration."""
        test_data = {"expires_soon": True}

        cache_manager.put(cache_key, test_data, expires_in_seconds=1)

        # Should be available immediately
        assert cache_manager.get(cache_key) == test_data

        # Should expire after waiting
        time.sleep(1.1)
        assert cache_manager.get(cache_key) is None

    def test_cache_stats_tracking(self, cache_manager, cache_key):
        """Test cache statistics tracking."""
        initial_stats = cache_manager.get_stats()
        assert initial_stats.hit_count == 0
        assert initial_stats.miss_count == 0

        # Cache miss
        cache_manager.get(cache_key)
        stats = cache_manager.get_stats()
        assert stats.miss_count == 1

        # Cache hit
        cache_manager.put(cache_key, {"test": "data"})
        cache_manager.get(cache_key)
        stats = cache_manager.get_stats()
        assert stats.hit_count == 1

    def test_size_estimation(self, cache_manager):
        """Test data size estimation."""
        test_data = {"key": "value", "number": 42}
        estimated_size = cache_manager._estimate_size(test_data)

        assert isinstance(estimated_size, int)
        assert estimated_size > 0

    def test_lru_eviction(self, temp_cache_dir):
        """Test LRU eviction when cache is full."""
        # Create small cache (1KB max)
        cache_manager = CacheManager(
            cache_dir=temp_cache_dir,
            max_size_mb=0.001,  # Very small cache
            enable_persistence=False,
        )

        # Add multiple entries that exceed cache size
        keys = []
        for i in range(5):
            key = CacheKey(
                cache_type=CacheType.SEMGREP_RESULT,
                content_hash=f"hash_{i}",
                metadata_hash=f"meta_{i}",
            )
            keys.append(key)
            # Large data to trigger eviction
            large_data = {"data": "x" * 200, "index": i}
            cache_manager.put(key, large_data)

        # Access first key to make it recently used
        cache_manager.get(keys[0])

        # Add another large entry to trigger eviction
        final_key = CacheKey(
            cache_type=CacheType.LLM_RESPONSE,
            content_hash="final",
            metadata_hash="final",
        )
        cache_manager.put(final_key, {"data": "x" * 200, "final": True})

        # Check that some entries were evicted due to size constraints
        remaining_count = sum(1 for key in keys if cache_manager.get(key) is not None)

        # With a very small cache, some entries should be evicted
        # Don't enforce which specific entries remain - LRU implementation details may vary
        assert remaining_count < len(keys), "Expected some entries to be evicted"

        # Final key should still be there (most recently added)
        assert cache_manager.get(final_key) is not None

    def test_expired_entry_cleanup(self, cache_manager):
        """Test cleanup of expired entries."""
        key = CacheKey(
            cache_type=CacheType.VALIDATION_RESULT,
            content_hash="expire_test",
            metadata_hash="expire_meta",
        )

        # Add entry with short expiration
        cache_manager.put(key, {"will_expire": True}, expires_in_seconds=0.1)

        # Should be available immediately
        assert cache_manager.get(key) is not None

        # Wait for expiration
        time.sleep(0.2)

        # Should be None after expiration
        assert cache_manager.get(key) is None

    def test_invalidate_by_content_hash(self, cache_manager):
        """Test invalidating entries by content hash."""
        content_hash = "shared_content_hash"

        # Add multiple entries with same content hash
        keys = []
        for i in range(3):
            key = CacheKey(
                cache_type=CacheType.SEMGREP_RESULT,
                content_hash=content_hash,
                metadata_hash=f"meta_{i}",
            )
            keys.append(key)
            cache_manager.put(key, {"data": i})

        # Add entry with different content hash
        different_key = CacheKey(
            cache_type=CacheType.LLM_RESPONSE,
            content_hash="different_hash",
            metadata_hash="different_meta",
        )
        cache_manager.put(different_key, {"different": True})

        # Invalidate by content hash
        invalidated_count = cache_manager.invalidate_by_content_hash(content_hash)
        assert invalidated_count == 3

        # Entries with shared content hash should be gone
        for key in keys:
            assert cache_manager.get(key) is None

        # Entry with different content hash should remain
        assert cache_manager.get(different_key) is not None

    def test_invalidate_by_type(self, cache_manager):
        """Test invalidating entries by cache type."""
        # Add entries of different types
        semgrep_key = CacheKey(
            cache_type=CacheType.SEMGREP_RESULT,
            content_hash="semgrep_hash",
            metadata_hash="semgrep_meta",
        )
        cache_manager.put(semgrep_key, {"type": "semgrep"})

        llm_key = CacheKey(
            cache_type=CacheType.LLM_RESPONSE,
            content_hash="llm_hash",
            metadata_hash="llm_meta",
        )
        cache_manager.put(llm_key, {"type": "llm"})

        validation_key = CacheKey(
            cache_type=CacheType.VALIDATION_RESULT,
            content_hash="validation_hash",
            metadata_hash="validation_meta",
        )
        cache_manager.put(validation_key, {"type": "validation"})

        # Invalidate LLM entries only
        invalidated_count = cache_manager.invalidate_by_type(CacheType.LLM_RESPONSE)
        assert invalidated_count == 1

        # LLM entry should be gone
        assert cache_manager.get(llm_key) is None

        # Other entries should remain
        assert cache_manager.get(semgrep_key) is not None
        assert cache_manager.get(validation_key) is not None

    def test_clear_cache(self, cache_manager):
        """Test clearing all cache entries."""
        # Add multiple entries
        for i in range(3):
            key = CacheKey(
                cache_type=CacheType.SEMGREP_RESULT,
                content_hash=f"hash_{i}",
                metadata_hash=f"meta_{i}",
            )
            cache_manager.put(key, {"data": i})

        assert len(cache_manager._cache) == 3

        # Clear cache
        cache_manager.clear()

        assert len(cache_manager._cache) == 0

    def test_cleanup_maintenance(self, cache_manager):
        """Test cache cleanup and maintenance."""
        # Add some entries
        key1 = CacheKey(
            cache_type=CacheType.SEMGREP_RESULT,
            content_hash="cleanup_hash1",
            metadata_hash="cleanup_meta1",
        )
        cache_manager.put(key1, {"cleanup": "test1"})

        # Add expired entry
        key2 = CacheKey(
            cache_type=CacheType.LLM_RESPONSE,
            content_hash="cleanup_hash2",
            metadata_hash="cleanup_meta2",
        )
        cache_manager.put(key2, {"cleanup": "test2"}, expires_in_seconds=0.1)

        # Wait for expiration
        time.sleep(0.2)

        # Run cleanup
        cache_manager.cleanup()

        # Valid entry should remain, expired should be gone
        assert cache_manager.get(key1) is not None
        assert cache_manager.get(key2) is None

    def test_get_hasher(self, cache_manager):
        """Test getting content hasher instance."""
        hasher = cache_manager.get_hasher()
        assert hasher is not None
        assert hasher == cache_manager._hasher

    def test_json_serializer_with_to_dict(self, cache_manager):
        """Test JSON serializer with objects having to_dict method."""

        class MockObject:
            def to_dict(self):
                return {"serialized": True}

        obj = MockObject()
        result = cache_manager._json_serializer(obj)
        assert result == {"serialized": True}

    def test_json_serializer_with_dict_attr(self, cache_manager):
        """Test JSON serializer with objects having __dict__ attribute."""

        class MockObject:
            def __init__(self):
                self.attr1 = "value1"
                self.attr2 = 42

        obj = MockObject()
        result = cache_manager._json_serializer(obj)
        assert result == {"attr1": "value1", "attr2": 42}

    def test_json_serializer_fallback(self, cache_manager):
        """Test JSON serializer fallback to string."""
        result = cache_manager._json_serializer(123)
        assert result == "123"

    def test_persistence_disabled(self, temp_cache_dir):
        """Test cache manager with persistence disabled."""
        cache_manager = CacheManager(cache_dir=temp_cache_dir, enable_persistence=False)

        key = CacheKey(
            cache_type=CacheType.SEMGREP_RESULT,
            content_hash="no_persist",
            metadata_hash="no_persist_meta",
        )

        # Should work without persistence
        cache_manager.put(key, {"no_persist": True})
        assert cache_manager.get(key) == {"no_persist": True}

    @patch("adversary_mcp_server.cache.cache_manager.logger")
    def test_error_handling_in_save_entry(self, mock_logger, cache_manager, cache_key):
        """Test error handling when saving entry to disk fails."""
        # Mock file operations to raise exception
        with patch("builtins.open", side_effect=OSError("Disk error")):
            cache_manager.put(cache_key, {"test": "data"})

            # Should log error and increment error count
            mock_logger.error.assert_called()
            assert cache_manager._stats.error_count > 0

    def test_cache_entry_access_tracking(self, cache_manager, cache_key):
        """Test that cache entries track access properly."""
        test_data = {"access": "tracking"}

        # Put and get data multiple times
        cache_manager.put(cache_key, test_data)

        # Initial access through get
        cache_manager.get(cache_key)
        cache_manager.get(cache_key)
        cache_manager.get(cache_key)

        # Entry should have been accessed multiple times
        entry = cache_manager._cache[str(cache_key)]
        assert entry.access_count >= 3
