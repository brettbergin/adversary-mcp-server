"""Tests for telemetry cache module."""

import threading
import time

from adversary_mcp_server.telemetry.cache import (
    CachedRepositoryMixin,
    QueryResultCache,
    cache_dashboard_queries,
    cached_query,
    get_global_cache,
)


class TestQueryResultCache:
    """Test QueryResultCache functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.cache = QueryResultCache(default_ttl=60)

    def test_cache_initialization(self):
        """Test cache initialization."""
        cache = QueryResultCache(default_ttl=300)
        assert cache.default_ttl == 300
        assert cache._cache == {}
        assert type(cache._lock).__name__ == "RLock"

    def test_set_and_get_basic(self):
        """Test basic set and get operations."""
        # Set a value
        self.cache.set("test_key", "test_value")

        # Get the value
        result = self.cache.get("test_key")
        assert result == "test_value"

    def test_get_nonexistent_key(self):
        """Test getting a key that doesn't exist."""
        result = self.cache.get("nonexistent")
        assert result is None

    def test_set_with_custom_ttl(self):
        """Test setting value with custom TTL."""
        self.cache.set("test_key", "test_value", ttl=10)

        # Verify entry has correct TTL
        entry = self.cache._cache["test_key"]
        assert entry["ttl"] == 10
        assert entry["data"] == "test_value"

    def test_ttl_expiration(self):
        """Test that entries expire after TTL."""
        # Set with very short TTL
        self.cache.set("test_key", "test_value", ttl=0.1)

        # Should be available immediately
        assert self.cache.get("test_key") == "test_value"

        # Wait for expiration
        time.sleep(0.2)

        # Should be expired now
        assert self.cache.get("test_key") is None

    def test_access_tracking(self):
        """Test that access count and last accessed are tracked."""
        self.cache.set("test_key", "test_value")

        # First access
        self.cache.get("test_key")
        entry1 = self.cache._cache["test_key"]
        first_access_time = entry1["last_accessed"]

        # Second access - ensure we have different timestamps
        time.sleep(0.01)  # Small delay
        self.cache.get("test_key")
        entry2 = self.cache._cache["test_key"]
        second_access_time = entry2["last_accessed"]

        # Verify access count increased (set initializes to 1, then 2 gets = 3)
        assert entry2["access_count"] == 3
        # Verify timestamp was updated (allow for same timestamp due to precision)
        assert second_access_time >= first_access_time

    def test_invalidate_existing_key(self):
        """Test invalidating an existing key."""
        self.cache.set("test_key", "test_value")

        # Verify key exists
        assert self.cache.get("test_key") == "test_value"

        # Invalidate
        result = self.cache.invalidate("test_key")
        assert result is True

        # Verify key is gone
        assert self.cache.get("test_key") is None

    def test_invalidate_nonexistent_key(self):
        """Test invalidating a key that doesn't exist."""
        result = self.cache.invalidate("nonexistent")
        assert result is False

    def test_invalidate_pattern(self):
        """Test invalidating multiple keys with pattern matching."""
        # Set multiple keys
        self.cache.set("user_1_data", "data1")
        self.cache.set("user_2_data", "data2")
        self.cache.set("config_data", "config")

        # Invalidate user data
        invalidated = self.cache.invalidate_pattern("user_")
        assert invalidated == 2

        # Verify correct keys were removed
        assert self.cache.get("user_1_data") is None
        assert self.cache.get("user_2_data") is None
        assert self.cache.get("config_data") == "config"

    def test_clear_cache(self):
        """Test clearing all cache entries."""
        # Add multiple entries
        self.cache.set("key1", "value1")
        self.cache.set("key2", "value2")
        self.cache.set("key3", "value3")

        # Clear cache
        count = self.cache.clear()
        assert count == 3

        # Verify cache is empty
        assert self.cache.get("key1") is None
        assert self.cache.get("key2") is None
        assert self.cache.get("key3") is None

    def test_get_stats_empty_cache(self):
        """Test getting stats for empty cache."""
        stats = self.cache.get_stats()

        expected = {
            "total_entries": 0,
            "total_accesses": 0,
            "average_age_seconds": 0,
            "oldest_entry_age_seconds": 0,
            "newest_entry_age_seconds": 0,
        }
        assert stats == expected

    def test_get_stats_with_entries(self):
        """Test getting stats with cache entries."""
        # Add entries with different access counts
        self.cache.set("key1", "value1")
        self.cache.set("key2", "value2", ttl=120)

        # Access first key multiple times
        self.cache.get("key1")
        self.cache.get("key1")
        self.cache.get("key2")

        stats = self.cache.get_stats()

        assert stats["total_entries"] == 2
        assert stats["total_accesses"] == 5  # 2 sets (1 each) + 3 gets = 5 total
        assert "average_age_seconds" in stats
        assert "oldest_entry_age_seconds" in stats
        assert "newest_entry_age_seconds" in stats
        assert "entries_by_ttl" in stats

    def test_cleanup_expired(self):
        """Test cleaning up expired entries."""
        # Add entries with different TTLs
        self.cache.set("short_lived", "value1", ttl=0.1)
        self.cache.set("long_lived", "value2", ttl=60)

        # Wait for short-lived to expire
        time.sleep(0.2)

        # Cleanup expired
        removed = self.cache.cleanup_expired()
        assert removed == 1

        # Verify correct entry was removed
        assert self.cache.get("short_lived") is None
        assert self.cache.get("long_lived") == "value2"

    def test_thread_safety(self):
        """Test thread safety of cache operations."""
        results = []
        errors = []

        def worker(thread_id):
            try:
                for i in range(100):
                    key = f"thread_{thread_id}_key_{i}"
                    value = f"thread_{thread_id}_value_{i}"

                    # Set value
                    self.cache.set(key, value)

                    # Get value
                    retrieved = self.cache.get(key)
                    if retrieved == value:
                        results.append(f"{thread_id}_{i}")

            except Exception as e:
                errors.append(e)

        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors and all operations completed
        assert len(errors) == 0
        assert len(results) == 500  # 5 threads * 100 operations each


class TestCachedQueryDecorator:
    """Test the cached_query decorator."""

    def setup_method(self):
        """Setup test fixtures."""
        # Clear global cache
        get_global_cache().clear()

    def test_basic_caching(self):
        """Test basic function caching."""
        call_count = 0

        @cached_query(ttl=60)
        def expensive_function(x, y):
            nonlocal call_count
            call_count += 1
            return x + y

        # First call should execute function
        result1 = expensive_function(1, 2)
        assert result1 == 3
        assert call_count == 1

        # Second call with same args should use cache
        result2 = expensive_function(1, 2)
        assert result2 == 3
        assert call_count == 1  # Not incremented

        # Different args should execute function again
        result3 = expensive_function(2, 3)
        assert result3 == 5
        assert call_count == 2

    def test_cache_with_key_prefix(self):
        """Test caching with key prefix."""

        @cached_query(ttl=60, key_prefix="test_")
        def test_function():
            return "test_result"

        # Function should have correct cache key prefix
        assert test_function._cache_key_prefix == "test_test_function"

        # Test cache invalidation method
        test_function()
        invalidated = test_function.invalidate_cache()
        assert invalidated >= 0  # Should return number of invalidated entries

    def test_cache_invalidation(self):
        """Test cache invalidation functionality."""
        call_count = 0

        @cached_query(ttl=60)
        def test_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # Call function to populate cache
        result1 = test_function(5)
        assert result1 == 10
        assert call_count == 1

        # Invalidate cache
        test_function.invalidate_cache()

        # Next call should execute function again
        result2 = test_function(5)
        assert result2 == 10
        assert call_count == 2

    def test_cache_stats_access(self):
        """Test accessing cache stats."""

        @cached_query(ttl=60)
        def test_function():
            return "result"

        # Call function to populate cache
        test_function()

        # Access stats
        stats = test_function.get_cache_stats()
        assert isinstance(stats, dict)
        assert "total_entries" in stats


class TestGlobalCache:
    """Test global cache functionality."""

    def test_get_global_cache(self):
        """Test getting global cache instance."""
        cache1 = get_global_cache()
        cache2 = get_global_cache()

        # Should return same instance
        assert cache1 is cache2
        assert isinstance(cache1, QueryResultCache)


class TestCacheDashboardQueries:
    """Test cache_dashboard_queries decorator."""

    def test_class_decoration(self):
        """Test class decorator adds caching to dashboard queries."""

        # Create test service class
        class TestService:
            def get_dashboard_data(self):
                return {"test": "data"}

        # Apply decorator
        CachedService = cache_dashboard_queries(TestService)

        # Verify method has caching attributes
        service = CachedService()
        assert hasattr(service.get_dashboard_data, "_cache_key_prefix")
        assert hasattr(service.get_dashboard_data, "invalidate_cache")


class TestCachedRepositoryMixin:
    """Test CachedRepositoryMixin functionality."""

    def test_mixin_initialization(self):
        """Test mixin initialization."""

        class TestRepository(CachedRepositoryMixin):
            pass

        repo = TestRepository()
        assert hasattr(repo, "_query_cache")
        assert isinstance(repo._query_cache, QueryResultCache)

    def test_cached_query_method(self):
        """Test cached_query method."""

        class TestRepository(CachedRepositoryMixin):
            pass

        repo = TestRepository()
        call_count = 0

        def expensive_query():
            nonlocal call_count
            call_count += 1
            return "query_result"

        # First call should execute query
        result1 = repo.cached_query("test_key", expensive_query)
        assert result1 == "query_result"
        assert call_count == 1

        # Second call should use cache
        result2 = repo.cached_query("test_key", expensive_query)
        assert result2 == "query_result"
        assert call_count == 1  # Not incremented

    def test_cached_query_with_ttl(self):
        """Test cached_query with custom TTL."""

        class TestRepository(CachedRepositoryMixin):
            pass

        repo = TestRepository()

        def test_query():
            return "result"

        # Set with short TTL
        repo.cached_query("test_key", test_query, ttl=0.1)

        # Verify entry has correct TTL
        entry = repo._query_cache._cache["test_key"]
        assert entry["ttl"] == 0.1

    def test_invalidate_cache_with_pattern(self):
        """Test cache invalidation with pattern."""

        class TestRepository(CachedRepositoryMixin):
            pass

        repo = TestRepository()

        # Add multiple entries
        repo.cached_query("user_1", lambda: "data1")
        repo.cached_query("user_2", lambda: "data2")
        repo.cached_query("config", lambda: "config")

        # Invalidate user entries
        invalidated = repo.invalidate_cache("user_")
        assert invalidated == 2

    def test_invalidate_cache_clear_all(self):
        """Test clearing all cache entries."""

        class TestRepository(CachedRepositoryMixin):
            pass

        repo = TestRepository()

        # Add entries
        repo.cached_query("key1", lambda: "value1")
        repo.cached_query("key2", lambda: "value2")

        # Clear all
        cleared = repo.invalidate_cache("")
        assert cleared == 2

    def test_get_cache_stats(self):
        """Test getting cache statistics."""

        class TestRepository(CachedRepositoryMixin):
            pass

        repo = TestRepository()

        # Add some entries
        repo.cached_query("key1", lambda: "value1")
        repo.cached_query("key2", lambda: "value2")

        # Get stats
        stats = repo.get_cache_stats()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 2


class TestCacheIntegration:
    """Integration tests for cache functionality."""

    def test_decorator_and_global_cache_interaction(self):
        """Test interaction between decorator and global cache."""
        # Clear global cache
        get_global_cache().clear()

        @cached_query(ttl=60, key_prefix="integration_")
        def test_function(value):
            return value * 2

        # Call function
        result = test_function(10)
        assert result == 20

        # Verify entry in global cache
        global_cache = get_global_cache()
        stats = global_cache.get_stats()
        assert stats["total_entries"] >= 1

    def test_multiple_cached_functions(self):
        """Test multiple cached functions."""
        get_global_cache().clear()

        @cached_query(ttl=60, key_prefix="func1_")
        def function1(x):
            return x + 1

        @cached_query(ttl=60, key_prefix="func2_")
        def function2(x):
            return x * 2

        # Call both functions
        result1 = function1(5)
        result2 = function2(5)

        assert result1 == 6
        assert result2 == 10

        # Verify both cached
        stats = get_global_cache().get_stats()
        assert stats["total_entries"] == 2

    def test_cache_with_complex_arguments(self):
        """Test caching with complex argument types."""
        call_count = 0

        @cached_query(ttl=60)
        def complex_function(data_dict, data_list, keyword_arg="default"):
            nonlocal call_count
            call_count += 1
            return sum(data_dict.values()) + sum(data_list) + len(keyword_arg)

        # Call with complex arguments
        result1 = complex_function({"a": 1, "b": 2}, [3, 4], keyword_arg="test")
        assert result1 == 14  # 1+2+3+4+4 = 14
        assert call_count == 1

        # Same call should use cache
        result2 = complex_function({"a": 1, "b": 2}, [3, 4], keyword_arg="test")
        assert result2 == 14
        assert call_count == 1  # Not incremented
