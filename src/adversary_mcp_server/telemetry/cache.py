"""Query result caching for telemetry system performance optimization."""

import threading
import time
from collections.abc import Callable
from functools import wraps
from typing import Any


class QueryResultCache:
    """Thread-safe cache for telemetry query results with TTL."""

    def __init__(self, default_ttl: int = 300):  # 5 minutes default TTL
        self.default_ttl = default_ttl
        self._cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        """Get cached result if valid."""
        with self._lock:
            if key not in self._cache:
                return None

            entry = self._cache[key]
            if time.time() > entry["expires_at"]:
                del self._cache[key]
                return None

            entry["last_accessed"] = time.time()
            entry["access_count"] += 1
            return entry["data"]

    def set(self, key: str, data: Any, ttl: int | None = None) -> None:
        """Set cached result with TTL."""
        ttl = ttl or self.default_ttl
        expires_at = time.time() + ttl

        with self._lock:
            self._cache[key] = {
                "data": data,
                "created_at": time.time(),
                "expires_at": expires_at,
                "last_accessed": time.time(),
                "access_count": 1,
                "ttl": ttl,
            }

    def invalidate(self, key: str) -> bool:
        """Invalidate a specific cache entry."""
        with self._lock:
            return self._cache.pop(key, None) is not None

    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all cache entries matching a pattern."""
        invalidated = 0
        with self._lock:
            keys_to_remove = [k for k in self._cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self._cache[key]
                invalidated += 1
        return invalidated

    def clear(self) -> int:
        """Clear all cache entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_entries = len(self._cache)
            total_access_count = sum(
                entry["access_count"] for entry in self._cache.values()
            )

            if not self._cache:
                return {
                    "total_entries": 0,
                    "total_accesses": 0,
                    "average_age_seconds": 0,
                    "oldest_entry_age_seconds": 0,
                    "newest_entry_age_seconds": 0,
                }

            current_time = time.time()
            ages = [
                current_time - entry["created_at"] for entry in self._cache.values()
            ]

            return {
                "total_entries": total_entries,
                "total_accesses": total_access_count,
                "average_age_seconds": sum(ages) / len(ages),
                "oldest_entry_age_seconds": max(ages),
                "newest_entry_age_seconds": min(ages),
                "entries_by_ttl": {
                    str(entry["ttl"]): sum(
                        1 for e in self._cache.values() if e["ttl"] == entry["ttl"]
                    )
                    for entry in self._cache.values()
                },
            }

    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        current_time = time.time()
        removed = 0

        with self._lock:
            keys_to_remove = [
                k
                for k, entry in self._cache.items()
                if current_time > entry["expires_at"]
            ]

            for key in keys_to_remove:
                del self._cache[key]
                removed += 1

        return removed


# Global cache instance
_global_cache = QueryResultCache()


def cached_query(ttl: int = 300, key_prefix: str = ""):
    """Decorator for caching query results."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            func_name = func.__name__
            args_str = str(args) + str(sorted(kwargs.items()))
            cache_key = f"{key_prefix}{func_name}:{hash(args_str)}"

            # Try to get from cache first
            cached_result = _global_cache.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            result = func(*args, **kwargs)
            _global_cache.set(cache_key, result, ttl)
            return result

        # Add cache management methods
        wrapper._cache_key_prefix = f"{key_prefix}{func.__name__}"
        wrapper.invalidate_cache = lambda: _global_cache.invalidate_pattern(
            wrapper._cache_key_prefix
        )
        wrapper.get_cache_stats = lambda: _global_cache.get_stats()

        return wrapper

    return decorator


def get_global_cache() -> QueryResultCache:
    """Get the global query result cache instance."""
    return _global_cache


def cache_dashboard_queries(service_class):
    """Class decorator to add caching to dashboard queries."""

    # Cache dashboard data with 5-minute TTL
    original_get_dashboard_data = service_class.get_dashboard_data
    service_class.get_dashboard_data = cached_query(ttl=300, key_prefix="dashboard:")(
        original_get_dashboard_data
    )

    return service_class


class CachedRepositoryMixin:
    """Mixin to add query caching capabilities to repository classes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._query_cache = QueryResultCache(default_ttl=300)

    def cached_query(self, cache_key: str, query_func: Callable, ttl: int = 300) -> Any:
        """Execute a query with caching."""
        cached_result = self._query_cache.get(cache_key)
        if cached_result is not None:
            return cached_result

        result = query_func()
        self._query_cache.set(cache_key, result, ttl)
        return result

    def invalidate_cache(self, pattern: str = "") -> int:
        """Invalidate cache entries matching pattern."""
        if pattern:
            return self._query_cache.invalidate_pattern(pattern)
        else:
            return self._query_cache.clear()

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self._query_cache.get_stats()
