"""Cache interfaces for intelligent caching with content-based hashing."""

from typing import Any, Protocol, runtime_checkable

from ..cache.content_hasher import ContentHasher
from ..cache.types import CacheKey, CacheStats, CacheType


@runtime_checkable
class ICacheManager(Protocol):
    """Interface for intelligent cache management with content-based hashing.

    This interface defines the contract for caching systems that provide:
    - Content-based cache invalidation
    - LRU eviction with size management
    - Type-based cache organization
    - Persistent storage with SQLite
    - Git-aware cache invalidation
    """

    def get(self, key: CacheKey) -> Any | None:
        """Retrieve cached data by key.

        Args:
            key: Cache key to lookup

        Returns:
            Cached data if found and valid, None otherwise
        """
        ...

    def put(
        self, key: CacheKey, data: Any, expires_in_seconds: int | None = None
    ) -> None:
        """Store data in cache with optional expiration.

        Args:
            key: Cache key for the data
            data: Data to cache (must be JSON serializable)
            expires_in_seconds: Optional expiration time in seconds,
                               falls back to max_age_seconds if not specified
        """
        ...

    def invalidate_by_content_hash(self, content_hash: str) -> int:
        """Invalidate cache entries by content hash.

        Useful for git-aware cache invalidation when file content changes.

        Args:
            content_hash: Content hash to invalidate

        Returns:
            Number of entries invalidated
        """
        ...

    def invalidate_by_type(self, cache_type: CacheType) -> int:
        """Invalidate all cache entries of a specific type.

        Args:
            cache_type: Type of cache entries to invalidate

        Returns:
            Number of entries invalidated
        """
        ...

    def clear(self) -> None:
        """Clear all cache entries from memory and disk."""
        ...

    def cleanup(self) -> None:
        """Clean up expired entries and optimize cache performance."""
        ...

    def get_stats(self) -> CacheStats:
        """Get current cache statistics.

        Returns:
            Cache statistics including hit/miss ratios, entry counts, etc.
        """
        ...

    def get_hasher(self) -> ContentHasher:
        """Get the content hasher instance for manual hash computation.

        Returns:
            ContentHasher instance used by this cache manager
        """
        ...
