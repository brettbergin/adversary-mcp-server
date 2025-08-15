"""Intelligent cache manager with LRU eviction and git-aware invalidation."""

import json
import time
from pathlib import Path
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from ..database.models import AdversaryDatabase
from ..database.models import CacheEntry as CacheEntryModel
from ..logger import get_logger
from ..telemetry.integration import MetricsCollectionOrchestrator
from ..telemetry.service import TelemetryService
from .content_hasher import ContentHasher
from .types import CacheEntry, CacheKey, CacheStats, CacheType

logger = get_logger("cache_manager")


class CacheManager:
    """Intelligent cache manager with content-based hashing and LRU eviction."""

    def __init__(
        self,
        cache_dir: Path,
        max_size_mb: int = 500,
        max_age_hours: int = 24,
        enable_persistence: bool = True,
        metrics_collector=None,
        metrics_orchestrator: MetricsCollectionOrchestrator = None,
    ):
        """Initialize cache manager.

        Args:
            cache_dir: Directory to store cache files
            max_size_mb: Maximum cache size in MB
            max_age_hours: Maximum age for cache entries in hours
            enable_persistence: Whether to persist cache to disk
            metrics_collector: Optional legacy metrics collector for cache operations
            metrics_orchestrator: Optional telemetry orchestrator for comprehensive tracking
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_age_seconds = max_age_hours * 3600
        self.enable_persistence = enable_persistence
        self.metrics_collector = metrics_collector

        # Initialize database connection for ORM operations
        try:
            self._db = AdversaryDatabase()
            logger.debug("Initialized database connection for cache manager")
        except Exception as e:
            logger.error(f"Failed to initialize database connection: {e}")
            raise

        # Initialize telemetry system
        self.metrics_orchestrator = metrics_orchestrator
        if self.metrics_orchestrator is None:
            try:
                telemetry_service = TelemetryService(self._db)
                self.metrics_orchestrator = MetricsCollectionOrchestrator(
                    telemetry_service
                )
                logger.debug("Initialized telemetry system for cache manager")
            except Exception as e:
                logger.warning(f"Failed to initialize telemetry system for cache: {e}")
                self.metrics_orchestrator = None

        # In-memory cache storage
        self._cache: dict[str, CacheEntry] = {}
        self._stats = CacheStats()
        self._hasher = ContentHasher()

        # Initialize database schema (ORM handles this)
        try:
            self._db.get_session()  # Ensures database is initialized
            logger.debug("Database schema initialized for cache manager")
        except Exception as e:
            logger.warning(f"Failed to initialize database schema: {e}")

        # Load cache from disk if persistence enabled
        if self.enable_persistence:
            self._load_cache()

        logger.info(
            f"Cache manager initialized: max_size={max_size_mb}MB, max_age={max_age_hours}h"
        )

    def _load_cache(self) -> None:
        """Load cache entries from disk using SQLAlchemy ORM."""
        try:
            with self._db.get_session() as session:
                entries = session.query(CacheEntryModel).all()

                loaded_count = 0
                for entry in entries:
                    key_str = entry.key
                    cache_type = entry.cache_type
                    content_hash = entry.content_hash
                    created_at = entry.created_at
                    expires_at = entry.expires_at
                    access_count = entry.access_count
                    last_accessed = entry.last_accessed
                    size_bytes = entry.data_size_bytes
                    cache_metadata = entry.cache_metadata or {}

                    # Reconstruct cache key
                    cache_key = CacheKey(
                        cache_type=CacheType(cache_type),
                        content_hash=str(content_hash),
                        metadata_hash=cache_metadata.get("metadata_hash", ""),
                    )

                    # Try to load data from disk
                    data_file = self.cache_dir / f"{key_str}.json"
                    if data_file.exists():
                        try:
                            with open(data_file, encoding="utf-8") as f:
                                data = json.load(f)

                            entry = CacheEntry(
                                key=cache_key,
                                data=data,
                                created_at=float(created_at),
                                expires_at=float(expires_at) if expires_at else None,
                                access_count=int(access_count),
                                last_accessed=float(last_accessed),
                                size_bytes=int(size_bytes),
                            )

                            # Skip expired entries
                            if not entry.is_expired:
                                self._cache[key_str] = entry
                                loaded_count += 1
                        except Exception as e:
                            logger.warning(f"Failed to load cache entry {key_str}: {e}")
                            # Clean up corrupted file
                            data_file.unlink(missing_ok=True)

                logger.info(f"Loaded {loaded_count} cache entries from disk")

        except SQLAlchemyError as e:
            logger.error(f"Failed to load cache from database: {e}")
            # Initialize empty cache on database error

        except Exception as e:
            logger.error(f"Failed to load cache from disk: {e}")

    def _save_entry_to_disk(self, key_str: str, entry: CacheEntry) -> None:
        """Save cache entry to disk."""
        if not self.enable_persistence:
            return

        try:
            # Save data to JSON file
            data_file = self.cache_dir / f"{key_str}.json"
            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(entry.data, f, indent=2, default=self._json_serializer)

            # Update database metadata using ORM
            try:
                with self._db.get_session() as session:
                    # Check if entry exists and update or create
                    db_entry = (
                        session.query(CacheEntryModel).filter_by(key=key_str).first()
                    )
                    if db_entry:
                        # Update existing entry
                        db_entry.cache_type = entry.key.cache_type.value
                        db_entry.content_hash = entry.key.content_hash
                        db_entry.created_at = entry.created_at
                        db_entry.expires_at = entry.expires_at
                        db_entry.access_count = entry.access_count
                        db_entry.last_accessed = entry.last_accessed
                        db_entry.data_size_bytes = entry.size_bytes
                        db_entry.cache_metadata = {
                            "metadata_hash": entry.key.metadata_hash
                        }
                    else:
                        # Create new entry
                        db_entry = CacheEntryModel(
                            key=key_str,
                            cache_type=entry.key.cache_type.value,
                            content_hash=entry.key.content_hash,
                            created_at=entry.created_at,
                            expires_at=entry.expires_at,
                            access_count=entry.access_count,
                            last_accessed=entry.last_accessed,
                            data_size_bytes=entry.size_bytes,
                            cache_metadata={"metadata_hash": entry.key.metadata_hash},
                        )
                        session.add(db_entry)
                    session.commit()
            except SQLAlchemyError as e:
                logger.error(f"Failed to save cache entry to database: {e}")

        except Exception as e:
            logger.error(f"Failed to save cache entry {key_str}: {e}")
            self._stats.error_count += 1

    def _remove_entry_from_disk(self, key_str: str) -> None:
        """Remove cache entry from disk."""
        if not self.enable_persistence:
            return

        try:
            # Remove data file
            data_file = self.cache_dir / f"{key_str}.json"
            data_file.unlink(missing_ok=True)

            # Remove from database using ORM
            try:
                with self._db.get_session() as session:
                    entry = (
                        session.query(CacheEntryModel).filter_by(key=key_str).first()
                    )
                    if entry:
                        session.delete(entry)
                        session.commit()
                        logger.debug(f"Removed cache entry from database: {key_str}")
            except SQLAlchemyError as e:
                logger.error(f"Failed to remove cache entry from database: {e}")

        except Exception as e:
            logger.error(f"Failed to remove cache entry {key_str}: {e}")

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for complex objects."""
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        elif hasattr(obj, "__dict__"):
            return obj.__dict__
        else:
            return str(obj)

    def _estimate_size(self, data: Any) -> int:
        """Estimate size of data in bytes."""
        try:
            return len(json.dumps(data, default=self._json_serializer).encode("utf-8"))
        except Exception:
            # Fallback to string representation
            return len(str(data).encode("utf-8"))

    def _evict_lru_entries(self, target_size: int) -> None:
        """Evict least recently used entries to free up space."""
        if not self._cache:
            return

        # Sort by last accessed time (oldest first)
        sorted_entries = sorted(self._cache.items(), key=lambda x: x[1].last_accessed)

        current_size = sum(entry.size_bytes for entry in self._cache.values())
        freed_size = 0

        for key_str, entry in sorted_entries:
            if current_size - freed_size <= target_size:
                break

            # Remove entry
            del self._cache[key_str]
            self._remove_entry_from_disk(key_str)

            freed_size += entry.size_bytes
            self._stats.eviction_count += 1

            # Legacy metrics
            if self.metrics_collector:
                self.metrics_collector.record_metric(
                    "cache_evictions_total", 1, labels={"reason": "lru"}
                )
                self.metrics_collector.record_metric(
                    "cache_evicted_bytes_total", entry.size_bytes
                )

            # New telemetry tracking
            if self.metrics_orchestrator:
                self.metrics_orchestrator.track_cache_operation(
                    operation_type="evict",
                    cache_name=(
                        entry.key.cache_type.value
                        if hasattr(entry.key, "cache_type")
                        else "unknown"
                    ),
                    key=key_str,
                    size_bytes=entry.size_bytes,
                    eviction_reason="lru",
                )

            logger.debug(f"Evicted cache entry: {key_str}")

        if freed_size > 0:
            logger.info(
                f"Evicted {len(sorted_entries)} entries, freed {freed_size / 1024:.1f} KB"
            )

    def _cleanup_expired_entries(self) -> None:
        """Remove expired cache entries."""
        current_time = time.time()
        expired_keys = []

        for key_str, entry in self._cache.items():
            if entry.is_expired or entry.age_seconds > self.max_age_seconds:
                expired_keys.append(key_str)

        for key_str in expired_keys:
            del self._cache[key_str]
            self._remove_entry_from_disk(key_str)
            logger.debug(f"Removed expired cache entry: {key_str}")

        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")

    def get(self, key: CacheKey) -> Any | None:
        """Get cached data by key.

        Args:
            key: Cache key to lookup

        Returns:
            Cached data if found and valid, None otherwise
        """
        key_str = str(key)

        if key_str not in self._cache:
            self._stats.miss_count += 1
            # Legacy metrics
            if self.metrics_collector:
                self.metrics_collector.record_cache_operation("get", hit=False)
            # New telemetry tracking
            if self.metrics_orchestrator:
                self.metrics_orchestrator.track_cache_operation(
                    operation_type="miss",
                    cache_name=(
                        key.cache_type.value
                        if hasattr(key, "cache_type")
                        else "unknown"
                    ),
                    key=key_str,
                    access_time_ms=0.0,
                )
            logger.debug(f"Cache miss: {key_str}")
            return None

        entry = self._cache[key_str]

        # Check if expired
        if entry.is_expired or entry.age_seconds > self.max_age_seconds:
            del self._cache[key_str]
            self._remove_entry_from_disk(key_str)
            self._stats.miss_count += 1
            # Legacy metrics
            if self.metrics_collector:
                self.metrics_collector.record_cache_operation("get", hit=False)
            # New telemetry tracking
            if self.metrics_orchestrator:
                self.metrics_orchestrator.track_cache_operation(
                    operation_type="expired",
                    cache_name=(
                        key.cache_type.value
                        if hasattr(key, "cache_type")
                        else "unknown"
                    ),
                    key=key_str,
                    access_time_ms=0.0,
                )
            logger.debug(f"Cache expired: {key_str}")
            return None

        # Update access stats
        entry.mark_accessed()
        self._stats.hit_count += 1
        # Legacy metrics
        if self.metrics_collector:
            self.metrics_collector.record_cache_operation("get", hit=True)
        # New telemetry tracking
        if self.metrics_orchestrator:
            self.metrics_orchestrator.track_cache_operation(
                operation_type="hit",
                cache_name=(
                    key.cache_type.value if hasattr(key, "cache_type") else "unknown"
                ),
                key=key_str,
                size_bytes=entry.size_bytes,
                access_time_ms=0.1,  # Approximate access time
            )
        logger.debug(f"Cache hit: {key_str}")

        return entry.data

    def put(
        self, key: CacheKey, data: Any, expires_in_seconds: int | None = None
    ) -> None:
        """Store data in cache.

        Args:
            key: Cache key for the data
            data: Data to cache
            expires_in_seconds: Optional expiration time in seconds
        """
        key_str = str(key)
        current_time = time.time()

        # Calculate expiration time
        expires_at = None
        if expires_in_seconds:
            expires_at = current_time + expires_in_seconds
        elif self.max_age_seconds > 0:
            expires_at = current_time + self.max_age_seconds

        # Estimate data size
        size_bytes = self._estimate_size(data)

        # Check if we need to evict entries
        current_size = sum(entry.size_bytes for entry in self._cache.values())
        if current_size + size_bytes > self.max_size_bytes:
            target_size = self.max_size_bytes - size_bytes
            self._evict_lru_entries(max(0, target_size))

        # Create cache entry
        entry = CacheEntry(
            key=key,
            data=data,
            created_at=current_time,
            expires_at=expires_at,
            size_bytes=size_bytes,
        )

        # Store in memory cache
        self._cache[key_str] = entry

        # Save to disk
        self._save_entry_to_disk(key_str, entry)

        # Track telemetry for cache set operation
        if self.metrics_orchestrator:
            self.metrics_orchestrator.track_cache_operation(
                operation_type="set",
                cache_name=(
                    key.cache_type.value if hasattr(key, "cache_type") else "unknown"
                ),
                key=key_str,
                size_bytes=size_bytes,
                access_time_ms=1.0,  # Approximate put time
                ttl_seconds=expires_in_seconds,
            )

        logger.debug(f"Cached data: {key_str} ({size_bytes} bytes)")

    def invalidate_by_content_hash(self, content_hash: str) -> int:
        """Invalidate all cache entries matching content hash.

        Args:
            content_hash: Content hash to invalidate

        Returns:
            Number of entries invalidated
        """
        invalidated_keys = []

        for key_str, entry in self._cache.items():
            if entry.key.content_hash == content_hash:
                invalidated_keys.append(key_str)

        for key_str in invalidated_keys:
            del self._cache[key_str]
            self._remove_entry_from_disk(key_str)

        if invalidated_keys:
            logger.info(
                f"Invalidated {len(invalidated_keys)} cache entries for content hash {content_hash[:8]}..."
            )

        return len(invalidated_keys)

    def invalidate_by_type(self, cache_type: CacheType) -> int:
        """Invalidate all cache entries of specified type.

        Args:
            cache_type: Cache type to invalidate

        Returns:
            Number of entries invalidated
        """
        invalidated_keys = []

        for key_str, entry in self._cache.items():
            if entry.key.cache_type == cache_type:
                invalidated_keys.append(key_str)

        for key_str in invalidated_keys:
            del self._cache[key_str]
            self._remove_entry_from_disk(key_str)

        if invalidated_keys:
            logger.info(
                f"Invalidated {len(invalidated_keys)} cache entries of type {cache_type.value}"
            )

        return len(invalidated_keys)

    def clear(self) -> None:
        """Clear all cache entries."""
        count = len(self._cache)

        # Remove all entries from disk
        for key_str in list(self._cache.keys()):
            self._remove_entry_from_disk(key_str)

        # Clear memory cache
        self._cache.clear()

        logger.info(f"Cleared {count} cache entries")

    def cleanup(self) -> None:
        """Perform cache maintenance (remove expired entries, update stats)."""
        logger.info("Starting cache cleanup...")

        # Remove expired entries
        self._cleanup_expired_entries()

        # Update total statistics
        self._stats.total_entries = len(self._cache)
        self._stats.total_size_bytes = sum(
            entry.size_bytes for entry in self._cache.values()
        )

        # Save updated stats using ORM
        if self.enable_persistence:
            try:
                # Note: Cache stats are now handled through telemetry system
                # Legacy stats saving removed in favor of telemetry integration
                logger.debug("Cache stats are now tracked through telemetry system")
            except Exception as e:
                logger.error(f"Failed to save cache stats: {e}")

        logger.info("Cache cleanup completed")

    def get_stats(self) -> CacheStats:
        """Get current cache statistics.

        Returns:
            Current cache statistics
        """
        # Update current stats
        self._stats.total_entries = len(self._cache)
        self._stats.total_size_bytes = sum(
            entry.size_bytes for entry in self._cache.values()
        )

        return self._stats

    def get_hasher(self) -> ContentHasher:
        """Get content hasher instance.

        Returns:
            Content hasher for generating cache keys
        """
        return self._hasher
