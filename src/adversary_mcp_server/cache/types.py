"""Type definitions for the caching system."""

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any


class CacheType(str, Enum):
    """Types of cache entries."""

    LLM_RESPONSE = "llm_response"
    SEMGREP_RESULT = "semgrep_result"
    VALIDATION_RESULT = "validation_result"
    FILE_ANALYSIS = "file_analysis"
    PROJECT_CONTEXT = "project_context"
    ANALYSIS_RESULT = "analysis_result"
    BATCH_LLM_RESPONSE = "batch_llm_response"  # For batch analysis results
    DEDUPLICATED_CONTENT = "deduplicated_content"  # For content deduplication


@dataclass
class CacheKey:
    """Unique identifier for cache entries."""

    cache_type: CacheType
    content_hash: str
    metadata_hash: str | None = None  # For context-dependent caching

    def __str__(self) -> str:
        parts = [self.cache_type.value, self.content_hash]
        if self.metadata_hash:
            parts.append(self.metadata_hash)
        return ":".join(parts)


@dataclass
class CacheEntry:
    """Cache entry with metadata and expiration."""

    key: CacheKey
    data: Any
    created_at: float
    expires_at: float | None = None
    access_count: int = 0
    last_accessed: float = 0
    size_bytes: int = 0

    def __post_init__(self):
        if self.last_accessed == 0:
            self.last_accessed = self.created_at

    @property
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def age_seconds(self) -> float:
        """Get age of cache entry in seconds."""
        return time.time() - self.created_at

    def mark_accessed(self) -> None:
        """Mark entry as accessed and increment counter."""
        self.access_count += 1
        self.last_accessed = time.time()


@dataclass
class CacheStats:
    """Statistics about cache performance."""

    total_entries: int = 0
    total_size_bytes: int = 0
    hit_count: int = 0
    miss_count: int = 0
    eviction_count: int = 0
    error_count: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_requests = self.hit_count + self.miss_count
        if total_requests == 0:
            return 0.0
        return self.hit_count / total_requests

    @property
    def average_entry_size(self) -> float:
        """Calculate average entry size in bytes."""
        if self.total_entries == 0:
            return 0.0
        return self.total_size_bytes / self.total_entries

    def to_dict(self) -> dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "total_entries": self.total_entries,
            "total_size_mb": round(self.total_size_bytes / (1024 * 1024), 2),
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "hit_rate": round(self.hit_rate * 100, 2),
            "eviction_count": self.eviction_count,
            "error_count": self.error_count,
            "average_entry_size_kb": round(self.average_entry_size / 1024, 2),
        }
