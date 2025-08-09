"""Configuration change tracking for intelligent cache invalidation."""

import hashlib
from pathlib import Path

from ..logger import get_logger
from .cache_manager import CacheManager
from .types import CacheType

logger = get_logger("config_tracker")


class ConfigurationTracker:
    """Track configuration changes for cache invalidation."""

    def __init__(self, cache_manager: CacheManager, state_file: Path | None = None):
        """Initialize configuration tracker.

        Args:
            cache_manager: Cache manager instance for invalidation
            state_file: Optional file to persist configuration state
        """
        self.cache_manager = cache_manager
        self.state_file = (
            state_file or Path.home() / ".adversary-mcp" / "config_state.txt"
        )
        self._last_config_hash = self._load_last_config_hash()

    def _load_last_config_hash(self) -> str | None:
        """Load last known configuration hash from disk."""
        try:
            if self.state_file.exists():
                return self.state_file.read_text().strip()
        except Exception as e:
            logger.warning(f"Failed to load config hash from {self.state_file}: {e}")
        return None

    def _save_config_hash(self, config_hash: str) -> None:
        """Save configuration hash to disk."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(config_hash)
        except Exception as e:
            logger.warning(f"Failed to save config hash to {self.state_file}: {e}")

    def _hash_config(self, config: dict | str) -> str:
        """Generate hash for configuration."""
        if isinstance(config, dict):
            # Sort keys for consistent hashing
            import json

            config_str = json.dumps(config, sort_keys=True, default=str)
        else:
            config_str = str(config)

        return hashlib.sha256(config_str.encode()).hexdigest()

    def check_and_invalidate_on_config_change(
        self, current_config: dict | str, cache_types: list[CacheType] | None = None
    ) -> bool:
        """Check if configuration changed and invalidate cache if needed.

        Args:
            current_config: Current configuration (dict or string)
            cache_types: Specific cache types to invalidate (default: all semgrep)

        Returns:
            True if configuration changed and cache was invalidated
        """
        config_hash = self._hash_config(current_config)

        if self._last_config_hash and self._last_config_hash != config_hash:
            # Configuration changed - invalidate relevant cache entries
            cache_types = cache_types or [CacheType.SEMGREP_RESULT]

            total_invalidated = 0
            for cache_type in cache_types:
                invalidated = self.cache_manager.invalidate_by_type(cache_type)
                total_invalidated += invalidated

            logger.info(
                f"Configuration changed (hash: {self._last_config_hash[:8]}... → {config_hash[:8]}...), "
                f"invalidated {total_invalidated} cache entries"
            )

            self._last_config_hash = config_hash
            self._save_config_hash(config_hash)
            return True

        if self._last_config_hash is None:
            # First time tracking this configuration
            self._last_config_hash = config_hash
            self._save_config_hash(config_hash)
            logger.info(f"Started tracking configuration (hash: {config_hash[:8]}...)")

        return False

    def force_invalidate(self, cache_types: list[CacheType] | None = None) -> int:
        """Force cache invalidation regardless of configuration state.

        Args:
            cache_types: Specific cache types to invalidate (default: all semgrep)

        Returns:
            Number of entries invalidated
        """
        cache_types = cache_types or [CacheType.SEMGREP_RESULT]

        total_invalidated = 0
        for cache_type in cache_types:
            invalidated = self.cache_manager.invalidate_by_type(cache_type)
            total_invalidated += invalidated

        logger.info(f"Force invalidated {total_invalidated} cache entries")
        return total_invalidated

    def get_current_config_hash(self) -> str | None:
        """Get the currently tracked configuration hash."""
        return self._last_config_hash

    def reset_tracking(self) -> None:
        """Reset configuration tracking state."""
        self._last_config_hash = None
        try:
            if self.state_file.exists():
                self.state_file.unlink()
            logger.info("Reset configuration tracking state")
        except Exception as e:
            logger.warning(f"Failed to reset config tracking: {e}")
