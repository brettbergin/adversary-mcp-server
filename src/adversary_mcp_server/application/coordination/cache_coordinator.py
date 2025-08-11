"""Cache coordination for scan result caching and retrieval."""

from pathlib import Path
from typing import Any

from ...cache import CacheKey, CacheType, SerializableThreatMatch
from ...interfaces.cache import ICacheManager
from ...logger import get_logger
from ...scanner.scan_engine import EnhancedScanResult

logger = get_logger("cache_coordinator")


class CacheCoordinator:
    """Coordinates caching operations for scan results."""

    def __init__(self, cache_manager: ICacheManager | None = None):
        """Initialize the cache coordinator."""
        self.cache_manager = cache_manager
        logger.debug(
            f"CacheCoordinator initialized with cache_manager: {cache_manager is not None}"
        )

    def is_cache_available(self) -> bool:
        """Check if cache is available for operations."""
        return self.cache_manager is not None

    async def get_cached_scan_result(
        self,
        file_path: Path,
        content_hash: str,
        scan_parameters: dict[str, Any],
    ) -> EnhancedScanResult | None:
        """Get cached scan result if available."""
        if not self.cache_manager:
            return None

        try:
            # Create cache key based on content and scan parameters
            metadata = {
                "use_llm": scan_parameters.get("use_llm", True),
                "use_semgrep": scan_parameters.get("use_semgrep", True),
                "use_validation": scan_parameters.get("use_validation", True),
                "language": scan_parameters.get("language"),
                "severity_threshold": str(scan_parameters.get("severity_threshold")),
            }

            metadata_hash = self.cache_manager.get_hasher().hash_metadata(metadata)

            cache_key = CacheKey(
                cache_type=CacheType.FILE_ANALYSIS,
                content_hash=f"{file_path.name}:{content_hash}:{metadata_hash}",
                metadata_hash=scan_parameters.get("language"),
            )

            cached_data = self.cache_manager.get(cache_key)
            if cached_data and isinstance(cached_data, dict):
                result = self._deserialize_scan_result(cached_data)
                # Add cache metadata
                result.scan_metadata["cache_hit"] = True
                result.scan_metadata["cache_key"] = str(cache_key)
                logger.info(f"Cache hit for scan: {file_path}")
                return result
            else:
                logger.debug(f"Cache miss for scan: {file_path}")
                return None

        except Exception as e:
            logger.warning(f"Failed to retrieve cached scan result: {e}")
            return None

    async def cache_scan_result(
        self,
        file_path: Path,
        result: EnhancedScanResult,
        content_hash: str,
        scan_parameters: dict[str, Any],
        cache_expiry_seconds: int | None = None,
    ) -> None:
        """Cache scan result for future use."""
        if not self.cache_manager:
            return

        try:
            # Create cache key
            metadata = {
                "use_llm": scan_parameters.get("use_llm", True),
                "use_semgrep": scan_parameters.get("use_semgrep", True),
                "use_validation": scan_parameters.get("use_validation", True),
                "language": scan_parameters.get("language"),
                "severity_threshold": str(scan_parameters.get("severity_threshold")),
            }

            metadata_hash = self.cache_manager.get_hasher().hash_metadata(metadata)

            cache_key = CacheKey(
                cache_type=CacheType.FILE_ANALYSIS,
                content_hash=f"{file_path.name}:{content_hash}:{metadata_hash}",
                metadata_hash=scan_parameters.get("language"),
            )

            # Serialize the result
            serialized_result = self._serialize_scan_result(result)

            # Add cache metadata to result before storing
            result.scan_metadata["cache_hit"] = False
            result.scan_metadata["cache_key"] = str(cache_key)

            # Cache the result
            self.cache_manager.put(cache_key, serialized_result, cache_expiry_seconds)
            logger.debug(f"Cached scan result for {file_path}")

        except Exception as e:
            logger.warning(f"Failed to cache scan result: {e}")

    def create_content_hash(self, content: str) -> str:
        """Create content hash for caching."""
        if not self.cache_manager:
            return ""

        try:
            return self.cache_manager.get_hasher().hash_content(content)
        except Exception as e:
            logger.warning(f"Failed to create content hash: {e}")
            return ""

    def create_cache_key_for_code(
        self,
        content: str,
        scan_parameters: dict[str, Any],
    ) -> CacheKey | None:
        """Create cache key for code snippet analysis."""
        if not self.cache_manager:
            return None

        try:
            hasher = self.cache_manager.get_hasher()
            content_hash = hasher.hash_content(content)

            metadata = {
                "use_llm": scan_parameters.get("use_llm", True),
                "use_semgrep": scan_parameters.get("use_semgrep", True),
                "use_validation": scan_parameters.get("use_validation", True),
                "language": scan_parameters.get("language"),
                "severity_threshold": str(scan_parameters.get("severity_threshold")),
            }
            metadata_hash = hasher.hash_metadata(metadata)

            return CacheKey(
                cache_type=CacheType.FILE_ANALYSIS,
                content_hash=f"code:{content_hash}:{metadata_hash}",
                metadata_hash=scan_parameters.get("language"),
            )

        except Exception as e:
            logger.warning(f"Failed to create cache key for code: {e}")
            return None

    def get_cached_code_result(self, cache_key: CacheKey) -> EnhancedScanResult | None:
        """Get cached result for code analysis."""
        if not self.cache_manager or not cache_key:
            return None

        try:
            cached_data = self.cache_manager.get(cache_key)
            if cached_data and isinstance(cached_data, dict):
                result = self._deserialize_scan_result(cached_data)
                result.scan_metadata["cache_hit"] = True
                result.scan_metadata["cache_key"] = str(cache_key)
                logger.info("Cache hit for code analysis")
                return result
            else:
                logger.debug("Cache miss for code analysis")
                return None

        except Exception as e:
            logger.warning(f"Cache check failed for code analysis: {e}")
            return None

    def cache_code_result(
        self,
        cache_key: CacheKey,
        result: EnhancedScanResult,
        cache_expiry_seconds: int | None = None,
    ) -> None:
        """Cache result for code analysis."""
        if not self.cache_manager or not cache_key:
            return

        try:
            result.scan_metadata["cache_hit"] = False
            result.scan_metadata["cache_key"] = str(cache_key)

            serialized_result = self._serialize_scan_result(result)
            self.cache_manager.put(cache_key, serialized_result, cache_expiry_seconds)
            logger.debug("Cached code analysis result")

        except Exception as e:
            logger.warning(f"Failed to cache code result: {e}")

    def _serialize_scan_result(self, result: EnhancedScanResult) -> dict[str, Any]:
        """Serialize scan result for caching."""
        return {
            "file_path": result.file_path,
            "llm_threats": [
                SerializableThreatMatch.from_threat_match(threat).to_dict()
                for threat in result.llm_threats
            ],
            "semgrep_threats": [
                SerializableThreatMatch.from_threat_match(threat).to_dict()
                for threat in result.semgrep_threats
            ],
            "scan_metadata": result.scan_metadata,
            "validation_results": result.validation_results,
            "llm_usage_stats": result.llm_usage_stats,
            "stats": getattr(result, "stats", None),
        }

    def _deserialize_scan_result(
        self, cached_data: dict[str, Any]
    ) -> EnhancedScanResult:
        """Deserialize cached data back to EnhancedScanResult."""
        llm_threats = [
            SerializableThreatMatch.from_dict(threat_data).to_threat_match()
            for threat_data in cached_data.get("llm_threats", [])
        ]
        semgrep_threats = [
            SerializableThreatMatch.from_dict(threat_data).to_threat_match()
            for threat_data in cached_data.get("semgrep_threats", [])
        ]

        result = EnhancedScanResult(
            file_path=cached_data["file_path"],
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=cached_data.get("scan_metadata", {}),
            validation_results=cached_data.get("validation_results", {}),
            llm_usage_stats=cached_data.get("llm_usage_stats"),
        )

        # Restore stats if available
        if "stats" in cached_data:
            result.stats = cached_data["stats"]

        return result
