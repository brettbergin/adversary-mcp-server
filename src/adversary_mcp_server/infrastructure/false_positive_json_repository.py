"""Infrastructure adapter for false positive persistence using .adversary.json files."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from adversary_mcp_server.domain.value_objects.false_positive_info import (
    FalsePositiveInfo,
)

logger = logging.getLogger(__name__)


class FalsePositiveJsonRepository:
    """
    Infrastructure adapter for false positive persistence using .adversary.json files.

    This adapter implements the IFalsePositiveRepository interface and provides
    concrete persistence logic for storing false positive information in
    .adversary.json files alongside scan results.
    """

    def __init__(self, adversary_file_path: str):
        """
        Initialize the JSON repository.

        Args:
            adversary_file_path: Path to the .adversary.json file
        """
        self.adversary_file = Path(adversary_file_path)
        self.logger = logger

        # Performance optimization: Cache for false positive lookups
        self._fp_cache: dict[str, FalsePositiveInfo] = {}
        self._cache_file_mtime: float = 0

    def _invalidate_cache_if_needed(self) -> None:
        """Invalidate cache if .adversary.json file was modified."""
        try:
            if self.adversary_file.exists():
                current_mtime = self.adversary_file.stat().st_mtime
                if current_mtime != self._cache_file_mtime:
                    self.logger.debug(
                        f"Cache invalidated: {self.adversary_file} was modified"
                    )
                    self._fp_cache.clear()
                    self._cache_file_mtime = 0
        except OSError:
            # File might have been deleted or is inaccessible
            if self._cache_file_mtime > 0:
                self.logger.debug(
                    f"Cache invalidated: {self.adversary_file} is no longer accessible"
                )
                self._fp_cache.clear()
                self._cache_file_mtime = 0

    def _build_cache(self) -> None:
        """Build cache of all false positive information."""
        if self._fp_cache:
            return  # Cache already built and valid

        self.logger.debug("Building false positive cache...")
        start_time = datetime.now()

        try:
            data = self._load_adversary_json()
            if data and "threats" in data:
                # Track file modification time for cache invalidation
                if self.adversary_file.exists():
                    self._cache_file_mtime = self.adversary_file.stat().st_mtime

                for threat in data["threats"]:
                    threat_uuid = threat.get("uuid")
                    if threat_uuid:
                        try:
                            fp_info = FalsePositiveInfo.from_dict(threat)
                            self._fp_cache[threat_uuid] = fp_info
                        except (ValueError, KeyError) as e:
                            self.logger.warning(
                                f"Failed to parse false positive info for {threat_uuid}: {e}"
                            )
        except Exception as e:
            self.logger.warning(f"Failed to build false positive cache: {e}")

        build_time = (datetime.now() - start_time).total_seconds()
        self.logger.info(
            f"False positive cache built: {len(self._fp_cache)} entries in {build_time:.3f}s"
        )

    def _load_adversary_json(self) -> dict[str, Any] | None:
        """Load and parse the .adversary.json file."""
        if not self.adversary_file.exists():
            return None

        try:
            with open(self.adversary_file, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            self.logger.warning(
                f"Failed to load .adversary.json file {self.adversary_file}: {e}"
            )
            return None

    def _save_adversary_json(self, data: dict[str, Any]) -> bool:
        """Save data to the .adversary.json file."""
        try:
            # Ensure parent directory exists
            self.adversary_file.parent.mkdir(parents=True, exist_ok=True)

            # Write atomically using temporary file
            temp_path = self.adversary_file.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Atomic move
            temp_path.replace(self.adversary_file)

            # Invalidate cache since we modified the file
            self._fp_cache.clear()
            self._cache_file_mtime = 0

            return True

        except OSError as e:
            self.logger.error(
                f"Failed to save .adversary.json file {self.adversary_file}: {e}"
            )
            return False

    async def get_false_positive_info(self, uuid: str) -> FalsePositiveInfo | None:
        """Retrieve false positive information for a finding."""
        try:
            self._invalidate_cache_if_needed()
            self._build_cache()
            return self._fp_cache.get(uuid)
        except Exception as e:
            self.logger.error(f"Error retrieving false positive info for {uuid}: {e}")
            return None

    async def save_false_positive_info(self, info: FalsePositiveInfo) -> bool:
        """Save false positive information."""
        try:
            # Load current data
            data = self._load_adversary_json()
            if not data:
                self.logger.warning(
                    f"No .adversary.json file found at {self.adversary_file} - cannot save false positive info"
                )
                return False

            if "threats" not in data:
                self.logger.warning("No threats section in .adversary.json file")
                return False

            # Find and update the threat
            updated = False
            for threat in data["threats"]:
                if threat.get("uuid") == info.uuid:
                    # Update threat with false positive information
                    fp_dict = info.to_dict()
                    threat.update(fp_dict)
                    updated = True
                    break

            if not updated:
                self.logger.warning(
                    f"Threat {info.uuid} not found in .adversary.json file"
                )
                return False

            # Save the updated data
            success = self._save_adversary_json(data)

            if success:
                self.logger.info(
                    f"Saved false positive info for {info.uuid} to {self.adversary_file}"
                )

            return success

        except Exception as e:
            self.logger.error(f"Error saving false positive info for {info.uuid}: {e}")
            return False

    async def remove_false_positive_info(self, uuid: str) -> bool:
        """Remove false positive information for a finding."""
        try:
            # Create legitimate finding info to overwrite false positive data
            legitimate_info = FalsePositiveInfo.create_legitimate(uuid)
            return await self.save_false_positive_info(legitimate_info)

        except Exception as e:
            self.logger.error(f"Error removing false positive info for {uuid}: {e}")
            return False

    async def list_false_positives(self) -> list[FalsePositiveInfo]:
        """List all false positive information."""
        try:
            self._invalidate_cache_if_needed()
            self._build_cache()
            return list(self._fp_cache.values())
        except Exception as e:
            self.logger.error(f"Error listing false positives: {e}")
            return []

    def get_adversary_file_path(self) -> str:
        """Get the path to the adversary file being managed."""
        return str(self.adversary_file.resolve())

    def file_exists(self) -> bool:
        """Check if the adversary file exists."""
        return self.adversary_file.exists()

    def get_file_stats(self) -> dict[str, Any]:
        """Get statistics about the adversary file."""
        try:
            if not self.adversary_file.exists():
                return {
                    "exists": False,
                    "path": str(self.adversary_file.resolve()),
                }

            stat = self.adversary_file.stat()
            data = self._load_adversary_json()
            threat_count = len(data.get("threats", [])) if data else 0

            return {
                "exists": True,
                "path": str(self.adversary_file.resolve()),
                "size_bytes": stat.st_size,
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "threat_count": threat_count,
                "cache_entries": len(self._fp_cache),
            }

        except Exception as e:
            self.logger.error(f"Error getting file stats: {e}")
            return {
                "exists": False,
                "path": str(self.adversary_file.resolve()),
                "error": str(e),
            }
