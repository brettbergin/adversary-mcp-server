"""False positive management for tracking and suppressing vulnerability findings."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..logger import get_logger

logger = get_logger("false_positive_manager")


class FalsePositiveManager:
    """Manager for tracking and handling false positive vulnerability findings.

    This class manages false positives by storing them directly within
    .adversary.json files alongside the threats they represent.
    """

    def __init__(self, adversary_file_path: str):
        """Initialize false positive manager.

        Args:
            adversary_file_path: Path to the .adversary.json file to manage.
        """
        self.adversary_file = Path(adversary_file_path)

        # Performance optimization: Cache for false positive lookups
        self._fp_cache: dict[str, dict[str, Any] | None] = {}
        self._cache_file_mtime: float = 0

    def _invalidate_cache_if_needed(self) -> None:
        """Invalidate cache if .adversary.json file was modified."""
        try:
            if self.adversary_file.exists():
                current_mtime = self.adversary_file.stat().st_mtime
                if current_mtime != self._cache_file_mtime:
                    logger.debug(
                        f"Cache invalidated: {self.adversary_file} was modified"
                    )
                    self._fp_cache.clear()
                    self._cache_file_mtime = 0
        except OSError:
            # File might have been deleted or is inaccessible
            if self._cache_file_mtime > 0:
                logger.debug(
                    f"Cache invalidated: {self.adversary_file} is no longer accessible"
                )
                self._fp_cache.clear()
                self._cache_file_mtime = 0

    def _build_false_positive_cache(self) -> None:
        """Build cache of all false positive UUIDs and their metadata."""
        if self._fp_cache:
            return  # Cache already built and valid

        logger.debug("Building false positive cache...")
        start_time = datetime.now()

        # Load from .adversary.json file in project root
        try:
            if self.adversary_file.exists():
                # Track file modification time for cache invalidation
                self._cache_file_mtime = self.adversary_file.stat().st_mtime

                data = self._load_adversary_json()
                if data and "threats" in data:
                    for threat in data["threats"]:
                        threat_uuid = threat.get("uuid")
                        if threat_uuid and threat.get("is_false_positive"):
                            self._fp_cache[threat_uuid] = {
                                "uuid": threat_uuid,
                                "reason": threat.get("false_positive_reason", ""),
                                "marked_date": threat.get(
                                    "false_positive_marked_date", ""
                                ),
                                "last_updated": threat.get(
                                    "false_positive_last_updated", ""
                                ),
                                "marked_by": threat.get(
                                    "false_positive_marked_by", "system"
                                ),
                                "source": "project",
                            }
        except Exception as e:
            logger.warning(f"Failed to load .adversary.json for cache: {e}")

        build_time = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"False positive cache built: {len(self._fp_cache)} entries in {build_time:.3f}s"
        )

    def _load_adversary_json(self) -> dict[str, Any] | None:
        """Load and parse the .adversary.json file.

        Returns:
            Parsed JSON data or None if file cannot be loaded
        """
        if not self.adversary_file.exists():
            return None

        try:
            with open(self.adversary_file, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(
                f"Failed to load .adversary.json file {self.adversary_file}: {e}"
            )
            return None

    def _save_adversary_json(self, data: dict[str, Any]) -> bool:
        """Save data to the .adversary.json file.

        Args:
            data: Data to save

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            with open(self.adversary_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except OSError as e:
            logger.error(
                f"Failed to save .adversary.json file {self.adversary_file}: {e}"
            )
            return False

    def get_false_positive_details(self, finding_uuid: str) -> dict[str, Any] | None:
        """Get complete false positive details for a finding.

        Args:
            finding_uuid: UUID of the finding to check

        Returns:
            False positive metadata dict if marked, None otherwise
        """
        # Use cached lookup for performance
        self._invalidate_cache_if_needed()
        self._build_false_positive_cache()

        return self._fp_cache.get(finding_uuid)

    def mark_false_positive(
        self,
        finding_uuid: str,
        reason: str = "",
        marked_by: str = "user",
    ) -> bool:
        """Mark a finding as a false positive in .adversary.json file.

        Args:
            finding_uuid: UUID of the finding to mark
            reason: Reason for marking as false positive
            marked_by: Who marked it as false positive

        Returns:
            True if marked successfully, False if finding not found
        """
        # Ensure cache is up-to-date before loading data
        self._invalidate_cache_if_needed()

        # Load .adversary.json data
        data = self._load_adversary_json()
        if not data or "threats" not in data:
            logger.warning(f"No .adversary.json file found for {finding_uuid}")
            return False

        # Find and update the threat
        updated = False
        for threat in data["threats"]:
            if threat.get("uuid") == finding_uuid:
                # Create or update false positive fields
                current_time = datetime.now().isoformat()

                threat["is_false_positive"] = True
                threat["false_positive_reason"] = reason
                threat["false_positive_marked_by"] = marked_by
                threat["false_positive_last_updated"] = current_time

                # Set marked_date if not already set
                if not threat.get("false_positive_marked_date"):
                    threat["false_positive_marked_date"] = current_time

                if self._save_adversary_json(data):
                    updated = True
                    # Invalidate cache since we modified the data
                    self._fp_cache.clear()
                    self._cache_file_mtime = 0
                    adversary_file_abs = str(self.adversary_file.resolve())
                    logger.info(
                        f"Marked threat {finding_uuid} as false positive in {adversary_file_abs}"
                    )
                else:
                    adversary_file_abs = str(self.adversary_file.resolve())
                    logger.error(
                        f"Failed to save false positive update to {adversary_file_abs}"
                    )
                break

        if not updated:
            logger.warning(f"Threat {finding_uuid} not found in .adversary.json")

        return updated

    def unmark_false_positive(self, finding_uuid: str) -> bool:
        """Remove false positive marking from a finding.

        Args:
            finding_uuid: UUID of the finding to unmark

        Returns:
            True if finding was unmarked, False if not found
        """
        # Ensure cache is up-to-date before loading data
        self._invalidate_cache_if_needed()

        # Load .adversary.json file
        data = self._load_adversary_json()
        if not data or "threats" not in data:
            logger.warning(
                f"No .adversary.json file found for unmarking {finding_uuid}"
            )
            return False

        updated = False
        for threat in data["threats"]:
            if threat.get("uuid") == finding_uuid and threat.get("is_false_positive"):
                # Remove false positive marking
                threat["is_false_positive"] = False
                threat["false_positive_reason"] = None
                threat["false_positive_marked_date"] = None
                threat["false_positive_last_updated"] = None
                threat["false_positive_marked_by"] = None

                if self._save_adversary_json(data):
                    updated = True
                    # Invalidate cache since we modified the data
                    self._fp_cache.clear()
                    self._cache_file_mtime = 0
                    adversary_file_abs = str(self.adversary_file.resolve())
                    logger.info(
                        f"Unmarked threat {finding_uuid} as false positive in {adversary_file_abs}"
                    )
                else:
                    adversary_file_abs = str(self.adversary_file.resolve())
                    logger.error(
                        f"Failed to save false positive removal to {adversary_file_abs}"
                    )
                break

        return updated

    def is_false_positive(self, finding_uuid: str) -> bool:
        """Check if a finding is marked as false positive.

        Args:
            finding_uuid: UUID of the finding to check

        Returns:
            True if marked as false positive, False otherwise
        """
        return self.get_false_positive_details(finding_uuid) is not None

    def get_false_positives(self) -> list[dict[str, Any]]:
        """Get all false positive findings from .adversary.json file.

        Returns:
            List of false positive findings
        """
        false_positives = []

        # Ensure cache is up-to-date before loading data
        self._invalidate_cache_if_needed()

        # Get false positives from .adversary.json file
        data = self._load_adversary_json()
        if data and "threats" in data:
            for threat in data["threats"]:
                if threat.get("is_false_positive"):
                    fp_data = {
                        "uuid": threat.get("uuid"),
                        "reason": threat.get("false_positive_reason", ""),
                        "marked_date": threat.get("false_positive_marked_date", ""),
                        "last_updated": threat.get("false_positive_last_updated", ""),
                        "marked_by": threat.get("false_positive_marked_by", "system"),
                        "source": "project",
                        "file_source": str(self.adversary_file),
                    }
                    false_positives.append(fp_data)

        return false_positives

    def get_false_positive_uuids(self) -> set[str]:
        """Get set of all false positive UUIDs for quick lookup.

        Returns:
            Set of false positive UUIDs
        """
        false_positives = self.get_false_positives()
        return {fp["uuid"] for fp in false_positives}

    def filter_false_positives(self, threats: list) -> list:
        """Filter out false positives from a list of threat matches.

        Args:
            threats: List of ThreatMatch objects

        Returns:
            List of threats with false positives filtered out
        """
        false_positive_uuids = self.get_false_positive_uuids()

        filtered_threats = []
        for threat in threats:
            if hasattr(threat, "uuid") and threat.uuid in false_positive_uuids:
                # Mark as false positive but keep in results for transparency
                if hasattr(threat, "is_false_positive"):
                    threat.is_false_positive = True
            filtered_threats.append(threat)

        return filtered_threats

    def clear_all_false_positives(self) -> None:
        """Clear all false positive markings from .adversary.json file."""
        # Ensure cache is up-to-date before loading data
        self._invalidate_cache_if_needed()

        # Clear from .adversary.json file
        data = self._load_adversary_json()
        if not data or "threats" not in data:
            logger.info("No .adversary.json file found to clear false positives from")
            return

        updated = False
        for threat in data["threats"]:
            if threat.get("is_false_positive"):
                threat["is_false_positive"] = False
                threat["false_positive_reason"] = None
                threat["false_positive_marked_date"] = None
                threat["false_positive_last_updated"] = None
                threat["false_positive_marked_by"] = None
                updated = True

        if updated:
            self._save_adversary_json(data)
            adversary_file_abs = str(self.adversary_file.resolve())
            logger.info(f"Cleared false positives from {adversary_file_abs}")

        # Invalidate cache since we cleared all data
        self._fp_cache.clear()
        self._cache_file_mtime = 0

    def export_false_positives(self, output_path: Path) -> None:
        """Export false positives to a file.

        Args:
            output_path: Path to export file
        """
        false_positives = self.get_false_positives()
        data = {"false_positives": false_positives, "version": "2.0"}
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
