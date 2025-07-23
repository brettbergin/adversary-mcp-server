"""False positive management for tracking and suppressing vulnerability findings."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .logging_config import get_logger

logger = get_logger("false_positive_manager")


class FalsePositiveManager:
    """Manager for tracking and handling false positive vulnerability findings.

    This class now manages false positives by storing them directly within
    .adversary.json files alongside the threats they represent, providing
    better project-specific tracking and consolidation.
    """

    def __init__(self, working_directory: str | None = None):
        """Initialize false positive manager.

        Args:
            working_directory: Project directory to search for .adversary.json files.
                              If None, uses current working directory.
        """
        self.working_directory = (
            Path(working_directory) if working_directory else Path.cwd()
        )

        # Legacy support - keep the old config dir for migration
        self.config_dir = Path.home() / ".local" / "share" / "adversary-mcp-server"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.false_positives_file = self.config_dir / "false_positives.json"

    def _find_adversary_json_files(
        self, working_directory: str | None = None
    ) -> list[Path]:
        """Find all .adversary.json files in the specified directory and subdirectories.

        Args:
            working_directory: Directory to search in, defaults to instance working_directory

        Returns:
            List of paths to .adversary.json files
        """
        search_dir = (
            Path(working_directory) if working_directory else self.working_directory
        )
        adversary_files = []

        # Search in working directory and subdirectories
        for pattern in [".adversary.json", "*.adversary.json", "adversary*.json"]:
            adversary_files.extend(search_dir.rglob(pattern))

        return adversary_files

    def _load_adversary_json(self, file_path: Path) -> dict[str, Any] | None:
        """Load and parse a .adversary.json file.

        Args:
            file_path: Path to the .adversary.json file

        Returns:
            Parsed JSON data or None if file cannot be loaded
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load adversary JSON file {file_path}: {e}")
            return None

    def _save_adversary_json(self, file_path: Path, data: dict[str, Any]) -> bool:
        """Save data to a .adversary.json file.

        Args:
            file_path: Path to the .adversary.json file
            data: Data to save

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except OSError as e:
            logger.error(f"Failed to save adversary JSON file {file_path}: {e}")
            return False

    def _load_false_positives(self) -> dict[str, Any]:
        """Load false positives from legacy file (for migration support).

        Returns:
            Dictionary of false positive data
        """
        if not self.false_positives_file.exists():
            return {"false_positives": [], "version": "1.0"}

        try:
            with open(self.false_positives_file) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"false_positives": [], "version": "1.0"}

    def _save_false_positives(self, data: dict[str, Any]) -> None:
        """Save false positives to file.

        Args:
            data: False positive data to save
        """
        try:
            with open(self.false_positives_file, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            raise RuntimeError(f"Failed to save false positives: {e}")

    def get_false_positive_details(
        self, finding_uuid: str, working_directory: str | None = None
    ) -> dict[str, Any] | None:
        """Get complete false positive details for a finding.

        Args:
            finding_uuid: UUID of the finding to check
            working_directory: Directory to search for .adversary.json files

        Returns:
            False positive metadata dict if marked, None otherwise
        """
        # First check the new system (.adversary.json files)
        adversary_files = self._find_adversary_json_files(working_directory)

        for file_path in adversary_files:
            data = self._load_adversary_json(file_path)
            if not data or "threats" not in data:
                continue

            for threat in data["threats"]:
                if threat.get("uuid") == finding_uuid and threat.get(
                    "false_positive_metadata"
                ):
                    return threat["false_positive_metadata"]

        # Fallback to legacy system for migration support
        legacy_data = self._load_false_positives()
        for fp in legacy_data.get("false_positives", []):
            if fp["uuid"] == finding_uuid:
                return {
                    "uuid": fp["uuid"],
                    "reason": fp.get("reason", ""),
                    "marked_date": fp.get("marked_date", ""),
                    "last_updated": fp.get("last_updated", ""),
                    "marked_by": fp.get("marked_by", "system"),
                    "source": "legacy",
                }

        return None

    def mark_false_positive(
        self,
        finding_uuid: str,
        reason: str = "",
        marked_by: str = "user",
        working_directory: str | None = None,
    ) -> bool:
        """Mark a finding as a false positive in .adversary.json files.

        Args:
            finding_uuid: UUID of the finding to mark
            reason: Reason for marking as false positive
            marked_by: Who marked it as false positive
            working_directory: Directory to search for .adversary.json files

        Returns:
            True if marked successfully, False if finding not found
        """
        # Find and update the threat in .adversary.json files
        adversary_files = self._find_adversary_json_files(working_directory)
        updated = False

        for file_path in adversary_files:
            data = self._load_adversary_json(file_path)
            if not data or "threats" not in data:
                continue

            for threat in data["threats"]:
                if threat.get("uuid") == finding_uuid:
                    # Create or update false positive metadata
                    current_time = datetime.now().isoformat()
                    false_positive_metadata = {
                        "uuid": finding_uuid,
                        "reason": reason,
                        "marked_date": threat.get("false_positive_metadata", {}).get(
                            "marked_date", current_time
                        ),
                        "last_updated": current_time,
                        "marked_by": marked_by,
                        "source": "project",
                    }

                    threat["is_false_positive"] = True
                    threat["false_positive_metadata"] = false_positive_metadata

                    if self._save_adversary_json(file_path, data):
                        updated = True
                        logger.info(
                            f"Marked threat {finding_uuid} as false positive in {file_path}"
                        )
                    else:
                        logger.error(
                            f"Failed to save false positive update to {file_path}"
                        )

        if not updated:
            # Fallback to legacy system if threat not found in any .adversary.json
            logger.warning(
                f"Threat {finding_uuid} not found in any .adversary.json files, using legacy fallback"
            )
            data = self._load_false_positives()

            # Check if already marked in legacy system
            for fp in data["false_positives"]:
                if fp["uuid"] == finding_uuid:
                    fp["reason"] = reason
                    fp["last_updated"] = datetime.now().isoformat()
                    fp["marked_by"] = marked_by
                    self._save_false_positives(data)
                    return True

            # Add new false positive to legacy system
            false_positive = {
                "uuid": finding_uuid,
                "reason": reason,
                "marked_date": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "marked_by": marked_by,
            }

            data["false_positives"].append(false_positive)
            try:
                self._save_false_positives(data)
                return True
            except RuntimeError:
                return False

        return updated

    def unmark_false_positive(
        self, finding_uuid: str, working_directory: str | None = None
    ) -> bool:
        """Remove false positive marking from a finding in .adversary.json files.

        Args:
            finding_uuid: UUID of the finding to unmark
            working_directory: Directory to search for .adversary.json files

        Returns:
            True if finding was unmarked, False if not found
        """
        # Find and update the threat in .adversary.json files
        adversary_files = self._find_adversary_json_files(working_directory)
        updated = False

        for file_path in adversary_files:
            data = self._load_adversary_json(file_path)
            if not data or "threats" not in data:
                continue

            for threat in data["threats"]:
                if threat.get("uuid") == finding_uuid and threat.get(
                    "is_false_positive"
                ):
                    # Remove false positive marking
                    threat["is_false_positive"] = False
                    threat["false_positive_metadata"] = None

                    if self._save_adversary_json(file_path, data):
                        updated = True
                        logger.info(
                            f"Unmarked threat {finding_uuid} as false positive in {file_path}"
                        )
                    else:
                        logger.error(
                            f"Failed to save false positive removal to {file_path}"
                        )

        # Also remove from legacy system if present
        data = self._load_false_positives()
        original_count = len(data["false_positives"])
        data["false_positives"] = [
            fp for fp in data["false_positives"] if fp["uuid"] != finding_uuid
        ]

        if len(data["false_positives"]) < original_count:
            try:
                self._save_false_positives(data)
                updated = True
            except RuntimeError:
                pass  # Log but don't fail the operation

        return updated

    def is_false_positive(
        self, finding_uuid: str, working_directory: str | None = None
    ) -> bool:
        """Check if a finding is marked as false positive.

        Args:
            finding_uuid: UUID of the finding to check
            working_directory: Directory to search for .adversary.json files

        Returns:
            True if marked as false positive, False otherwise
        """
        # Use the new method that checks both systems
        return (
            self.get_false_positive_details(finding_uuid, working_directory) is not None
        )

    def get_false_positives(
        self, working_directory: str | None = None
    ) -> list[dict[str, Any]]:
        """Get all false positive findings from both new and legacy systems.

        Args:
            working_directory: Directory to search for .adversary.json files

        Returns:
            List of false positive findings
        """
        false_positives = []
        seen_uuids = set()

        # Get false positives from .adversary.json files (new system)
        adversary_files = self._find_adversary_json_files(working_directory)
        for file_path in adversary_files:
            data = self._load_adversary_json(file_path)
            if not data or "threats" not in data:
                continue

            for threat in data["threats"]:
                if (
                    threat.get("is_false_positive")
                    and threat.get("false_positive_metadata")
                    and threat.get("uuid") not in seen_uuids
                ):

                    fp_data = threat["false_positive_metadata"].copy()
                    fp_data["file_source"] = str(file_path)
                    false_positives.append(fp_data)
                    seen_uuids.add(threat.get("uuid"))

        # Get false positives from legacy system
        legacy_data = self._load_false_positives()
        for fp in legacy_data.get("false_positives", []):
            if fp["uuid"] not in seen_uuids:
                fp_copy = fp.copy()
                fp_copy["source"] = "legacy"
                false_positives.append(fp_copy)
                seen_uuids.add(fp["uuid"])

        return false_positives

    def get_false_positive_uuids(
        self, working_directory: str | None = None
    ) -> set[str]:
        """Get set of all false positive UUIDs for quick lookup.

        Args:
            working_directory: Directory to search for .adversary.json files

        Returns:
            Set of false positive UUIDs
        """
        false_positives = self.get_false_positives(working_directory)
        return {fp["uuid"] for fp in false_positives}

    def filter_false_positives(
        self, threats: list, working_directory: str | None = None
    ) -> list:
        """Filter out false positives from a list of threat matches.

        Args:
            threats: List of ThreatMatch objects
            working_directory: Directory to search for .adversary.json files

        Returns:
            List of threats with false positives filtered out
        """
        false_positive_uuids = self.get_false_positive_uuids(working_directory)

        filtered_threats = []
        for threat in threats:
            if hasattr(threat, "uuid") and threat.uuid in false_positive_uuids:
                # Mark as false positive but keep in results for transparency
                if hasattr(threat, "is_false_positive"):
                    threat.is_false_positive = True
            filtered_threats.append(threat)

        return filtered_threats

    def clear_all_false_positives(self, working_directory: str | None = None) -> None:
        """Clear all false positive markings from both new and legacy systems.

        Args:
            working_directory: Directory to search for .adversary.json files
        """
        # Clear from .adversary.json files
        adversary_files = self._find_adversary_json_files(working_directory)
        for file_path in adversary_files:
            data = self._load_adversary_json(file_path)
            if not data or "threats" not in data:
                continue

            updated = False
            for threat in data["threats"]:
                if threat.get("is_false_positive"):
                    threat["is_false_positive"] = False
                    threat["false_positive_metadata"] = None
                    updated = True

            if updated:
                self._save_adversary_json(file_path, data)
                logger.info(f"Cleared false positives from {file_path}")

        # Clear legacy system
        data = {"false_positives": [], "version": "1.0"}
        try:
            self._save_false_positives(data)
        except RuntimeError:
            pass  # Log but don't fail

    def export_false_positives(self, output_path: Path) -> None:
        """Export false positives to a file.

        Args:
            output_path: Path to export file
        """
        data = self._load_false_positives()
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

    def import_false_positives(self, input_path: Path, merge: bool = True) -> None:
        """Import false positives from a file.

        Args:
            input_path: Path to import file
            merge: If True, merge with existing; if False, replace
        """
        with open(input_path) as f:
            imported_data = json.load(f)

        if merge:
            existing_data = self._load_false_positives()
            existing_uuids = {fp["uuid"] for fp in existing_data["false_positives"]}

            # Add only new false positives
            for fp in imported_data.get("false_positives", []):
                if fp["uuid"] not in existing_uuids:
                    existing_data["false_positives"].append(fp)

            self._save_false_positives(existing_data)
        else:
            self._save_false_positives(imported_data)
