"""False positive management for tracking and suppressing vulnerability findings."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class FalsePositiveManager:
    """Manager for tracking and handling false positive vulnerability findings."""

    def __init__(self):
        """Initialize false positive manager."""
        self.config_dir = Path.home() / ".local" / "share" / "adversary-mcp-server"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.false_positives_file = self.config_dir / "false_positives.json"

    def _load_false_positives(self) -> dict[str, Any]:
        """Load false positives from file.

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

    def mark_false_positive(self, finding_uuid: str, reason: str = "") -> None:
        """Mark a finding as a false positive.

        Args:
            finding_uuid: UUID of the finding to mark
            reason: Reason for marking as false positive
        """
        data = self._load_false_positives()

        # Check if already marked
        for fp in data["false_positives"]:
            if fp["uuid"] == finding_uuid:
                fp["reason"] = reason
                fp["last_updated"] = datetime.now().isoformat()
                self._save_false_positives(data)
                return

        # Add new false positive
        false_positive = {
            "uuid": finding_uuid,
            "reason": reason,
            "marked_date": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
        }

        data["false_positives"].append(false_positive)
        self._save_false_positives(data)

    def unmark_false_positive(self, finding_uuid: str) -> bool:
        """Remove false positive marking from a finding.

        Args:
            finding_uuid: UUID of the finding to unmark

        Returns:
            True if finding was unmarked, False if not found
        """
        data = self._load_false_positives()

        original_count = len(data["false_positives"])
        data["false_positives"] = [
            fp for fp in data["false_positives"] if fp["uuid"] != finding_uuid
        ]

        if len(data["false_positives"]) < original_count:
            self._save_false_positives(data)
            return True
        return False

    def is_false_positive(self, finding_uuid: str) -> bool:
        """Check if a finding is marked as false positive.

        Args:
            finding_uuid: UUID of the finding to check

        Returns:
            True if marked as false positive, False otherwise
        """
        data = self._load_false_positives()
        return any(fp["uuid"] == finding_uuid for fp in data["false_positives"])

    def get_false_positives(self) -> list[dict[str, Any]]:
        """Get all false positive findings.

        Returns:
            List of false positive findings
        """
        data = self._load_false_positives()
        return data["false_positives"]

    def get_false_positive_uuids(self) -> set[str]:
        """Get set of all false positive UUIDs for quick lookup.

        Returns:
            Set of false positive UUIDs
        """
        data = self._load_false_positives()
        return {fp["uuid"] for fp in data["false_positives"]}

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
        """Clear all false positive markings."""
        data = {"false_positives": [], "version": "1.0"}
        self._save_false_positives(data)

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
