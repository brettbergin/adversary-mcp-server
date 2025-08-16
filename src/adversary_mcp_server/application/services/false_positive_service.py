"""Application service for managing false positive findings using Clean Architecture."""

import logging
from datetime import datetime
from typing import Any

from adversary_mcp_server.domain.interfaces import IFalsePositiveRepository
from adversary_mcp_server.domain.value_objects.false_positive_info import (
    FalsePositiveInfo,
)

logger = logging.getLogger(__name__)


class FalsePositiveService:
    """
    Application service for managing false positive security findings.

    This service provides business logic for marking and managing false positive
    findings while maintaining Clean Architecture principles by depending only
    on domain interfaces.
    """

    def __init__(self, repository: IFalsePositiveRepository):
        """
        Initialize the false positive service.

        Args:
            repository: Repository for false positive data persistence
        """
        self.repository = repository
        self.logger = logger

    async def mark_as_false_positive(
        self,
        uuid: str,
        reason: str = "",
        marked_by: str = "user",
    ) -> bool:
        """
        Mark a security finding as a false positive.

        Args:
            uuid: UUID of the finding to mark
            reason: Reason for marking as false positive
            marked_by: Who marked it as false positive

        Returns:
            True if marked successfully, False otherwise
        """
        try:
            # Validate inputs
            if not uuid.strip():
                raise ValueError("UUID cannot be empty")

            # Create false positive info
            fp_info = FalsePositiveInfo.create_false_positive(
                uuid=uuid,
                reason=reason,
                marked_by=marked_by,
            )

            # Save to repository
            success = await self.repository.save_false_positive_info(fp_info)

            if success:
                self.logger.info(
                    f"Marked finding {uuid} as false positive (reason: '{reason}', marked_by: {marked_by})"
                )
            else:
                self.logger.error(f"Failed to mark finding {uuid} as false positive")

            return success

        except Exception as e:
            self.logger.error(f"Error marking finding {uuid} as false positive: {e}")
            return False

    async def unmark_false_positive(self, uuid: str) -> bool:
        """
        Remove false positive marking from a finding.

        Args:
            uuid: UUID of the finding to unmark

        Returns:
            True if unmarked successfully, False otherwise
        """
        try:
            # Validate input
            if not uuid.strip():
                raise ValueError("UUID cannot be empty")

            # Check if it exists and is marked as false positive
            existing_info = await self.repository.get_false_positive_info(uuid)
            if not existing_info or not existing_info.is_false_positive:
                self.logger.warning(f"Finding {uuid} is not marked as false positive")
                return False

            # Remove false positive marking
            success = await self.repository.remove_false_positive_info(uuid)

            if success:
                self.logger.info(f"Unmarked finding {uuid} as false positive")
            else:
                self.logger.error(f"Failed to unmark finding {uuid} as false positive")

            return success

        except Exception as e:
            self.logger.error(f"Error unmarking finding {uuid} as false positive: {e}")
            return False

    async def update_false_positive_reason(
        self,
        uuid: str,
        new_reason: str,
        updated_by: str = "user",
    ) -> bool:
        """
        Update the reason for a false positive marking.

        Args:
            uuid: UUID of the finding
            new_reason: New reason for false positive marking
            updated_by: Who updated the reason

        Returns:
            True if updated successfully, False otherwise
        """
        try:
            # Validate inputs
            if not uuid.strip():
                raise ValueError("UUID cannot be empty")

            # Get existing false positive info
            existing_info = await self.repository.get_false_positive_info(uuid)
            if not existing_info or not existing_info.is_false_positive:
                self.logger.warning(f"Finding {uuid} is not marked as false positive")
                return False

            # Update reason
            updated_info = existing_info.update_reason(new_reason, updated_by)

            # Save updated info
            success = await self.repository.save_false_positive_info(updated_info)

            if success:
                self.logger.info(
                    f"Updated false positive reason for {uuid}: '{new_reason}' (updated_by: {updated_by})"
                )
            else:
                self.logger.error(f"Failed to update false positive reason for {uuid}")

            return success

        except Exception as e:
            self.logger.error(f"Error updating false positive reason for {uuid}: {e}")
            return False

    async def is_false_positive(self, uuid: str) -> bool:
        """
        Check if a finding is marked as a false positive.

        Args:
            uuid: UUID of the finding to check

        Returns:
            True if marked as false positive, False otherwise
        """
        try:
            info = await self.repository.get_false_positive_info(uuid)
            return info is not None and info.is_false_positive
        except Exception as e:
            self.logger.error(f"Error checking false positive status for {uuid}: {e}")
            return False

    async def get_false_positive_details(self, uuid: str) -> dict[str, Any] | None:
        """
        Get detailed false positive information for a finding.

        Args:
            uuid: UUID of the finding

        Returns:
            Dictionary with false positive details or None if not found
        """
        try:
            info = await self.repository.get_false_positive_info(uuid)
            if info and info.is_false_positive:
                return info.to_dict()
            return None
        except Exception as e:
            self.logger.error(f"Error getting false positive details for {uuid}: {e}")
            return None

    async def list_all_false_positives(self) -> list[dict[str, Any]]:
        """
        List all false positive findings.

        Returns:
            List of dictionaries containing false positive information
        """
        try:
            fp_infos = await self.repository.list_false_positives()
            return [info.to_dict() for info in fp_infos if info.is_false_positive]
        except Exception as e:
            self.logger.error(f"Error listing false positives: {e}")
            return []

    async def get_false_positive_stats(self) -> dict[str, Any]:
        """
        Get statistics about false positive findings.

        Returns:
            Dictionary with false positive statistics
        """
        try:
            fp_infos = await self.repository.list_false_positives()
            false_positives = [info for info in fp_infos if info.is_false_positive]

            stats: dict[str, Any] = {
                "total_false_positives": len(false_positives),
                "marked_by": {},
                "recent_markings": 0,
            }

            # Count by who marked them
            for info in false_positives:
                marked_by = info.marked_by or "unknown"
                stats["marked_by"][marked_by] = stats["marked_by"].get(marked_by, 0) + 1

            # Count recent markings (last 7 days)
            if false_positives:
                recent_cutoff = datetime.now().replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                recent_cutoff = recent_cutoff.replace(day=recent_cutoff.day - 7)

                for info in false_positives:
                    if info.marked_date and info.marked_date >= recent_cutoff:
                        stats["recent_markings"] += 1

            return stats

        except Exception as e:
            self.logger.error(f"Error getting false positive stats: {e}")
            return {
                "total_false_positives": 0,
                "marked_by": {},
                "recent_markings": 0,
            }
