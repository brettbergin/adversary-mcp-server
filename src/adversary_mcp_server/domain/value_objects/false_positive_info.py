"""False positive information value object for Clean Architecture."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class FalsePositiveInfo:
    """
    Value object representing false positive metadata for security findings.

    This immutable object encapsulates all information about why and when
    a security finding was marked as a false positive.
    """

    uuid: str
    is_false_positive: bool
    reason: str | None = None
    marked_by: str | None = None
    marked_date: datetime | None = None
    last_updated: datetime | None = None

    def __post_init__(self):
        """Validate false positive information after initialization."""
        if not self.uuid.strip():
            raise ValueError("UUID cannot be empty")

        if self.is_false_positive and self.marked_date is None:
            raise ValueError("False positives must have a marked_date")

    @classmethod
    def create_false_positive(
        cls,
        uuid: str,
        reason: str = "",
        marked_by: str = "user",
        marked_date: datetime | None = None,
    ) -> "FalsePositiveInfo":
        """
        Create a new false positive marking.

        Args:
            uuid: UUID of the finding
            reason: Reason for marking as false positive
            marked_by: Who marked it as false positive
            marked_date: When it was marked (defaults to now)

        Returns:
            FalsePositiveInfo instance with false positive marking
        """
        if marked_date is None:
            marked_date = datetime.now()

        return cls(
            uuid=uuid,
            is_false_positive=True,
            reason=reason,
            marked_by=marked_by,
            marked_date=marked_date,
            last_updated=marked_date,
        )

    @classmethod
    def create_legitimate(cls, uuid: str) -> "FalsePositiveInfo":
        """
        Create a legitimate finding (not a false positive).

        Args:
            uuid: UUID of the finding

        Returns:
            FalsePositiveInfo instance marking finding as legitimate
        """
        return cls(
            uuid=uuid,
            is_false_positive=False,
        )

    def update_reason(self, reason: str, updated_by: str) -> "FalsePositiveInfo":
        """
        Create a new instance with updated reason.

        Args:
            reason: New reason for false positive marking
            updated_by: Who updated the reason

        Returns:
            New FalsePositiveInfo instance with updated reason

        Raises:
            ValueError: If this is not a false positive
        """
        if not self.is_false_positive:
            raise ValueError("Cannot update reason for legitimate finding")

        return FalsePositiveInfo(
            uuid=self.uuid,
            is_false_positive=True,
            reason=reason,
            marked_by=updated_by,
            marked_date=self.marked_date,
            last_updated=datetime.now(),
        )

    def remove_false_positive_marking(self) -> "FalsePositiveInfo":
        """
        Create a new instance with false positive marking removed.

        Returns:
            New FalsePositiveInfo instance marking finding as legitimate
        """
        return FalsePositiveInfo(
            uuid=self.uuid,
            is_false_positive=False,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "uuid": self.uuid,
            "is_false_positive": self.is_false_positive,
        }

        if self.is_false_positive:
            result.update(
                {
                    "false_positive_reason": self.reason,
                    "false_positive_marked_by": self.marked_by,
                    "false_positive_marked_date": (
                        self.marked_date.isoformat() if self.marked_date else None
                    ),
                    "false_positive_last_updated": (
                        self.last_updated.isoformat() if self.last_updated else None
                    ),
                }
            )

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FalsePositiveInfo":
        """
        Create instance from dictionary representation.

        Args:
            data: Dictionary containing false positive data

        Returns:
            FalsePositiveInfo instance
        """
        uuid = data.get("uuid", "")
        is_false_positive = data.get("is_false_positive", False)

        if not is_false_positive:
            return cls.create_legitimate(uuid)

        # Parse dates
        marked_date = None
        if data.get("false_positive_marked_date"):
            marked_date = datetime.fromisoformat(data["false_positive_marked_date"])

        last_updated = None
        if data.get("false_positive_last_updated"):
            last_updated = datetime.fromisoformat(data["false_positive_last_updated"])

        return cls(
            uuid=uuid,
            is_false_positive=True,
            reason=data.get("false_positive_reason"),
            marked_by=data.get("false_positive_marked_by"),
            marked_date=marked_date,
            last_updated=last_updated,
        )

    def __str__(self) -> str:
        """String representation for logging and debugging."""
        if self.is_false_positive:
            return f"FalsePositive({self.uuid}, reason='{self.reason}', marked_by={self.marked_by})"
        else:
            return f"Legitimate({self.uuid})"
